import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { createHmac, timingSafeEqual, createSign } from "node:crypto";
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type ServerResponse,
  type RequestOptions,
} from "node:http";
import { readFileSync } from "node:fs";

// --- Types ---

interface GitHubWebhookConfig {
  secret?: string;
  path?: string;
  repos?: string[];
  mentionFilter?: string;
  hooksPort?: number;
  hooksToken?: string;
  hooksPath?: string;

  // If true, forward formatted webhook events into OpenClaw via /hooks/agent.
  // WARNING: this is noisy (it will show up in the main session/Telegram).
  forwardToAgent?: boolean;

  // Command routing to avoid double-replies when multiple agents receive the same webhook.
  // - "zero": react only to !azero/!zero
  // - "one":  react only to !aone/!one
  // - "both": react to both (default)
  commandMode?: "zero" | "one" | "both";

  // Optional overrides for GitHub App auth (defaults are hardcoded for this deployment)
  appId?: number;
  installationId?: number;
  pemPath?: string;
}

interface PluginCore {
  config: { loadConfig: () => any };
  logging: { getChildLogger: (opts?: any) => any };
  system: { enqueueSystemEvent: (text: string, opts: { sessionKey: string }) => void };
}

// --- Signature verification ---

function verifySignature(payload: string, signature: string, secret: string): boolean {
  if (!signature.startsWith("sha256=")) return false;
  const expected = createHmac("sha256", secret).update(payload, "utf-8").digest("hex");
  const actual = signature.slice(7);
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(actual, "hex"));
}

// --- GitHub App auth + REST helpers ---

const DEFAULT_APP_ID = 2817294;
const DEFAULT_INSTALLATION_ID = 108670284;
const DEFAULT_PEM_PATH = "/home/ubuntu/.openclaw/credentials/a0a1-app.2026-02-07.private-key.pem";

function b64url(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input) : input;
  return buf
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function jwtRS256(appId: number, pem: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = { iat: now - 60, exp: now + 540, iss: appId };
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  const signingInput = `${h}.${p}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  const sig = signer.sign(pem);
  return `${signingInput}.${b64url(sig)}`;
}

async function getRepoInstallationId(cfg: GitHubWebhookConfig, owner: string, repo: string): Promise<number> {
  const appId = cfg.appId ?? DEFAULT_APP_ID;
  const pemPath = cfg.pemPath ?? DEFAULT_PEM_PATH;

  const pem = readFileSync(pemPath, "utf8");
  const appJwt = jwtRS256(appId, pem);

  const resp = await fetch(`https://api.github.com/repos/${owner}/${repo}/installation`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${appJwt}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "openclaw-github-webhook",
    },
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Failed to resolve installation for ${owner}/${repo}: ${resp.status} ${resp.statusText} ${text}`);
  }

  const data: any = await resp.json();
  const installationId = Number(data?.id);
  if (!Number.isFinite(installationId)) throw new Error("No installation id in /installation response");
  return installationId;
}

async function getInstallationToken(cfg: GitHubWebhookConfig, opts?: { owner?: string; repo?: string }): Promise<string> {
  const appId = cfg.appId ?? DEFAULT_APP_ID;
  const pemPath = cfg.pemPath ?? DEFAULT_PEM_PATH;

  const pem = readFileSync(pemPath, "utf8");
  const appJwt = jwtRS256(appId, pem);

  // Prefer per-repo installation id resolution to avoid hardcoding the installation.
  const owner = opts?.owner;
  const repo = opts?.repo;
  const installationId =
    owner && repo
      ? await getRepoInstallationId(cfg, owner, repo)
      : (cfg.installationId ?? DEFAULT_INSTALLATION_ID);

  const resp = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${appJwt}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "openclaw-github-webhook",
    },
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Failed to mint installation token: ${resp.status} ${resp.statusText} ${text}`);
  }

  const data: any = await resp.json();
  if (!data?.token) throw new Error("No token in installation token response");
  return data.token as string;
}

async function postDiscussionComment(params: {
  token: string;
  discussionNodeId: string;
  body: string;
}): Promise<void> {
  const { token, discussionNodeId, body } = params;
  const query = `mutation($discussionId: ID!, $body: String!) {
    addDiscussionComment(input: { discussionId: $discussionId, body: $body }) {
      comment { id }
    }
  }`;
  const resp = await fetch("https://api.github.com/graphql", {
    method: "POST",
    headers: {
      Authorization: `bearer ${token}`,
      "User-Agent": "openclaw-github-webhook",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query, variables: { discussionId: discussionNodeId, body } }),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Failed to post discussion comment: ${resp.status} ${resp.statusText} ${text}`);
  }
  const data: any = await resp.json();
  if (data.errors?.length) {
    throw new Error(`GraphQL error: ${JSON.stringify(data.errors)}`);
  }
}

async function postIssueComment(params: {
  token: string;
  owner: string;
  repo: string;
  issueNumber: number;
  body: string;
}): Promise<void> {
  const { token, owner, repo, issueNumber, body } = params;
  const resp = await fetch(`https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}/comments`, {
    method: "POST",
    headers: {
      Authorization: `token ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "openclaw-github-webhook",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ body }),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Failed to post issue comment: ${resp.status} ${resp.statusText} ${text}`);
  }
}

function isBotActor(payload: any): boolean {
  const sender = payload?.sender;
  const login = (sender?.login ?? "").toString();
  const type = (sender?.type ?? "").toString();
  return type.toLowerCase() === "bot" || /\[bot\]$/i.test(login) || /bot$/i.test(login);
}

function parseCommandTargets(text: string): { one: boolean; zero: boolean } {
  const t = (text ?? "").toLowerCase();
  return {
    one: /(^|\s)!(aone|one)\b/.test(t),
    zero: /(^|\s)!(azero|zero)\b/.test(t),
  };
}

function filterTargetsByMode(
  targets: { one: boolean; zero: boolean },
  mode: "zero" | "one" | "both" | undefined
): { one: boolean; zero: boolean } {
  if (mode === "zero") return { one: false, zero: targets.zero };
  if (mode === "one") return { one: targets.one, zero: false };
  return targets; // both / default
}

function extractCommandText(body: string): string {
  // Strip the !one/!aone/!zero/!azero command prefix and return remaining text
  return body.replace(/(^|\s)!(aone|one|azero|zero)\b/gi, "").trim();
}

function buildCommandReply(targets: { one: boolean; zero: boolean }, agentName?: string): string | null {
  // Each agent only responds to its own command
  if (agentName === "one" && !targets.one) return null;
  if (agentName === "zero" && !targets.zero) return null;
  if (!agentName && !targets.one && !targets.zero) return null;

  const label = agentName === "zero" ? "aZero" : "aOne";
  return `${label}: на связи ✅`;
}

// --- Payload formatting ---

function formatEvent(event: string, payload: any): string | null {
  const repo = payload.repository?.full_name ?? "unknown";

  switch (event) {
    case "discussion_comment": {
      const disc = payload.discussion;
      const comment = payload.comment;
      const author = comment?.user?.login ?? "unknown";
      const title = disc?.title ?? "";
      const num = disc?.number ?? "";
      const body = truncate(comment?.body ?? "", 500);
      const url = comment?.html_url ?? "";
      return `[GitHub] ${author} commented on discussion #${num} "${title}" in ${repo}:\n${body}\n${url}`;
    }

    case "issue_comment": {
      const issue = payload.issue;
      const comment = payload.comment;
      const author = comment?.user?.login ?? "unknown";
      const title = issue?.title ?? "";
      const num = issue?.number ?? "";
      const body = truncate(comment?.body ?? "", 500);
      const isPR = !!issue?.pull_request;
      const kind = isPR ? "PR" : "issue";
      const url = comment?.html_url ?? "";
      return `[GitHub] ${author} commented on ${kind} #${num} "${title}" in ${repo}:\n${body}\n${url}`;
    }

    case "pull_request_review": {
      const pr = payload.pull_request;
      const review = payload.review;
      const author = review?.user?.login ?? "unknown";
      const state = review?.state ?? "";
      const title = pr?.title ?? "";
      const num = pr?.number ?? "";
      const body = truncate(review?.body ?? "", 500);
      const url = review?.html_url ?? "";
      return `[GitHub] ${author} ${state} PR #${num} "${title}" in ${repo}:\n${body}\n${url}`;
    }

    case "pull_request_review_comment": {
      const pr = payload.pull_request;
      const comment = payload.comment;
      const author = comment?.user?.login ?? "unknown";
      const title = pr?.title ?? "";
      const num = pr?.number ?? "";
      const file = comment?.path ?? "";
      const body = truncate(comment?.body ?? "", 500);
      const url = comment?.html_url ?? "";
      return `[GitHub] ${author} commented on PR #${num} "${title}" (${file}) in ${repo}:\n${body}\n${url}`;
    }

    case "pull_request": {
      const action = payload.action;
      if (!["opened", "closed", "reopened"].includes(action)) return null;
      const pr = payload.pull_request;
      const author = pr?.user?.login ?? "unknown";
      const title = pr?.title ?? "";
      const num = pr?.number ?? "";
      const merged = pr?.merged ? " (merged)" : "";
      const url = pr?.html_url ?? "";
      return `[GitHub] ${author} ${action}${merged} PR #${num} "${title}" in ${repo}\n${url}`;
    }

    case "issues": {
      const action = payload.action;
      if (!["opened", "closed", "reopened"].includes(action)) return null;
      const issue = payload.issue;
      const author = issue?.user?.login ?? "unknown";
      const title = issue?.title ?? "";
      const num = issue?.number ?? "";
      const url = issue?.html_url ?? "";
      return `[GitHub] ${author} ${action} issue #${num} "${title}" in ${repo}\n${url}`;
    }

    case "discussion": {
      const action = payload.action;
      if (!["created"].includes(action)) return null;
      const disc = payload.discussion;
      const author = disc?.user?.login ?? "unknown";
      const title = disc?.title ?? "";
      const num = disc?.number ?? "";
      const body = truncate(disc?.body ?? "", 300);
      const url = disc?.html_url ?? "";
      return `[GitHub] ${author} created discussion #${num} "${title}" in ${repo}:\n${body}\n${url}`;
    }

    case "ping": {
      return `[GitHub] Webhook ping received for ${repo}. Hook ID: ${payload.hook_id}. Zen: "${payload.zen}"`;
    }

    default:
      return null;
  }
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + "…";
}

// --- Read body helper ---

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

// --- Plugin ---

let pluginCore: PluginCore | null = null;

// Hot-reload safe singleton: keep one server instance on globalThis to avoid EADDRINUSE.
const G: any = globalThis as any;
let activeServer: ReturnType<typeof createServer> | null = null;

function getConfig(): GitHubWebhookConfig {
  const cfg = pluginCore?.config.loadConfig() as any;
  return cfg?.plugins?.entries?.["github-webhook"]?.config ?? {};
}

const plugin = {
  id: "github-webhook",
  name: "GitHub Webhook",
  description: "Receives GitHub webhooks and injects them as system events.",
  configSchema: emptyPluginConfigSchema(),

  register(api: OpenClawPluginApi) {
    pluginCore = {
      config: api.runtime.config,
      logging: api.runtime.logging,
      system: api.runtime.system,
    };

    const logger = api.runtime.logging.getChildLogger({ plugin: "github-webhook" });
    const webhookConfig = getConfig();
    const listenPath = webhookConfig.path || "/github-webhook";

    const handler = async (req: IncomingMessage, res: ServerResponse) => {
      const url = req.url?.split("?")[0] ?? "/";

      // Health check
      if (url === "/healthz" || (req.method === "GET" && url === listenPath)) {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("github-webhook ok");
        return;
      }

      if (url !== listenPath) {
        res.writeHead(404);
        res.end();
        return;
      }

      if (req.method !== "POST") {
        res.writeHead(405);
        res.end();
        return;
      }

      try {
        const body = await readBody(req);
        const cfg = getConfig();

        // Verify signature if secret is configured
        if (cfg.secret) {
          const sig = req.headers["x-hub-signature-256"] as string | undefined;
          if (!sig || !verifySignature(body, sig, cfg.secret)) {
            logger.warn("[github-webhook] Invalid or missing signature");
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Invalid signature" }));
            return;
          }
        }

        // Respond immediately
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true }));

        // Parse and process
        const event = req.headers["x-github-event"] as string | undefined;
        if (!event) return;

        let payload: any;
        try {
          payload = JSON.parse(body);
        } catch {
          logger.warn("[github-webhook] Failed to parse payload");
          return;
        }

        // Repo filter
        const repoName = payload.repository?.full_name;
        if (cfg.repos?.length && repoName && !cfg.repos.includes(repoName)) {
          logger.info(`[github-webhook] Skipping event from ${repoName} (not in filter)`);
          return;
        }

        // Mention filter: only dispatch if mentionFilter user is mentioned in the comment body
        if (cfg.mentionFilter) {
          const commentBody = payload.comment?.body ?? payload.review?.body ?? payload.discussion?.body ?? "";
          if (!commentBody.toLowerCase().includes(`@${cfg.mentionFilter.toLowerCase()}`)) {
            logger.info(`[github-webhook] Skipping: no mention of @${cfg.mentionFilter}`);
            return;
          }
        }

        // Format the event
        const text = formatEvent(event, payload);
        if (!text) {
          logger.info(`[github-webhook] Skipping unhandled event: ${event}/${payload.action ?? ""}`);
          return;
        }

        logger.info(`[github-webhook] Dispatching: ${event}/${payload.action ?? ""} from ${repoName}`);

        // --- Command handling ---
        // !one/!zero in newly created comments → either ping or full agent turn
        const action = payload.action ?? "";
        let commandHandled = false;
        if ((event === "discussion_comment" || event === "issue_comment") && action === "created" && !isBotActor(payload)) {
          const commentBody = payload.comment?.body ?? "";
          const mode = cfg.commandMode ?? "both";
          const targets = filterTargetsByMode(parseCommandTargets(commentBody), mode);

          // Check if this command is addressed to us
          const isForMe = (cfg.agentName === "one" && targets.one) ||
                          (cfg.agentName === "zero" && targets.zero) ||
                          (!cfg.agentName && (targets.one || targets.zero));

          if (isForMe) {
            const requestText = extractCommandText(commentBody);
            // Always post an immediate ACK via GitHub App so replies never come from a human gh token.
            // - If it's a pure ping (no requestText): reply is "на связи".
            // - If it has requestText: reply is "принято" and we forward to agent for the full response.
            const reply = !requestText
              ? buildCommandReply(targets, cfg.agentName)
              : `${cfg.agentName === "zero" ? "aZero" : "aOne"}: принято ✅ (готовлю ответ через GitHub App)`;

            if (reply && repoName) {
              try {
                const [owner, repo] = repoName.split("/");
                const token = await getInstallationToken(cfg, { owner, repo });
                if (event === "discussion_comment") {
                  const discussionNodeId = payload.discussion?.node_id;
                  if (discussionNodeId) {
                    await postDiscussionComment({ token, discussionNodeId, body: reply });
                    logger.info("[github-webhook] ACK reply posted");
                  }
                }
                if (event === "issue_comment") {
                  const issueNumber = Number(payload.issue?.number);
                  if (owner && repo && Number.isFinite(issueNumber)) {
                    await postIssueComment({ token, owner, repo, issueNumber, body: reply });
                    logger.info("[github-webhook] ACK reply posted");
                  }
                }
              } catch (e: any) {
                logger.error(`[github-webhook] Failed to post ACK reply: ${e?.message ?? e}`);
              }
            }

            // If requestText exists, we still forward to agent for the full answer.
            commandHandled = !requestText;
          
          }
        }

        // Forward to agent via /hooks/agent
        // - Always forward if forwardToAgent is enabled
        // - Also forward when a command with text is addressed to us (even if forwardToAgent is off)
        const shouldForward = cfg.forwardToAgent || !commandHandled;
        // But skip if it's a pure ping that was already handled, or not addressed to us
        const isCommandEvent = (event === "discussion_comment" || event === "issue_comment") && action === "created" && !isBotActor(payload);
        const commentBody2 = payload.comment?.body ?? "";
        const targets2 = filterTargetsByMode(parseCommandTargets(commentBody2), cfg.commandMode ?? "both");
        const isForMe2 = isCommandEvent && ((cfg.agentName === "one" && targets2.one) ||
                          (cfg.agentName === "zero" && targets2.zero) ||
                          (!cfg.agentName && (targets2.one || targets2.zero)));
        const hasRequestText = isForMe2 && !!extractCommandText(commentBody2);

        if (hasRequestText || cfg.forwardToAgent) {
          // Dispatch via /hooks/agent — triggers an active agent turn (not just a passive queue entry)
          const hooksToken = cfg.hooksToken ?? "";
          const hooksPath = cfg.hooksPath ?? "/hooks";
          const hooksPort = cfg.hooksPort || 3001;

          if (!hooksToken) {
            logger.warn("[github-webhook] hooksToken not configured — event dropped");
            return;
          }

          let forwardMessage = text;

          // If this is a command with payload for us, instruct the agent to post the final answer back to GitHub via GitHub App.
          if (hasRequestText && isForMe2) {
            const requestText2 = extractCommandText(commentBody2);
            const commentUrl = payload.comment?.html_url ?? "";
            const repoFullName = repoName ?? "";
            const discussionNumber = payload.discussion?.number;
            const issueNumber = payload.issue?.number;
            const pemPath = cfg.pemPath ?? DEFAULT_PEM_PATH;

            const lines: string[] = [
              "[GitHubCommand]",
              `agent=${cfg.agentName ?? ""}`,
              `repo=${repoFullName}`,
              event === "discussion_comment" ? `discussionNumber=${discussionNumber}` : `issueNumber=${issueNumber}`,
              `commentUrl=${commentUrl}`,
              `commandText=${requestText2}`,
              "",
              "TASK:",
              "- Generate a helpful reply.",
              "- Post the reply back into the same GitHub discussion/issue as a comment.",
              "- MUST post via GitHub App (installation token + GraphQL addDiscussionComment / REST issue comments).",
              "- DO NOT use the gh CLI for posting (it will post as a human).",
              `- GitHub App PEM path: ${pemPath}`,
            ];

            forwardMessage = lines.join("\n");
          }

          const postData = JSON.stringify({
            message: forwardMessage,
            name: "github-webhook",
            wakeMode: "now",
            deliver: false,
          });

          const reqOpts: RequestOptions = {
            hostname: "127.0.0.1",
            port: hooksPort,
            path: `${hooksPath}/agent`,
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Content-Length": Buffer.byteLength(postData),
              Authorization: `Bearer ${hooksToken}`,
            },
          };

          const agentReq = httpRequest(reqOpts, (agentRes) => {
            if (agentRes.statusCode === 202) {
              logger.info("[github-webhook] Agent turn dispatched (202)");
            } else {
              logger.error(`[github-webhook] /hooks/agent returned HTTP ${agentRes.statusCode}`);
            }
            agentRes.resume();
          });

          agentReq.on("error", (err: Error) => {
            logger.error(`[github-webhook] /hooks/agent request failed: ${err.message}`);
          });

          agentReq.write(postData);
          agentReq.end();
        } else {
          logger.info("[github-webhook] forwardToAgent disabled — not forwarding event to OpenClaw");
        }
      } catch (err: any) {
        logger.error(`[github-webhook] Error: ${err?.message ?? err}`);
        if (!res.headersSent) {
          res.writeHead(500);
          res.end();
        }
      }
    };

    // Close previous server on re-register (hot-reload)
    // NOTE: module scope can be recreated; ensure singleton via globalThis.
    const prev = G.__githubWebhookServer as ReturnType<typeof createServer> | undefined;
    if (prev) {
      try { prev.close(); } catch {}
      G.__githubWebhookServer = undefined;
    }
    if (activeServer) {
      try { activeServer.close(); } catch {}
      activeServer = null;
    }

    // Start standalone HTTP server
    const port = webhookConfig.port || 9876;
    const server = createServer(handler);
    activeServer = server;
    G.__githubWebhookServer = server;
    server.listen(port, "127.0.0.1", () => {
      logger.info(`[github-webhook] Listening on http://127.0.0.1:${port}${listenPath}`);
    });
    server.on("error", (err: Error) => {
      logger.error(`[github-webhook] Server error: ${err.message}`);
    });
  },
};

export default plugin;
