import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { exec as execCb } from "node:child_process";

// --- Types ---

interface GitHubWebhookConfig {
  secret?: string;
  path?: string;
  repos?: string[];
  mentionFilter?: string;
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

        // Format the event
        const text = formatEvent(event, payload);
        if (!text) {
          logger.info(`[github-webhook] Skipping unhandled event: ${event}/${payload.action ?? ""}`);
          return;
        }

        // Mention filter: only dispatch if mentionFilter user is mentioned in the comment body
        if (cfg.mentionFilter) {
          const commentBody =
            payload.comment?.body ?? payload.review?.body ?? payload.discussion?.body ?? "";
          if (!commentBody.toLowerCase().includes(`@${cfg.mentionFilter.toLowerCase()}`)) {
            logger.info(`[github-webhook] Skipping: no mention of @${cfg.mentionFilter}`);
            return;
          }
        }

        logger.info(`[github-webhook] Dispatching: ${event}/${payload.action ?? ""} from ${repoName}`);

        // Enqueue system event AND wake the agent immediately
        execCb(`openclaw system event --text ${JSON.stringify(text)} --mode now`, (err, stdout, stderr) => {
          if (err) {
            logger.error(`[github-webhook] system event failed: ${err.message}`);
            // Fallback: enqueue directly without wake
            pluginCore!.system.enqueueSystemEvent(text, { sessionKey: "agent:main:main" });
          } else {
            logger.info(`[github-webhook] Event dispatched + wake sent`);
          }
        });
      } catch (err: any) {
        logger.error(`[github-webhook] Error: ${err?.message ?? err}`);
        if (!res.headersSent) {
          res.writeHead(500);
          res.end();
        }
      }
    };

    // Start standalone HTTP server
    const port = webhookConfig.port || 9876;
    const server = createServer(handler);
    server.listen(port, "127.0.0.1", () => {
      logger.info(`[github-webhook] Listening on http://0.0.0.0:${port}${listenPath}`);
    });
    server.on("error", (err: Error) => {
      logger.error(`[github-webhook] Server error: ${err.message}`);
    });
  },
};

export default plugin;
