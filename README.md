# openclaw-github-webhook

OpenClaw plugin that receives GitHub webhook events, dispatches them to the agent, and supports automatic command-based replies via GitHub App auth.

## Features

- Receives GitHub webhooks (discussions, PRs, issues, reviews, comments)
- HMAC SHA-256 signature verification
- Command protocol: `!one` / `!zero` / `!a2a` for agent-to-agent coordination
- Smart command handling: ping (no text) → quick reply, with text → full agent turn
- GitHub App JWT auth for posting replies as bot identity
- Repo/mention filtering (optional)
- Forwards events to `/hooks/agent` for full agent processing

## Architecture

```
GitHub → nginx → 127.0.0.1:9876 (this plugin) → /hooks/agent on gateway → agent turn
                                                → GitHub API (direct reply for pings)
```

## Installation

1. Copy plugin files to `~/.openclaw/extensions/github-webhook/`
2. Enable OpenClaw hooks in `openclaw.json` (required for agent forwarding):

```json
{
  "hooks": {
    "enabled": true,
    "token": "your-hooks-secret-token"
  }
}
```

3. Add plugin config to `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "github-webhook": {
        "enabled": true,
        "config": {
          "secret": "your-github-webhook-secret",
          "port": 9876,
          "path": "/github-webhook",
          "agentName": "one",
          "hooksToken": "your-hooks-secret-token",
          "hooksPort": 22408,
          "appId": 2817578,
          "installationId": 108678450,
          "pemPath": "/path/to/github-app-private-key.pem"
        }
      }
    }
  }
}
```

4. Restart gateway: `openclaw gateway restart`
5. Configure GitHub webhook:
   - URL: `http://<host>:9876/github-webhook` (or via nginx reverse proxy)
   - Content type: `application/json`
   - Secret: same as `config.secret`
   - Events: Discussions, Discussion comments, Issues, Issue comments, Pull requests, PR reviews, PR review comments

## Config Reference

| Field | Required | Description |
|---|---|---|
| `secret` | Yes | HMAC SHA-256 webhook secret for signature verification |
| `port` | No | HTTP port (default: 9876) |
| `path` | No | HTTP path (default: `/github-webhook`) |
| `agentName` | **Yes** | Agent identity: `"one"` or `"zero"`. Only reacts to matching `!` commands |
| `hooksToken` | **Yes** | Token for OpenClaw `/hooks/agent` endpoint (must match `hooks.token` in main config) |
| `hooksPort` | No | Gateway port (default: 3001, usually set to your gateway port e.g. 22408) |
| `hooksPath` | No | Hooks base path (default: `/hooks`) |
| `appId` | No | GitHub App ID for bot auth (for direct replies) |
| `installationId` | No | GitHub App Installation ID |
| `pemPath` | No | Path to GitHub App private key PEM file |
| `repos` | No | Filter: only process events from these repos. Empty array = all |
| `mentionFilter` | No | Only dispatch comments mentioning this username. Empty = all |
| `commandMode` | No | `"one"`, `"zero"`, or `"both"` (legacy, prefer `agentName`) |
| `forwardToAgent` | No | Forward ALL events to agent (not just commands). Default: false |

## Multi-Agent Setup

When running multiple agents (e.g. aOne + aZero), each agent's plugin instance must have:

1. **Unique `agentName`** — `"one"` or `"zero"` — so each responds only to its own commands
2. **Own `hooksToken`** — matching the agent's `hooks.token` in its `openclaw.json`
3. **Own `hooksPort`** — matching the agent's gateway port
4. **Own `appId` / `pemPath`** — for posting replies under its own bot identity

Without `hooksToken`, the plugin cannot forward to `/hooks/agent` and falls back to a simple ping reply for all commands.

### Example: aZero config

```json
{
  "hooks": {
    "enabled": true,
    "token": "azero-hooks-token"
  },
  "plugins": {
    "entries": {
      "github-webhook": {
        "enabled": true,
        "config": {
          "secret": "shared-github-webhook-secret",
          "port": 9876,
          "agentName": "zero",
          "hooksToken": "azero-hooks-token",
          "hooksPort": 22409,
          "appId": 2817294,
          "pemPath": "/home/ubuntu/.openclaw/credentials/azero-app.pem"
        }
      }
    }
  }
}
```

## Command Protocol

| Command | Behavior |
|---|---|
| `!one` | Quick ping: "aOne: на связи ✅" |
| `!one <question>` | Full agent turn → agent processes and replies via GitHub API |
| `!zero` | Quick ping: "aZero: на связи ✅" |
| `!zero <question>` | Full agent turn for aZero |
| `!a2a` | Agent-to-agent (TTL=1) |

## Supported Events

| GitHub Event | Action | Dispatched |
|---|---|---|
| `ping` | — | ✅ |
| `discussion` | created | ✅ |
| `discussion_comment` | created | ✅ |
| `issue_comment` | created | ✅ |
| `issues` | opened/closed/reopened | ✅ |
| `pull_request` | opened/closed/reopened | ✅ |
| `pull_request_review` | submitted | ✅ |
| `pull_request_review_comment` | created | ✅ |

## License

MIT
