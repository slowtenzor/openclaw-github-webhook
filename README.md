# openclaw-github-webhook

OpenClaw plugin that receives GitHub webhook events and dispatches them as system events to the agent session in real-time.

## Features

- Receives GitHub webhooks (discussions, PRs, issues, reviews, comments)
- HMAC SHA-256 signature verification
- Repo filtering
- Optional mention filtering
- Dispatches formatted events as system events into the main agent session

## Installation

1. Copy plugin files to `~/.openclaw/extensions/github-webhook/`
2. Add to `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "github-webhook": {
        "enabled": true,
        "config": {
          "secret": "your-webhook-secret",
          "port": 9876,
          "path": "/github-webhook",
          "repos": ["org/repo1", "org/repo2"],
          "mentionFilter": ""
        }
      }
    }
  }
}
```

3. Restart gateway: `openclaw gateway restart`
4. Configure GitHub webhook:
   - URL: `http://<host>:<port>/github-webhook`
   - Content type: `application/json`
   - Secret: same as config
   - Events: Discussions, Discussion comments, Issues, Issue comments, Pull requests, PR reviews, PR review comments

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
