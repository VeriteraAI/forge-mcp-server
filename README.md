# eydii-mcp-server

EYDII verification for **Claude Code**, **Claude Cowork**, **ChatGPT**, and **Cursor** via MCP. No SDK. No code changes. Just config.

> **This repo contains setup docs only.** The EYDII verification server is hosted at [`id.veritera.ai/mcp`](https://id.veritera.ai/mcp) — nothing to build, install, or self-host. Point your MCP client at the URL below.

> [EYDII](https://github.com/veritera-ai/eydii-python) is the content-blind trust layer for AI agents — verifies actions without seeing your code, prompts, or data. [Learn more →](https://github.com/veritera-ai/eydii-python)

## Setup — Claude Code

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "eydii-verify": {
      "url": "https://id.veritera.ai/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_EYDII_API_KEY"
      }
    }
  }
}
```

Restart Claude Code. Every action is now verified against your policies.

## Setup — Claude Cowork

1. Open Settings > Integrations > MCP Servers
2. Add server URL: `https://id.veritera.ai/mcp`
3. Add your EYDII API key
4. Done

## Setup — ChatGPT / Cursor

Same MCP protocol. Add the server URL and API key through each platform's MCP configuration.

## What Happens

When your agent tries to use a tool — run a command, edit a file, call an API — the MCP server:

1. Checks the action against your EYDII policies
2. Returns **approved** or **denied**
3. Logs a mathematical proof of the decision

Denied actions never execute. No code changes needed. No SDK to install.

## Get an API Key

Sign up at [id.veritera.ai](https://id.veritera.ai) — free tier includes 250 verifications.

## License

MIT — [EYDII](https://id.veritera.ai) by Veritera
