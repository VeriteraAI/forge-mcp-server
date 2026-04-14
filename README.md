# forge-mcp-server

Forge verification for **Claude Code**, **Claude Cowork**, **ChatGPT**, and **Cursor** via MCP. No SDK. No code changes. Just config.

> [Forge](https://github.com/veritera-ai/forge-python) is the content-blind trust layer for AI agents — verifies actions without seeing your code, prompts, or data. [Learn more →](https://github.com/veritera-ai/forge-python)

## Setup — Claude Code

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "forge-verify": {
      "url": "https://forge.veritera.ai/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_FORGE_API_KEY"
      }
    }
  }
}
```

Restart Claude Code. Every action is now verified against your policies.

## Setup — Claude Cowork

1. Open Settings > Integrations > MCP Servers
2. Add server URL: `https://forge.veritera.ai/mcp`
3. Add your Forge API key
4. Done

## Setup — ChatGPT / Cursor

Same MCP protocol. Add the server URL and API key through each platform's MCP configuration.

## What Happens

When your agent tries to use a tool — run a command, edit a file, call an API — the MCP server:

1. Checks the action against your Forge policies
2. Returns **approved** or **denied**
3. Logs a cryptographic proof of the decision

Denied actions never execute. No code changes needed. No SDK to install.

## Get an API Key

Sign up at [forge.veritera.ai](https://forge.veritera.ai) — free tier includes 250 verifications.

## License

MIT — [Forge](https://forge.veritera.ai) by Veritera AI
