# forge-mcp-server

Forge Verify [MCP server](https://modelcontextprotocol.io/) for **Claude Code** and **Claude Cowork**. Adds trust verification to every action your Claude agent takes.

## Setup — Claude Code

Add to your Claude Code MCP config (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "forge-verify": {
      "url": "https://veritera.ai/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_FORGE_API_KEY"
      }
    }
  }
}
```

Restart Claude Code. Forge verification is now active.

## Setup — Claude Cowork

1. Open Claude Cowork settings
2. Go to **Integrations > MCP Servers**
3. Add server URL: `https://veritera.ai/mcp`
4. Add your Forge API key
5. Done — every action is now verified

## What It Does

When your Claude agent tries to use a tool (run a command, edit a file, call an API), the MCP server:

1. Checks the action against your Forge policies
2. Returns **approved** or **denied**
3. Logs a cryptographic proof of the decision

No code changes needed. No SDK to install. Just configuration.

## Get an API Key

Sign up at [veritera.ai](https://veritera.ai) to get your Forge API key.

## License

MIT — [Veritera AI](https://veritera.ai)
