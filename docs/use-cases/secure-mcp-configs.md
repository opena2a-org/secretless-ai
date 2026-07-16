# I want to protect MCP server credentials

**Time:** 3 minutes
**Prerequisites:** Node.js 20.19+, at least one MCP client configured

MCP (Model Context Protocol) servers are configured through JSON files that contain plaintext API keys. These configuration files are readable by the AI tool that uses them, which means your credentials are visible in the LLM context window.

## Where MCP credentials live

Each AI tool stores MCP server configs in a different location:

| Client | Config Path |
|--------|-------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Claude Code | `.claude/settings.json` or `~/.claude/settings.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json` |

A typical MCP config looks like this:

```json
{
  "mcpServers": {
    "browserbase": {
      "command": "npx",
      "args": ["-y", "@browserbasehq/mcp-server"],
      "env": {
        "BROWSERBASE_API_KEY": "sk-bb-live-abc123...",
        "BROWSERBASE_PROJECT_ID": "proj-456..."
      }
    }
  }
}
```

The `BROWSERBASE_API_KEY` value is stored in plaintext. When the AI tool reads this config to start the MCP server, it sees the key.

## Step 1: Encrypt MCP credentials

```bash
npx secretless-ai protect-mcp
```

Expected output:

```
  Scanned 1 client(s)

  + claude-desktop/browserbase
      BROWSERBASE_API_KEY (encrypted)
  + claude-desktop/github
      GITHUB_PERSONAL_ACCESS_TOKEN (encrypted)
  + claude-desktop/stripe
      STRIPE_SECRET_KEY (encrypted)

  3 secret(s) encrypted across 3 server(s).
  MCP servers start normally -- no workflow changes needed.
```

Secretless moves each secret value into your configured storage backend and replaces the plaintext value in the JSON config with a reference. The MCP server still starts normally because secretless injects the real value at launch time.

Non-secret environment variables (URLs, project IDs, region identifiers) are left untouched.

## Step 2: Verify protection

```bash
npx secretless-ai verify
```

Expected output includes MCP-specific entries:

```
  Checking protections...

  MCP: claude-desktop/browserbase
    BROWSERBASE_API_KEY        encrypted, stored in local backend
  MCP: claude-desktop/github
    GITHUB_PERSONAL_ACCESS_TOKEN  encrypted, stored in local backend

  All secrets protected.
```

## Step 3: Check MCP status

To see which MCP servers are protected and which still have plaintext credentials:

```bash
npx secretless-ai mcp-status
```

Expected output:

```
  claude-desktop
    browserbase     protected (1 secret)
    github          protected (1 secret)
    stripe          protected (1 secret)

  cursor
    (no MCP servers configured)
```

## Using a different storage backend

By default, secrets are stored in an AES-256-GCM encrypted local file. To use a team-friendly backend:

```bash
npx secretless-ai protect-mcp --backend 1password
npx secretless-ai protect-mcp --backend keychain
npx secretless-ai protect-mcp --backend vault
```

## Restoring original configs

If you need to revert to the original plaintext configs (for example, before uninstalling secretless):

```bash
npx secretless-ai mcp-unprotect
```

Secretless keeps a backup of the original config file and restores it exactly as it was.

## What happened

The `protect-mcp` command did three things:

1. **Scanned** all known MCP client config paths on your machine
2. **Identified** environment variables that contain secrets (API keys, tokens) versus non-secrets (URLs, IDs)
3. **Moved** secret values to encrypted storage and replaced them with references in the config file

The MCP servers continue to work because secretless resolves the references at server start time.

## Next steps

- [Protect My Credentials](protect-my-credentials.md) -- Block AI tools from reading all credential files
- [Team Setup](team-setup.md) -- Use 1Password or Vault so your team shares MCP secrets securely
- [Migrate from .env](migrate-from-dotenv.md) -- Move .env file secrets into the same backend
