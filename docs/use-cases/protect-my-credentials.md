# I want to keep my API keys out of AI tools

**Time:** 2 minutes
**Prerequisites:** Node.js 20.19+

AI coding tools like Claude Code, Cursor, and Copilot can read files in your project directory. If your `.env` file or `*.key` files are accessible, the AI tool sees those credentials in its context window.

Secretless blocks AI tools from reading credential files and patterns.

## Step 1: Initialize protection

Run `init` in your project directory:

```bash
npx secretless-ai init
```

Expected output:

```
  Detected:  Claude Code, Cursor
  Protected: .env, .aws/credentials, *.key, *.pem (21 file patterns)
  Blocked:   49 credential patterns from AI context
  Done.      Secrets are now invisible to AI tools.
```

This creates tool-specific configuration files (`.cursorrules`, `.claude/settings.json` hooks, etc.) that instruct each AI tool to avoid reading credential files and environment variables.

## Step 2: Verify protection

Confirm that your secrets are protected and still usable:

```bash
npx secretless-ai verify
```

Expected output:

```
  Checking protections...

  .env                     blocked
  .aws/credentials         blocked
  *.key, *.pem             blocked
  ANTHROPIC_API_KEY         hidden from AI, usable via $ENV
  OPENAI_API_KEY            hidden from AI, usable via $ENV

  All secrets protected.
```

The `verify` command confirms two things: AI tools cannot read your credential files, and your credentials are still available as environment variables for your code to use.

## Step 3: Check status anytime

To see a summary of what is protected:

```bash
npx secretless-ai status
```

Expected output:

```
  Backend:     local (AES-256-GCM)
  AI tools:    Claude Code, Cursor
  File rules:  21 patterns blocked
  Cred rules:  49 patterns blocked
  Secrets:     3 stored
```

## What happened

The `init` command did three things:

1. **Detected** which AI tools are installed on your machine
2. **Created** tool-specific deny rules that block reads of credential files (`.env`, `*.key`, `*.pem`, and 18 other patterns)
3. **Added** pattern rules that block 49 credential formats (AWS keys, GitHub tokens, Stripe keys, etc.) from appearing in AI context

No credentials were moved or modified. Your existing workflow continues unchanged. The AI tool simply cannot see the sensitive files anymore.

## Next steps

- [Secure MCP Configs](secure-mcp-configs.md) -- Encrypt credentials stored in MCP server configuration files
- [Migrate from .env](migrate-from-dotenv.md) -- Move `.env` contents into encrypted storage
- [Team Setup](team-setup.md) -- Share a backend across your team
