# I want to keep my API keys out of AI tools

**Time:** 2 minutes
**Prerequisites:** Node.js 20.19+

AI coding tools like Claude Code, Cursor, and Copilot can read files in your project directory. If your `.env` file or `*.key` files are accessible, the AI tool sees those credentials in its context window.

For Claude Code, Secretless denies tool calls that would read credential files. For the other AI tools it writes an instruction file that asks the tool not to read them.

## Step 1: Initialize protection

Run `init` in your project directory:

```bash
npx secretless-ai init
```

Expected output in a project that Claude Code and Cursor both use, after the version banner:

```
  Configured: Claude Code, Cursor (2 of 2 detected)

  Created:
    + .claude/hooks/secretless-guard.sh
    + .claude/hooks/secretless-output-check.cjs
    + CLAUDE.md
    + .cursor/rules/secretless.mdc

  Modified:
    ~ .claude/settings.json (added 99 deny patterns)

  Next steps:
    Verify: secretless-ai verify
    Scan:   secretless-ai scan
    Status: secretless-ai status
```

For Claude Code, `init` adds deny rules to `.claude/settings.json`, writes instructions to `CLAUDE.md` and wires in two hooks: `.claude/hooks/secretless-guard.sh` denies tool calls that would read credential files before they run, and `.claude/hooks/secretless-output-check.cjs` warns after a Bash command prints a credential-shaped value (detection, not prevention). For Cursor it writes `.cursor/rules/secretless.mdc`, an instruction file: nothing enforces it, and it has no effect unless Cursor loads that file. The [Supported tools](../../README.md#supported-tools) table names the file `init` writes for each tool.

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

1. **Detected** which AI tools the project uses, from their files and directories in it (`.claude/` and `.cursor/` here)
2. **Added** deny rules and the guard hook for Claude Code, which deny its tool calls that would read credential files such as `.env`, `*.key` and `*.pem` or expose secrets, and an output check that warns after a Bash command prints a credential
3. **Wrote** instructions for each tool it configured: `CLAUDE.md` for Claude Code and `.cursor/rules/secretless.mdc` for Cursor

In a project that already has a `.cursorrules` file or a single-file `.clinerules`, `init` appends the instructions to that file; it never creates either one.

No credentials were moved or modified. Your existing workflow continues unchanged. Claude Code's tool calls that would read the credential files are denied before they run. Cursor gets instructions only, and they have no effect unless Cursor loads that file.

## Next steps

- [Secure MCP Configs](secure-mcp-configs.md) -- Encrypt credentials stored in MCP server configuration files
- [Migrate from .env](migrate-from-dotenv.md) -- Move `.env` contents into encrypted storage
- [Team Setup](team-setup.md) -- Share a backend across your team
