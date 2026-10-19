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
    Enforced: Claude Code (guard hook and deny patterns)
    Advisory: Cursor (instruction file, nothing enforces it)

  Created:
    + .claude/hooks/secretless-guard.sh
    + .claude/hooks/secretless-output-check.cjs
    + .claude/settings.json (147 deny patterns)
    + CLAUDE.md
    + .cursor/rules/secretless.mdc

  Next steps:
    Verify: secretless-ai verify
    Scan:   secretless-ai scan
    Status: secretless-ai status

  Transcript watcher not installed: no transcript directory yet. Claude Code creates ~/.claude/projects at its first session.
    Install it then: secretless-ai watch install
```

For Claude Code, `init` adds deny rules to `.claude/settings.json`, writes instructions to `CLAUDE.md` and wires in three hooks: `.claude/hooks/secretless-guard.sh` denies tool calls that would read credential files before they run, `.claude/hooks/secretless-output-check.cjs` warns after a Bash command prints a credential-shaped value (detection, not prevention), and `secretless-ai hook --check-prompt` runs on each prompt you submit and refuses one that holds a credential-shaped value or the value of a stored secret, naming the pattern or the secret and never the value. For Cursor it writes `.cursor/rules/secretless.mdc`, an instruction file: nothing enforces it, and it has no effect unless Cursor loads that file. The [Supported tools](../how-it-works.md#supported-tools) table names the file `init` writes for each tool.

On a terminal, `init` then asks whether to install the transcript watcher, which redacts a credential that reaches a saved transcript and shows a desktop notification; the default is yes, and `init --no-watch` skips the question. In the sample above there is no transcript directory yet, so nothing is asked and the install command is named instead.

## Step 2: Verify protection

Confirm that your API keys are still set for your code and that no credential value sits in the files AI tools read:

```bash
npx secretless-ai verify
```

Expected output in the project from Step 1, in a shell that sets `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` and no other variable `verify` knows:

```
  Secretless Verify

  Scope: this project + global AI config (~/.claude) + current-shell env vars

  │ + ANTHROPIC_API_KEY
  │ + OPENAI_API_KEY
    44 known env vars not set (use --all to list)

  AI context: clean (no credentials found)

  PASS Secrets accessible via env vars, hidden from AI context.
```

`verify` names each credential variable it knows that your shell sets, without its value, and counts the ones your shell does not set; `verify --all` lists those too. It then looks for credential values in a fixed list of project files, among them `CLAUDE.md`, `.claude/settings.json`, `.cursorrules`, the MCP configs and `.env`, in `~/.claude/CLAUDE.md` and `~/.claude/settings.json`, and in the five most recent transcript files under `~/.claude/projects`. `PASS` means at least one of those variables is set and no value was found; otherwise `verify` exits 1 and prints the command to run next. It does not check the deny rules or the guard hook: `status` in Step 3 reports on those.

## Step 3: Check status anytime

To see a summary of what is protected:

```bash
npx secretless-ai status
```

Expected output in the project from Step 1:

```
  Secretless Status

  ── Observations ────────────────────────────────────────────
  ✓ Claude Code hook installed (.claude/settings.json — 147 deny patterns)
  ✓ Output check hook installed (PostToolUse)
  ✓ Stop hook installed (transcript redaction)
  ✓ Prompt check installed (a credential in a prompt is refused before it is sent)
  ✓ Tool instructions: Claude Code, Cursor (advisory, not enforced)
  ✓ No credentials detected in scanned files
  ⚠ Biometric session not initialized                                               → secretless-ai warm
  ⚠ Transcript watcher not running                                                  → secretless-ai watch install
  ⚠ Broker daemon not installed                                                     → secretless-ai install

  ── Verdict ─────────────────────────────────────────────────
  Protected (3 observations need attention)
```

Each `⚠` row names the command that addresses it. The `Biometric session` row appears only when secrets are stored in the OS keychain (the default on macOS) or 1Password.

## What happened

The `init` command did three things:

1. **Detected** which AI tools the project uses, from their files and directories in it (`.claude/` and `.cursor/` here)
2. **Added** deny rules and the guard hook for Claude Code, which deny its tool calls that would read credential files such as `.env`, `*.key` and `*.pem` or expose secrets, and an output check that warns after a Bash command prints a credential
3. **Wrote** instructions for each tool it configured: `CLAUDE.md` for Claude Code and `.cursor/rules/secretless.mdc` for Cursor

In a project that already has a `.cursorrules` file or a single-file `.clinerules`, `init` appends the instructions to that file; it never creates either one.

No credentials were moved or modified. Your existing workflow continues unchanged. Claude Code's tool calls that would read the credential files are denied before they run. Cursor gets instructions only, and they have no effect unless Cursor loads that file.

## Next steps

- [Secure MCP Configs](secure-mcp-configs.md): Encrypt credentials stored in MCP server configuration files
- [Migrate from .env](migrate-from-dotenv.md): Move `.env` contents into encrypted storage
- [Team Setup](team-setup.md): Share a backend across your team
