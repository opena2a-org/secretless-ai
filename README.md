> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [Secretless](https://github.com/opena2a-org/secretless-ai) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [ABG](https://github.com/opena2a-org/AI-BrowserGuard) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [OASB](https://github.com/opena2a-org/oasb) · [ARP](https://github.com/opena2a-org/arp) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

# Secretless AI

[![npm version](https://img.shields.io/npm/v/secretless-ai.svg)](https://www.npmjs.com/package/secretless-ai)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

One command to keep secrets out of AI LLMs. Works with Claude Code, Cursor, Copilot, Windsurf, Cline, and Aider.

Part of the [OpenA2A](https://opena2a.org) ecosystem — open-source security for AI agents.

```bash
npx secretless-ai init
```

<p align="center">
  <img src="docs/secretless-ai-demo.gif" alt="Secretless AI scanning and protecting credentials" width="700" />
</p>

## Secret Storage Backends

Secretless stores secrets in your choice of backend. Secrets are never in environment variables, shell profiles, or config files — they exist only in the backend and get injected into process memory at runtime.

| Backend | Storage | Sync | Auth | Best For |
|---------|---------|------|------|----------|
| `local` | AES-256-GCM encrypted file | None (single machine) | Filesystem | Quick start, simple setups |
| `keychain` | macOS Keychain / Linux Secret Service | Device-local | OS login | Native OS integration |
| `1password` | 1Password vault | Cross-device | Biometric (Touch ID) / Service Account | Teams, CI/CD, multi-device |

```bash
npx secretless-ai backend                     # Show available backends
npx secretless-ai backend set 1password       # Switch to 1Password
npx secretless-ai backend set keychain        # Switch to OS keychain
npx secretless-ai migrate --from local --to 1password  # Migrate existing secrets
```

### 1Password Backend

Stores secrets in a dedicated "Secretless" vault using the [`op` CLI](https://developer.1password.com/docs/cli). Secrets never touch disk.

**Setup:**

```bash
brew install --cask 1password                 # Install 1Password desktop app
brew install --cask 1password-cli             # Install op CLI
```

Then enable CLI integration: **1Password > Settings > Developer > "Integrate with 1Password CLI"**. This allows the CLI to authenticate through the desktop app with biometric unlock (Touch ID / Windows Hello).

```bash
npx secretless-ai backend set 1password       # Switch backend
```

**CI/CD:** Set `OP_SERVICE_ACCOUNT_TOKEN` — same secrets, no code changes. No desktop app needed.

## Secret Management

Store, list, and inject secrets without exposing them to AI tools.

```bash
npx secretless-ai secret set STRIPE_KEY=sk_live_...   # Store a secret
npx secretless-ai secret set DATABASE_URL              # Read value from stdin
npx secretless-ai secret list                          # List secret names (never values)
npx secretless-ai secret rm STRIPE_KEY                 # Remove a secret
```

### Running Commands with Secrets

Inject secrets as environment variables into any command. The AI tool sees the command output but never the secret values.

```bash
npx secretless-ai run -- npm test                              # Inject all secrets
npx secretless-ai run --only STRIPE_KEY -- curl -u "$STRIPE_KEY:" https://api.stripe.com/v1/balance
npx secretless-ai run --only DATABASE_URL -- npm run migrate   # Inject specific key
```

### AI-Safe by Design

When an AI tool tries to read a secret value, secretless blocks it:

```
$ npx secretless-ai secret get STRIPE_KEY    # (run by AI tool)

  secretless: Blocked -- secret values cannot be read in non-interactive contexts.
  AI tools capture stdout, which would expose the secret in their context.

  To inject secrets into a command:
    npx secretless-ai run -- <command>
```

Direct terminal access (human) works normally. The guard detects non-interactive execution (how AI tools run commands) and refuses to output.

### Import from .env Files

```bash
npx secretless-ai import .env                 # Import from specific file
npx secretless-ai import --detect             # Auto-find and import all .env files
```

### Project Manifests

Define required secrets in a `.secretless` file at the project root:

```
STRIPE_KEY        required    Stripe API key for payments
DATABASE_URL      required    PostgreSQL connection string
SENTRY_DSN        optional    Error tracking
```

```bash
npx secretless-ai setup                       # Interactive setup for missing secrets
npx secretless-ai setup --check               # CI: fail if required secrets are missing
```

## Backend Inspection

```bash
npx secretless-ai backend list                # Show all entries grouped by prefix
npx secretless-ai backend purge               # Dry-run: show what would be deleted
npx secretless-ai backend purge --yes         # Delete all entries
npx secretless-ai backend purge --prefix mcp --yes  # Delete only mcp/ entries
```

## MCP Secret Protection

Every MCP server config has plaintext API keys sitting in JSON files on your laptop. The LLM sees them. Secretless encrypts them.

```bash
npx secretless-ai protect-mcp
```

```
  Secretless MCP Protection

  Scanned 1 client(s)

  + claude-desktop/browserbase
      BROWSERBASE_API_KEY (encrypted)
  + claude-desktop/github
      GITHUB_PERSONAL_ACCESS_TOKEN (encrypted)
  + claude-desktop/stripe
      STRIPE_SECRET_KEY (encrypted)

  3 secret(s) encrypted across 3 server(s).

  MCP servers will start normally — no workflow changes needed.
```

**What happens:**

1. Scans MCP configs across Claude Desktop, Cursor, Claude Code, VS Code, and Windsurf
2. Identifies which env vars are secrets (key name patterns + value regex matching)
3. Stores secrets in your configured backend (local, keychain, or 1Password)
4. Rewrites configs to use the `secretless-mcp` wrapper — decrypts at runtime, injects as env vars
5. Non-secret env vars (URLs, org names, regions) stay in the config untouched

```bash
npx secretless-ai protect-mcp --backend 1password  # Store MCP secrets in 1Password
npx secretless-ai mcp-status                       # Show which servers are protected/exposed
npx secretless-ai mcp-unprotect                    # Restore original configs from backup
```

---

## AI Context Protection

AI coding tools read your files to provide context. That includes `.env` files, API keys in config, SSH keys, and cloud credentials. Once a secret enters an AI context window, it's sent to a remote API — and you can't take it back.

## How It Works

Secretless auto-detects which AI tools you use and installs the right protections for each one:

| Tool | Protection Method |
|------|------------------|
| **Claude Code** | PreToolUse hook (blocks file reads before they happen) + deny rules + CLAUDE.md instructions |
| **Cursor** | `.cursorrules` instructions |
| **GitHub Copilot** | `.github/copilot-instructions.md` instructions |
| **Windsurf** | `.windsurfrules` instructions |
| **Cline** | `.clinerules` instructions |
| **Aider** | `.aiderignore` file patterns |

Claude Code gets the strongest protection because it supports [hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) — a shell script runs *before* every file read and blocks access to secret files at the tool level. Other tools get instruction-based protection.

## Quick Start

```bash
# In any project directory
npx secretless-ai init
```

Output:

```
  Secretless v0.7.1
  Keeping secrets out of AI

  Detected:
    + Claude Code
    + Cursor

  Configured:
    * Claude Code
    * Cursor

  Created:
    + .claude/hooks/secretless-guard.sh
    + CLAUDE.md

  Modified:
    ~ .claude/settings.json
    ~ .cursorrules

  Done. Secrets are now blocked from AI context.
```

## Moving Keys from AI Context to Env Vars

The safest setup: keys live in environment variables, AI tools reference them by name.

**Step 1: Move keys to the correct shell profile**

Non-interactive subprocesses (Claude Code's Bash tool, CI/CD, Docker) don't source interactive-only profiles. Use the right file for your platform:

| Platform | Shell | Correct File | Why |
|----------|-------|-------------|-----|
| macOS | zsh | `~/.zshenv` | Sourced by ALL shells (interactive + non-interactive) |
| Linux | bash | `~/.bashrc` | Sourced by interactive bash; most tools source it explicitly |
| Windows | — | System Environment Variables | Use `setx` or Settings > System > Environment Variables |

**Step 2: Run secretless init**

```bash
npx secretless-ai init
```

**Step 3: Verify**

```bash
npx secretless-ai verify
```

```
  Env vars available (usable by tools):
    + ANTHROPIC_API_KEY
    + OPENAI_API_KEY

  AI context files: clean (no credentials found)

  PASS: Secrets are accessible via env vars but hidden from AI context.
```

## Git Protection

Prevent secrets from being committed:

```bash
npx secretless-ai hook install       # Install pre-commit secret scanner
npx secretless-ai hook status        # Check hook installation status
npx secretless-ai hook uninstall     # Remove pre-commit hook
```

## All Commands

| Command | Description |
|---------|-------------|
| `init` | Set up protections for your AI tools |
| `scan` | Scan for hardcoded secrets (49 patterns) |
| `status` | Show protection status |
| `verify` | Verify keys are usable but hidden from AI |
| `doctor [--fix]` | Diagnose and auto-fix shell profile issues |
| `clean [--dry-run]` | Scan and redact credentials in transcripts |
| `watch` | Monitor transcripts in real-time |
| **Secret Management** | |
| `secret set <NAME[=VALUE]>` | Store a secret |
| `secret list` | List stored secret names |
| `secret get <NAME>` | Retrieve a secret value (blocked in non-interactive contexts) |
| `secret rm <NAME>` | Remove a secret |
| `run [--only K1,K2] -- <cmd>` | Run command with secrets injected as env vars |
| `import <file>` | Import secrets from .env file |
| `import --detect` | Auto-find and import .env files |
| **Project Setup** | |
| `setup` | Interactive setup from `.secretless` manifest |
| `setup --check` | CI: fail if required secrets are missing |
| **Git Protection** | |
| `hook install` | Install pre-commit secret scanner |
| `hook uninstall` | Remove pre-commit hook |
| `hook status` | Check hook installation status |
| **MCP Protection** | |
| `protect-mcp [--backend TYPE]` | Encrypt MCP server secrets |
| `mcp-status` | Show MCP protection status |
| `mcp-unprotect` | Restore original MCP configs |
| **Backend Management** | |
| `backend` | Show current backend status |
| `backend set <TYPE>` | Set backend (local, keychain, 1password) |
| `backend list` | List all stored entries |
| `backend purge [--prefix] [--yes]` | Delete entries from backend |
| `migrate --from TYPE --to TYPE` | Migrate secrets between backends |

## What Gets Blocked

### File patterns (20+)

`.env`, `.env.*`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.crt`, `.aws/credentials`, `.ssh/*`, `.docker/config.json`, `.git-credentials`, `.npmrc`, `.pypirc`, `*.tfstate`, `*.tfvars`, `secrets/`, `credentials/`

### Credential patterns (49)

Anthropic API keys, OpenAI keys, AWS access keys, GitHub PATs, Slack tokens, Google API keys, Stripe keys, SendGrid keys, Supabase keys, Azure keys, GitLab tokens, Twilio keys, Mailgun keys, MongoDB URIs, JWTs, and 34 more

### Bash commands

Commands that dump secret files (`cat .env`, `head *.key`) and commands that echo secret environment variables (`echo $API_KEY`, `echo $SECRET`)

## Claude Code Hook

For Claude Code, Secretless installs a PreToolUse hook that intercepts every `Read`, `Grep`, `Glob`, `Bash`, `Write`, and `Edit` tool call. The hook runs *before* the tool executes, so secrets never enter the AI context window.

## Development

```bash
npm run build      # Compile TypeScript to dist/
npm test           # Run tests (vitest, 461 tests)
npm run dev        # Watch mode — recompile on file changes
npm run clean      # Remove dist/ directory
```

## Requirements

- Node.js 18+
- A project directory with at least one AI tool configured (or Secretless defaults to Claude Code)
- **Optional:** 1Password CLI (`op`) for 1Password backend
- **Optional:** macOS Keychain or `secret-tool` (Linux) for keychain backend

## Zero Dependencies

Secretless has zero runtime dependencies.

## OpenA2A Ecosystem

| Project | Description | Install |
|---------|-------------|---------|
| [**AIM**](https://github.com/opena2a-org/agent-identity-management) | Agent Identity Management -- identity and access control for AI agents | `pip install aim-sdk` |
| [**HackMyAgent**](https://github.com/opena2a-org/hackmyagent) | Security scanner -- 147 checks, attack mode, auto-fix | `npx hackmyagent secure` |
| [**OASB**](https://github.com/opena2a-org/oasb) | Open Agent Security Benchmark -- 182 attack scenarios | `npm install @opena2a/oasb` |
| [**ARP**](https://github.com/opena2a-org/arp) | Agent Runtime Protection -- process, network, filesystem monitoring | `npm install @opena2a/arp` |
| [**Secretless AI**](https://github.com/opena2a-org/secretless-ai) | Keep credentials out of AI context windows | `npx secretless-ai init` |
| [**DVAA**](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Damn Vulnerable AI Agent -- security training and red-teaming | `docker pull opena2a/dvaa` |

## License

Apache-2.0
