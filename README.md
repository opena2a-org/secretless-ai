> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · **Secretless AI** · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) · Registry (coming soon)

# Secretless AI

[![npm version](https://img.shields.io/npm/v/secretless-ai.svg)](https://www.npmjs.com/package/secretless-ai)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-738-brightgreen)](https://github.com/opena2a-org/secretless-ai)

AI coding tools can read `~/.aws/credentials`, `echo $OPENAI_API_KEY`, and access any secret on your machine. Secretless makes secrets invisible to AI context without changing your workflow.

Works with Claude Code, Cursor, Copilot, Windsurf, Cline, and Aider.

[Website](https://opena2a.org) | [Demos](https://opena2a.org/demos) | [OpenA2A CLI](https://github.com/opena2a-org/opena2a) | [Discord](https://discord.gg/opena2a)

## Get Started in 30 Seconds

The recommended way to use Secretless AI is through [opena2a-cli](https://github.com/opena2a-org/opena2a) — the unified CLI for all OpenA2A security tools. It runs Secretless under the hood along with security scanning, config integrity, and more.

```bash
# Recommended: full security review via opena2a-cli
npx opena2a-cli review

# Or use Secretless AI directly
npx secretless-ai init
```

That's it. No config files, no setup, no flags needed.

**What happens when you run it?**

Detects which AI coding tools you use, installs the right protections for each, and blocks secrets from ever entering an AI context window.

```
┌──────────────────────────────────────────────────┐
│  Secretless v0.11.4                              │
│  Keeping secrets out of AI                       │
│                                                  │
│  Detected:                                       │
│    + Claude Code                                 │
│    + Cursor                                      │
│                                                  │
│  Configured:                                     │
│    * Claude Code                                 │
│    * Cursor                                      │
│                                                  │
│  Created:                                        │
│    + .claude/hooks/secretless-guard.sh           │
│    + CLAUDE.md                                   │
│                                                  │
│  Modified:                                       │
│    ~ .claude/settings.json                       │
│    ~ .cursorrules                                │
│                                                  │
│  Done. Secrets are now blocked from AI context.  │
└──────────────────────────────────────────────────┘
```

![Secretless AI Demo](docs/secretless-ai-demo.gif)

> See all demos at [opena2a.org/demos](https://opena2a.org/demos)

## Installation

```bash
# Run without installing (recommended to start)
npx secretless-ai init

# Install globally
npm install -g secretless-ai

# Add to your project
npm install --save-dev secretless-ai
```

Requirements: Node.js 18+. Zero runtime dependencies.

## Using with opena2a-cli (Recommended)

[opena2a-cli](https://github.com/opena2a-org/opena2a) is the main CLI that unifies all OpenA2A security tools. Secretless AI powers the credential management commands:

| opena2a-cli command | What it runs | Description |
|---------------------|-------------|-------------|
| `opena2a review` | All tools | Full security dashboard (HTML) |
| `opena2a protect` | HackMyAgent + Secretless | Auto-fix findings + credential protection |
| `opena2a secrets init` | Secretless AI | Initialize secretless protection |
| `opena2a secrets verify` | Secretless AI | Verify secrets are hidden from AI |
| `opena2a broker start` | Secretless AI | Identity-aware credential brokering |
| `opena2a dlp scan` | Secretless AI | Scan transcripts for leaked credentials |
| `opena2a shield init` | All tools | Full security setup in one command |

```bash
npm install -g opena2a-cli
opena2a review    # best place to start
```

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

## Commands

### Core

| Command | What It Does |
|---------|-------------|
| `init` | Set up protections for your AI tools |
| `scan` | Scan for hardcoded secrets (49 patterns) |
| `status` | Show protection status (session, broker, transcripts) |
| `verify` | Verify keys are usable but hidden from AI |
| `doctor [--fix]` | Diagnose and auto-fix shell profile issues |
| `clean [--dry-run] [--path P]` | Scan and redact credentials in transcripts |
| `watch` | Monitor transcripts in real-time |

### Secret Management

```bash
npx secretless-ai secret set STRIPE_KEY=sk_live_...   # Store a secret
npx secretless-ai secret set DATABASE_URL              # Read value from stdin
npx secretless-ai secret list                          # List secret names (never values)
npx secretless-ai secret rm STRIPE_KEY                 # Remove a secret
```

#### Running Commands with Secrets

Inject secrets as environment variables into any command. The AI tool sees the command output but never the secret values.

```bash
npx secretless-ai run -- npm test                              # Inject all secrets
npx secretless-ai run --only STRIPE_KEY -- curl -u "$STRIPE_KEY:" https://api.stripe.com/v1/balance
npx secretless-ai run --only DATABASE_URL -- npm run migrate   # Inject specific key
```

#### AI-Safe by Design

When an AI tool tries to read a secret value, secretless blocks it:

```
$ npx secretless-ai secret get STRIPE_KEY    # (run by AI tool)

  secretless: Blocked -- secret values cannot be read in non-interactive contexts.
  AI tools capture stdout, which would expose the secret in their context.

  To inject secrets into a command:
    npx secretless-ai run -- <command>
```

Direct terminal access (human) works normally. The guard detects non-interactive execution (how AI tools run commands) and refuses to output.

#### Import from .env Files

```bash
npx secretless-ai import .env                 # Import from specific file
npx secretless-ai import --detect             # Auto-find and import all .env files
```

#### Project Manifests

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

### Secret Storage Backends

Secrets are never in environment variables, shell profiles, or config files — they exist only in the backend and get injected into process memory at runtime.

| Backend | Storage | Sync | Auth | Best For |
|---------|---------|------|------|----------|
| `local` | AES-256-GCM encrypted file | None (single machine) | Filesystem | Quick start, simple setups |
| `keychain` | macOS Keychain / Linux Secret Service | Device-local | OS login | Native OS integration |
| `1password` | 1Password vault | Cross-device | Biometric (Touch ID) / Service Account | Teams, CI/CD, multi-device |
| `vault` | HashiCorp Vault KV v2 | Cross-device / cluster | Vault token | Enterprise, self-hosted, team secrets |
| `gcp-sm` | GCP Secret Manager | Cross-device / cloud | ADC / Service Account | GCP-native, Cloud Run, GKE |

```bash
npx secretless-ai backend                     # Show available backends
npx secretless-ai backend set 1password       # Switch to 1Password
npx secretless-ai backend set keychain        # Switch to OS keychain
npx secretless-ai backend set gcp-sm          # Switch to GCP Secret Manager
npx secretless-ai migrate --from local --to 1password  # Migrate existing secrets
```

#### 1Password Backend

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

**Prevent repeated popups:** Run `npx secretless-ai warm --ttl 1h` before starting an AI coding session. This pre-loads all secrets into the encrypted cache so no `op` CLI calls (and no biometric popups) happen during the session. See [Session Management](#session-management).

**CI/CD:** Set `OP_SERVICE_ACCOUNT_TOKEN` — same secrets, no code changes. No desktop app needed.

#### HashiCorp Vault Backend

Stores secrets in a Vault KV v2 engine using the HTTP API. Zero SDK dependency — raw `fetch` calls.

**Setup:**

```bash
brew install vault                            # Install Vault CLI
vault server -dev                             # Start dev server (for testing)
```

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<your-token>
npx secretless-ai backend set vault           # Switch backend
npx secretless-ai secret set DB_PASSWORD=...  # Stored in Vault KV v2
```

Supports custom mount paths via backend config. Default mount: `secret`.

#### Backend Inspection

```bash
npx secretless-ai backend list                # Show all entries grouped by prefix
npx secretless-ai backend purge               # Dry-run: show what would be deleted
npx secretless-ai backend purge --yes         # Delete all entries
npx secretless-ai backend purge --prefix mcp --yes  # Delete only mcp/ entries
```

### MCP Secret Protection

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
3. Stores secrets in your configured backend (local, keychain, 1Password, Vault, or GCP Secret Manager)
4. Rewrites configs to use the `secretless-mcp` wrapper — decrypts at runtime, injects as env vars
5. Non-secret env vars (URLs, org names, regions) stay in the config untouched

```bash
npx secretless-ai protect-mcp --backend 1password  # Store MCP secrets in 1Password
npx secretless-ai mcp-status                       # Show which servers are protected/exposed
npx secretless-ai mcp-unprotect                    # Restore original configs from backup
```

### Credential Scope Discovery

Credentials are not static — their effective permissions change when platforms evolve. Secretless detects when a credential's scope expands beyond its baseline, catching privilege escalation before it becomes a breach.

```bash
npx secretless-ai scope discover MY_CREDENTIAL   # Discover current permissions, save baseline
npx secretless-ai scope check MY_CREDENTIAL      # Compare to baseline, report drift
npx secretless-ai scope list                      # Show all baselines
npx secretless-ai scope reset MY_CREDENTIAL      # Clear baseline
```

#### Supported Providers

| Provider | Detection | API Used | Permissions Needed |
|----------|-----------|----------|-------------------|
| **GCP** | Service account key JSON | `testIamPermissions` (Cloud Resource Manager) | None (self-inspection) |
| **Vault** | Token prefix (`hvs.`, `s.`) | `capabilities-self` (Sys) | None (self-inspection) |
| **AWS** | Access key prefix (`AKIA`) | STS `GetCallerIdentity` + IAM policy introspection | None (self-inspection) |

#### Broker Integration

Add `scopeCheck: true` to any broker policy rule. The broker will block credential access if the credential's scope has expanded beyond its baseline.

### Session Management

If you use 1Password or OS keychain as your backend, every secret access triggers a biometric prompt (Touch ID, 1Password popup). During an AI coding session, these fire repeatedly and interrupt your workflow.

The `warm` command front-loads all authentication into one intentional moment:

```bash
npx secretless-ai warm               # Authenticate once, pre-load all secrets into cache
npx secretless-ai warm --ttl 1h      # Set session length (default: 5m, accepts 300, 10m, 1h, 1d)
npx secretless-ai warm --no-broker   # Skip auto-starting the broker daemon
```

**What happens during warm:**

1. Touch ID authenticates your biometric session (macOS)
2. All secrets are resolved from your backend (1Password, keychain, vault) and cached in an AES-256-GCM encrypted file at `~/.secretless-ai/store/.secret-cache`
3. Cache TTL is synced with your session TTL so entries don't expire mid-session
4. The broker daemon starts if not already running

**After warm, for the entire session:** every `resolve()` call hits the encrypted file cache. Zero `op` CLI calls, zero keychain prompts, zero popups.

```
$ npx secretless-ai warm --ttl 1h

  Secretless Session

  Warming session...
  Session is warm.

  TTL:          3600s (1h 0m)
  Expires at:   2026-03-04T17:30:00.000Z
  Touch ID:     used
  Cache:        12 secrets preloaded
  Broker:       running

  You can now use AI tools without repeated auth prompts.
```

#### Auto-Start on Login (macOS)

Install as a macOS LaunchAgent so the broker starts automatically:

```bash
npx secretless-ai install            # Install LaunchAgent
npx secretless-ai install status     # Check installation status
npx secretless-ai install uninstall  # Remove LaunchAgent
```

#### Claude Code Integration

Add a session gate to Claude Code so it blocks tool calls when your session has expired:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "npx secretless-ai hook --check-only"
          }
        ]
      }
    ]
  }
}
```

When the session is warm, the hook passes silently (exit 0, ~57ms). When expired, it blocks with an actionable message:

```
Secretless session expired. Run: secretless-ai warm
```

If secretless has never been set up (no session file exists), the hook passes — it won't block users who haven't opted in.

#### Secret Cache

The cache reduces OS authentication prompts for keychain and 1Password backends by storing resolved secrets in an AES-256-GCM encrypted file. The `warm` command pre-populates the cache automatically.

```bash
npx secretless-ai cache              # Show cache status
npx secretless-ai cache ttl 1h       # Set cache TTL (5m, 1h, 1d, off)
npx secretless-ai cache clear        # Clear cached secrets
```

### Identity-Aware Credential Broker

The broker is a daemon that provides identity-aware credential brokering for AI agents. Instead of giving agents direct access to secrets, the broker requires agents to authenticate (via AIM identity tokens) before credentials are injected into their process environment.

```bash
npx secretless-ai broker start       # Start the credential broker daemon
npx secretless-ai broker stop        # Stop the broker daemon
npx secretless-ai broker status      # Show broker status, uptime, and request count
```

**Policy example** — define rules in `~/.secretless-ai/broker-policies.json`:

```json
{
  "rules": [
    {
      "id": "scan-agents-read-github",
      "agentSelector": "scan-*",
      "credentialSelector": "GITHUB_*",
      "effect": "allow",
      "constraints": {
        "minTrustScore": 0.7,
        "rateLimit": { "maxPerMinute": 10 },
        "scopeCheck": true
      }
    },
    {
      "id": "deny-all-production-keys",
      "agentSelector": "*",
      "credentialSelector": "PROD_*",
      "effect": "deny",
      "constraints": {}
    }
  ]
}
```

The policy engine is default-deny: deny rules are evaluated first, then allow rules. All constraints must pass for an allow rule to grant access. Supported constraints include `minTrustScore` (AIM trust score), `rateLimit`, `timeWindow`, `requireCapability`, and `scopeCheck` (blocks access if a credential's scope has expanded beyond its baseline).

**Request flow:**

1. `broker start` — starts the broker daemon on a local socket
2. An agent requests a credential (e.g., `GITHUB_TOKEN`)
3. The broker verifies the agent's AIM identity token
4. The policy engine evaluates the request against loaded rules
5. If allowed, the broker resolves the secret from the configured backend and returns it
6. If denied, the broker returns an error and logs the attempt to the audit log

### Data Loss Prevention (DLP)

DLP commands scan AI tool transcripts (conversation logs, shell history, tool output) for accidentally leaked credentials. If an API key, token, or connection string appears in a transcript, DLP flags it so you can rotate the exposed credential.

```bash
npx secretless-ai scan --history         # Scan shell history for credentials
npx secretless-ai clean-history          # Redact credentials in shell history
npx secretless-ai clean-history --dry-run  # Preview without modifying
```

### Git Protection

Prevent secrets from being committed:

```bash
npx secretless-ai hook install       # Install pre-commit secret scanner
npx secretless-ai hook status        # Check hook installation status
npx secretless-ai hook uninstall     # Remove pre-commit hook
```

### Moving Keys from AI Context to Env Vars

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

## What Gets Blocked

### File patterns (21)

`.env`, `.env.*`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.crt`, `.aws/credentials`, `.ssh/*`, `.docker/config.json`, `.git-credentials`, `.npmrc`, `.pypirc`, `*.tfstate`, `*.tfvars`, `secrets/`, `credentials/`

### Credential patterns (56)

Anthropic API keys, OpenAI keys, AWS access keys, GitHub PATs, Slack tokens, Google API keys, Stripe keys, SendGrid keys, Supabase keys, Azure keys, GitLab tokens, Twilio keys, Mailgun keys, MongoDB URIs, JWTs, and 41 more

### Bash commands

Commands that dump secret files (`cat .env`, `head *.key`) and commands that echo secret environment variables (`echo $API_KEY`, `echo $SECRET`)

## Claude Code Hook

For Claude Code, Secretless installs a PreToolUse hook that intercepts every `Read`, `Grep`, `Glob`, `Bash`, `Write`, and `Edit` tool call. The hook runs *before* the tool executes, so secrets never enter the AI context window.

## CI/CD Integration

All commands support `--json` and `--ci` flags.

```yaml
# GitHub Actions
name: Credential Check
on: [push, pull_request]
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npx secretless-ai scan --json > scan-report.json
      - run: npx secretless-ai setup --check
```

## All Commands

| Command | Description |
|---------|-------------|
| **Core** | |
| `init` | Set up protections for your AI tools |
| `scan` | Scan for hardcoded secrets (49 patterns) |
| `status` | Show protection status (session, broker, transcripts) |
| `verify` | Verify keys are usable but hidden from AI |
| `doctor [--fix]` | Diagnose and auto-fix shell profile issues |
| `clean [--dry-run] [--path P]` | Scan and redact credentials in transcripts |
| `watch` | Monitor transcripts in real-time |
| **Session Management** | |
| `warm` | Warm biometric session and pre-load secrets into cache |
| `warm --ttl 10m` | Set session TTL (accepts seconds, 5m, 1h, 1d) |
| `warm --no-broker` | Skip auto-starting the broker daemon |
| `install` | Install broker as macOS login daemon (LaunchAgent) |
| `install uninstall` | Remove LaunchAgent |
| `install status` | Check daemon installation status |
| `hook --check-only` | Session gate for Claude Code PreToolUse hooks |
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
| **Shell History** | |
| `scan --history` | Scan shell history for credentials |
| `clean-history` | Redact credentials in shell history |
| `clean-history --dry-run` | Preview redaction without modifying |
| **MCP Protection** | |
| `protect-mcp [--backend TYPE]` | Encrypt MCP server secrets |
| `mcp-status` | Show MCP protection status |
| `mcp-unprotect` | Restore original MCP configs |
| **Backend Management** | |
| `backend` | Show current backend status |
| `backend set <TYPE>` | Set backend (local, keychain, 1password, vault, gcp-sm) |
| `backend list` | List all stored entries |
| `backend purge [--prefix] [--yes]` | Delete entries from backend |
| `migrate --from TYPE --to TYPE` | Migrate secrets between backends |
| **Scope Discovery** | |
| `scope discover <NAME>` | Discover credential permissions and save baseline |
| `scope check <NAME>` | Compare current permissions to baseline |
| `scope list` | Show all scope baselines |
| `scope reset <NAME>` | Clear a scope baseline |
| **Shell Integration** | |
| `env [--only K1,K2]` | Output export statements for stored secrets (use with `eval`) |
| `scan-staged` | Scan git staged files for secrets (used by pre-commit hook) |
| **Cache Management** | |
| `cache` | Show cache status (backend, TTL, entries) |
| `cache clear` | Clear the encrypted secret cache |
| `cache ttl [DURATION]` | Show or set cache TTL (e.g., `5m`, `1h`, `off`) |
| **Credential Broker** | |
| `broker start` | Start the credential broker daemon |
| `broker stop` | Stop the broker daemon |
| `broker status` | Show broker status, uptime, and request count |

## Development

```bash
npm run build      # Compile TypeScript to dist/
npm test           # Run tests (vitest, 738 tests)
npm run dev        # Watch mode — recompile on file changes
npm run clean      # Remove dist/ directory
```

## OpenA2A Ecosystem

| Project | Description | Install |
|---------|-------------|---------|
| [**OpenA2A CLI**](https://github.com/opena2a-org/opena2a) | Unified security CLI -- orchestrates all OpenA2A tools | `npx opena2a` |
| [**HackMyAgent**](https://github.com/opena2a-org/hackmyagent) | Security scanner and red-team toolkit -- checks, attack mode, benchmarks, runtime protection | `npx hackmyagent secure` |
| [**AIM**](https://github.com/opena2a-org/agent-identity-management) | Agent Identity Management -- identity, access control, and trust scoring for AI agents | Self-hosted |
| [**AI Browser Guard**](https://github.com/opena2a-org/AI-BrowserGuard) | Browser agent detection and control -- 4-layer detection, delegation engine | Chrome Web Store |
| [**DVAA**](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Damn Vulnerable AI Agent -- security training target | `docker pull opena2a/dvaa` |
| **Registry** | Trust registry -- agent discovery, trust scores, supply chain verification | Coming soon |

## License

Apache-2.0
