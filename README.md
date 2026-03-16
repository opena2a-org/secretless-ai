> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · **Secretless AI** · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) · Registry (coming soon)

# secretless-ai

[![npm version](https://img.shields.io/npm/v/secretless-ai.svg)](https://www.npmjs.com/package/secretless-ai)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-791-brightgreen)](https://github.com/opena2a-org/secretless-ai)

Keep API keys and secrets invisible to AI coding tools. Works with Claude Code, Cursor, GitHub Copilot, Windsurf, Cline, and Aider.

## Quick Start

```bash
npx secretless-ai init
```

```
  Detected:  Claude Code, Cursor
  Protected: .env, .aws/credentials, *.key, *.pem (21 file patterns)
  Blocked:   49 credential patterns from AI context
  Done.      Secrets are now invisible to AI tools.
```

## MCP Server Protection

Every MCP server config has plaintext API keys in JSON files on your machine. The LLM sees them. Secretless encrypts them.

```bash
npx secretless-ai protect-mcp
```

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

Scans configs across Claude Desktop, Cursor, Claude Code, VS Code, and Windsurf. Secrets move to your configured backend. Non-secret env vars (URLs, regions) stay untouched.

```bash
npx secretless-ai protect-mcp --backend 1password  # Store MCP secrets in 1Password
npx secretless-ai mcp-status                       # Show which servers are protected
npx secretless-ai mcp-unprotect                    # Restore original configs from backup
```

## How It Works

1. **Scans** your project for hardcoded credentials (49 patterns)
2. **Migrates** them to secure storage (OS keychain, 1Password, Vault, GCP Secret Manager)
3. **Blocks** AI tools from reading credential files (21 file patterns)
4. **Brokers** access through environment variables -- secrets never enter AI context

## Supported Tools

| Tool | Protection Method |
|------|------------------|
| Claude Code | PreToolUse hook (blocks reads before they happen) + deny rules + CLAUDE.md |
| Cursor | `.cursorrules` instructions |
| GitHub Copilot | `.github/copilot-instructions.md` instructions |
| Windsurf | `.windsurfrules` instructions |
| Cline | `.clinerules` instructions |
| Aider | `.aiderignore` file patterns |

Claude Code gets the strongest protection because it supports [hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) -- a shell script runs *before* every file read and blocks access at the tool level.

## Storage Backends

| Backend | Storage | Best For |
|---------|---------|----------|
| `local` | AES-256-GCM encrypted file | Quick start, single machine |
| `keychain` | macOS Keychain / Linux Secret Service | Native OS integration |
| `1password` | 1Password vault | Teams, CI/CD, multi-device |
| `vault` | HashiCorp Vault KV v2 | Enterprise, self-hosted |
| `gcp-sm` | GCP Secret Manager | GCP-native workloads |

```bash
npx secretless-ai backend set 1password              # Switch backend
npx secretless-ai migrate --from local --to 1password # Migrate existing secrets
```

## Installation

```bash
npx secretless-ai init                # Run without installing
npm install -g secretless-ai          # Install globally
npm install --save-dev secretless-ai  # Add to project
```

Requirements: Node.js 18+. Zero runtime dependencies.

## Using with opena2a-cli

[opena2a-cli](https://github.com/opena2a-org/opena2a) unifies all OpenA2A security tools. Secretless powers the credential management commands:

```bash
npm install -g opena2a-cli
opena2a review          # Full security dashboard (HTML)
opena2a secrets init    # Initialize secretless protection
opena2a secrets verify  # Verify secrets are hidden from AI
opena2a broker start    # Identity-aware credential brokering
```

---

## Detailed Reference

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

### Custom Rules

Organizations can define deny patterns for company-specific secrets. Custom rules extend built-in protections.

```bash
npx secretless-ai rules init           # Create a .secretless-rules.yaml template
```

**`.secretless-rules.yaml` format:**

```yaml
env:
  - "ACME_*"
  - "INTERNAL_*_TOKEN"

files:
  - "*.corp-secret"
  - "config/production-keys.*"

bash:
  - "curl*internal.corp.com*"
  - "vault read*"
```

| Section | Blocks |
|---------|--------|
| `env` | Environment variable references matching the pattern |
| `files` | File reads matching the pattern |
| `bash` | Bash commands matching the pattern |

```bash
npx secretless-ai rules list           # Show active rules and deny rule count
npx secretless-ai rules test "ACME_*"  # Preview generated deny rules
npx secretless-ai init                 # Re-generate protections with custom rules
```

### Session Management

If you use 1Password or OS keychain, every secret access triggers a biometric prompt. The `warm` command front-loads all authentication into one moment:

```bash
npx secretless-ai warm               # Authenticate once, pre-load all secrets
npx secretless-ai warm --ttl 1h      # Set session length (default: 5m)
npx secretless-ai warm --no-broker   # Skip auto-starting the broker daemon
```

After warming, every `resolve()` call hits the encrypted file cache. Zero `op` CLI calls, zero keychain prompts.

#### Auto-Start on Login (macOS)

```bash
npx secretless-ai install            # Install LaunchAgent
npx secretless-ai install status     # Check installation status
npx secretless-ai install uninstall  # Remove LaunchAgent
```

#### Claude Code Session Gate

Add to `.claude/settings.json` to block tool calls when your session has expired:

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

When warm, the hook passes silently (~57ms). When expired, it blocks with: `Secretless session expired. Run: secretless-ai warm`

#### Secret Cache

```bash
npx secretless-ai cache              # Show cache status
npx secretless-ai cache ttl 1h       # Set cache TTL (5m, 1h, 1d, off)
npx secretless-ai cache clear        # Clear cached secrets
```

### Credential Scope Discovery

Detect when a credential's permissions expand beyond its baseline -- catching privilege escalation before it becomes a breach.

```bash
npx secretless-ai scope discover MY_CREDENTIAL   # Discover permissions, save baseline
npx secretless-ai scope check MY_CREDENTIAL      # Compare to baseline, report drift
npx secretless-ai scope list                      # Show all baselines
npx secretless-ai scope reset MY_CREDENTIAL      # Clear baseline
```

| Provider | Detection | API Used |
|----------|-----------|----------|
| GCP | Service account key JSON | `testIamPermissions` |
| Vault | Token prefix (`hvs.`, `s.`) | `capabilities-self` |
| AWS | Access key prefix (`AKIA`) | STS `GetCallerIdentity` + IAM introspection |

### Identity-Aware Credential Broker

The broker provides identity-aware credential brokering for AI agents. Agents authenticate via AIM identity tokens before credentials are injected.

```bash
npx secretless-ai broker start       # Start the credential broker daemon
npx secretless-ai broker stop        # Stop the broker daemon
npx secretless-ai broker status      # Show broker status and request count
```

**Policy example** (`~/.secretless-ai/broker-policies.json`):

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
      "effect": "deny"
    }
  ]
}
```

Default-deny policy engine. Supported constraints: `minTrustScore`, `rateLimit`, `timeWindow`, `requireCapability`, `scopeCheck`.

### Data Loss Prevention

Scan AI tool transcripts for accidentally leaked credentials:

```bash
npx secretless-ai scan --history         # Scan shell history
npx secretless-ai clean-history          # Redact credentials in shell history
npx secretless-ai clean-history --dry-run  # Preview without modifying
```

### Git Protection

```bash
npx secretless-ai hook install       # Install pre-commit secret scanner
npx secretless-ai hook status        # Check hook installation status
npx secretless-ai hook uninstall     # Remove pre-commit hook
```

### Backend Configuration

#### 1Password

Stores secrets in a dedicated "Secretless" vault using the [`op` CLI](https://developer.1password.com/docs/cli).

```bash
brew install --cask 1password 1password-cli
# Enable: 1Password > Settings > Developer > "Integrate with 1Password CLI"
npx secretless-ai backend set 1password
```

**CI/CD:** Set `OP_SERVICE_ACCOUNT_TOKEN` -- same secrets, no desktop app needed.

#### HashiCorp Vault

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<your-token>
npx secretless-ai backend set vault
```

#### Backend Inspection

```bash
npx secretless-ai backend list                # Show all entries grouped by prefix
npx secretless-ai backend purge               # Dry-run: show what would be deleted
npx secretless-ai backend purge --yes         # Delete all entries
npx secretless-ai backend purge --prefix mcp --yes  # Delete only mcp/ entries
```

### CI/CD Integration

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

### What Gets Blocked

**File patterns (21):** `.env`, `.env.*`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.crt`, `.aws/credentials`, `.ssh/*`, `.docker/config.json`, `.git-credentials`, `.npmrc`, `.pypirc`, `*.tfstate`, `*.tfvars`, `secrets/`, `credentials/`

**Credential patterns (49):** Anthropic, OpenAI, AWS, GitHub, Slack, Google, Stripe, SendGrid, Supabase, Azure, GitLab, Twilio, Mailgun, MongoDB, JWTs, and more

**Bash commands:** Commands that dump secret files (`cat .env`, `head *.key`) and commands that echo secret environment variables (`echo $API_KEY`)

### Security Architecture

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Secret encryption | AES-256-GCM | Encrypt secrets at rest |
| Key derivation | scrypt (N=16384, r=8, p=1) | Derive keys from machine identity + random salt |
| Session integrity | HMAC-SHA256 | Tamper detection on session state |
| Broker auth | crypto.randomBytes(32) | Bearer token for credential broker |
| Cloud signing | HMAC-SHA256 / RS256 | Authenticate to cloud secret managers |

All encryption uses Node.js built-in `crypto` module. No external crypto dependencies. Key material zeroed after use. File permissions 0o600/0o700.

### All Commands

| Command | Description |
|---------|-------------|
| **Core** | |
| `init` | Set up protections for your AI tools |
| `scan` | Scan for hardcoded secrets (49 patterns) |
| `status` | Show protection status |
| `verify` | Verify keys are usable but hidden from AI |
| `doctor [--fix]` | Diagnose and auto-fix shell profile issues |
| `clean [--dry-run] [--path P]` | Scan and redact credentials in transcripts |
| `watch start\|stop\|status\|install\|uninstall` | Real-time transcript monitoring |
| `scan-history` | Scan shell history for leaked credentials |
| **Session** | |
| `warm [--ttl T] [--no-broker]` | Warm biometric session, pre-load secrets |
| `install [status\|uninstall]` | macOS LaunchAgent management |
| `hook --check-only` | Session gate for Claude Code hooks |
| **Secrets** | |
| `secret set\|list\|get\|rm` | Manage stored secrets |
| `run [--only K1,K2] -- <cmd>` | Run command with secrets injected |
| `import <file>\|--detect` | Import from .env files |
| `setup [--check]` | Interactive setup from `.secretless` manifest |
| **MCP** | |
| `protect-mcp [--backend TYPE]` | Encrypt MCP server secrets |
| `mcp-status` | Show MCP protection status |
| `mcp-unprotect` | Restore original MCP configs |
| **Backend** | |
| `backend [set\|list\|purge]` | Manage storage backends |
| `migrate --from TYPE --to TYPE` | Migrate secrets between backends |
| **Scope** | |
| `scope discover\|check\|list\|reset` | Credential scope discovery |
| **Broker** | |
| `broker start\|stop\|status` | Identity-aware credential broker |
| **Rules** | |
| `rules init\|list\|test` | Custom deny rules |
| **Git** | |
| `hook install\|uninstall\|status` | Pre-commit secret scanner |
| **Cache** | |
| `cache [clear\|ttl]` | Secret cache management |
| **Shell** | |
| `env [--only K1,K2]` | Output export statements for secrets |
| `scan-staged` | Scan git staged files |
| `clean-history [--dry-run]` | Redact credentials in shell history |

## Development

```bash
npm run build      # Compile TypeScript to dist/
npm test           # Run tests (vitest, 791 tests)
npm run dev        # Watch mode
npm run clean      # Remove dist/
```

## OpenA2A Ecosystem

| Project | Description | Install |
|---------|-------------|---------|
| [**OpenA2A CLI**](https://github.com/opena2a-org/opena2a) | Unified security CLI | `npx opena2a` |
| [**HackMyAgent**](https://github.com/opena2a-org/hackmyagent) | Security scanner and red-team toolkit | `npx hackmyagent secure` |
| [**AIM**](https://github.com/opena2a-org/agent-identity-management) | Agent identity, access control, trust scoring | Self-hosted |
| [**AI Browser Guard**](https://github.com/opena2a-org/AI-BrowserGuard) | Browser agent detection and control | Chrome Web Store |
| [**DVAA**](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | Security training target | `docker pull opena2a/dvaa` |

## License

Apache-2.0
