> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)
# secretless-ai

[![npm version](https://img.shields.io/npm/v/secretless-ai.svg)](https://www.npmjs.com/package/secretless-ai)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-809-brightgreen)](https://github.com/opena2a-org/secretless-ai)

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

![Secretless AI Demo](docs/secretless-ai-demo.gif)

For a full security dashboard covering credentials, shadow AI, config integrity, and more:

```bash
npx opena2a-cli review
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

1. **Scans** your project for hardcoded credentials in config files *and* source code (49 patterns across .js, .ts, .py, .go, .java, .rb, and more)
2. **Migrates** them to secure storage (OS keychain, 1Password, Vault, GCP Secret Manager)
3. **Blocks** AI tools from reading credential files (21 file patterns)
4. **Brokers** access through environment variables -- secrets never enter AI context

## Architecture

Secretless has three layers. You can use one, two, or all three — each is independent and works against any supported backend.

**Tier 1 — In-process SDK.** Credentials resolved in the call stack and zeroized after use. Available in the Python and TypeScript AIM SDKs. Sub-millisecond overhead.

**Tier 2 — Vault Exec.** A subprocess primitive that injects a credential into a child process's environment without exposing it to the parent. The agent running under an AI assistant never sees the secret.

```bash
npx secretless-ai vault exec github -- curl https://api.github.com/user
```

The child process receives `$GITHUB`. The parent shell, the AI tool's context, and any process listing see nothing. Language-agnostic — wraps any command.

**Tier 3 — Broker with identity policy.** A local daemon that mediates credential access across multiple agents. Policy rules allow or deny access by agent ID, credential name, time window, and rate limit. Optional AIM integration adds trust-score and capability constraints.

```bash
npx secretless-ai broker start
```

See [Run the Broker](docs/use-cases/run-broker.md) for when to use the daemon and how to configure it.

**AIM is optional.** Tier 1 and Tier 2 work against any of the five [storage backends](#storage-backends) with no AIM involvement. Tier 3 adds identity-bound policy when an AIM server is reachable; it still enforces default-deny locally without one.

## Use Cases

Step-by-step guides for common workflows: [docs/USE-CASES.md](docs/USE-CASES.md)

- [Protect My Credentials](docs/use-cases/protect-my-credentials.md) -- Keep API keys out of AI tools (2 min)
- [Secure MCP Configs](docs/use-cases/secure-mcp-configs.md) -- Encrypt MCP server credentials (3 min)
- [Bring Your Own Vault](docs/use-cases/bring-your-own-vault.md) -- Point Secretless at HashiCorp Vault, GCP SM, or 1Password (3 min)
- [Run the Broker](docs/use-cases/run-broker.md) -- Policy-gated credential daemon for multi-agent runtimes (3 min)
- [Team Setup](docs/use-cases/team-setup.md) -- Shared backend, CI/CD, onboarding (5 min)
- [Migrate from .env](docs/use-cases/migrate-from-dotenv.md) -- Move .env files to encrypted storage (3 min)

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

## NanoMind Integration

Optional integration with [NanoMind](https://github.com/opena2a-org/nanomind) for enhanced security analysis:

```bash
npm install @nanomind/guard @nanomind/engine  # Optional
```

- **MCP injection screening**: `protect-mcp` screens env var values for prompt injection patterns and warns when suspicious content is detected
- **Rich scan explanations**: `scan --explain` generates context-aware security explanations for each finding using NanoMind's local inference engine

Both features gracefully degrade when NanoMind packages are not installed.

## Using with opena2a-cli

[opena2a-cli](https://github.com/opena2a-org/opena2a) unifies all OpenA2A security tools:

```bash
npm install -g opena2a-cli
opena2a review          # Full security dashboard
opena2a secrets init    # Initialize secretless protection
```

## Development

```bash
npm run build && npm test    # 809 tests
```

## Telemetry

Secretless sends anonymous tier-1 usage data to the OpenA2A Registry: tool name (`secretless-ai`), version, command name (`scan`, `protect`, etc.), success, duration, platform, Node major version, and a stable per-machine `install_id`. **No content is collected** — no scanned secrets, no file paths, no env-var values, no rule contents, no IPs.

- **Policy:** [opena2a.org/telemetry](https://opena2a.org/telemetry).
- **Status:** `secretless-ai telemetry status`.
- **Disable per-invocation:** `OPENA2A_TELEMETRY=off secretless-ai <anything>`.
- **Disable persistently:** `secretless-ai telemetry off`.
- **Audit every payload:** `OPENA2A_TELEMETRY_DEBUG=print secretless-ai <anything>` echoes each event to stderr in JSON.

Fire-and-forget with a 2-second timeout — telemetry never blocks Secretless.

## License

Apache-2.0

---

Part of the [OpenA2A](https://opena2a.org) ecosystem. Full reference: [opena2a.org/docs/secretless](https://opena2a.org/docs/secretless)
