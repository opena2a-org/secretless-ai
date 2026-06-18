# secretless-ai

[![Status: stable](https://img.shields.io/badge/status-stable-green)](./STATUS.md)

> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

Keep API keys and other secrets invisible to AI coding tools. Works with Claude Code, Cursor, GitHub Copilot, Windsurf, Cline, and Aider. Apache 2.0.

[![npm version](https://img.shields.io/npm/v/secretless-ai.svg)](https://www.npmjs.com/package/secretless-ai)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-988%20passing-brightgreen)](https://github.com/opena2a-org/secretless-ai)

[Website](https://opena2a.org/secretless) · [Demos](https://opena2a.org/demos) · [Discord](https://discord.gg/uRZa3KXgEn)

## Quick start

```bash
npx secretless-ai init
```

```
  Secretless v0.17.1
  Keeping secrets out of AI

  Configured: Claude Code (1 of 1 detected)

  Created:
    + .claude/hooks/secretless-guard.sh
    + CLAUDE.md

  Modified:
    ~ .claude/settings.json (added 69 deny patterns)

  Next steps:
    Verify: secretless-ai verify
    Scan:   secretless-ai scan
    Status: secretless-ai status
```

![Secretless AI Demo](docs/secretless-ai-demo.gif)

## Install

### npm

```bash
npx secretless-ai init          # run once, no install
npm install -g secretless-ai    # install globally
```

Requires Node.js 18 or later.

### Homebrew

```bash
brew install opena2a-org/tap/secretless-ai
```

### From source

```bash
git clone https://github.com/opena2a-org/secretless-ai.git
cd secretless-ai
npm install
npm run build && npm test
node dist/cli.js verify
```

### Verifying what was installed

Every release publishes via npm Trusted Publishing with SLSA v1 provenance. No long-lived `NPM_TOKEN`. GitHub Actions exchanges its OIDC token with npm at publish time.

```bash
npm view secretless-ai dist.attestations --json
# Expects non-empty result with predicateType "https://slsa.dev/provenance/v1"
```

Secretless never reads or transmits credential values it manages. Backends (OS keychain, 1Password, HashiCorp Vault, GCP Secret Manager, AES-256-GCM encrypted file) decrypt on demand at subprocess spawn time. `secretless-ai verify` runs an integrity check of your local install.

## How it works

1. **Scans** your project for hardcoded credentials in config files and source code. 56 credential patterns from [`@opena2a/credential-patterns@0.1.1`](https://www.npmjs.com/package/@opena2a/credential-patterns), lockstep-asserted, across `.js`, `.ts`, `.py`, `.go`, `.java`, `.rb`, and more. Suppresses fixture-path false positives via `.secretlessignore` defaults (`test/`, `__tests__/`, `examples/`, `e2e/`, `docs/vhs/`, `node_modules/`, etc.).
2. **Migrates** them to secure storage: OS keychain, 1Password, HashiCorp Vault, GCP Secret Manager, or AES-256-GCM encrypted file.
3. **Blocks** AI tools from reading credential files. 21 file patterns enforced at the AI-tool hook layer.
4. **Brokers** access through environment variables. Secrets never enter AI context.

## MCP server protection

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
  MCP servers start normally. No workflow changes needed.
```

Scans configs across Claude Desktop, Cursor, Claude Code, VS Code, and Windsurf. Secrets move to your configured backend. Non-secret env vars (URLs, regions) stay untouched.

```bash
npx secretless-ai protect-mcp --backend 1password   # store MCP secrets in 1Password
npx secretless-ai mcp-status                        # show which servers are protected
npx secretless-ai mcp-unprotect                     # restore original configs from backup
```

## Triage helpers

```bash
npx secretless-ai scan --min-confidence 0.85   # high-confidence findings only
npx secretless-ai ignore docs/migration.md     # append a path to .secretlessignore
npx secretless-ai ignore --pattern '*.golden.txt'
npx secretless-ai diff main                    # audit secretless-managed file changes vs a git ref
```

`scan` renders a `Confidence: high (0.92)` line under every finding. The score combines pattern specificity, value entropy, value length, and path tier. With `--no-ignore`, findings whose path matches the default-ignore list are tagged `(looks like a test fixture)` so they stay visible without being re-suppressed.

## Architecture

Three layers. Use one, two, or all three. Each works against any supported backend.

**Tier 1: In-process SDK.** Credentials resolved in the call stack and zeroized after use. Available in the Python and TypeScript AIM SDKs. Sub-millisecond overhead.

**Tier 2: Vault Exec.** A subprocess primitive that injects a credential into a child process's environment without exposing it to the parent. The agent running under an AI assistant never sees the secret.

```bash
npx secretless-ai vault exec github -- curl https://api.github.com/user
```

The child process receives `$GITHUB`. The parent shell, the AI tool's context, and any process listing see nothing. Language-agnostic. Wraps any command.

**Tier 3: Broker with identity policy.** A local daemon that mediates credential access across multiple agents. Policy rules allow or deny access by agent ID, credential name, time window, and rate limit. Optional AIM integration adds trust-score and capability constraints.

```bash
npx secretless-ai broker start
```

See [Run the Broker](docs/use-cases/run-broker.md) for when to use the daemon and how to configure it.

AIM is optional. Tier 1 and Tier 2 work against any of the five [storage backends](#storage-backends) with no AIM involvement. Tier 3 adds identity-bound policy when an AIM server is reachable. Default-deny still enforces locally without one.

## Supported tools

| Tool | Protection method |
|---|---|
| Claude Code | PreToolUse hook (blocks reads before they happen) + deny rules + CLAUDE.md |
| Cursor | `.cursorrules` instructions |
| GitHub Copilot | `.github/copilot-instructions.md` instructions |
| Windsurf | `.windsurfrules` instructions |
| Cline | `.clinerules` instructions |
| Aider | `.aiderignore` file patterns |

Claude Code gets the strongest protection because it supports [hooks](https://docs.anthropic.com/en/docs/claude-code/hooks). A shell script runs before every file read and blocks access at the tool level.

## Storage backends

| Backend | Storage | Best for |
|---|---|---|
| `local` | AES-256-GCM encrypted file | Quick start, single machine |
| `keychain` | macOS Keychain or Linux Secret Service | Native OS integration |
| `1password` | 1Password vault | Teams, CI/CD, multi-device |
| `vault` | HashiCorp Vault KV v2 | Enterprise, self-hosted |
| `gcp-sm` | GCP Secret Manager | GCP-native workloads |

```bash
npx secretless-ai backend set 1password               # switch backend
npx secretless-ai migrate --from local --to 1password # migrate existing secrets
```

## NanoMind integration

Optional integration with [NanoMind](https://github.com/opena2a-org/nanomind) for enhanced security analysis:

```bash
npm install @nanomind/guard @nanomind/engine  # optional
```

- **MCP injection screening.** `protect-mcp` screens env-var values for prompt-injection patterns and warns when suspicious content is detected.
- **Rich scan explanations.** `scan --explain` generates context-aware security explanations for each finding using NanoMind's local inference engine.

Both features gracefully degrade when NanoMind packages are not installed.

## Using with opena2a-cli

[`opena2a-cli`](https://github.com/opena2a-org/opena2a) is the unified CLI for the OpenA2A security toolchain. Secretless powers `opena2a secrets`.

```bash
npm install -g opena2a-cli
opena2a review          # full security dashboard
opena2a secrets init    # initialize secretless protection
```

## Telemetry

Secretless sends anonymous tier-1 usage data to the OpenA2A Registry: tool name (`secretless-ai`), version, command name (`scan`, `protect`, etc.), success, duration, platform, Node major version, and a stable per-machine `install_id`. No content is collected. No scanned secrets, no file paths, no env-var values, no rule contents, no IPs.

- Policy: [opena2a.org/telemetry](https://opena2a.org/telemetry).
- Status: `secretless-ai telemetry status`.
- Disable per-invocation: `OPENA2A_TELEMETRY=off secretless-ai <anything>`.
- Disable persistently: `secretless-ai telemetry off`.
- Audit every payload: `OPENA2A_TELEMETRY_DEBUG=print secretless-ai <anything>` echoes each event to stderr as JSON.

Fire-and-forget with a 2-second timeout. Telemetry never blocks Secretless.

## Use cases

| Guide | Time |
|---|---|
| [Protect My Credentials](docs/use-cases/protect-my-credentials.md) | 2 min |
| [Secure MCP Configs](docs/use-cases/secure-mcp-configs.md) | 3 min |
| [Bring Your Own Vault](docs/use-cases/bring-your-own-vault.md) | 3 min |
| [Run the Broker](docs/use-cases/run-broker.md) | 3 min |
| [Team Setup](docs/use-cases/team-setup.md) | 5 min |
| [Migrate from .env](docs/use-cases/migrate-from-dotenv.md) | 3 min |

Full index: [docs/USE-CASES.md](docs/USE-CASES.md).

## Contributing

Apache 2.0. PRs from outside the org welcome.

```bash
git clone https://github.com/opena2a-org/secretless-ai.git
cd secretless-ai && npm install && npm run build && npm test
```

Security issues: `security@opena2a.org` (coordinated disclosure, response within 24 hours).

## Links

- [Website](https://opena2a.org/secretless)
- [Documentation](https://opena2a.org/docs/secretless)
- [Demos](https://opena2a.org/demos)
- [OpenA2A CLI](https://github.com/opena2a-org/opena2a)
- [Credential patterns library](https://www.npmjs.com/package/@opena2a/credential-patterns)
- [aicomply](https://github.com/opena2a-org/aicomply) — inline PII and credential classification for agent I/O at runtime, the complement to protecting credentials at rest

Part of the [OpenA2A](https://opena2a.org) security platform.

## License

Apache-2.0. See [LICENSE](LICENSE).
