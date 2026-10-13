# secretless-ai

[![Status: stable](https://img.shields.io/badge/status-stable-green)](./STATUS.md)
[![npm version](https://img.shields.io/npm/v/secretless-ai.svg)](https://www.npmjs.com/package/secretless-ai)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/opena2a-org/secretless-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/opena2a-org/secretless-ai/actions/workflows/ci.yml)

> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

Secretless stores API keys outside your project files and sets up AI coding tools not to read credential files. In Claude Code a hook and deny rules enforce that; Cursor, GitHub Copilot, Windsurf, Cline and Aider get instruction or ignore files that nothing enforces. A command that prints its own credential is not blocked. Apache 2.0.

## Quick start

```bash
npx secretless-ai init
```

What `npx secretless-ai init` prints, trimmed ([full output](docs/captures/quick-start.txt)):

```
  Configured: Claude Code (1 of 1 detected)
    Enforced: Claude Code (guard hook and deny patterns)

  Created:
    + .claude/hooks/secretless-guard.sh
    + .claude/hooks/secretless-output-check.cjs
    + .claude/settings.json (99 deny patterns)
    + CLAUDE.md

  Next steps:
    Verify: secretless-ai verify
    Scan:   secretless-ai scan
    Status: secretless-ai status
```

Run it in a project root. It needs Node.js 20.19 or later and exits 1 when it leaves a tool not configured.

`npx secretless-ai status` prints `Protected` only where the Claude Code hook or deny patterns apply. A project set up through instruction files alone reads `Advisory only`.

## Common tasks

- [Store a secret and use it by name](#store-secrets-and-use-them-in-ai-sessions)
- [Scan for hardcoded credentials](docs/commands.md#scan-for-hardcoded-credentials)
- [Encrypt keys in MCP configs](docs/commands.md#mcp-server-protection)
- [Move secrets to another machine](docs/managing-secrets.md#move-secrets-to-another-machine)
- [Track an exposed key until rotated](docs/managing-secrets.md#track-an-exposed-key-until-it-is-rotated)
- [Give git a stored token](docs/managing-secrets.md#give-git-a-stored-token-over-https)
- [Push secrets to a cloud store](docs/managing-secrets.md#push-secrets-to-a-cloud-secret-store)
- [Switch storage backend](docs/how-it-works.md#storage-backends)
- [Run the broker](docs/use-cases/run-broker.md)

## Store secrets and use them in AI sessions

```bash
npx secretless-ai secret set STRIPE_SECRET_KEY --from-clipboard   # key copied from a web page
npx secretless-ai secret set STRIPE_SECRET_KEY   # or type or paste it at a prompt, input hidden
npx secretless-ai import .env                    # or migrate an existing .env in one step
npx secretless-ai secret list                    # names only, values are never printed
npx secretless-ai run --only STRIPE_SECRET_KEY -- node charge.js   # one command gets the value
```

Commands and AI tools see the name, and the value goes to the process that uses it. With no backend configured, secrets go to the OS keychain where one is available, and otherwise to an AES-256-GCM encrypted file.

`secret set` installs a shell hook in `~/.zshenv` or `~/.bashrc` that exports stored secrets as environment variables in every new terminal. `secret set NAME=VALUE` puts the value in shell history.

The guard hook and the deny rules that `init` installs check a command before it runs and cannot see what it prints. A command whose own output is a credential puts the value in AI context, and nothing in Secretless blocks it: see [What the guard cannot see](docs/managing-secrets.md#what-the-guard-cannot-see).

## Install

```bash
npx secretless-ai init                        # run once, no install
npm install -g secretless-ai                  # install globally
brew install opena2a-org/tap/secretless-ai    # Homebrew
```

[Install](docs/install.md) covers building from source, checking a release's provenance, and when Secretless reads a value it stores.

## Telemetry

Secretless sends anonymous tier-1 usage data to the OpenA2A Registry: tool name (`secretless-ai`), version, command name (`scan`, `init`, etc.; a first argument that is not a command is sent as `unknown`), success, duration, platform, Node major version, and a stable per-machine `install_id`.

No content is collected. No scanned secrets, no file paths, no env-var values, no rule contents, no IPs.

- Policy: [opena2a.org/telemetry](https://opena2a.org/telemetry).
- Status: `secretless-ai telemetry status`.
- Disable per-invocation: `OPENA2A_TELEMETRY=off secretless-ai <anything>`.
- Disable persistently: `secretless-ai telemetry off`.
- Audit every payload: `OPENA2A_TELEMETRY_DEBUG=print secretless-ai <anything>` echoes each event to stderr as JSON.

Never sent from CI or a test runner: nothing is sent while `CI`, a CI service's own variable (`GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `TF_BUILD` and others), `VITEST`, `JEST_WORKER_ID` or `NODE_TEST_CONTEXT` is set. `telemetry status` then shows `state: off` and names the variable.

A variable counts as unset when its value is empty or only spaces, or is `false` or `0` in any letter case with surrounding spaces ignored, so `CI=false` and `CI=` leave telemetry as you configured it.

Fire-and-forget with a 2-second timeout. Telemetry never blocks Secretless.

## Documentation

- [How it works](docs/how-it-works.md): the scan, supported tools, storage backends, Vault Exec and the broker
- [Store and use secrets](docs/managing-secrets.md): every `secret` workflow
- [Commands](docs/commands.md): MCP protection, triage flags, exit codes
- [Scan coverage and exit codes](docs/scanning.md), with [what a directory scan opens](docs/scanning.md#what-a-directory-scan-opens)
- [Use cases](docs/USE-CASES.md): step-by-step guides
- [secretless-ai init: sets up a project, then verifies the setup](docs/vhs/init.gif), [Contributing](CONTRIBUTING.md)

Security issues: report privately through [GitHub private vulnerability reporting](https://github.com/opena2a-org/secretless-ai/security/advisories/new) or `info@opena2a.org`. We acknowledge receipt within 48 hours; [SECURITY.md](SECURITY.md) has the full policy.

[Website](https://opena2a.org/secretless) · [Documentation site](https://opena2a.org/docs/secretless) · [Demos](https://opena2a.org/demos) · [Discord](https://discord.gg/uRZa3KXgEn) · [aicomply](https://github.com/opena2a-org/aicomply)

## License

Apache-2.0. See [LICENSE](LICENSE).
