# Secretless AI

[![Status: stable](https://img.shields.io/badge/status-stable-green)](STATUS.md)
[![npm version](https://img.shields.io/npm/v/secretless-ai.svg)](https://www.npmjs.com/package/secretless-ai)
[![CI](https://github.com/opena2a-org/secretless-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/opena2a-org/secretless-ai/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **[OpenA2A](https://github.com/opena2a-org)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · **Secretless** · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/ai-browserguard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

[Website](https://opena2a.org/secretless) · [Discord](https://discord.gg/uRZa3KXgEn)

Secretless stores API keys outside your project files and sets up Claude Code, Cursor, GitHub Copilot, Windsurf, Cline and Aider not to read credential files. In Claude Code a hook and deny rules enforce that.

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
    + .claude/settings.json (147 deny patterns)
    + CLAUDE.md

  Next steps:
    Verify: secretless-ai verify
    Scan:   secretless-ai scan
    Status: secretless-ai status
```

Captured in a project holding an empty `.claude/` directory. Run it in a project root. It needs Node.js 20.19 or later and exits 1 when it leaves a tool not configured.

`npx secretless-ai status` prints `Protected` only where the Claude Code hook or deny patterns apply. A project set up through instruction files alone reads `Advisory only`.

<!-- demo:init:start -->
![secretless-ai init sets up a project, then verify checks it](docs/vhs/init.gif)
Recorded with secretless-ai 0.23.1 on 2026-10-22 (pre-release build)
[Text version](docs/vhs/init-capture.txt) · [How it was recorded](docs/vhs/init.json)
<!-- demo:init:end -->

## Common tasks

- [Store a secret and use it by name](#store-secrets-and-use-them-in-ai-sessions)
- [Scan for hardcoded credentials](docs/commands.md#scan-for-hardcoded-credentials)
- [Send scan findings to the GitHub Security tab](docs/scanning.md#scan-in-ci)
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

On a terminal, `secret set` asks before it adds a hook to `~/.zshenv` or `~/.bashrc` that exports every stored secret as an environment variable in each new terminal; `--no-shell-hook` skips the question, and with a value piped in the profile is left as it is. `secret set NAME=VALUE` puts the value in shell history.

`init` also registers a prompt-submit hook that refuses a prompt holding a credential-shaped value or a stored secret's value, and offers a watcher that redacts a credential reaching a saved transcript. Both are local hooks; a chat in a browser is outside their reach.

## Install

```bash
npm install -g secretless-ai
brew install opena2a-org/tap/secretless-ai
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

While telemetry is off (`OPENA2A_TELEMETRY=off`, `telemetry off`, CI or a test runner), Secretless writes no `install_id` to the setting file (`~/.config/opena2a/telemetry.json`, or `$XDG_CONFIG_HOME/opena2a/telemetry.json` when that variable is set), and removes one an earlier run stored there, keeping the stored on or off setting. The next run with telemetry on creates an `install_id` again.

Fire-and-forget with a 2-second timeout. Telemetry never blocks Secretless.

## What it does not cover

Cursor, GitHub Copilot, Windsurf, Cline and Aider get instruction or ignore files, and nothing enforces them.

The guard hook and the deny rules check a command before it runs and cannot see what it prints, so a command whose own output is a credential puts that value in AI context: see [What the guard cannot see](docs/managing-secrets.md#what-the-guard-cannot-see).

## Documentation

- [How it works](docs/how-it-works.md): the scan, supported tools, storage backends, Vault Exec and the broker
- [Store and use secrets](docs/managing-secrets.md): every `secret` workflow
- [Commands](docs/commands.md): MCP protection, triage flags, exit codes
- [Scan coverage and exit codes](docs/scanning.md), with [what a directory scan opens](docs/scanning.md#what-a-directory-scan-opens)
- [Use cases](docs/USE-CASES.md): step-by-step guides
- [Contributing](CONTRIBUTING.md)

Security issues: report privately through [GitHub private vulnerability reporting](https://github.com/opena2a-org/secretless-ai/security/advisories/new) or `info@opena2a.org`. We acknowledge receipt within 48 hours; [SECURITY.md](SECURITY.md) has the full policy.

[Documentation site](https://opena2a.org/docs/secretless) · [Demos](https://opena2a.org/demos) · [aicomply](https://github.com/opena2a-org/aicomply)

## License

Apache-2.0. See [LICENSE](LICENSE).
