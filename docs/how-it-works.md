# How it works

1. **Scans** your project for hardcoded credentials in source files, key files, and the config files it recognizes by name; a directory scan does not open other files, such as `values.yaml` or `main.tf` (see [What a directory scan opens](scanning.md#what-a-directory-scan-opens)), and naming a file scans it: `npx secretless-ai scan deploy/values.yaml`. 57 credential patterns from [`@opena2a/credential-patterns@0.1.3`](https://www.npmjs.com/package/@opena2a/credential-patterns), lockstep-asserted. Suppresses fixture-path false positives via `.secretlessignore` defaults (`test/`, `__tests__/`, `examples/`, `e2e/`, `docs/vhs/`, `node_modules/`, etc.).
2. **Migrates** them to secure storage: OS keychain, 1Password, HashiCorp Vault, GCP Secret Manager, or AES-256-GCM encrypted file.
3. **Gates** AI-tool reads of credential files. 18 file patterns enforced as Claude Code deny rules, plus a PreToolUse hook that denies tool calls that would read credential files or expose secrets before they run: a gate on the assistant's tool path, not a security boundary around the machine. Other tools get instruction files or ignore patterns (see [Supported tools](#supported-tools)).
4. **Brokers** access through environment variables: commands and AI tools see the name, and the value goes to the process that uses it. In Claude Code a PostToolUse check warns after a Bash command prints a credential-shaped value.

## Architecture

Three layers. Use one, two, or all three. Vault Exec (Tier 2) reads the Identity Vault, not the configured [storage backend](#storage-backends); the broker (Tier 3) reads the backend. [Two separate stores](use-cases/run-broker.md#storage-two-separate-stores) says which command fills each.

**Tier 1: In-process SDK.** Credentials resolved in the call stack and zeroized after use. Available in the Python and TypeScript AIM SDKs. Sub-millisecond overhead.

**Tier 2: Vault Exec.** Runs one command with a credential from the Identity Vault (`~/.aim/vault`, filled by `vault register`) set in that command's environment. Vault Exec does not export the value to the calling shell, pass it on the command line, or write it to a file.

```bash
npx secretless-ai vault exec github -- sh -c 'printf "Authorization: Bearer %s\n" "$GITHUB" | curl -s -H @- https://api.github.com/user'
```

The child process receives the value as `$GITHUB` and holds it in its environment for as long as it runs. Vault Exec does not mask the child's output: whatever the command prints goes to whoever ran it, so when an AI assistant runs a wrapped command that prints its environment or the credential, the value enters the assistant's context (see [What the guard cannot see](managing-secrets.md#what-the-guard-cannot-see)). While the child runs, another process running as the same user can read its environment. Wraps any command, in any language.

Vault Exec does not read the configured storage backend: a secret stored with `secret set` is not visible to it, and `vault exec` stops with `Vault resolution denied: Namespace "<name>" not found`. For a secret in the backend, `run --only` sets it in one command's environment under its stored name:

```bash
npx secretless-ai run --only GITHUB_TOKEN -- sh -c 'printf "Authorization: Bearer %s\n" "$GITHUB_TOKEN" | curl -s -H @- https://api.github.com/user'
```

**Tier 3: Broker with identity policy.** A local daemon that mediates credential access across multiple agents. Policy rules allow or deny access by agent ID, credential name, time window, and rate limit. Optional AIM integration adds trust-score and capability constraints.

```bash
npx secretless-ai broker start
```

See [Run the Broker](use-cases/run-broker.md) for when to use the daemon and how to configure it.

AIM is optional. `run --only` and the broker work against any of the five [storage backends](#storage-backends) with no AIM involvement. Vault Exec needs the optional `@opena2a/aim-core` package for its Identity Vault, and no AIM server. Tier 3 adds identity-bound policy when an AIM server is reachable. Default-deny still enforces locally without one.

## Supported tools

| Tool | Protection method |
|---|---|
| Claude Code | PreToolUse hook (`secretless-guard.sh`, a gate on the assistant's tool path: denies tool calls that would read credential files or expose secrets, before they run) + PostToolUse output check (`secretless-output-check.cjs`, warns after a Bash command prints a credential-shaped value; detection, not prevention) + deny rules + CLAUDE.md |
| Cursor | `.cursor/rules/secretless.mdc` instructions |
| GitHub Copilot | `.github/copilot-instructions.md` instructions |
| Windsurf | `.windsurfrules` instructions |
| Cline | `.clinerules/secretless.md` instructions |
| Aider | `.aiderignore` file patterns |

Claude Code gets the strongest protection because it supports [hooks](https://code.claude.com/docs/en/hooks). Hook commands run before the assistant's tool calls and can deny them: a gate on the assistant's tool path, not a security boundary against other processes on the machine.

The Stop hook `init` adds, which redacts the session transcript after each turn, and the git pre-commit hook `hook install` adds store the path of the copy of Secretless that installed them (or `npx --yes secretless-ai@<version>` when that copy runs from npm's npx cache, which npm may remove), so a teammate whose checkout carries your committed `.claude/settings.json` runs `npx secretless-ai init` once, and when that copy is gone the hook prints one line naming the missing file and the command that reinstalls it, the pre-commit hook blocks the commit, and `status` and `hook status` report it as `target missing`.

`init` prints the mode of each tool it configures (`Enforced`, `Ignore file` or `Advisory`). `status` prints `Protected` only where Claude Code applies a guard hook or deny patterns; a project configured through instruction files alone reads `Advisory only`, one configured through `.aiderignore` reads `Ignore file only`, and `status --json` carries the same as `enforcement` (`hook`, `ignore-file`, `advisory` or `none`). `isProtected` and `summary.verdict` do not tell these apart.

For Cursor, GitHub Copilot, Windsurf and Cline, Secretless writes an instruction file that asks the model not to read credential files. For Aider it writes patterns to `.aiderignore`, a list of paths for Aider to leave out. The table shows the file `init` creates in a project with no rule file yet. `init` never creates a `.cursorrules` file or a single-file `.clinerules`; where a project already has one, the block is appended to it. A Cursor project whose rules live only in `.cursorrules` gets no `.mdc` file, and a Cline project with a `.cline/rules/` directory and no `.clinerules` gets `.cline/rules/secretless.md`.

## Storage backends

| Backend | Storage | Best for |
|---|---|---|
| `local` | AES-256-GCM encrypted file | Quick start, single machine |
| `keychain` | macOS Keychain or Linux Secret Service | Native OS integration |
| `1password` | 1Password vault | Teams, CI/CD, multi-device |
| `vault` | HashiCorp Vault KV v2 | Enterprise, self-hosted |
| `gcp-sm` | GCP Secret Manager | GCP-native workloads |

```bash
npx secretless-ai backend set 1password                  # switch backend
npx secretless-ai migrate --from keychain --to 1password # migrate existing secrets
```

`--from` takes the store the secrets are in before the switch: the backend `npx secretless-ai backend` prints as `Current:`, with `keychain` for `keychain-macos` or `keychain-linux`. With no backend configured, secrets go to the OS keychain where one is available (macOS Keychain, or Linux Secret Service when `secret-tool` is installed), as in the example, and otherwise to the encrypted file (`--from local`). Once any backend is configured, `--from local` reads the encrypted file, not the keychain.

Set `SECRETLESS_OS_KEYCHAIN=off` to refuse every call to the macOS Keychain and Linux Secret Service CLIs; reads and writes through those backends then fail with an error instead of prompting, and nothing is read from or written to another store. The value is exactly `off`, in lowercase: `OFF`, `0` or `false` leave the OS keychain reachable.

To seed a new machine from a team's shared backend, `secret sync` copies the names a project's `.secretless` manifest requires (or the names given with `--only K1,K2`) into this machine's store. It prints names only, and leaves a local value that differs as it is unless `--force` is given:

```bash
npx secretless-ai secret sync --from 1password --dry-run  # created / updated / left alone, nothing written
npx secretless-ai secret sync --from 1password            # copy the required names of ./.secretless
npx secretless-ai setup --check                           # confirm nothing required is missing
```

To write a stored secret to Azure Key Vault, HashiCorp Vault or GCP Secret Manager for a deployment, see [Push secrets to a cloud secret store](managing-secrets.md#push-secrets-to-a-cloud-secret-store).

## NanoMind integration

Optional integration with [NanoMind](https://github.com/opena2a-org/nanomind) for enhanced security analysis:

```bash
npm install @nanomind/guard @nanomind/engine  # optional
```

- **MCP injection screening.** `protect-mcp` screens env-var values for prompt-injection patterns and warns when suspicious content is detected.
- **Generated scan context.** `scan --explain` prints a detailed view of each finding without NanoMind: the pattern that matched, the inputs to its confidence score, the path rule that applied, and Fix and Verify commands. It can also add a model-written note beside each finding, off by default and enabled with `SECRETLESS_NANOMIND_EXPLAIN=1`. The note needs the engine's local model and runtime, which installing `@nanomind/engine` does not download. It is off because the local engine does not yet produce explanations worth showing: over 30 measured runs, none were usable and several asserted things about the credential that were not true. Verified remediation always comes from the finding itself, never from the model.

Both features gracefully degrade when NanoMind packages are not installed.

## What it does not cover

For Cursor, GitHub Copilot, Windsurf and Cline, nothing enforces the instruction file, and it has no effect unless the tool loads that file. For Aider, no hook enforces `.aiderignore`, and Secretless does not check that Aider applies it.

The hook and the deny rules check a command before it runs and cannot see what it prints, so a command whose own output is a credential puts that value in AI context. In Claude Code the PostToolUse check warns after such a command runs: see [What the guard cannot see](managing-secrets.md#what-the-guard-cannot-see).
