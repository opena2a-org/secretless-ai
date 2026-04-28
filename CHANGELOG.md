# Changelog

All notable changes to [secretless-ai](https://www.npmjs.com/package/secretless-ai) are documented in this file.

```bash
npm install -g secretless-ai
```

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.2] - 2026-04-28

### Fixed
- **Read-only commands no longer trigger Touch ID or "1Password Access Requested" dialogs.** `secretless-ai backend` (no subcommand) and the local→keychain upgrade in `createBackend` were calling `isKeychainAvailable()` (`security default-keychain` — can fire Touch ID on Macs with biometric-locked keychains) and `isOnePasswordAvailable()` (`op account get` — fires the "Allow Terminal to get CLI access" dialog on Macs with the 1Password desktop app). A first-time user running `npx secretless-ai backend` to inspect available backends would see these prompts and reasonably uninstall. Split each probe into a `*Likely()` variant (cheap PATH/platform check, never spawns a process) and the existing `*Available()` variant (active probe, kept for genuine pre-flight on `backend set <type>` and `migrate`). Read-only display paths now use `*Likely()`. Regression test in `src/commands/backend.silence.test.ts` asserts `runBackend([])`, `runStatus`, and `createBackend('local')` never invoke `security` or `op` via `child_process`. Public API gains `isKeychainLikely` and `isOnePasswordLikely` exports.

## [0.16.1] - 2026-04-28

### Fixed
- **Telemetry exit-path coverage** (#61). Every command now emits exactly one telemetry event regardless of which exit path it takes. Previously, ~50 `process.exit()` calls in `src/commands/*.ts` bypassed the `try/finally` in `src/cli.ts`, so failure paths (`scan` with findings, `verify` FAIL/WARN, `doctor` unhealthy, every command's error branch) emitted no telemetry. Adoption metrics were biased toward "everything always works." All command handlers now return their exit code; `process.exit()` lives only in `main().then()` at `src/cli.ts:178`. Exit codes preserved across the surface (including `vault exec` upstream-process exit, `run` child-process exit). The `hook --check-only` fast path retains its silent-and-fast contract intentionally and is excluded from telemetry by design.

## [0.16.0] - 2026-04-27

### Added
- Tier-1 anonymous usage telemetry via `@opena2a/telemetry@0.1.2` and `@opena2a/cli-ui@0.4.0`. `secretless-ai --version` now prints the disclosure line; `secretless-ai telemetry [on|off|status]` inspects/toggles. Disable per-invocation with `OPENA2A_TELEMETRY=off`, persistently with `secretless-ai telemetry off`, audit payloads with `OPENA2A_TELEMETRY_DEBUG=print`. README §Telemetry documents the schema and links to [opena2a.org/telemetry](https://opena2a.org/telemetry). Default ON; opt-out is one env var or one subcommand.
- `docs/testing/release-smoke.md` — first release-smoke for this repo, covering build/help/version + the seven telemetry checks.

### Changed
- `src/cli.ts` `main()` is now async to support `await tele.flush()` before `process.exit()` (prevents subcommand telemetry events from being lost on exit). The dispatcher logic moved into a sync `dispatch()` helper to keep the case statement compact.
- First runtime dependency: `@opena2a/telemetry` + `@opena2a/cli-ui`. Previously the package had only devDependencies.

## [0.15.1] - 2026-04-22

### Changed
- **Release pipeline**: secretless now publishes via npm Trusted Publishing with SLSA v1 provenance. GitHub Actions exchanges an OIDC token with the npm registry at publish time — no long-lived `NPM_TOKEN` in the repo or workflow. Consumers verify provenance via `npm view secretless-ai dist.attestations --json`.
- **Lockfile sync**: `package-lock.json` realigned with `package.json` after a prior drift where the lockfile stayed at 0.14.1 during the 0.15.0 bump.

## [0.15.0] - 2026-04-14

### Added
- **Broker AIM auth**: `broker start --aim-token <token>` (or `SECRETLESS_AIM_TOKEN` env var) sends `Authorization: Bearer` on AIM requests. Without it, AIM returns 401 and trust-score / capability policy constraints cannot be satisfied.
- **Broker AIM reachability probe**: on startup, the broker pings AIM `/health` once and reports the result via `aimReachable` in `/status` and `broker status` output.
- **Audit log for AIM 4xx responses**: AIM 4xx failures now emit an `aim_auth_error` audit event (was silently swallowed). Helps diagnose auth misconfiguration.

### Changed
- `broker status` now displays `AIM: not configured` / `AIM: configured (reachable)` / `AIM: configured (unreachable)` instead of the misleading `AIM: connected`. **BREAKING**: the `aimConnected` field in `BrokerStatus` is split into `aimConfigured` (was `--aim-url` passed) + `aimReachable` (actually responded). Downstream TypeScript consumers of `BrokerStatus` will need to update.
- `broker status` CLI queries the running daemon over its HTTP `/status` endpoint to report live `Policies`, `Requests`, `aimConfigured`, `aimReachable` counts. Previously reported cached zeros from the PID file.

### Fixed
- `broker status` no longer reports `Policies: 0 / Requests: 0 / AIM: not connected` regardless of live state.
- `scan-staged` (pre-commit hook) now applies the same known-example-key allowlist as `scan`. Previously, docs or CHANGELOG entries that referenced public example keys like `AKIAIOSFODNN7EXAMPLE` could trigger false-positive commit blocks.
- `isKnownExample` operator precedence: the comment-marker check used `A && B || C` which bound as `(A && B) || C`, causing any line containing `#` to enter the inner block regardless of 'example' context. Fixed to `A && (B || C)` (#50).
- Known-example keys no longer shadow real credentials on the same line. Both the cross-pattern case (e.g. `AKIAIOSFODNN7EXAMPLE` + real `ghp_…` on one line) and the within-pattern case (two AWS keys, first example second real) are now detected. Scanner iterates every match via `matchAll` instead of breaking at the first (#51).
- `scan --help`, `init --help`, `broker start --help` and every other `<subcommand> --help` now print help instead of running the subcommand. Previously `init --help` created a literal `--help/` directory in the user's cwd and `broker start --help` launched the daemon.

### Documentation
- New README "Architecture" section names the three tiers (SDK, Vault Exec, Broker) and states that AIM is optional — Tiers 1 and 2 work against any supported backend.
- New guide `docs/use-cases/bring-your-own-vault.md` — connect Secretless to an existing HashiCorp Vault / 1Password / GCP Secret Manager with round-trip verification using stock vault tooling.
- New guide `docs/use-cases/run-broker.md` — when to run the broker daemon, how to write policies, AIM-connected mode, audit log.
- `team-setup.md` now flags the 1Password desktop biometric prompt on first `backend` run.

## [0.14.0] - 2026-04-01

### Added
- **NanoMind guard integration**: MCP protection now screens env var values for prompt injection patterns (role-switching, instruction override). Warns during `protect-mcp` when suspicious values are detected.
- **NanoMind engine integration**: `scan --explain` generates rich context-aware explanations for each finding using NanoMind's local inference engine.
- Both integrations are optional. NanoMind packages are optional dependencies with graceful fallback when not installed.

## [0.13.0] - 2026-04-01

### Added
- **False positive reduction**: Known example keys (AWS `AKIAIOSFODNN7EXAMPLE`, Stripe test keys, etc.) and placeholder patterns (`your_`, `example`, `fake_`) are now excluded from scan results
- **Scan fix guidance**: Each finding includes actionable fix text with rotation URLs (e.g., "Move to env var ANTHROPIC_API_KEY. Rotate at console.anthropic.com")

### Changed
- Split `commands/secrets.ts` (409 lines) into `secrets.ts` (234) + `env-run.ts` (177)
- TypeScript upgraded to 6.0.2, vitest to 4.1.2
- tsconfig: `module` and `moduleResolution` set to `Node16`

### Fixed
- All 5 npm audit vulnerabilities resolved (esbuild/vite chain via vitest 4.x)

## [0.12.7] - 2026-04-01

### Added
- Source code scanning: `scan` now detects hardcoded credentials in `.js`, `.ts`, `.py`, `.go`, `.java`, `.rb`, and 10+ more file types by walking the project tree
- Test files (`.test.*`, `.spec.*`, `__tests__/`) are excluded by default -- use `--include-tests` to opt in
- `rules test` auto-detects bash command patterns when starting with known commands (`curl`, `wget`, `ssh`, `aws`, `docker`, etc.)

### Changed
- Split `cli.ts` (2336 lines) into 12 focused modules under `src/commands/` for maintainability
- `watch` with no subcommand now shows usage help instead of silently starting
- `setup --check` with no `.secretless` manifest now returns failure instead of misleading PASS

### Updated
- typescript: ^5.3.0 -> ^5.9.3
- vitest: ^1.2.0 -> ^2.1.9
- @types/node: ^25.2.3 -> ^25.5.0

## [0.12.5] - 2026-03-18

### Changed
- `verify` hides unset env vars by default — shows count with `--all` flag to list them
- Transcript findings collapsed by credential type (e.g., "found in 16 transcript files")

### Added
- Quick start section in `--help` output (scan -> init -> verify)

## [0.12.4] - 2026-03-14

### Fixed

- Fix `--only` flag case-insensitive matching in `run` command -- `--only shodan_key` now correctly matches secrets stored as `SHODAN_KEY`

## [0.12.3] - 2026-03-12

### Security

- Replace SHA-256 key derivation with scrypt + random salt for MCP backup encryption
- Add bearer token authentication to credential broker HTTP transport
- Add HMAC-SHA256 integrity protection to session state files
- Fix Windows shell injection in `doctor --fix` (execFileSync instead of execSync)
- Add XML escaping for LaunchAgent plist generation to prevent injection
- Add symlink traversal protection in transcript directory walker
- Add response size limits (1 MB) to AIM client to prevent memory exhaustion
- Restrict file permissions on wrapper installation (0o700 dirs, 0o600 files)
- Add security headers (X-Content-Type-Options, Cache-Control) to broker responses
- Move rate limiter evaluation after other policy checks to prevent slot exhaustion
- Add secret name validation regex to prevent injection via malformed names

## [0.12.2] - 2026-03-11

### Fixed

- YAML parser key regex now handles underscores, hyphens, and numbers in section names
- Improved error messages for `secret set` and `scan` when given invalid paths

### Changed

- Documentation updates for custom deny rules

## [0.12.1] - 2026-03-11

### Fixed

- `rules import` command ENOENT error when importing rules files
- Distinguish between empty and missing rules files in validation

### Added

- `--env`, `--file`, and `--bash` flags to `rules test` for targeted rule testing

## [0.12.0] - 2026-03-11

### Added

- Custom deny rules via `.secretless-rules.yaml` configuration files
- User-defined patterns for blocking env vars, files, and bash commands
- `rules` CLI command with `init`, `list`, and `test` subcommands

## [0.11.7] - 2026-03-11

### Security

- Block `python3`/`node` env var extraction in hooks
- Block `eval`-based credential extraction attempts

## [0.11.6] - 2026-03-11

### Security

- Encrypt MCP backup files with AES-256-GCM

## [0.11.5] - 2026-03-11

### Fixed

- `--force` flag parsing order in `secret get` CLI command

## [0.11.4] - 2026-03-10

### Added

- GCP Secret Manager backend (`gcp-sm`)
- Graceful fallback when configured backend (1Password, Vault) is unavailable

### Fixed

- `migrate` command failing to find secrets from keychain/1Password backends
- Vault env var validation before migration
- Vault status display in `backend` command

### Security

- Harden against adversarial bypass attempts

## [0.11.0] - 2026-03-04

### Added

- v2 session management with phantom refs for automatic cleanup
- Structured audit events for secret access tracking
- Cache preloading to eliminate 1Password Touch ID popups
- AWS scope discovery and shell history scanning
- Per-key service names in keychain backends

### Fixed

- Touch ID authentication using LAContext via compiled Swift binary
- Dead-end CLI outputs now include actionable hints
- Duplicate vault creation in 1Password backend
- 1Password approval dialog now shows "Secretless" instead of "terminal"

### Changed

- Hardened `.gitignore` with additional secret and environment patterns

## [0.10.0] - 2026-03-02

### Added

- Credential scope discovery (detect where each secret is used)
- HashiCorp Vault backend for secret storage
- `scope` CLI command for viewing credential usage

## [0.9.2] - 2026-03-02

### Added

- `broker start`, `broker stop`, `broker status` CLI commands
- TTL-based encrypted cache for keychain/1Password backends to reduce OS auth prompts

## [0.9.0] - 2026-03-02

### Added

- `env` command for loading vault secrets into shell sessions
- Auto shell hook for transparent secret injection
- Broker service for identity-aware credential mediation

## [0.8.2] - 2026-02-27

### Fixed

- `secret set` hanging in interactive TTY mode

## [0.8.1] - 2026-02-26

### Changed

- Add star prompt and link to meta repository

## [0.8.0] - 2026-02-23

### Added

- OS keychain backend (macOS Keychain, Linux Secret Service)
- 1Password backend for secret storage and retrieval
- `secret get`, `secret set`, `secret list`, `secret delete` commands
- `backend` command for switching between storage backends
- MCP configuration protection (backup and sanitize MCP config files)

## [0.7.1] - 2026-02-18

### Added

- Shell profile doctor command (`doctor`) for diagnosing profile issues
- Cross-platform shell profile detection and auto-fix during `init`

## [0.7.0] - 2026-02-18

### Added

- `doctor` command for shell profile diagnostics

## [0.6.2] - 2026-02-17

### Fixed

- Use global regex in `transcript clean` to redact all occurrences of a credential

### Changed

- Ecosystem header banner with cross-links to related tools

## [0.6.0] - 2026-02-10

### Added

- MCP secret protection: detect and block credential exposure in MCP tool calls

## [0.5.0] - 2026-02-10

### Added

- Expanded credential pattern library from 12 to 49 patterns
- Coverage for AWS, Azure, GCP, Stripe, Twilio, SendGrid, and more

## [0.4.0] - 2026-02-10

### Added

- Transcript credential scanning and redaction (`transcript scan`, `transcript clean`)

### Fixed

- Complete redaction of partial credential matches
- Tightened Azure credential pattern to reduce false positives

## [0.3.1] - 2026-02-09

### Fixed

- Security findings: complete redaction and tighter Azure pattern matching

## [0.2.0] - 2026-02-09

### Added

- Global config scanning (`.env`, shell profiles, git configs)
- `verify` command for checking environment protection status
- Environment variable hints in scan output

### Changed

- Renamed package from `secretless` to `secretless-ai`

## [0.1.1] - 2026-02-09

### Fixed

- Homepage URL in package.json
- CLI package name references

### Added

- README documentation

## [0.1.0] - 2026-02-09

### Added

- Initial release: one-command AI secret protection
- Shell hook (`secretless-guard.sh`) for intercepting credential access
- Credential pattern matching for common API key formats
- `init` command for automated setup
- `scan` command for detecting exposed credentials

[0.12.2]: https://github.com/opena2a-org/secretless/compare/v0.12.0...HEAD
[0.12.1]: https://github.com/opena2a-org/secretless/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/opena2a-org/secretless/compare/v0.11.7...v0.12.0
[0.11.7]: https://github.com/opena2a-org/secretless/compare/v0.11.6...v0.11.7
[0.11.6]: https://github.com/opena2a-org/secretless/compare/v0.11.5...v0.11.6
[0.11.5]: https://github.com/opena2a-org/secretless/compare/v0.11.0...v0.11.5
[0.11.4]: https://github.com/opena2a-org/secretless/compare/v0.11.0...v0.11.5
[0.11.0]: https://github.com/opena2a-org/secretless/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/opena2a-org/secretless/compare/v0.9.2...v0.10.0
[0.9.2]: https://github.com/opena2a-org/secretless/compare/v0.8.2...v0.9.2
[0.9.0]: https://github.com/opena2a-org/secretless/compare/v0.8.2...v0.9.2
[0.8.2]: https://github.com/opena2a-org/secretless/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/opena2a-org/secretless/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/opena2a-org/secretless/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/opena2a-org/secretless/compare/v0.6.2...v0.7.1
[0.7.0]: https://github.com/opena2a-org/secretless/compare/v0.6.2...v0.7.1
[0.6.2]: https://github.com/opena2a-org/secretless/compare/v0.6.0...v0.6.2
[0.6.0]: https://github.com/opena2a-org/secretless/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/opena2a-org/secretless/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/opena2a-org/secretless/compare/v0.2.0...v0.4.0
[0.3.1]: https://github.com/opena2a-org/secretless/compare/v0.2.0...v0.4.0
[0.2.0]: https://github.com/opena2a-org/secretless/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/opena2a-org/secretless/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/opena2a-org/secretless/releases/tag/v0.1.0
