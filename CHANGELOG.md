# Changelog

All notable changes to [secretless-ai](https://www.npmjs.com/package/secretless-ai) are documented in this file.

```bash
npm install -g secretless-ai
```

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Post-quantum broker assertions (AAP-SPEC 0.4 §8.2/§9.3/§9.4/§9.5, RFC 9964).**
  The broker now mints ML-DSA-65 (FIPS 204) assertions on two new paths:
  `mintBrokerAssertionMlDsa65` (compact `ML-DSA-65` JWT, the PQ-interop lane)
  and `mintHybridBrokerAssertion` (hybrid Ed25519 + ML-DSA-65 as JWS General
  JSON Serialization — one signature entry per suite over the same payload; a
  conformant verifier accepts only if every declared entry verifies and both
  suite families are present). New key surface: `generateBrokerPqcSigningKey`
  (seed-injectable, the FIPS 204 xi / RFC 9964 AKP `priv` form) and
  `brokerPublicAkpJwk` (RFC 9964 `AKP` public JWK for the discovery document).
  Signing is hedged by default and deterministic on request
  (`PqcMintOptions.deterministic`, required for byte-exact fixtures); tests
  prove sha256 byte-parity with the AAP spec repo's published fixtures across
  three independent FIPS 204 implementations. The existing compact EdDSA path
  is byte-for-byte unchanged. Serialization-profile decision:
  agent-authorization-protocol `decisions/2026-07-16-mldsa65-serialization-profile.md`.

### Changed
- **Node engine floor raised from `>=18.0.0` to `>=20.19.0`** — the ML-DSA-65
  suite loads the ESM-only `@noble/post-quantum` via `require(esm)`, supported
  since Node 20.19; Node 18 and 20 are both end-of-life. The dependency loads
  lazily: classical EdDSA minting never touches it, and requesting a PQ mint on
  an older runtime fails with an actionable error instead of `ERR_REQUIRE_ESM`.
- New dependency: `@noble/post-quantum` 0.6.1 (exact pin).

### Security
- **`scan`, `verify`, `status`, and `mcp-status` now cover the Claude Code
  project-scope MCP config `.mcp.json` (release-test P1).** The file sits at the
  project root and is committed to repos, yet none of the four surfaces read it:
  a planted Anthropic key inside `mcpServers.*.env` survived `scan` (exit 0),
  `mcp-status` ("No MCP configurations found"), and `verify` (PASS). The scan
  and verify file lists gain `.mcp.json` (via `@opena2a/credential-patterns`
  0.1.3, lockstep-asserted), and MCP discovery now enumerates the project-scope
  `.mcp.json` alongside the five per-user client configs, so `mcp-status`
  reports its servers and `protect-mcp` can wrap them.
- **`.cursor/mcp.json` is now actually scanned** — the config-file list carried
  a `.curse/mcp.json` typo since the entry was introduced, so Cursor's
  project-scope MCP config never matched (fixed in
  `@opena2a/credential-patterns` 0.1.3).
- **The scan list also gains `.mcp/config.json`, `.claude/settings.local.json`,
  and `.windsurf/mcp.json`**, and the global scan (`scan` without
  `--no-global`) now reads `~/.claude.json` (the store `claude mcp add` writes
  user-scope MCP `env` into) and `~/.cursor/mcp.json`. Known limit, disclosed:
  individual lines over 4096 chars are skipped by the ReDoS guard, so a fully
  minified config can pass unscanned — structural JSON parsing for config
  files is tracked as follow-up work.

### Fixed
- **Database connection-string patterns no longer flag credential-free URIs.**
  `postgresql://localhost:5432/mydb` — the canonical Postgres MCP server
  layout — produced `CRITICAL PostgreSQL Connection String` with nothing
  secret in it. The `mongodb`/`postgres`/`mysql`/`redis` patterns (via
  `@opena2a/credential-patterns` 0.1.3) now require an embedded secret: a
  userinfo password (`user:pass@`, `:pass@`), a
  `password=`/`pwd=`/`sslpassword=` query param (case-insensitive), or —
  redis only — any single userinfo token (`redis://your-password@host`; pre-ACL
  Redis has no usernames; the literal Redis 6+ ACL username `default@` is
  carved out). Plain `mongodb://` URIs are now covered (the old pattern
  matched only `mongodb+srv://`). Env-var-interpolated passwords
  (`postgres://app:${POSTGRES_PASSWORD}@db` — the shape this tool tells you
  to use) are no longer flagged, while a real password next to an
  interpolated host still is; matches cannot cross JSON string boundaries on
  minified content (no false positives, no destructive over-masking in
  `clean-history`); and every run is length-bounded so scheme-stuffed
  one-line files scan in linear time. Also fixes a quick-check derivation bug
  that silently skipped plain `redis://` lines containing a `${VAR}` — a real
  redis password on such a line was never scanned. Deliberate narrowing:
  username-only URIs for postgres/mysql/mongodb (`postgres://user@host`) no
  longer match — a username without a password is not a credential.

> Note: the ML-DSA-65 broker work above is intentionally unreleased. `0.19.1`
> was published as a hotfix off the `v0.19.0` tag (guard-hook hardening only),
> so the next release carrying this work must be `0.20.0` (minor), not `0.19.1`.

## [0.19.1] - 2026-07-16

### Security
- **The generated guard hook now inspects the full command instead of truncating at the first quote (#99).** The hook extracted the Bash command with `grep -o '"command":"[^"]*"'`, which stops at the first `"`. Any command containing a quote — `x="" ; cat .env`, `eval "$(secretless-ai env)"`, `echo ""; secretless-ai secret get X --force` — was truncated before the dangerous part and slipped past every hook guard. The hook now parses the command with `python3`'s JSON reader when available, and **fails closed**: on any extraction failure or empty output it falls back to the grep extraction rather than skipping guards. The `env` subcommand match also gained a proper word boundary, so it catches `$(secretless-ai env)` (terminated by `)`), `env;`, and `env|` while still ignoring the word `environment`. The native `permissions.deny` rules already enforced these at the Claude Code layer; this restores the guard hook as a real second layer rather than one a single quote walks through.
- **`secretless-ai vault exec <ns> -- env` / `-- printenv` is now blocked (#99).** `vault exec` injects an identity-vault namespace credential into the child process, which `env`/`printenv` would then print — the same shape as the already-denied `run -- env`, but it had no deny rule or hook arm. Added `Bash(*secretless-ai vault exec*-- env*)` / `-- printenv*` deny rules and a matching hook arm, with a word boundary so `-- envsubst` (a legit templating program) is not over-blocked.

These harden the best-effort Claude Code layers that back the primary tool-level `env` gate shipped in 0.19.0. Re-run `secretless-ai init` to regenerate the hook and deny rules. Two honest, adversarially-reviewed notes on the heuristic hook layer: (1) now that the full command is inspected, a benign command that merely *mentions* a secret-file path inside a quoted string (e.g. `git commit -m "fix cat .env parsing"`) is also flagged — safe-direction (it blocks, never leaks), recoverable by rephrasing, and the deliberate trade-off of not truncating; (2) command-string matching stays heuristic (e.g. a path-prefixed `-- /usr/bin/env` is not matched). The tool-level agent-runtime gate on `env` is the enforcing layer; the hook is defense-in-depth.

## [0.19.0] - 2026-07-16

### Security
- **`secretless-ai env` now refuses to print secrets when it runs inside an AI-agent runtime.** `env` dumps every stored secret as plaintext `export` statements — it exists only for the user's shell-profile `eval` hook, which runs in the user's own shell. `secret get` was TTY-guarded and `run -- env` was denied, but the bare `env` command was unguarded, so an agent in a "protected" project could exfiltrate the entire machine-global store with one documented command. The primary, spelling-independent fix is in the tool: `env` checks for a known agent-runtime marker (`CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CURSOR_TRACE_ID`, `AIDER_MODEL`) and, if set, emits nothing and points to `secretless-ai run --only NAME -- <cmd>` instead. Because the check is on the runtime, not the command text, it holds however the agent spells the invocation (`npx …@latest env`, quoted `env`, a shell variable, a tab) — every one of which slips past a deny-glob or a grep in the guard hook. The shell-profile hook is unaffected (no marker set in a normal shell); inside an agent shell, secrets no longer auto-load into the environment, so use `run --only` for the specific secret a command needs. Enumeration-limited by nature (it can only name agents that set a marker), so it is backed by two best-effort Claude Code layers below.
- **Best-effort Claude Code layers for the naive form: a `Bash(*secretless-ai env*)` deny rule and a guard-hook arm.** These block the literal `secretless-ai env` before it runs. They are heuristic, not airtight — a deny glob and a grep over the command string can be evaded by re-spelling — so they back the runtime gate above rather than standing alone. Known limits, tracked for follow-up: the deny glob also blocks benign strings containing `secretless-ai env` (e.g. `env --help`, a commit message), and the guard hook's grep-based JSON parsing is defeated by an embedded quote.
- **The generated guard hook's entire Bash-command branch was dead code; it now runs.** Every Bash tool call died at the `FILE_PATH` extraction under `set -euo pipefail` (a `grep` with no match returns non-zero) before reaching any command guard, so none of the hook's Bash protections (`cat .env`, `run -- env`, `secret get --force`, ...) ever fired. The JSON-field extractions now tolerate a no-match (`|| true`), reviving the branch. Native `permissions.deny` rules already enforced these at the Claude Code layer, so this restores the hook as a (best-effort) second layer rather than closing an open hole. Found by release-test 2026-07-16. Re-run `secretless-ai init` to regenerate the hook and deny rules.

### Fixed
- **`setup --check` prints a coherent report when no `.secretless` manifest exists (#97).** It used to render "Missing: 0 required", an empty "Missing secrets:" block, and a FAIL telling the user to configure secrets the same output said don't exist. The no-manifest path now stops after the create-a-manifest hint with a single `FAIL: No .secretless manifest to check against.` line. Exit codes unchanged (still 1, so CI gates keep failing on a missing manifest). Library surface: `SetupResult` gains `manifestFound`.
- **The broker assertion's `trust_class` claim now carries the abstract ATX trust class (e.g. `orders:read`) from the matched policy clause instead of duplicating the downstream `scope` (e.g. `orders.read`).** The two were conflated at minting, against the AAP broker profile §11 federation semantics — a v2 peer broker verifying the assertion needs the portable capability, not a deployment-local scope name. The grant resolver now injects the matched trust class into the resource binding (`ResourceBinding.trustClass`, resolver-populated, never authored in configuration); `mintBrokerAssertion` now throws if the field is missing rather than silently minting a token the pinned claim schema rejects (breaking only for direct library callers; the wired daemon path always injects). Regression-tested at the unit and end-to-end (conformance) layers. Pinned normatively by AAP-SPEC 0.3 §4.2.

### Added
- **`status --json` emits a machine-readable status document (#63).** Same envelope convention as `scan --json` (`{tool, version, ...facts, summary}`, camelCase); `summary.verdict` is one of `not-protected | protected-clean | protected-warnings` and `summary.warnings` always matches the human view's warning count (both derive from the same rows). Exit code stays 0; CI consumers gate on `summary.verdict`. `--help` now mentions `--json` on both `scan` and `status`.
- **`secret list` and `verify` disclose their scope (#89).** `secret list` names the backend and states the store is machine-global (shared across all projects); `verify` states it spans the project, global AI config (`~/.claude`), and current-shell env vars — so a green PASS is never mistaken for "this project only".
- **The broker strict-parses grant request bodies (#93).** `JSON.parse` is last-wins on duplicate members, so a duplicate-member smuggle inside the signed ATX credential was collapsed before the verifier could see it. `handleGrant` now runs atx-verify's fold-aware `firstDuplicateMember` over the raw body before any `JSON.parse` and refuses the request on the first colliding member at any depth (reject-side only; legitimate grants resolve unchanged). `@opena2a/atx-verify` bumped to 0.3.0, which also brings the declaredPurpose v1.1 TBS coverage fix into the broker's verify path.
- `mintBrokerAssertion` accepts an injectable `jti` (defaults to the existing 16-random-bytes-hex behavior) so conformance fixtures can be minted deterministically (AAP-SPEC §9.7).

### Docs
- **README now documents the secret workflow**: `secret set` / `import` / `run --only`, `secret get` TTY-gating, and how to ask an AI assistant to use a stored key without exposing its value. `docs/testing/release-smoke.md` expanded to full command-surface parity (#60), with every expected output verified against the built CLI.

### Changed
- **The ATX (Agent Trust eXtension) verifier now comes from `@opena2a/atx-verify` instead of a copy bundled in the broker.** The verifier was previously maintained as `src/broker/atx.ts` here *and* in the AIM SDK — two copies of byte-sensitive canonicalization (RFC 8785 JCS) that had to stay in lockstep with the Go/Python reference verifiers. It is now the single, separately-tested, SLSA-attested `@opena2a/atx-verify` package (consumed by both), closing that drift window. The broker's behavior is unchanged: the same Ed25519 verification over the same v1.0/v1.1 canonical payloads, proven by the AAP conformance test running against the package.

### Removed (breaking — library surface only; CLI unaffected)
- **`secretless-ai` no longer re-exports the ATX verifier *values* `LocalAtxVerifier`, `canonicalPayload`, `normalizeRfc3339`, and `SUPPORTED_ATX_VERSION`.** Import them from `@opena2a/atx-verify` directly (a CommonJS package cannot statically re-export the ESM-only verifier's values). The ATX *types* (`Atx`, `AtxVerifier`, `ResolutionContext`, `AtxTrustAnchors`, etc.) are still re-exported, since they appear in secretless's own public broker types. No CLI command or behavior changes.

## [0.18.2] - 2026-06-01

### Fixed
- **`init` now migrates an existing config instead of only appending to it.** Older `init` was additive-only: it appended new deny rules and wrote the guard hook only when absent, so upgrading the CLI did **not** propagate template/hook fixes to an already-initialized project — the broad `Read(.env*)` / `Grep(*.env*)` globs and a stale `secretless-guard.sh` survived, re-blocking `.env.example` while `init` reported "Already up to date". `init` now (1) prunes a known deprecated-rule list (`DEPRECATED_DENY_RULES`) after re-adding the current enumerated rules, so a real env file is never left unprotected, and (2) regenerates the managed guard hook and rewrites it in place when its content is stale. Output reports `removed N deprecated patterns` and `~ .claude/hooks/secretless-guard.sh (refreshed to current version)`; an already-current config is still a clean no-op (no churn on re-run).
- **`secretless-ai env` skips secret names that aren't valid shell variables instead of breaking the whole shell.** Stored secret names allow `-` (e.g. `vault-name`), but a shell identifier cannot — so `export vault-name='…'` made the shell reject the entire `eval "$(secretless-ai env)"`, printing `export: not valid in this context` on **every** command in profiles that use the eval hook, and silently dropping all the other secrets too. `env` now skips names that aren't valid POSIX shell identifiers (matching the validation `import` already applies), exports the rest normally, and reports the skipped names as a leading shell comment (a no-op inside `eval`, visible on direct invocation) that names them and how to fix — no secret value is exposed. Public API: `isValidShellIdentifier`.

## [0.18.1] - 2026-06-01

### Fixed
- **`scope` with no subcommand prints usage cleanly instead of an error.** Bare `secretless-ai scope` showed `Unknown scope command: (none)` and exited 1 (reads like an error for an empty invocation); it now prints the usage block and exits 0, mirroring the `secret` fix in #80. A real unrecognized subcommand (`scope bogus`) still errors with `Unknown scope command: bogus` and exits 1.
- **`scan` warns on an unrecognized flag instead of silently ignoring it (#81).** A typo like `--show-placeholder` (for `--show-placeholders`) used to no-op with no feedback. `scan` now prints `Warning: ignoring unknown flag --x` plus the supported-flag list. The warning is non-fatal — the exit code still reflects findings.
- **`secret` with no subcommand prints usage cleanly instead of an error (#80).** Bare `secretless-ai secret` showed `Unknown secret command: (none)` (which reads like an error for an empty invocation) and now prints the usage block and exits 0. A real unrecognized subcommand (`secret bogus`) still errors with `Unknown secret command: bogus` and exits 1.
- **`init` no longer blocks committed env template files (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`).** These hold placeholders, not real secrets, and are meant to be read/edited/committed, but the generated config blocked them three ways: the `Read(.env*)` / `Grep(*.env*)` deny globs, the guard hook's `.env.*` dotfile arm, and the `.aiderignore` `.env.*` entry. Deny rules now enumerate real env files (`.env`, `.env.local`, `.env.*.local`, `.env.{development,production,staging,test}`, `*.env`) instead of a broad `.env*` glob — Claude Code deny rules can't negate and `deny` beats `allow`, so enumeration is the only way to let templates fall through. The guard hook exempts `*.example` / `*.sample` / `*.template` / `*.dist` basenames before any block logic, and the generated `.aiderignore` un-ignores them. Real env files and other secrets stay blocked. Matches the env-file policy shipped to the user's global config.

## [0.18.0] - 2026-06-01

### Added
- **`scan --json` emits a single valid JSON document (issue #63).** Previously the flag printed the human report. Output is `{ tool, version, findings[], summary: { total, critical, high, placeholdersSuppressed } }` on stdout only (errors go to stderr); the exit code still signals findings (1) vs clean (0) for CI gating.
- **`scan --show-placeholders` and a "N values hidden" hint.** When the scanner suppresses values that look like known examples / placeholders (`AKIA…EXAMPLE`, `sk-…FAKE…`, `your_api_key`, an `example.com` connection string), it now reports how many were hidden and how to reveal them, instead of a silent "No hardcoded credentials found." This fixes the new-user trap of testing with obvious placeholder values and concluding the scanner is broken, and surfaces the over-suppression case where a real-looking value sits behind a documentation host.

### Fixed
- **`scan` and `verify` now use the same detection predicate, and `verify` no longer hides values silently (issue #64).** `verify` detected credentials in AI-context files with a raw `pattern.regex.test(line)` that applied no known-example / placeholder suppression, while `scan` routed through `findRealMatch` (which applies `isKnownExample`). A placeholder like `sk-ant-api03-FAKE…` in `.env` was suppressed by `scan` but flagged by `verify` — the two disagreed on the same file. `verify` now shares `scan`'s detection path. Because `verify` answers a higher-stakes question ("is a real key exposed right now?"), it also **counts and surfaces** suppressed values (`N values looked like a placeholder and were not counted — confirm with scan --show-placeholders`), so it never reports a green PASS while silently hiding a value whose random body happens to contain a token like `sample`/`xxx` or that sits on a `# example` line.
- **Guard hook now blocks secret files by extension suffix, not only literal dotfiles (security).** The generated `.claude/hooks/secretless-guard.sh` matched secret extensions with an anchored `^\.key`-style regex, so it blocked `.key`/`.env` but silently **allowed** the far more common `server.key`, `client.pem`, `id_rsa.pem`, and `prod.env` forms, and was case-sensitive, so `.KEY`/`server.PEM` bypassed it on case-insensitive filesystems. Matching is now a case-insensitive suffix check against the lowercased basename, with `.env` families and credential dotfiles handled explicitly. Added `Read(*.env)` / `Read(*.crt)` (and `Grep` equivalents) to the deny-rule backstop, closing the `prod.env` double-gap. Regression test feeds `server.key`/`prod.env`/`.KEY` to the generated hook and asserts deny.
- **Scanner now reads standalone private-key files (`*.pem`, `*.key`, `*.p12`, `*.pfx`).** These extensions were in the block list but were never fed to the scanner, so a private key in `server.key` or `id_rsa.pem`, the most common on-disk layout, reported clean. Text key files are scanned for a PEM `PRIVATE KEY` block (public certs in `.crt`/`.pem` do not match, so no false positive); binary PKCS#12 keystores are flagged by existence.
- **Confidence scoring no longer under-rates fixed-structure keys.** A real AWS access-key ID (`AKIA...`) displayed as `low (0.58)` because pattern specificity counted only the literal prefix, making the `high` tier unreachable for AWS / Stripe / Slack / GitHub keys. Specificity now also credits a fixed/bounded length quantifier over a restricted character class, and structurally-definitive patterns are floored at the `high` tier in real source/config locations (fixture and docs paths are left unfloored so demo creds don't outrank production ones). A fixed-structure AWS key in a source file now scores `high (0.85)`.
- **`diff` outside a git repository no longer dead-ends.** The "Not a git repository" message now explains what `diff` does and gives a next step (`git init`), satisfying the no-dead-ends rule.

## [0.17.0] - 2026-04-30

### Added
- **Per-finding confidence score on `ScanFinding`.** Every finding now carries a deterministic composite score in `[0, 1]` plus a tier label (`high` / `medium` / `low`). Inputs are pattern specificity (length of literal regex prefix), value entropy (Shannon over the matched value), value length tier, and path tier (live source / config files outrank docs and fixture paths). Renders inline as `Confidence: high (0.92)` so users can prioritise on noisy repos. Findings within the same severity are now sorted by descending confidence. Public API: `scoreFinding`, `formatConfidence`, `patternSpecificity`, `valueEntropy`, `lengthTier`, `pathTier`, `ConfidenceTier`, `ConfidenceBreakdown`. New CLI flag `scan --min-confidence <n>` (`n` in `[0, 1]`) drops findings below the threshold.
- **`secretless-ai ignore <path>` subcommand.** Convenience wrapper that appends a gitignore-style glob to `.secretlessignore`. Idempotent — re-running with the same pattern is a no-op. Creates the file with a header comment if it doesn't exist; otherwise appends and ensures a trailing newline. Validates input against path traversal (`..`), absolute paths, and symlinks at the target. Accepts an explicit `--pattern` form for non-path globs (`*.golden.txt`, `**/__fixtures__/**`).
- **`secretless-ai diff <ref>` subcommand.** Concrete change-set audit of secretless-managed files (`.claude/settings.json`, `.secretlessignore`, `.secretless-rules.yaml`) versus a git ref. Default ref is `HEAD`. Output is a unified-diff-like report with per-file `INTRODUCED` / `MODIFIED` / `REMOVED` / `UNCHANGED` tags. Missing or invalid refs return distinct exit codes (1 for malformed input, 2 for git errors). Refs are validated against `[A-Za-z0-9._/^@~+-]` only — shell metacharacters and refs starting with `-` are rejected; `execFileSync` is invoked with an argv array, never a shell string.
- **"Looks like a test fixture" inline hint** on `scan --no-ignore` findings whose path matches the default-ignore list. Helps users distinguish real-vs-fake findings without re-suppressing them. The hint is also exposed on the public `ScanFinding` interface as `looksLikeFixture: boolean`.

### Changed
- `ScanFinding` interface gained three required fields: `confidence: number`, `confidenceTier: 'high' | 'medium' | 'low'`, `looksLikeFixture: boolean`. Library consumers that destructure `ScanFinding` will need to handle the new fields (additive, not breaking — JSON consumers see strictly more keys).
- `printFindings` (CLI) renders the confidence tier under each finding. Tier colour mirrors the severity ramp — `high` green, `medium` yellow, `low` dim — so a low-confidence high-severity finding visually de-emphasises without disappearing.

### Internal
- New `src/confidence.ts` module + 32-test `confidence.test.ts` covering pattern-specificity escape handling, entropy noise floor, length-tier monotonicity, path-tier classification (Windows path normalisation, mixed-case, `*.test.ts` suffix), composite determinism, monotonicity-on-every-axis, and tier-rendering.
- New `src/commands/ignore.ts` + 20-test `ignore.test.ts` covering file creation, append behaviour, idempotence (whitespace and `./` normalisation), traversal rejection (Unix absolute, Windows drive prefix, parent traversal, nested `..`), symlink rejection, 1MB size cap, and non-file refusal.
- New `src/commands/diff.ts` + 14-test `diff.test.ts` exercising real `git init` repos in tmpdirs: clean diff, additions-only (synthesised diff for untracked files), mixed adds/mods, missing ref, malformed ref (shell metacharacter rejection, `-` prefix rejection, `..` rejection, length cap), not-a-git-repo handling.
- Test count: 915 → 988 (+73 new). Build is `tsc` clean. No public API removals.

## [0.16.4] - 2026-04-29

### Added
- `.secretlessignore` — gitignore-style file at the project root that suppresses scan findings for paths the user has marked as fixtures or examples. The default-ignore list is applied automatically on top of the user file and covers `__tests__/`, `__fixtures__/`, `test/`, `tests/`, `test-server/`, `docs/vhs/`, `examples/`, `e2e/`, `.golden/`, `node_modules/`, `dist/`, `build/`. Each default path is justified by a real-world false positive observed during dogfooding (e.g. `docs/vhs/setup-lab.sh` fixture credentials, `test-server/agents.js` adversarial system prompts). Negative patterns (`!docs/vhs/`) re-enable scanning for a default-ignored path. New CLI flag `--no-ignore` on `scan` and `scan-staged` disables both the user file and the defaults. Public API: `loadSecretlessIgnore`, `buildMatcher`, `DEFAULT_IGNORE_PATTERNS`, `IgnoreMatcher`.
- `secretless-ai feedback` — opt-in subcommand that prints the star/issue/discussion links. Replaces the unconditional "Helpful? Star the project" line that previously trailed every `init` invocation.

### Changed
- **`init` output redesigned** per CISO Rule 11. Collapsed the redundant Detected + Configured pair into one line (`Configured: Claude Code (1 of 1 detected)`); the previous `+` / `*` glyph distinction was confusing. The `Modified:` line now says exactly what changed (`.claude/settings.json (added 21 deny patterns)`) instead of just naming the file. Dropped the misleading `Done. Secrets are now blocked from AI context.` line — `init` configures hooks, the actual blocking happens at AI-tool invocation. Added a `Next steps:` block (Verify / Scan / Status) so every run ends in a runnable verb. Removed the unconditional star-prompt line from `init` output (now lives in `secretless-ai feedback`). `init` re-runs over an already-configured project now print `Already up to date. No files changed.` instead of an empty Created/Modified pair.
- **`status` output redesigned** per CISO Rule 11. The previous five sub-blocks (top-level metrics, Session, Broker, Transcript Protection, transcript line counts) collapsed into one Observations table. Every warning row ends in `→ <runnable command>` so the user has no dead end. Glyphs differentiate satisfied (`✓`) from needs-action (`⚠`). The Verdict line now reflects the warning count instead of a bare `Protected: Yes` — `Protected — Clean`, `Protected (4 unblocked credentials need review)`, `Not protected. Run secretless-ai init to install hooks.`
- **Catalog re-pin to `@opena2a/credential-patterns@0.1.1`** with three new false-positive suppression branches (mirrored locally to keep the lockstep test green): block-comment marker recognition for line-level `'''`/`"""`/`<!--`/`-->`/`*` (JSDoc continuation lines now allowlisted when paired with the substring `example`), bare `'fake'` in `PLACEHOLDER_INDICATORS` (replaces `'fake_'` and `'fake-'` — case-insensitive substring match accepts `sk-proj-fake1234567890abcdefghijklmnop`), and a localhost-bound demo-password allowlist for connection strings (`postgres://admin:password123@localhost`/`@127.0.0.1`/`@[::1]` recognized as tutorial fixtures).
- `init` `InitResult` interface gained `denyRulesAdded` (delta this run) and `denyRulesTotal` (full count after merge). The existing `denyRuleCount` on `StatusResult` is unchanged.

### Internal
- New `src/secretlessignore.ts` parser (gitignore-subset glob → regex) plus 18-test `secretlessignore.test.ts` covering defaults, user file, negation, glob semantics, anchor rules, Windows path normalization, and path-traversal rejection. New `scan()` integration tests assert default-ignore suppression of fixture paths and `--no-ignore` round-trip.
- `walkSourceFiles` now consults the ignore matcher at directory level (prunes whole subtrees) and again at file level (file-name globs).

## [0.16.3] - 2026-04-29

### Added
- Runtime dependency on `@opena2a/credential-patterns@0.1.0` (exact pin). PR 1 of the credential-pattern consolidation lifted the local pattern catalog into a shared, SLSA-attested package so secretless-ai and hackmyagent stop maintaining duplicate regex copies. This release brings the package in as a peer of the local catalog and asserts they stay in lockstep.
- `src/lockstep.test.ts` — equivalence test that fails CI on any drift between local `src/patterns.ts` and the package: pattern count, per-pattern (`id`, `name`, `regex.source`, `regex.flags`, `envPrefix`, `category`), `CREDENTIAL_PREFIX_QUICK_CHECK`, `KNOWN_EXAMPLE_KEYS`, `PLACEHOLDER_INDICATORS`, `SECRET_FILE_PATTERNS`, `CONFIG_FILES`, `SOURCE_FILE_EXTENSIONS`, `SOURCE_SKIP_DIRS`, plus functional parity of `isKnownExample` / `findRealMatch` on a panel of allowlist-branch oracle inputs. Mutation-tested: a regex change or allowlist addition on either side fails this test with a precise per-pattern diagnostic.

### Changed
- No behavior change. No public API change. `import { CREDENTIAL_PATTERNS } from 'secretless-ai'` still resolves to the local CommonJS-friendly catalog. `scan` / `verify` / `init` / `transcript` / `mcp` / `doctor` / `history` / `scan-staged` paths continue to read from `src/patterns.ts`. The full migration that moves consumer code onto the package directly requires converting secretless-ai from CommonJS to ESM (the package is ESM-only) and is tracked separately for a future major version.

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
