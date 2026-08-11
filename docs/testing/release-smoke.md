# secretless-ai release smoke test

**Run before every tag push to `v*`. ~20 minutes by hand.**

Every item came from a real bug or regression. Don't skip without writing down why.

Run every command from the local build (`node dist/cli.js`), not the global
install. Several commands operate on **machine-global state** (the secret
store, `~/.zshenv`, shell history, MCP configs) — the steps below flag each
one and use throwaway names or isolated `$HOME` so a smoke run never damages
the operator's real setup.

---

## 0. Build + tests (2 min)

```bash
cd secretless-ai
git status                 # clean, or only the branch you intend to ship
npm ci                     # lockfile valid
npm run build              # zero output, zero errors
npm test                   # all green (baseline: 1206 tests)
```

Fail the release if any step is red.

---

## 1. Help and version (1 min)

```bash
node dist/cli.js --help     # prints the full help block; no telemetry line here
node dist/cli.js --version  # prints two lines: version + telemetry disclosure
```

The `--version` output must be exactly two lines:

```
secretless-ai 0.x.x
Telemetry: on (opt-out: OPENA2A_TELEMETRY=off  •  details: opena2a.org/telemetry)
```

If the second line is missing, the `versionLine()` helper isn't wired or the
SDK init failed silently.

`--help` anywhere in the args must short-circuit to top-level help — `scan
--help` must NOT run the scanner and `init --help` must NOT create files
(regression: release-test 2026-04-14).

---

## 2. Core protection walkthrough (3 min)

Build the planted credential at runtime — a literal real-shaped key in this
doc would trip GitHub push protection and our own scanners, and short "fake"
strings like `sk-fake-deadbeef` do NOT match the patterns (verified 2026-07-16:
scan correctly ignores them, so they make this walkthrough fail spuriously):

```bash
SL="node /path/to/secretless-ai/dist/cli.js"
TMP=$(mktemp -d) && cd "$TMP"
PLANT="sk-ant-api03-$(openssl rand -base64 48 | tr -d '/+=' | head -c 51)"
echo "const k = \"$PLANT\";" > config.js

$SL status .        # "Not protected" verdict; every ⚠ row ends in a → command
$SL init .          # Configured: Claude Code; Created: hook + CLAUDE.md; Modified: settings.json (~86 deny patterns)
$SL scan .          # 1 credential found: HIGH Anthropic API Key, config.js:1, value REDACTED in preview; exit 1
$SL status .        # verdict flips to "Protected (...)"
$SL verify .        # scope disclosure line + PASS/WARN with next steps
```

Fail if any command crashes, prints a stack trace, or the verdict does not
flip after `init`.

### 2a. JSON contracts (issue #63)

```bash
$SL scan . --json | python3 -m json.tool >/dev/null && echo scan-json-ok
$SL status --json . | python3 -m json.tool >/dev/null && echo status-json-ok
$SL status --json . | python3 -c "import sys,json; d=json.load(sys.stdin); \
  assert d['tool']=='secretless-ai'; \
  assert d['summary']['verdict'] in ('not-protected','protected-clean','protected-warnings'); \
  print('verdict:', d['summary']['verdict'])"
```

- `scan --json`: single JSON document on stdout — `{tool, version, findings,
  summary}`. Exit 1 when findings exist (CI gating), 0 when clean.
- `status --json`: single JSON document — `{tool, version, isProtected,
  hookInstalled, denyRuleCount, configuredTools, secretsFound,
  transcriptProtection, backend, session, broker, summary}`. Exit 0; CI
  consumers gate on `summary.verdict`.
- Neither may print the human banner or any ANSI color in JSON mode.

### 2b. Unknown-flag rejection (issues #62 / #74 / #81 / #83)

```bash
$SL init --dry-run; echo "exit=$?"    # "Unknown option: --dry-run", exit 2, NO --dry-run/ dir created
$SL status --bogus; echo "exit=$?"    # rejected, exit 2
$SL scan --show-placeholder .         # WARNS about the unknown flag (typo of --show-placeholders), still scans
$SL bogus-command; echo "exit=$?"     # "Unknown command", help block, exit 1
```

`init`/`status` reject unknown flags (filesystem footgun — pre-fix, `init
--ci` created a literal `--ci/` directory). `scan` warns-but-runs so a typo'd
flag never hides scan results.

---

## 3. Secret lifecycle (3 min)

**Machine-global state.** The store is one per machine, shared across
projects. Use the throwaway name below and remove it at the end.

```bash
echo "smoke-value-123" | $SL secret set SMOKE_TEST_KEY_DELETEME   # "Stored: SMOKE_TEST_KEY_DELETEME"
$SL secret list                        # name appears; "Scope: global (<backend> backend)" note; values never printed
$SL run --only SMOKE_TEST_KEY_DELETEME -- node -e \
  "console.log('injected:', !!process.env.SMOKE_TEST_KEY_DELETEME)"   # injected: true
$SL env --only SMOKE_TEST_KEY_DELETEME # emits: export SMOKE_TEST_KEY_DELETEME=...
$SL secret get SMOKE_TEST_KEY_DELETEME | cat; echo "exit=$?"
# BLOCKED (non-TTY): "secret values cannot be read in non-interactive contexts", exit 1
$SL secret rm SMOKE_TEST_KEY_DELETEME  # "Removed: SMOKE_TEST_KEY_DELETEME"
```

Also verify import parses without keeping anything:

```bash
echo 'SMOKE_IMPORT_KEY_DELETEME=fake-import-value' > "$TMP/.env.smoke"
$SL import "$TMP/.env.smoke"           # imports 1 secret
$SL secret rm SMOKE_IMPORT_KEY_DELETEME
```

Fail the release if:
- `secret get` piped (non-TTY) prints the value without `--force`
- `secret list` or any command prints a stored secret VALUE
- `run --only` fails to inject, or injects keys outside the `--only` set
- `secret set` does not install the shell hook on first use (check
  `~/.zshenv` / `~/.bashrc` for `eval "$(secretless-ai env 2>/dev/null)"`)

---

## 4. Manifest + doctor (1 min)

```bash
cd "$TMP"
$SL setup --check; echo "exit=$?"   # no .secretless manifest -> hint + exit 1 (CI contract)
printf 'SMOKE_TEST_KEY_DELETEME\n' > .secretless
$SL setup --check; echo "exit=$?"   # missing required secret -> FAIL, exit 1
$SL doctor                          # Platform/Shell + per-profile key counts + health verdict
```

`doctor` must label exactly one profile RECOMMENDED and end with a
HEALTHY/DEGRADED/BROKEN verdict line. `--fix` is only exercised when a
DEGRADED verdict appears (it edits real shell profiles).

---

## 5. Git integration (2 min)

```bash
cd "$TMP" && git init -q
$SL hook status                     # "Pre-commit hook: not installed" + install hint
$SL hook install                    # "Pre-commit hook installed."; .git/hooks/pre-commit exists
echo "const s = \"$PLANT\";" > staged.js && git add staged.js
$SL scan-staged; echo "exit=$?"     # finds the planted credential, "Remove the secrets and try again.", non-zero exit
git rm --cached staged.js -q && rm staged.js
$SL diff main 2>&1 | head -3        # in a repo with no secretless-managed changes: clean/empty audit
cd / && $SL diff 2>&1 | head -3     # outside a repo: friendly "Not a git repository" + git init hint, no stack trace
```

---

## 6. Shell history (1 min)

Read-only / dry-run against the operator's real history — safe, but do NOT
run the destructive form during smoke.

```bash
$SL scan-history                    # Files scanned: N; findings show [service] + file:line, values masked
$SL clean-history --dry-run         # "(dry run)" in header; Lines redacted count; file NOT modified
```

Fail if `scan-history` prints raw credential values (previews must be masked)
or `--dry-run` modifies the history file (compare mtime).

---

## 7. MCP protection (1 min)

**Read-only during smoke.** Do NOT round-trip `protect-mcp` by hand, and do
NOT try to sandbox it with an isolated `$HOME`: `createBackend('local')`
silently upgrades to the OS keychain when the platform supports it
(`src/backends/factory.ts`), and macOS `security` resolves the default
keychain via `$HOME` — so an isolated `$HOME` pops a blocking "Keychain Not
Found" GUI dialog and hangs an unattended smoke (verified 2026-07-16). There
is no CLI flag that forces the pure file backend on macOS.

The protect → wrapper-injection → unprotect round-trip (including
byte-identical config restore and non-secret env vars staying untouched) is
covered by `src/mcp/e2e.test.ts` in the unit suite, which §0 already ran.

```bash
$SL mcp-status      # enumerates real clients without errors; exit 0
                    # unprotected servers show "! <name>: EXPOSED (N plaintext secret(s))" + a → command
```

Only exercise `protect-mcp`/`mcp-unprotect` manually (on the real `$HOME`,
against a client you actually use) when the diff touches `src/mcp/` — and
check the restored config with `git diff`-style comparison before and after.

---

## 8. Daemons + cache (1 min)

```bash
$SL broker status        # "Broker daemon is not running." (or PID + uptime if it is)
$SL install status       # "LaunchAgent: not installed" + install hint (macOS)
$SL cache                # Backend/TTL/Status; local backend says "Not needed"
```

Do not exercise `warm` in an unattended smoke — it triggers a Touch ID
prompt. `broker start`/`stop` round-trip is covered by unit tests; only
exercise it manually when the diff touches `src/broker/`.

---

## 9. Usage surfaces — no dead ends (1 min)

Each bare command must print usage/help with a runnable next step and exit
cleanly — no stack traces, no silent exits:

```bash
for c in rules scope vault ignore secret; do $SL $c; done
$SL feedback             # prints repo / issues / discussions links
```

---

## 10. Telemetry disclosure surfaces and opt-out (2 min)

**Do NOT point at the production endpoint while smoking** — set
`OPENA2A_TELEMETRY_URL=http://127.0.0.1:1/never` so events go to a port that
refuses connections (proves fire-and-forget tolerance) instead of polluting
prod aggregates.

```bash
export OPENA2A_TELEMETRY_URL=http://127.0.0.1:1/never
unset OPENA2A_TELEMETRY
rm -f ~/.config/opena2a/telemetry.json   # start clean
```

| # | Command | Expected |
|---|---------|----------|
| 10.1 | `secretless-ai --version` | Two lines: `secretless-ai 0.x.x` then `Telemetry: on (opt-out: ...)` |
| 10.2 | `secretless-ai telemetry status` | Prints `state: on`, install_id, config path, policy URL, toggle hint |
| 10.3 | `secretless-ai telemetry off` | Prints `Telemetry disabled for secretless-ai.` Then `--version` shows `Telemetry: off`. `~/.config/opena2a/telemetry.json` has `"enabled": false`. |
| 10.4 | `secretless-ai telemetry on` | Re-enables persistently. |
| 10.5 | `OPENA2A_TELEMETRY=off secretless-ai telemetry status` | Shows `state: off` even though file says `on` (env wins). |
| 10.6 | `OPENA2A_TELEMETRY_DEBUG=print secretless-ai status .` | Stderr contains a `[opena2a:telemetry]` line with the JSON payload (`tool: "secretless-ai"`, `event: "command"`, `name: "status"`, `success: true`, `duration_ms: <int>`, no PII fields). |
| 10.7 | `secretless-ai status .` (with the unreachable URL) | Command completes normally. Telemetry endpoint unreachable must not slow the command perceptibly (≤2s timeout). |

Fail the release if:
- any disclosure line is omitted
- the persisted config file leaks anything beyond `enabled` and `installId`
- the debug-print payload contains scanned secrets, file paths, env-var
  values, rule contents, or any field outside the locked schema (tool,
  version, install_id, event, name, success, duration_ms, platform,
  node_major)
- a command blocks more than 2 seconds when the telemetry endpoint is
  unreachable

---

## 10b. Documented commands must exist (1 min)

Every command the README and `docs/` tell a user to run is copied verbatim by
readers. Reading the page cannot tell you whether the CLI accepts it — only
running it can.

```bash
npm test -- src/docs-commands.test.ts   # derives the command list from cli.ts
```

This is covered by a unit test, so §0 already ran it. Exercise it by hand only
when the release **tightens a parser**: a stricter validator turns previously
silent doc errors into hard failures. Precedent (0.21.0): making `init` reject
unknown flags (#62) meant the team-setup guide's documented postinstall hook
(which passed `--ci` to `init`) began exiting 2, failing `npm install` for
every developer on a team that followed it.

**The same hook broke a second time in 0.21.3, and the first fix could not have
caught it.** #122 made `init` exit 1 on a `.claude/settings.json` it cannot
parse. No flag is involved, so the flag guard added in 0.21.0 stayed green while
`npm install` failed again for anyone whose settings file had a comment in it.

The root cause was never the flag. `init` is *allowed* to fail — that is the
whole point of the #122 fix — and an npm install-time lifecycle hook converts any
non-zero exit into a failed install. So the guard is now on the coupling:
`docs-commands.test.ts` fails if any doc wires a `secretless-ai` command into
`preinstall`, `install`, `postinstall`, `prepare` or `prepublish`. When you make
a command stricter, ask which documented automation consumes its exit code, not
only which documented command names still parse.

---

## 11. Cleanup

```bash
unset OPENA2A_TELEMETRY_URL
rm -rf "$TMP"
$SL secret list   # confirm no SMOKE_* names remain
# Restore your real telemetry config if you had one — the tests above
# overwrite ~/.config/opena2a/telemetry.json.
```

---

## When this checklist isn't enough

- Diff touches `src/patterns.ts` or bumps `@opena2a/credential-patterns`:
  re-run the lockstep tests and re-verify the pattern count claimed in
  README.md ("N credential patterns from @opena2a/credential-patterns@x.y.z").
- Diff touches `src/broker/` or `src/grant/`: exercise the broker
  round-trip manually (`broker start` → grant flow → `broker stop`) — the
  daemon lifecycle is not covered above.
- Diff touches `src/mcp/` or `mcp-wrapper.ts`: also smoke the `secretless-mcp`
  bin entry against a real MCP client config in isolated `$HOME`.
- Diff touches AIM / identity-vault integration (`src/vault-core.ts`,
  `vault` command): run the BYOV use-case doc
  (`docs/use-cases/bring-your-own-vault.md`) end to end.
- If a regression ships that would have been caught by an item NOT on this
  list: add the item here as part of the fix.
