# secretless-ai release smoke test

**Run before every tag push to `v*`. ~20 minutes by hand.**

Every item came from a real bug or regression. Don't skip without writing down why.

Run every command from the local build, not the global install. Several commands
operate on **machine-global state** (the secret store, `~/.zshenv`, shell
history, MCP configs). The steps below flag each one and use throwaway names or
isolated `$HOME` so a smoke run never damages the operator's real setup.

**The binary is `dist/cli.js`.** Take it from `package.json` `bin`, never from
habit: `dist/index.js` is this package's LIBRARY entry, it registers no commands,
and it prints nothing and exits 0 for every invocation including `--version`.
A walkthrough scripted against it produces a full sheet of exit-0 rows with no
output, which is indistinguishable from a clean pass. Two people hit this in one
day. Before trusting any sheet, confirm at least one row produced real output.

**Build from a clean checkout of the commit you intend to tag**, not from the
incrementally-built working tree. An incremental `dist/` is not the build
artifact of any particular commit, and the walkthrough certifies whatever
happens to be on disk.

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

`--help` anywhere in the args must short-circuit to top-level help: `scan
--help` must NOT run the scanner and `init --help` must NOT create files
(regression: release-test 2026-04-14).

---

## 2. Core protection walkthrough (3 min)

Build the planted credential at runtime. A literal real-shaped key in this
doc would trip GitHub push protection and our own scanners, and short "fake"
strings like `sk-fake-deadbeef` do NOT match the patterns (verified 2026-07-16:
scan correctly ignores them, so they make this walkthrough fail spuriously):

```bash
SL="node /path/to/secretless-ai/dist/cli.js"
TMP=$(mktemp -d) && cd "$TMP"
PLANT="sk-ant-api03-$(openssl rand -base64 48 | tr -d '/+=' | head -c 51)"
echo "const k = \"$PLANT\";" > config.js

$SL status .        # "Not protected" verdict; every ⚠ row ends in a → command
$SL init .          # Configured: Claude Code; Created: hooks + settings.json (147 deny patterns) + CLAUDE.md; no Modified: section
$SL scan .          # 1 credential found: HIGH Anthropic API Key, config.js:1, value REDACTED in preview; exit 1
$SL status .        # verdict flips to "Protected (...)"
$SL verify .        # scope disclosure line + PASS/WARN with next steps
```

Fail if any command crashes, prints a stack trace, or the verdict does not
flip after `init`.

### 2a. JSON contracts (issue #63)

```bash
$SL scan . --json | python3 -m json.tool >/dev/null && echo scan-json-ok
$SL scan . --format sarif | python3 -c "import sys,json; d=json.load(sys.stdin); \
  assert d['version']=='2.1.0'; print('sarif results:', len(d['runs'][0]['results']))"
$SL status --json . | python3 -m json.tool >/dev/null && echo status-json-ok
$SL status --json . | python3 -c "import sys,json; d=json.load(sys.stdin); \
  assert d['tool']=='secretless-ai'; \
  assert d['summary']['verdict'] in ('not-protected','protected-clean','protected-warnings'); \
  print('verdict:', d['summary']['verdict'])"
```

- `scan --json`: single JSON document on stdout (`{tool, version, findings,
  summary}`). Exit 1 when findings exist (CI gating), 0 when clean.
- `scan --format sarif`: single SARIF 2.1.0 document on stdout, one result per
  `--json` finding (`ruleId` is the `patternId`); the same exit codes as `--json`.
  `--format yaml`, and `--json` beside `--format sarif`, are refused with exit 2.
- `status --json`: single JSON document (`{tool, version, isProtected,
  protectionScope, enforcement, hookInstalled, hookWired, denyRuleCount, detectedTools,
  configuredTools, ignoreFileTools, secretsFound, scanIncomplete, settingsUnreadable,
  settingsAmbiguous, userSettings, transcriptProtection, exposuresOpen, gitCredentials, backend,
  configuredBackend, gcpProject, session, broker, summary}`).
  Exit 0; CI consumers gate on `summary.verdict`.
- Neither may print the human banner or any ANSI color in JSON mode.

### 2b. Unknown-flag rejection (issues #62 / #74 / #81 / #83 / #126 / #137)

**Run every flag row on BOTH a clean tree and a tree with a finding.** A tree
that contains a credential exits 1 for that reason, so it cannot tell you
whether a flag changed anything. This exact confound put "`scan --nosuchflag`
-> exit 1, warns and continues" on the record as evidence that warn-and-continue
was safe. On a clean tree the same command exited 0 and said `No hardcoded
credentials found.` The 1 was never the flag.

```bash
mkdir -p /tmp/sl-clean && : > /tmp/sl-clean/app.ts       # clean tree
$SL init --dry-run; echo "exit=$?"        # "Unknown option: --dry-run", exit 2, NO --dry-run/ dir created
$SL status --bogus; echo "exit=$?"        # rejected, exit 2
$SL scan /tmp/sl-clean --show-placeholder; echo "exit=$?"   # REFUSED, exit 2, names --show-placeholders
$SL scan /tmp/sl-clean; echo "exit=$?"                      # CONTROL: exit 0, "No hardcoded credentials found."
$SL scan-staged --no-ignoree; echo "exit=$?"                # REFUSED, exit 2 (the pre-commit gate)
$SL bogus-command; echo "exit=$?"         # "Unknown command", a pointer to --help, exit 2
$SL scna; echo "exit=$?"                  # "Unknown command: scna (did you mean `scan`?)", exit 2
```

`scan`, `scan-staged` and `scan-history` refuse an unrecognised flag: their
output is the answer, so a dropped flag is a wrong verdict rather than a wasted
run. `feedback` and `diff` still warn: they report no verdict. The
`secretless-mcp` wrapper still warns, because its argv lines live in hand-edited
client configs where a refusal is a server that will not start.

### 2c. `--json` is honored or refused (issue #126)

```bash
$SL scan /tmp/sl-clean --json | head -c 40; echo " exit=$?"   # JSON, exit 0
$SL status /tmp/sl-clean --json | head -c 40                  # JSON
$SL verify --json; echo "exit=$?"      # REFUSED, exit 2, names scan and status
$SL cache --json; echo "exit=$?"       # REFUSED, exit 2 (pre-fix: status page, exit 0)
$SL doctor --json; echo "exit=$?"      # REFUSED, exit 2
```

Check both argv positions (`scan --json <dir>` and `scan <dir> --json`), since
this checklist uses the leading form and `docs/commands.md` uses the trailing one.

The one that matters: pre-fix, `verify --json` resolved `--json` as the project
directory and printed `AI context: clean (no credentials found)` for a directory
whose `CLAUDE.md` held a live key.

---

### 2d. status tells three states apart (settings key collisions)

```bash
# A settings file whose permissions key appears TWICE loses every deny pattern in
# the first copy -- in Claude Code, which is what enforces them.
$SL status /path/with/duplicated-key --json | jq ".denyRuleCount, .settingsAmbiguous"
#   null
#   { "path": ".claude/settings.json", "reason": "repeats ..." }
$SL status /path/with/duplicated-key      # NO green check on that file
```

`denyRuleCount` is `number | null`: null in BOTH unknown states (would not parse, or
keys collide), a number only when it was actually measured. Check the three states are
distinguishable from the JSON alone (measured / settingsUnreadable / settingsAmbiguous)
and that no row renders green over a file in either unknown state. Do NOT verify a
collision with `grep` or `node -e JSON.parse`: both exit 0 on a duplicate and print
nothing. Also run it against a REAL settings file from a dev tree, not only fixtures:
a false positive here is a warning on the tool own status page.

---

### 2e. status and init name the mode (enforced, ignore file, advisory)

```bash
ADV=$(mktemp -d) && mkdir "$ADV/.windsurf"
$SL init "$ADV"      # under Configured: "Advisory: Windsurf (instruction file, nothing enforces it)"
$SL status "$ADV"    # verdict: "Advisory only: instructions for Windsurf, which nothing enforces (...)"
$SL status --json "$ADV" | jq ".isProtected, .enforcement, .summary.verdict"
#   true
#   "advisory"
#   "protected-warnings"
AID=$(mktemp -d) && touch "$AID/.aider.conf.yml"
$SL init "$AID"      # under Configured: "Ignore file: Aider (.aiderignore, no hook enforces it)"
$SL status "$AID"    # verdict: "Ignore file only: ..."; never "Not protected" after init
UNW=$(mktemp -d) && mkdir "$UNW/.claude" && $SL init "$UNW"
echo '{}' > "$UNW/.claude/settings.json" && rm "$UNW/CLAUDE.md"   # guard script stays, nothing runs it
$SL status "$UNW"    # row: "⚠ Claude Code guard script not run: ... → secretless-ai init"
                     # verdict: "Not enforced: the guard script is on disk and no settings file runs it. ..."
$SL status --json "$UNW" | jq ".isProtected, .enforcement, .hookInstalled, .hookWired"
#   true
#   "none"
#   true
#   false
$SL init "$UNW" && $SL status --json "$UNW" | jq ".enforcement, .hookWired"
#   "hook"
#   true
```

`enforcement` is `hook | ignore-file | advisory | none`: the strongest mechanism
`isProtected` rests on. `hookInstalled` says the guard script is on disk; `hookWired`
says `.claude/settings.json` runs it. `enforcement` is `hook` only when a settings file
that reaches the project runs the guard or carries deny patterns. Fail if the verdict
line prints `Protected` for a project where no settings file runs the guard and none
carries deny patterns, if `init` and
`status` disagree about any of these directories, or if a `Claude Code hook not installed` row
in these projects ends in a bare `secretless-ai init`, which installs no hook there.

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
- the piped `secret set` above changes `~/.zshenv` / `~/.bashrc`, or
  `secret set SMOKE_TEST_KEY_DELETEME --no-shell-hook` in a terminal asks a
  question or changes them
- `secret set SMOKE_TEST_KEY_DELETEME` in a terminal, on a home with no hook,
  does not ask `Add a hook to ~/.zshenv that exports every stored secret in
  each new shell? [y/N]` before writing; Enter or `n` changes the profile; or,
  after a `y`, the profile lacks the line after
  `# secretless-ai: auto-load secrets from vault`, which runs
  `'<node>' '<path>/dist/cli.js' env`, or a new shell with no `secretless-ai`
  on PATH does not receive the secret:
  `env -i HOME="$HOME" PATH=/usr/bin:/bin zsh -c '[ -n "$SMOKE_TEST_KEY_DELETEME" ] && echo set || echo unset'`
  prints `unset` (use `bash -c '. ~/.bashrc; ...'` on Linux)

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
HEALTHY/DEGRADED/BROKEN verdict line, or, when no key is found in the
environment or in a shell profile, exit 0 and end with
`No keys stored yet. Store one: npx secretless-ai secret set NAME` if the
store holds no secret, or with a line naming how many secrets the store holds
(`The secret store (<backend> backend) holds N secrets. List them: npx secretless-ai secret list`)
if it holds some.
`--fix` is only exercised when a
DEGRADED verdict appears (it edits real shell profiles).

---

## 5. Git integration (2 min)

```bash
cd "$TMP" && git init -q
$SL hook status                     # "Pre-commit hook: not installed" + install hint
$SL hook install                    # "Pre-commit hook installed."; .git/hooks/pre-commit exists
grep scan-staged .git/hooks/pre-commit  # this build's node and dist/cli.js paths, quoted; never a bare `npx secretless-ai`
echo "const s = \"$PLANT\";" > staged.js && git add staged.js
$SL scan-staged; echo "exit=$?"     # finds the planted credential, "Remove the secrets and try again.", non-zero exit
git rm --cached staged.js -q && rm staged.js
$SL diff main 2>&1 | head -3        # in a repo with no secretless-managed changes: clean/empty audit
cd / && $SL diff 2>&1 | head -3     # outside a repo: friendly "Not a git repository" + git init hint, no stack trace
```

---

## 6. Shell history (1 min)

Read-only / dry-run against the operator's real history: safe, but do NOT
run the destructive form during smoke.

```bash
$SL scan-history                    # Files scanned: N; findings show [service] + file:line, values masked
$SL clean-history --dry-run         # "(dry run)" in header; "Files that would change" / "Lines that would be redacted" counts; file NOT modified
```

Fail if `scan-history` prints raw credential values (previews must be masked)
or `--dry-run` modifies the history file (compare mtime).

---

## 7. MCP protection (1 min)

**Read-only during smoke.** Do NOT round-trip `protect-mcp` by hand, and do
NOT try to sandbox it with an isolated `$HOME`: with no backend configured,
`createBackend('local')` silently upgrades to the OS keychain when the
platform supports it (`src/backends/factory.ts`), and macOS `security`
resolves the default keychain via `$HOME`, so an isolated `$HOME` pops a
blocking "Keychain Not Found" GUI dialog and hangs an unattended smoke
(verified 2026-07-16). Running `backend set local` in that `$HOME` first
selects the pure file backend (#327); the round-trip still belongs to the
unit suite below.

The protect → wrapper-injection → unprotect round-trip (including
byte-identical config restore and non-secret env vars staying untouched) is
covered by `src/mcp/e2e.test.ts` in the unit suite, which §0 already ran.

```bash
$SL mcp-status      # enumerates real clients without errors; exit 0
                    # unprotected servers show "! <name>: EXPOSED (N plaintext secret(s))" + a → command
```

Only exercise `protect-mcp`/`mcp-unprotect` manually (on the real `$HOME`,
against a client you actually use) when the diff touches `src/mcp/`, and
check the restored config with `git diff`-style comparison before and after.

---

## 8. Daemons + cache (1 min)

```bash
$SL broker status        # "Broker daemon is not running." (or PID + uptime if it is)
$SL install status       # "LaunchAgent: not installed" + install hint (macOS)
$SL cache                # Backend/TTL/Status; local backend says "Not needed"
```

Do not exercise `warm` in an unattended smoke: it triggers a Touch ID
prompt. `broker start`/`stop` round-trip is covered by unit tests; only
exercise it manually when the diff touches `src/broker/`.

---

## 9. Usage surfaces: no dead ends (1 min)

Each bare command must print usage/help with a runnable next step and exit
cleanly (no stack traces, no silent exits):

```bash
for c in rules scope vault ignore secret; do $SL $c; done
$SL feedback             # prints repo / issues / discussions links
```

---

## 10. Telemetry disclosure surfaces and opt-out (2 min)

**Do NOT point at the production endpoint while smoking**. Set
`OPENA2A_TELEMETRY_URL=http://127.0.0.1:1/never` so events go to a port that
refuses connections (proves fire-and-forget tolerance) instead of polluting
prod aggregates.

Nothing is sent while `CI`, a CI service's own variable or a test runner's
variable is set, so clear every one `src/telemetry-gate.ts` lists for 10.1 to
10.7; 10.8 sets one on purpose.

```bash
export OPENA2A_TELEMETRY_URL=http://127.0.0.1:1/never
unset OPENA2A_TELEMETRY CI CONTINUOUS_INTEGRATION GITHUB_ACTIONS GITLAB_CI \
  CIRCLECI TRAVIS BUILDKITE BITBUCKET_BUILD_NUMBER DRONE APPVEYOR JENKINS_URL \
  TEAMCITY_VERSION TF_BUILD CODEBUILD_BUILD_ID VITEST VITEST_WORKER_ID \
  JEST_WORKER_ID NODE_TEST_CONTEXT
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
| 10.8 | `CI=true OPENA2A_TELEMETRY_DEBUG=print secretless-ai status .` then `CI=true secretless-ai telemetry status` | No `[opena2a:telemetry]` line on stderr. The status shows `state: off` and `Off for this run: CI is set, and no usage event is sent from CI or a test runner.` |
| 10.9 | `rm -f ~/.config/opena2a/telemetry.json` then `OPENA2A_TELEMETRY=off secretless-ai --version` and `OPENA2A_TELEMETRY=off secretless-ai telemetry status` | `~/.config/opena2a/telemetry.json` is still absent. The status shows `state: off`, `install_id:  none (one is created on the first run with telemetry on)` and `Off for this run: OPENA2A_TELEMETRY is set to turn it off.` |
| 10.10 | `printf '{"enabled":true,"installId":"FAKE-INSTALL-ID"}\n' > ~/.config/opena2a/telemetry.json` then `OPENA2A_TELEMETRY=off secretless-ai --version` and `OPENA2A_TELEMETRY=off secretless-ai telemetry on` | After each command the file holds `{"enabled": true}` with no `installId`. `telemetry on` prints `install_id:  none (one is created on the first run with telemetry on)`. |

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
readers. Reading the page cannot tell you whether the CLI accepts it. Only
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

The root cause was never the flag. `init` is *allowed* to fail (that is the
whole point of the #122 fix), and an npm install-time lifecycle hook converts any
non-zero exit into a failed install. So the guard is now on the coupling:
`docs-commands.test.ts` fails if any doc wires a `secretless-ai` command into
`preinstall`, `install`, `postinstall`, `prepare` or `prepublish`. When you make
a command stricter, ask which documented automation consumes its exit code, not
only which documented command names still parse.

---

## 10c. Recorded walkthrough

The README links `docs/vhs/init.gif`, rendered from `docs/vhs/init.tape`. The
sidecar beside it, `docs/vhs/init.json`, names the version the recording shows
and, as `commit`, the commit HEAD named when the render started,
and `src/recording-sidecar.test.ts` fails while that version differs from the one
in `package.json`. A version bump is therefore followed by a render. Commit the
bump first: while the version is not on npm, the render installs `npm pack` of
the committed tree at HEAD, not the working tree. The script asks the registry
with `npm view` and packs HEAD only when the answer is E404; any other failure,
such as a registry npm cannot reach, stops the script and its dry run with exit
1 and npm's error code.

`docker build` and `docker run` use a docker configuration directory the script
creates and removes, which names no credential helper and holds no registry
credentials, so a render does not go through the credential helper of your own
docker configuration (Docker Desktop's keeps registry credentials in the OS
keychain). The base images are public. The script reads the endpoint of your
docker context with `docker context inspect` and passes it as `DOCKER_HOST`; a
`DOCKER_HOST` you set is kept.

```bash
docs/vhs/record-init.sh --dry-run   # image, base images, build, tape, fixture, files written, docker configuration; runs npm view, git status, git rev-parse and node, no docker, build or pack
docs/vhs/record-init.sh             # needs Docker; exits 2 if ANTHROPIC_API_KEY or OPENAI_API_KEY is set
```

The render's last line is `sidecar: docs/vhs/init.json sha256 <hash>, version
<version>, meteredCostUsd <cost>, wallClockSeconds <seconds>`; put that line in
the release record. Commit `docs/vhs/init.gif`, `docs/vhs/init-capture.txt` and
`docs/vhs/init.json`. The MP4 the render writes to `docs/vhs/out/` is ignored
and never committed. Check that `meteredCostUsd` on that line is `0` and that
`version` is the version you are tagging.

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
  docs/how-it-works.md ("N credential patterns from @opena2a/credential-patterns@x.y.z").
- Diff touches `src/broker/` or `src/grant/`: exercise the broker
  round-trip manually (`broker start` → grant flow → `broker stop`). The
  daemon lifecycle is not covered above.
- Diff touches `src/mcp/` or `mcp-wrapper.ts`: also smoke the `secretless-mcp`
  bin entry against a real MCP client config in isolated `$HOME`.
- Diff touches AIM / identity-vault integration (`src/vault-core.ts`,
  `vault` command): run the BYOV use-case doc
  (`docs/use-cases/bring-your-own-vault.md`) end to end.
- If a regression ships that would have been caught by an item NOT on this
  list: add the item here as part of the fix.
