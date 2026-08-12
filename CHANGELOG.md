# Changelog

## [Unreleased]

Credential disclosure and integrity. Three defects a credential manager should
not carry, plus what sweeping their shape across the code turned up.

**Behavior change worth reading before you upgrade.** Reads that used to return
"nothing" on failure now fail closed. If the local store cannot be decrypted, if
the keychain will not answer, or if the name index is malformed, the command
exits non-zero and says so instead of reporting an empty store. If you have
automation that treats "no secrets" as a normal outcome, it will now see an
error in the cases where the tool never actually read anything.

**`secret set` now refuses a mangled value.** Null bytes, U+FFFD and control
characters other than tab, newline and carriage return are rejected rather than
stored. Multi-line secrets (PEM keys, service-account JSON) are unaffected.

**Your cache is invalidated once on upgrade.** Cached values are now tied to the
build that read them, so the first resolve after upgrading re-reads from the
backend. Expect one extra unlock prompt.

### Fixed

- **The on-disk cache served values written by a previous build ([#118](https://github.com/opena2a-org/secretless-ai/issues/118)).** Upgrading specifically to fix a corrupted credential returned the corrupted credential for another five minutes, because the cache had no idea which build wrote what. The TTL bounds how stale a value may be and says nothing about how it was read; #107 fixed a read path that corrupted most 32-hex secrets and changed no file format, so nothing invalidated what the broken build had cached. A fix the user cannot observe is indistinguishable from no fix, and this one actively taught them the tool was broken. Entries now carry the identity of the build that wrote them and are dropped unless it matches. Version alone is not the build — a working tree, a global install and an `npx` unpack can report the same version while running different code — so the install location is folded in.

- **`cache clear` cleared a directory the cache stopped using in 0.12.3.** It deleted the abandoned file, printed `Cache cleared`, and left every live entry in place. It is also the workaround #118 documents, so the one published remedy for a stale cached credential was a no-op that reported success. Both locations are cleared now, off the same default the backend writes to. Clearing the pre-0.12.3 file matters on its own: it is an encrypted file of credential values that nothing reads and nothing expires.

- **A cache marker that outlived its entries reported a successful resolve of nothing.** The marker asserts "this prefix is fully resolved" and was guarded by a condition that is true for every possible value, so `run` could inject no secrets at all and exit 0. Measured on 0.21.3. The marker now carries the count it was written with.

- **An unreadable local store was read as an empty one ([#104](https://github.com/opena2a-org/secretless-ai/issues/104)).** `resolve` caught every failure and returned nothing, so `run`, `status`, `verify` and manifest checks all reported success over a credential set they never saw, with exit 0 and empty stderr. Empty and unreadable are different states and the code cannot tell them apart by guessing. A store that is absent is still empty — that is a real first-run state — but one that is present and will not decrypt now fails closed, naming the store, the reason, and the two inputs its key derives from.

- **`secret set` destroyed the store when it could not read it.** The read failure was swallowed with "start fresh" and a one-entry store was written over the top. Measured: three secrets stored, then one `set` from an account that could not decrypt the store, and all three are gone — while the command printed `Stored: NAME` and exited 0. The original account's key still worked right up to that write, so the data was recoverable until the tool destroyed it.

- **The store format version was written on every save and checked nowhere.** A store written in a format this build does not understand would be decrypted, parsed as whatever it parsed as, and served. It is now checked before the decrypt, and a store with no version file is still read — that is a store from a build that never wrote one, not a mismatch.

- **`doctor` and `verify` called the local store healthy because the file existed.** Presence was the entire check, so the one state it exists to catch — a store that is there and unreadable — was the state it called healthy. `secret rm` likewise reported "no such secret" against a store it could not read.

- **A locked keychain made every secret read as missing.** `security` exits 44 for "the specified item could not be found"; every other failure, including a locked login keychain and a dismissed approval dialog, was read the same way. Only 44 means absent now.

- **A malformed name index reported an empty keychain.** The index is how the backends answer "what secrets exist", since the OS keychain has no such query. Any failure reading it returned an empty list, so `secret list` printed nothing and `run` injected nothing over a keychain that still held every secret. Only a missing file means "no secrets yet".

- **A keychain read that could not establish the encoding returned the raw value.** macOS hex-encodes binary passwords, and `-w` output alone cannot say whether it did. When the check that settles it does not complete, returning the raw value hands back the hex transcript of the credential rather than the credential — silently, exit 0. There are three answers to that question, not two, and the third is now a refusal.

- **`run` printed a secret value to stderr ([#117](https://github.com/opena2a-org/secretless-ai/issues/117)).** Node rejects an environment value containing a null byte and puts the value in the message. The throw is synchronous, so the handler meant to catch spawn failures never saw it, and the message went to stderr unredacted — which is what CI logs capture. Such a value is not exotic: macOS returns binary passwords hex-encoded, and they decode to bytes containing a null. Values are now checked before the spawn, so the error names every unusable secret and only its name, and the spawn is wrapped for anything a different Node version rejects that we did not anticipate.

- **The redaction backstop missed escaped and truncated values.** It compared whole values and whole lines, and runtimes embed neither: Node escapes control bytes and truncates long values, `JSON.parse` quotes the first ten characters. Measured against all three throws this tool actually hits, whole-value containment reports no leak over a message displaying most of the credential. Detection now works on runs of the value, in any escaping, and the macOS Keychain write path uses the same detector.

- **A mangled paste was stored without comment ([#104](https://github.com/opena2a-org/secretless-ai/issues/104)).** A 40-character hex token pasted at the interactive prompt was stored as 19 bytes of control characters and U+FFFD — the terminal's own bracketed-paste sequences captured into the value — and surfaced much later as a type error inside an unrelated consumer. Values are validated at the store boundary, so `set`, `import` and the MCP write path are all covered. Every successful write now prints the shape: length and character class, never content.

### Known issues

- On Linux, `secret-tool` failures are still read as "not found". Separating that from "could not read" needs exit codes that could not be measured on the machine this was fixed on, and a guessed mapping is worse than a recorded gap. The macOS path is fixed.

## [0.21.3] - 2026-08-11

Closes the `init` data-loss defect disclosed as a known issue in 0.21.2, plus
three more places where the same shape appeared: a file we could not parse or
could not open was treated as a file with nothing in it.

**Behavior change worth reading before you upgrade:** `init` now exits 1 and
changes nothing when `.claude/settings.json` cannot be merged into, instead of
replacing it. `scan` now exits 1 when a file was skipped for exceeding the
per-file size cap, the same way it already does for the file-count cap and for
unreadable paths. Both were previously exit 0.

**If you run `init` from a `postinstall` hook, move it before you upgrade.** Our
own team-setup guide recommended that wiring until this release. Because `init`
now exits 1 on a `.claude/settings.json` it cannot parse, and `npm` fails the
whole install when `postinstall` exits non-zero, a single developer's JSONC
settings file will stop `npm install` from completing for them. Run it as an
explicit script instead (`"protect": "secretless-ai init"`, then `npm run
protect`), so the failure is visible and actionable without blocking dependency
installation. Do not paper over it with `|| true` — that restores exactly the
silent success this release removes. `docs/use-cases/team-setup.md` is updated
with the exit-code table.

### Fixed

- **`init` destroyed `.claude/settings.json` when it did not parse as strict JSON, and reported the merge as successful ([#122](https://github.com/opena2a-org/secretless-ai/issues/122)).** The read helper collapsed "file absent" and "file present but unparseable" into the same `null`; the caller turned that into `{}` and wrote it back, so every user key was replaced by a Secretless-only document with no backup — while the run printed `added 96 deny patterns` and exited 0. The trigger is JSONC (`//` comments, trailing commas), which is what VS Code writes and what people hand-edit into that file, so the failure landed on files that looked normal to their owner.

  `init` now leaves such a file byte-identical, names the parse error, states that no deny patterns and no hook wiring were installed, and exits 1. The `Verify:` and `Fix:` lines are specific to which of the three failures occurred — a syntax error, valid JSON that is not an object, or a file that could not be opened at all. They have to be: a settings file whose top level is `null`, an array or a string is *valid JSON*, so a `JSON.parse` check exits 0 on it, and printing that as the verify step for every refusal would tell the user their file was fine while `init` refused it, under advice to remove comments the file does not contain. Each printed command is now executed by the test suite against the shape it is printed for, and against a healthy file, rather than asserted as a string. It does not list Claude Code as configured, because the guard script on disk is inert until settings.json references it — reporting it as configured would have been the same false success one line further down.

  Three neighbouring shapes reached the same write path and are fixed with it. A settings file containing valid JSON `null` took the overwrite branch. An **array** was worse than data loss: properties assigned to an array are dropped by `JSON.stringify`, so `init` wrote the array back unchanged while reporting 96 deny patterns added — a project left completely unprotected with a success message and nothing destroyed to prompt a second look. A **string** or number threw a raw `Cannot create property 'hooks' on string` at the user with no file named and no fix. A file that is empty or whitespace-only is still configured normally: it provably holds no user content.

- **`status` reported an unparseable `.claude/settings.json` as zero deny patterns.** "No rules configured" and "could not read the rules" rendered identically, so a project whose protection was never wired up looked exactly like a healthy one — and the ✓ next to `Claude Code hook installed` was keyed on the guard script merely existing on disk, not on anything having wired it in. `status` now reports the parse failure as a warning with a verify command, exposes `settingsUnreadable` in `--json`, and does not claim `isProtected`.

- **Setting the backend or the cache TTL silently reset the other one when `~/.secretless-ai/config.json` did not parse.** Same collapse as #122 in a smaller file: the read-modify-write started from `{}` on a parse failure, so `backend set` dropped `cacheTtl` and `cache set` reverted the backend to `local`. For a tool that decides where credentials get written, quietly resetting that choice is the defect, not the recovery. Both writers now refuse, name the file and the parse error, and leave it unchanged.

- **Files over the per-file size cap were skipped with no warning ([#120](https://github.com/opena2a-org/secretless-ai/issues/120)).** A config file over 10 MB or a source file over 1 MB was dropped with no `truncated`, no `unreadable` and no output of any kind. Measured: an 11 MB `config.json` with a live-shaped Google key on line 1 scanned to `total: 0`, `truncated: false`, exit 0. The cap bounds memory use and says nothing about the contents — the same bytes under it produce a finding — so this closes the size-cap gap in the class 0.21.2 was working through. It is not the last one: see the `status` transcript fix below, and the open scope gap in `Known issues`. Skipped files are now listed with their size and the cap, counted in `summary.oversize` and `oversizeFiles` in `--json`, and set exit 1.

- **`status` reported every discovered transcript as scanned, turning a three-file sample into a clean verdict.** It printed `Transcripts clean (8850 files scanned)` while having read three of them — `transcriptFiles` was a discovery count rendered as a scanned count. Measured on a real machine during this release's testing: that line printed while `clean --dry-run`, over the same 8850 files, found 882 credentials in 168 of them. Sampling is deliberate and stays (a full pass takes tens of seconds; `status` answers immediately), but the scope is now stated: `No credentials in the 3 most recent transcripts (8850 found; the rest were not read)`, with `clean --dry-run` offered as the full check. `--json` gains `transcriptFilesScanned` alongside `transcriptFiles`. Present in 0.21.2 and earlier; it is the same confident-zero-over-unread-content defect as the rest of this release, on the headline verdict surface.

- **The MCP wrapper told users to run a command that does not exist.** When the vault directory was missing, `secretless-mcp` printed `Run 'npx secretless-ai mcp-protect' to set up MCP secret protection` and exited 1. The command is `protect-mcp`, so following the instruction printed `Unknown command: mcp-protect` and exited 1 again — a dead end on an error path, where the user is already stuck. Present in 0.21.2 and every earlier version. Fixed, and the class is now covered: a test cross-references every command the tool suggests in its own output against the commands `cli.ts` actually dispatches. Markdown was already checked this way; the tool's own output strings were not, which is why this survived.

### Added

- **`scan --max-file-size <size>`** raises the per-file cap (`20mb`, `500kb`, or a byte count), so a reported skip has a fix and not only a name. One value applies to config and source files alike. An unparseable value is refused with a warning rather than silently falling back — `--max-files` had shown that `parseInt` turns `1e6` into a cap of 1 while the user believes it was raised.
- **The scan triage flags are now listed in `--help`.** `--max-files`, `--max-file-size`, `--min-confidence`, `--show-placeholders`, `--no-ignore` and `--include-tests` were all absent, including the two that coverage warnings tell the user to run.

### Documentation

- **Three stale numbers in the README, all corrected and pinned.** A number in a sample output is read as the tool's actual behavior, so a stale one misdescribes the build the reader just installed. The sample `init` output claimed 86 deny patterns where the build writes 96; the feature list claimed 21 blocked file patterns where the hook layer enforces 18; and the test badge was a hardcoded `1333 passing` that had to be edited by hand to stay true, so it is now the live CI badge instead. The two counts and the sample version banner are pinned by tests that read the README and compare it against what the code actually produces, both sides derived at run time so neither can drift silently.
- **`docs/use-cases/team-setup.md` no longer wires `init` into a `postinstall` hook.** See the upgrade note above; the guide now uses an explicit `npm run protect` script and documents `init`'s exit codes.

### Known issues

- **`scan <dir>` skips every config file whose name is not on a 33-entry allowlist, and reports the result as clean ([#124](https://github.com/opena2a-org/secretless-ai/issues/124)).** Found by this release's own testing, in the same defect class the release is about, so it is called out here rather than left silent. 14 files in one directory each holding the identical key produced `total: 4` with `truncated: false` and no exclusion notice; `secrets.json`, `settings.json`, `creds.json`, `appsettings.json`, `.npmrc`, `Dockerfile`, `serverless.yml`, `values.yaml`, `app.toml` and `app.ini` were never read, while `config.json` and `config.yaml` were. Each missed file is detected correctly when named directly (`secretless-ai scan secrets.json` finds it), so this is file selection, not detection. Reproduces identically on 0.21.2 and earlier — not a regression in this release.

  Until it is fixed, `secretless-ai scan <file>` on a specific config file is reliable, and a directory scan should not be read as covering config formats beyond the allowlist. **This blocks 1.0.0**: the version will not ship with it open, per the v1 burndown, and widening the file set has to be measured in both directions because a noisier scan is its own failure mode.

### Internal

- The finding-dedup key in `src/scan.ts` held two raw NUL bytes written directly into the source rather than as escapes. The compiled string is unchanged; the source is no longer classified as binary by `grep`, `rg` and every diff viewer.

## [0.21.2] - 2026-08-06

Three defects that shipped in 0.21.1, two of them regressions introduced by that
release's own fixes. All three are cases where the scanner reported a clean or
complete result for work it had not done, so upgrade promptly.

**Behavior change worth reading before you upgrade:** a scan that could not read
everything no longer exits 0. If the file walk stops at the cap, or any file
cannot be opened, `scan` exits 1 and says `No credentials found in the files
scanned` instead of `No hardcoded credentials found`. A CI job over a tree larger
than the 5000-file cap that was passing will now fail until you raise
`--max-files` or narrow the path. Those passes were not earned: the walk stopped
early and the result was reported as clean.

### Known issues

- **`init` destroys `.claude/settings.json` when it does not parse as strict JSON, and reports the merge as successful ([#122](https://github.com/opena2a-org/secretless-ai/issues/122)).** Not introduced here — it reproduces identically on 0.21.1 — but disclosed rather than left silent, because it is the same defect class this release is about: a tool reporting success for work it did not do. The trigger is JSONC (`//` comments, trailing commas), which is what VS Code writes and what people hand-edit. A valid JSON settings file merges correctly and preserves every user key; only a parse failure clobbers, and no backup is written. If you keep comments in that file, back it up before running `init`. Fix targeted at 0.21.3.

### Fixed

- **A symlinked config file or directory was silently skipped (regression in 0.21.1).** `walkConfigFiles` classified entries with `Dirent.isDirectory()` / `isFile()`, which are `lstat`-based — a symlink is neither, so it fell through both branches and was dropped. 0.21.0 reached config files through `existsSync`/`statSync`, which follow links; making the config walk recursive removed symlink support without anything noticing.

  ```
  repo/.claude -> shared-claude/          # settings.json holds a live key
  0.21.0   exit 1   1 critical credential exposed
  0.21.1   exit 0   No hardcoded credentials found.
  ```

  This affected every `CONFIG_FILES` entry at any depth — `.env`, `.mcp.json`, `docker-compose.yml`, `terraform.tfvars` — and a symlinked `.claude/` is exactly what a dotfile manager or a shared monorepo config produces. Entries are now classified by following the link, and the three near-identical tree walks were collapsed onto one shared traversal: they had drifted apart, which is how the config copy gained recursion while losing the symlink handling, and sharing the walk means link handling, cycle safety and coverage reporting cannot diverge again.

  Three bounds come with it, because a repository is an untrusted input to a scanner.

  A directory is treated as a cycle only when it appears in its **own ancestor chain**. A global visited-realpath set also terminates, but it drops a directory reachable by a second path once the first is seen — which silently re-broke this very case whenever the link's target was itself in the tree, and which of the two paths won depended on readdir order.

  A **directory** link resolving outside the scan root is not followed, because otherwise a repo containing `link -> $HOME` makes `scan .` traverse the whole home directory; these are listed with the command to scan the target directly, so declining is never silent. A **file** link is still followed wherever it points: reading one file the repository explicitly names is bounded work, and `pkg/.env -> ../../shared/.env` is what stow, chezmoi and monorepo-root env files actually produce.

  Finally, the number of distinct paths through a lattice of links is exponential — a 15-level fixture reaches one directory 32,767 ways — so the number of routes followed to any one directory is capped, and crossing that cap reports the scan as incomplete rather than passing silently. Sockets, FIFOs and device files are never opened.

  Findings are deduplicated on the resolved file, so a credential reachable by several paths is one finding rather than one per path.

- **A scan that hit the file cap reported clean.** The walkers stopped at `maxSourceFiles` (default 5000) and returned quietly, so an incomplete scan was indistinguishable from a complete one — fewer findings, no signal, exit 0. Truncation is now reported through `ScanStats.truncated`, surfaced in the human output and in `--json` as `summary.truncated` alongside `summary.maxFiles`, and exits 1. Adds `--max-files <n>` so the warning has a runnable fix.

- **`.secretless` parse errors echoed credential values to stderr, twice.** The manifest is documented safe to commit, and `setup --check` stderr is exactly what lands in CI logs. A `NAME=VALUE` line echoed the whole line; a `NAME VALUE` line echoed it again interpolated into the error reason, which was also unbounded — so a 200 KB token flooded stderr through a field the 120-char line limit did not cover.

  Redaction is an allowlist by position rather than a character test. Secret names allow `[a-zA-Z0-9_-]`, so a live token is itself a valid name and no charset rule can tell the two apart; only position can. The reason now names the shape it saw (dotenv, YAML, JSON), which is more actionable than the echo it replaces:

  ```
  line 1: [redacted]
          looks like dotenv (NAME=VALUE) — .secretless declares names only, never values
  ```

  The first token is echoed only when the WHOLE token is a valid secret name. An earlier form of this fix split a `NAME=VALUE` paste and printed the left side, on the reasoning that in dotenv the left of `=` is the name — but `=` is also base64 padding, so for a secret from `openssl rand -base64 32` the "name" is the entire secret, and it was printed in full.

- **An unreadable file or directory was reported as clean, exit 0 (#116).** The same content, readable, produces a finding. A directory scan dropped the file from the count and a named target printed `No hardcoded credentials found`; a directory whose listing failed vanished with nothing recorded at all. Unreadable paths are now listed with a runnable `chmod` fix, counted in `--json` as `summary.unreadable`, and exit 1. A broken symlink still counts as nothing to scan, but `EACCES`/`ELOOP` on a link target is reported rather than skipped.

- **`status` and `vault scan` discarded the coverage signal.** Both call the same scanner and neither asked for it, so `vault scan` printed the unqualified `No hardcoded credentials found` over a tree it could not fully read — the exact string `scan` was fixed to stop printing — and `status --json` reported `secretsFound: 0` as though it were a verdict. `status --json` gains `scanIncomplete`.

- **`--max-files` accepted a value it then ignored.** `parseInt` stops at the first non-digit, so `--max-files 20abc` silently became a cap of 20 and `--max-files 1e6` a cap of 1: the user believed the cap was raised while the scan covered a fraction of the tree and exited 0. The value must now be all digits.

- **`.env` variants were mostly missed (#116).** `.env` and `.env.local` were detected; `.env.development`, `.env.production`, `.env.staging`, `.env.test` and `.env.prod` were not — the exact set named in the CLAUDE.md block Secretless itself installs. Any unrecognised `.env.*` is now scanned and only known template suffixes (`.example`, `.sample`, `.template`, `.dist`) are skipped, so the unknown case fails closed.

- **Config filenames were matched case-sensitively.** On macOS and Windows `Claude.md` and `CLAUDE.md` are the same file to the OS but not to an exact-match lookup, so a file the user could plainly see was skipped.

### Security

- **The `Verify:` and `Fix:` lines quote the paths they print.** Those paths are filenames from the scanned repository — attacker-controlled by definition — and the lines exist to be copy-pasted into a terminal. A symlink named `a"; id; echo "b` previously produced a command that closed the quote and ran `id`.

### Internal

- Two tests asserted nothing and were rewritten. One asserted a pattern that accepted the unfixed value it claimed to guard against; the other computed its expectation by calling the same function as the code under test, so a wrong answer was wrong identically on both sides. Both are now pinned against independent oracles and verified to fail on a mutant.

## [0.21.1] - 2026-08-06

Four defects that shipped in 0.21.0, plus issues #110, #111 and #112. Two of
these let a command report success while doing less than it said: `--include-tests`
reported clean on a tree it never scanned, and `run --only` ran commands with
credentials missing. Both are reasons to upgrade promptly.

### Fixed

- **`scan <file>` reported a clean result for a file containing a credential.** A file path was accepted, checked for existence, then walked as if it were a directory — which found nothing:

  ```
  $ secretless-ai scan single.js
    No hardcoded credentials found.          # exit 0
  $ secretless-ai scan .                     # the same file, via its directory
    1 credential found                       # exit 1
  ```

  `secretless-ai scan src/config.ts` in a CI step was therefore a green pass over a live credential. A named file is now scanned as that file. Because naming a path is an explicit instruction rather than a directory walk, neither the ignore list nor the test-file heuristics apply to it: those exist to keep a walk from being noisy, and there is no walk.

- **Config files were only found at the scan root.** Source files recursed; `config.json`, `docker-compose.yml`, `.mcp.json`, `terraform.tfvars` and the rest were matched only against the top directory. A monorepo, or anything under `deploy/` or `infra/`, reported clean at exactly the invocation everyone runs first, while the same scan from inside the subdirectory found the credential immediately.

  Config files are now found at any depth, including in the hidden directories where tool configs actually live (`.cursor/`, `.claude/`, `.vscode/`). Generated trees (`node_modules/`, `dist/`, `build/`) are still never walked, and `.secretlessignore` still applies.

- **`scan <a> <b>` silently scanned only the first path.** The second was dropped with no warning, and because the first path's findings still set exit 1, the run looked complete while an entire file went unscanned. It now exits 2 naming the paths it was given, rather than answering for input it ignored.

- **A single-file finding reported a path that did not resolve.** `scan deploy/prod/app.js --json` reported `file: "app.js"`, so a CI job annotating `file:line` from the JSON pointed at the wrong file or at nothing. It now reports the same path a directory scan does.

- **`status`, `cache` and `mcp-status` reported the configured backend rather than the one in use.** The same defect as #111, in the three surfaces that were not swept when `backend` was fixed. `cache` drew a wrong conclusion from it — `Status: Not needed (local backend has no auth prompts)` on a machine whose secrets go to the Keychain, which does prompt. All four surfaces now name the effective backend and agree; `status --json` gains a `configuredBackend` field alongside it.

- **`run --only ''` ran the command and exited 0.** An empty value read as "flag not supplied", so the filter vanished — while the semantically identical `--only ,,` correctly refused. Same input, opposite fail direction. A CI step computing `--only "$KEYS"` with an empty `$KEYS` ran unprotected and reported success. Both forms now fail closed.

- **`run --only` never checked that the names it was given were found (#110).** One root cause, three failure modes, and only the least harmful was loud.

  | store | `--only` matches | before |
  |---|---|---|
  | non-empty | nothing | exit 1, blamed the backend |
  | non-empty | some, not all | exit 0, ran a credential short, silently |
  | empty | anything | exit 0, ran with nothing injected |

  `loadSecrets` filtered what the backend *returned* and never iterated what it was *asked for*, so an unmatched name left no trace and was indistinguishable downstream from a name nobody requested. `run` then saw only a count of zero and reached for the one explanation it had — the backend — which was reachable the whole time.

  The third mode needs no user error at all: on a fresh machine or a CI runner whose store was never populated, `run --only DEPLOY_TOKEN -- ./deploy.sh` ran the deploy with no token and exited 0. The warning said "No secrets found", which reads as informational next to a command that then appears to work.

  Requested is now compared against resolved inside `loadSecrets`, the only place both are in scope. Any name that resolved to nothing is an error naming the unmatched names — whether it is one of five or five of five — with `Verify:`/`Fix:` lines and a near-miss hint drawn from names actually in the store, since the whole class is typos. An empty `--only` list (`--only ,,`) refuses too. The count-based guard in `run` is scoped to the no-`--only` case, where it is the correct diagnosis. `env --only` shares `loadSecrets` and gets the same fix.

- **`backend` reported the configured value, not the backend actually in use (#111).** On a default machine `backend` printed `Current: local` while `secret list` printed `keychain-macos`. Both were describing the same store and disagreeing about it.

  `createBackend` deliberately upgrades `local` to the platform keychain (#34); the defect was that `backend` read the config value while everything else reported the constructed object. The two stores differ in ways a user acts on — the keychain is shared across every project on the machine and can prompt for authorization, the local encrypted file does neither — and "where does my value physically go" is the question this command exists to answer.

  `Current:` now names the backend that will actually be constructed, and says why when it differs: `keychain-macos  (configured: local, upgraded because a platform keychain is available)`. The effective name is derived from the same factory the store uses, so the two cannot drift apart again, and it is computed without any probe that could trigger an auth prompt.

- **`setup --check` misread an unrecognised manifest into names that do not exist (#112).** A YAML-shaped `.secretless` — a reasonable first guess, since the sibling rules manifest is YAML — was not rejected. It was parsed into `required:` and two bare `-` characters and reported as `Missing: 3 required`, none of which appear in the file as names. In CI, the documented use for `--check`, that is a red build whose message sends you to look at your store instead of at your file.

  Each line is now validated with the same rule the store uses for secret names, rather than a second copy of it. A line that cannot be a name is a manifest error reported with its line number and the offending character, followed by the expected format; nothing is counted, because the file did not say what to count. A trailing token that is neither `optional` nor a comment is rejected too, so the defect cannot simply move one token to the right.

  The format was also documented nowhere. `setup --help` now shows it. That help block — and `env`'s — existed but was unreachable, because `--help` was intercepted for every subcommand before dispatch; the interception stays for runners that would otherwise perform their action (`init --help` once created a literal `--help/` directory), with an explicit exception list for the two that answer help first.

- **`scan --explain` printed model output instead of the fix, not alongside it.** When the local NanoMind engine happened to return text, that text *replaced* the deterministic `Fix:` line, so a HIGH finding arrived with no remediation at all. One run produced `Also, provide a solution to the security risk of a hardcoded OpenAI Project Key found in src/client.js.` — the model echoing its own prompt back, presented as the tool's own guidance. Other runs produced a `require('openai-project-key')` (no such npm package) and a repetition loop.

  The trigger looked intermittent because the engine usually returns an empty string and the fallback branch then printed the real fix. The defect itself was not intermittent: *any* non-null explanation replaced the remediation.

  The `Fix:` line now always prints. Generated text may only appear beside it, labelled `Context (generated, unverified):`, and is dropped when it fails validation — prompt echo (measured against the actual prompt, so it survives rewording), install or import directives, host references, degenerate repetition, and length. The prompt no longer asks the model for "the immediate action to take"; remediation belongs to the verified fix, and soliciting it is what invited an invented package name. A security tool must not emit a package name or a rotation URL it made up: an invented URL points at a domain an attacker is free to register.

- **`--explain` no longer prints generated context at all by default.** Measuring the local engine over 30 runs while fixing the above: 30 produced text and **none produced a usable explanation**. Validation caught 27. The three that passed were instruction-tuning noise ("Your answer must contain exactly 3 bullet points"). Among those correctly rejected were confident and *wrong* security claims — a leaked OpenAI key described as "vulnerable to brute-force attacks", and as letting an attacker "inject malicious code into the client". Neither is true of an API key.

  A wrong security claim from a security tool is worse than no claim, and a label does not make it true, so the generated line is now off unless `SECRETLESS_NANOMIND_EXPLAIN=1` is set. `--explain` still gives the detailed per-finding view with verified remediation, which is the part that was worth having. The help text no longer promises "rich context explanations" it could not deliver.

- **`--include-tests` did not include test files.** A credential in `test/fixture.test.js` was reported clean with the flag set — a silent false all-clear on exactly the tree the user asked to check.

  Two independent gates suppress test paths: the walker's `TEST_DIRS` check and the default-ignore list's `test/` entry. The flag opened only the first, so anything inside a test *directory* stayed hidden; a test-*named* file outside one (`src/fixture.test.js`) was found, which is why the flag looked like it worked. It now opens both, and reaches `tests/`, `__tests__/`, `__fixtures__/`, `test-server/` and `e2e/` as well.

  Deliberately unchanged: `node_modules/`, `dist/` and `build/` stay suppressed — asking for tests is not asking to scan dependency trees — and an explicit entry in your own `.secretlessignore` still wins, with `--no-ignore` remaining the way to override that.

- **40 of 57 credential patterns produced findings with no fix.** `aws-secret` was the one a release-test fixture happened to exercise; the missing guidance covered most of the catalog, including every GitHub token variant, `npm`, `gitlab`, `sendgrid`, `digitalocean`, `sentry` and `stripe-webhook`. Each rendered a HIGH or CRITICAL finding and then stopped, with nothing to act on.

  `fix` is now non-optional. Patterns without a hand-written entry derive one from data the pattern already carries — the exact env var name, plus revoke-and-reissue — so a newly added pattern cannot ship a dead end. Derived text names no console URL, because we have not verified one for those providers and inventing it is the same failure as inventing a package name.

- **An AWS secret-key preview hid which variable was exposed.** The name-gated pattern's match spans the variable name, so redacting the whole match rendered `AWS_SECRET_ACCESS_KEY = "…"` as a bare `"`. Patterns that capture their value now redact only the value: the preview reads `const AWS_SECRET_ACCESS_KEY = "[AWS Secret Access Key REDACTED]";`. The secret itself is still never shown.

- **The `--explain` footer claimed "147+ checks" for `hackmyagent secure`.** The real figure is over 300 and moves every release. The claim is gone rather than restated — a number in user-facing output has to trace to something measured.

## [0.21.0] - 2026-08-05

### Fixed

- **A configured backend that could not be reached was silently replaced by the local store.** With `backend set 1password` and the 1Password desktop app disconnected, `secret set NAME=value` wrote to the *local* store and printed `Stored: NAME`. `secret get NAME` then read 1Password and reported nothing. `run` executed the command with no credentials injected at all. Each of those reports success at the point of use, and the failure only surfaces later as an authentication error that never mentions secretless.

  `createBackend()` took a `strict` flag that defaulted to false, and `SecretStore` — the code behind `secret set`, `secret get`, `secret list` and `run` — never passed it. Only `backend migrate` did. On the default path an unavailable backend printed two lines to stderr and returned a `LocalBackend`.

  The state that triggers it is ordinary. With the `op` binary installed and an account configured but the desktop app not running, `op --version` and `op account list` both exit 0 (the latter answers from local config), while `op account get` exits 1. Quitting the app, rebooting, or a reset CLI-integration toggle is enough.

  Substituting a store is not a safe degradation for a credential manager, so it no longer happens. An unreachable configured backend now fails closed with an error that names the backend you chose, states that nothing was read from or written to anywhere else, and carries the `Verify:` and `Fix:` commands plus the deliberate `backend migrate` path. The permissive path remains for read-only diagnostics, and now says plainly that it is listing a different store.

  **Behaviour change.** Commands that previously appeared to succeed against the wrong store now exit non-zero. That is the point: if `secret set` was quietly writing somewhere you did not choose, it was never succeeding. If a script depended on the old fallback, switch it deliberately with `secretless-ai backend set local`.

- **Overwriting a 1Password secret could destroy it.** `store()` deleted the existing item before creating the replacement. If `op item create` then failed for any reason — app disconnected mid-command, vault permissions, network — the old value was already gone and the new one was never written. The replacement is now created first and the superseded item retired afterwards, by ID rather than by title, because the two legitimately share a title in the window between the calls.

- **1Password items could land untagged and become invisible to every later read.** The tag was set only inside the JSON template, while `listItems()` filters on it, so an item that did not pick the tag up could never be resolved again. Title and tag are now passed as explicit `--title` and `--tags` flags as well, which take precedence in `op item create`.

- **A pending 1Password approval hung the entire command.** `op` was invoked with no timeout, so an approval dialog waiting on someone who is not at the machine blocked the caller indefinitely with no output. Calls are now bounded (30s default, `SECRETLESS_OP_TIMEOUT_MS` to change it) and report what to check.

- **The team-setup guide published a `postinstall` hook that fails every `npm install`.** `docs/use-cases/team-setup.md` told teams to add `"postinstall": "npx secretless-ai init --ci"`, directly under the line "Now every `npm install` configures AI tool protections automatically." `init` takes an optional directory path and no flags, so it exits 2 with `Unknown option: --ci` and npm fails the install for every developer who followed the guide.

  The guide was correct when it was written. Making `init` reject unknown flags (#62 — before that, `init --dry-run` created a literal `--dry-run/` directory) is what turned a silently-wrong documented command into a loudly-broken one. A release that tightens a parser has to re-check every command its own docs publish. `src/docs-commands.test.ts` now derives the command list from the dispatch sites in `cli.ts` and fails if any documented command does not exist, or if any doc puts a flag on `init`.

- **Errors were buried under a stack trace.** The top-level handler printed the raw error object, so messages carrying `Verify:` and `Fix:` lines arrived underneath our own file paths and read as a crash. It now prints the message; set `SECRETLESS_DEBUG=1` when the stack is what you need.

- **Overwriting a macOS Keychain secret could destroy it.** `store()` deleted the existing entry before adding the replacement, so a write that failed afterwards — a locked Keychain, a dismissed approval — left nothing behind. The entry is now updated in place with `security add-generic-password -U`, and the legacy-named duplicate is swept only after the new value is committed. Same defect and same fix as the 1Password backend above.

- **Most 32-hex-character secrets were silently corrupted on read (macOS Keychain).** A HIBP Pro API key stored with `secret set` came back from `secret get` as 16 bytes of binary, and the same corrupted value was injected by `secret run`, so every consumer of that credential authenticated with garbage. The key in the Keychain was never wrong; only the read path was, which is why nothing looked broken until an API rejected the request.

  `security find-generic-password -w` hex-encodes a password it will not print literally (an embedded newline, for example), and the value has to be decoded back. But its output is genuinely ambiguous — the text `d259cc9961fbd259cc9961fbd259cc99` and the bytes `line1\nline2` both come back as an even-length run of hex digits, and nothing in the output distinguishes them. The old code decided from content: decode when the decoded bytes contain a control character, a rule meant to spare hex-looking passwords such as `deadbeef`.

  A 32-hex-character key is 16 random bytes, and the control ranges that rule tested cover 32 of 256 values, so `1 - (224/256)^16` = **88%** of such keys tripped it. That shape is ordinary: HIBP keys, MD5-form tokens, and many other API keys are exactly 32 hex characters. The remaining 12% round-tripped fine, which is what made the failure look intermittent.

  Content cannot answer the question, so the decision no longer comes from content. `security ... -g` states the encoding explicitly — `password: "…"` for text, `password: 0x…` for encoded bytes — and that marker is now what decides. The exact bytes still come from `-w`; `-g` is consulted only when the value is ambiguously shaped, so the common case still costs one `security` call. Anything unclear (probe fails, Keychain locked, no `0x` marker) returns the raw value undecoded: handing back a secret verbatim is always safe, decoding one that was never encoded is the bug.

  No re-entry is needed. Values already in the Keychain were stored correctly and read back intact once this is in — confirmed against a real affected key, which read back byte-identical to what `security` reports.

  One upgrade note: resolved values are cached for five minutes in `~/.secretless-ai/store/.secret-cache`, so a corrupted value read by the previous version can still be served briefly after upgrading. It expires on its own; the cache is keyed on write time, not on access, so it cannot be held alive by reads. If a credential still looks wrong immediately after upgrading, wait out the TTL rather than re-entering the secret. This is also worth knowing when diagnosing: while the old CLI is still installed alongside a new build, running either one repopulates the shared cache for the other.

### Security

- **`secret set` printed the secret value in its own error message (macOS).** When the Keychain refused a write, the failure surfaced as:

  ```
  Error: Command failed: security add-generic-password -s Secretless: NUTEST -a secret/NUTEST -w hello-world-123
  ```

  `security add-generic-password` takes the password as `-w <value>`, and Node's `execFileSync` puts the whole argv into the error it throws. So the credential landed in the terminal at the exact moment a user is most likely to copy the output and paste it somewhere to ask what went wrong — including into the AI assistant this tool exists to keep it away from. Found in a fresh-user walkthrough, not in the test suite.

  The argv echo is our own command line and tells the user nothing, so it is now dropped entirely, the value is scrubbed from what remains, and a final unconditional check discards the detail altogether if the value can still be found in it. A vaguer error is always better than a leaked one. The message that replaces it names the key, explains that the Keychain declined the write, and carries `Verify:` and `Fix:` lines including the fallback to the encrypted file store.

  The other backends were checked for the same shape: Linux passes the value on stdin, 1Password writes it to a mode-0600 temp file specifically to keep it out of argv, and Vault and GCP send it over HTTP. macOS was the only one, and it is the default there.

  Not fixed in this release: the value is still in `argv` while `security` runs, so it is briefly visible to `ps`. macOS documents this itself ("Use of the -p or -w options is insecure"). The obvious fix — `-w` with no argument, reading the password from stdin — reads a single line and would silently truncate multi-line secrets such as private keys, which this backend supports. Tracked separately rather than traded for data loss.

- **The guard hook no longer fails open on a pretty-printed payload.** `tool_name` and `file_path` were extracted with greps that match only compact JSON (`"tool_name":"Bash"`, no space after the colon). A client that pretty-prints its hook payload left both empty, which skipped the entire Bash-command branch and the file-path guard, so every guard silently permitted the call. This is the same dead-branch class as the 2026-07-16 `FILE_PATH` regression, reached through payload formatting rather than through `set -euo pipefail`. Both fields are now parsed with `python3`'s JSON module (as the `command` field already was), with the greps kept as the fallback for hosts without python3 — where python3 is absent, the pretty-printed payload still fails open, so this closes the hole only on hosts that have it.

  Only non-empty strings are accepted from the parser. `str()` of a number, boolean, or object produced a non-empty WRONG value (`'123'`, `'True'`), which suppressed the grep fallback and left the guard reading a field that was not there.

- **Custom `env:` or `bash:` rules no longer generate a broken hook.** `customRulesToHookBlocks` returned its blocks without a trailing newline, and the caller interpolates that directly ahead of `  exit 0`, so the last block's `fi` collided with it (`  fi  exit 0`). The generated script was not valid bash, and the hook exited 2 on every tool call, for every tool, in any project defining those rules. It failed closed, but a guard that blocks `ls -la` gets uninstalled. `files:`-only rules produce an empty block string and never hit it, which is why the existing `bash -n` coverage — written against a `files:` rule — never caught it. The new test asserts the rules actually reach the generated hook before checking it parses, so a fixture rejected by the pattern validator cannot report a false pass.

- **The file guard now checks every candidate path in the payload, not just the first.** The structured parse reads the documented top-level fields, so on its own it would have narrowed the older whole-payload grep: a secret path nested below the top level (MultiEdit-style edit lists, MCP tool payloads) was no longer seen once a benign top-level path satisfied the extraction. Candidates from the structured walk and from the greps are now unioned and each one is checked, so a benign `path` cannot mask a nested secret `file_path`.

### Known limitation (deliberate, documented in the hook)

- **The command guard still refuses to read committed template files**, while the file-path guard allows them. The two layers disagree on purpose.

  The obvious fix — subtracting template-suffixed path tokens from the command before matching — was implemented, tested against a 50-command corpus, and then reverted, because it is a credential bypass. The guard is a denylist over command TEXT whose only evidence is the literal secret path appearing after a verb; removing that literal hands the attacker the deletion. `cat "$(basename <name>.env.example .example)"` reconstructs the real path from the very token the scrub erased, needs no preconditions, and was measured reading a real secret file that the previous hook blocked. Requiring the extension match at the end of the token fails identically, because the template token still never matches.

  Closing the disagreement safely requires resolving the path a command would actually open rather than pattern-matching its text. Until then, over-blocking a placeholder file is the correct trade against leaking a real one.

All notable changes to [secretless-ai](https://www.npmjs.com/package/secretless-ai) are documented in this file.

```bash
npm install -g secretless-ai
```

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.20.1] - 2026-07-28

### Fixed
- **The guard hook missed every prefixed secret variable.** The `echo`/`printenv`
  arm anchored the secret word immediately after the `$`, so it matched only the
  bare `$API_KEY`, `$SECRET`, `$TOKEN` forms. Real variables carry a prefix, and
  `echo $ANTHROPIC_API_KEY`, `echo $OPENAI_API_KEY`, `echo $GITHUB_TOKEN`,
  `echo $AWS_SECRET_ACCESS_KEY` and `echo $DATABASE_URL` all walked past it. The
  native `permissions.deny` globs (`Bash(echo $*API_KEY*)`) already allowed the
  prefix, so the two layers disagreed and the hook was the weaker one. The
  variable name may now carry any prefix, and `${BRACED}` form is matched too.
- **`printenv NAME` was never checked.** `printenv` takes a bare variable name
  with no `$`, which the `$`-based arm could not see, so `printenv ANTHROPIC_API_KEY`
  was allowed. Bare `printenv`, which prints the whole environment, is now blocked
  as well. `env` is deliberately left alone: it is overwhelmingly used as a prefix
  (`env -u VAR cmd`), and its dump form is covered by the deny rules.
- Deny rules gained the matching entries: `echo $*PRIVATE_KEY*`, `echo $*ACCESS_KEY*`,
  `echo $*DATABASE_URL*`, `printenv *PASSWORD*`, `printenv *CREDENTIAL*`,
  `printenv *VAULT*`, `printenv *DATABASE_URL*`, and bare `printenv`.

- **The guard blocked ordinary work in two ways, so it trained people to work
  around it.** A guard that refuses the day job gets switched off, which is the
  real security cost.
  - The echo/printenv arm matched a secret variable anywhere on the line, so a
    line that began with echo and later passed a key to curl was refused, even
    though passing a secret to curl is the intended way to use one. The span now
    stops at a command separator; a separate echo of a secret later on still
    matches by itself.
  - A secret file extension matched mid-word, so the key extension also caught
    the keys() method call and keychain filenames, and an inline interpreter
    one-liner listing manifest fields was refused as if it read a private key.
    The extension must now end there. The dotted local env file still matches,
    because the next character is a dot.
- **Locale-dependent matching allowed an evasion.** In a UTF-8 locale grep
  decodes each line as characters, and a line carrying an invalid byte sequence
  cannot be decoded, so patterns using a bracket expression stopped matching on
  that line while plain literal patterns still matched. Appending one invalid
  byte to a secret-reading command made the bracket-expression guards fall
  silent. The generated hook now sets LC_ALL=C, so matching is bytewise and no
  longer varies with the developer's locale. Caught by the existing
  lone-surrogate fail-closed test when the extension boundary was added.

### Note for existing installs
A hook generated by an older version stays on disk until `secretless-ai init` is
run again. Two behaviours worth re-checking on an old hook: it blocks committed
template files (`.env.example`, `.env.sample`) that were never meant to be
blocked, and it allows real secret files in the `name.key` / `name.pem` suffix
form. Both were fixed earlier; re-running `init` picks them up.

## [0.20.0] - 2026-07-22

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
- **`redis` and `mysql` findings now carry a `Fix:` line** — both ids were
  missing from the per-pattern fix-guidance map, so their findings were dead
  ends; a regression test asserts every database connection-string finding
  has one. Also fixes the `status` verdict grammar ("1 unblocked credential
  needs review").

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

### Security

- **The `Verify:` and `Fix:` lines quote the paths they print.** Those paths are filenames from the scanned repository — attacker-controlled by definition — and the lines exist to be copy-pasted into a terminal. A symlink named `a"; id; echo "b` previously produced a command that closed the quote and ran `id`.

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

### Security

- **The `Verify:` and `Fix:` lines quote the paths they print.** Those paths are filenames from the scanned repository — attacker-controlled by definition — and the lines exist to be copy-pasted into a terminal. A symlink named `a"; id; echo "b` previously produced a command that closed the quote and ran `id`.

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
