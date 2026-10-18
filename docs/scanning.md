# Scan coverage and exit codes

What `scan` opens, which gaps fail a build, and how a command line the tool cannot bind is refused. The commands themselves are in [Commands](commands.md#triage-helpers).

## Incomplete scans do not report clean

A scan that could not read everything is not a passing scan. If the walk stops at the file cap, or a path cannot be opened, `scan` prints what it missed, exits 1, and says `No credentials found in the files scanned` rather than `No hardcoded credentials found`. In `--json`, `summary.truncated` and `summary.unreadable` carry the same signal, so CI can tell "clean" from "unfinished". After a stop at the file cap, `summary.eligibleFiles` is the `--max-files` value that covers every eligible file; `summary.walkBudgetExceeded` is `true` when the walk's directory limit stopped it instead, which no file cap clears.

**Two kinds of gap, and only one of them gates.** A gap against a claim the scanner made (it said it would read something and did not) sets exit 1: `truncated`, `unreadable`, `oversize`, `ignoreFileExcluded`. The last counts the paths the scanned directory's own `.secretlessignore` excluded and the default-ignore list does not: the tree being scanned wrote that rule, and a `.secretlessignore` holding `*` reported the whole tree as `No hardcoded credentials found` at exit 0 before it was counted. `scan --no-ignore` reads those paths. A boundary the scanner declared and never claimed to cross does not: `outOfRoot`, `skippedUnsupported` (files enumerated but not opened, such as a `.png` or a `.md`), `notEntered` (directories not descended into, such as `node_modules/` or `.turbo/`), and `unscannedConfig` (config-format files whose names are not on the built-in list, such as `secrets.json`, `.npmrc` or `values.yaml`; `scan --include-config` reads them). The second group is reported, sampled and given the command that scans it, but it does not fail your build. Every repository contains at least one of them, so gating on it would fail every build. If you want a declared boundary to gate, test it yourself: `jq -e '.summary.notEntered == 0'`.

## What a directory scan opens

A directory scan checks source files by extension (`.js`, `.ts`, `.py`, `.go`, `.java`, `.rb`, and others), key files (`.pem`, `.key`, `.crt`, `.p12`, `.pfx`, and `.secretless-bundle` files from `export`), and the config files it recognizes by name (`.env` files other than templates such as `.env.example`, `config.json`, `package.json`, `CLAUDE.md`, MCP client configs, `docker-compose.yml`, and others); the full source extension and config name lists are in [`src/patterns.ts`](https://github.com/opena2a-org/secretless-ai/blob/main/src/patterns.ts). It does not open other files, such as `values.yaml`, `main.tf`, `.ipynb` notebooks, GitHub Actions workflows other than one whose file name is a recognized config name (such as `.github/workflows/config.yml`), or most `.md` files. `scan --include-config` also reads config-format files, such as `values.yaml` and `main.tf`, in every directory it reads source files in, and naming a file scans it: `npx secretless-ai scan deploy/values.yaml`. A scan also checks these AI tool configs in your home directory: `~/.claude/CLAUDE.md`, `~/.claude/settings.json`, `~/.claude.json`, and `~/.cursor/mcp.json`. It reads `.secretlessignore` at the top of the scanned directory for its ignore rules, unless `--no-ignore` is given.

Dot-directories are read for source files like any other directory, `.claude/` and `.github/` included, apart from `.git/`, the dependency and build directories no walk enters (such as `.next/` and `.venv/`), and these hidden caches and worktree directories: `.netlify/`, `.open-next/`, `.turbo/`, `.playwright-mcp/`, `.yarn/`, `.pnpm-store/`, `.cache/`, `.terraform/`, `.parcel-cache/`, `.angular/`, `.serverless/` and `.worktrees/`. Those last twelve are in the `notEntered` group, and inside them key files and the config files the scan recognizes by name are still scanned; source files and other files are not. Naming one scans it: `npx secretless-ai scan .turbo`.

The source files in an entered dot-directory count toward the file cap (`--max-files`, default 5000). The walk reads every directory that is not hidden before it enters a dot-directory, so a scan that stops at the cap leaves files in dot-directories unscanned before any other file. A large generated dot-directory not in the list above, such as `.nuxt/` or `.svelte-kit/`, can still fill the cap: the scan then reports itself incomplete, and `summary.eligibleFiles` is the `--max-files` value that covers it.

Symlinks are followed inside the scan root. A link whose target resolves outside it is not followed (otherwise a repo containing `link -> $HOME` would pull the whole home directory into the scan), and each one is listed with the command to scan its target directly, so the boundary is never silent. These do not affect the exit code.

## A flag never widens scope

A command line the tool cannot bind is refused with exit 2 before anything runs, rather than partly ignored. That covers an unrecognised flag, a flag given a value it cannot use, and a value-taking flag given no value at all. `--only=NAME`, `--path=DIR` and every other `--flag=value` spelling binds the same way as the spaced form.

`scan`, `scan-staged` and `scan-history` refuse an unrecognised flag rather than warning and continuing, because their output is the answer: a typo in a coverage flag used to produce `No hardcoded credentials found.` at exit 0 over a narrower scan than the one you asked for. `feedback`, `diff` and `mcp-status` still warn, since they report no verdict.

`--json` is implemented by `scan`, `status`, `secret list` and `secret show`. Passing it to any other command exits 2 and names the commands that implement it, rather than printing human text and exiting 0. The caller of `--json` is a machine, and a machine reading exit 0 beside prose cannot tell it was ignored.

Exit codes: `0` clean, `1` credentials found (or an incomplete scan, or a `scan`, `status` or `verify` target that is missing or cannot be opened, or a `clean --path` that is missing, cannot be opened, or is a file other than a `.jsonl` or `.md` transcript, or an `init` that left a tool not configured, or a `verify` that found no API key in the environment to check), `2` the command line was refused and nothing ran, such as an unknown command or subcommand, or a flag it could not bind. Gate CI on `2` separately: it means the tool did not answer the question, not that the answer was clean.

```bash
npx secretless-ai clean --dry-run --path ./transcripts   # reports findings without redacting
```

`--path` takes a directory, which is walked for `.jsonl` transcripts and `session-memory/summary.md` files, or one `.jsonl` or `.md` file. Any other target reads nothing: a path that is not there prints `Error: <path> was not found. Nothing was read.`, and a file such as `transcript.log` prints `Error: <path> is not a transcript (.jsonl or .md). Nothing was read.`, each at exit 1. A directory holding no transcript prints `Scanned: 0 files — nothing to report.` rather than calling it clean.

Mistype that flag as `--dryrun` and `clean` does not run. It exits 2 and prints:

```
  Unknown option: --dryrun (did you mean --dry-run?)
  `clean` was not run. Nothing was changed.
  Supported: --dry-run, --help, --last, --path <value>
  Run `secretless-ai clean --help` for usage.
```

```bash
npx secretless-ai scan --json | jq '.summary'
# { "total": 0, "critical": 0, "high": 0, "placeholdersSuppressed": 0,
#   "minConfidence": 0, "confidenceSuppressed": 0, "truncated": false, "maxFiles": 5000, "eligibleFiles": 0,
#   "walkBudgetExceeded": false, "unreadable": 0, "outOfRoot": 0, "oversize": 0, "skippedUnsupported": 0, "notEntered": 0,
#   "unscannedConfig": 0 }
```

`scan --format sarif` writes the same findings as SARIF 2.1.0, for `github/codeql-action/upload-sarif` and the editors that read SARIF. Each finding is one result: `ruleId` is its `patternId`, `locations[0].physicalLocation` carries its file and line, and `message.text` carries its pattern name and fix; the preview line is not in the document. Each pattern id is one rule, with `security-severity` `9.0` for a `critical` finding and `7.0` for a `high` one, the bands GitHub code scanning shows as Critical and High; every result is level `error`, as every finding sets exit 1. The `summary` above is on the run as `runs[0].properties.summary`, so `truncated` and `unreadable` are in the document, and the exit code is the one `--json` gives. A path under the scanned directory is relative to it, with `%SRCROOT%` in `originalUriBaseIds` naming the directory; a home-directory file such as `~/.claude/CLAUDE.md` is an absolute `file:` URI. `--format json` is `--json`. A format the tool does not write, and `--json` beside `--format sarif`, are refused with exit 2 before anything runs. [Scan in CI](#scan-in-ci) shows the upload step.

## Scan in CI

`scan` exits 1 when it finds a credential, so a step that runs it fails the job. `scan --format sarif` writes the same findings as SARIF:

```bash
npx secretless-ai scan --format sarif > secretless.sarif
```

[`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action) sends that file to the repository's Security tab under Code scanning alerts:

```yaml
name: secretless
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx secretless-ai scan --format sarif > secretless.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secretless.sarif
```

Each alert carries the file and line, the pattern id as its rule, and the fix. `if: always()` runs the upload after the scan step has failed on a finding.
