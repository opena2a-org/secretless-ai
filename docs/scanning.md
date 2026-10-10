# Scan coverage and exit codes

What `scan` opens, which gaps fail a build, and how a command line the tool cannot bind is refused. The commands themselves are in the [README](../README.md#triage-helpers).

## Incomplete scans do not report clean

A scan that could not read everything is not a passing scan. If the walk stops at the file cap, or a path cannot be opened, `scan` prints what it missed, exits 1, and says `No credentials found in the files scanned` rather than `No hardcoded credentials found`. In `--json`, `summary.truncated` and `summary.unreadable` carry the same signal, so CI can tell "clean" from "unfinished". After a stop at the file cap, `summary.eligibleFiles` is the `--max-files` value that covers every eligible file; `summary.walkBudgetExceeded` is `true` when the walk's directory limit stopped it instead, which no file cap clears.

**Two kinds of gap, and only one of them gates.** A gap against a claim the scanner made -- it said it would read something and did not -- sets exit 1: `truncated`, `unreadable`, `oversize`. A boundary the scanner declared and never claimed to cross does not: `outOfRoot`, `skippedUnsupported` (files enumerated but not opened, such as a `.png` or a `.md`), `notEntered` (directories not descended into, such as `node_modules/` or any dot-directory), and `unscannedConfig` (config-format files whose names are not on the built-in list, such as `secrets.json`, `.npmrc` or `values.yaml`; `scan --include-config` reads them). The second group is reported, sampled and given the command that scans it, but it does not fail your build -- every repository contains at least one of them, so gating on it would fail every build. If you want a declared boundary to gate, test it yourself: `jq -e '.summary.notEntered == 0'`.

## What a directory scan opens

A directory scan checks source files by extension (`.js`, `.ts`, `.py`, `.go`, `.java`, `.rb`, and others), key files (`.pem`, `.key`, `.crt`, `.p12`, `.pfx`, and `.secretless-bundle` files from `export`), and the config files it recognizes by name (`.env` files other than templates such as `.env.example`, `config.json`, `package.json`, `CLAUDE.md`, MCP client configs, `docker-compose.yml`, and others); the full source extension and config name lists are in [`src/patterns.ts`](https://github.com/opena2a-org/secretless-ai/blob/main/src/patterns.ts). It does not open other files, such as `values.yaml`, `main.tf`, `.ipynb` notebooks, GitHub Actions workflows other than one whose file name is a recognized config name (such as `.github/workflows/config.yml`), or most `.md` files. `scan --include-config` also reads config-format files outside dot-directories, such as `values.yaml` and `main.tf`, and naming a file scans it: `npx secretless-ai scan deploy/values.yaml`. A scan also checks these AI tool configs in your home directory: `~/.claude/CLAUDE.md`, `~/.claude/settings.json`, `~/.claude.json`, and `~/.cursor/mcp.json`. It reads `.secretlessignore` at the top of the scanned directory for its ignore rules, unless `--no-ignore` is given.

Dot-directories are among the `notEntered` group, and that includes `.claude/`. Inside them, key files and the config files the scan recognizes by name are still scanned; source files and other files are not. See issue #144.

Symlinks are followed inside the scan root. A link whose target resolves outside it is not followed -- otherwise a repo containing `link -> $HOME` would pull the whole home directory into the scan -- and each one is listed with the command to scan its target directly, so the boundary is never silent. These do not affect the exit code.

## A flag never widens scope

A command line the tool cannot bind is refused with exit 2 before anything runs, rather than partly ignored. That covers an unrecognised flag, a flag given a value it cannot use, and a value-taking flag given no value at all. `--only=NAME`, `--path=DIR` and every other `--flag=value` spelling binds the same way as the spaced form.

`scan`, `scan-staged` and `scan-history` refuse an unrecognised flag rather than warning and continuing, because their output is the answer: a typo in a coverage flag used to produce `No hardcoded credentials found.` at exit 0 over a narrower scan than the one you asked for. `feedback` and `diff` still warn, since they report no verdict.

`--json` is implemented by `scan`, `status`, `secret list` and `secret show`. Passing it to any other command exits 2 and names the commands that implement it, rather than printing human text and exiting 0 -- the caller of `--json` is a machine, and a machine reading exit 0 beside prose cannot tell it was ignored.

Exit codes: `0` clean, `1` credentials found (or an incomplete scan), `2` the command line was refused and nothing ran. Gate CI on `2` separately -- it means the tool did not answer the question, not that the answer was clean.

```bash
npx secretless-ai clean --dry-run --path ./transcripts   # reports findings without redacting
```

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
