import * as path from 'path';
import { init } from '../init';
import { RULES_FILENAME } from '../custom-rules';
import { scan, emptySkips } from '../scan';
import { status, USER_SETTINGS_PATH } from '../status';
import { verify } from '../verify';
import { toolDisplayName, type AITool } from '../detect';
import { doctor, quickDiagnosis, fixProfiles } from '../doctor';
import { readBackendConfig, resolveBackendType } from '../backends/config';
import { effectiveBackendName } from '../backends/factory';
import { GCP_PROJECT_KEY, resolveGcpProject } from '../backends/gcp-project';
import type { GcpProjectResolution } from '../backends/gcp-project';
import { readManifestDetailed } from '../manifest';
import { getDaemonStatus } from '../broker/daemon';
import { getSessionStatus } from '../session/session-state';
import { isDaemonInstalled } from '../session/install';
import { VERSION, CLI, IS_EMBEDDED, CLI_BARE, formatUptime, formatRemainingTime } from './utils';
import { findGitCredentialExposure, describeExposure } from '../git-credential-files';
import { explainFinding, isEngineAvailable } from '../nanomind';
import { c, divider } from './colors';

export function runInit(projectDir: string): number {
  // Suppress the standalone brand+version banner when embedded under a host CLI
  // (SECRETLESS_CLI_PREFIX set) — it shows secretless's own version, which is
  // misleading under the host's umbrella. Keep the tagline.
  if (!IS_EMBEDDED) {
    console.log('\n  Secretless v' + VERSION);
  }
  console.log('  Keeping secrets out of AI\n');

  const result = init(projectDir);

  // Configured line: collapse Detected + Configured into one row that tells
  // the user what's now active and how it compares to what we found.
  const configuredCount = result.toolsConfigured.length;
  const detectedCount = result.toolsDetected.length;
  if (configuredCount > 0) {
    const names = result.toolsConfigured.map(toolDisplayName).join(', ');
    if (detectedCount === 0) {
      console.log(`  Configured: ${names} (no AI tools detected — defaulted to Claude Code)`);
    } else {
      console.log(`  Configured: ${names} (${configuredCount} of ${detectedCount} detected)`);
    }
  } else {
    console.log('  Configured: none');
  }

  // Files: keep the breakdown but with a specific deny-rule count when
  // settings.json was modified. The count is the load-bearing fact (not just
  // "modified") — users want to know what changed, not that it changed.
  const settingsModified = result.filesModified.includes('.claude/settings.json');
  const otherModified = result.filesModified.filter(f => f !== '.claude/settings.json');

  if (result.filesCreated.length > 0) {
    console.log();
    console.log('  Created:');
    for (const f of result.filesCreated) {
      console.log(`    + ${f}`);
    }
  }

  if (settingsModified || otherModified.length > 0) {
    console.log();
    console.log('  Modified:');
    if (settingsModified) {
      const changes: string[] = [];
      if (result.denyRulesAdded > 0) {
        changes.push(`added ${result.denyRulesAdded} deny pattern${result.denyRulesAdded === 1 ? '' : 's'}`);
      }
      if (result.denyRulesRemoved > 0) {
        changes.push(`removed ${result.denyRulesRemoved} deprecated pattern${result.denyRulesRemoved === 1 ? '' : 's'}`);
      }
      if (changes.length > 0) {
        console.log(`    ~ .claude/settings.json (${changes.join(', ')})`);
      } else {
        console.log(`    ~ .claude/settings.json`);
      }
    }
    for (const f of otherModified) {
      const suffix = (f === '.claude/hooks/secretless-guard.sh' && result.hookRefreshed) ? ' (refreshed to current version)' : '';
      console.log(`    ~ ${f}${suffix}`);
    }
  }

  // A refused path leaves its tool unconfigured. Without this block the tool
  // just dropped off the Configured line and the run read as a clean no-op.
  if (result.pathsRefused.length > 0) {
    printRefusedPaths(projectDir, result.pathsRefused);
  }

  // No-op case: nothing created, nothing modified — already up to date.
  // Not reachable when settings.json or an instruction path was refused: that
  // is work not done, not a no-op.
  if (!result.settingsUnusable && result.pathsRefused.length === 0
      && result.filesCreated.length === 0 && !settingsModified && otherModified.length === 0) {
    console.log();
    console.log('  Already up to date. No files changed.');
  }

  // Surface inline observations: secrets found + shell profile fix. Each
  // observation ends in a runnable verb (no dead ends).
  if (result.secretsFound > 0) {
    console.log();
    console.log(`  Warning: ${result.secretsFound} hardcoded credential${result.secretsFound === 1 ? '' : 's'} in config files  → secretless-ai scan`);
  }

  const fix = fixProfiles();
  if (fix) {
    console.log();
    console.log(`  Shell profile fix: copied ${fix.fixed.length} export${fix.fixed.length === 1 ? '' : 's'} from ~/${fix.sourceProfile} to ~/${fix.targetProfile}`);
    for (const v of fix.fixed) {
      console.log(`    + ${v}`);
    }
    if (fix.created) {
      console.log(`    Created ~/${fix.targetProfile}`);
    }
    console.log('    Restart your terminal for changes to take effect.');
  }

  // Suggest warm for backends that trigger OS auth prompts.
  const configuredBackend = readBackendConfig();
  if (configuredBackend === '1password' || configuredBackend === 'keychain') {
    const backendName = configuredBackend === '1password' ? '1Password' : 'keychain';
    console.log();
    console.log(`  Tip: Run \`secretless-ai warm\` before starting an AI session to avoid`);
    console.log(`  repeated ${backendName} auth prompts.`);
  }

  // A settings file we could not merge into means no deny rules and no hook
  // wiring: the guard script on disk never runs. Say that plainly, name the
  // parse error, and end on a runnable verb. Exiting 0 here would repeat the
  // defect this path exists to fix — reporting success for work not done.
  if (result.settingsUnusable) {
    const { path: rel, kind, reason } = result.settingsUnusable;
    console.log();
    console.log(`  ${c.yellow('Could not update')} ${rel}`);
    console.log();
    console.log(`    Secretless did not modify the file, so nothing was lost:`);
    console.log(`      ${reason}`);
    console.log();

    // The three failure kinds need three remediations. A file whose top level is
    // `null`, an array or a string is VALID JSON, so the JSON.parse check below
    // exits 0 on it — printing that as the verify step for every kind told the
    // user their file was fine, under advice to remove comments it did not have.
    if (kind === 'parse-error') {
      console.log(`    Claude Code settings must be strict JSON. Comments (${'//'}) and`);
      console.log(`    trailing commas are not valid, though some editors write them.`);
    } else if (kind === 'not-an-object') {
      console.log(`    The file is valid JSON, so a syntax check will pass. Claude Code`);
      console.log(`    settings must be a JSON object — a mapping wrapped in { }.`);
    } else {
      console.log(`    Secretless could not open the file at all, so its contents are`);
      console.log(`    unknown. This is usually permissions or a broken symlink.`);
    }
    console.log();
    console.log(`    No deny patterns and no hook wiring were installed, so Claude Code`);
    console.log(`    is not protected in this project yet.`);
    console.log();

    if (kind === 'parse-error') {
      console.log(`  ${c.cyan('Verify:')} node -e 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))' ${rel}`);
      console.log(`  ${c.cyan('Fix:')}    remove the comments and trailing commas, then re-run: secretless-ai init`);
    } else if (kind === 'not-an-object') {
      console.log(`  ${c.cyan('Verify:')} node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));if(Object.prototype.toString.call(v)!=="[object Object]"){console.error("top level is "+(v===null?"null":Array.isArray(v)?"an array":typeof v));process.exit(1)}' ${rel}`);
      console.log(`  ${c.cyan('Fix:')}    replace the contents with a JSON object (\`{}\` if you have no settings of your own), then re-run: secretless-ai init`);
    } else {
      console.log(`  ${c.cyan('Verify:')} ls -l ${rel}`);
      console.log(`  ${c.cyan('Fix:')}    restore read permission on the file, then re-run: secretless-ai init`);
    }
    console.log();
    return 1;
  }

  // Next steps block — every action ends in a runnable verb.
  console.log();
  console.log('  Next steps:');
  console.log('    Verify: secretless-ai verify');
  console.log('    Scan:   secretless-ai scan');
  console.log('    Status: secretless-ai status');
  console.log();

  // A rules file the operator wrote that is not fully in force fails the run:
  // part of what they asked for was not installed, and exiting 0 over that is
  // the accepted-but-narrower defect this block exists to close. Rendered last
  // so the problem and its fix are the bottom lines of the output.
  if (result.rulesFileProblem) {
    if (result.rulesFileProblem.kind === 'unrecognised-content') {
      const { issues } = result.rulesFileProblem;
      console.log(`  ${c.yellow('Warning:')} ${RULES_FILENAME} has ${issues.length} line${issues.length === 1 ? '' : 's'} this build does not read`);
      console.log();
      for (const issue of issues) {
        console.log(`    line ${issue.line}: ${issue.text}`);
        console.log(`      ${issue.message}`);
      }
      console.log();
      console.log('    The flagged lines generated no deny rules, so the protections they');
      console.log('    describe are not installed.');
      // "were applied" is only true when a Claude Code configuration was
      // actually written this run — custom rules generate Claude Code deny
      // rules and nothing for the other tools.
      if (result.toolsConfigured.includes('claude-code')) {
        console.log('    Lines that were read were applied.');
      } else {
        console.log('    Custom rules generate Claude Code deny rules, and Claude Code was');
        console.log('    not configured in this run, so none of this file is in force here.');
      }
    } else {
      console.log(`  ${c.yellow('Warning:')} ${RULES_FILENAME} was refused — none of its patterns were applied`);
      console.log();
      for (const l of result.rulesFileProblem.reason.split('\n')) {
        console.log(`    ${l}`);
      }
    }
    console.log();
    console.log(`  ${c.cyan('Verify:')} secretless-ai rules list`);
    console.log(`  ${c.cyan('Fix:')}    edit ${RULES_FILENAME}, then re-run: secretless-ai init`);
    console.log();
    return 1;
  }

  return 0;
}

/**
 * One line per path `init` refused to write through, with its reason, then a
 * Verify and a Fix line. Paths are shown relative to the working directory so
 * the printed commands run as pasted, including under `init <dir>`.
 */
function printRefusedPaths(projectDir: string, refused: Array<{ tool: AITool; path: string; reason: string }>): void {
  const shown = refused.map(r => ({
    ...r,
    shown: path.relative(process.cwd(), path.join(projectDir, r.path)) || '.',
  }));
  const tools = [...new Set(refused.map(r => r.tool))].map(toolDisplayName);

  console.log();
  console.log(`  ${c.yellow('Not configured:')} ${tools.join(', ')}`);
  for (const r of shown) {
    console.log(`    ${r.shown} ${r.reason} (${toolDisplayName(r.tool)})`);
  }
  console.log('    Nothing was written for these tools: init does not write through a');
  console.log('    symbolic or hard link, into an entry of the wrong kind, or outside the');
  console.log('    project.');
  console.log();
  // `--` because a path relative to the working directory can start with `-`.
  console.log(`  ${c.cyan('Verify:')} ls -ld -- ${shown.map(r => shellQuote(r.shown)).join(' ')}`);
  const fixes = shown.map(r => refusedPathFix(shellQuote(r.shown), r.reason));
  fixes[fixes.length - 1] += ', then re-run: secretless-ai init';
  fixes.forEach((f, i) => console.log(i === 0 ? `  ${c.cyan('Fix:')}    ${f}` : `          ${f}`));
}

/** What the user changes so `init` accepts a path it refused for `reason`. */
function refusedPathFix(quoted: string, reason: string): string {
  if (reason === 'is a symbolic link') {
    return `replace the link ${quoted} with a copy of what it points to, or remove the link`;
  }
  if (reason === 'has more than one hard link') {
    // The copy goes to a new file mktemp creates, never to a fixed name such
    // as `.tmp`: `cp` writes through a link the project already has there.
    // `init` refuses on the link count without reading the file, so this is
    // printed for an unreadable file too; a failed `cp` or `mv` removes the
    // file mktemp created and still exits non-zero.
    return `replace ${quoted} with a copy of itself (t=$(mktemp -- ${quoted}.XXXXXX) && { cp -p -- ${quoted} "$t" && mv -- "$t" ${quoted} || { rm -f -- "$t"; false; }; }), or remove it`;
  }
  if (reason === 'is not a regular file') return `move ${quoted} aside, or replace it with a regular file`;
  if (reason === 'is not a directory') return `move ${quoted} aside, or replace it with a directory`;
  return `make ${quoted} a regular file or directory inside the project`;
}

/**
 * Quote a path for a shell command we PRINT for the user to copy.
 *
 * The paths here are filenames from a scanned repository, i.e. attacker
 * controlled, and the whole point of a `Fix:` line is that it gets pasted into a
 * terminal. A link named `a"; id; echo "b` interpolated raw produced a command
 * that closed the quote and ran `id`. Single quotes with the standard
 * `'\''` escape make every byte literal.
 */
export function shellQuote(p: string): string {
  return /^[A-Za-z0-9_./-]+$/.test(p) ? p : `'${p.split("'").join("'\\''")}'`;
}

/** C0 controls, DEL and C1 controls: bytes a terminal acts on instead of showing. */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * Show control characters in a scanned file name as `\xNN`. A file name in a
 * scanned repository is attacker-chosen, and printed raw an escape sequence in
 * it can clear or rewrite the lines around it.
 */
function visibleControls(s: string): string {
  return s.replace(new RegExp(CONTROL_CHARS.source, 'g'), ch => `\\x${ch.charCodeAt(0).toString(16).padStart(2, '0')}`);
}

/**
 * Human-readable byte size for coverage warnings ("11 MB", "1.0 MB"), with the
 * byte count the rounded figure stands for.
 */
function roundBytes(bytes: number): { text: string; shown: number } {
  if (bytes >= 1024 * 1024) {
    const mb = (bytes / (1024 * 1024)).toFixed(bytes >= 10 * 1024 * 1024 ? 0 : 1);
    return { text: `${mb} MB`, shown: Number(mb) * 1024 * 1024 };
  }
  if (bytes >= 1024) {
    const kb = (bytes / 1024).toFixed(0);
    return { text: `${kb} KB`, shown: Number(kb) * 1024 };
  }
  return { text: `${bytes} B`, shown: bytes };
}

/**
 * Size and cap of a file skipped for size ("11 MB, cap 10 MB").
 *
 * Rounding alone printed "1.0 MB, cap 1.0 MB" for a file 4 KB over the 1 MB
 * source cap, which reads as a file at the cap rather than over it. When the
 * rounded figures do not show the file as larger, both are printed as exact
 * byte counts.
 */
export function formatSizeOverCap(bytes: number, capBytes: number): string {
  const size = roundBytes(bytes);
  const cap = roundBytes(capBytes);
  if (size.shown > cap.shown) return `${size.text}, cap ${cap.text}`;
  return `${bytes.toLocaleString('en-US')} bytes, cap ${capBytes.toLocaleString('en-US')} bytes`;
}

/**
 * Parse a `--max-file-size` value into bytes. Accepts a bare byte count or a
 * `kb`/`mb`/`gb` suffix (case-insensitive, `k`/`m`/`g` also accepted).
 *
 * Returns null for anything unparseable or non-positive so the caller can
 * refuse rather than silently fall back to the default cap — a size flag that
 * is ignored without saying so is the same class of defect as the silent skip
 * it exists to fix.
 */
export function parseFileSize(input: string): number | null {
  const m = /^\s*(\d+(?:\.\d+)?)\s*(b|kb|mb|gb|k|m|g)?\s*$/i.exec(input);
  if (!m) return null;
  const value = parseFloat(m[1]);
  if (!isFinite(value) || value <= 0) return null;
  const unit = (m[2] ?? 'b').toLowerCase();
  const mult = unit.startsWith('g') ? 1024 ** 3
    : unit.startsWith('m') ? 1024 ** 2
      : unit.startsWith('k') ? 1024
        : 1;
  return Math.floor(value * mult);
}

export async function runScan(projectDir: string, options?: { includeTests?: boolean; includeConfig?: boolean; explain?: boolean; noIgnore?: boolean; minConfidence?: number; json?: boolean; showPlaceholders?: boolean; maxFiles?: number; maxFileSizeBytes?: number }): Promise<number> {
  const nodeFs = require('fs') as typeof import('fs');
  const scanOpts = {
    includeTests: options?.includeTests,
    includeConfig: options?.includeConfig,
    // `noIgnore` disables BOTH the user `.secretlessignore` and the
    // default-ignore list. Used when a user wants to see every finding,
    // including known-fixture noise.
    ignore: options?.noIgnore ? false : undefined,
    minConfidence: options?.minConfidence,
    showPlaceholders: options?.showPlaceholders,
    maxSourceFiles: options?.maxFiles,
    maxFileSizeBytes: options?.maxFileSizeBytes,
  };
  const capUsed = options?.maxFiles ?? 5000;

  // --json: emit a single valid JSON document to stdout and nothing else, so the
  // output is machine-parseable (issue #63 — the flag previously printed the human
  // report). Errors go to stderr; exit code still signals findings for CI gating.
  if (options?.json) {
    if (!nodeFs.existsSync(projectDir)) {
      console.error(`Directory not found: ${projectDir}`);
      return 1;
    }
    const stats = {
      placeholdersSuppressed: 0, truncated: false, unreadable: [] as string[], outOfRoot: [] as string[],
      oversize: [] as Array<{ path: string; bytes: number; capBytes: number }>, skips: emptySkips(),
      confidenceSuppressed: 0,
      unscannedConfig: { count: 0, files: [] as string[] },
    };
    const findings = scan(projectDir, scanOpts, stats);
    const critical = findings.filter(f => f.severity === 'critical').length;
    console.log(JSON.stringify({
      tool: 'secretless-ai',
      version: require('../../package.json').version,
      findings,
      summary: {
        total: findings.length,
        critical,
        high: findings.length - critical,
        placeholdersSuppressed: stats.placeholdersSuppressed,
        // What --min-confidence removed. A filtered finding is not a clean
        // file, so `total: 0` must not be the only thing a consumer sees when
        // the filter hid every match (#125). Like placeholders, the user asked
        // for the filter, so it does not set the exit code.
        minConfidence: options?.minConfidence ?? 0,
        confidenceSuppressed: stats.confidenceSuppressed,
        // A machine consumer must be able to tell "clean" from "unfinished".
        truncated: stats.truncated,
        maxFiles: capUsed,
        unreadable: stats.unreadable.length,
        outOfRoot: stats.outOfRoot.length,
        // Files skipped for size were never opened, so they are coverage lost,
        // not content judged clean.
        oversize: stats.oversize.length,
        // DECLARED BOUNDARIES, not broken claims — so, like outOfRoot, these do
        // NOT set the exit code. A count that is non-zero on every repository
        // is not a signal; gating on it would turn every clean scan into a
        // failure. A consumer who wants to gate on a boundary gates on these
        // explicitly.
        skippedUnsupported: stats.skips.fileCount,
        notEntered: stats.skips.dirCount,
        // #124 — config-format files no walk read (`secrets.json`, `.npmrc`,
        // `values.yaml`). The same declared-boundary class, and the field a CI
        // job gates on when it wants them read: `--include-config` scans them.
        unscannedConfig: stats.unscannedConfig.count,
      },
      unreadableFiles: stats.unreadable,
      outOfRootLinks: stats.outOfRoot,
      oversizeFiles: stats.oversize,
      // Samples, capped. The counts above carry the magnitude; these carry the
      // REASON, because `notEntered: 171` on a repo with dependencies installed
      // is not something a human can act on without knowing which 171.
      skippedUnsupportedFiles: stats.skips.files,
      notEnteredDirs: stats.skips.dirs,
      unscannedConfigFiles: stats.unscannedConfig.files,
    }, null, 2));
    // An incomplete scan is not a pass. `total: 0` with `truncated: true`, an
    // unreadable file, or a file skipped for size means part of the tree was
    // never read, so exiting 0 would gate CI on a subset. An out-of-root link
    // is a deliberate, reported boundary rather than a failure, so it does not
    // by itself set exit 1.
    return findings.length > 0 || stats.truncated
      || stats.unreadable.length > 0 || stats.oversize.length > 0 ? 1 : 0;
  }

  console.log('\n  Secretless Scanner\n');

  if (!nodeFs.existsSync(projectDir)) {
    console.error(`  Directory not found: ${projectDir}`);
    console.error('  Check the path and try again.\n');
    return 1;
  }

  const stats = {
    placeholdersSuppressed: 0, truncated: false, unreadable: [] as string[], outOfRoot: [] as string[],
    oversize: [] as Array<{ path: string; bytes: number; capBytes: number }>, skips: emptySkips(),
    confidenceSuppressed: 0,
    unscannedConfig: { count: 0, files: [] as string[] },
  };
  const findings = scan(projectDir, scanOpts, stats);
  const minConfidence = options?.minConfidence ?? 0;

  // Coverage-gap paths are reported relative to the SCAN ROOT, which is not the
  // shell's cwd when a path argument was given. Printing them bare produced a
  // `ls -l config.json` that fails with "No such file or directory" — a fix
  // command that does not run is a dead end, which is exactly what this whole
  // release is about.
  const nodePath = require('path') as typeof import('path');
  const runnable = (rel: string) => {
    const abs = nodePath.resolve(projectDir, rel);
    const cwd = process.cwd();
    const fromCwd = nodePath.relative(cwd, abs);
    // From the filesystem root every path is "inside cwd", and the relative
    // form is the absolute path minus its leading slash: `private/tmp/x/a.js`
    // runs there but reads as a path under the current directory anywhere it
    // is pasted (#120).
    const atRoot = nodePath.parse(cwd).root === cwd;
    // A bare relative path is only usable when it stays inside cwd AND does not
    // read as a flag; anything else falls back to the absolute path.
    const chosen = fromCwd && !atRoot && !fromCwd.startsWith('..') && !fromCwd.startsWith('-') ? fromCwd : abs;
    return shellQuote(chosen);
  };

  // A walk that stopped at the file cap left tree unvisited, and a file we could
  // not open was never read at all. Either way the findings are a SUBSET, so
  // rendering them as "No hardcoded credentials found." is the fail-open these
  // warnings close: an answer we never got is not a good answer.
  const coverageWarnings = () => {
    if (stats.truncated) {
      console.log(`  ${c.boldYellow('Scan incomplete')} — stopped at the ${capUsed}-file cap, so files were left unscanned.`);
      console.log(`  ${c.dim('This is not a clean result. Raise the cap, or scan a subtree at a time:')}`);
      console.log(`  ${c.cyan('Fix:')}    npx secretless-ai scan ${runnable('.')} --max-files ${capUsed * 4}`);
      console.log(`  ${c.cyan('Verify:')} npx secretless-ai scan ${runnable('.')} --max-files ${capUsed * 4} --json | jq .summary.truncated\n`);
    }
    if (stats.unreadable.length > 0) {
      const n = stats.unreadable.length;
      console.log(`  ${c.boldYellow(`${n} path${n > 1 ? 's' : ''} could not be read`)} — not scanned, so not known to be clean.`);
      for (const f of stats.unreadable.slice(0, 10)) {
        console.log(`  ${c.dim(`  ${runnable(f)}`)}`);
      }
      if (n > 10) console.log(`  ${c.dim(`  … and ${n - 10} more`)}`);
      // Do NOT assert the cause. "Unreadable" covers permissions, a symlink
      // loop (ELOOP) and a too-many-open-files failure, and `chmod +r` is a dead
      // end for the last two — a Fix that cannot work is worse than none.
      // `ls -ld` distinguishes them, so it leads. `+rx` not `+r`: a directory
      // needs the execute bit to be traversed, so `+r` alone leaves the scan
      // still unable to enter it.
      console.log(`  ${c.dim('Cause differs by path — permissions, a broken or looping symlink, or an I/O error.')}`);
      console.log(`  ${c.cyan('Verify:')} ls -ld ${runnable(stats.unreadable[0])}`);
      console.log(`  ${c.cyan('Fix:')}    chmod +rx ${runnable(stats.unreadable[0])}   ${c.dim('# if the cause is permissions')}\n`);
    }
    if (stats.outOfRoot.length > 0) {
      const n = stats.outOfRoot.length;
      console.log(`  ${c.boldYellow(`${n} symlink${n > 1 ? 's' : ''} ${n > 1 ? 'point' : 'points'} outside the scan root`)} — not followed.`);
      for (const f of stats.outOfRoot.slice(0, 10)) {
        console.log(`  ${c.dim(`  ${runnable(f)}`)}`);
      }
      if (n > 10) console.log(`  ${c.dim(`  … and ${n - 10} more`)}`);
      console.log(`  ${c.dim('Following them would let a link to $HOME pull the whole home directory into the scan.')}`);
      // No `$(...)` here: the path is attacker-controlled (it is a filename in a
      // scanned repo), and a command substitution around it hands a
      // copy-pasting user an execution primitive.
      console.log(`  ${c.cyan('Fix:')}    npx secretless-ai scan ${runnable(nodeFs.realpathSync(nodePath.resolve(projectDir, stats.outOfRoot[0])))}\n`);
    }
    if (stats.oversize.length > 0) {
      const n = stats.oversize.length;
      console.log(`  ${c.boldYellow(`${n} file${n > 1 ? 's' : ''} skipped for size`)} — not scanned, so not known to be clean.`);
      for (const f of stats.oversize.slice(0, 10)) {
        console.log(`  ${c.dim(`  ${runnable(f.path)} (${formatSizeOverCap(f.bytes, f.capBytes)})`)}`);
      }
      if (n > 10) console.log(`  ${c.dim(`  … and ${n - 10} more`)}`);
      // The cap is a resource guard, not a judgement — the same bytes under it
      // produce a finding, so an 11 MB config with a key on line 1 scanned to
      // zero and exited 0 before this was reported (#120).
      console.log(`  ${c.dim('The cap bounds memory use; it says nothing about the contents.')}`);
      console.log(`  ${c.cyan('Verify:')} head -c 4096 ${runnable(stats.oversize[0].path)}`);
      console.log(`  ${c.cyan('Fix:')}    npx secretless-ai scan ${runnable('.')} --max-file-size ${Math.ceil(stats.oversize[0].bytes / (1024 * 1024)) + 1}mb\n`);
    }

    // #124 — a config-format file whose name is not on the built-in list was
    // read by no walk, and a clean scan said nothing: `secrets.json` beside a
    // scanned `config.json`. Named, with the flag that reads them and the
    // command that reads one. A boundary, so it does not change the exit code.
    if (stats.unscannedConfig.count > 0) {
      const n = stats.unscannedConfig.count;
      console.log(`  ${c.boldYellow(`${n} config file${n > 1 ? 's' : ''} not scanned`)} — ${n > 1 ? 'their names are' : 'its name is'} not on the built-in config list, so not known to be clean.`);
      for (const f of stats.unscannedConfig.files.slice(0, 10)) {
        console.log(`  ${c.dim(`  ${runnable(f)}`)}`);
      }
      if (n > 10) console.log(`  ${c.dim(`  … and ${n - 10} more`)}`);
      console.log(`  ${c.cyan('Fix:')}      npx secretless-ai scan ${runnable('.')} --include-config`);
      console.log(`  ${c.cyan('Scan one:')} npx secretless-ai scan ${runnable(stats.unscannedConfig.files[0])}\n`);
    }

    // Declared boundaries. Reported in the same place as the gaps above and
    // deliberately NOT in the same class: these do not change the exit code and
    // do not stop the scan reading as clean, because the scanner never claimed
    // to open a `.png` or to walk `node_modules`.
    //
    // A directory is named rather than counted because the count alone is not
    // actionable — the entry that matters on a real repo is a hidden directory
    // like `.claude/`, and it is invisible inside a single total. Each line is
    // followed by the command that scans it, so naming a gap is never a dead
    // end.
    if (stats.skips.dirCount > 0) {
      const n = stats.skips.dirCount;
      console.log(`  ${c.dim(`${n} director${n > 1 ? 'ies' : 'y'} not entered`)} — declared boundaries, not findings.`);
      for (const d of stats.skips.dirs.slice(0, 8)) {
        console.log(`  ${c.dim(`  ${runnable(d.path)} — ${d.reason}`)}`);
      }
      if (n > 8) console.log(`  ${c.dim(`  … and ${n - 8} more`)}`);
      const first = stats.skips.dirs[0];
      if (first) {
        console.log(`  ${c.cyan('Scan one:')} npx secretless-ai scan ${runnable(first.path)}`);
      }
      console.log();
    }
    // Files are their own block, not a line inside the directory block. Nested
    // there, a tree with no pruned directory printed nothing about a file it
    // never opened, so a planted AWS key in `notes.txt` read as "No hardcoded
    // credentials found." with no qualification. Naming a file scans it
    // whatever its type, so `Scan one:` names a file, not a flag.
    if (stats.skips.fileCount > 0) {
      const n = stats.skips.fileCount;
      console.log(`  ${c.dim(`${n} file${n > 1 ? 's' : ''} not opened`)} — declared boundaries, not findings.`);
      for (const f of stats.skips.files.slice(0, 8)) {
        console.log(`  ${c.dim(`  ${visibleControls(runnable(f.path))} — ${f.reason}`)}`);
      }
      if (n > 8) console.log(`  ${c.dim(`  … and ${n - 8} more`)}`);
      // A name holding a control character cannot be copied as it reads, so it
      // is listed but never offered as the command.
      const first = stats.skips.files.find(f => !CONTROL_CHARS.test(f.path));
      if (first) {
        console.log(`  ${c.cyan('Scan one:')} npx secretless-ai scan ${runnable(first.path)}`);
      }
      console.log();
    }
  };
  // An out-of-root link is a reported boundary, not a gap in what we claimed to
  // cover, so it does not make the result non-clean. A file skipped for size
  // IS such a gap: we said we scan config files, and did not scan that one.
  const anyCoverageGap = () => stats.truncated || stats.unreadable.length > 0 || stats.oversize.length > 0;

  // When everything (or a real subset) was hidden as a placeholder, say so and
  // point at the flag that reveals them. A silent "No credentials found" makes a
  // user who tested with obvious placeholder values think the scanner is broken,
  // and silently dropping a real-looking value whose host is `example.com` is the
  // over-suppression the audit flagged. The hint is suppressed once the user is
  // already showing placeholders.
  const placeholderHint = () => {
    if (stats.placeholdersSuppressed > 0 && !options?.showPlaceholders) {
      const n = stats.placeholdersSuppressed;
      console.log(`  ${c.dim(`${n} value${n > 1 ? 's' : ''} looked like a placeholder and ${n > 1 ? 'were' : 'was'} hidden.`)}`);
      console.log(`  ${c.dim('See them: npx secretless-ai scan --show-placeholders')}\n`);
    }
  };

  // Same disclosure for the --min-confidence filter. Without it, a threshold
  // that hid every match printed "No hardcoded credentials found." over a repo
  // holding a credential (#125).
  const confidenceHint = () => {
    if (stats.confidenceSuppressed > 0) {
      const n = stats.confidenceSuppressed;
      console.log(`  ${c.dim(`${n} match${n > 1 ? 'es' : ''} scored below --min-confidence ${minConfidence} and ${n > 1 ? 'were' : 'was'} hidden.`)}`);
      console.log(`  ${c.dim(`See ${n > 1 ? 'them' : 'it'}: npx secretless-ai scan ${runnable('.')}`)}\n`);
    }
  };

  if (findings.length === 0) {
    if (anyCoverageGap()) {
      // Deliberately NOT "No hardcoded credentials found" — nothing was found in
      // the part we reached, which is a different claim.
      console.log('  No credentials found in the files scanned.\n');
      coverageWarnings();
      placeholderHint();
      confidenceHint();
      return 1;
    }
    // With matches filtered out, "no credentials" is not the claim we can make;
    // "none at or above the threshold you set" is.
    console.log(stats.confidenceSuppressed > 0
      ? `  No credentials found at or above confidence ${minConfidence}.\n`
      : '  No hardcoded credentials found.\n');
    // Still report a boundary we chose not to cross. The result IS clean for the
    // tree we claimed to scan, so this stays exit 0 — but a link we declined to
    // follow must be visible, or declining becomes its own silent gap.
    coverageWarnings();
    placeholderHint();
    confidenceHint();
    console.log('  Verify keys are working: npx secretless-ai verify\n');
    return 0;
  }

  // If --explain requested, use NanoMind engine for rich context
  if (options?.explain) {
    const code = await runScanWithExplanations(findings);
    coverageWarnings();
    confidenceHint();
    return code;
  }

  printFindings(findings);
  coverageWarnings();
  placeholderHint();
  confidenceHint();
  return 1;
}

function printFindings(findings: ReturnType<typeof scan>): void {
  const critCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.length - critCount;

  if (critCount > 0) {
    console.log(`  ${c.boldRed(`${critCount} critical credential${critCount > 1 ? 's' : ''} exposed`)}`);
  } else {
    console.log(`  ${c.boldYellow(`${findings.length} credential${findings.length > 1 ? 's' : ''} found`)}`);
  }

  console.log(divider('Findings'));

  const summaryParts: string[] = [];
  if (critCount > 0) summaryParts.push(c.brightRed(`${critCount} critical`));
  if (highCount > 0) summaryParts.push(c.yellow(`${highCount} high`));
  console.log(`  ${summaryParts.join('  ')}`);

  for (const finding of findings) {
    const sevColor = finding.severity === 'critical' ? c.brightRed : c.yellow;
    const sevLabel = finding.severity === 'critical' ? 'CRITICAL' : 'HIGH';
    // Confidence rendering: `confidence: high (0.92)`. Tier colour mirrors the
    // severity colour ramp \u2014 high green, medium yellow, low dim \u2014 so a low-
    // confidence high-severity finding still looks lower than a high-
    // confidence one without the user squinting at the number.
    const tierColor = finding.confidenceTier === 'high'
      ? c.green
      : finding.confidenceTier === 'medium'
        ? c.yellow
        : c.dim;
    const fixtureSuffix = finding.looksLikeFixture
      ? c.dim(' (looks like a test fixture)')
      : '';
    console.log();
    console.log(`  ${sevColor('\u2502')} ${c.bold(sevLabel)}  ${c.boldWhite(finding.patternName)}`);
    console.log(`  ${sevColor('\u2502')} ${c.dim(`${finding.file}:${finding.line}`)}${fixtureSuffix}`);
    console.log(`  ${sevColor('\u2502')} ${finding.preview}`);
    console.log(`  ${sevColor('\u2502')} ${c.cyan('Confidence:')} ${tierColor(`${finding.confidenceTier} (${finding.confidence.toFixed(2)})`)}`);
    if (finding.fix) {
      console.log(`  ${sevColor('\u2502')} ${c.cyan('Fix:')} ${finding.fix}`);
    }
  }

  console.log(divider('Next Steps'));
  console.log(`  ${c.cyan('Protect now:')}        npx secretless-ai init`);
  console.log(`  ${c.cyan('Full security scan:')} npx hackmyagent secure`);
  console.log();
}

async function runScanWithExplanations(findings: ReturnType<typeof scan>): Promise<number> {
  const engineReady = await isEngineAvailable();

  if (!engineReady) {
    console.log('  NanoMind engine not available. Install @nanomind/engine for rich explanations.');
    console.log('  Falling back to standard output.\n');
    printFindings(findings);
    return findings.length > 0 ? 1 : 0;
  }

  console.log(`  Found ${findings.length} credential(s):\n`);
  console.log('  AI coding tools (Claude Code, Cursor, Copilot) can read .env files in their');
  console.log('  context window, exposing credentials to the LLM provider.\n');

  for (const finding of findings) {
    const severity = finding.severity === 'critical' ? 'CRIT' : 'HIGH';
    console.log(`  [${severity}] ${finding.patternName}`);
    console.log(`         ${finding.file}:${finding.line}`);
    console.log(`         ${finding.preview}`);

    // The deterministic fix ALWAYS prints. Generated text may only appear
    // alongside it, explicitly labelled, never in place of it — substituting
    // model output for the verified remediation left findings with no fix at
    // all and presented echoed prompt text as the tool's own guidance.
    if (finding.fix) {
      console.log(`         Fix: ${finding.fix}`);
    }
    // Generated context is OFF by default. Measured over 30 runs against the
    // local engine (2026-08-06): 30/30 produced text, 0/30 produced a usable
    // explanation. What survived validation was instruction-tuning noise
    // ("Your answer must contain exactly 3 bullet points"); what validation
    // caught included confident and WRONG security claims — a leaked OpenAI key
    // described as "vulnerable to brute-force attacks" and as letting an
    // attacker "inject malicious code into the client".
    //
    // A wrong security claim from a security tool is worse than no claim, and a
    // label does not make it true. Kept behind an opt-in so the path stays
    // exercised and can be re-enabled when a model earns it.
    if (process.env.SECRETLESS_NANOMIND_EXPLAIN === '1') {
      const explanation = await explainFinding(finding.patternName, finding.patternId, finding.file);
      if (explanation) {
        console.log(`         Context (generated, unverified): ${explanation}`);
      }
    }
    console.log();
  }

  console.log(`  Run \`npx secretless-ai init\` to add protections.`);
  console.log('  For a full security scan: npx hackmyagent secure\n');
  return findings.length > 0 ? 1 : 0;
}

/**
 * Refuse a target directory that does not exist, with the same message and
 * exit code as `scan`. `status` and `verify` used to answer anyway: a typo in
 * a CI path produced a clean verdict and exit 0 over a directory nobody read
 * (#125). Errors go to stderr, so `status --json` keeps stdout empty.
 */
function refuseMissingDir(projectDir: string): boolean {
  const nodeFs = require('fs') as typeof import('fs');
  if (nodeFs.existsSync(projectDir)) return false;
  console.error(`  Directory not found: ${projectDir}`);
  console.error('  Check the path and try again.\n');
  return true;
}

export async function runStatus(projectDir: string, options?: { json?: boolean }): Promise<number> {
  if (refuseMissingDir(projectDir)) return 1;
  const s = await status(projectDir);
  const session = getSessionStatus();
  const brokerStatus = getDaemonStatus();
  const brokerInstalled = isDaemonInstalled();
  const tp = s.transcriptProtection;
  const user = s.userSettings;
  const configuredBackend = readBackendConfig();
  // Session warmth only matters for backends that trigger OS auth prompts, and
  // that is a property of the EFFECTIVE backend: `local` upgrades to the
  // platform keychain, which prompts.
  const effectiveBackend = effectiveBackendName(resolveBackendType());
  const sessionRelevant = effectiveBackend.startsWith('keychain') || effectiveBackend === '1password';
  // Which GCP project names resolve from in this directory, and why (#177).
  // File reads only: status makes no request to GCP.
  const gcpProject = effectiveBackend === 'gcp-sm' ? resolveGcpProject({ projectDir }) : undefined;

  // Build observation rows. Each row: glyph + label + optional → command.
  // Satisfied observations use ✓; needs-action use ⚠. Every ⚠ ends in a
  // runnable verb so the user has no dead end (CISO Rule 11).
  type Row = { glyph: '✓' | '⚠'; label: string; action?: string };
  const rows: Row[] = [];
  const addRow = (row: Row): void => { rows[rows.length] = row; };

  // Protection / hook.
  //
  // The guard script on disk is inert until settings.json wires it into
  // PreToolUse. When settings.json does not parse we cannot read that wiring,
  // and `hookInstalled` alone only says the script file exists — so a ✓ here
  // would be a green claim about something never verified.
  if (s.settingsUnreadable) {
    addRow({
      glyph: '⚠',
      label: `${s.settingsUnreadable.path} does not parse — deny patterns and hook wiring cannot be read`,
      action: `node -e 'JSON.parse(require("fs").readFileSync("${s.settingsUnreadable.path}","utf8"))'`,
    });
  } else if (s.settingsAmbiguous) {
    // Ahead of the hookInstalled branch on purpose: the file's authorization
    // content cannot be read as written, so no row about it renders green.
    // Claude Code, not this tool, is what enforces these patterns — the loss is
    // real and it happened there; our defect was reporting fine over it.
    addRow({
      glyph: '⚠',
      label: `${s.settingsAmbiguous.path} ${s.settingsAmbiguous.reason} — the deny patterns cannot be read as configured`,
      // NOT a grep and NOT `node -e JSON.parse`: both exit 0 on a duplicate and
      // print nothing, and an escape-spelled or case-variant collision survives
      // a grep and a diff review. Re-running status is what actually re-checks.
      action: 'delete the repeated key, then re-run: secretless-ai status',
    });
  } else if (s.hookInstalled) {
    const denyText = (s.denyRuleCount ?? 0) > 0 ? ` — ${s.denyRuleCount} deny pattern${s.denyRuleCount === 1 ? '' : 's'}` : '';
    addRow({ glyph: '✓', label: `Claude Code hook installed (.claude/settings.json${denyText})` });
  } else if (user?.coversProject && user.guardReachable) {
    const denyText = (user.denyRuleCount ?? 0) > 0 ? ` — ${user.denyRuleCount} deny pattern${user.denyRuleCount === 1 ? '' : 's'}` : '';
    addRow({ glyph: '✓', label: `Claude Code hook installed at user level (${user.path}${denyText})` });
  } else if (user?.guardWired && !user.guardReachable) {
    // `init` run from the home directory wires the guard as
    // "$CLAUDE_PROJECT_DIR"/.claude/hooks/secretless-guard.sh, which from the
    // user-level file resolves to THIS project — where there is no script.
    addRow({
      glyph: '⚠',
      label: `Claude Code hook not installed in this project (${user.path} expects it here)`,
      action: 'secretless-ai init',
    });
  } else {
    addRow({ glyph: '⚠', label: 'Claude Code hook not installed', action: 'secretless-ai init' });
  }

  // User-level settings, when this project has no guard of its own. Claude
  // Code applies their deny patterns in every project, so they are what is
  // enforced here; a file that cannot be read as written gets no green row.
  if (user && !s.hookInstalled && !s.settingsUnreadable) {
    if (user.unreadable) {
      addRow({
        glyph: '⚠',
        label: `${user.path} does not parse — user-level deny patterns and hooks cannot be read`,
        action: `node -e 'JSON.parse(require("fs").readFileSync(require("os").homedir()+"/.claude/settings.json","utf8"))'`,
      });
    } else if (user.ambiguous) {
      addRow({
        glyph: '⚠',
        label: `${user.path} ${user.ambiguous.reason} — the user-level deny patterns cannot be read as configured`,
        action: 'delete the repeated key, then re-run: secretless-ai status',
      });
    } else if (user.coversProject && !user.guardReachable) {
      addRow({ glyph: '✓', label: `User-level deny patterns apply (${user.path} — ${user.denyRuleCount} deny pattern${user.denyRuleCount === 1 ? '' : 's'})` });
    }
  }

  // Stop hook (transcript redaction).
  if (tp.stopHookInstalled && tp.stopHookScope === 'user') {
    addRow({ glyph: '✓', label: `Stop hook installed at user level (${USER_SETTINGS_PATH}, transcript redaction)` });
  } else if (tp.stopHookInstalled) {
    addRow({ glyph: '✓', label: 'Stop hook installed (transcript redaction)' });
  } else {
    addRow({ glyph: '⚠', label: 'Stop hook not installed (transcripts unredacted)', action: 'secretless-ai init' });
  }

  // Configured tools (instructions present in tool config files).
  if (s.configuredTools.length > 0) {
    addRow({ glyph: '✓', label: `Tool instructions: ${s.configuredTools.map(toolDisplayName).join(', ')}` });
  }

  // Secrets in the project scan. The scan covers the file types it knows, not
  // every config file: a key in values.yaml or main.tf is not read, so a clean
  // result is a statement about the scanned files only.
  if (s.secretsFound > 0) {
    addRow({ glyph: '⚠', label: `${s.secretsFound} credential${s.secretsFound === 1 ? '' : 's'} detected in project files`, action: 'secretless-ai scan' });
  } else {
    addRow({ glyph: '✓', label: 'No credentials detected in scanned files' });
  }

  // GCP project (gcp-sm only). A repository's .secretless may name its own.
  if (gcpProject?.error) {
    addRow({ glyph: '⚠', label: gcpProject.error, action: 'fix that line, then re-run: secretless-ai status' });
  } else if (gcpProject?.projectId) {
    addRow({ glyph: '✓', label: `GCP project ${gcpProject.projectId} (${describeGcpProjectSource(gcpProject)})` });
  } else if (gcpProject) {
    addRow({
      glyph: '⚠',
      label: 'GCP project not set — gcp-sm cannot resolve any name',
      action: `add "${GCP_PROJECT_KEY}: <project-id>" to .secretless, then re-run: secretless-ai status`,
    });
  }

  // Plaintext git credentials in the home directory. Machine-wide, like the
  // broker rows: one row per file or setting, and `doctor` prints the Verify
  // and Fix lines for each. Counts and line numbers only, never a value.
  const gitCredentials = findGitCredentialExposure();
  const gitCredentialFindings = describeExposure(gitCredentials, CLI);
  for (const finding of gitCredentialFindings) {
    addRow({ glyph: '⚠', label: finding.summary, action: 'secretless-ai doctor' });
  }

  // Session warmth (only relevant when a backend that prompts is configured).
  if (sessionRelevant) {
    if (session.warm) {
      addRow({ glyph: '✓', label: `Biometric session warm (expires ${formatRemainingTime(session.remainingSeconds)})` });
    } else if (session.authenticatedAt) {
      addRow({ glyph: '⚠', label: `Biometric session expired (last auth ${session.authenticatedAt})`, action: 'secretless-ai warm' });
    } else {
      addRow({ glyph: '⚠', label: 'Biometric session not initialized', action: 'secretless-ai warm' });
    }
  }

  // Watcher running (transcript file monitoring).
  if (tp.watcherRunning) {
    addRow({ glyph: '✓', label: 'Transcript watcher running' });
  } else {
    addRow({ glyph: '⚠', label: 'Transcript watcher not running', action: 'secretless-ai watch' });
  }

  // Transcript files + secrets within them.
  //
  // `transcriptFiles` is a DISCOVERY count; `transcriptFilesScanned` is what was
  // actually read. Rendering the first as "N files scanned" turned a three-file
  // sample into a clean verdict over everything — measured on a real machine,
  // "Transcripts clean (8850 files scanned)" alongside `clean --dry-run` finding
  // 882 credentials in 168 of those files. Say what was read, and say what was
  // not, the same way the scan coverage warnings do.
  if (tp.transcriptSecretsFound > 0) {
    addRow({ glyph: '⚠', label: `${tp.transcriptSecretsFound} credential${tp.transcriptSecretsFound === 1 ? '' : 's'} in the ${tp.transcriptFilesScanned} most recent transcript${tp.transcriptFilesScanned === 1 ? '' : 's'}`, action: 'secretless-ai clean' });
  } else if (tp.transcriptFilesScanned > 0 && tp.transcriptFilesScanned < tp.transcriptFiles) {
    addRow({
      glyph: '✓',
      label: `No credentials in the ${tp.transcriptFilesScanned} most recent transcripts (${tp.transcriptFiles} found; the rest were not read)`,
      action: 'secretless-ai clean --dry-run',
    });
  } else if (tp.transcriptFilesScanned > 0) {
    addRow({ glyph: '✓', label: `Transcripts clean (${tp.transcriptFilesScanned} file${tp.transcriptFilesScanned === 1 ? '' : 's'} scanned)` });
  }

  // Exposed stored secrets not yet rotated (#236). A redacted transcript does
  // not end an exposure; only a new value at the provider does.
  if (s.exposuresOpen === null) {
    addRow({ glyph: '⚠', label: 'Exposed-secret records could not be read', action: 'secretless-ai secret list --needs-rotation' });
  } else if (s.exposuresOpen > 0) {
    addRow({
      glyph: '⚠',
      label: `${s.exposuresOpen} exposed secret${s.exposuresOpen === 1 ? '' : 's'} not yet rotated`,
      action: 'secretless-ai secret list --needs-rotation',
    });
  }

  // Broker daemon.
  if (brokerStatus) {
    addRow({ glyph: '✓', label: `Broker running (PID ${brokerStatus.pid}, ${formatUptime(brokerStatus.uptimeSeconds)})` });
  } else if (brokerInstalled) {
    addRow({ glyph: '⚠', label: 'Broker daemon not running', action: 'secretless-ai broker start' });
  } else {
    addRow({ glyph: '⚠', label: 'Broker daemon not installed', action: 'secretless-ai install' });
  }

  // Verdict facts — shared by the JSON and human paths so both always agree.
  const warningCount = rows.filter(r => r.glyph === '⚠').length;
  const verdict = !s.isProtected
    ? 'not-protected'
    : warningCount === 0
      ? 'protected-clean'
      : 'protected-warnings';

  // --json: emit a single valid JSON document to stdout and nothing else, so
  // the output is machine-parseable (issue #63 — same contract as `scan --json`).
  // Exit code stays 0 to match the human view; CI consumers gate on
  // `summary.verdict` / `summary.warnings`.
  if (options?.json) {
    console.log(JSON.stringify({
      tool: 'secretless-ai',
      version: VERSION,
      isProtected: s.isProtected,
      // `project` or `user`: which settings scope `isProtected` rests on.
      protectionScope: s.protectionScope,
      hookInstalled: s.hookInstalled,
      denyRuleCount: s.denyRuleCount,
      configuredTools: s.configuredTools,
      secretsFound: s.secretsFound,
      // `secretsFound: 0` is a lower bound, not a verdict, when the scan behind
      // it could not read the whole tree. A CI consumer gating on this needs to
      // tell "found nothing" from "could not look".
      scanIncomplete: s.scanIncomplete,
      // Two distinct unknowns, and `denyRuleCount` is NULL for both — a number
      // implies a measurement. `settingsUnreadable`: the file does not parse as
      // a JSON object. `settingsAmbiguous`: it parses, but a repeated member
      // means only the last copy is in effect, so what it configures cannot be
      // read as written. `denyRuleCount: 0` now means measured, and none.
      settingsUnreadable: s.settingsUnreadable ?? null,
      settingsAmbiguous: s.settingsAmbiguous ?? null,
      userSettings: user
        ? { ...user, unreadable: user.unreadable ?? null, ambiguous: user.ambiguous ?? null }
        : null,
      transcriptProtection: tp,
      // Null when the metadata file could not be read, never 0 (#236).
      exposuresOpen: s.exposuresOpen,
      // Plaintext git credential files and `store` helper settings: paths,
      // line numbers and hosts, never a user or a value. `findings` carries
      // the Verify and Fix lines `doctor` prints for each.
      gitCredentials: { ...gitCredentials, findings: gitCredentialFindings },
      backend: effectiveBackend,
      configuredBackend: configuredBackend ?? null,
      // Null unless the backend is gcp-sm. `source` says which rule applied:
      // explicit, manifest, user-config, service-account-key,
      // adc-quota-project or none; `from` says where it was read.
      gcpProject: gcpProject ?? null,
      session: { relevant: sessionRelevant, warm: session.warm },
      broker: {
        installed: brokerInstalled,
        running: !!brokerStatus,
        pid: brokerStatus?.pid ?? null,
        uptimeSeconds: brokerStatus?.uptimeSeconds ?? null,
      },
      summary: { warnings: warningCount, verdict },
    }, null, 2));
    return 0;
  }

  console.log('\n  Secretless Status\n');

  // Render the Observations block. We measure the visible width (glyph +
  // label) so the `→ command` column lines up tidily across rows.
  const headerLine = '──────────────────────────────────────────────────────────';
  console.log(`  ── Observations ${headerLine.slice(0, Math.max(0, 44))}`);
  let leftWidth = 0;
  for (const row of rows) {
    const visible = row.glyph + ' ' + row.label;
    if (visible.length > leftWidth) leftWidth = visible.length;
  }
  for (const row of rows) {
    const left = `${row.glyph} ${row.label}`;
    if (row.action) {
      const padded = left.padEnd(leftWidth, ' ');
      console.log(`  ${padded}  → ${row.action}`);
    } else {
      console.log(`  ${left}`);
    }
  }

  // Verdict — reflects warnings (count of ⚠ rows). "Protected" requires
  // the hook installed; "Clean" requires zero warnings.
  console.log();
  console.log(`  ── Verdict ${headerLine.slice(0, Math.max(0, 49))}`);
  if (!s.isProtected) {
    if (s.settingsUnreadable) {
      // `init` refuses on this project, so sending the user there is a dead
      // end — the same defect as pointing at a command that no-ops for the
      // very state that printed it. Name the blocking step instead.
      console.log(`  Not protected. Fix the JSON in ${s.settingsUnreadable.path}, then run \`secretless-ai init\`.`);
    } else {
      console.log('  Not protected. Run `secretless-ai init` to install hooks.');
    }
  } else {
    // Say when the protection comes from the user-level file, so a project
    // covered only by it does not read as having an install of its own.
    const scopeText = s.protectionScope === 'user' && user ? ` by user-level settings in ${user.path}` : '';
    if (warningCount === 0) {
      console.log(`  Protected${scopeText} — Clean`);
    } else {
      const credSuffix = s.secretsFound > 0
        ? ` (${s.secretsFound} unblocked credential${s.secretsFound === 1 ? '' : 's'} need${s.secretsFound === 1 ? 's' : ''} review)`
        : ` (${warningCount} observation${warningCount === 1 ? '' : 's'} need attention)`;
      console.log(`  Protected${scopeText}${credSuffix}`);
    }
  }

  console.log();
  return 0;
}

export function runVerify(projectDir: string, showAll = false): number {
  if (refuseMissingDir(projectDir)) return 1;
  console.log(`\n  ${c.boldWhite('Secretless Verify')}\n`);

  // Scope disclosure: verify spans more than the current project — it reads the
  // current shell's env vars (process-global) and your global AI config under
  // ~/.claude, not just files in this directory. State that so a green PASS is
  // never mistaken for "this project only".
  console.log(`  ${c.dim('Scope: this project + global AI config (~/.claude) + current-shell env vars')}\n`);

  const result = verify(projectDir);

  // Show env var availability
  const setVars = Object.entries(result.envVars).filter(([, v]) => v);
  const unsetVars = Object.entries(result.envVars).filter(([, v]) => !v);

  if (setVars.length > 0) {
    for (const [name] of setVars) {
      console.log(`  ${c.green('\u2502')} ${c.green('+')} ${name}`);
    }
  }

  if (showAll && unsetVars.length > 0) {
    for (const [name] of unsetVars) {
      console.log(`  ${c.dim('\u2502')} ${c.dim('-')} ${name}`);
    }
  } else if (unsetVars.length > 0) {
    console.log(`  ${c.dim(`  ${unsetVars.length} known env vars not set (use --all to list)`)}`);
  }

  printGcpProjectPerName(projectDir);

  // Show context exposure
  if (result.exposedInContext.length > 0) {
    console.log(divider('Exposed in AI Context'));
    for (const exp of result.exposedInContext) {
      console.log(`  ${c.brightRed('\u2502')} ${c.brightRed('!')} ${c.bold(exp.patternName)} ${c.dim(`${exp.file}:${exp.line}`)}`);
    }
  } else {
    console.log(`\n  ${c.green('AI context: clean')} ${c.dim('(no credentials found)')}`);
  }

  // Show transcript exposure (collapsed by pattern name)
  if (result.exposedInTranscripts.length > 0) {
    console.log(divider('Exposed in Transcripts'));
    const grouped = new Map<string, number>();
    for (const exp of result.exposedInTranscripts) {
      grouped.set(exp.patternName, (grouped.get(exp.patternName) ?? 0) + 1);
    }
    for (const [patternName, count] of grouped) {
      if (count === 1) {
        const single = result.exposedInTranscripts.find(e => e.patternName === patternName)!;
        console.log(`  ${c.yellow('\u2502')} ${c.yellow('!')} ${c.bold(patternName)} ${c.dim(`${single.file}:${single.line}`)}`);
      } else {
        console.log(`  ${c.yellow('\u2502')} ${c.yellow('!')} ${c.bold(patternName)} ${c.dim(`in ${count} transcript files`)}`);
      }
    }
  }

  // Surface suppressed placeholders BEFORE the verdict, so a green pass is never silent
  // over a value verify chose to hide (a real key whose body contains a token like
  // `sample`/`xxx`, or a real key on a `# example` line, is suppressed by the shared
  // detection path — the user must be told to confirm it, not shown a bare PASS).
  if (result.placeholdersSuppressed > 0) {
    const n = result.placeholdersSuppressed;
    console.log();
    console.log(`  ${c.dim(`${n} value${n > 1 ? 's' : ''} in AI context looked like a placeholder and ${n > 1 ? 'were' : 'was'} not counted.`)}`);
    console.log(`  ${c.dim('Confirm none are real: npx secretless-ai scan --show-placeholders')}`);
  }

  // Verdict
  console.log();
  if (result.passed) {
    console.log(`  ${c.boldGreen('PASS')} ${c.green('Secrets accessible via env vars, hidden from AI context.')}`);
  } else if (result.exposedInContext.length > 0 || result.exposedInTranscripts.length > 0) {
    console.log(`  ${c.boldRed('FAIL')} ${c.red('Credentials found in AI context or transcripts.')}`);
    console.log(divider('Next Steps'));
    if (result.exposedInContext.length > 0) {
      console.log(`  ${c.cyan('Protect context:')}    npx secretless-ai init`);
    }
    if (result.exposedInTranscripts.length > 0) {
      console.log(`  ${c.cyan('Redact transcripts:')} npx secretless-ai clean`);
    }
    console.log();
    return 1;
  } else {
    console.log(`  ${c.boldYellow('WARN')} ${c.yellow('No API keys found in env vars.')}`);

    const diag = quickDiagnosis();
    if (diag.wrongProfile.length > 0) {
      console.log(`  Found ${diag.wrongProfile.length} key(s) in interactive-only shell profile:`);
      for (const v of diag.wrongProfile) {
        console.log(`  ${c.yellow('\u2502')} ${c.dim('-')} ${v}`);
      }
    }
    console.log(divider('Next Steps'));
    console.log(`  ${c.cyan('Diagnose:')} npx secretless-ai doctor`);
    console.log();
    return 1;
  }
  console.log();
  return 0;
}

/** "named by <manifest line>" or "from <file>", for a resolved project. */
function describeGcpProjectSource(project: GcpProjectResolution): string {
  return `${project.source === 'manifest' ? 'named by' : 'from'} ${project.from}`;
}

/**
 * Name the GCP project each manifest name resolves from (#177). A repository's
 * .secretless can name its own project, so verify says which one was used and
 * where that was decided. File reads only: no request is made and no value is
 * read. Informational: it does not change the verdict.
 */
function printGcpProjectPerName(projectDir: string): void {
  const manifest = readManifestDetailed(projectDir);
  if (effectiveBackendName(resolveBackendType()) !== 'gcp-sm') {
    if (manifest?.gcpProjectId) {
      console.log(`\n  ${c.dim(`.secretless names GCP project ${manifest.gcpProjectId}; it applies only to the gcp-sm backend, and this machine uses another.`)}`);
    }
    return;
  }

  const project = resolveGcpProject({ projectDir });
  console.log(divider('GCP Project (gcp-sm)'));
  if (project.error) {
    console.log(`  ${c.yellow('\u2502')} ${c.yellow('!')} ${project.error}`);
    return;
  }
  if (!project.projectId) {
    console.log(`  ${c.yellow('\u2502')} ${c.yellow('!')} No GCP project set. Add "${GCP_PROJECT_KEY}: <project-id>" to .secretless.`);
    return;
  }
  const entries = manifest?.entries ?? [];
  const width = Math.max(0, ...entries.map((e) => e.name.length));
  for (const entry of entries) {
    console.log(`  ${c.dim('\u2502')} ${entry.name.padEnd(width)}  project ${project.projectId}`);
  }
  console.log(`  ${c.dim(`Project ${project.projectId} ${describeGcpProjectSource(project)}`)}`);
  console.log(`  ${c.dim(`Verify access: gcloud secrets list --project ${project.projectId} --limit 1`)}`);
}

/**
 * The git credentials block of `doctor`: plaintext credential files and a
 * `store` helper, each with Verify and Fix lines (#238). Separate from the
 * shell profile verdict and its exit code, which it does not change, and
 * untouched by `--fix`: deleting a credential file is the user's call, after
 * the token in it is revoked.
 */
function printGitCredentials(): void {
  const exposure = findGitCredentialExposure();
  const findings = describeExposure(exposure, CLI);
  console.log('  Git credentials:');
  if (findings.length === 0) {
    console.log(`    + No plaintext credential in ${exposure.checked.join(', ')}`);
  }
  for (const finding of findings) {
    console.log(`    [WARN] ${finding.message}`);
    console.log(`           Verify: ${finding.verify}`);
    finding.fix.forEach((step, i) => {
      console.log(`           ${i === 0 ? 'Fix:' : '    '}    ${i + 1}. ${step}`);
    });
  }
  if (!exposure.configChecked) {
    console.log('    - credential.helper was not checked: git could not be run');
  } else if (exposure.storeHelpers.length === 0) {
    console.log('    + No credential.helper set to store');
  }
  console.log();
}

export function runDoctor(autoFix: boolean): number {
  console.log('\n  Secretless Doctor\n');

  const result = doctor();

  // Platform & shell
  console.log(`  Platform: ${result.platform}`);
  console.log(`  Shell:    ${result.shell}`);
  console.log();

  // Profiles
  console.log('  Shell profiles:');
  for (const profile of result.profiles) {
    const tag = profile.recommendation === 'recommended'
      ? ' (RECOMMENDED)'
      : profile.recommendation === 'interactive-only'
        ? ' (interactive-only)'
        : profile.recommendation === 'login-only'
          ? ' (login-only)'
          : '';
    const profileStatus = profile.exists
      ? (profile.secretExports.length > 0
          ? `${profile.secretExports.length} key(s)`
          : 'no keys')
      : 'not found';
    console.log(`    ${profile.exists ? '+' : '-'} ~/${require('path').basename(profile.path)}${tag}: ${profileStatus}`);
    // Name and line only: the value never leaves the profile.
    for (const exp of profile.secretExports) {
      console.log(`        ${exp.name} (line ${exp.line})`);
    }
  }
  console.log();

  // Findings
  if (result.findings.length > 0) {
    console.log('  Findings:');
    for (const finding of result.findings) {
      const label = finding.severity.toUpperCase();
      console.log(`    [${label}] ${finding.message}`);
      if (finding.verify) {
        console.log(`        Verify: ${finding.verify}`);
      }
      if (finding.fix) {
        console.log(`           Fix: ${finding.fix}`);
      }
    }
    console.log();
  }

  // --fix only moves known keys between profiles; a plain-text secret is
  // moved into the store by the user, so it alone does not trigger it.
  const plainText = result.findings.filter((f) => f.kind === 'plain-text');
  const accessProblem = result.findings.some((f) => f.severity !== 'info' && f.kind !== 'plain-text');

  printGitCredentials();

  // Auto-fix if requested or if there are fixable issues
  if (autoFix && accessProblem) {
    const fix = fixProfiles();
    if (fix) {
      console.log('  Auto-fix applied:');
      console.log(`    Copied ${fix.fixed.length} export(s) from ~/${fix.sourceProfile} to ~/${fix.targetProfile}`);
      for (const v of fix.fixed) {
        console.log(`      + ${v}`);
      }
      if (fix.created) {
        console.log(`    Created ~/${fix.targetProfile}`);
      }
      console.log('    Restart your terminal for changes to take effect.\n');
      return 0;
    }
  }

  // Health verdict
  const verdictMap = {
    healthy: 'HEALTHY: All keys correctly configured for subprocess access.',
    degraded: 'DEGRADED: Keys work in your terminal but may fail in subprocesses.',
    broken: 'BROKEN: Keys are not available to subprocesses.',
  };
  if (!accessProblem && plainText.length > 0) {
    const what = plainText.length === 1
      ? 'A shell profile holds a secret in plain text.'
      : `Shell profiles hold ${plainText.length} secrets in plain text.`;
    console.log(`  DEGRADED: ${what}\n`);
    console.log(`  Store each one with \`${CLI_BARE} secret set NAME\`, then remove its export line.\n`);
    return 1;
  }
  console.log(`  ${verdictMap[result.health]}\n`);

  if (result.health !== 'healthy') {
    console.log('  Run `npx secretless-ai doctor --fix` to auto-fix.\n');
    return 1;
  }
  return 0;
}
