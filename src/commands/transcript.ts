import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { cleanTranscripts, transcriptTarget, MAX_LINE_SIZE, type CleanProgress, type CleanResult } from '../transcript';
import { startWatch, stopWatch, isWatchRunning, watchStatus, installWatcher, uninstallLaunchAgent, resolveWatchDirs } from '../watch';
import type { InstallWatcherResult, WatchStatus } from '../watch';
import { askOnTerminal } from './secrets';
import { scanHistory, cleanHistory, HISTORY_LINES_NOT_READ, MAX_LINES as HISTORY_MAX_LINES, type HistoryScanResult } from '../history';
import { pathOperand, shellQuote } from './core';
import { CLI, CLI_BARE, VERSION } from './utils';
import { escapeForDisplay, escapePathForDisplay } from '../display-safe';
import { EXIT_USAGE } from '../argv';
import { SecretStore, isSettableSecretName, notSettableReason } from '../secret-store';
import { markRedactedSecretsExposed } from '../secret-exposure';
import type { ExposureMarks, RedactedSpan } from '../secret-exposure';

/**
 * Name the lines `clean` did not read. A line over the length cap is skipped
 * whole, so "Transcripts are clean" over a 60 KB line carrying a token reported
 * a line nobody read as clean.
 */
function reportLinesNotRead(result: CleanResult): void {
  const n = result.totalLinesNotRead;
  if (n === 0) return;
  const files = result.linesNotRead.length;
  console.log(`  Not read: ${n} line${n > 1 ? 's' : ''} longer than ${MAX_LINE_SIZE} characters in ${files} file${files > 1 ? 's' : ''}, left unchanged.`);
  for (const entry of result.linesNotRead.slice(0, 10)) {
    const more = entry.lines.length > 10 ? `, … and ${entry.lines.length - 10} more` : '';
    console.log(`    ${entry.file}  line${entry.lines.length > 1 ? 's' : ''} ${entry.lines.slice(0, 10).join(', ')}${more}`);
  }
  if (files > 10) console.log(`    … and ${files - 10} more files`);
  console.log('  A line over this length is skipped whole, so a credential on it is neither reported nor redacted.');
  console.log(`  Verify:   awk 'length($0) > ${MAX_LINE_SIZE} { print FNR ": " length($0) }' ${shellQuote(result.linesNotRead[0].path)}\n`);
}

/**
 * Name the stored secrets whose values were among the redacted spans, and the
 * next step for each (#236). Redacting a transcript does not revoke a key.
 */
function reportExposures(marks: ExposureMarks, dryRun: boolean): void {
  if (marks.notChecked) {
    console.log('  Not checked: whether a redacted value is one of your stored secrets.');
    console.log(`  Reason:   ${marks.notChecked}`);
    console.log(`  Verify:   ${CLI_BARE} secret list\n`);
    return;
  }
  const total = marks.marked.length + marks.alreadyOpen.length + marks.failed.length;
  if (total === 0) return;
  console.log(`  Stored secrets among the redacted values: ${total}`);
  for (const m of marks.marked) {
    console.log(`    ${m.name}  ${dryRun ? 'would be marked exposed' : 'marked exposed'} (${m.where})`);
  }
  for (const m of marks.alreadyOpen) {
    console.log(`    ${m.name}  already marked exposed since ${m.exposedAt}`);
  }
  for (const m of marks.failed) {
    console.log(`    ${m.name}  NOT marked exposed: ${m.reason}`);
  }
  console.log('  A redacted value still works until it is replaced at its provider.');
  // The store holds names `secret set` refuses, ones that start with a digit,
  // '_' or '-' (#509). With such a name listed, each name gets a step of its
  // own: the command for a name `secret set` takes, the reason in place of it
  // for a name it refuses.
  const names = [...marks.marked, ...marks.alreadyOpen, ...marks.failed].map((m) => m.name);
  if (names.every((name) => isSettableSecretName(name))) {
    console.log(`  Next:     rotate each one at its provider, then  ${CLI_BARE} secret set NAME`);
  } else {
    console.log('  Next:     rotate each one at its provider, then store its new value');
    for (const name of names) {
      console.log(isSettableSecretName(name)
        ? `            ${CLI_BARE} secret set ${name}`
        : `            ${notSettableReason(name)}; store its new value the way it was first stored.`);
    }
  }
  console.log(`  Open:     ${CLI_BARE} secret list --needs-rotation${dryRun ? '   (run without --dry-run to record)' : ''}\n`);
}

/**
 * Refuse a `--path` that `clean` reads nothing from, on stderr. Returns true
 * when it refused. It used to print "Scanned: 0 files" and "Transcripts are
 * clean" at exit 0 over a missing path, and a file that is not a transcript
 * read the default directory instead of the file given.
 */
function refuseCleanTarget(targetPath: string): boolean {
  const target = transcriptTarget(targetPath);
  if (target.kind === 'directory' || target.kind === 'file') return false;
  const named = escapePathForDisplay(targetPath);
  const what = target.kind === 'missing'
    ? 'was not found'
    : target.kind === 'notTranscript'
      ? 'is not a transcript (.jsonl or .md)'
      : `could not be read (${target.code})`;
  console.error(`\n  Error: ${named} ${what}. Nothing was read.`);
  console.error(`  Verify: ls -ld ${pathOperand(targetPath)}`);
  // The remark is a line of its own: pasted into a zsh that does not take `#`
  // as a comment, a remark after the command becomes arguments to it.
  console.error(`  Fix:    ${CLI} clean --dry-run`);
  console.error('          reads the transcripts under ~/.claude/projects\n');
  return true;
}

export interface RunCleanOptions {
  /** Store factory, read only when something was redacted. For DI/testing. */
  createStore?: () => SecretStore;
  /** Where the progress line goes; stderr when unset. For DI/testing. */
  progressOut?: ProgressOut;
  /** The clock the run time is read from, in milliseconds. For DI/testing. */
  now?: () => number;
}

/** A stream the progress line can be written to. */
export interface ProgressOut {
  isTTY?: boolean;
  write(chunk: string): unknown;
}

/** Least time between two rewrites of the progress line, in milliseconds. */
const PROGRESS_INTERVAL_MS = 100;

/**
 * The line `clean` keeps up to date while it reads (#127). Without it, a run
 * over a large `~/.claude/projects` printed `Scanning Claude Code
 * transcripts...` and nothing else until it finished. The line is written to
 * `out` only when `out` is a terminal, so a Stop hook, a pipe or a log gets
 * none of it, and it is rewritten in place with a carriage return and
 * spaces, which every terminal reads the same. `clear` blanks it before the
 * report is printed.
 */
function progressLine(out: ProgressOut, now: () => number): { update?: (p: CleanProgress) => void; clear: () => void } {
  if (!out.isTTY) return { clear: () => {} };
  let width = 0;
  let last = -Infinity;
  const put = (text: string): void => {
    out.write(`\r${text}${' '.repeat(Math.max(0, width - text.length))}\r`);
    width = text.length;
  };
  return {
    update: (p) => {
      const at = now();
      // The first and the last state are always shown; between them, at most
      // one rewrite per interval.
      if (p.filesDone !== 0 && p.filesDone !== p.filesTotal && at - last < PROGRESS_INTERVAL_MS) return;
      last = at;
      const share = p.bytesTotal > 0 ? p.bytesDone / p.bytesTotal : p.filesDone / Math.max(p.filesTotal, 1);
      put(`  Read ${p.filesDone} of ${p.filesTotal} files (${Math.floor(share * 100)}%)`);
    },
    clear: () => {
      if (width > 0) put('');
    },
  };
}

/** A run time as the report prints it: seconds, to a tenth. */
export function formatRunTime(ms: number): string {
  return `${(Math.max(0, ms) / 1000).toFixed(1)}s`;
}

export async function runClean(args: string[], options: RunCleanOptions = {}): Promise<number> {
  const dryRun = args.includes('--dry-run');
  const lastSession = args.includes('--last');
  let targetPath: string | undefined;

  const pathIdx = args.indexOf('--path');
  if (pathIdx !== -1 && args[pathIdx + 1]) {
    targetPath = path.resolve(args[pathIdx + 1]);
  }

  if (targetPath && refuseCleanTarget(targetPath)) return 1;

  // Warn when scanning outside the default transcript directory
  if (targetPath) {
    const os = require('os');
    const claudeDir = path.join(os.homedir(), '.claude');
    if (!targetPath.startsWith(claudeDir)) {
      console.log(`  Note: scanning outside ~/.claude/ — target: ${targetPath}\n`);
    }
  }

  console.log(targetPath
    ? `\n  Scanning transcripts at ${targetPath}...\n`
    : '\n  Scanning Claude Code transcripts...\n');

  const now = options.now ?? Date.now;
  const startedAt = now();
  const progress = progressLine(options.progressOut ?? process.stderr, now);
  // Held in memory for the stored-secret comparison below, then dropped.
  const spans: RedactedSpan[] = [];
  const result = cleanTranscripts({
    dryRun,
    targetPath,
    lastSession,
    onRedacted: (span, where) => { spans.push({ span, ...where }); },
    onProgress: progress.update,
  });
  progress.clear();
  // The run time is printed with the file count, so a slow run says how slow.
  const took = formatRunTime(now() - startedAt);

  // No file read is no verdict: an empty directory is not a clean transcript.
  if (result.filesScanned === 0) {
    console.log('  Scanned: 0 files — nothing to report.\n');
    return 0;
  }

  if (result.totalFindings === 0) {
    console.log(`  Scanned: ${result.filesScanned} files in ${took}`);
    if (result.totalLinesNotRead > 0) {
      console.log('  No credentials found in the lines that were read.\n');
      reportLinesNotRead(result);
      return 0;
    }
    console.log('  No credentials found. Transcripts are clean.\n');
    return 0;
  }

  // Group findings by file
  const byFile = new Map<string, typeof result.findings>();
  for (const f of result.findings) {
    const existing = byFile.get(f.file) || [];
    existing.push(f);
    byFile.set(f.file, existing);
  }

  for (const [file, findings] of byFile) {
    console.log(`  ${file}`);
    for (const f of findings) {
      console.log(`    Line ${f.line}:  ${f.jsonPath} → [REDACTED:${f.patternId}]`);
    }
    console.log();
  }

  console.log(`  Scanned:  ${result.filesScanned} files in ${took}`);
  console.log(`  Found:    ${result.totalFindings} credential(s) in ${result.filesWithSecrets} file(s)`);
  if (dryRun) {
    console.log('  Mode:     dry-run (no changes made)');
    console.log('  Run without --dry-run to redact.\n');
  } else {
    console.log(`  Redacted: ${result.totalRedacted}\n`);
  }
  const marks = await markRedactedSecretsExposed(spans, options.createStore ?? (() => new SecretStore()), {
    foundBy: 'clean',
    dryRun,
  });
  spans.length = 0;
  reportExposures(marks, dryRun);
  reportLinesNotRead(result);
  return 0;
}

/** A directory as the user reads it: the home directory shown as `~`. */
function displayDir(dir: string): string {
  const home = os.homedir();
  return dir === home || dir.startsWith(home + path.sep) ? '~' + dir.slice(home.length) : dir;
}

/** `(watching A, B)`, for a status line. */
function watchingClause(dirs: readonly string[]): string {
  return dirs.length > 0 ? ` (watching ${dirs.map(displayDir).join(', ')})` : '';
}

/**
 * The values of every `--dir` in `args`, in order (#237). `prepareArgv` has
 * already split `--dir=X` into two tokens and refused a `--dir` with no value.
 */
function dirFlags(args: string[]): string[] {
  const dirs: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--dir' && i + 1 < args.length) dirs.push(args[++i]);
  }
  return dirs;
}

export async function runWatch(args: string[]): Promise<number> {
  const action = args[0];
  const dirs = dirFlags(args);

  switch (action) {
    case 'start': {
      const current = watchStatus();
      if (current.running) {
        console.log(`\n  Watcher is already running${watchingClause(current.dirs)}.\n`);
        return 0;
      }
      console.log('\n  Starting Secretless transcript watcher...');
      if (!startWatch({ dirs })) {
        console.error('\n  Watcher did not start; the log lines above say why.\n');
        return 1;
      }
      console.log(`  Watcher is running${watchingClause(watchStatus().dirs)}. Press Ctrl+C to stop.\n`);
      // The watcher runs in this process, in the foreground. Returning here
      // would hand an exit code to the dispatcher, whose process.exit() ends
      // the watcher that was just reported running. The process ends in the
      // SIGTERM/SIGINT handler startWatch installs, which removes the PID file.
      return await new Promise<number>(() => {});
    }

    case 'stop':
      if (stopWatch()) {
        console.log('\n  Watcher stopped.\n');
      } else {
        console.log('\n  No watcher is running.\n');
      }
      return 0;

    case 'status': {
      const current = watchStatus();
      if (current.running) {
        console.log(`\n  Watcher: running${watchingClause(current.dirs)}\n`);
      } else {
        console.log('\n  Watcher: not running');
        console.log(`  Would watch: ${resolveWatchDirs(dirs).map(displayDir).join(', ')}`);
        console.log(`  Start: ${CLI} watch install\n`);
      }
      return 0;
    }

    case 'install': {
      const result = await installWatcher({ dirs });
      console.log();
      for (const line of installWatcherLines(result)) console.log(`  ${line}`);
      console.log();
      return result.running ? 0 : 1;
    }

    case 'uninstall': {
      const removed = uninstallLaunchAgent();
      const stopped = stopWatch();
      if (removed || stopped) {
        console.log(`\n  ${removed ? 'LaunchAgent removed. ' : ''}${stopped ? 'Watcher stopped.' : 'No watcher was running.'}\n`);
      } else {
        console.log('\n  No LaunchAgent found to remove, and no watcher is running.\n');
      }
      return 0;
    }

    case '--help':
    case '-h':
    default: {
      const isUnknown = !!action && action !== '--help' && action !== '-h';
      if (isUnknown) {
        console.error(`\n  Unknown watch action: ${escapeForDisplay(action)}`);
      }
      console.log('\n  Usage: secretless-ai watch <start|stop|status|install|uninstall> [--dir <path>]...\n');
      console.log('  Commands:');
      console.log('    start      Start watching transcripts for credentials (foreground)');
      console.log('    stop       Stop the watcher');
      console.log('    status     Show watcher status and the directories it covers');
      console.log('    install    Start the watcher in the background; on macOS also at each login');
      console.log('    uninstall  Remove the LaunchAgent and stop the watcher');
      console.log('    --dir <p>  start, install: a directory to watch besides the default (repeatable)\n');
      // Asked for, the usage is the answer. With no action nothing ran, so
      // that exits EXIT_USAGE as an unknown one does (#127).
      return action === '--help' || action === '-h' ? 0 : EXIT_USAGE;
    }
  }
}

/** What `watch install` and `init` print about an install attempt (#237). */
function installWatcherLines(result: InstallWatcherResult): string[] {
  if (!result.running) {
    return [
      `Transcript watcher not installed: ${result.reason ?? 'it did not start'}.`,
      `Verify: ${CLI_BARE} watch status`,
    ];
  }
  const lines = [
    result.alreadyRunning
      ? `Transcript watcher already running${watchingClause(result.dirs)}.`
      : `Transcript watcher running${watchingClause(result.dirs)}: a credential that reaches a saved transcript is redacted, logged to ~/.secretless-ai/watch.log and shown as a desktop notification.`,
  ];
  if (result.launchAgent) {
    lines.push('It also starts at each login: ~/Library/LaunchAgents/ai.secretless.watch.plist.');
  } else if (!result.alreadyRunning && process.platform !== 'darwin') {
    lines.push(`It ends with this login session; to start it again: ${CLI_BARE} watch install`);
  }
  return lines;
}

export interface WatcherOfferOptions {
  /** `init --no-watch`: leave the watcher as it is, and do not ask. */
  noWatch?: boolean;
  /** Asks the yes/no question; null when there is no terminal to ask on. For tests. */
  ask?: (question: string) => Promise<boolean | null>;
  install?: (options?: { dirs?: string[] }) => Promise<InstallWatcherResult>;
  status?: () => WatchStatus;
  /** Whether a directory exists; `fs.existsSync` unless given. */
  exists?: (dir: string) => boolean;
}

/**
 * After `init`: offer the transcript watcher, and install it on a yes (#237).
 * On a terminal the question defaults to yes. With no terminal to ask on, or
 * with `--no-watch`, the watcher is left as it is and the install command is
 * named instead; so is it when no transcript directory exists yet, because
 * a watcher with nothing to watch does not start.
 */
export async function offerTranscriptWatcher(options: WatcherOfferOptions = {}): Promise<void> {
  if (options.noWatch) {
    console.log('  Transcript watcher left as it is (--no-watch).');
    console.log();
    return;
  }
  const current = (options.status ?? watchStatus)();
  if (current.running) {
    console.log(`  Transcript watcher running${watchingClause(current.dirs)}.`);
    console.log();
    return;
  }
  const dirs = resolveWatchDirs();
  const exists = options.exists ?? fs.existsSync;
  if (!dirs.some(exists)) {
    console.log(`  Transcript watcher not installed: no transcript directory yet. Claude Code creates ${displayDir(dirs[0])} at its first session.`);
    console.log(`    Install it then: ${CLI_BARE} watch install`);
    console.log();
    return;
  }
  const question = `  Install the transcript watcher? It redacts a credential that reaches a saved transcript under ${dirs.map(displayDir).join(', ')} and shows a desktop notification, now and at each login. [Y/n] `;
  const answer = options.ask
    ? await options.ask(question)
    : await askOnTerminal(question, undefined, undefined, true);
  if (answer === null) {
    console.log(`  Transcript watcher not installed: no terminal to ask on. Install: ${CLI_BARE} watch install`);
    console.log();
    return;
  }
  if (!answer) {
    console.log(`  Transcript watcher not installed. Install later: ${CLI_BARE} watch install`);
    console.log();
    return;
  }
  const result = await (options.install ?? installWatcher)();
  for (const line of installWatcherLines(result)) console.log(`  ${line}`);
  console.log();
}

export interface RunScanHistoryOptions {
  /** `scan --history --json` or `--format json`: one JSON document on stdout. */
  json?: boolean;
}

/** How many lines a run of lines not read holds. */
function runLength(run: { firstLine: number; lastLine: number }): number {
  return run.lastLine - run.firstLine + 1;
}

/**
 * Name what the history scan did not read (#462): a history file that is
 * present and could not be read, and the lines before the last 10000 or
 * longer than 4096 characters. The scan skipped each without a word, so
 * "No credentials found in shell history." at exit 0 also covered history it
 * never read. `clean-history` prints the same lists for what it did not read
 * and so did not clean (#466).
 */
function reportHistoryNotRead(result: Pick<HistoryScanResult, 'filesNotRead' | 'linesNotRead'>): void {
  const files = result.filesNotRead ?? [];
  if (files.length > 0) {
    const n = files.length;
    console.log(`  ${n} history file${n > 1 ? 's' : ''} not read, so not known to be clean:`);
    for (const f of files) console.log(`    ${f.file}: ${f.reason}`);
    console.log(`  Verify: ls -l ${files.map((f) => f.file).join(' ')}\n`);
  }
  const runs = result.linesNotRead ?? [];
  if (runs.length > 0) {
    const n = runs.reduce((sum, run) => sum + runLength(run), 0);
    console.log(`  ${n} line${n > 1 ? 's' : ''} not read, so not known to be clean:`);
    for (const run of runs.slice(0, 10)) {
      const at = run.firstLine === run.lastLine ? `${run.firstLine}` : `${run.firstLine}-${run.lastLine}`;
      console.log(`    ${run.file}:${at}: ${run.reason}`);
    }
    if (runs.length > 10) console.log(`    … and ${runs.length - 10} more`);
    // `clean-history` has no line window, so its dry run counts a credential
    // on a line before the window. The remark is a line of its own, as under
    // `refuseCleanTarget`.
    if (runs.some((run) => run.reason === HISTORY_LINES_NOT_READ.beforeWindow)) {
      console.log(`  Verify: ${CLI} clean-history --dry-run`);
      console.log(`          clean-history has no ${HISTORY_MAX_LINES}-line limit`);
    }
    console.log();
  }
}

/**
 * `scan --history --json`: one JSON document on stdout and nothing else, so a
 * caller can parse it (#458: the flag was not read and the text report was
 * printed). The exit codes are the text report's: 1 when a credential is
 * found, 0 when none is, and 1 with the error on stderr when the scan fails.
 */
async function runScanHistoryJson(): Promise<number> {
  let result: HistoryScanResult;
  try {
    result = await scanHistory();
  } catch (err) {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
  console.log(JSON.stringify({
    tool: 'secretless-ai',
    version: VERSION,
    // Named one by one, so a field added to the finding later is not written
    // here until it is added to this list.
    findings: result.findings.map(({ file, line, patternId, patternName, preview }) => (
      { file, line, patternId, patternName, preview }
    )),
    summary: { total: result.findingCount, filesScanned: result.filesScanned },
    // What the scan did not read, and why (#462): history files that are
    // present and could not be read, and runs of lines it did not match. Both
    // lists are written whether or not they are empty, so a consumer reads an
    // empty list as nothing left unread rather than as a field left out.
    notRead: {
      files: (result.filesNotRead ?? []).map(({ file, reason }) => ({ file, reason })),
      lines: (result.linesNotRead ?? []).map((run) => ({
        file: run.file,
        firstLine: run.firstLine,
        lastLine: run.lastLine,
        count: runLength(run),
        reason: run.reason,
      })),
    },
  }, null, 2));
  return result.findingCount > 0 ? 1 : 0;
}

export async function runScanHistory(options: RunScanHistoryOptions = {}): Promise<number> {
  if (options.json) return runScanHistoryJson();
  console.log('\n  Shell History Scanner\n');

  try {
    const result = await scanHistory();
    console.log(`  Files scanned: ${result.filesScanned}`);
    const notRead = (result.filesNotRead?.length ?? 0) > 0 || (result.linesNotRead?.length ?? 0) > 0;

    if (result.findingCount === 0) {
      if (notRead) {
        // Nothing was found in what was read, which is a different claim, and
        // with no file read there is nothing to claim.
        console.log(result.filesScanned === 0
          ? '  No history file was read.\n'
          : '  No credentials found in the lines that were read.\n');
        reportHistoryNotRead(result);
        return 0;
      }
      console.log('  No credentials found in shell history.\n');
      return 0;
    }

    console.log(`  Found ${result.findingCount} credential(s):\n`);
    for (const finding of result.findings) {
      console.log(`  [${finding.patternId}] ${finding.patternName}`);
      console.log(`         ${finding.file}:${finding.line}`);
      console.log(`         ${finding.preview}`);
      console.log();
    }

    console.log('  Run `npx secretless-ai clean-history` to redact credentials.');
    console.log('  Run `npx secretless-ai clean-history --dry-run` to preview changes.\n');
    reportHistoryNotRead(result);
    return 1;
  } catch (err) {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

export async function runCleanHistory(dryRun: boolean): Promise<number> {
  if (dryRun) {
    console.log('\n  Shell History Cleaner (dry run)\n');
  } else {
    console.log('\n  Shell History Cleaner\n');
  }

  try {
    const result = await cleanHistory(dryRun);
    // A dry run writes nothing, so it reports what would change.
    if (dryRun) {
      console.log(`  Files scanned:                ${result.filesScanned}`);
      console.log(`  Files that would change:      ${result.filesModified}`);
      console.log(`  Lines that would be redacted: ${result.linesRedacted}`);
    } else {
      console.log(`  Files scanned:  ${result.filesScanned}`);
      console.log(`  Files modified: ${result.filesModified}`);
      console.log(`  Lines redacted: ${result.linesRedacted}`);
    }

    if (result.backupPaths.length > 0) {
      console.log('\n  Backups created:');
      for (const p of result.backupPaths) {
        console.log(`    ${p}`);
      }
    }

    // A history file not read and a line not matched were passed over without
    // a word, so this said "No credentials found in shell history." over
    // history it never read (#466). The claim is now made of what was read,
    // and what was not is listed below it, as `scan --history` lists it.
    const notRead = (result.filesNotRead?.length ?? 0) > 0 || (result.linesNotRead?.length ?? 0) > 0;
    if (result.linesRedacted === 0) {
      if (!notRead) {
        console.log('\n  No credentials found in shell history.\n');
      } else if (result.filesScanned === 0) {
        console.log('\n  No history file was read.\n');
      } else {
        console.log('\n  No credentials found in the lines that were read.\n');
      }
    } else if (dryRun) {
      console.log('\n  Dry run complete. Run without --dry-run to apply changes.\n');
    } else if (notRead) {
      console.log('\n  History cleaned in the lines that were read. Backups saved with .bak extension.\n');
    } else {
      console.log('\n  History cleaned. Backups saved with .bak extension.\n');
    }
    reportHistoryNotRead(result);
    return 0;
  } catch (err) {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}
