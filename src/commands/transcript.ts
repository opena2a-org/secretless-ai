import * as path from 'path';
import { cleanTranscripts, MAX_LINE_SIZE, type CleanResult } from '../transcript';
import { startWatch, stopWatch, isWatchRunning, installLaunchAgent, uninstallLaunchAgent } from '../watch';
import { scanHistory, cleanHistory } from '../history';
import { shellQuote } from './core';
import { CLI_BARE } from './utils';
import { SecretStore } from '../secret-store';
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
  console.log(`  Next:     rotate each one at its provider, then  ${CLI_BARE} secret set NAME`);
  console.log(`  Open:     ${CLI_BARE} secret list --needs-rotation${dryRun ? '   (run without --dry-run to record)' : ''}\n`);
}

export interface RunCleanOptions {
  /** Store factory, read only when something was redacted. For DI/testing. */
  createStore?: () => SecretStore;
}

export async function runClean(args: string[], options: RunCleanOptions = {}): Promise<number> {
  const dryRun = args.includes('--dry-run');
  const lastSession = args.includes('--last');
  let targetPath: string | undefined;

  const pathIdx = args.indexOf('--path');
  if (pathIdx !== -1 && args[pathIdx + 1]) {
    targetPath = path.resolve(args[pathIdx + 1]);
  }

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

  // Held in memory for the stored-secret comparison below, then dropped.
  const spans: RedactedSpan[] = [];
  const result = cleanTranscripts({
    dryRun,
    targetPath,
    lastSession,
    onRedacted: (span, where) => { spans.push({ span, ...where }); },
  });

  if (result.totalFindings === 0) {
    console.log(`  Scanned: ${result.filesScanned} files`);
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

  console.log(`  Scanned:  ${result.filesScanned} files`);
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

export async function runWatch(args: string[]): Promise<number> {
  const action = args[0];

  switch (action) {
    case 'start':
      if (isWatchRunning()) {
        console.log('\n  Watcher is already running.\n');
        return 0;
      }
      console.log('\n  Starting Secretless transcript watcher...');
      if (!startWatch()) {
        console.error('\n  Watcher did not start; the log lines above say why.\n');
        return 1;
      }
      console.log('  Watcher is running. Press Ctrl+C to stop.\n');
      // The watcher runs in this process, in the foreground. Returning here
      // would hand an exit code to the dispatcher, whose process.exit() ends
      // the watcher that was just reported running. The process ends in the
      // SIGTERM/SIGINT handler startWatch installs, which removes the PID file.
      return await new Promise<number>(() => {});

    case 'stop':
      if (stopWatch()) {
        console.log('\n  Watcher stopped.\n');
      } else {
        console.log('\n  No watcher is running.\n');
      }
      return 0;

    case 'status':
      if (isWatchRunning()) {
        console.log('\n  Watcher: running\n');
      } else {
        console.log('\n  Watcher: not running');
        console.log('  Start: npx secretless-ai watch start\n');
      }
      return 0;

    case 'install':
      if (installLaunchAgent()) {
        console.log('\n  LaunchAgent installed.');
        console.log('  Watcher will auto-start on login.');
        console.log('  Run `launchctl load ~/Library/LaunchAgents/ai.secretless.watch.plist` to start now.\n');
      } else {
        console.log('\n  LaunchAgent installation is only supported on macOS.\n');
      }
      return 0;

    case 'uninstall':
      if (uninstallLaunchAgent()) {
        stopWatch();
        console.log('\n  LaunchAgent removed. Watcher will no longer auto-start.\n');
      } else {
        console.log('\n  No LaunchAgent found to remove.\n');
      }
      return 0;

    case '--help':
    case '-h':
    default: {
      const isUnknown = !!action && action !== '--help' && action !== '-h';
      if (isUnknown) {
        console.error(`\n  Unknown watch action: ${action}`);
      }
      console.log('\n  Usage: secretless-ai watch <start|stop|status|install|uninstall>\n');
      console.log('  Commands:');
      console.log('    start      Start watching transcripts for credentials');
      console.log('    stop       Stop the watcher');
      console.log('    status     Show watcher status');
      console.log('    install    Install as macOS LaunchAgent');
      console.log('    uninstall  Remove LaunchAgent\n');
      return isUnknown ? 1 : 0;
    }
  }
}

export async function runScanHistory(): Promise<number> {
  console.log('\n  Shell History Scanner\n');

  try {
    const result = await scanHistory();
    console.log(`  Files scanned: ${result.filesScanned}`);

    if (result.findingCount === 0) {
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

    if (result.linesRedacted === 0) {
      console.log('\n  No credentials found in shell history.\n');
    } else if (dryRun) {
      console.log('\n  Dry run complete. Run without --dry-run to apply changes.\n');
    } else {
      console.log('\n  History cleaned. Backups saved with .bak extension.\n');
    }
    return 0;
  } catch (err) {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}
