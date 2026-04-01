import * as path from 'path';
import { cleanTranscripts } from '../transcript';
import { startWatch, stopWatch, isWatchRunning, installLaunchAgent, uninstallLaunchAgent } from '../watch';
import { scanHistory, cleanHistory } from '../history';

export function runClean(args: string[]): void {
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

  const result = cleanTranscripts({ dryRun, targetPath, lastSession });

  if (result.totalFindings === 0) {
    console.log(`  Scanned: ${result.filesScanned} files`);
    console.log('  No credentials found. Transcripts are clean.\n');
    return;
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
}

export function runWatch(args: string[]): void {
  const action = args[0] || 'start';

  switch (action) {
    case 'start':
      if (isWatchRunning()) {
        console.log('\n  Watcher is already running.\n');
        return;
      }
      console.log('\n  Starting Secretless transcript watcher...');
      console.log('  Press Ctrl+C to stop.\n');
      startWatch();
      break;

    case 'stop':
      if (stopWatch()) {
        console.log('\n  Watcher stopped.\n');
      } else {
        console.log('\n  No watcher is running.\n');
      }
      break;

    case 'status':
      if (isWatchRunning()) {
        console.log('\n  Watcher: running\n');
      } else {
        console.log('\n  Watcher: not running');
        console.log('  Start: npx secretless-ai watch start\n');
      }
      break;

    case 'install':
      if (installLaunchAgent()) {
        console.log('\n  LaunchAgent installed.');
        console.log('  Watcher will auto-start on login.');
        console.log('  Run `launchctl load ~/Library/LaunchAgents/ai.secretless.watch.plist` to start now.\n');
      } else {
        console.log('\n  LaunchAgent installation is only supported on macOS.\n');
      }
      break;

    case 'uninstall':
      if (uninstallLaunchAgent()) {
        stopWatch();
        console.log('\n  LaunchAgent removed. Watcher will no longer auto-start.\n');
      } else {
        console.log('\n  No LaunchAgent found to remove.\n');
      }
      break;

    case '--help':
    case '-h':
    default:
      if (action && action !== '--help' && action !== '-h') {
        console.error(`\n  Unknown watch action: ${action}`);
      }
      console.log('\n  Usage: secretless-ai watch <start|stop|status|install|uninstall>\n');
      console.log('  Commands:');
      console.log('    start      Start watching transcripts for credentials');
      console.log('    stop       Stop the watcher');
      console.log('    status     Show watcher status');
      console.log('    install    Install as macOS LaunchAgent');
      console.log('    uninstall  Remove LaunchAgent\n');
      if (action && action !== '--help' && action !== '-h') process.exit(1);
      break;
  }
}

export function runScanHistory(): void {
  console.log('\n  Shell History Scanner\n');

  scanHistory().then((result) => {
    console.log(`  Files scanned: ${result.filesScanned}`);

    if (result.findingCount === 0) {
      console.log('  No credentials found in shell history.\n');
      return;
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
    process.exit(1);
  }).catch((err) => {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}

export function runCleanHistory(dryRun: boolean): void {
  if (dryRun) {
    console.log('\n  Shell History Cleaner (dry run)\n');
  } else {
    console.log('\n  Shell History Cleaner\n');
  }

  cleanHistory(dryRun).then((result) => {
    console.log(`  Files scanned:  ${result.filesScanned}`);
    console.log(`  Files modified: ${result.filesModified}`);
    console.log(`  Lines redacted: ${result.linesRedacted}`);

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
  }).catch((err) => {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
