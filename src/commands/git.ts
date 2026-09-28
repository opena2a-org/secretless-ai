import { installPreCommitHook, uninstallPreCommitHook, isHookInstalled, installedHookVersion } from '../git-hook';
import { scanStagedFiles } from '../scan-staged';
import { runHookCheck } from '../session/hook';

export function runHook(args: string[]): number {
  const subcommand = args[0];
  const projectDir = process.cwd();

  // Fast path: --check-only for Claude Code PreToolUse hook (must be first arg).
  // runHookCheck calls process.exit() internally — this path bypasses telemetry
  // by design (it fires on every Claude Code tool call and would dominate the dataset).
  if (subcommand === '--check-only') {
    runHookCheck();
    return 0; // Unreachable: runHookCheck always exits.
  }

  switch (subcommand) {
    case 'install': {
      const result = installPreCommitHook(projectDir);
      console.log(`\n  ${result.message}\n`);
      return result.installed ? 0 : 1;
    }

    case 'uninstall': {
      const result = uninstallPreCommitHook(projectDir);
      console.log(`\n  ${result.message}\n`);
      return result.removed ? 0 : 1;
    }

    case 'status': {
      const installed = isHookInstalled(projectDir);
      console.log(`\n  Pre-commit hook: ${installed ? 'installed' : 'not installed'}`);
      if (!installed) {
        console.log('  Install: npx secretless-ai hook install');
      } else if (installedHookVersion(projectDir) === null) {
        // An older hook body runs `npx secretless-ai scan-staged` unpinned.
        console.log('  This hook runs an unpinned scanner. Update it: npx secretless-ai hook install');
      }
      console.log();
      return 0;
    }

    default:
      console.error(`\n  Unknown hook command: ${subcommand ?? '(none)'}`);
      console.log('  Usage:');
      console.log('    secretless-ai hook install       Install pre-commit hook');
      console.log('    secretless-ai hook uninstall     Remove pre-commit hook');
      console.log('    secretless-ai hook status        Check hook status');
      console.log('    secretless-ai hook --check-only  Session gate for Claude Code hooks (silent, fast)\n');
      return 1;
  }
}

export function runScanStaged(args: string[] = []): number {
  const noIgnore = args.includes('--no-ignore');
  const allowUnscanned = args.includes('--allow-unscanned');
  const { findings, blockedFiles, unscannedFiles, error } = scanStagedFiles({ noIgnore });

  if (error) {
    // Nothing was scanned, so there is no clean result to report.
    console.error(`\n  secretless: Blocked commit — ${error}\n`);
    console.error('  To bypass: git commit --no-verify\n');
    return 1;
  }

  const total = findings.length + blockedFiles.length;
  const blockOnUnscanned = unscannedFiles.length > 0 && !allowUnscanned;

  if (total === 0 && !blockOnUnscanned) {
    if (unscannedFiles.length > 0) {
      console.error('\n  secretless: Not scanned (--allow-unscanned):');
      for (const u of unscannedFiles) {
        console.error(`    - ${u.file} (${u.reason})`);
      }
      console.error();
    }
    // Clean — allow commit
    return 0;
  }

  console.error(
    total > 0
      ? '\n  secretless: Blocked commit — secrets detected\n'
      : '\n  secretless: Blocked commit — staged files could not be scanned\n',
  );

  if (blockedFiles.length > 0) {
    console.error('  Secret files staged for commit:');
    for (const file of blockedFiles) {
      console.error(`    ! ${file}`);
    }
    console.error();
  }

  if (findings.length > 0) {
    console.error('  Credentials found in staged files:');
    for (const f of findings) {
      console.error(`    ! ${f.patternName} in ${f.file}:${f.line}`);
    }
    console.error();
  }

  if (unscannedFiles.length > 0) {
    console.error(allowUnscanned ? '  Not scanned (--allow-unscanned):' : '  Staged files that could not be scanned:');
    for (const u of unscannedFiles) {
      console.error(`    ${allowUnscanned ? '-' : '!'} ${u.file} (${u.reason})`);
    }
    console.error();
  }

  if (total > 0) {
    console.error('  Remove the secrets and try again.');
  }
  if (blockOnUnscanned) {
    console.error('  Review the unscanned files by hand. To let them through, add --allow-unscanned to the scan-staged command.');
  }
  console.error('  To bypass: git commit --no-verify\n');
  return 1;
}
