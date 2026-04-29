import { installPreCommitHook, uninstallPreCommitHook, isHookInstalled } from '../git-hook';
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
  const { findings, blockedFiles } = scanStagedFiles({ noIgnore });
  const total = findings.length + blockedFiles.length;

  if (total === 0) {
    // Clean — allow commit
    return 0;
  }

  console.error('\n  secretless: Blocked commit — secrets detected\n');

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

  console.error('  Remove the secrets and try again.');
  console.error('  To bypass: git commit --no-verify\n');
  return 1;
}
