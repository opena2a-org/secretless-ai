import { installPreCommitHook, uninstallPreCommitHook, isHookInstalled, preCommitTargetMissing } from '../git-hook';
import { scanStagedFiles } from '../scan-staged';
import { runHookCheck } from '../session/hook';
import { escapeForDisplay, escapePathForDisplay, hasDisplayHazard, shellQuote } from '../display-safe';
import { EXIT_USAGE } from '../argv';

export function runHook(args: string[], projectDir: string = process.cwd()): number {
  const subcommand = args[0];

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
      // The hook names the copy that installed it by path. Once that copy is
      // gone the hook blocks every commit, so it is not reported as installed
      // alone.
      const missing = installed ? preCommitTargetMissing(projectDir) : null;
      if (missing !== null) {
        console.log(`\n  Pre-commit hook: installed, target missing: ${escapePathForDisplay(missing)}`);
        console.log(`  Verify: ls -l ${hasDisplayHazard(missing) ? '<path>' : shellQuote(missing)}`);
        console.log('  Fix:    npx secretless-ai hook install');
        console.log();
        return 0;
      }
      console.log(`\n  Pre-commit hook: ${installed ? 'installed' : 'not installed'}`);
      if (!installed) {
        console.log('  Install: npx secretless-ai hook install');
      }
      console.log();
      return 0;
    }

    default:
      console.error(`\n  Unknown hook command: ${subcommand === undefined ? '(none)' : escapeForDisplay(subcommand)}`);
      console.log('  Usage:');
      console.log('    secretless-ai hook install       Install pre-commit hook');
      console.log('    secretless-ai hook uninstall     Remove pre-commit hook');
      console.log('    secretless-ai hook status        Check hook status');
      console.log('    secretless-ai hook --check-only  Session gate for Claude Code hooks (silent, fast)\n');
      return EXIT_USAGE;
  }
}

export function runScanStaged(args: string[] = []): number {
  const noIgnore = args.includes('--no-ignore');
  const { findings, blockedFiles, notARepo, placeholdersSuppressed } = scanStagedFiles({ noIgnore });
  if (notARepo) {
    // Same message and exit code as `diff` in the same situation. Exiting 0
    // with no output made a pre-commit or CI step in the wrong directory look
    // installed and passing while it scanned nothing (#125).
    console.error('\n  Not a git repository (or any parent up to mount point).');
    console.error('  `scan-staged` scans the files staged for commit, so it runs inside a git repo.');
    console.error('  Run it inside a git repo, or scan a directory instead: npx secretless-ai scan .\n');
    return 2;
  }
  const total = findings.length + blockedFiles.length;

  // Same disclosure `scan` prints: a commit check that hid a value as a
  // placeholder says how many, and where to see them, so a real key that looked
  // like one is not passed in silence.
  const placeholderHint = () => {
    if (placeholdersSuppressed > 0) {
      const n = placeholdersSuppressed;
      console.error(`  ${n} value${n > 1 ? 's' : ''} looked like a placeholder and ${n > 1 ? 'were' : 'was'} hidden.`);
      console.error('  See them: npx secretless-ai scan --show-placeholders\n');
    }
  };

  if (total === 0) {
    // Clean — allow commit
    if (placeholdersSuppressed > 0) console.error();
    placeholderHint();
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

  placeholderHint();
  console.error('  Remove the secrets and try again.');
  console.error('  To bypass: git commit --no-verify\n');
  return 1;
}
