#!/usr/bin/env node

/**
 * Secretless CLI - Entry point and command dispatcher.
 * Command implementations live in src/commands/*.ts
 */

import * as path from 'path';
import type { TelemetryAction } from '@opena2a/cli-ui' with { 'resolution-mode': 'import' };
import { VERSION, CLI_BARE } from './commands/utils';
// @opena2a/telemetry and @opena2a/cli-ui are pure ESM; this CLI is CommonJS,
// so they're loaded via dynamic import() inside the async main().
import { runInit, runScan, runStatus, runVerify, runDoctor } from './commands/core';
import { runClean, runWatch, runScanHistory, runCleanHistory } from './commands/transcript';
import { runSecret } from './commands/secrets';
import { runRun, runEnv, runImport, runSetupCommand } from './commands/env-run';
import { runRules } from './commands/rules';
import { runHook, runScanStaged } from './commands/git';
import { runProtectMcp, runMcpStatus, runMcpUnprotect } from './commands/mcp';
import { runBackend, runMigrate, runCache } from './commands/backend';
import { runBroker } from './commands/broker';
import { runVault } from './commands/vault';
import { runScope } from './commands/scope';
import { runWarm, runInstall } from './commands/session';
import { runFeedback } from './commands/feedback';
import { runIgnore } from './commands/ignore';
import { runDiff } from './commands/diff';
import { printHelp } from './commands/help';

const TOOL = 'secretless-ai';
// Subcommands we don't track: pure-help / pure-config calls don't represent
// the user actually using the tool, and tracking 'telemetry' itself creates
// confusing self-referential events.
const NON_TRACKED = new Set<string>(['telemetry', '--version', '-v', '--help', '-h']);

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const command = args[0];

  // Tier-1 anonymous usage telemetry — default ON; opt-out via OPENA2A_TELEMETRY=off
  // or `secretless-ai telemetry off`. See README §Telemetry. Disclosure surfaces:
  // README, --version line, telemetry subcommand, opena2a.org/telemetry.
  const tele = await import('@opena2a/telemetry');
  const { versionLine, runTelemetryCommand } = await import('@opena2a/cli-ui');
  await tele.init({ tool: TOOL, version: VERSION });

  // Intercept `--help` / `-h` anywhere in the args BEFORE dispatching. Subcommand
  // runners do not parse per-subcommand help, so without this guard `scan --help`
  // would actually run the scanner, `init --help` would create a literal `--help/`
  // directory, and `broker start --help` would launch the daemon. Print top-level
  // help instead — a safe no-op. Regression: release-test 2026-04-14.
  if (command && (args.includes('--help') || args.includes('-h'))) {
    printHelp();
    return 0;
  }

  // --version: cli-ui versionLine helper appends the standard telemetry line.
  if (command === '--version' || command === '-v') {
    console.log(versionLine({ tool: TOOL, version: VERSION, telemetry: tele.status() }));
    return 0;
  }

  // telemetry subcommand
  if (command === 'telemetry') {
    console.log(runTelemetryCommand(args[1] as TelemetryAction, {
      tool: TOOL,
      getStatus: tele.status,
      setOptOut: tele.setOptOut,
    }));
    return 0;
  }

  const startedAt = Date.now();
  let exitCode = 0;
  try {
    exitCode = await dispatch(args, command);
  } catch (err) {
    exitCode = 1;
    if (command) tele.error(command, (err as { code?: string; name?: string })?.code || (err as { name?: string })?.name || 'UNKNOWN');
    throw err;
  } finally {
    if (command && !NON_TRACKED.has(command)) {
      // Exit 1 = scanner found credentials (the tool's job); >=2 = real error.
      // npm audit / eslint convention. Matches @opena2a/telemetry.successFromExitCode.
      await tele.track(command, { success: exitCode <= 1, durationMs: Date.now() - startedAt });
    }
    await tele.flush();
  }
  return exitCode;
}

/**
 * Reject unknown `--flag` / `-flag` args that would otherwise be silently
 * treated as a directory path by commands whose only positional is `[dir]`.
 * Pre-fix: `secretless-ai init --ci` created a literal `--ci/` directory and
 * scaffolded files into it (release-test 2026-05-12 P1).
 *
 * Returns `false` if the caller should bail with exit 2; `true` to proceed.
 */
function rejectUnknownFlagAsDirArg(command: string, dirArg: string | undefined): boolean {
  if (dirArg && dirArg.startsWith('-')) {
    console.error(`  Unknown option: ${dirArg}`);
    console.error(`  \`${command}\` takes an optional directory path, not flags.`);
    console.error(`  Run \`${CLI_BARE} ${command} --help\` for usage.`);
    return false;
  }
  return true;
}

async function dispatch(args: string[], command: string | undefined): Promise<number> {
  switch (command) {
    case 'init': {
      const dirArg = args[1];
      if (!rejectUnknownFlagAsDirArg('init', dirArg)) return 2;
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      return runInit(projectDir);
    }
    case 'scan': {
      if (args.includes('--history')) {
        return runScanHistory();
      }
      const includeTests = args.includes('--include-tests');
      const explain = args.includes('--explain');
      const noIgnore = args.includes('--no-ignore');
      const json = args.includes('--json');
      const showPlaceholders = args.includes('--show-placeholders');
      // --min-confidence <n>  (n in [0, 1]). Drops findings whose composite
      // confidence score is below the threshold. Useful on noisy repos to
      // surface only high-confidence credentials. Invalid values fall back to
      // 0 (no filtering) and the runner prints a warning.
      let minConfidence = 0;
      const mcIdx = args.indexOf('--min-confidence');
      if (mcIdx !== -1 && mcIdx + 1 < args.length) {
        const raw = args[mcIdx + 1];
        const parsed = Number.parseFloat(raw);
        if (Number.isFinite(parsed) && parsed >= 0 && parsed <= 1) {
          minConfidence = parsed;
        } else {
          console.error(`  Warning: ignoring invalid --min-confidence value "${raw}" (must be in [0, 1]).`);
        }
      }
      const flagFlag = new Set(['--include-tests', '--explain', '--no-ignore', '--json', '--show-placeholders', '--min-confidence']);
      const positionalArgs: string[] = [];
      const unknownFlags: string[] = [];
      for (let k = 1; k < args.length; k++) {
        const a = args[k];
        if (flagFlag.has(a)) {
          if (a === '--min-confidence') k++;
          continue;
        }
        // Warn (don't fail) on an unrecognized flag so a typo like `--show-placeholder`
        // for `--show-placeholders` doesn't silently no-op (#81). Matches the warn-not-
        // crash behavior already used for an invalid `--min-confidence` value.
        if (a.startsWith('--')) { unknownFlags.push(a); continue; }
        positionalArgs.push(a);
      }
      if (unknownFlags.length > 0) {
        console.error(`  Warning: ignoring unknown flag${unknownFlags.length > 1 ? 's' : ''} ${unknownFlags.join(', ')}.`);
        console.error(`  Run \`${CLI_BARE} scan\` for supported flags (--json, --show-placeholders, --min-confidence, --no-ignore, --include-tests, --explain).`);
      }
      const dirArg = positionalArgs[0];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      return runScan(projectDir, { includeTests, explain, noIgnore, minConfidence, json, showPlaceholders });
    }
    case 'status': {
      const json = args.includes('--json');
      const positional = args.slice(1).filter(a => a !== '--json');
      const dirArg = positional[0];
      if (!rejectUnknownFlagAsDirArg('status', dirArg)) return 2;
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      return runStatus(projectDir, { json });
    }
    case 'verify': {
      const showAll = args.includes('--all');
      const positional = args.slice(1).filter(a => a !== '--all');
      const dirArg = positional[0];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      return runVerify(projectDir, showAll);
    }
    case 'doctor':
      return runDoctor(args.includes('--fix'));
    case 'clean':
      return runClean(args.slice(1));
    case 'watch':
      return runWatch(args.slice(1));
    case 'rules':
      return runRules(args.slice(1));
    case 'protect-mcp':
      return runProtectMcp(args.slice(1));
    case 'mcp-status':
      return runMcpStatus();
    case 'mcp-unprotect':
      return runMcpUnprotect();
    case 'backend':
      return runBackend(args.slice(1));
    case 'migrate':
      return runMigrate(args.slice(1));
    case 'secret':
      return runSecret(args.slice(1));
    case 'run':
      return runRun(args.slice(1));
    case 'env':
      return runEnv(args.slice(1));
    case 'import':
      return runImport(args.slice(1));
    case 'setup':
      return runSetupCommand(args.slice(1));
    case 'hook':
      return runHook(args.slice(1));
    case 'scan-staged':
      return runScanStaged(args.slice(1));
    case 'cache':
      return runCache(args.slice(1));
    case 'broker':
      return runBroker(args.slice(1));
    case 'vault':
      return runVault(args.slice(1));
    case 'scope':
      return runScope(args.slice(1));
    case 'scan-history':
      return runScanHistory();
    case 'clean-history':
      return runCleanHistory(args.includes('--dry-run'));
    case 'warm':
      return runWarm(args.slice(1));
    case 'install':
      return runInstall(args.slice(1));
    case 'feedback':
      return runFeedback();
    case 'ignore':
      return runIgnore(args.slice(1));
    case 'diff':
      return runDiff(args.slice(1));
    case '--help':
    case '-h':
    case undefined:
      printHelp();
      return 0;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      return 1;
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err);
    process.exit(1);
  },
);
