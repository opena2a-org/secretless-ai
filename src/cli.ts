#!/usr/bin/env node

/**
 * Secretless CLI - Entry point and command dispatcher.
 * Command implementations live in src/commands/*.ts
 */

import * as path from 'path';
import type { TelemetryAction } from '@opena2a/cli-ui' with { 'resolution-mode': 'import' };
import { VERSION } from './commands/utils';
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
    exitCode = dispatch(args, command);
  } catch (err) {
    exitCode = 1;
    if (command) tele.error(command, (err as { code?: string; name?: string })?.code || (err as { name?: string })?.name || 'UNKNOWN');
    throw err;
  } finally {
    if (command && !NON_TRACKED.has(command)) {
      await tele.track(command, { success: exitCode === 0, durationMs: Date.now() - startedAt });
    }
    await tele.flush();
  }
  return exitCode;
}

function dispatch(args: string[], command: string | undefined): number {
  switch (command) {
    case 'init': {
      const dirArg = args[1];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      runInit(projectDir);
      break;
    }
    case 'scan': {
      if (args.includes('--history')) {
        runScanHistory();
        break;
      }
      const includeTests = args.includes('--include-tests');
      const explain = args.includes('--explain');
      const positionalArgs = args.slice(1).filter(a => !a.startsWith('--'));
      const dirArg = positionalArgs[0];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      runScan(projectDir, { includeTests, explain });
      break;
    }
    case 'status': {
      const dirArg = args[1];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      runStatus(projectDir);
      break;
    }
    case 'verify': {
      const showAll = args.includes('--all');
      const positional = args.slice(1).filter(a => a !== '--all');
      const dirArg = positional[0];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      runVerify(projectDir, showAll);
      break;
    }
    case 'doctor':
      runDoctor(args.includes('--fix'));
      break;
    case 'clean':
      runClean(args.slice(1));
      break;
    case 'watch':
      runWatch(args.slice(1));
      break;
    case 'rules':
      runRules(args.slice(1));
      break;
    case 'protect-mcp':
      runProtectMcp(args.slice(1));
      break;
    case 'mcp-status':
      runMcpStatus();
      break;
    case 'mcp-unprotect':
      runMcpUnprotect();
      break;
    case 'backend':
      runBackend(args.slice(1));
      break;
    case 'migrate':
      runMigrate(args.slice(1));
      break;
    case 'secret':
      runSecret(args.slice(1));
      break;
    case 'run':
      runRun(args.slice(1));
      break;
    case 'env':
      runEnv(args.slice(1));
      break;
    case 'import':
      runImport(args.slice(1));
      break;
    case 'setup':
      runSetupCommand(args.slice(1));
      break;
    case 'hook':
      runHook(args.slice(1));
      break;
    case 'scan-staged':
      runScanStaged();
      break;
    case 'cache':
      runCache(args.slice(1));
      break;
    case 'broker':
      runBroker(args.slice(1));
      break;
    case 'vault':
      runVault(args.slice(1));
      break;
    case 'scope':
      runScope(args.slice(1));
      break;
    case 'scan-history':
      runScanHistory();
      break;
    case 'clean-history':
      runCleanHistory(args.includes('--dry-run'));
      break;
    case 'warm':
      runWarm(args.slice(1));
      break;
    case 'install':
      runInstall(args.slice(1));
      break;
    case '--help':
    case '-h':
    case undefined:
      printHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      return 1;
  }
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err);
    process.exit(1);
  },
);
