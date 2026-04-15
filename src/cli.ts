#!/usr/bin/env node

/**
 * Secretless CLI - Entry point and command dispatcher.
 * Command implementations live in src/commands/*.ts
 */

import * as path from 'path';
import { VERSION } from './commands/utils';
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

function main(): void {
  const args = process.argv.slice(2);
  const command = args[0];

  // Intercept `--help` / `-h` anywhere in the args BEFORE dispatching. Subcommand
  // runners do not parse per-subcommand help, so without this guard `scan --help`
  // would actually run the scanner, `init --help` would create a literal `--help/`
  // directory, and `broker start --help` would launch the daemon. Print top-level
  // help instead — a safe no-op. Regression: release-test 2026-04-14.
  if (command && (args.includes('--help') || args.includes('-h'))) {
    printHelp();
    return;
  }

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
    case '--version':
    case '-v':
      console.log(`secretless-ai ${VERSION} \u2014 credential protection for AI coding tools`);
      break;
    case '--help':
    case '-h':
    case undefined:
      printHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

main();
