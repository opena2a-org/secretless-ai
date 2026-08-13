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
import { runInit, runScan, runStatus, runVerify, runDoctor, parseFileSize } from './commands/core';
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
import { printHelp, OWN_HELP } from './commands/help';
import { prepareArgv, supportedFlags, VERBS, EXIT_USAGE, type PreparedArgv } from './argv';

/**
 * The stderr block for a refused command.
 *
 * States that nothing ran, because the failure mode being closed here is a
 * command that did something OTHER than what was asked: after a refusal the
 * user has to know the difference between "not run" and "run wrongly".
 *
 * Lives here rather than in `argv.ts` because it needs `CLI_BARE`, and
 * `argv.ts` is in the `mcp-wrapper` require graph, which is copied to a
 * standalone directory where `commands/utils`' `require('../../package.json')`
 * does not resolve. See the import note at the top of `argv.ts`.
 */
function formatArgvErrors(verb: string, errors: string[]): string[] {
  const spec = VERBS[verb];
  const lines = errors.map((e) => `  ${e}`);
  lines.push(`  \`${verb}\` was not run. Nothing was changed.`);
  if (spec) {
    lines.push(`  Supported: ${supportedFlags(spec).join(', ')}`);
  }
  // CLI_BARE, not a literal: an embedding host sets SECRETLESS_CLI_PREFIX and
  // every citation we print has to rebrand with it (#191). A hardcoded name
  // here tells that host's users to run a command that does not exist.
  lines.push(`  Run \`${CLI_BARE} ${verb} --help\` for usage.`);
  return lines;
}

const TOOL = 'secretless-ai';
// Subcommands we don't track: pure-help / pure-config calls don't represent
// the user actually using the tool, and tracking 'telemetry' itself creates
// confusing self-referential events.
const NON_TRACKED = new Set<string>(['telemetry', '--version', '-v', '--help', '-h']);


async function main(): Promise<number> {
  const rawArgs = process.argv.slice(2);
  const command = rawArgs[0];

  // Normalise argv ONCE, here, before anything reads it. Every command below
  // still does its own `args.includes('--dry-run')` / `args.indexOf('--path')`
  // and none of them had to change, because by this point they are looking at
  // the split form: `--path=DIR` has already become `--path` `DIR`. See
  // src/argv.ts for why this is not an `=` branch inside each parser.
  const prepared = prepareArgv(command, rawArgs);
  const args = prepared.args;

  // Tier-1 anonymous usage telemetry — default ON; opt-out via OPENA2A_TELEMETRY=off
  // or `secretless-ai telemetry off`. See README §Telemetry. Disclosure surfaces:
  // README, --version line, telemetry subcommand, opena2a.org/telemetry.
  const tele = await import('@opena2a/telemetry');
  const { versionLine, runTelemetryCommand } = await import('@opena2a/cli-ui');
  await tele.init({ tool: TOOL, version: VERSION });

  // Intercept `--help` / `-h` anywhere in the args BEFORE dispatching. Most
  // subcommand runners do not parse per-subcommand help, so without this guard
  // `scan --help` would actually run the scanner, `init --help` would create a
  // literal `--help/` directory, and `broker start --help` would launch the
  // daemon. Print top-level help instead — a safe no-op. Regression:
  // release-test 2026-04-14.
  //
  // OWN_HELP lists the runners that DO handle it, as their first statement and
  // before any side effect. Their help blocks were unreachable until now, which
  // matters for `setup`: the manifest format is documented nowhere else, and
  // guessing it wrong is the reported first experience (#112).
  if (command && (args.includes('--help') || args.includes('-h')) && !OWN_HELP.has(command)) {
    printHelp();
    return 0;
  }

  // --version: cli-ui versionLine helper appends the standard telemetry line.
  if (command === '--version' || command === '-v') {
    console.log(versionLine({ tool: TOOL, version: VERSION, telemetry: tele.status() }));
    return 0;
  }

  // Refuse a command line we could not bind, BEFORE any side effect: before
  // telemetry is recorded, before dispatch, and so before the first byte is
  // written by a destructive verb. `clean --dryrun` reaching runClean at all is
  // the defect — by then the only signal is a missing "Mode: dry-run" line,
  // printed after the file has already been rewritten.
  if (prepared.errors.length > 0 && command) {
    for (const line of formatArgvErrors(command, prepared.errors)) console.error(line);
    return EXIT_USAGE;
  }
  for (const warning of prepared.warnings) console.error(`  ${warning}`);

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
    exitCode = await dispatch(args, command, prepared);
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

/**
 * Refuse a flag whose VALUE we could not use, instead of falling back to the
 * default and answering a different question than the one asked.
 *
 * The fallback was a silent scope change, not merely a wasted flag: `scan
 * --max-files ./src` consumes `./src` as the cap's value, so no positional
 * remains, so the scan retargets to the current directory and prints "No
 * hardcoded credentials found." over a tree it never opened. Measured on
 * 0.22.0: exit 0, one warning naming the VALUE, and nothing anywhere saying a
 * different directory was scanned.
 */
function refuseFlagValue(verb: string, flag: string, raw: string, expected: string): number {
  const detail = `${flag} needs ${expected}, but was given "${raw}".`;
  for (const line of formatArgvErrors(verb, [detail])) console.error(line);
  return EXIT_USAGE;
}

async function dispatch(args: string[], command: string | undefined, prepared: PreparedArgv): Promise<number> {
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
      // surface only high-confidence credentials.
      let minConfidence = 0;
      const mcIdx = args.indexOf('--min-confidence');
      if (mcIdx !== -1) {
        const raw = args[mcIdx + 1];
        const parsed = Number.parseFloat(raw);
        if (Number.isFinite(parsed) && parsed >= 0 && parsed <= 1) {
          minConfidence = parsed;
        } else {
          return refuseFlagValue('scan', '--min-confidence', raw, 'a number in [0, 1], e.g. --min-confidence 0.8');
        }
      }
      // --max-files <n>  Raise the per-walk file cap (default 5000). Without
      // this, hitting the cap is a dead end: the scan reports it stopped early
      // but the user has no way to finish it short of scanning subtrees by hand.
      let maxFiles: number | undefined;
      const mfIdx = args.indexOf('--max-files');
      if (mfIdx !== -1) {
        const raw = args[mfIdx + 1];
        // Must be ALL digits. `parseInt` stops at the first non-digit and
        // returns what it got, so `--max-files 20abc` silently became a cap of
        // 20 and `--max-files 1e6` a cap of 1 — the user believes the cap was
        // raised while the scan quietly covers a fraction of the tree.
        const parsed = /^\d+$/.test(raw) ? Number.parseInt(raw, 10) : NaN;
        if (Number.isSafeInteger(parsed) && parsed > 0) {
          maxFiles = parsed;
        } else {
          return refuseFlagValue('scan', '--max-files', raw, 'a positive whole number, e.g. --max-files 20000');
        }
      }
      // --max-file-size <size>  Raise the per-file size cap (10MB config, 1MB
      // source). Without it, "skipped for size" is a dead end in exactly the
      // way hitting the file cap was before --max-files existed.
      let maxFileSizeBytes: number | undefined;
      const fsIdx = args.indexOf('--max-file-size');
      if (fsIdx !== -1) {
        const raw = args[fsIdx + 1];
        const parsed = parseFileSize(raw);
        if (parsed !== null) {
          maxFileSizeBytes = parsed;
        } else {
          return refuseFlagValue('scan', '--max-file-size', raw, 'a size, e.g. --max-file-size 20mb, 500kb, or a byte count');
        }
      }
      // Positionals come from the shared argv layer, which knows which tokens
      // were consumed as flag values. The local loop this replaces had its own
      // copy of the flag list, and a flag missing from that copy became a
      // positional — a second place for the two to disagree about what the user
      // typed. The unknown-flag warning #81 added moved there with it.
      const positionalArgs = prepared.positionals;
      // Refuse extra paths rather than silently scanning only the first. A
      // second path used to be dropped with no warning, and since the first
      // path's findings still set exit 1, the run LOOKED complete while a whole
      // file went unscanned — the same silent-shortfall class this release is
      // about. Failing loudly is better than answering for input we ignored.
      if (positionalArgs.length > 1) {
        console.error(`  scan takes one path, but ${positionalArgs.length} were given: ${positionalArgs.join(', ')}`);
        console.error('  Scan them one at a time, or pass the directory that contains them:');
        console.error(`    ${CLI_BARE} scan ${positionalArgs[0]}`);
        console.error(`    ${CLI_BARE} scan .`);
        return 2;
      }
      const dirArg = positionalArgs[0];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      return runScan(projectDir, { includeTests, explain, noIgnore, minConfidence, json, showPlaceholders, maxFiles, maxFileSizeBytes });
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
    // Print what the user can act on, not the call stack. These messages
    // already carry Verify/Fix lines; a stack trace on top of them reads as a
    // crash and buries the instructions under our own file paths.
    // Set SECRETLESS_DEBUG=1 when the stack is what you actually need.
    if (process.env.SECRETLESS_DEBUG) {
      console.error(err);
    } else if (err instanceof Error) {
      console.error(`\n  ${err.message.split('\n').join('\n  ')}\n`);
    } else {
      console.error(`\n  ${String(err)}\n`);
    }
    process.exit(1);
  },
);
