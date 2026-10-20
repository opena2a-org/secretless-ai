#!/usr/bin/env node

/**
 * Secretless CLI - Entry point and command dispatcher.
 * Command implementations live in src/commands/*.ts
 */

import * as path from 'path';
import type { TelemetryAction } from '@opena2a/cli-ui' with { 'resolution-mode': 'import' };
import { VERSION, CLI_BARE, formatCommandError } from './commands/utils';
// @opena2a/telemetry and @opena2a/cli-ui are pure ESM; this CLI is CommonJS,
// so they're loaded via dynamic import() inside the async main().
import { runInit, runScan, runStatus, runVerify, runDoctor, parseFileSize, pathOperand, listedPath } from './commands/core';
import { escapeForDisplay, escapePathForDisplay } from './display-safe';
import { runClean, runWatch, runScanHistory, runCleanHistory, offerTranscriptWatcher } from './commands/transcript';
import { runSecret } from './commands/secrets';
import { runRun, runEnv, runImport, runSetupCommand } from './commands/env-run';
import { runExport } from './commands/bundle';
import { runRules } from './commands/rules';
import { runHook, runScanStaged } from './commands/git';
import { runPromptCheck, CHECK_PROMPT_FLAG } from './prompt-check';
import { runProtectMcp, runMcpStatus, runMcpUnprotect } from './commands/mcp';
import { runBackend, runMigrate, runCache } from './commands/backend';
import { runBroker } from './commands/broker';
import { runVault } from './commands/vault';
import { runScope } from './commands/scope';
import { runWarm, runInstall } from './commands/session';
import { runFeedback } from './commands/feedback';
import { runIgnore } from './commands/ignore';
import { runDiff } from './commands/diff';
import { runGitCredential } from './commands/git-credential';
import { GIT_PROTOCOL_ACTIONS } from './git-credential';
import { printHelp, OWN_HELP } from './commands/help';
import { printCommandHelp } from './command-help';
import { prepareArgv, supportedFlags, VERBS, EXIT_USAGE, type FormFlags, type PreparedArgv } from './argv';
import { nearestMatch } from './near-miss';
import {
  automatedRunVariable, optedOutByVariable, OPT_OUT_VARIABLE, telemetrySettingFile, readTelemetrySetting, storeTelemetrySetting,
  dropStoredInstallId,
} from './telemetry-gate';

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
 *
 * Each error is printed escaped: it quotes the token the user typed, and a
 * line feed in that token started a line of its own under this message.
 */
function formatArgvErrors(verb: string, errors: string[], supported?: string): string[] {
  const spec = VERBS[verb];
  const lines = errors.map((e) => `  ${escapeForDisplay(e)}`);
  lines.push(`  \`${verb}\` was not run. Nothing was changed.`);
  // `supported` stands in for the verb's list on a form of the verb that takes
  // fewer flags, so the line does not offer a flag the error above refused.
  if (supported !== undefined) {
    lines.push(`  ${supported}`);
  } else if (spec) {
    lines.push(`  Supported: ${supportedFlags(spec).join(', ')}`);
  }
  // CLI_BARE, not a literal: an embedding host sets SECRETLESS_CLI_PREFIX and
  // every citation we print has to rebrand with it (#191). A hardcoded name
  // here tells that host's users to run a command that does not exist.
  lines.push(`  Run \`${CLI_BARE} ${verb} --help\` for usage.`);
  return lines;
}

const TOOL = 'secretless-ai';
/**
 * Mirrors `TelemetryAction` in @opena2a/cli-ui, which is a type and therefore
 * erased at compile — so it cannot validate anything at runtime. A test pins
 * this list against the helper's own accepted set.
 */
const TELEMETRY_ACTIONS = ['on', 'off', 'status'];
/** The `install_id:` value `telemetry status` prints while telemetry is off and none is stored. */
const NO_INSTALL_ID = 'none (one is created on the first run with telemetry on)';
// Subcommands we don't track: pure-help / pure-config calls don't represent
// the user actually using the tool, and tracking 'telemetry' itself creates
// confusing self-referential events.
const NON_TRACKED = new Set<string>(['telemetry', '--version', '-v', '-V', '--help', '-h']);

/**
 * `git-credential get|store|erase` is run by git each time it authenticates,
 * not by the user, so it is not tracked: it would dominate the dataset and add
 * a network call to every authenticated git operation. `install` and
 * `uninstall` are tracked like any other command. The Claude Code hook checks
 * (`hook --check-only` on each tool call, `hook --check-prompt` on each prompt,
 * #237) are left out for the same reason: a usage event from the prompt check
 * would be a network call of its own on every prompt.
 */
function isUntrackedCall(command: string, prepared: PreparedArgv): boolean {
  return NON_TRACKED.has(command)
    || (command === 'git-credential' && GIT_PROTOCOL_ACTIONS.includes(prepared.positionals[0] ?? ''))
    || (command === 'hook' && (prepared.args.includes('--check-prompt') || prepared.args.includes('--check-only')));
}


async function main(): Promise<number> {
  const rawArgs = process.argv.slice(2);
  const command = rawArgs[0];

  // Normalise argv ONCE, here, before anything reads it. Every command below
  // still does its own `args.includes('--dry-run')` / `args.indexOf('--path')`
  // and none of them had to change, because by this point they are looking at
  // the split form: `--path=DIR` has already become `--path` `DIR`. See
  // src/argv.ts for why this is not an `=` branch inside each parser.
  // Under `scan --history` a did-you-mean is chosen from the flags it takes (#468).
  const prepared = prepareArgv(command, rawArgs, (normalised) => formFlagsFor(command, normalised));
  const args = prepared.args;

  // Tier-1 anonymous usage telemetry — default ON; opt-out via OPENA2A_TELEMETRY=off
  // or `secretless-ai telemetry off`. See README §Telemetry. Disclosure surfaces:
  // README, --version line, telemetry subcommand, opena2a.org/telemetry.
  const tele = await import('@opena2a/telemetry');
  const { versionLine, runTelemetryCommand } = await import('@opena2a/cli-ui');
  // Nothing is sent from CI or a test runner (#320): each starts in a fresh
  // home and was counted as a new user. The status says so, rather than
  // reporting `on` for a run that sends nothing. See src/telemetry-gate.ts.
  const automated = automatedRunVariable(process.env);
  const optedOut = optedOutByVariable(process.env);
  // No install id is derived or written while telemetry is off (#422): the
  // SDK's init, status and setOptOut write one whatever the opt-out says.
  // init is called only on a run that starts with telemetry on. status and
  // setOptOut are called on such a run, and on one more: `telemetry on` with a
  // stored `telemetry off` and none of OPENA2A_TELEMETRY=off, CI or a test
  // runner set, which turns telemetry on through setOptOut and so stores an
  // id (#428).
  const settingFile = telemetrySettingFile(process.env);
  const telemetryOn = () => !automated && !optedOut && (readTelemetrySetting(settingFile)?.enabled ?? true);
  const sending = telemetryOn();
  if (sending) {
    await tele.init({ tool: TOOL, version: VERSION });
  } else {
    // An install id an earlier run left in the file is deleted, keeping the
    // stored setting (#426). Best effort, as the SDK's own write is: a setting
    // file that cannot be written does not stop the run.
    try {
      dropStoredInstallId(settingFile);
    } catch {
      // The id stays; `telemetry status` reads the file and still prints it.
    }
  }
  const telemetryStatus = () => (telemetryOn() ? tele.status() : {
    enabled: false,
    configPath: settingFile,
    policyURL: tele.POLICY_URL,
    installId: readTelemetrySetting(settingFile)?.installId ?? NO_INSTALL_ID,
  });
  const setOptOut = (enabled: boolean) => (enabled && !automated && !optedOut
    ? tele.setOptOut(true)
    : storeTelemetrySetting(settingFile, enabled));

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
    // The verb's own flags (src/command-help.ts), or the global help for a
    // token that is not a registered verb. Still a no-op: no runner executes.
    printCommandHelp(command);
    return 0;
  }

  // --version: cli-ui versionLine helper appends the standard telemetry line.
  // `-V` too: it is the version flag in commander-based CLIs, and refusing it
  // as an unknown command while `-v` works was a surprise with no upside.
  if (command === '--version' || command === '-v' || command === '-V') {
    console.log(versionLine({ tool: TOOL, version: VERSION, telemetry: telemetryStatus() }));
    return 0;
  }

  // Refuse a command line we could not bind, BEFORE any side effect: before
  // telemetry is recorded, before dispatch, and so before the first byte is
  // written by a destructive verb. `clean --dryrun` reaching runClean at all is
  // the defect — by then the only signal is a missing "Mode: dry-run" line,
  // printed after the file has already been rewritten.
  if (prepared.errors.length > 0 && command) {
    for (const line of formatArgvErrors(command, prepared.errors, supportedFor(command, args))) console.error(line);
    return EXIT_USAGE;
  }
  // Escaped for the same reason as the errors above: a warning quotes the flag.
  for (const warning of prepared.warnings) console.error(`  ${escapeForDisplay(warning)}`);

  // telemetry subcommand
  if (command === 'telemetry') {
    // The action is validated HERE rather than left to the helper. Measured on
    // 0.22.1: `telemetry bogus` printed "Unknown action 'bogus'" to STDOUT and
    // returned 0, so a caller checking the exit code was told the opt-out had
    // been applied when nothing was called. Third instance of the same shape as
    // `cache` and `backend` — a token we do not recognise answered with
    // success — and the only one whose message came from a dependency, which
    // is why it is caught before the call rather than parsed out of the reply.
    const action = args[1];
    if (action !== undefined && !TELEMETRY_ACTIONS.includes(action)) {
      const near = nearestMatch(action, TELEMETRY_ACTIONS);
      console.error(`\n  Unknown telemetry action: ${escapeForDisplay(action)}${near ? ` (did you mean \`${near}\`?)` : ''}`);
      console.error('  Telemetry was NOT changed.');
      console.log(`  Usage: ${CLI_BARE} telemetry <${TELEMETRY_ACTIONS.join('|')}>`);
      console.log(`  Run \`${CLI_BARE} telemetry\` with no action to see the current setting.\n`);
      return EXIT_USAGE;
    }
    console.log(runTelemetryCommand(action as TelemetryAction, {
      tool: TOOL,
      getStatus: telemetryStatus,
      setOptOut,
    }));
    // `telemetry on` saves the setting and still prints `state: off` here, so
    // the line says why.
    if (automated) {
      console.log(`\n  Off for this run: ${automated} is set, and no usage event is sent from CI or a test runner.`);
    } else if (optedOut) {
      console.log(`\n  Off for this run: ${OPT_OUT_VARIABLE} is set to turn it off.`);
    }
    return 0;
  }

  const startedAt = Date.now();
  let exitCode = 0;
  // The event's `name` is a command name. A first argument that is not a
  // command (a path, a mistyped verb, a pasted value) was sent there as typed;
  // it is sent as `unknown`, and that run, which printed "Unknown command" and
  // did nothing, is not a success.
  const known = command !== undefined && Object.prototype.hasOwnProperty.call(VERBS, command);
  const eventName = known && command ? command : 'unknown';
  try {
    exitCode = await dispatch(args, command, prepared);
  } catch (err) {
    exitCode = 1;
    if (command && sending) tele.error(eventName, (err as { code?: string; name?: string })?.code || (err as { name?: string })?.name || 'UNKNOWN');
    throw err;
  } finally {
    if (command && sending && !isUntrackedCall(command, prepared)) {
      // Exit 1 = scanner found credentials (the tool's job); >=2 = real error.
      // npm audit / eslint convention. Matches @opena2a/telemetry.successFromExitCode.
      await tele.track(eventName, { success: known && exitCode <= 1, durationMs: Date.now() - startedAt });
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
 * The argument is printed escaped, as a path is: a line feed in it started a
 * line of its own under this message.
 *
 * Returns `false` if the caller should bail with exit 2; `true` to proceed.
 */
function rejectUnknownFlagAsDirArg(command: string, dirArg: string | undefined): boolean {
  if (dirArg && dirArg.startsWith('-')) {
    console.error(`  Unknown option: ${escapePathForDisplay(dirArg)}`);
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
function refuseFlagValue(verb: string, flag: string, raw: string, expected: string, supported?: string): number {
  const detail = `${flag} needs ${expected}, but was given "${raw}".`;
  for (const line of formatArgvErrors(verb, [detail], supported)) console.error(line);
  return EXIT_USAGE;
}

/**
 * The `scan` flags the history scan reads. `--format` is here for `json`:
 * `--format sarif` is refused under `--history` on a line of its own.
 */
const HISTORY_SCAN_FLAGS: ReadonlySet<string> = new Set(['--history', '--json', '--format']);
/**
 * The flags `scan --history` takes, each as a refusal under `--history` names
 * it: HISTORY_SCAN_FLAGS but `--history` itself, and `--help`. `--format` is
 * named with json, the one value it takes there.
 */
const HISTORY_TAKES: FormFlags = { '--format': '--format json', '--help': '--help', '--json': '--json' };
/** The supported line of a refusal under `--history`, naming HISTORY_TAKES. */
const HISTORY_SUPPORTED = `Supported with --history: ${Object.values(HISTORY_TAKES).join(', ')}`;

/**
 * Whether `command` as typed is `scan --history`. `--history` is looked for
 * as the `scan` branch looks for it.
 */
function isHistoryScan(command: string | undefined, args: readonly string[]): boolean {
  return command === 'scan' && args.includes('--history');
}

/**
 * The supported line of a refusal of `command` as typed: HISTORY_SUPPORTED
 * when it is `scan --history`, and undefined, for the verb's own list,
 * otherwise.
 *
 * The refusals made before that branch is reached (those of the argv layer,
 * such as an unknown flag or a flag given no value, a `--format` value other
 * than json or sarif, and `--json` with `--format sarif`) printed every `scan`
 * flag under `--history` as well, so they offered the directory-scan flags it
 * refuses (#466).
 */
function supportedFor(command: string, args: string[]): string | undefined {
  return isHistoryScan(command, args) ? HISTORY_SUPPORTED : undefined;
}

/**
 * The flags the did-you-mean for an unknown flag of `command` as typed is
 * chosen from: HISTORY_TAKES when it is `scan --history`, the flags the
 * supported line of the same refusal names, and undefined, for the verb's own
 * flags, otherwise. Chosen from every `scan` flag, it could name a flag
 * `--history` refuses: `scan --history --explian` was answered with
 * `did you mean --explain?` (#468).
 */
function formFlagsFor(command: string | undefined, args: readonly string[]): FormFlags | undefined {
  return isHistoryScan(command, args) ? HISTORY_TAKES : undefined;
}

/**
 * Why `scan --history` cannot run as given, one line for each reason, or none
 * when it can.
 *
 * The history scan reads the shell history files in the home directory, so it
 * takes no path, and of `scan`'s flags it reads only HISTORY_SCAN_FLAGS. The
 * others were accepted and had no effect, their values unchecked (#463):
 * `scan --history --min-confidence 7` printed the full report at exit 1,
 * where `scan . --min-confidence 7` is refused, and
 * `scan --history ./some-dir` printed the report without naming ./some-dir.
 * They are refused as `--format sarif` is. The flags are read from the
 * registry, so a flag `scan` gains later is refused here until the history
 * scan reads it and it is added above.
 */
function historyScanRefusals(args: string[], positionals: string[], format: string | undefined): string[] {
  const refusals: string[] = [];
  if (format === 'sarif') {
    refusals.push('--history has no SARIF output; give --json or --format json for JSON, or neither for text.');
  }
  // In the order typed, each named once.
  const unused = [...new Set(args.slice(1).filter((a) => (
    Object.prototype.hasOwnProperty.call(VERBS.scan.flags, a) && !HISTORY_SCAN_FLAGS.has(a)
  )))];
  if (unused.length > 1) {
    const named = `${unused.slice(0, -1).join(', ')} or ${unused[unused.length - 1]}`;
    refusals.push(`--history does not use ${named}, which apply to a directory scan; give them without --history, or leave them out.`);
  } else if (unused.length === 1) {
    refusals.push(`--history does not use ${unused[0]}, which applies to a directory scan; give it without --history, or leave it out.`);
  }
  // Named as `scan` names a path it did not read: quoted where the shell needs
  // it, and escaped where it holds a character that would reach the terminal
  // as a control, so a line feed in it cannot start a line of its own.
  const paths = positionals.map((p) => listedPath(p)).join(', ');
  if (positionals.length > 1) {
    refusals.push(`--history scans shell history and takes no path; scan each path on its own, without --history: ${paths}`);
  } else if (positionals.length === 1) {
    refusals.push(`--history scans shell history and takes no path; give the path without --history to scan it: ${paths}`);
  }
  return refusals;
}

/**
 * Why `scan-history` or `clean-history` cannot run with these positionals, or
 * null when none was given.
 *
 * Both read the shell history files in the home directory and take no path.
 * Neither read its positionals, so a path given to either was accepted and
 * not used (#466): `scan-history ./some-dir` printed the shell history report
 * and `clean-history ./some-dir` redacted the shell history files, neither
 * naming ./some-dir. Each is refused before anything runs, as
 * `scan --history ./some-dir` is, and the paths are named as that refusal
 * names them.
 */
function historyVerbPathRefusal(verb: 'scan-history' | 'clean-history', positionals: string[]): string | null {
  if (positionals.length === 0) return null;
  const paths = positionals.map((p) => listedPath(p)).join(', ');
  const many = positionals.length > 1;
  if (verb === 'scan-history') {
    return many
      ? `\`scan-history\` scans shell history and takes no path; to scan the paths, give each to \`scan\` on its own: ${paths}`
      : `\`scan-history\` scans shell history and takes no path; to scan the path, give it to \`scan\`: ${paths}`;
  }
  return many
    ? `\`clean-history\` redacts credentials in shell history and takes no path; leave the paths out: ${paths}`
    : `\`clean-history\` redacts credentials in shell history and takes no path; leave the path out: ${paths}`;
}

async function dispatch(args: string[], command: string | undefined, prepared: PreparedArgv): Promise<number> {
  switch (command) {
    case 'init': {
      // The first positional: `--no-watch` is a flag, not the directory.
      const dirArg = prepared.positionals[0];
      if (!rejectUnknownFlagAsDirArg('init', dirArg)) return 2;
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      const code = runInit(projectDir);
      // The watcher offer (#237) follows a set-up that succeeded. A run that
      // exits 1 ends on the problem and its fix, as before.
      if (code === 0) await offerTranscriptWatcher({ noWatch: args.includes('--no-watch') });
      return code;
    }
    case 'scan': {
      const jsonFlag = args.includes('--json');
      // --format <json|sarif>  One machine-readable document on stdout. `json`
      // is `--json`; `sarif` is SARIF 2.1.0 for GitHub code scanning and the
      // editors that read it. Any other value is refused: a format the tool
      // does not write would otherwise fall through to the human report and
      // exit as though it had answered.
      //
      // This flag and the value flags below are read from the values the argv
      // layer bound, not as the token after the flag's spelling in `args`. In
      // `scan --min-confidence --format`, `--format` is the value of
      // `--min-confidence`. Looked up by spelling, `--format` was found and the
      // token after it, which does not exist, was read as its value, so the
      // refusal said `--format` was given "undefined" (#469).
      let format: 'json' | 'sarif' | undefined;
      const history = args.includes('--history');
      const rawFormat = prepared.values.get('--format');
      if (rawFormat !== undefined) {
        if (rawFormat === 'json' || rawFormat === 'sarif') {
          format = rawFormat;
        } else if (history) {
          // `--history` refuses `--format sarif`, so the value it takes is json.
          return refuseFlagValue('scan', '--format', rawFormat, 'json with --history, e.g. --format json', HISTORY_SUPPORTED);
        } else {
          return refuseFlagValue('scan', '--format', rawFormat, 'json or sarif, e.g. --format sarif');
        }
      }
      // Two formats cannot share one stdout: a reader expecting one document
      // would get the other. Refused before anything runs, like any other
      // command line the tool cannot bind.
      if (jsonFlag && format === 'sarif') {
        const detail = '--json and --format sarif ask for two formats on one output; give one of them.';
        for (const line of formatArgvErrors('scan', [detail], supportedFor('scan', args))) console.error(line);
        return EXIT_USAGE;
      }
      const json = jsonFlag || format === 'json';
      // --history  Shell history in place of a directory. The output flags are
      // read above it so that it honors them as well: it returned before they
      // were read, and `scan --history --json` printed the text report (#458).
      // It writes text or JSON. It has no SARIF form, so `--format sarif` is
      // refused rather than answered with text. It takes no path and none of
      // the directory-scan flags read below, so each of those is refused too,
      // rather than accepted and ignored (#463).
      if (history) {
        const refusals = historyScanRefusals(args, prepared.positionals, format);
        if (refusals.length > 0) {
          for (const line of formatArgvErrors('scan', refusals, HISTORY_SUPPORTED)) console.error(line);
          return EXIT_USAGE;
        }
        return runScanHistory({ json });
      }
      const includeTests = args.includes('--include-tests');
      const includeConfig = args.includes('--include-config');
      const explain = args.includes('--explain');
      const noIgnore = args.includes('--no-ignore');
      const showPlaceholders = args.includes('--show-placeholders');
      // --check-validity  Ask the provider that issued each found credential
      // whether it still accepts it. Opt-in: without it no credential is sent
      // anywhere. `scan --help` lists the host contacted per credential type.
      const checkValidity = args.includes('--check-validity');
      // --min-confidence <n>  (n in [0, 1]). Drops findings whose composite
      // confidence score is below the threshold. Useful on noisy repos to
      // surface only high-confidence credentials.
      let minConfidence = 0;
      const rawMinConfidence = prepared.values.get('--min-confidence');
      if (rawMinConfidence !== undefined) {
        const parsed = Number.parseFloat(rawMinConfidence);
        if (Number.isFinite(parsed) && parsed >= 0 && parsed <= 1) {
          minConfidence = parsed;
        } else {
          return refuseFlagValue('scan', '--min-confidence', rawMinConfidence, 'a number in [0, 1], e.g. --min-confidence 0.8');
        }
      }
      // --max-files <n>  Raise the per-walk file cap (default 5000). Without
      // this, hitting the cap is a dead end: the scan reports it stopped early
      // but the user has no way to finish it short of scanning subtrees by hand.
      let maxFiles: number | undefined;
      const rawMaxFiles = prepared.values.get('--max-files');
      if (rawMaxFiles !== undefined) {
        // Must be ALL digits. `parseInt` stops at the first non-digit and
        // returns what it got, so `--max-files 20abc` silently became a cap of
        // 20 and `--max-files 1e6` a cap of 1 — the user believes the cap was
        // raised while the scan quietly covers a fraction of the tree.
        const parsed = /^\d+$/.test(rawMaxFiles) ? Number.parseInt(rawMaxFiles, 10) : NaN;
        if (Number.isSafeInteger(parsed) && parsed > 0) {
          maxFiles = parsed;
        } else {
          return refuseFlagValue('scan', '--max-files', rawMaxFiles,'a positive whole number, e.g. --max-files 20000');
        }
      }
      // --max-file-size <size>  Raise the per-file size cap (10MB config, 1MB
      // source). Without it, "skipped for size" is a dead end in exactly the
      // way hitting the file cap was before --max-files existed.
      let maxFileSizeBytes: number | undefined;
      const rawMaxFileSize = prepared.values.get('--max-file-size');
      if (rawMaxFileSize !== undefined) {
        const parsed = parseFileSize(rawMaxFileSize);
        if (parsed !== null) {
          maxFileSizeBytes = parsed;
        } else {
          return refuseFlagValue('scan', '--max-file-size', rawMaxFileSize,'a size, e.g. --max-file-size 20mb, 500kb, or a byte count');
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
        // The paths are printed escaped, and the command names the first only
        // when it prints as itself: a line feed in one started a line of its
        // own in both places.
        const given = positionalArgs.map((p) => escapePathForDisplay(p)).join(', ');
        console.error(`  scan takes one path, but ${positionalArgs.length} were given: ${given}`);
        console.error('  Scan them one at a time, or pass the directory that contains them:');
        console.error(`    ${CLI_BARE} scan ${pathOperand(positionalArgs[0])}`);
        console.error(`    ${CLI_BARE} scan .`);
        return 2;
      }
      const dirArg = positionalArgs[0];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      return runScan(projectDir, { includeTests, includeConfig, explain, noIgnore, minConfidence, json, format, showPlaceholders, maxFiles, maxFileSizeBytes, checkValidity });
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
    case 'secret': {
      // `secret list` and `secret show` produce JSON; `set`, `get` and `rm`
      // refuse the flag rather than ignore it (commands/secrets.ts).
      const json = args.includes('--json');
      return runSecret(args.slice(1), { json });
    }
    case 'run':
      return runRun(args.slice(1));
    case 'env':
      return runEnv(args.slice(1));
    case 'import':
      return runImport(args.slice(1));
    case 'export':
      return runExport(args.slice(1));
    case 'setup':
      return runSetupCommand(args.slice(1));
    case 'hook':
      // The prompt check for the Claude Code UserPromptSubmit hook (#237):
      // the prompt on stdin, exit 2 with the reason when it holds a
      // credential. It reads stdin and the secret store, so it answers
      // through a promise; runHook answers its subcommands at once.
      if (args[1] === CHECK_PROMPT_FLAG) return runPromptCheck();
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
    case 'scan-history': {
      const refusal = historyVerbPathRefusal('scan-history', prepared.positionals);
      if (refusal) {
        for (const line of formatArgvErrors('scan-history', [refusal])) console.error(line);
        return EXIT_USAGE;
      }
      return runScanHistory();
    }
    case 'clean-history': {
      const refusal = historyVerbPathRefusal('clean-history', prepared.positionals);
      if (refusal) {
        for (const line of formatArgvErrors('clean-history', [refusal])) console.error(line);
        return EXIT_USAGE;
      }
      return runCleanHistory(args.includes('--dry-run'));
    }
    case 'warm':
      return runWarm(args.slice(1));
    case 'install':
      return runInstall(args.slice(1));
    case 'feedback':
      return runFeedback();
    case 'ignore':
      return runIgnore(args.slice(1));
    case 'diff':
      // Positionals, not `args.slice(1)`: an unknown flag is warned about as
      // ignored, and it is still in `args`, where `diff` read it as the ref.
      return runDiff(prepared.positionals);
    case 'git-credential':
      return runGitCredential(args.slice(1));
    case '--help':
    case '-h':
    case undefined:
      printHelp();
      return 0;
    default: {
      // A command we do not know is a refused command line, not a finding:
      // exit 1 would read as "credentials found" to a CI gate.
      // The nearest command, when one is close, and a pointer to the help
      // rather than the help itself (#410): the whole help followed this line
      // and named no command to run instead of the one mistyped.
      const near = nearestMatch(command, [...Object.keys(VERBS), '--help', '--version']);
      console.error(`Unknown command: ${escapeForDisplay(command)}${near ? ` (did you mean \`${near}\`?)` : ''}`);
      console.error(`Run \`${CLI_BARE} --help\` for the list of commands.`);
      return EXIT_USAGE;
    }
  }
}

/**
 * End the process with `code` once stdout and stderr have written everything
 * queued on them.
 *
 * `process.exit()` does not wait for a write that is still in progress. On
 * macOS a Node 20 parent gives this process a stdout that takes 8192 bytes at
 * once, so a longer output, `--help` among them, reached a caller reading it
 * through `child_process` cut off mid-line. When nothing is queued this exits
 * at once, as before. An empty write's callback runs after every write queued
 * before it.
 */
function exitWhenWritten(code: number): void {
  const queued = [process.stdout, process.stderr].filter((stream) => stream.writableLength > 0);
  let left = queued.length;
  if (left === 0) process.exit(code);
  for (const stream of queued) {
    // A reader that has gone away fails the queued write. Exit with `code`
    // anyway, as before, rather than turn that into an uncaught error.
    stream.once('error', () => {});
    stream.write('', () => {
      left -= 1;
      if (left === 0) process.exit(code);
    });
  }
}

main().then(
  (code) => exitWhenWritten(code),
  (err) => {
    // Print what the user can act on, not the call stack. These messages
    // already carry Verify/Fix lines; a stack trace on top of them reads as a
    // crash and buries the instructions under our own file paths.
    // Set SECRETLESS_DEBUG=1 when the stack is what you actually need.
    if (process.env.SECRETLESS_DEBUG) {
      console.error(err);
    } else {
      console.error(formatCommandError(err));
    }
    exitWhenWritten(1);
  },
);
