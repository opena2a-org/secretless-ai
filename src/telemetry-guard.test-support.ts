/**
 * A test that starts the CLI with telemetry on fails (#320).
 *
 * Loaded in every test worker by vitest.config.ts (`setupFiles`). Every way a
 * test starts a child process is wrapped: when the child is this CLI and the
 * environment it is given would send a usage event, the call throws before
 * the child starts. Each such child sent an event under a fresh install id,
 * and the tool's usage figures were mostly test runs.
 *
 * A child given `process.env` carries `OPENA2A_TELEMETRY=off` from the config
 * and passes. One given an environment built from scratch has to set it. A
 * test that needs the event itself points `OPENA2A_TELEMETRY_URL` at this
 * machine, which is allowed: nothing it sends leaves it.
 */
import { createRequire, syncBuiltinESMExports } from 'module';
import * as path from 'path';
import { promisify } from 'util';

/** The values the telemetry SDK reads as an opt-out. */
const OPT_OUT_VALUES = new Set(['off', '0', 'false', 'no']);
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

const CLI_ENTRY = /(^|[\\/])dist[\\/]cli\.js$/;
const BIN_NAME = 'secretless-ai';
const LAUNCHERS = new Set(['node', 'npx']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash']);
const IN_COMMAND_LINE = /(^|[\s'"\\/])(dist[\\/]cli\.js|secretless-ai)(?=$|[\s'"])/;

const GUARDED = Symbol.for('secretless.telemetryGuard');

type Options = { env?: NodeJS.ProcessEnv } | undefined;
type Launch = ((...args: unknown[]) => unknown) & { [GUARDED]?: true; [promisify.custom]?: (...args: unknown[]) => unknown };

/** True when a child started with `env` would send a usage event. */
export function wouldSendTelemetry(env: NodeJS.ProcessEnv): boolean {
  const optOut = env.OPENA2A_TELEMETRY;
  if (optOut !== undefined && OPT_OUT_VALUES.has(optOut.toLowerCase())) return false;
  const url = env.OPENA2A_TELEMETRY_URL;
  if (url !== undefined) {
    try {
      if (LOOPBACK_HOSTS.has(new URL(url).hostname)) return false;
    } catch {
      // Not a URL: the SDK's request fails, but the test still meant to send.
    }
  }
  return true;
}

/** True when `file` with `args` starts this CLI, directly or through a shell. */
export function startsCli(file: string, args: readonly string[]): boolean {
  const base = path.basename(file);
  if (CLI_ENTRY.test(file) || base === BIN_NAME) return true;
  if (file === process.execPath || LAUNCHERS.has(base)) {
    const script = args.find((a) => !a.startsWith('-'));
    return script !== undefined && (CLI_ENTRY.test(script) || script === BIN_NAME);
  }
  if (SHELLS.has(base)) {
    const c = args.indexOf('-c');
    if (c === -1) return false;
    // `sh -c '"$0" "$1" scan' node dist/cli.js` names the CLI after the script.
    return IN_COMMAND_LINE.test(args[c + 1] ?? '') || args.slice(c + 2).some((a) => CLI_ENTRY.test(a));
  }
  return false;
}

function refuse(described: string, options: Options): void {
  if (!wouldSendTelemetry(options?.env ?? process.env)) return;
  throw new Error(
    `This test starts the CLI with telemetry on: ${described}\n`
    + 'It would send a usage event under a fresh install id. Give the child OPENA2A_TELEMETRY: \'off\''
    + ' (process.env carries it from vitest.config.ts), or point OPENA2A_TELEMETRY_URL at 127.0.0.1'
    + ' when the test reads the event.',
  );
}

function asOptions(value: unknown): Options {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Options) : undefined;
}

/** `spawn`, `spawnSync`, `execFile`, `execFileSync`: (file, [args], [options], ...). */
function checkFile(name: string, callArgs: unknown[]): void {
  const file = String(callArgs[0]);
  const hasArgs = Array.isArray(callArgs[1]);
  const args = hasArgs ? (callArgs[1] as unknown[]).map(String) : [];
  const options = asOptions(hasArgs ? callArgs[2] : callArgs[1]);
  // `fork` starts its module with node.
  const started = name === 'fork' ? startsCli(process.execPath, [file, ...args]) : startsCli(file, args);
  if (started) refuse([file, ...args].join(' '), options);
}

/** `exec`, `execSync`: (command, [options], ...). */
function checkCommand(_name: string, callArgs: unknown[]): void {
  const command = String(callArgs[0]);
  if (IN_COMMAND_LINE.test(command)) refuse(command, asOptions(callArgs[1]));
}

const childProcess = createRequire(__filename)('child_process') as Record<string, Launch>;

function guard(name: string, check: (name: string, callArgs: unknown[]) => void): void {
  const original = childProcess[name];
  if (original[GUARDED]) return;
  const guarded: Launch = function (this: unknown, ...callArgs: unknown[]) {
    check(name, callArgs);
    return original.apply(this, callArgs);
  };
  // `promisify(exec)` and `promisify(execFile)` resolve `{ stdout, stderr }`
  // through this property; it is checked the same way.
  const custom = original[promisify.custom];
  if (custom) {
    guarded[promisify.custom] = function (this: unknown, ...callArgs: unknown[]) {
      check(name, callArgs);
      return custom.apply(this, callArgs);
    };
  }
  guarded[GUARDED] = true;
  childProcess[name] = guarded;
}

for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) guard(name, checkFile);
for (const name of ['exec', 'execSync']) guard(name, checkCommand);
// `import { spawnSync } from 'child_process'` reads the wrapped functions too.
syncBuiltinESMExports();
