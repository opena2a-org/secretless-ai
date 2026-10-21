import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * No usage event is sent from CI or from a test runner.
 *
 * A CI job and a test run usually start in a fresh home directory, and the
 * telemetry SDK gives every fresh home a new install id, so each job and each
 * test run was counted as a new user of the tool: one month's figures were
 * mostly test traffic (#320). The opt-out variable stays the user's switch;
 * this is the default for runs no person started at a terminal.
 *
 * A variable counts when it is set to anything other than an empty string,
 * `false` or `0`, compared after trimming spaces and in any letter case, so
 * `CI=false`, `CI=FALSE` and `CI=` leave telemetry as the user configured it.
 */
export const AUTOMATED_RUN_VARIABLES: readonly string[] = [
  // CI services. Most set `CI`; these are the ones that also set, or only
  // set, a variable of their own.
  'CI',
  'CONTINUOUS_INTEGRATION',
  'GITHUB_ACTIONS',
  'GITLAB_CI',
  'CIRCLECI',
  'TRAVIS',
  'BUILDKITE',
  'BITBUCKET_BUILD_NUMBER',
  'DRONE',
  'APPVEYOR',
  'JENKINS_URL',
  'TEAMCITY_VERSION',
  'TF_BUILD',
  'CODEBUILD_BUILD_ID',
  // Test runners: vitest, jest and `node --test`, each of which sets its
  // variable in the environment a test's child process inherits.
  'VITEST',
  'VITEST_WORKER_ID',
  'JEST_WORKER_ID',
  'NODE_TEST_CONTEXT',
];

const UNSET_VALUES = new Set(['', 'false', '0']);

/**
 * The first variable in `env` that marks this run as CI or a test run, or
 * `undefined` when there is none and telemetry follows the user's setting.
 */
export function automatedRunVariable(env: NodeJS.ProcessEnv): string | undefined {
  return AUTOMATED_RUN_VARIABLES.find((name) => {
    const value = env[name];
    return value !== undefined && !UNSET_VALUES.has(value.trim().toLowerCase());
  });
}

/**
 * No install id is derived or written while telemetry is off (#422).
 *
 * The telemetry SDK's `init`, `status` and `setOptOut` each derive an install
 * id and write it to the setting file when the file has none, whatever
 * OPENA2A_TELEMETRY says: the opt-out only stopped sending. cli.ts calls them
 * on a run that starts with telemetry on, and uses the functions below
 * otherwise, with one exception: `telemetry on` with a stored `telemetry off`
 * and none of OPENA2A_TELEMETRY=off, CI or a test runner set calls the SDK's
 * `setOptOut` and then its `status`, because that command turns telemetry on.
 */
export const OPT_OUT_VARIABLE = 'OPENA2A_TELEMETRY';

/** The values the SDK reads as off, compared in any letter case and untrimmed, as the SDK compares them. */
const OPT_OUT_VALUES = new Set(['off', '0', 'false', 'no']);

/** True when OPENA2A_TELEMETRY turns telemetry off for this run. */
export function optedOutByVariable(env: NodeJS.ProcessEnv): boolean {
  const value = env[OPT_OUT_VARIABLE];
  return value !== undefined && OPT_OUT_VALUES.has(value.toLowerCase());
}

/**
 * The file the SDK keeps the setting and the install id in:
 * `$XDG_CONFIG_HOME/opena2a/telemetry.json` when that variable is set and not
 * empty, `~/.config/opena2a/telemetry.json` otherwise. The SDK does not export
 * its own function for it; a test checks this one against the file it creates.
 */
export function telemetrySettingFile(env: NodeJS.ProcessEnv, home: string = os.homedir()): string {
  const dir = env.XDG_CONFIG_HOME
    ? path.join(env.XDG_CONFIG_HOME, 'opena2a')
    : path.join(home, '.config', 'opena2a');
  return path.join(dir, 'telemetry.json');
}

export interface TelemetrySetting {
  enabled: boolean;
  installId?: string;
}

/**
 * The stored setting, read without creating or changing anything, or `null`
 * when the file is absent or is not JSON. `enabled` is read as the SDK reads
 * it: a missing or null value is on, any other value is on when truthy.
 */
export function readTelemetrySetting(file: string): TelemetrySetting | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch {
    return null;
  }
  const stored = typeof parsed === 'object' && parsed !== null ? parsed as Record<string, unknown> : {};
  const enabled = Boolean(stored.enabled ?? true);
  const installId = typeof stored.installId === 'string' && stored.installId !== '' ? stored.installId : undefined;
  return installId ? { enabled, installId } : { enabled };
}

/** Symbolic links followed from the setting file before a chain counts as a loop. */
const MAX_SETTING_LINKS = 40;

/**
 * The path the setting is renamed to: the setting file, or the file at the
 * end of its symbolic links. fs.existsSync and fs.realpathSync fail on a link
 * whose target does not exist yet, so such a link is followed one readlink at
 * a time, and the target is created as the in-place write created it (#432).
 * A link loop throws ELOOP, as the in-place write did, and is not replaced.
 */
function settingWriteTarget(file: string): string {
  if (fs.existsSync(file)) {
    const target = fs.realpathSync(file);
    fs.accessSync(target, fs.constants.W_OK);
    return target;
  }
  let target = file;
  for (let links = 0; ; links++) {
    try {
      if (!fs.lstatSync(target).isSymbolicLink()) return target;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return target;
      throw err;
    }
    if (links === MAX_SETTING_LINKS) {
      throw Object.assign(new Error(`ELOOP: too many symbolic links, open '${file}'`), { code: 'ELOOP' });
    }
    target = path.resolve(fs.realpathSync(path.dirname(target)), fs.readlinkSync(target));
  }
}

/** The errors that refuse the new file, or its rename over the setting file, and lead to the in-place write; see writeTelemetrySetting. */
const NEW_FILE_REFUSALS = new Set(['EACCES', 'EPERM']);

/** True when `err` is one of NEW_FILE_REFUSALS. */
function refused(err: unknown): boolean {
  return NEW_FILE_REFUSALS.has((err as NodeJS.ErrnoException).code ?? '');
}

/**
 * Write the setting as the SDK writes it: directory mode 0700, file mode 0600.
 *
 * The content goes to a new file in the same directory, which is then renamed
 * over the setting file (#429). Writing the setting file in place truncated it
 * first, so a write that failed part way left it empty, an
 * empty file reads as absent, and absent is on: a stored `"enabled": false`
 * was lost. A write that fails now leaves the setting file as it was and
 * removes the new file, unless the directory refuses that too (below); a
 * process killed before the rename leaves the setting file as it was and a
 * `.telemetry.json.*.tmp` file next to it.
 *
 * A symlinked setting file is followed, so the link stays a link. A setting
 * file this user cannot write is not replaced: the write throws, as the
 * in-place write did.
 *
 * A setting file this user can write, in a directory that refuses the new
 * file or its rename with EACCES or EPERM, is rewritten in place: the new file
 * needs write permission on the directory (EACCES, #431) and, on macOS, no
 * `chflags uchg` immutable flag on it (EPERM, #434), and its rename needs no
 * `chflags uappnd` append-only flag on it (EPERM, #436); the in-place write
 * needs none of these. That write keeps the file's mode and does not truncate
 * the file before writing, so a write that fails before its first byte leaves
 * the setting file as it was. With no setting file, the refusal is thrown.
 *
 * An append-only directory takes the new file and then refuses to rename or
 * remove it, so before the new file is made, the setting file is renamed to
 * itself. On macOS that rename changes nothing in a directory that allows it,
 * and each of the three directories above refuses it with the error it
 * refuses the new file or its rename with; the file is then rewritten in
 * place without a new file. With no setting file there is nothing to rename,
 * so in an append-only directory the new file stays and its refused rename
 * is thrown.
 */
function writeTelemetrySetting(file: string, setting: TelemetrySetting): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const content = JSON.stringify(setting, null, 2) + '\n';
  const exists = fs.existsSync(file);
  const target = settingWriteTarget(file);
  if (exists && renameRefused(target)) {
    writeInPlace(target, content);
    return;
  }
  const temp = path.join(
    path.dirname(target),
    `.${path.basename(target)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
  );
  let fd: number;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
  } catch (err) {
    if (!exists || !refused(err)) throw err;
    writeInPlace(target, content);
    return;
  }
  try {
    try {
      fs.writeFileSync(fd, content);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch (err) {
    removeNewFile(temp);
    throw err;
  }
  try {
    fs.renameSync(temp, target);
  } catch (err) {
    removeNewFile(temp);
    if (!exists || !refused(err)) throw err;
    writeInPlace(target, content);
  }
}

/** True when renaming `target` to itself is refused with one of NEW_FILE_REFUSALS. */
function renameRefused(target: string): boolean {
  try {
    fs.renameSync(target, target);
    return false;
  } catch (err) {
    return refused(err);
  }
}

/**
 * Remove the new file after its write or rename failed. A directory that
 * refuses this as well keeps it, and that refusal is not thrown (#436).
 */
function removeNewFile(temp: string): void {
  try {
    fs.rmSync(temp, { force: true });
  } catch {
    // The new file stays.
  }
}

/** Write `content` over the start of `file`, then cut the file to its length. */
function writeInPlace(file: string, content: string): void {
  const fd = fs.openSync(file, 'r+');
  try {
    fs.writeFileSync(fd, content);
    fs.ftruncateSync(fd, Buffer.byteLength(content));
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Store the setting without an install id: `telemetry on` under
 * OPENA2A_TELEMETRY=off, CI or a test runner, and `telemetry off` on any run.
 * An id already stored is dropped for `on` as for `off` (#426); the SDK
 * derives one on the next run with telemetry on.
 */
export function storeTelemetrySetting(file: string, enabled: boolean): TelemetrySetting {
  const setting: TelemetrySetting = { enabled };
  writeTelemetrySetting(file, setting);
  return setting;
}

/**
 * Delete an install id an earlier run left in the setting file, keeping the
 * stored `enabled` value (#426). cli.ts calls it on every run with telemetry
 * off, so an id is kept only while telemetry is on. A file with no id is not
 * written. Returns true when the file was rewritten.
 */
export function dropStoredInstallId(file: string): boolean {
  const setting = readTelemetrySetting(file);
  if (!setting?.installId) return false;
  writeTelemetrySetting(file, { enabled: setting.enabled });
  return true;
}

/** Why `telemetry status` shows the state it shows, as cli.ts reads it. */
export interface TelemetryState {
  /** The state shown: on when no variable turns it off and the setting is on. */
  on: boolean;
  /** The CI or test-runner variable that turns it off for this run, if any. */
  automated: string | undefined;
  /** True when OPENA2A_TELEMETRY turns it off for this run. */
  optedOut: boolean;
  /** The stored setting: on when no `telemetry off` is stored. */
  storedOn: boolean;
}

/**
 * The `toggle:` line `telemetry status` ends with, or null when nothing given
 * here turns it on.
 *
 * The status helper of @opena2a/cli-ui ends with
 * `toggle: '<tool> telemetry off'  or  OPENA2A_TELEMETRY=off` whatever the
 * state, so `state: off` was followed by a way to turn it off (#127). The
 * line names what changes the state shown: `telemetry off` while it is on;
 * `telemetry on` while a stored `telemetry off` is what turns it off; unsetting
 * OPENA2A_TELEMETRY, then `telemetry on` if it is stored off as well, while
 * the variable does. A CI or test-runner run sends nothing whatever is set,
 * so there is no line, and the "Off for this run" line says why.
 */
export function telemetryToggleLine(cli: string, state: TelemetryState): string | null {
  if (state.on) return `toggle: '${cli} telemetry off'  or  ${OPT_OUT_VARIABLE}=off`;
  if (state.automated) return null;
  if (state.optedOut) return `toggle: unset ${OPT_OUT_VARIABLE}${state.storedOn ? '' : `, then '${cli} telemetry on'`}`;
  return `toggle: '${cli} telemetry on'`;
}

/**
 * `status`, the text the status helper printed, with its `toggle:` line
 * replaced by `toggle`, or removed with the blank line above it when `toggle`
 * is null. The helper colours the line, and the colour is kept. A status with
 * no such line is returned as it is.
 */
export function withToggleLine(status: string, tool: string, toggle: string | null): string {
  const helperToggle = `toggle: '${tool} telemetry off'  or  ${OPT_OUT_VARIABLE}=off`;
  const lines = status.split('\n');
  const at = lines.findIndex((line) => line.includes(helperToggle));
  if (at === -1) return status;
  if (toggle !== null) {
    lines[at] = lines[at].replace(helperToggle, () => toggle);
  } else if (at > 0 && lines[at - 1] === '') {
    lines.splice(at - 1, 2);
  } else {
    lines.splice(at, 1);
  }
  return lines.join('\n');
}
