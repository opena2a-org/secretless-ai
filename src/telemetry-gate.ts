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

/**
 * Write the setting as the SDK writes it: directory mode 0700, file mode 0600.
 *
 * The content goes to a new file in the same directory, which is then renamed
 * over the setting file (#429). Writing the setting file in place truncated it
 * first, so a write that failed part way left it empty, an
 * empty file reads as absent, and absent is on: a stored `"enabled": false`
 * was lost. A write that fails now removes the new file and leaves the
 * setting file as it was; a process killed before the rename leaves the
 * setting file as it was and a `.telemetry.json.*.tmp` file next to it.
 *
 * A symlinked setting file is followed, so the link stays a link. A setting
 * file this user cannot write is not replaced: the write throws, as the
 * in-place write did.
 */
function writeTelemetrySetting(file: string, setting: TelemetrySetting): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  let target = file;
  if (fs.existsSync(file)) {
    target = fs.realpathSync(file);
    fs.accessSync(target, fs.constants.W_OK);
  }
  const temp = path.join(
    path.dirname(target),
    `.${path.basename(target)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`,
  );
  const fd = fs.openSync(temp, 'wx', 0o600);
  try {
    try {
      fs.writeFileSync(fd, JSON.stringify(setting, null, 2) + '\n');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temp, target);
  } catch (err) {
    fs.rmSync(temp, { force: true });
    throw err;
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
