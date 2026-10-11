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
 * `false` or `0`, so `CI=false` leaves telemetry as the user configured it.
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
