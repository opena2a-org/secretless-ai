import { defineConfig } from 'vitest/config';

// An embedding host sets SECRETLESS_CLI_PREFIX to print its own command name in
// place of `npx secretless-ai`. The tests assert the default name, so a prefix
// set where the suite runs is removed here, before vitest copies process.env
// into each worker and the tests copy it into every CLI child they start. A
// test of the prefix sets it itself. Removing this line is caught by
// src/vitest-config-env.test.ts.
delete process.env.SECRETLESS_CLI_PREFIX;

// CLAUDE_CONFIG_DIR moves the transcript directory `watch`, `clean`, `status`
// and `verify` read by default away from ~/.claude (#237). The tests keep
// those commands off real transcripts by giving each CLI child its own HOME,
// so a value set where the suite runs, as inside a Claude Code session with
// its own configuration directory, is removed here the same way. A test of
// the variable sets it itself. Removing this line is caught by
// src/vitest-config-env.test.ts.
delete process.env.CLAUDE_CONFIG_DIR;

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
    // Every worker, and every CLI child the tests start from a copy of
    // process.env, refuses to start the OS credential-store CLIs. Removing
    // this line is caught by src/backends/bounded-child.test.ts.
    //
    // OPENA2A_TELEMETRY: the same children send no usage event (#320).
    // Removing it is caught by src/telemetry-automated-run.test.ts.
    env: { SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off' },
    // Fails a test that starts the CLI with telemetry on.
    setupFiles: ['src/telemetry-guard.test-support.ts'],
  },
});
