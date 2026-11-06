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
    // The bound for a test that sets none of its own (vitest's default is
    // 5000 ms). Three whole-suite runs with four workers on a 16-core machine,
    // each started while the one-minute load average was under 24, measured
    // per-test durations of p99 6160 to 7960 ms (7017 ms over all three) and a
    // max of 171644 ms, a test that sets its own larger bound and keeps it. The
    // slowest test that passed under the 5000 ms default took 4988 ms. The
    // value is the smallest multiple of 5000 ms that is at least the highest
    // p99 and at least twice 4988 ms (derivation: the builder's, not ruled).
    //
    // The worker count stays vitest's default unless VITEST_MAX_WORKERS is
    // set; vitest reads that variable itself, ahead of this file and of
    // --maxWorkers.
    testTimeout: 10_000,
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
