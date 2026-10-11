import { defineConfig } from 'vitest/config';

// An embedding host sets SECRETLESS_CLI_PREFIX to print its own command name in
// place of `npx secretless-ai`. The tests assert the default name, so a prefix
// set where the suite runs is removed here, before vitest copies process.env
// into each worker and the tests copy it into every CLI child they start. A
// test of the prefix sets it itself. Removing this line is caught by
// src/vitest-config-env.test.ts.
delete process.env.SECRETLESS_CLI_PREFIX;

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
    // Every worker, and every CLI child the tests start from a copy of
    // process.env, refuses to start the OS credential-store CLIs. Removing
    // this line is caught by src/backends/bounded-child.test.ts.
    env: { SECRETLESS_OS_KEYCHAIN: 'off' },
  },
});
