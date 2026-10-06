import { defineConfig } from 'vitest/config';

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
