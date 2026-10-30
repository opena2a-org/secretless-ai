/**
 * Shared by the broker audit-record tests: spies on every unsigned channel a process writes to
 * (stdout, stderr and the five console methods), so a test can show that text the signed record
 * does not carry was written nowhere else either.
 */

import { vi } from 'vitest';

export interface ChannelSpies {
  /** Everything written to stdout, stderr and the console since the spies were armed. */
  text(): string;
  /** Put every spied method back. */
  restore(): void;
}

function asText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString('utf-8');
  return String(value);
}

/**
 * Arm the spies. Each one calls through, so output still reaches the runner, unless `swallow` is
 * set: then nothing written while they are armed is printed.
 */
export function armChannelSpies(options?: { swallow?: boolean }): ChannelSpies {
  const stdout = vi.spyOn(process.stdout, 'write');
  const stderr = vi.spyOn(process.stderr, 'write');
  const consoles = (['log', 'error', 'warn', 'info', 'debug'] as const).map((method) => vi.spyOn(console, method));
  if (options?.swallow) {
    stdout.mockImplementation(() => true);
    stderr.mockImplementation(() => true);
    for (const spy of consoles) spy.mockImplementation(() => undefined);
  }
  const calls = (): unknown[][] => [
    ...(stdout.mock.calls as unknown[][]),
    ...(stderr.mock.calls as unknown[][]),
    ...consoles.flatMap((spy) => spy.mock.calls as unknown[][]),
  ];
  return {
    text: () => calls().flat().map(asText).join('\n'),
    restore: () => {
      stdout.mockRestore();
      stderr.mockRestore();
      for (const spy of consoles) spy.mockRestore();
    },
  };
}
