import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../backends/factory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../backends/factory')>();
  return {
    ...actual,
    createBackend: vi.fn(),
  };
});

vi.mock('../backends/config', () => ({
  readBackendConfig: vi.fn(),
}));

import { createBackend, unavailableBackendError } from '../backends/factory';
import { readBackendConfig } from '../backends/config';
import { resolveRef, RefResolutionError } from './resolver';

const mockCreateBackend = vi.mocked(createBackend);
const mockReadBackendConfig = vi.mocked(readBackendConfig);

/**
 * `resolveFromBackend` builds the backend a reference names through
 * `createBackend`, which THROWS when that backend is unreachable instead of
 * quietly handing back a local store.
 *
 * Escaping there would replace the RefResolutionError — which names the URI
 * that failed — with a bare backend error carrying no reference at all, from a
 * function whose caller has no try/catch.
 */
describe('resolveRef when backends are unreachable', () => {
  beforeEach(() => {
    mockCreateBackend.mockReset();
    mockReadBackendConfig.mockReset();
  });

  it('reports the failing ref when neither the ref backend nor the configured one is reachable', async () => {
    mockReadBackendConfig.mockReturnValue('1password' as never);
    mockCreateBackend.mockImplementation(() => {
      throw new Error('Configured backend "1password" is not reachable: not signed in');
    });

    const uri = 'secret://1password/op://Personal/prod/password';

    // Pre-fix this rejected with the raw backend Error, which names no ref.
    await expect(resolveRef(uri)).rejects.toBeInstanceOf(RefResolutionError);
    await expect(resolveRef(uri)).rejects.toThrow(uri);
  });

  it('does not answer the ref from the configured backend when only the ref backend is down (#372)', async () => {
    mockReadBackendConfig.mockReturnValue('local' as never);

    let call = 0;
    mockCreateBackend.mockImplementation((() => {
      call += 1;
      if (call === 1) {
        throw unavailableBackendError('1password', 'not signed in', ['op signin'], 'op account get', 'named');
      }
      return {
        name: 'local',
        resolve: async () => ({ 'secret/prod/password': 'held-by-the-configured-backend' }),
        store: async () => {},
        delete: async () => false,
        healthCheck: async () => ({ healthy: true, latencyMs: 0, message: '' }),
      };
    }) as never);

    const uri = 'secret://1password/prod/password';
    const refusal = await resolveRef(uri).then(
      (r) => r,
      (e: Error) => e,
    );

    // Before the fix this resolved to 'held-by-the-configured-backend',
    // reported as backend '1password'.
    expect(refusal).toBeInstanceOf(RefResolutionError);
    expect((refusal as RefResolutionError).message).toBe(
      `Backend "1password" named by ${uri} is not reachable: not signed in. No other store was read in its place.`,
    );
    expect((refusal as RefResolutionError).ref).toBe(uri);
    expect((refusal as RefResolutionError).backend).toBe('1password');
    // #369: the ref's backend is named for this read. Nothing else is built.
    expect(mockCreateBackend.mock.calls).toEqual([
      ['1password', undefined, true, { role: 'named' }],
    ]);
  });
});
