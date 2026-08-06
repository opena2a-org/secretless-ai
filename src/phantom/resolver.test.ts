import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../backends/factory', () => ({
  createBackend: vi.fn(),
}));

vi.mock('../backends/config', () => ({
  readBackendConfig: vi.fn(),
}));

import { createBackend } from '../backends/factory';
import { readBackendConfig } from '../backends/config';
import { resolveRef, RefResolutionError } from './resolver';

const mockCreateBackend = vi.mocked(createBackend);
const mockReadBackendConfig = vi.mocked(readBackendConfig);

/**
 * `resolveFromBackend` tries the ref's own backend, then falls back to the
 * configured one. Both calls go through `createBackend`, which since 0.21.0
 * THROWS when a configured backend is unreachable instead of quietly handing
 * back a local store.
 *
 * That made the fallback call able to throw for the first time. Escaping there
 * would replace the RefResolutionError — which names the URI that failed — with
 * a bare backend error carrying no reference at all, from a function whose
 * caller has no try/catch.
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

  it('still resolves through the fallback backend when only the ref backend is down', async () => {
    mockReadBackendConfig.mockReturnValue('local' as never);

    let call = 0;
    mockCreateBackend.mockImplementation((() => {
      call += 1;
      if (call === 1) throw new Error('1password unreachable');
      return {
        name: 'local',
        resolve: async () => ({ 'secret/prod/password': 'the-value' }),
        store: async () => {},
        delete: async () => false,
        healthCheck: async () => ({ healthy: true, latencyMs: 0, message: '' }),
      };
    }) as never);

    const result = await resolveRef('secret://1password/prod/password');
    expect(result.value).toBe('the-value');
    expect(mockCreateBackend).toHaveBeenCalledTimes(2);
  });
});
