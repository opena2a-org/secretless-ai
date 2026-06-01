/**
 * Ephemeral-worker URL resolution — regression tests for the credential-confinement
 * invariant (AAP §4 / §6.5). The agent controls `operation.path`; the broker controls the
 * `audience`. The worker MUST NOT let a crafted path repoint the request host, because the
 * scoped bearer token rides on that request — a host change is a token exfiltration.
 */

import { describe, it, expect } from 'vitest';
import { resolveDownstreamUrl, HttpsDownstreamCaller } from './worker';
import type { ScopedCredential } from './cpi/types';

const AUDIENCE = 'https://api.orders.internal';

describe('resolveDownstreamUrl — origin pinning', () => {
  it('resolves a normal absolute path against the audience origin', () => {
    const url = resolveDownstreamUrl(AUDIENCE, '/orders');
    expect(url.origin).toBe('https://api.orders.internal');
    expect(url.pathname).toBe('/orders');
  });

  it('keeps a trailing-slash audience on its own origin', () => {
    const url = resolveDownstreamUrl('https://api.orders.internal/', '/orders/123');
    expect(url.origin).toBe('https://api.orders.internal');
    expect(url.pathname).toBe('/orders/123');
  });

  // The exfiltration vectors: each would, under naive `audience + path` concatenation,
  // repoint the host to evil.com and leak the scoped token.
  it.each([
    ['userinfo smuggling', '@evil.com/collect'],
    ['protocol-relative host', '//evil.com/collect'],
    ['absolute URL', 'https://evil.com/collect'],
    ['scheme-relative with creds', '//user:pass@evil.com/'],
    ['relative (no leading slash)', 'orders'],
    ['backslash host trick', '/\\evil.com/collect'],
  ])('rejects %s (%s)', (_label, path) => {
    expect(() => resolveDownstreamUrl(AUDIENCE, path)).toThrow();
  });

  it('the resolved host always equals the audience host for accepted paths', () => {
    for (const p of ['/', '/a', '/a/b/c', '/orders?x=1']) {
      expect(resolveDownstreamUrl(AUDIENCE, p).host).toBe('api.orders.internal');
    }
  });
});

describe('HttpsDownstreamCaller — rejects host-changing paths without making a request', () => {
  const cred: ScopedCredential = {
    token: 'SCOPED-TOKEN-MUST-NOT-LEAK',
    tokenType: 'Bearer',
    expiresInSeconds: 300,
  };

  it('rejects before any network call when the path would change the host', async () => {
    const caller = new HttpsDownstreamCaller();
    await expect(
      caller.call(AUDIENCE, { method: 'GET', path: '@evil.com/collect' }, cred),
    ).rejects.toThrow(/origin|absolute/i);
  });
});
