/**
 * Ephemeral-worker URL resolution — regression tests for the credential-confinement
 * invariant (AAP §4 / §6.5). The agent controls `operation.path`; the broker controls the
 * `audience`. The worker MUST NOT let a crafted path repoint the request host, because the
 * scoped bearer token rides on that request — a host change is a token exfiltration.
 */

import * as crypto from 'crypto';
import { describe, it, expect } from 'vitest';
import { resolveDownstreamUrl, EphemeralWorker, HttpsDownstreamCaller } from './worker';
import type { ResourceBinding, ScopedCredential } from './cpi/types';

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

describe('EphemeralWorker — the operation salt goes to the caller and nowhere else', () => {
  const cred: ScopedCredential = {
    token: crypto.randomBytes(16).toString('hex'),
    tokenType: 'Bearer',
    expiresInSeconds: 300,
  };
  const binding: ResourceBinding = {
    mode: 'exchange',
    providerId: 'orders-idp',
    scope: 'orders.read',
    audience: AUDIENCE,
    ttlSeconds: 300,
  };
  const answer = async () => ({ status: 200, body: null });

  it('reports whether its caller delivers salts', () => {
    expect(new EphemeralWorker({ deliversSalt: true, call: answer }).deliversSalt).toBe(true);
    expect(new EphemeralWorker({ call: answer }).deliversSalt).toBe(false);
    expect(new EphemeralWorker(new HttpsDownstreamCaller()).deliversSalt).toBe(false);
  });

  it('hands the salt to the caller with the operation', async () => {
    const received: Array<Uint8Array | undefined> = [];
    const worker = new EphemeralWorker({
      deliversSalt: true,
      call: async (_audience, _op, _cred, salt) => {
        received.push(salt);
        return answer();
      },
    });
    const salt = crypto.randomBytes(32);
    await worker.run(binding, cred, { method: 'GET', path: '/orders' }, salt);
    expect(received).toHaveLength(1);
    expect(Buffer.from(received[0] as Uint8Array).equals(salt)).toBe(true);
  });

  it('never runs the caller, so the salt goes nowhere, when the origin pin refuses the path', async () => {
    let ran = false;
    const worker = new EphemeralWorker({
      deliversSalt: true,
      call: async () => {
        ran = true;
        return answer();
      },
    });
    await expect(
      worker.run(binding, cred, { method: 'GET', path: '//evil.com/collect' }, crypto.randomBytes(32)),
    ).rejects.toThrow(/absolute/);
    expect(ran).toBe(false);
  });
});
