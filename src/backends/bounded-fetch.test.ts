import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as http from 'http';
import type { AddressInfo } from 'net';
import { boundedFetch, describeRequest } from './bounded-fetch';

/**
 * A real HTTP server on loopback, so the bound is measured against Node's own
 * fetch and sockets rather than a mock that may not honour an abort.
 */
type Mode = 'silent' | 'headers-then-stall' | 'json';

let server: http.Server;
let base: string;
let mode: Mode;
let closed: Promise<void>;

beforeEach(async () => {
  let markClosed: () => void = () => {};
  closed = new Promise(r => { markClosed = r; });
  server = http.createServer((req, res) => {
    req.socket.on('close', markClosed);
    if (mode === 'json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    } else if (mode === 'headers-then-stall') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.write('{"data":');
    }
    // silent: never answers
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  server.closeAllConnections();
  await new Promise<void>(r => server.close(() => r()));
});

const TIMEOUT_MS = 300;
const onTimeout = () => new Error('planted backend did not respond; Verify: planted');

describe('boundedFetch', () => {
  it('a server that never answers: throws the caller\'s error within the bound and closes the connection', async () => {
    mode = 'silent';
    const start = Date.now();
    await expect(
      boundedFetch(`${base}/v1/x`, { method: 'GET' }, { timeoutMs: TIMEOUT_MS, onTimeout }),
    ).rejects.toThrow('planted backend did not respond; Verify: planted');
    expect(Date.now() - start).toBeLessThan(TIMEOUT_MS + 1_000);
    await closed;
  });

  it('a server that sends headers and stalls the body: the body read throws the caller\'s error within the same bound', async () => {
    mode = 'headers-then-stall';
    const start = Date.now();
    const res = await boundedFetch(`${base}/v1/x`, { method: 'GET' }, { timeoutMs: TIMEOUT_MS, onTimeout });
    expect(res.status).toBe(200);
    await expect(res.json()).rejects.toThrow('planted backend did not respond; Verify: planted');
    expect(Date.now() - start).toBeLessThan(TIMEOUT_MS + 1_000);
    await closed;
  });

  it('a server that answers in time: status and body come through, and nothing fires after the bound', async () => {
    mode = 'json';
    let fired = 0;
    const res = await boundedFetch(`${base}/v1/x`, { method: 'GET' }, {
      timeoutMs: TIMEOUT_MS,
      onTimeout: () => { fired += 1; return new Error('should not fire'); },
    });
    expect(res.ok).toBe(true);
    expect(await res.json()).toEqual({ ok: true });
    await new Promise(r => setTimeout(r, TIMEOUT_MS + 100));
    expect(fired).toBe(0);
  });
});

describe('describeRequest', () => {
  it('names the method and path, and drops userinfo and the query', () => {
    const userinfo = ['user', 'FAKE-pw'].join(':');
    expect(describeRequest('GET', `https://${userinfo}@vault.example:8200/v1/secret/data/K?version=2`))
      .toBe('GET /v1/secret/data/K');
  });

  it('falls back to the method for a URL it cannot parse', () => {
    expect(describeRequest('POST', 'not a url')).toBe('POST');
  });
});
