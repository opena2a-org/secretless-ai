import { describe, it, expect, afterEach, afterAll, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';
import { startDaemon, getDaemonStatus, getLiveDaemonStatus, isDaemonRunning } from './daemon';
import { TOKEN_FILE } from './server';

/**
 * daemon.ts and server.ts fix their default paths under ~/.secretless-ai when
 * they load, and startDaemon builds a server whose resolver opens the store
 * configured there. Run against the HOME of whoever runs the suite, these tests
 * wrote that user's broker.pid, broker.sock, broker.token and audit log, and a
 * long HOME pushed broker.sock past the Unix socket path limit (104 bytes on
 * macOS), so `listen` failed with EINVAL. Hoisted above the imports, this sets
 * a short temporary HOME before either module loads.
 */
const testHome = vi.hoisted(() => {
  const fs = require('fs') as typeof import('fs');
  const os = require('os') as typeof import('os');
  const path = require('path') as typeof import('path');
  // broker.sock is 42 bytes longer than the directory this is made in, so
  // under a TMPDIR longer than 61 bytes it passed the macOS limit again. On
  // POSIX it is made under /tmp.
  const makeHome = (): string =>
    fs.mkdtempSync(path.join(process.platform === 'win32' ? os.tmpdir() : '/tmp', 'sl-home-'));
  const original = process.env.HOME;
  const dir = makeHome();
  process.env.HOME = dir;
  return { dir, original, makeHome };
});

// startDaemon adds SIGTERM and SIGINT handlers that stop the server, and stop()
// writes a shutdown entry to the audit log under HOME. Left in place, the
// worker's own SIGTERM at the end of the run writes one per daemon started
// here, after the temporary HOME is gone.
const signalListeners = {
  SIGTERM: process.listeners('SIGTERM'),
  SIGINT: process.listeners('SIGINT'),
};

afterAll(() => {
  for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    for (const listener of process.listeners(signal)) {
      if (!signalListeners[signal].includes(listener)) process.removeListener(signal, listener);
    }
  }
  if (testHome.original === undefined) delete process.env.HOME;
  else process.env.HOME = testHome.original;
  fs.rmSync(testHome.dir, { recursive: true, force: true });
});

describe('daemon test HOME', () => {
  it('runs the daemon under a temporary HOME the socket path fits in', async () => {
    const dir = path.join(testHome.dir, '.secretless-ai');
    expect(TOKEN_FILE).toBe(path.join(dir, 'broker.token'));

    const server = await startDaemon({ httpPort: 23000 + Math.floor(Math.random() * 1000) });
    try {
      const socketPath = getDaemonStatus()?.socketPath;
      expect(socketPath).toBe(path.join(dir, 'broker.sock'));
      // sun_path holds 104 bytes on macOS and 108 on Linux, the NUL included.
      expect(Buffer.byteLength(socketPath!)).toBeLessThan(104);
    } finally {
      await server.stop();
      fs.rmSync(path.join(dir, 'broker.pid'), { force: true });
    }
  });

  it('keeps the temporary HOME short when TMPDIR is long', () => {
    // Made under a TMPDIR this long, the temporary HOME put broker.sock past the limit.
    const longTmp = path.join(testHome.dir, 'x'.repeat(80));
    fs.mkdirSync(longTmp);
    const savedTmp = process.env.TMPDIR;
    process.env.TMPDIR = longTmp;
    let home: string;
    try {
      home = testHome.makeHome();
    } finally {
      if (savedTmp === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = savedTmp;
    }
    try {
      expect(Buffer.byteLength(path.join(home, '.secretless-ai', 'broker.sock'))).toBeLessThan(104);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

/**
 * Integration tests for `getLiveDaemonStatus`.
 *
 * Regression for a bug where `broker status` reported zero for
 * requestCount/aimConfigured/policyCount because it read only the PID
 * file and never queried the live server.
 *
 * Note: we call `server.stop()` directly rather than `stopDaemon()`
 * because startDaemon runs in-process during tests, so stopDaemon's
 * SIGTERM would kill the test runner itself.
 */
describe('getLiveDaemonStatus', () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'broker-daemon-test-'));
  const policyFile = path.join(tmpBase, 'policies.json');
  fs.writeFileSync(
    policyFile,
    JSON.stringify({
      version: 1,
      rules: [
        {
          id: 'live-status-allow',
          agentSelector: 'test-agent',
          credentialSelector: 'TEST_KEY',
          constraints: {},
          effect: 'allow',
        },
        {
          id: 'live-status-deny',
          agentSelector: 'other',
          credentialSelector: 'OTHER_KEY',
          constraints: {},
          effect: 'deny',
        },
      ],
    }),
  );

  function cleanupDaemonFiles(): void {
    const dir = path.join(os.homedir(), '.secretless-ai');
    for (const f of ['broker.pid', 'broker.sock']) {
      try { fs.unlinkSync(path.join(dir, f)); } catch { /* ignore */ }
    }
    try { fs.unlinkSync(TOKEN_FILE); } catch { /* ignore */ }
  }

  it('returns null when the daemon is not running', async () => {
    cleanupDaemonFiles();
    const status = await getLiveDaemonStatus();
    expect(status).toBeNull();
  });

  it('returns live policyCount from the running server', async () => {
    cleanupDaemonFiles();
    const port = 20000 + Math.floor(Math.random() * 1000);
    const server = await startDaemon({ httpPort: port, policyFile });
    try {
      const status = await getLiveDaemonStatus();
      expect(status).not.toBeNull();
      expect(status!.policyCount).toBe(2);
      expect(status!.aimConfigured).toBe(false);
      expect(typeof status!.requestCount).toBe('number');
    } finally {
      await server.stop();
      cleanupDaemonFiles();
    }
  });

  it('falls back to pid-file-only status when the server HTTP is unreachable', async () => {
    cleanupDaemonFiles();
    const port = 20000 + Math.floor(Math.random() * 1000);
    const server = await startDaemon({ httpPort: port, policyFile });
    // server.stop() removes the auth token file, so the live HTTP probe
    // fails. Meanwhile startDaemon wrote the PID as the current process,
    // which is still alive (we're running in it), so PID-file status is
    // still valid. Live status must fall back to those base values.
    await server.stop();

    const baseStatus = getDaemonStatus();
    expect(baseStatus).not.toBeNull();

    const liveStatus = await getLiveDaemonStatus();
    expect(liveStatus).not.toBeNull();
    // Fallback: policyCount and requestCount are the PID-file placeholders (0),
    // not a live value. aimConfigured is false either way.
    expect(liveStatus!.policyCount).toBe(0);
    expect(liveStatus!.aimConfigured).toBe(false);

    cleanupDaemonFiles();
  });

  it('reports aimConfigured=true, aimReachable=true when AIM responds to /health', async () => {
    cleanupDaemonFiles();

    // Start a mock AIM that returns 200 on /health
    const aim = http.createServer((req, res) => {
      if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'healthy' }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((resolve) => { aim.listen(0, '127.0.0.1', resolve); });
    const aimPort = (aim.address() as { port: number }).port;

    const port = 21000 + Math.floor(Math.random() * 1000);
    const server = await startDaemon({
      httpPort: port,
      policyFile,
      aimUrl: `http://127.0.0.1:${aimPort}`,
    });

    try {
      const status = await getLiveDaemonStatus();
      expect(status).not.toBeNull();
      expect(status!.aimConfigured).toBe(true);
      expect(status!.aimReachable).toBe(true);
    } finally {
      await server.stop();
      await new Promise<void>((resolve) => { aim.close(() => resolve()); });
      cleanupDaemonFiles();
    }
  });

  it('reports aimConfigured=true, aimReachable=false when AIM /health fails', async () => {
    cleanupDaemonFiles();

    // Port that's definitely not listening
    const port = 22000 + Math.floor(Math.random() * 1000);
    const server = await startDaemon({
      httpPort: port,
      policyFile,
      aimUrl: 'http://127.0.0.1:1', // blackhole
    });

    try {
      const status = await getLiveDaemonStatus();
      expect(status).not.toBeNull();
      expect(status!.aimConfigured).toBe(true);
      expect(status!.aimReachable).toBe(false);
    } finally {
      await server.stop();
      cleanupDaemonFiles();
    }
  });
});

/**
 * The two JSON reads in daemon.ts refuse a repeated member name rather than
 * letting JSON.parse keep the last copy.
 */
describe('daemon status reads refuse a duplicated member name', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'broker-daemon-dup-'));
  const pidFile = path.join(dir, 'broker.pid');

  afterEach(() => {
    try { fs.unlinkSync(pidFile); } catch { /* ignore */ }
    try { fs.unlinkSync(TOKEN_FILE); } catch { /* ignore */ }
  });

  function writePidFile(httpPort: number): void {
    // The exact shape startDaemon writes.
    fs.writeFileSync(pidFile, JSON.stringify({
      pid: process.pid,
      startedAt: new Date().toISOString(),
      socketPath: path.join(dir, 'broker.sock'),
      httpPort,
    }));
  }

  it('reads a PID file as startDaemon writes it (control)', () => {
    writePidFile(1);
    expect(getDaemonStatus(pidFile)?.pid).toBe(process.pid);
    expect(isDaemonRunning(pidFile)).toBe(true);
  });

  it('reads a PID file that repeats a member as no daemon', () => {
    // The live pid comes last, so JSON.parse alone would report a running
    // daemon and stopDaemon would signal that process.
    fs.writeFileSync(
      pidFile,
      `{"pid":999999999,"startedAt":"2026-10-06T00:00:00.000Z","httpPort":1,"pid":${process.pid}}`,
    );
    expect(getDaemonStatus(pidFile)).toBeNull();
    expect(isDaemonRunning(pidFile)).toBe(false);
  });

  it('falls back to the PID-file status when /status repeats a member', async () => {
    let statusBody = '';
    const statusServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(statusBody);
    });
    await new Promise<void>((resolve) => { statusServer.listen(0, '127.0.0.1', resolve); });
    const port = (statusServer.address() as { port: number }).port;
    writePidFile(port);
    fs.mkdirSync(path.dirname(TOKEN_FILE), { recursive: true, mode: 0o700 });
    fs.writeFileSync(TOKEN_FILE, 'test-token', { mode: 0o600 });

    try {
      // Control: a clean response is read as live status.
      statusBody = '{"requestCount":3,"aimConfigured":false,"aimReachable":false,"policyCount":7}';
      const live = await getLiveDaemonStatus(pidFile);
      expect(live!.policyCount).toBe(7);
      expect(live!.requestCount).toBe(3);

      statusBody =
        '{"requestCount":3,"aimConfigured":false,"aimReachable":false,"policyCount":2,"policyCount":7}';
      const fallback = await getLiveDaemonStatus(pidFile);
      expect(fallback).not.toBeNull();
      expect(fallback!.policyCount).toBe(0);
      expect(fallback!.requestCount).toBe(0);
    } finally {
      await new Promise<void>((resolve) => { statusServer.close(() => resolve()); });
    }
  });
});
