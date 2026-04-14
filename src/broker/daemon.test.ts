import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';
import { startDaemon, getDaemonStatus, getLiveDaemonStatus } from './daemon';
import { TOKEN_FILE } from './server';

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
