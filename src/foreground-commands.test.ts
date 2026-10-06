import { describe, it, expect, afterEach } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';

/**
 * `broker start` and `watch start` run their service inside the CLI process
 * and print that it is running. The dispatcher exits the process when a
 * command returns, and both commands used to return straight after printing,
 * so the service ended the moment it was reported running and the matching
 * `status` command said it was not. `warm` started the broker the same way.
 *
 * These tests run the built CLI with a temporary HOME and check, as a user
 * would, that the service is still there after the report.
 */

const DIST = path.resolve(__dirname, '..', 'dist');
const CLI_PATH = path.join(DIST, 'cli.js');
const DAEMON_PATH = path.join(DIST, 'broker', 'daemon.js');
const hasBuild = fs.existsSync(CLI_PATH) && fs.existsSync(DAEMON_PATH);
const itIfBuilt = hasBuild ? it : it.skip;

const TEST_TIMEOUT_MS = 30_000;

const homes: string[] = [];
const pids: number[] = [];

afterEach(() => {
  for (const pid of pids.splice(0)) {
    try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ }
  }
  for (const home of homes.splice(0)) fs.rmSync(home, { recursive: true, force: true });
});

function tempHome(): string {
  // Short prefix: the broker's unix socket lives under this HOME, and socket
  // paths are capped at 104 bytes on macOS.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'slfg-'));
  homes.push(home);
  return home;
}

function envFor(home: string): NodeJS.ProcessEnv {
  return { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' };
}

function runCli(args: string[], home: string) {
  return spawnSync(process.execPath, [CLI_PATH, ...args], {
    env: envFor(home),
    encoding: 'utf-8',
    timeout: 20_000,
  });
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

/** Start the CLI and resolve once `marker` is on its stdout. */
function startUntil(args: string[], home: string, marker: string): Promise<ChildProcess> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      env: envFor(home),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (child.pid) pids.push(child.pid);
    let out = '';
    let err = '';
    let done = false;
    const fail = (why: string) => {
      if (done) return;
      done = true;
      reject(new Error(`${why}\n--- stdout ---\n${out}\n--- stderr ---\n${err}`));
    };
    const timer = setTimeout(() => fail(`no "${marker}" within 20 s`), 20_000);
    child.stdout!.on('data', (chunk) => {
      out += chunk;
      if (!done && out.includes(marker)) {
        done = true;
        clearTimeout(timer);
        resolve(child);
      }
    });
    child.stderr!.on('data', (chunk) => { err += chunk; });
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      fail(`exited before printing "${marker}" (code ${code}, signal ${signal})`);
    });
  });
}

/** Resolves with the exit code once the child exits, or 'running' after `ms`. */
function exitWithin(child: ChildProcess, ms: number): Promise<number | null | 'running'> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(child.exitCode);
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve('running'), ms);
    child.once('exit', (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
}

describe('broker start', () => {
  itIfBuilt('keeps the broker running after reporting it running, until SIGTERM', async () => {
    const home = tempHome();
    const port = await freePort();
    const child = await startUntil(['broker', 'start', '--port', String(port)], home, 'Press Ctrl+C to stop.');

    expect(await exitWithin(child, 1_000)).toBe('running');

    const status = runCli(['broker', 'status'], home);
    expect(status.stdout).toContain('Status:       running');
    expect(status.stdout).toContain(`PID:          ${child.pid}`);
    expect(status.stdout).toContain(`HTTP port:    ${port}`);

    child.kill('SIGTERM');
    expect(await exitWithin(child, 10_000)).toBe(0);
    expect(fs.existsSync(path.join(home, '.secretless-ai', 'broker.pid'))).toBe(false);
    expect(runCli(['broker', 'status'], home).stdout).toContain('Broker daemon is not running.');
  }, TEST_TIMEOUT_MS);
});

describe('spawnDaemon', () => {
  itIfBuilt('leaves the broker running after the process that started it exits', async () => {
    const home = tempHome();
    const port = await freePort();
    const script = [
      `require(${JSON.stringify(DAEMON_PATH)}).spawnDaemon({ httpPort: ${port} }).then(`,
      '  (s) => { process.stdout.write(JSON.stringify({ pid: s.pid })); },',
      '  (e) => { process.stderr.write(String(e && e.message)); process.exit(1); });',
    ].join('\n');
    const starter = spawnSync(process.execPath, ['-e', script], {
      env: envFor(home),
      encoding: 'utf-8',
      timeout: 20_000,
    });
    expect(starter.status, starter.stderr).toBe(0);
    const { pid } = JSON.parse(starter.stdout) as { pid: number };
    pids.push(pid);

    expect(() => process.kill(pid, 0)).not.toThrow();
    const status = runCli(['broker', 'status'], home);
    expect(status.stdout).toContain('Status:       running');
    expect(status.stdout).toContain(`PID:          ${pid}`);

    expect(runCli(['broker', 'stop'], home).stdout).toContain('Broker daemon stopped.');
  }, TEST_TIMEOUT_MS);
});

describe('watch start', () => {
  itIfBuilt('keeps the watcher running after reporting it running, until SIGTERM', async () => {
    const home = tempHome();
    fs.mkdirSync(path.join(home, '.claude', 'projects'), { recursive: true });
    const child = await startUntil(['watch', 'start'], home, 'Press Ctrl+C to stop.');

    expect(await exitWithin(child, 1_000)).toBe('running');
    expect(runCli(['watch', 'status'], home).stdout).toContain('Watcher: running');

    child.kill('SIGTERM');
    expect(await exitWithin(child, 10_000)).toBe(0);
    expect(fs.existsSync(path.join(home, '.secretless-ai', 'watch.pid'))).toBe(false);
  }, TEST_TIMEOUT_MS);

  itIfBuilt('says the watcher did not start, and exits 1, when there is nothing to watch', () => {
    const home = tempHome();
    const res = runCli(['watch', 'start'], home);
    expect(res.status).toBe(1);
    expect(res.stdout).not.toContain('Press Ctrl+C to stop.');
    expect(res.stderr).toContain('Transcript directory not found');
    expect(res.stderr).toContain('Watcher did not start');
  }, TEST_TIMEOUT_MS);
});
