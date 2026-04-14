/**
 * Broker daemon lifecycle — start, stop, status, and signal handling.
 *
 * Manages the broker process as a foreground daemon with PID file tracking.
 * Handles graceful shutdown on SIGTERM/SIGINT and cleans up resources.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { BrokerConfig, BrokerStatus } from './types';
import { BrokerServer, TOKEN_FILE } from './server';

const SECRETLESS_DIR = path.join(os.homedir(), '.secretless-ai');
const DEFAULT_PID_FILE = path.join(SECRETLESS_DIR, 'broker.pid');
const DEFAULT_SOCKET_PATH = path.join(SECRETLESS_DIR, 'broker.sock');
const DEFAULT_HTTP_PORT = 19421;
const DEFAULT_POLICY_FILE = path.join(SECRETLESS_DIR, 'broker-policies.json');
const DEFAULT_AUDIT_LOG = path.join(SECRETLESS_DIR, 'broker-audit.log');

export interface DaemonOptions {
  /** Override socket path. */
  socketPath?: string;
  /** Override HTTP port. */
  httpPort?: number;
  /** AIM server URL. */
  aimUrl?: string;
  /** AIM bearer token. Falls back to SECRETLESS_AIM_TOKEN env var if unset. */
  aimToken?: string;
  /** Policy file path. */
  policyFile?: string;
  /** Audit log path. */
  auditLog?: string;
  /** PID file path. */
  pidFile?: string;
}

/**
 * Start the broker daemon in the foreground.
 * Writes a PID file and installs signal handlers for graceful shutdown.
 */
export async function startDaemon(options?: DaemonOptions): Promise<BrokerServer> {
  const pidFile = options?.pidFile ?? DEFAULT_PID_FILE;

  fs.mkdirSync(SECRETLESS_DIR, { recursive: true, mode: 0o700 });

  // Check for existing daemon
  if (isDaemonRunning(pidFile)) {
    throw new Error('Broker daemon is already running');
  }

  // Clean up stale PID file
  if (fs.existsSync(pidFile)) {
    fs.unlinkSync(pidFile);
  }

  const config: BrokerConfig = {
    socketPath: options?.socketPath ?? DEFAULT_SOCKET_PATH,
    httpPort: options?.httpPort ?? DEFAULT_HTTP_PORT,
    aimUrl: options?.aimUrl,
    aimToken: options?.aimToken ?? process.env.SECRETLESS_AIM_TOKEN ?? undefined,
    policyFile: options?.policyFile ?? DEFAULT_POLICY_FILE,
    auditLog: options?.auditLog ?? DEFAULT_AUDIT_LOG,
  };

  const server = new BrokerServer(config);

  // Write PID file before starting (TOCTOU protection via O_EXCL)
  const pidData = JSON.stringify({
    pid: process.pid,
    startedAt: new Date().toISOString(),
    socketPath: config.socketPath,
    httpPort: config.httpPort,
  });

  try {
    const fd = fs.openSync(pidFile, 'wx');
    fs.writeSync(fd, pidData);
    fs.closeSync(fd);
  } catch (err: unknown) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === 'EEXIST') {
      throw new Error('Broker daemon is already running (PID file exists)');
    }
    throw err;
  }

  // Install signal handlers
  const shutdown = async () => {
    try {
      await server.stop();
    } catch {
      // Best-effort cleanup
    }
    cleanupPidFile(pidFile);
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  try {
    await server.start();
  } catch (err) {
    cleanupPidFile(pidFile);
    throw err;
  }

  // Print token file path so callers know where to read the auth token
  console.log(`Broker auth token: ${TOKEN_FILE}`);

  return server;
}

/**
 * Stop a running broker daemon by sending SIGTERM.
 * Returns true if the daemon was stopped, false if it was not running.
 */
export function stopDaemon(pidFile?: string): boolean {
  const file = pidFile ?? DEFAULT_PID_FILE;
  const pidInfo = readPidFile(file);

  if (!pidInfo) return false;

  try {
    process.kill(pidInfo.pid, 'SIGTERM');
    // Wait briefly for cleanup, then remove PID file
    cleanupPidFile(file);
    cleanupTokenFile();
    return true;
  } catch {
    // Process already dead — clean up
    cleanupPidFile(file);
    cleanupTokenFile();
    return false;
  }
}

/** Remove token file (best-effort). */
function cleanupTokenFile(): void {
  try {
    fs.unlinkSync(TOKEN_FILE);
  } catch {
    // Ignore — file may already be gone (server.stop() may have removed it)
  }
}

/**
 * Get the status of the broker daemon from the PID file alone.
 * Returns null if the daemon is not running.
 *
 * Fast and sync, but `requestCount`, `aimConfigured`, `aimReachable`, and `policyCount`
 * are always returned as zero/false because reading those requires
 * an HTTP call to the live server. Use `getLiveDaemonStatus` when
 * those fields matter.
 */
export function getDaemonStatus(pidFile?: string): BrokerStatus | null {
  const file = pidFile ?? DEFAULT_PID_FILE;
  const pidInfo = readPidFile(file);

  if (!pidInfo) return null;

  // Verify the process is actually running
  try {
    process.kill(pidInfo.pid, 0);
  } catch {
    // Process is dead — clean up stale PID file
    cleanupPidFile(file);
    return null;
  }

  const startedAt = pidInfo.startedAt ?? '';
  const uptimeSeconds = startedAt
    ? Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000)
    : 0;

  return {
    healthy: true,
    uptimeSeconds,
    requestCount: 0, // Not available without querying the server
    aimConfigured: false,
    aimReachable: false,
    policyCount: 0,
    pid: pidInfo.pid,
    startedAt,
    socketPath: pidInfo.socketPath ?? DEFAULT_SOCKET_PATH,
    httpPort: pidInfo.httpPort ?? DEFAULT_HTTP_PORT,
  };
}

/**
 * Get the status of the broker daemon with live fields queried from the server.
 *
 * Merges PID-file base info with live data from the server's /status endpoint
 * (requestCount, aimConfigured, aimReachable, policyCount). Falls back to the PID-file-only
 * status if the HTTP call fails, so the CLI always prints something useful.
 *
 * Returns null if the daemon is not running at all.
 */
export async function getLiveDaemonStatus(pidFile?: string): Promise<BrokerStatus | null> {
  const base = getDaemonStatus(pidFile);
  if (!base) return null;

  const token = readBrokerToken();
  if (!token) return base;

  try {
    const http = await import('http');
    const live = await new Promise<Partial<BrokerStatus> | null>((resolve) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: base.httpPort,
          path: '/status',
          method: 'GET',
          headers: { Authorization: `Bearer ${token}` },
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => { body += chunk; });
          res.on('end', () => {
            if (res.statusCode !== 200) return resolve(null);
            try {
              resolve(JSON.parse(body));
            } catch {
              resolve(null);
            }
          });
        },
      );
      req.setTimeout(500, () => { req.destroy(); resolve(null); });
      req.on('error', () => resolve(null));
      req.end();
    });

    if (live && typeof live === 'object') {
      return {
        ...base,
        requestCount: typeof live.requestCount === 'number' ? live.requestCount : base.requestCount,
        aimConfigured: typeof live.aimConfigured === 'boolean' ? live.aimConfigured : base.aimConfigured,
        aimReachable: typeof live.aimReachable === 'boolean' ? live.aimReachable : base.aimReachable,
        policyCount: typeof live.policyCount === 'number' ? live.policyCount : base.policyCount,
      };
    }
  } catch {
    // Network/parse failure — fall through to base status
  }
  return base;
}

/** Read the broker auth token from disk. Returns null if absent. */
function readBrokerToken(): string | null {
  try {
    const token = fs.readFileSync(TOKEN_FILE, 'utf-8').trim();
    return token || null;
  } catch {
    return null;
  }
}

/**
 * Check if a broker daemon is currently running.
 */
export function isDaemonRunning(pidFile?: string): boolean {
  const file = pidFile ?? DEFAULT_PID_FILE;
  const pidInfo = readPidFile(file);
  if (!pidInfo) return false;

  try {
    process.kill(pidInfo.pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Read and parse the PID file. */
function readPidFile(
  filePath: string,
): { pid: number; startedAt?: string; socketPath?: string; httpPort?: number } | null {
  if (!fs.existsSync(filePath)) return null;

  try {
    const raw = fs.readFileSync(filePath, 'utf-8').trim();
    try {
      const data = JSON.parse(raw);
      if (data && typeof data === 'object' && typeof data.pid === 'number') {
        return data;
      }
    } catch {
      // Legacy plain PID format
      const pid = parseInt(raw, 10);
      if (!isNaN(pid) && pid > 0) return { pid };
    }
  } catch {
    // Unreadable PID file
  }
  return null;
}

/** Remove PID file (best-effort). */
function cleanupPidFile(filePath: string): void {
  try {
    fs.unlinkSync(filePath);
  } catch {
    // Ignore — file may already be gone
  }
}

// Export constants for testing
export {
  DEFAULT_PID_FILE,
  DEFAULT_SOCKET_PATH,
  DEFAULT_HTTP_PORT,
  DEFAULT_POLICY_FILE,
  DEFAULT_AUDIT_LOG,
};
