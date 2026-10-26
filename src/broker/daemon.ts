/**
 * Broker daemon lifecycle — start, stop, status, and signal handling.
 *
 * Manages the broker process as a foreground daemon with PID file tracking.
 * Handles graceful shutdown on SIGTERM/SIGINT and cleans up resources.
 */

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as http from 'http';
import * as path from 'path';
import * as os from 'os';
import type { BrokerConfig, BrokerStatus, BrokerRoutes, PidFileBrokerStatus, ResolveOffReason } from './types';
import { BrokerServer, TOKEN_FILE, createAimClient } from './server';
import { parseJsonRefusingDuplicates } from './strict-json';
import { AuditLogger } from './audit';
import { GrantResolver } from './grant-resolver';
import { EphemeralWorker, HttpsDownstreamCaller } from './worker';
import { loadGrantConfig, type GrantConfig } from './grant-config';

const SECRETLESS_DIR = path.join(os.homedir(), '.secretless-ai');
const DEFAULT_PID_FILE = path.join(SECRETLESS_DIR, 'broker.pid');
const DEFAULT_SOCKET_PATH = path.join(SECRETLESS_DIR, 'broker.sock');
const DEFAULT_HTTP_PORT = 19421;
const DEFAULT_POLICY_FILE = path.join(SECRETLESS_DIR, 'broker-policies.json');
const DEFAULT_AUDIT_LOG = path.join(SECRETLESS_DIR, 'broker-audit.log');
const DEFAULT_GRANT_FILE = path.join(SECRETLESS_DIR, 'broker-grants.json');

/**
 * The longest Unix socket path, in bytes, a start accepts on `platform` under the libuv that
 * Node bundles (`process.versions.uv`), or undefined on a platform with no limit recorded,
 * which is not checked.
 *
 * Linux: 108, the size the unix(7) manual page gives for `sun_path`.
 *
 * macOS: `sun_path` in `sockaddr_un` is 104 bytes, and under a libuv before 1.53.0 a longer
 * path failed with EINVAL (Node 24, and Node 26 before it bundled 1.53.0) or was shortened
 * to 104 bytes (Node 20 and 22). libuv 1.53.0 ("unix: support long path names in pipe.c" in
 * its ChangeLog) sizes the path from `SOCK_MAXADDRLEN` on Darwin, which gives 253 bytes.
 * Measured on Darwin 25.6.0 (macOS 26.6.2) under Node 26.12.0, which bundles libuv 1.53.0:
 * `net.Server.listen` listened on a path of 253 bytes and failed with EINVAL on one of 254
 * (#441). A libuv version that does not parse counts as older.
 */
export function socketPathMaxBytes(
  platform: NodeJS.Platform = process.platform,
  uvVersion: string = process.versions.uv,
): number | undefined {
  switch (platform) {
    case 'linux':
      return 108;
    case 'darwin':
      return atLeastVersion(uvVersion, [1, 53, 0]) ? 253 : 104;
    default:
      return undefined;
  }
}

/**
 * Whether `version` (`1.53.0`, or `1.53.0-dev`) is `min` or later, comparing each dotted
 * component as a number. A missing or non-numeric component counts as 0.
 */
function atLeastVersion(version: string, min: readonly number[]): boolean {
  const parts = version.split('.').map((part) => parseInt(part, 10));
  for (let i = 0; i < min.length; i++) {
    const part = parts[i];
    const n = part === undefined || Number.isNaN(part) ? 0 : part;
    if (n !== min[i]) return n > min[i];
  }
  return true;
}

/** Bytes the default socket path adds to the home directory path. */
const DEFAULT_SOCKET_SUFFIX_BYTES = Buffer.byteLength(
  path.join(path.sep, '.secretless-ai', 'broker.sock'),
);

/**
 * Throw when `socketPath` is longer than the limit `socketPathMaxBytes` gives for `platform`
 * under `uvVersion`, naming the path, its length in bytes and the limit, with a Verify and a
 * Fix line.
 *
 * `startDaemon` calls this first, before it creates the config directory, a PID file or a
 * token.
 */
export function assertSocketPathFits(
  socketPath: string,
  platform: NodeJS.Platform = process.platform,
  uvVersion: string = process.versions.uv,
): void {
  const max = socketPathMaxBytes(platform, uvVersion);
  if (max === undefined) return;
  const bytes = Buffer.byteLength(socketPath);
  if (bytes <= max) return;

  const fix = socketPath === DEFAULT_SOCKET_PATH
    ? `HOME=<directory> secretless-ai broker start   (a directory whose path is at most ` +
      `${max - DEFAULT_SOCKET_SUFFIX_BYTES} bytes; the broker then keeps its files in ` +
      `<directory>/.secretless-ai)`
    : `start the broker on a socket path of at most ${max} bytes`;
  // Single-quoted, with `'\''` for a quote in the path, so the shell the line is pasted into
  // counts the path's own bytes and expands nothing in it.
  const quoted = `'${socketPath.replace(/'/g, `'\\''`)}'`;
  throw new Error(
    `Broker socket path ${socketPath} is ${bytes} bytes long, and a Unix socket path on this ` +
    `platform can be at most ${max} bytes. The broker was not started.\n` +
    `  Verify: printf %s ${quoted} | wc -c\n` +
    `  Fix:    ${fix}`,
  );
}

export interface DaemonOptions {
  /** Override socket path. */
  socketPath?: string;
  /** Override HTTP port. */
  httpPort?: number;
  /** AIM server URL. */
  aimUrl?: string;
  /** AIM bearer token. Falls back to SECRETLESS_AIM_TOKEN env var if unset. */
  aimToken?: string;
  /**
   * Policy file path. A broker that loads one answers `POST /resolve`. A path named here must
   * exist. Left unset, ~/.secretless-ai/broker-policies.json is loaded when it exists, and
   * `/resolve` answers 404 when it does not.
   */
  policyFile?: string;
  /**
   * Serve no `POST /resolve`, whatever policy file exists: the broker is built with
   * `resolver: null` and reads no policy file. Refused together with `policyFile`.
   */
  noResolve?: boolean;
  /**
   * Grant file path. A broker that loads one answers `POST /grant`. A path named here must
   * exist. Left unset, ~/.secretless-ai/broker-grants.json is loaded when it exists, and
   * `/grant` answers 404 when it does not.
   */
  grantFile?: string;
  /** Audit log path. */
  auditLog?: string;
  /** PID file path. */
  pidFile?: string;
  /**
   * Auth token file path. Default: ~/.secretless-ai/broker.token, which `broker status` and
   * `broker stop` read; a broker started on another path is not one they can reach.
   */
  tokenFile?: string;
}

/**
 * Start the broker daemon in the foreground.
 * Writes a PID file and installs signal handlers for graceful shutdown.
 */
export async function startDaemon(options?: DaemonOptions): Promise<BrokerServer> {
  const pidFile = options?.pidFile ?? DEFAULT_PID_FILE;
  const socketPath = options?.socketPath ?? DEFAULT_SOCKET_PATH;

  assertSocketPathFits(socketPath);
  if (options?.noResolve && options.policyFile !== undefined) {
    throw new TypeError(
      'startDaemon with noResolve does not accept policyFile: noResolve keeps POST /resolve off, ' +
      'so the file would not be read. Remove policyFile, or remove noResolve.',
    );
  }

  fs.mkdirSync(SECRETLESS_DIR, { recursive: true, mode: 0o700 });

  // Check for existing daemon
  if (isDaemonRunning(pidFile)) {
    throw new Error('Broker daemon is already running');
  }

  // Clean up stale PID file
  if (fs.existsSync(pidFile)) {
    fs.unlinkSync(pidFile);
  }

  // Decided before the grant file loads, which can create the assertion key: a refused policy
  // file leaves no key behind either.
  const resolve = resolveRoute(options);

  const config: BrokerConfig = {
    socketPath,
    httpPort: options?.httpPort ?? DEFAULT_HTTP_PORT,
    aimUrl: options?.aimUrl,
    aimToken: options?.aimToken ?? process.env.SECRETLESS_AIM_TOKEN ?? undefined,
    ...('policyFile' in resolve ? { policyFile: resolve.policyFile } : {}),
    auditLog: options?.auditLog ?? DEFAULT_AUDIT_LOG,
    tokenFile: options?.tokenFile ?? TOKEN_FILE,
  };

  // Loaded here, before the PID file is written and before a socket or token exists: a grant
  // file this build cannot apply stops the start with nothing left behind, for the reason a
  // refused policy file does (see BrokerServer.start).
  const grants = await loadGrants(options?.grantFile);
  const server = new BrokerServer(config, {
    ...(grants ? grantDependencies(config, grants) : {}),
    ...('off' in resolve ? { resolver: null, resolveOff: resolve.off } : {}),
  });

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
  console.log(`Broker auth token: ${config.tokenFile}`);
  if (grants) {
    console.log(
      `Grant file: ${grants.file} ` +
      `(${countOf(grants.bindingCount, 'binding')}, ${countOf(grants.providerCount, 'provider')})`,
    );
    console.log(
      `Broker assertion public key: ${grants.assertionPublicKeyFile}` +
      (grants.assertionKeyCreated
        ? ' (new key: register it with each identity provider in the grant file)'
        : ''),
    );
  }

  return server;
}

/**
 * The policy file a start loads, which turns `POST /resolve` on: the one named, or the default
 * when it exists. With neither, or with `noResolve`, `/resolve` is off, for the reason returned.
 *
 * A named file that is missing is refused, as a named grant file is: otherwise a typo in the
 * path would start a broker that serves no `/resolve` while the command line names a policy.
 */
function resolveRoute(
  options: DaemonOptions | undefined,
): { policyFile: string } | { off: ResolveOffReason } {
  if (options?.noResolve) return { off: 'disabled' };
  if (options?.policyFile !== undefined) {
    if (!fs.existsSync(options.policyFile)) {
      throw new Error(
        `Policy file ${options.policyFile} does not exist. The broker was not started: a policy ` +
        `file that was named and cannot be read is not the same as none, and starting without it ` +
        `would leave /resolve off while the command line says it is on.`,
      );
    }
    return { policyFile: options.policyFile };
  }
  return fs.existsSync(DEFAULT_POLICY_FILE) ? { policyFile: DEFAULT_POLICY_FILE } : { off: 'noPolicyFile' };
}

/**
 * The grant file a start loads: the one named, or the default when it exists.
 *
 * A named file that is missing is refused by `loadGrantConfig`. A missing default is the
 * ordinary case of a broker that serves no grants, and returns null.
 */
async function loadGrants(grantFile: string | undefined): Promise<GrantConfig | null> {
  if (grantFile !== undefined) return loadGrantConfig(grantFile);
  return fs.existsSync(DEFAULT_GRANT_FILE) ? loadGrantConfig(DEFAULT_GRANT_FILE) : null;
}

/**
 * The dependencies of a broker that serves grants.
 *
 * The audit logger and the AIM client are built here and handed to both the grant resolver
 * and the server, so a grant decision lands in the same log as every other broker event and
 * is checked against the same AIM the `/resolve` path asks.
 */
function grantDependencies(
  config: BrokerConfig,
  grants: GrantConfig,
): NonNullable<ConstructorParameters<typeof BrokerServer>[1]> {
  const audit = new AuditLogger(config.auditLog);
  const aimClient = createAimClient(config, audit);
  const grantResolver = new GrantResolver({
    verifier: grants.verifier,
    policy: grants.policy,
    providers: grants.providers,
    worker: new EphemeralWorker(new HttpsDownstreamCaller()),
    audit,
    aimClient,
  });
  return {
    audit,
    aimClient,
    grantResolver,
    // The members `/status` reports, picked by name: never the private key path, the verifier,
    // the policy or the providers.
    grantSource: {
      file: grants.file,
      bindingCount: grants.bindingCount,
      providerCount: grants.providerCount,
      assertionPublicKeyFile: grants.assertionPublicKeyFile,
      assertionKeyCreated: grants.assertionKeyCreated,
    },
  };
}

function countOf(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

export interface SpawnDaemonOptions {
  /** CLI entry point the broker process runs. Defaults to this package's cli.js. */
  cliPath?: string;
  /** HTTP port passed to `broker start --port`. Defaults to the broker's default. */
  httpPort?: number;
  /** PID file the started broker writes. Defaults to the broker's default. */
  pidFile?: string;
  /** How long to wait for the broker to answer before giving up. */
  timeoutMs?: number;
}

/**
 * Start the broker in a detached process of its own and wait until it answers.
 *
 * `startDaemon` runs the broker inside the calling process, so it lives only as
 * long as that process does. A command that returns once the broker is up
 * (`warm`) needs the broker to outlive it: this starts `broker start` detached
 * and resolves only once that process holds the PID file and answers an
 * authenticated /health request on its port. The token it authenticates with
 * is the one that process wrote, so a 200 cannot come from another listener.
 *
 * Rejects if the process exits first or does not answer within `timeoutMs`;
 * on timeout the process is stopped so nothing half-started is left behind.
 */
export async function spawnDaemon(options?: SpawnDaemonOptions): Promise<PidFileBrokerStatus> {
  const cliPath = options?.cliPath ?? path.join(__dirname, '..', 'cli.js');
  const pidFile = options?.pidFile ?? DEFAULT_PID_FILE;
  const timeoutMs = options?.timeoutMs ?? 10_000;
  const args = [cliPath, 'broker', 'start'];
  if (options?.httpPort !== undefined) args.push('--port', String(options.httpPort));

  const child = spawn(process.execPath, args, { detached: true, stdio: 'ignore' });
  const state: { ended?: string } = {};
  child.once('error', (err) => {
    state.ended = `could not be started: ${err.message}`;
  });
  child.once('exit', (code, signal) => {
    state.ended = `exited before it answered (${signal ? `signal ${signal}` : `exit code ${code}`})`;
  });
  child.unref();

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (state.ended) throw new Error(`Broker process ${state.ended}`);
    const status = getDaemonStatus(pidFile);
    if (status && status.pid === child.pid && (await brokerAnswers(status.httpPort))) {
      return status;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  try {
    if (child.pid) process.kill(child.pid, 'SIGTERM');
  } catch {
    // Already gone
  }
  throw new Error(`Broker process did not answer within ${timeoutMs} ms`);
}

/** True when the broker on `port` accepts the token in the token file. */
function brokerAnswers(port: number): Promise<boolean> {
  const token = readBrokerToken();
  if (!token) return Promise.resolve(false);
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: '/health',
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
      },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      },
    );
    req.setTimeout(500, () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.end();
  });
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
 * those fields matter. `grantServed`, `resolveServed` and `routes` are absent: the PID file
 * does not say which routes the broker serves.
 */
export function getDaemonStatus(pidFile?: string): PidFileBrokerStatus | null {
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
 * `grantServed`, `resolveServed` and `routes` are copied together, and only when the reply
 * carries all three in shape; otherwise the result has none of them. A reply from a broker
 * that predates them (a detached daemon older than this CLI) yields no route table.
 *
 * Returns null if the daemon is not running at all.
 */
export async function getLiveDaemonStatus(
  pidFile?: string,
): Promise<BrokerStatus | PidFileBrokerStatus | null> {
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
            // A repeated member is refused rather than kept last-wins, and the
            // caller falls back to the PID-file status as for any unreadable reply.
            parseJsonRefusingDuplicates(body).then(
              (parsed) => resolve(parsed.ok ? (parsed.value as Partial<BrokerStatus>) : null),
              () => resolve(null),
            );
          });
        },
      );
      req.setTimeout(500, () => { req.destroy(); resolve(null); });
      req.on('error', () => resolve(null));
      req.end();
    });

    if (live && typeof live === 'object') {
      const merged: PidFileBrokerStatus = {
        ...base,
        requestCount: typeof live.requestCount === 'number' ? live.requestCount : base.requestCount,
        aimConfigured: typeof live.aimConfigured === 'boolean' ? live.aimConfigured : base.aimConfigured,
        aimReachable: typeof live.aimReachable === 'boolean' ? live.aimReachable : base.aimReachable,
        policyCount: typeof live.policyCount === 'number' ? live.policyCount : base.policyCount,
      };
      // The three live-only members travel together or not at all, and none is defaulted here:
      // a status without them prints no route rows rather than rows this process invented.
      if (
        typeof live.grantServed === 'boolean' &&
        typeof live.resolveServed === 'boolean' &&
        isBrokerRoutes(live.routes)
      ) {
        return { ...merged, grantServed: live.grantServed, resolveServed: live.resolveServed, routes: live.routes };
      }
      return merged;
    }
  } catch {
    // Network/parse failure — fall through to base status
  }
  return base;
}

/** True when `value` has the shape of `BrokerRoutes`: both routes, each an object with a boolean `served`. */
function isBrokerRoutes(value: unknown): value is BrokerRoutes {
  if (!value || typeof value !== 'object') return false;
  const { grant, resolve } = value as Record<string, unknown>;
  const isRoute = (route: unknown): boolean =>
    !!route && typeof route === 'object' && typeof (route as { served?: unknown }).served === 'boolean';
  return isRoute(grant) && isRoute(resolve);
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
      // startDaemon writes this file with JSON.stringify, so a file it wrote
      // re-serializes to the same text. One that does not was not written by
      // it, and that includes a file repeating a member, which JSON.parse would
      // resolve last-wins into the pid stopDaemon signals. This reader is sync
      // (isDaemonRunning, getDaemonStatus and stopDaemon are), so it cannot load
      // the ESM duplicate-member scanner the async parse sites use.
      if (
        data && typeof data === 'object' && typeof data.pid === 'number' &&
        JSON.stringify(data) === raw
      ) {
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
  DEFAULT_GRANT_FILE,
};
