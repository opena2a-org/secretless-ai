/**
 * Broker HTTP server — mediates credential access via Unix socket and HTTP.
 *
 * Primary transport: Unix domain socket at ~/.secretless-ai/broker.sock
 * Fallback transport: HTTP on 127.0.0.1:19421 (for Docker/non-Unix clients)
 *
 * Routes:
 *   POST /resolve  — Resolve a credential for an agent (policy-gated)
 *   GET  /health   — Health check
 *   GET  /status   — Extended status with metrics
 *
 * Never binds to 0.0.0.0. All traffic is localhost-only.
 */

import * as http from 'http';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as net from 'net';
import * as path from 'path';
import * as os from 'os';
import type { BrokerConfig, ResolveRequest, BrokerHealth, BrokerStatus } from './types';
import { PolicyEngine } from './policy';
import { CredentialResolver } from './resolver';
import { AuditLogger } from './audit';
import { AimClient } from './aim-client';
import type { GrantResolver, GrantResolveInput } from './grant-resolver';

/** Default path to the broker authentication token file. */
export const TOKEN_FILE = path.join(os.homedir(), '.secretless-ai', 'broker.token');

/** Maximum request body size (64 KB — credential names should be tiny). */
const MAX_BODY_SIZE = 64 * 1024;

export class BrokerServer {
  private readonly config: BrokerConfig;
  private readonly policy: PolicyEngine;
  private readonly resolver: CredentialResolver;
  private readonly audit: AuditLogger;
  private readonly aimClient: AimClient | null;
  /** AAP grant resolver (Exchange mode). Null when AAP authorization is not configured. */
  private readonly grantResolver: GrantResolver | null;

  private socketServer: http.Server | null = null;
  private httpServer: http.Server | null = null;
  private startedAt: Date | null = null;
  private requestCount = 0;
  private authToken: Buffer | null = null;
  private aimReachable = false;

  constructor(
    config: BrokerConfig,
    deps?: {
      policy?: PolicyEngine;
      resolver?: CredentialResolver;
      audit?: AuditLogger;
      aimClient?: AimClient | null;
      grantResolver?: GrantResolver | null;
    },
  ) {
    this.config = config;
    this.policy = deps?.policy ?? new PolicyEngine({ policyFile: config.policyFile });
    this.resolver = deps?.resolver ?? new CredentialResolver();
    this.audit = deps?.audit ?? new AuditLogger(config.auditLog);
    this.grantResolver = deps?.grantResolver ?? null;
    this.aimClient = deps?.aimClient !== undefined ? deps.aimClient : (
      config.aimUrl
        ? new AimClient(config.aimUrl, {
            authToken: config.aimToken,
            onAuthError: ({ url, status }) => {
              this.audit.logEvent(
                'aim_auth_error',
                'broker',
                '',
                '',
                'denied',
                `AIM returned ${status} for ${url}`,
                0,
              );
            },
          })
        : null
    );
  }

  /**
   * Start the broker server on both Unix socket and HTTP port.
   */
  async start(): Promise<void> {
    // Load policies
    try {
      this.policy.loadPolicies();
    } catch {
      // No policies is fine — default deny applies
    }

    // Generate and persist bearer token for caller authentication
    const tokenFile = this.config.tokenFile ?? TOKEN_FILE;
    const tokenHex = crypto.randomBytes(32).toString('hex');
    this.authToken = Buffer.from(tokenHex, 'utf-8');
    const tokenDir = path.dirname(tokenFile);
    fs.mkdirSync(tokenDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(tokenFile, tokenHex, { mode: 0o600 });

    this.startedAt = new Date();

    // Remove stale socket file
    if (fs.existsSync(this.config.socketPath)) {
      // Check if something is actually listening
      const inUse = await this.isSocketInUse(this.config.socketPath);
      if (inUse) {
        throw new Error(`Socket ${this.config.socketPath} is already in use`);
      }
      fs.unlinkSync(this.config.socketPath);
    }

    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
      this.handleRequest(req, res);
    };

    // Start Unix socket server
    this.socketServer = http.createServer(handler);
    await new Promise<void>((resolve, reject) => {
      this.socketServer!.on('error', reject);
      this.socketServer!.listen(this.config.socketPath, () => {
        // Restrict socket permissions
        try { fs.chmodSync(this.config.socketPath, 0o600); } catch { /* ignore */ }
        resolve();
      });
    });

    // Start HTTP server (localhost only)
    this.httpServer = http.createServer(handler);
    await new Promise<void>((resolve, reject) => {
      this.httpServer!.on('error', reject);
      this.httpServer!.listen(this.config.httpPort, '127.0.0.1', () => {
        resolve();
      });
    });

    // One-shot AIM reachability probe. Non-blocking: failures don't prevent startup,
    // but the result is reflected in status so operators know the real state.
    if (this.aimClient) {
      try {
        this.aimReachable = await this.aimClient.isAvailable();
      } catch {
        this.aimReachable = false;
      }
      if (!this.aimReachable) {
        this.audit.logEvent(
          'aim_unreachable',
          'broker',
          '',
          '',
          'denied',
          'AIM configured but did not respond to reachability probe',
          0,
        );
      }
    }

    this.audit.logEvent('startup', 'broker', '', '', 'allowed', 'Broker started', 0);
  }

  /**
   * Stop the broker server gracefully.
   */
  async stop(): Promise<void> {
    this.audit.logEvent('shutdown', 'broker', '', '', 'allowed', 'Broker stopping', 0);

    const closeServer = (server: http.Server | null): Promise<void> => {
      return new Promise((resolve) => {
        if (!server) { resolve(); return; }
        server.close(() => resolve());
        // Force-close after 5 seconds
        setTimeout(() => resolve(), 5000);
      });
    };

    await Promise.all([
      closeServer(this.socketServer),
      closeServer(this.httpServer),
    ]);

    // Clean up socket file
    if (fs.existsSync(this.config.socketPath)) {
      try { fs.unlinkSync(this.config.socketPath); } catch { /* ignore */ }
    }

    // Clean up token file
    try { fs.unlinkSync(this.config.tokenFile ?? TOKEN_FILE); } catch { /* ignore */ }
    this.authToken = null;

    this.socketServer = null;
    this.httpServer = null;
    this.audit.close();
  }

  /** Get the health status. */
  getHealth(): BrokerHealth {
    const uptimeSeconds = this.startedAt
      ? Math.floor((Date.now() - this.startedAt.getTime()) / 1000)
      : 0;

    return {
      healthy: this.socketServer !== null || this.httpServer !== null,
      uptimeSeconds,
      requestCount: this.requestCount,
      aimConfigured: this.aimClient !== null,
      aimReachable: this.aimReachable,
      policyCount: this.policy.ruleCount,
    };
  }

  /** Get extended status. */
  getStatus(): BrokerStatus {
    const health = this.getHealth();
    return {
      ...health,
      pid: process.pid,
      startedAt: this.startedAt?.toISOString() ?? '',
      socketPath: this.config.socketPath,
      httpPort: this.config.httpPort,
    };
  }

  /** Route incoming HTTP requests. */
  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    this.requestCount++;

    // Authenticate caller via bearer token (defense in depth: applies to both HTTP and Unix socket)
    if (!this.verifyAuth(req)) {
      const remoteAddr = req.socket?.remoteAddress ?? 'unknown';
      this.audit.logEvent(
        'auth',
        'unknown',
        '',
        '',
        'denied',
        `Unauthorized access attempt from ${remoteAddr}`,
        0,
      );
      this.sendJson(res, 401, { error: 'Unauthorized' });
      return;
    }

    const url = req.url ?? '/';
    const method = req.method ?? 'GET';

    if (method === 'POST' && url === '/resolve') {
      this.handleResolve(req, res);
      return;
    }

    if (method === 'POST' && url === '/grant') {
      this.handleGrant(req, res);
      return;
    }

    if (method === 'GET' && url === '/health') {
      this.sendJson(res, 200, this.getHealth());
      return;
    }

    if (method === 'GET' && url === '/status') {
      this.sendJson(res, 200, this.getStatus());
      return;
    }

    this.sendJson(res, 404, { error: 'Not found' });
  }

  /**
   * Verify the Authorization header contains the correct bearer token.
   * Uses constant-time comparison to prevent timing attacks.
   */
  private verifyAuth(req: http.IncomingMessage): boolean {
    if (!this.authToken) return false;

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return false;

    const providedToken = Buffer.from(authHeader.slice(7), 'utf-8');
    if (providedToken.length !== this.authToken.length) return false;

    return crypto.timingSafeEqual(providedToken, this.authToken);
  }

  /** Handle POST /resolve — the core credential resolution endpoint. */
  private handleResolve(req: http.IncomingMessage, res: http.ServerResponse): void {
    const startTime = Date.now();

    this.readBody(req).then(async (body) => {
      let request: ResolveRequest;
      try {
        request = parseResolveRequest(body);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Invalid request';
        this.sendJson(res, 400, { error: message });
        return;
      }

      // Fetch agent identity from AIM (if configured)
      const agentIdentity = this.aimClient
        ? await this.aimClient.getAgentIdentity(request.agentId)
        : undefined;

      // Evaluate policy
      const evaluation = this.policy.evaluate(
        request.agentId,
        request.credentialName,
        agentIdentity,
      );

      const latencyMs = Date.now() - startTime;

      if (!evaluation.allowed) {
        this.audit.logEvent(
          'resolve',
          request.agentId,
          request.credentialName,
          evaluation.matchedRuleId,
          'denied',
          evaluation.reason,
          latencyMs,
        );
        this.sendJson(res, 403, { error: 'Access denied', reason: evaluation.reason });
        return;
      }

      // Resolve the credential
      try {
        const value = await this.resolver.resolve(request.credentialName);
        if (value === undefined) {
          this.audit.logEvent(
            'resolve',
            request.agentId,
            request.credentialName,
            evaluation.matchedRuleId,
            'denied',
            'Credential not found',
            Date.now() - startTime,
          );
          this.sendJson(res, 404, { error: 'Credential not found' });
          return;
        }

        this.audit.logEvent(
          'resolve',
          request.agentId,
          request.credentialName,
          evaluation.matchedRuleId,
          'allowed',
          evaluation.reason,
          Date.now() - startTime,
        );

        this.sendJson(res, 200, { value });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Resolution failed';
        this.audit.logEvent(
          'resolve',
          request.agentId,
          request.credentialName,
          evaluation.matchedRuleId,
          'denied',
          `Resolution error: ${message}`,
          Date.now() - startTime,
        );
        this.sendJson(res, 500, { error: 'Internal error' });
      }
    }).catch(() => {
      this.sendJson(res, 400, { error: 'Failed to read request body' });
    });
  }

  /**
   * Handle POST /grant — the AAP §6 resolution endpoint.
   *
   * The agent presents its ATX, a grant reference, and a logical operation. The broker
   * verifies, authorizes, resolves a scoped credential, runs the operation in an ephemeral
   * worker, and returns ONLY the result. Every failure is the same opaque denial (§6.6).
   */
  private handleGrant(req: http.IncomingMessage, res: http.ServerResponse): void {
    if (!this.grantResolver) {
      // AAP authorization not configured on this broker.
      this.sendJson(res, 404, { error: 'Not found' });
      return;
    }

    this.readBody(req).then(async (body) => {
      let input: GrantResolveInput;
      try {
        input = parseGrantResolveInput(body);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Invalid request';
        this.sendJson(res, 400, { error: message });
        return;
      }

      const outcome = await this.grantResolver!.resolve(input);
      if (outcome.ok) {
        // Only the operation result crosses back — never the token or any backend detail.
        this.sendJson(res, 200, { result: outcome.result });
      } else {
        // Uniform opaque denial. Diagnostic detail is in the audit log, not here.
        this.sendJson(res, 403, { error: 'denied' });
      }
    }).catch(() => {
      this.sendJson(res, 400, { error: 'Failed to read request body' });
    });
  }

  /** Read and parse request body with size limit. */
  private readBody(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;

      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY_SIZE) {
          req.destroy();
          reject(new Error('Request body too large'));
          return;
        }
        chunks.push(chunk);
      });

      req.on('end', () => {
        resolve(Buffer.concat(chunks).toString('utf-8'));
      });

      req.on('error', reject);
    });
  }

  /** Send a JSON response with security headers. */
  private sendJson(res: http.ServerResponse, statusCode: number, data: unknown): void {
    const body = JSON.stringify(data);
    res.writeHead(statusCode, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    });
    res.end(body);
  }

  /** Check if a Unix socket is already in use. */
  private isSocketInUse(socketPath: string): Promise<boolean> {
    return new Promise((resolve) => {
      const client = net.createConnection({ path: socketPath }, () => {
        client.end();
        resolve(true);
      });
      client.on('error', () => {
        resolve(false);
      });
    });
  }
}

/** Parse and validate a resolve request body. */
function parseResolveRequest(body: string): ResolveRequest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error('Invalid JSON');
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Request body must be a JSON object');
  }

  const obj = parsed as Record<string, unknown>;

  if (typeof obj.agentId !== 'string' || !obj.agentId) {
    throw new Error('Missing or invalid "agentId"');
  }

  if (typeof obj.credentialName !== 'string' || !obj.credentialName) {
    throw new Error('Missing or invalid "credentialName"');
  }

  return {
    agentId: obj.agentId,
    credentialName: obj.credentialName,
  };
}

/** Parse and validate a grant-resolve request body (AAP §6). */
function parseGrantResolveInput(body: string): GrantResolveInput {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error('Invalid JSON');
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Request body must be a JSON object');
  }
  const obj = parsed as Record<string, unknown>;

  if (typeof obj.agentId !== 'string' || !obj.agentId) {
    throw new Error('Missing or invalid "agentId"');
  }
  if (typeof obj.grant !== 'string' || !obj.grant) {
    throw new Error('Missing or invalid "grant"');
  }
  if (!obj.atx || typeof obj.atx !== 'object') {
    throw new Error('Missing or invalid "atx"');
  }
  if (!obj.operation || typeof obj.operation !== 'object') {
    throw new Error('Missing or invalid "operation"');
  }
  const op = obj.operation as Record<string, unknown>;
  if (typeof op.method !== 'string' || typeof op.path !== 'string') {
    throw new Error('"operation" requires string "method" and "path"');
  }

  return {
    agentId: obj.agentId,
    grant: obj.grant,
    // Validated structurally here; cryptographic verification happens in the resolver.
    atx: obj.atx as GrantResolveInput['atx'],
    operation: obj.operation as GrantResolveInput['operation'],
  };
}
