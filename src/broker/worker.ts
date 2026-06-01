/**
 * Ephemeral worker — AAP §6.5. Where the scoped credential is used.
 *
 * The scoped downstream token MUST be confined here, isolated from the agent process and
 * its context. The token MAY exist briefly in the worker; it MUST NOT enter the agent
 * process or the agent context. Only the *result* of the operation returns to the agent.
 *
 * The worker takes a logical operation from the agent (method + path + optional query/body
 * — no host, no credential) and the resource binding (which supplies the audience/host) and
 * performs the call with the scoped token. The token is a local — never returned, never
 * logged.
 */

import * as https from 'https';
import * as http from 'http';
import type { ResourceBinding, ScopedCredential } from './cpi/types';

/** A logical operation the agent requested. Carries no host and no credential. */
export interface AgentOperation {
  method: string;
  /** Path relative to the binding audience, e.g. "/orders". */
  path: string;
  query?: Record<string, string>;
  body?: unknown;
}

/** The result of the downstream operation. This — and only this — returns to the agent. */
export interface OperationResult {
  status: number;
  body: unknown;
}

/** Performs the downstream call. Injectable so tests don't hit the network. */
export interface DownstreamCaller {
  call(audience: string, op: AgentOperation, cred: ScopedCredential): Promise<OperationResult>;
}

export class EphemeralWorker {
  constructor(private readonly caller: DownstreamCaller) {}

  /**
   * Run the operation with the scoped credential and return ONLY the result.
   * `cred` is intentionally not returned, not stored on the instance, and not logged.
   */
  async run(
    binding: ResourceBinding,
    cred: ScopedCredential,
    op: AgentOperation,
  ): Promise<OperationResult> {
    return this.caller.call(binding.audience, op, cred);
  }
}

/** Default HTTPS downstream caller. Adds the scoped token as a bearer credential. */
export class HttpsDownstreamCaller implements DownstreamCaller {
  call(audience: string, op: AgentOperation, cred: ScopedCredential): Promise<OperationResult> {
    return new Promise((resolve, reject) => {
      const base = audience.replace(/\/+$/, '');
      const url = new URL(base + op.path);
      for (const [k, v] of Object.entries(op.query ?? {})) url.searchParams.set(k, v);

      const transport = url.protocol === 'http:' ? http : https;
      const payload = op.body === undefined ? undefined : JSON.stringify(op.body);

      const req = transport.request(
        {
          hostname: url.hostname,
          port: url.port || (url.protocol === 'http:' ? 80 : 443),
          path: url.pathname + url.search,
          method: op.method,
          headers: {
            // The scoped token lives only in this header, inside this worker.
            Authorization: `${cred.tokenType} ${cred.token}`,
            Accept: 'application/json',
            ...(payload
              ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
              : {}),
          },
          timeout: 5_000,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf-8');
            let body: unknown = text;
            try {
              body = JSON.parse(text);
            } catch {
              /* leave as text */
            }
            resolve({ status: res.statusCode ?? 0, body });
          });
        },
      );
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('downstream operation timed out'));
      });
      if (payload) req.write(payload);
      req.end();
    });
  }
}
