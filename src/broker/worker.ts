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
  /**
   * Whether this caller delivers the operation salt to the resource with the request. The broker
   * commits to an operation only when the caller declares that it does: with any other caller it
   * draws no salt and the record carries no operation commitment, because nobody would hold the
   * salt that opens it.
   */
  readonly deliversSalt?: boolean;
  /**
   * `salt`, when given, is the 32-byte salt the broker's record commits to with this operation.
   * The caller delivers it to the resource with the request, and the resource keeps it beside the
   * operation in its own record. It never goes inside `op`, a token, a URL or a query parameter,
   * and the resource never returns it.
   */
  call(
    audience: string,
    op: AgentOperation,
    cred: ScopedCredential,
    salt?: Uint8Array,
  ): Promise<OperationResult>;
}

export class EphemeralWorker {
  constructor(private readonly caller: DownstreamCaller) {}

  /** Whether this worker's caller delivers operation salts to the resource (see DownstreamCaller). */
  get deliversSalt(): boolean {
    return this.caller.deliversSalt === true;
  }

  /**
   * Run the operation with the scoped credential and return ONLY the result.
   * `cred` is intentionally not returned, not stored on the instance, and not logged.
   * `salt`, when given, goes to the caller with the operation and nowhere else.
   */
  async run(
    binding: ResourceBinding,
    cred: ScopedCredential,
    op: AgentOperation,
    salt?: Uint8Array,
  ): Promise<OperationResult> {
    // Origin-pin before the scoped credential is handed to ANY caller implementation: a
    // crafted `op.path` must not be able to repoint the request host and exfiltrate the
    // token. Enforced here (not only in HttpsDownstreamCaller) so every DownstreamCaller —
    // including proxies and test doubles — inherits the guard. Throws ⇒ caller never runs,
    // and the salt goes nowhere.
    resolveDownstreamUrl(binding.audience, op.path);
    return this.caller.call(binding.audience, op, cred, salt);
  }
}

/**
 * Resolve an agent-supplied operation path against the operator-configured audience,
 * pinning the resulting request to the audience's origin.
 *
 * The agent controls `op.path`; the broker controls `audience`. Naive concatenation
 * (`audience + op.path`) lets a crafted path (`"@evil.com/x"`, `"//evil.com/x"`, or a full
 * `"https://evil.com"`) repoint the host — which would send the scoped bearer token to an
 * attacker-controlled origin, defeating the AAP §4 credential-confinement invariant. We
 * therefore (1) require an absolute, non-protocol-relative path, (2) resolve it against the
 * audience origin, and (3) assert the resolved origin still equals the audience origin.
 */
export function resolveDownstreamUrl(audience: string, path: string): URL {
  const audienceUrl = new URL(audience);
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new Error('operation path must be an absolute, non-protocol-relative path');
  }
  const url = new URL(path, audienceUrl.origin);
  if (url.origin !== audienceUrl.origin) {
    throw new Error('operation path must not change the downstream origin');
  }
  return url;
}

/** Default HTTPS downstream caller. Adds the scoped token as a bearer credential. */
export class HttpsDownstreamCaller implements DownstreamCaller {
  /**
   * No wire carrier for the salt is named yet, so this caller delivers none, and the broker
   * commits to no operation it forwards through it.
   */
  readonly deliversSalt = false;

  call(audience: string, op: AgentOperation, cred: ScopedCredential): Promise<OperationResult> {
    return new Promise((resolve, reject) => {
      let url: URL;
      try {
        url = resolveDownstreamUrl(audience, op.path);
      } catch (err) {
        reject(err);
        return;
      }
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
