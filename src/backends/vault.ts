/**
 * HashiCorp Vault secret backend.
 *
 * Implements WritableSecretBackend using the Vault KV v2 HTTP API.
 * Zero SDK dependency -- raw fetch calls to the Vault server.
 *
 * Auth: VAULT_ADDR + VAULT_TOKEN from environment (standard Vault pattern).
 * Engine: KV v2 (most common) -- secrets at /v1/{mount}/data/{key}.
 */

import * as crypto from 'crypto';
import type { WritableSecretBackend, BackendHealth, ResolveOptions, StoreScopeLine } from './types';
import { boundedFetch, describeRequest, type BoundedResponse } from './bounded-fetch';

const DEFAULT_MOUNT_PATH = 'secret';
const REQUEST_TIMEOUT_MS = 10_000;
const HEALTH_TIMEOUT_MS = 5_000;
const DEFAULT_PORTS: Record<string, string> = { 'http:': '80', 'https:': '443' };

/**
 * A server address as the value cache's scope names it: scheme, host and
 * port, then the path with no trailing slash, so `https://vault.example.com/`
 * and `https://VAULT.example.com:443` name one server. Userinfo is left out:
 * fetch refuses a URL that carries it, so no read is made with it.
 */
function normalizedVaultAddr(addr: string): string {
  let url: URL;
  try {
    url = new URL(addr);
  } catch {
    return addr.replace(/\/+$/, '');
  }
  const port = url.port || DEFAULT_PORTS[url.protocol] || '';
  return `${url.protocol}//${url.hostname}:${port}${url.pathname.replace(/\/+$/, '')}`;
}

/**
 * Where to point a user whose Vault did not answer. The origin only: an
 * address may carry userinfo, which is not ours to reprint.
 */
function vaultOrigin(addr: string): string {
  try {
    return new URL(addr).origin;
  } catch {
    return '$VAULT_ADDR';
  }
}

/** A Vault request that did not complete in time. Holds no token and no body. */
function vaultTimeoutError(addr: string, method: string, url: string, timeoutMs: number): Error {
  const origin = vaultOrigin(addr);
  return new Error(
    [
      `Vault did not respond within ${timeoutMs / 1000}s (${describeRequest(method, url)}).`,
      '',
      '  The request was abandoned and its connection closed. A write that timed',
      '  out may still have been applied by the server.',
      '',
      `  Verify:  curl -s ${origin}/v1/sys/health`,
      `  Fix:     check that ${origin} is reachable from this machine, or set`,
      '           VAULT_ADDR to the Vault server, and retry',
    ].join('\n'),
  );
}

export interface VaultBackendConfig {
  /** Vault server address (overrides VAULT_ADDR env var). */
  addr?: string;
  /** Vault token (overrides VAULT_TOKEN env var). */
  token?: string;
  /** KV v2 mount path. Default: "secret". */
  mountPath?: string;
}

export class VaultBackend implements WritableSecretBackend {
  readonly name = 'vault';

  private addr: string;
  private token: string;
  private mountPath: string;

  constructor(config?: VaultBackendConfig | Record<string, unknown>) {
    const c = (config ?? {}) as VaultBackendConfig;
    this.addr = (c.addr ?? process.env.VAULT_ADDR ?? '').replace(/\/$/, '');
    this.token = c.token ?? process.env.VAULT_TOKEN ?? '';
    this.mountPath = c.mountPath ?? DEFAULT_MOUNT_PATH;
  }

  /**
   * The server, namespace and mount this backend reads, and the token it
   * reads with as its SHA-256, for the value cache's scope (cacheScope).
   */
  describeStore(): StoreScopeLine[] {
    return [
      ['addr', normalizedVaultAddr(this.addr)],
      ['namespace', process.env.VAULT_NAMESPACE ?? ''],
      ['mount', this.mountPath],
      ['token-sha256', crypto.createHash('sha256').update(this.token, 'utf-8').digest('hex')],
    ];
  }

  /**
   * Resolve secrets from Vault.
   *
   * Matches the LocalBackend contract:
   * - resolve("secret/KEY") returns { "secret/KEY": "value" }
   * - resolve("secret") returns all keys under the "secret/" prefix
   * - resolve("secret/KEY", { exact: true }) reads that one entry: a 404
   *   returns {} and no LIST is sent
   */
  async resolve(path: string, options?: ResolveOptions): Promise<Record<string, string>> {
    this.ensureConfigured();

    // Try direct read first
    const readUrl = this.kvUrl('data', path);
    const readResponse = await this.request('GET', readUrl);

    if (readResponse.ok) {
      const body = await readResponse.json() as {
        data?: { data?: Record<string, string> };
      };
      const value = body.data?.data?.value;
      if (value !== undefined) {
        return { [path]: value };
      }
      return {};
    }

    if (readResponse.status === 403) {
      throw new Error(`Vault: permission denied reading "${path}"`);
    }

    if (readResponse.status === 404) {
      // An exact read asked for this one entry, and the 404 is its answer.
      // Listing the path as a prefix made a read of one name that is not
      // stored depend on the list capability, and a token without it got
      // `permission denied listing` where the name was simply absent (#375).
      if (options?.exact) return {};

      // 404 on direct read -- try listing keys under this prefix
      return this.listPrefix(path);
    }

    throw new Error(`Vault: read failed (HTTP ${readResponse.status})`);
  }

  /**
   * List all keys under a prefix and read each one.
   * Uses the KV v2 metadata LIST endpoint.
   */
  private async listPrefix(prefix: string): Promise<Record<string, string>> {
    const listUrl = this.kvUrl('metadata', prefix);
    const listResponse = await this.request('LIST', listUrl);

    if (listResponse.status === 404) {
      return {};
    }

    // Only a 404 means nothing is stored under the prefix. A refused LIST
    // answered as an empty store made `migrate --from vault` report that
    // there was nothing to migrate and exit 0, while a refused GET on the
    // same path throws (#372).
    if (listResponse.status === 403) {
      throw new Error(`Vault: permission denied listing "${prefix}"`);
    }

    if (!listResponse.ok) {
      throw new Error(`Vault: list failed (HTTP ${listResponse.status})`);
    }

    const listBody = await listResponse.json() as {
      data?: { keys?: string[] };
    };

    const keys = listBody.data?.keys ?? [];
    const results: Record<string, string> = {};

    for (const key of keys) {
      // Skip subdirectories (trailing /)
      if (key.endsWith('/')) continue;

      const fullPath = `${prefix}/${key}`;
      const readUrl = this.kvUrl('data', fullPath);
      const readResponse = await this.request('GET', readUrl);

      if (readResponse.ok) {
        const body = await readResponse.json() as {
          data?: { data?: Record<string, string> };
        };
        const value = body.data?.data?.value;
        if (value !== undefined) {
          results[fullPath] = value;
        }
      }
    }

    return results;
  }

  async store(key: string, value: string): Promise<void> {
    await this.storeVersion(key, value);
  }

  /**
   * Write `value` at `key` and return the KV v2 version the write created, or
   * 0 when the server's answer names none. The response is read for its
   * version number only.
   */
  async storeVersion(key: string, value: string): Promise<number> {
    this.ensureConfigured();

    const url = this.kvUrl('data', key);
    const response = await this.request('POST', url, {
      data: { value },
    });

    if (response.status === 403) {
      throw new Error(`Vault: permission denied writing "${key}"`);
    }

    if (!response.ok) {
      throw new Error(`Vault: write failed (HTTP ${response.status})`);
    }

    const body = await response.json().catch(() => undefined) as
      { data?: { version?: unknown } } | undefined;
    const version = body?.data?.version;
    return typeof version === 'number' ? version : 0;
  }

  /**
   * Whether `key` holds any version, from its KV v2 metadata. Never reads a
   * value: the metadata path answers with version numbers and timestamps.
   */
  async hasEntry(key: string): Promise<boolean> {
    this.ensureConfigured();

    const url = this.kvUrl('metadata', key);
    const response = await this.request('GET', url);

    if (response.status === 404) return false;
    if (response.status === 403) {
      throw new Error(`Vault: permission denied reading the metadata of "${key}"`);
    }
    if (!response.ok) {
      throw new Error(`Vault: metadata read failed (HTTP ${response.status})`);
    }
    return true;
  }

  /** The settings a request needs that are not set, by variable name. */
  missingSettings(): string[] {
    const missing: string[] = [];
    if (!this.addr) missing.push('VAULT_ADDR');
    if (!this.token) missing.push('VAULT_TOKEN');
    return missing;
  }

  /** The server's origin, for output. Empty when VAULT_ADDR is not set. */
  get origin(): string {
    return this.addr ? vaultOrigin(this.addr) : '';
  }

  /** The KV v2 mount path. */
  get kvMount(): string {
    return this.mountPath;
  }

  async delete(key: string): Promise<boolean> {
    this.ensureConfigured();

    const url = this.kvUrl('data', key);
    const response = await this.request('DELETE', url);

    if (response.status === 404) {
      return false;
    }

    if (response.status === 403) {
      throw new Error(`Vault: permission denied deleting "${key}"`);
    }

    if (response.status === 204 || response.ok) {
      return true;
    }

    throw new Error(`Vault: delete failed (HTTP ${response.status})`);
  }

  async healthCheck(): Promise<BackendHealth> {
    if (!this.addr) {
      return { healthy: false, latencyMs: 0, message: 'VAULT_ADDR not configured' };
    }

    const start = Date.now();

    try {
      const url = `${this.addr}/v1/sys/health`;
      const origin = vaultOrigin(this.addr);
      const response = await boundedFetch(url, {
        method: 'GET',
        headers: { 'User-Agent': 'secretless-ai/1.0' },
      }, {
        timeoutMs: HEALTH_TIMEOUT_MS,
        onTimeout: () => new Error(
          `Vault did not respond within ${HEALTH_TIMEOUT_MS / 1000}s. Verify: curl -s ${origin}/v1/sys/health`,
        ),
      });

      const latencyMs = Date.now() - start;

      // Vault health endpoint status codes:
      // 200 = initialized, unsealed, active
      // 429 = unsealed, standby
      // 472 = data recovery replication secondary
      // 473 = performance standby
      // 501 = not initialized
      // 503 = sealed
      if (response.status === 200) {
        return { healthy: true, latencyMs, message: 'Vault is healthy' };
      }

      if (response.status === 429 || response.status === 472 || response.status === 473) {
        return { healthy: true, latencyMs, message: `Vault is healthy (standby, HTTP ${response.status})` };
      }

      if (response.status === 503) {
        return { healthy: false, latencyMs, message: 'Vault is sealed' };
      }

      if (response.status === 501) {
        return { healthy: false, latencyMs, message: 'Vault is not initialized' };
      }

      return { healthy: false, latencyMs, message: `Vault health check returned HTTP ${response.status}` };
    } catch (err) {
      return {
        healthy: false,
        latencyMs: Date.now() - start,
        message: err instanceof Error ? err.message : 'Connection failed',
      };
    }
  }

  private ensureConfigured(): void {
    if (!this.addr) {
      throw new Error('Vault backend not configured: VAULT_ADDR is not set');
    }
    if (!this.token) {
      throw new Error('Vault backend not configured: VAULT_TOKEN is not set');
    }
  }

  /**
   * The request URL for `key` under the KV mount's `data` or `metadata` path.
   * A URL resolves a "." or ".." segment away, and a key holding ".." segments
   * was sent outside the mount with the token:
   * `secret://vault/../../../sys/policies/acl` became
   * `GET /v1/sys/policies/acl` (#384). A key with a "." or ".." segment is
   * refused before its request. Every other segment is percent-encoded, so a
   * "%2e", "\", tab, line feed or carriage return in a key cannot form a dot
   * segment, and a "?" or "#" cannot end the path.
   */
  private kvUrl(section: 'data' | 'metadata', key: string): string {
    const segments = key.split('/');
    if (segments.some((segment) => segment === '.' || segment === '..')) {
      throw new Error(
        `Vault: refused the key ${JSON.stringify(key)}: a "." or ".." segment is resolved away ` +
        `in a request URL and can send the request outside the "${this.mountPath}" KV mount. ` +
        'The request was not sent.',
      );
    }
    const encoded = segments.map((segment) => encodeURIComponent(segment)).join('/');
    return `${this.addr}/v1/${this.mountPath}/${section}/${encoded}`;
  }

  /**
   * One Vault request, bounded end to end: the headers and the body read share
   * one deadline, and a request that misses it throws an error that says what
   * to do.
   */
  private async request(
    method: string,
    url: string,
    body?: unknown,
  ): Promise<BoundedResponse> {
    const headers: Record<string, string> = {
      'X-Vault-Token': this.token,
      'User-Agent': 'secretless-ai/1.0',
    };

    const init: RequestInit = { method, headers };

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }

    return boundedFetch(url, init, {
      timeoutMs: REQUEST_TIMEOUT_MS,
      onTimeout: () => vaultTimeoutError(this.addr, method, url, REQUEST_TIMEOUT_MS),
    });
  }
}
