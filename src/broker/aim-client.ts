/**
 * AIM integration client — verifies agent identity via AIM REST API.
 *
 * Checks agent capabilities, trust scores, and verification status against
 * the AIM server. Results are cached for 60 seconds to reduce API calls.
 * Fails gracefully if AIM is unavailable (returns undefined, not errors).
 */

import * as http from 'http';
import * as https from 'https';
import type { AgentIdentity } from './types';

/** Cache entry with TTL tracking. */
interface CacheEntry {
  identity: AgentIdentity;
  expiresAt: number;
}

/** Default cache TTL in milliseconds (60 seconds). */
const DEFAULT_CACHE_TTL_MS = 60_000;

/** Request timeout in milliseconds. */
const REQUEST_TIMEOUT_MS = 5_000;

/** Maximum response body size (1 MB). */
const MAX_RESPONSE_SIZE = 1024 * 1024;

/** Callback invoked when AIM returns a 4xx response. */
export type AimErrorHandler = (info: { url: string; status: number }) => void;

export interface AimClientOptions {
  cacheTtlMs?: number;
  /** Bearer token sent as `Authorization: Bearer <token>` on every request. */
  authToken?: string;
  /** Called when AIM returns a 4xx response (e.g. 401, 403). For audit logging. */
  onAuthError?: AimErrorHandler;
}

export class AimClient {
  private readonly baseUrl: string;
  private readonly cache: Map<string, CacheEntry> = new Map();
  private readonly cacheTtlMs: number;
  private readonly authToken: string | undefined;
  private readonly onAuthError: AimErrorHandler | undefined;

  constructor(baseUrl: string, options?: AimClientOptions) {
    // Remove trailing slash
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.cacheTtlMs = options?.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.authToken = options?.authToken;
    this.onAuthError = options?.onAuthError;
  }

  /**
   * Fetch agent identity from AIM.
   * Returns cached result if available and not expired.
   * Returns undefined if AIM is unreachable or the agent is not found.
   */
  async getAgentIdentity(agentId: string): Promise<AgentIdentity | undefined> {
    // Check cache first
    const cached = this.cache.get(agentId);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.identity;
    }

    // Evict expired entry
    if (cached) {
      this.cache.delete(agentId);
    }

    try {
      const url = `${this.baseUrl}/api/v1/agents/${encodeURIComponent(agentId)}`;
      const response = await this.httpGet(url);

      if (!response) return undefined;

      const identity = parseAgentResponse(response);
      if (!identity) return undefined;

      // Cache the result
      this.cache.set(agentId, {
        identity,
        expiresAt: Date.now() + this.cacheTtlMs,
      });

      return identity;
    } catch {
      // AIM unavailable — fail gracefully
      return undefined;
    }
  }

  /**
   * Check if the AIM server is reachable.
   */
  async isAvailable(): Promise<boolean> {
    try {
      const url = `${this.baseUrl}/health`;
      const response = await this.httpGet(url);
      return response !== undefined;
    } catch {
      return false;
    }
  }

  /**
   * Clear the identity cache.
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Evict a specific agent from the cache.
   */
  evict(agentId: string): void {
    this.cache.delete(agentId);
  }

  /** Get the number of cached entries (for testing/status). */
  get cacheSize(): number {
    return this.cache.size;
  }

  /**
   * HTTP GET returning parsed JSON body, or undefined on error.
   *
   * Sends `Authorization: Bearer <token>` when `authToken` is configured.
   * 4xx responses invoke `onAuthError` so the broker can audit auth failures
   * rather than silently dropping them.
   */
  private httpGet(url: string): Promise<Record<string, unknown> | undefined> {
    return new Promise((resolve) => {
      const parsedUrl = new URL(url);
      const transport = parsedUrl.protocol === 'https:' ? https : http;

      const headers: Record<string, string> = {};
      if (this.authToken) {
        headers['Authorization'] = `Bearer ${this.authToken}`;
      }

      const req = transport.request(
        {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          method: 'GET',
          headers,
          timeout: REQUEST_TIMEOUT_MS,
        },
        (res) => {
          const status = res.statusCode ?? 0;

          if (status >= 400 && status < 500) {
            res.resume();
            try { this.onAuthError?.({ url, status }); } catch { /* swallow */ }
            resolve(undefined);
            return;
          }

          if (status < 200 || status >= 300) {
            res.resume();
            resolve(undefined);
            return;
          }

          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_RESPONSE_SIZE) {
              res.destroy();
              resolve(undefined);
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            try {
              const body = Buffer.concat(chunks).toString('utf-8');
              resolve(JSON.parse(body));
            } catch {
              resolve(undefined);
            }
          });
        },
      );

      req.on('error', () => resolve(undefined));
      req.on('timeout', () => {
        req.destroy();
        resolve(undefined);
      });
      req.end();
    });
  }
}

/** Parse an AIM API agent response into an AgentIdentity. */
function parseAgentResponse(data: Record<string, unknown>): AgentIdentity | undefined {
  const agentId = typeof data.agentId === 'string' ? data.agentId : undefined;
  if (!agentId) return undefined;

  const trustScore = typeof data.trustScore === 'number' ? data.trustScore : 0;
  const capabilities = Array.isArray(data.capabilities)
    ? data.capabilities.filter((c): c is string => typeof c === 'string')
    : [];
  const verified = typeof data.verified === 'boolean' ? data.verified : false;

  return { agentId, trustScore, capabilities, verified };
}
