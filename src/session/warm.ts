/**
 * Warm command — interactive session warmup for credential access.
 *
 * Intended to be run once before starting an AI coding session.
 * Warms the biometric session so subsequent credential access
 * doesn't trigger repeated Touch ID / 1Password prompts.
 *
 * After biometric auth, pre-loads all secrets from the configured backend
 * (1Password, keychain, etc.) into the AES-256-GCM encrypted file cache.
 * This ensures no backend CLI calls (op, security, etc.) happen during the
 * warm window — all resolve() calls hit the cache instead.
 *
 * Also ensures the broker daemon is running.
 */

import { warmSession, isMacOS, isTouchIDAvailable } from './touchid';
import { getSessionStatus, type SessionStatus } from './session-state';
import { isDaemonRunning, startDaemon, getDaemonStatus } from '../broker/daemon';
import { createBackend } from '../backends/factory';
import { resolveBackendType, readCacheTtl, writeCacheTtl } from '../backends/config';

export interface WarmResult {
  /** Whether the session is now warm. */
  sessionWarm: boolean;
  /** Session status after warming. */
  session: SessionStatus;
  /** Whether the broker daemon is running. */
  brokerRunning: boolean;
  /** Whether the broker was started by this command. */
  brokerStarted: boolean;
  /** Whether Touch ID was used (macOS only). */
  touchIdUsed: boolean;
  /** Number of secrets preloaded into cache. */
  cachePreloaded: number;
  /** Error message if warming failed. */
  error?: string;
}

/**
 * Warm the session: authenticate once, preload cache, start broker if needed.
 *
 * @param ttlSeconds - Session TTL in seconds (default: 300 = 5 minutes)
 * @param startBrokerIfStopped - Whether to start the broker if not running
 */
export async function warm(
  ttlSeconds?: number,
  startBrokerIfStopped = true,
): Promise<WarmResult> {
  const ttl = ttlSeconds ?? 300;

  const result: WarmResult = {
    sessionWarm: false,
    session: getSessionStatus(),
    brokerRunning: false,
    brokerStarted: false,
    touchIdUsed: false,
    cachePreloaded: 0,
  };

  // Check if session is already warm
  const currentStatus = getSessionStatus(ttl);
  if (currentStatus.warm) {
    result.sessionWarm = true;
    result.session = currentStatus;
    result.brokerRunning = isDaemonRunning();
    return result;
  }

  // Warm the biometric session
  try {
    result.touchIdUsed = isMacOS() && isTouchIDAvailable();
    const session = await warmSession(ttl);
    result.session = session;
    result.sessionWarm = session.warm;
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    return result;
  }

  // Pre-load secrets into cache so no backend CLI calls happen during the warm window.
  // This is what actually prevents 1Password popups — all subsequent resolve() calls
  // hit the encrypted file cache instead of calling `op` CLI.
  if (result.sessionWarm) {
    try {
      result.cachePreloaded = await preloadCache(ttl);
    } catch {
      // Preload failure is non-fatal — session is still warm,
      // but individual secret accesses may trigger backend prompts.
    }
  }

  // Start broker if not running
  result.brokerRunning = isDaemonRunning();
  if (!result.brokerRunning && startBrokerIfStopped) {
    try {
      await startDaemon();
      result.brokerRunning = true;
      result.brokerStarted = true;
    } catch {
      // Broker start failure is non-fatal for warm
      // Session is still warm even if broker isn't running
    }
  }

  return result;
}

/**
 * Pre-load all secrets from the configured backend into the encrypted file cache.
 *
 * Creates the configured backend (which may be CachedBackend wrapping 1Password/keychain),
 * resolves all stored secret and MCP prefixes, and writes results to the cache file.
 * This triggers one round of backend CLI calls (op, security) NOW — during warmup when
 * the user expects it — so no calls happen later during the AI coding session.
 *
 * Also syncs the cache TTL with the session TTL so cache entries don't expire
 * before the session does.
 *
 * @param sessionTtlSeconds - Session TTL to sync cache TTL with
 * @returns Number of secrets preloaded into cache
 */
export async function preloadCache(sessionTtlSeconds: number): Promise<number> {
  const backendType = resolveBackendType();

  // Only preload for backends that trigger external CLI prompts.
  // Local backend uses file-based encryption with no OS prompts.
  if (backendType === 'local') {
    return 0;
  }

  // Sync cache TTL with session TTL so entries stay valid for the entire session.
  // This prevents the scenario where cache expires mid-session and triggers a popup.
  const currentCacheTtl = readCacheTtl();
  if (currentCacheTtl < sessionTtlSeconds) {
    writeCacheTtl(sessionTtlSeconds);
  }

  // Create the backend — factory wraps it with CachedBackend automatically.
  // The CachedBackend will call the inner backend (1Password/keychain/vault)
  // on cache miss, then store results in the encrypted file cache.
  const backend = createBackend(backendType);

  let count = 0;

  // Resolve all user secrets (secret/ prefix)
  try {
    const secrets = await backend.resolve('secret');
    count += Object.keys(secrets).length;
  } catch {
    // No user secrets stored — that is fine
  }

  // Resolve all MCP secrets (mcp/ prefix)
  try {
    const mcpSecrets = await backend.resolve('mcp');
    count += Object.keys(mcpSecrets).length;
  } catch {
    // No MCP secrets stored — that is fine
  }

  return count;
}
