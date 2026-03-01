/**
 * In-memory sliding window rate limiter.
 *
 * Tracks request timestamps per key (agentId:credentialName) and enforces
 * a maximum number of requests within a sliding window. Thread-safe for
 * single-process Node.js (no external state needed).
 */

/** Default sliding window duration in milliseconds. */
const DEFAULT_WINDOW_MS = 60_000;

/** Maximum entries before automatic cleanup of expired keys. */
const CLEANUP_THRESHOLD = 10_000;

export class RateLimiter {
  private readonly windows: Map<string, number[]> = new Map();
  private readonly windowMs: number;

  constructor(windowMs?: number) {
    this.windowMs = windowMs ?? DEFAULT_WINDOW_MS;
  }

  /**
   * Check whether a request is allowed under the rate limit.
   * If allowed, the request is recorded. If denied, no state changes.
   *
   * @param key - Rate limit key (typically `${agentId}:${credentialName}`)
   * @param maxPerWindow - Maximum requests allowed within the window
   * @returns true if the request is allowed, false if rate-limited
   */
  check(key: string, maxPerWindow: number): boolean {
    const now = Date.now();
    const cutoff = now - this.windowMs;

    let timestamps = this.windows.get(key);
    if (!timestamps) {
      timestamps = [];
      this.windows.set(key, timestamps);
    }

    // Evict expired timestamps
    const firstValid = timestamps.findIndex(t => t > cutoff);
    if (firstValid > 0) {
      timestamps.splice(0, firstValid);
    } else if (firstValid === -1) {
      timestamps.length = 0;
    }

    if (timestamps.length >= maxPerWindow) {
      return false;
    }

    timestamps.push(now);

    // Periodic cleanup to prevent unbounded memory growth
    if (this.windows.size > CLEANUP_THRESHOLD) {
      this.cleanup(now);
    }

    return true;
  }

  /**
   * Get the current request count for a key within the active window.
   */
  getCount(key: string): number {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const timestamps = this.windows.get(key);
    if (!timestamps) return 0;
    return timestamps.filter(t => t > cutoff).length;
  }

  /**
   * Reset rate limit state for a specific key.
   */
  reset(key: string): void {
    this.windows.delete(key);
  }

  /**
   * Clear all rate limit state.
   */
  clear(): void {
    this.windows.clear();
  }

  /** Remove keys with no active timestamps. */
  private cleanup(now: number): void {
    const cutoff = now - this.windowMs;
    for (const [key, timestamps] of this.windows) {
      const active = timestamps.filter(t => t > cutoff);
      if (active.length === 0) {
        this.windows.delete(key);
      } else {
        this.windows.set(key, active);
      }
    }
  }
}
