import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { RateLimiter } from './rate-limiter';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    limiter = new RateLimiter(60_000);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('allows requests under the limit', () => {
    expect(limiter.check('agent:cred', 5)).toBe(true);
    expect(limiter.check('agent:cred', 5)).toBe(true);
    expect(limiter.check('agent:cred', 5)).toBe(true);
  });

  it('denies requests at the limit', () => {
    for (let i = 0; i < 3; i++) {
      expect(limiter.check('agent:cred', 3)).toBe(true);
    }
    expect(limiter.check('agent:cred', 3)).toBe(false);
  });

  it('tracks keys independently', () => {
    for (let i = 0; i < 3; i++) {
      limiter.check('agent-a:cred', 3);
    }
    expect(limiter.check('agent-a:cred', 3)).toBe(false);
    expect(limiter.check('agent-b:cred', 3)).toBe(true);
  });

  it('allows requests after window expires', () => {
    const now = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(now);

    for (let i = 0; i < 3; i++) {
      expect(limiter.check('agent:cred', 3)).toBe(true);
    }
    expect(limiter.check('agent:cred', 3)).toBe(false);

    // Advance past the window
    vi.spyOn(Date, 'now').mockReturnValue(now + 61_000);
    expect(limiter.check('agent:cred', 3)).toBe(true);
  });

  it('reports correct count', () => {
    expect(limiter.getCount('agent:cred')).toBe(0);
    limiter.check('agent:cred', 10);
    limiter.check('agent:cred', 10);
    expect(limiter.getCount('agent:cred')).toBe(2);
  });

  it('reports zero count for unknown key', () => {
    expect(limiter.getCount('nonexistent')).toBe(0);
  });

  it('resets a specific key', () => {
    limiter.check('agent:cred', 10);
    limiter.check('agent:cred', 10);
    expect(limiter.getCount('agent:cred')).toBe(2);

    limiter.reset('agent:cred');
    expect(limiter.getCount('agent:cred')).toBe(0);
  });

  it('clears all keys', () => {
    limiter.check('a:1', 10);
    limiter.check('b:2', 10);
    limiter.clear();
    expect(limiter.getCount('a:1')).toBe(0);
    expect(limiter.getCount('b:2')).toBe(0);
  });

  it('uses default 60s window when no argument provided', () => {
    const defaultLimiter = new RateLimiter();
    const now = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(now);

    defaultLimiter.check('k', 1);
    expect(defaultLimiter.check('k', 1)).toBe(false);

    // At 59s still blocked
    vi.spyOn(Date, 'now').mockReturnValue(now + 59_000);
    expect(defaultLimiter.check('k', 1)).toBe(false);

    // At 61s allowed
    vi.spyOn(Date, 'now').mockReturnValue(now + 61_000);
    expect(defaultLimiter.check('k', 1)).toBe(true);
  });

  it('does not record denied requests', () => {
    for (let i = 0; i < 3; i++) {
      limiter.check('agent:cred', 3);
    }
    // Denied — should not increment
    limiter.check('agent:cred', 3);
    limiter.check('agent:cred', 3);
    expect(limiter.getCount('agent:cred')).toBe(3);
  });
});
