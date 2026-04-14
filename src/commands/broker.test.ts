import { describe, it, expect } from 'vitest';
import { formatAimStatus } from './broker';

describe('formatAimStatus', () => {
  it('reports "not configured" when aimConfigured is false', () => {
    expect(formatAimStatus(false, false)).toBe('not configured');
    // reachable flag is ignored when not configured
    expect(formatAimStatus(false, true)).toBe('not configured');
  });

  it('reports "configured (reachable)" when AIM responded at startup', () => {
    expect(formatAimStatus(true, true)).toBe('configured (reachable)');
  });

  it('reports "configured (unreachable)" when AIM was set but did not respond', () => {
    expect(formatAimStatus(true, false)).toBe('configured (unreachable)');
  });
});
