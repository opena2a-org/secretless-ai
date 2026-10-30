import { describe, expect, it } from 'vitest';
import { AUDIT_REASONS, GRANT_AUDIT_REASONS } from './types';

/**
 * Every broker audit record carries a reason from one closed set: the grant codes, unchanged and
 * in their order, then the codes of the broker's other writers.
 */

/** The broker's own codes, in the order the set lists them. */
const BROKER_CODES = [
  'aim-unauthorized',
  'aim-forbidden',
  'aim-not-found',
  'aim-rate-limited',
  'aim-client-error',
  'aim-unreachable',
  'broker-started',
  'broker-stopping',
  'auth-refused-socket',
  'auth-refused-http',
  'scanner-unavailable-resolve',
  'scanner-unavailable-grant',
  'rule-allow',
  'rule-deny',
  'rule-default-deny',
  'rule-outside-time-window',
  'rule-trust-score-no-identity',
  'rule-trust-score-below-minimum',
  'rule-capability-no-identity',
  'rule-capability-missing',
  'rule-rate-limit-exceeded',
  'credential-not-found',
  'backend-error',
  'credential-requested',
  'credential-granted',
  'credential-denied',
  'credential-expired-after-use',
  'credential-expired-unused',
  'credential-revoked',
  'credential-rotated',
  'credential-leak-detected',
];

describe('AUDIT_REASONS', () => {
  it('T1: is the 32 grant codes in their order, then the 31 broker codes', () => {
    expect(GRANT_AUDIT_REASONS).toHaveLength(32);
    expect(BROKER_CODES).toHaveLength(31);
    expect(AUDIT_REASONS).toEqual([...GRANT_AUDIT_REASONS, ...BROKER_CODES]);
    expect(AUDIT_REASONS).toHaveLength(63);
  });

  it('T1: every code is lowercase words joined by hyphens', () => {
    expect(AUDIT_REASONS.filter((code) => !/^[a-z]+(-[a-z]+)*$/.test(code))).toEqual([]);
  });

  it('T1: lists each code once, and shares none between the grant and broker codes', () => {
    expect(new Set(AUDIT_REASONS).size).toBe(AUDIT_REASONS.length);
    const grant = new Set<string>(GRANT_AUDIT_REASONS);
    expect(BROKER_CODES.filter((code) => grant.has(code))).toEqual([]);
  });
});
