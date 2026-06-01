import { describe, it, expect } from 'vitest';
import { isGrantRef, parseGrantRef, buildGrantRef, GRANT_SCHEME } from './index';

describe('grant references', () => {
  describe('parseGrantRef', () => {
    it('parses a plain logical name', () => {
      expect(parseGrantRef('grant://orders-db')).toEqual({
        uri: 'grant://orders-db',
        name: 'orders-db',
      });
    });

    it('accepts RFC 3986 unreserved characters', () => {
      for (const name of ['orders_db', 'orders.db', 'a~b', 'A1', 'x-y-z']) {
        expect(parseGrantRef(`grant://${name}`).name).toBe(name);
      }
    });

    it('rejects a non-grant scheme', () => {
      expect(() => parseGrantRef('secret://vault/orders')).toThrow();
      expect(() => parseGrantRef('https://example.com')).toThrow();
    });

    it('rejects an empty name', () => {
      expect(() => parseGrantRef('grant://')).toThrow(/empty/);
    });

    // LOCK-IN: a grant reference must never carry backend topology (AAP Principle 4).
    // These are the shapes that would leak a host, port, path, userinfo, query, or mode.
    it.each([
      'grant://orders-db/table',          // path
      'grant://db.internal:5432',         // host:port
      'grant://user@host',                // userinfo
      'grant://orders?mode=exchange',     // query (would reveal CPI mode)
      'grant://orders#frag',              // fragment
      'grant://vault/secret/orders',      // backend + path
      'grant://https://api.example.com',  // nested URL
    ])('rejects backend-leaking reference %s', (leaky) => {
      expect(() => parseGrantRef(leaky)).toThrow();
      expect(isGrantRef(leaky)).toBe(false);
    });
  });

  describe('buildGrantRef', () => {
    it('builds from a logical name', () => {
      expect(buildGrantRef('orders-db')).toBe('grant://orders-db');
    });

    it('refuses to build a reference that would encode a backend', () => {
      expect(() => buildGrantRef('vault/secret/orders')).toThrow();
      expect(() => buildGrantRef('db.internal:5432')).toThrow();
    });

    it('round-trips with parseGrantRef', () => {
      const ref = buildGrantRef('orders-db');
      expect(parseGrantRef(ref).name).toBe('orders-db');
    });
  });

  it('GRANT_SCHEME is grant://', () => {
    expect(GRANT_SCHEME).toBe('grant://');
  });
});
