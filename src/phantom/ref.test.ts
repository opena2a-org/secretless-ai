import { describe, it, expect } from 'vitest';
import {
  parseSecretRef,
  isSecretRef,
  findSecretRefs,
  buildSecretRef,
} from './ref';

describe('phantom/ref', () => {
  describe('parseSecretRef', () => {
    it('parses a simple keychain reference', () => {
      const ref = parseSecretRef('secret://keychain/prod-db-password');
      expect(ref.backend).toBe('keychain');
      expect(ref.path).toBe('prod-db-password');
      expect(ref.uri).toBe('secret://keychain/prod-db-password');
      expect(ref.scope).toBeUndefined();
      expect(ref.ttlSeconds).toBeUndefined();
    });

    it('parses a vault reference with nested path', () => {
      const ref = parseSecretRef('secret://vault/secret/data/prod/api-key');
      expect(ref.backend).toBe('vault');
      expect(ref.path).toBe('secret/data/prod/api-key');
    });

    it('parses an env reference', () => {
      const ref = parseSecretRef('secret://env/ANTHROPIC_API_KEY');
      expect(ref.backend).toBe('env');
      expect(ref.path).toBe('ANTHROPIC_API_KEY');
    });

    it('parses a 1password reference', () => {
      const ref = parseSecretRef('secret://1password/op://Personal/prod-server/password');
      expect(ref.backend).toBe('1password');
      expect(ref.path).toBe('op://Personal/prod-server/password');
    });

    it('parses a local reference', () => {
      const ref = parseSecretRef('secret://local/my-secret');
      expect(ref.backend).toBe('local');
      expect(ref.path).toBe('my-secret');
    });

    it('parses query parameters', () => {
      const ref = parseSecretRef('secret://keychain/db?scope=read&ttl=300&capability=db:read');
      expect(ref.scope).toBe('read');
      expect(ref.ttlSeconds).toBe(300);
      expect(ref.capability).toBe('db:read');
    });

    it('ignores invalid TTL', () => {
      const ref = parseSecretRef('secret://keychain/db?ttl=abc');
      expect(ref.ttlSeconds).toBeUndefined();
    });

    it('ignores zero TTL', () => {
      const ref = parseSecretRef('secret://keychain/db?ttl=0');
      expect(ref.ttlSeconds).toBeUndefined();
    });

    it('throws for non-secret:// URI', () => {
      expect(() => parseSecretRef('https://example.com')).toThrow('must start with "secret://"');
    });

    it('throws for missing path', () => {
      expect(() => parseSecretRef('secret://keychain')).toThrow('missing path');
    });

    it('throws for empty path', () => {
      expect(() => parseSecretRef('secret://keychain/')).toThrow('empty path');
    });

    it('throws for unknown backend', () => {
      expect(() => parseSecretRef('secret://azure/secret-name')).toThrow('Unknown backend "azure"');
    });
  });

  describe('isSecretRef', () => {
    it('returns true for secret:// URIs', () => {
      expect(isSecretRef('secret://keychain/db')).toBe(true);
      expect(isSecretRef('secret://env/KEY')).toBe(true);
    });

    it('returns false for non-secret URIs', () => {
      expect(isSecretRef('https://example.com')).toBe(false);
      expect(isSecretRef('ANTHROPIC_API_KEY')).toBe(false);
      expect(isSecretRef('')).toBe(false);
    });
  });

  describe('findSecretRefs', () => {
    it('finds refs in text', () => {
      const text = `
        DATABASE_URL=secret://keychain/prod-db
        API_KEY=secret://env/ANTHROPIC_API_KEY
        Regular text here
        VAULT=secret://vault/secret/data/key?ttl=300
      `;
      const refs = findSecretRefs(text);
      expect(refs).toHaveLength(3);
      expect(refs[0]).toBe('secret://keychain/prod-db');
      expect(refs[1]).toBe('secret://env/ANTHROPIC_API_KEY');
      expect(refs[2]).toBe('secret://vault/secret/data/key?ttl=300');
    });

    it('returns empty array for text with no refs', () => {
      expect(findSecretRefs('no secrets here')).toHaveLength(0);
    });
  });

  describe('buildSecretRef', () => {
    it('builds a simple ref', () => {
      expect(buildSecretRef('keychain', 'prod-db')).toBe('secret://keychain/prod-db');
    });

    it('builds a ref with options', () => {
      const ref = buildSecretRef('vault', 'secret/key', {
        scope: 'read',
        ttlSeconds: 300,
        capability: 'db:read',
      });
      expect(ref).toBe('secret://vault/secret/key?scope=read&ttl=300&capability=db%3Aread');
    });

    it('round-trips through parse', () => {
      const uri = buildSecretRef('keychain', 'my-secret', { scope: 'read', ttlSeconds: 60 });
      const parsed = parseSecretRef(uri);
      expect(parsed.backend).toBe('keychain');
      expect(parsed.path).toBe('my-secret');
      expect(parsed.scope).toBe('read');
      expect(parsed.ttlSeconds).toBe(60);
    });
  });
});
