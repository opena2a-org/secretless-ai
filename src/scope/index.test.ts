import { describe, it, expect } from 'vitest';
import { detectProvider } from './index';

describe('detectProvider', () => {
  it('detects GCP from service account JSON', () => {
    const cred = JSON.stringify({
      type: 'service_account',
      project_id: 'my-project',
      private_key: '...',
      client_email: 'test@my-project.iam.gserviceaccount.com',
    });
    expect(detectProvider(cred)).toBe('gcp');
  });

  it('detects Vault from hvs. prefix', () => {
    expect(detectProvider('hvs.CAESIG_abc123')).toBe('vault');
  });

  it('detects Vault from s. prefix', () => {
    expect(detectProvider('s.123abc456def')).toBe('vault');
  });

  it('detects AWS from AKIA prefix', () => {
    // Use a test pattern that matches the AKIA regex but is clearly fake
    expect(detectProvider('AKIA' + 'TESTKEY012345678')).toBe('aws');
  });

  it('returns null for unknown credential format', () => {
    expect(detectProvider('some-random-string-123')).toBeNull();
  });

  it('returns null for invalid JSON that starts with {', () => {
    expect(detectProvider('{not valid json}')).toBeNull();
  });

  it('returns null for JSON with wrong type', () => {
    const cred = JSON.stringify({ type: 'authorized_user', project_id: 'test' });
    expect(detectProvider(cred)).toBeNull();
  });

  it('handles whitespace around credentials', () => {
    expect(detectProvider('  hvs.test123  ')).toBe('vault');
  });
});
