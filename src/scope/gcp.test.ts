import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { GCPScopeProvider, parseServiceAccountKey, createSignedJwt } from './gcp';

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// Generate a valid RSA key at import time for testing JWT signing
import * as crypto from 'crypto';
const { privateKey: FAKE_PRIVATE_KEY } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});

function makeServiceAccountKey(overrides?: Partial<Record<string, unknown>>): string {
  return JSON.stringify({
    type: 'service_account',
    project_id: 'test-project-123',
    private_key_id: 'key-id-abc',
    private_key: FAKE_PRIVATE_KEY,
    client_email: 'test@test-project-123.iam.gserviceaccount.com',
    client_id: '123456789',
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://oauth2.googleapis.com/token',
    ...overrides,
  });
}

describe('parseServiceAccountKey', () => {
  it('parses a valid service account key', () => {
    const key = parseServiceAccountKey(makeServiceAccountKey());
    expect(key.type).toBe('service_account');
    expect(key.project_id).toBe('test-project-123');
    expect(key.client_email).toBe('test@test-project-123.iam.gserviceaccount.com');
  });

  it('rejects non-JSON input', () => {
    expect(() => parseServiceAccountKey('not json')).toThrow('Invalid JSON');
  });

  it('rejects wrong type field', () => {
    expect(() => parseServiceAccountKey(JSON.stringify({ type: 'authorized_user' })))
      .toThrow('Expected type "service_account"');
  });

  it('rejects missing project_id', () => {
    expect(() => parseServiceAccountKey(makeServiceAccountKey({ project_id: '' })))
      .toThrow('Missing or empty project_id');
  });

  it('rejects missing private_key', () => {
    expect(() => parseServiceAccountKey(makeServiceAccountKey({ private_key: '' })))
      .toThrow('Missing or empty private_key');
  });

  it('rejects missing client_email', () => {
    expect(() => parseServiceAccountKey(makeServiceAccountKey({ client_email: '' })))
      .toThrow('Missing or empty client_email');
  });
});

describe('createSignedJwt', () => {
  it('produces a valid JWT with three base64url segments', () => {
    const jwt = createSignedJwt(
      'test@test.iam.gserviceaccount.com',
      FAKE_PRIVATE_KEY,
      'https://www.googleapis.com/auth/cloud-platform',
    );

    const parts = jwt.split('.');
    expect(parts).toHaveLength(3);

    // Verify header
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    expect(header.alg).toBe('RS256');
    expect(header.typ).toBe('JWT');

    // Verify payload
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    expect(payload.iss).toBe('test@test.iam.gserviceaccount.com');
    expect(payload.aud).toBe('https://oauth2.googleapis.com/token');
    expect(payload.scope).toBe('https://www.googleapis.com/auth/cloud-platform');
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.exp).toBe('number');
    expect(payload.exp - payload.iat).toBe(300);

    // Verify signature is non-empty base64url
    expect(parts[2].length).toBeGreaterThan(0);
    expect(parts[2]).not.toContain('+');
    expect(parts[2]).not.toContain('/');
  });
});

describe('GCPScopeProvider', () => {
  it('discovers permissions via testIamPermissions', async () => {
    // Mock token exchange
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ access_token: 'fake-access-token' }),
    });

    // Mock testIamPermissions
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        permissions: [
          'aiplatform.endpoints.predict',
          'storage.objects.get',
          'iam.serviceAccounts.list',
        ],
      }),
    });

    const provider = new GCPScopeProvider(makeServiceAccountKey());
    const permissions = await provider.discover(makeServiceAccountKey());

    expect(permissions).toEqual([
      'aiplatform.endpoints.predict',
      'iam.serviceAccounts.list',
      'storage.objects.get',
    ]);

    expect(mockFetch).toHaveBeenCalledTimes(2);

    // Verify token request
    const [tokenUrl] = mockFetch.mock.calls[0];
    expect(tokenUrl).toBe('https://oauth2.googleapis.com/token');

    // Verify testIamPermissions request
    const [permUrl, permOpts] = mockFetch.mock.calls[1];
    expect(permUrl).toContain('test-project-123:testIamPermissions');
    expect(permOpts.headers['Authorization']).toBe('Bearer fake-access-token');
  });

  it('handles 403 from testIamPermissions', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ access_token: 'fake-token' }),
    });
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      text: async () => 'Forbidden',
    });

    const provider = new GCPScopeProvider(makeServiceAccountKey());
    await expect(provider.discover(makeServiceAccountKey()))
      .rejects.toThrow('does not have access');
  });

  it('handles token exchange failure', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      text: async () => 'Unauthorized',
    });

    const provider = new GCPScopeProvider(makeServiceAccountKey());
    await expect(provider.discover(makeServiceAccountKey()))
      .rejects.toThrow('Token exchange failed');
  });

  it('returns empty array when no permissions granted', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ access_token: 'fake-token' }),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ permissions: [] }),
    });

    const provider = new GCPScopeProvider(makeServiceAccountKey());
    const permissions = await provider.discover(makeServiceAccountKey());
    expect(permissions).toEqual([]);
  });

  it('returns empty array when permissions field is missing', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ access_token: 'fake-token' }),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({}),
    });

    const provider = new GCPScopeProvider(makeServiceAccountKey());
    const permissions = await provider.discover(makeServiceAccountKey());
    expect(permissions).toEqual([]);
  });

  it('handles timeout', async () => {
    const abortError = new Error('The operation was aborted');
    abortError.name = 'AbortError';
    mockFetch.mockRejectedValueOnce(abortError);

    const provider = new GCPScopeProvider(makeServiceAccountKey());
    await expect(provider.discover(makeServiceAccountKey())).rejects.toThrow();
  });

  describe('healthCheck', () => {
    it('returns true when token exchange succeeds', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'test-token' }),
      });

      const provider = new GCPScopeProvider(makeServiceAccountKey());
      const healthy = await provider.healthCheck();
      expect(healthy).toBe(true);
    });

    it('returns false when token exchange fails', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const provider = new GCPScopeProvider(makeServiceAccountKey());
      const healthy = await provider.healthCheck();
      expect(healthy).toBe(false);
    });
  });
});
