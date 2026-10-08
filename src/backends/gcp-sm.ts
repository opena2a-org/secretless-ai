/**
 * GCP Secret Manager backend.
 *
 * Implements WritableSecretBackend using the GCP Secret Manager REST API.
 * Zero SDK dependency -- raw fetch calls with JWT-based authentication.
 *
 * Auth: Application Default Credentials (ADC) or service account key via
 * GOOGLE_APPLICATION_CREDENTIALS environment variable.
 *
 * API: https://secretmanager.googleapis.com/v1/projects/{project}/secrets
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import type { WritableSecretBackend, BackendHealth } from './types';
import { boundedFetch, describeRequest, type BoundedResponse } from './bounded-fetch';
import { resolveGcpProject } from './gcp-project';
import type { GcpProjectResolution } from './gcp-project';

const SM_BASE_URL = 'https://secretmanager.googleapis.com';
const OAUTH2_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const OAUTH2_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
const REQUEST_TIMEOUT_MS = 10_000;
const HEALTH_TIMEOUT_MS = 5_000;
const TOKEN_LIFETIME_SECONDS = 3600; // 1 hour

/**
 * GCP Secret Manager name validation regex.
 * Names must be 1-255 characters, alphanumeric plus dash and underscore.
 */
const SECRET_NAME_REGEX = /^[a-zA-Z0-9_-]{1,255}$/;

/**
 * A Google API request that did not complete in time. Names the host, which is
 * one of the constants above, and the path; holds no token, assertion or body.
 */
function gcpTimeoutError(method: string, url: string, timeoutMs: number): Error {
  const host = new URL(url).host;
  return new Error(
    [
      `GCP Secret Manager: ${host} did not respond within ${timeoutMs / 1000}s (${describeRequest(method, url)}).`,
      '',
      '  The request was abandoned and its connection closed. A write that timed',
      '  out may still have been applied by the server.',
      '',
      `  Verify:  curl -sI https://${host}/`,
      '  Fix:     check the network path from this machine to Google APIs (proxy,',
      '           firewall, DNS) and retry',
    ].join('\n'),
  );
}

export interface GCPSecretManagerConfig {
  /** GCP project ID. Overrides auto-detected project. */
  projectId?: string;
  /** Path to service account key file. Overrides GOOGLE_APPLICATION_CREDENTIALS. */
  keyFilePath?: string;
  /**
   * Directory whose `.secretless` may name the project. Default: the current
   * working directory, so commands run inside a repository use its project.
   */
  projectDir?: string;
}

interface ServiceAccountKey {
  type: string;
  project_id: string;
  private_key: string;
  client_email: string;
}

interface ADCCredentials {
  client_id: string;
  client_secret: string;
  refresh_token: string;
  type: string;
}

export class GCPSecretManagerBackend implements WritableSecretBackend {
  readonly name = 'gcp-sm';

  private projectId: string | undefined;
  private keyFilePath: string | undefined;
  private projectDir: string | undefined;
  private resolution: GcpProjectResolution | undefined;

  // Token cache
  private accessToken: string | null = null;
  private tokenExpiry: number = 0;

  constructor(config?: GCPSecretManagerConfig | Record<string, unknown>) {
    const c = (config ?? {}) as GCPSecretManagerConfig;
    this.projectId = c.projectId;
    this.keyFilePath = c.keyFilePath;
    this.projectDir = c.projectDir;
  }

  /**
   * Which project this backend reads and writes, and where that was decided.
   * File reads only; no request is made. A resolved project is kept for the
   * life of the backend.
   */
  describeProject(): GcpProjectResolution {
    if (this.resolution) return this.resolution;
    const resolution = resolveGcpProject({
      explicit: this.projectId,
      projectDir: this.projectDir,
      keyFilePath: this.keyFilePath,
    });
    if (resolution.projectId) this.resolution = resolution;
    return resolution;
  }

  /**
   * Resolve secrets from GCP Secret Manager.
   *
   * - resolve("secret/KEY") returns { "secret/KEY": "value" } (exact match on "KEY")
   * - resolve("secret") lists all secrets and returns all key-value pairs
   */
  async resolve(resolvePath: string): Promise<Record<string, string>> {
    const { projectId, token } = await this.ensureAuth();

    // Extract the secret name from path (last segment)
    const segments = resolvePath.split('/');
    const secretName = segments[segments.length - 1];

    // Try direct read first
    try {
      const value = await this.getSecretValue(projectId, secretName, token);
      return { [resolvePath]: value };
    } catch (err) {
      if (err instanceof Error && err.message.includes('not found')) {
        // If the path looks like a prefix (not a specific secret name), list all
        return this.listPrefix(projectId, resolvePath, token);
      }
      throw err;
    }
  }

  async store(key: string, value: string): Promise<void> {
    // Extract secret name from key path
    const segments = key.split('/');
    const secretName = segments[segments.length - 1];

    this.validateSecretName(secretName);

    const { projectId, token } = await this.ensureAuth();

    // Try to create the secret first
    const created = await this.createSecret(projectId, secretName, token);

    if (!created) {
      // Secret might already exist -- that's fine, we'll add a version
    }

    // Add a new version with the value
    await this.addSecretVersion(projectId, secretName, value, token);
  }

  /**
   * Store `value` as a new version of the secret `secretName`, creating the
   * secret first when it does not exist, and return the version's resource
   * name (`projects/<n>/secrets/<name>/versions/<v>`).
   */
  async storeVersion(secretName: string, value: string): Promise<string> {
    this.validateSecretName(secretName);
    const { projectId, token } = await this.ensureAuth();
    await this.createSecret(projectId, secretName, token);
    return this.addSecretVersion(projectId, secretName, value, token);
  }

  /**
   * Whether the secret `secretName` exists. Reads the secret's resource, which
   * carries no payload, never a version's value.
   */
  async hasSecret(secretName: string): Promise<boolean> {
    this.validateSecretName(secretName);
    const { projectId, token } = await this.ensureAuth();

    const url = `${SM_BASE_URL}/v1/projects/${projectId}/secrets/${secretName}`;
    const response = await this.request('GET', url, token);

    if (response.status === 404) return false;
    if (response.status === 403) {
      throw new Error(
        `GCP Secret Manager: insufficient IAM permissions. Grant 'Secret Manager Viewer' role.`
      );
    }
    if (!response.ok) {
      throw new Error(`GCP Secret Manager: read failed (HTTP ${response.status})`);
    }
    return true;
  }

  /** Obtain a token and return the project requests go to. */
  async authenticate(): Promise<string> {
    const { projectId } = await this.ensureAuth();
    return projectId;
  }

  async delete(key: string): Promise<boolean> {
    const segments = key.split('/');
    const secretName = segments[segments.length - 1];

    const { projectId, token } = await this.ensureAuth();

    const url = `${SM_BASE_URL}/v1/projects/${projectId}/secrets/${secretName}`;
    const response = await this.request('DELETE', url, token);

    if (response.status === 404) {
      return false;
    }

    if (response.status === 403) {
      throw new Error(
        `GCP Secret Manager: insufficient IAM permissions on ${this.projectLabel(projectId)}. Grant 'Secret Manager Admin' role.`
      );
    }

    if (!response.ok) {
      throw new Error(`GCP Secret Manager: delete failed (HTTP ${response.status})`);
    }

    return true;
  }

  async healthCheck(): Promise<BackendHealth> {
    const start = Date.now();

    try {
      const { projectId, token } = await this.ensureAuth();

      // Try listing secrets (limit 1) to verify access
      const url = `${SM_BASE_URL}/v1/projects/${projectId}/secrets?pageSize=1`;
      const response = await boundedFetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'User-Agent': 'secretless-ai/1.0',
        },
      }, {
        timeoutMs: HEALTH_TIMEOUT_MS,
        onTimeout: () => new Error(
          `GCP Secret Manager did not respond within ${HEALTH_TIMEOUT_MS / 1000}s. Verify: curl -sI ${SM_BASE_URL}/`,
        ),
      });

      const latencyMs = Date.now() - start;

      if (response.ok) {
        return { healthy: true, latencyMs, message: `GCP Secret Manager (${this.projectLabel(projectId)})` };
      }

      if (response.status === 403) {
        return {
          healthy: false,
          latencyMs,
          message: `Insufficient IAM permissions on ${this.projectLabel(projectId)}`,
        };
      }

      return {
        healthy: false,
        latencyMs,
        message: `GCP Secret Manager returned HTTP ${response.status}`,
      };
    } catch (err) {
      return {
        healthy: false,
        latencyMs: Date.now() - start,
        message: err instanceof Error ? err.message : 'Connection failed',
      };
    }
  }

  // --- Private helpers ---

  private validateSecretName(name: string): void {
    if (!SECRET_NAME_REGEX.test(name)) {
      throw new Error(
        `Invalid secret name '${name}'. ` +
        `GCP Secret Manager names must match: [a-zA-Z0-9_-]{1,255}. ` +
        `Use dashes or underscores instead of slashes or dots.`
      );
    }
  }

  /**
   * Ensure we have a valid access token and project ID.
   * Returns both for use in API calls.
   */
  private async ensureAuth(): Promise<{ projectId: string; token: string }> {
    const projectId = this.resolveProjectId();
    if (!projectId) {
      throw new Error(
        'GCP Secret Manager: project ID not configured. ' +
        'Name it in the repository\'s .secretless as "gcp.projectId: <project-id>", ' +
        'set it in ~/.secretless-ai/config.json under gcp.projectId, ' +
        'or use a service account key with a project_id field.'
      );
    }

    const token = await this.ensureAccessToken();
    return { projectId, token };
  }

  /**
   * Resolve the GCP project ID. Throws when the repository's manifest names a
   * project that cannot be used: falling back to another project would read
   * and write across the boundary the manifest exists to keep (#177).
   */
  private resolveProjectId(): string | undefined {
    const resolution = this.describeProject();
    if (resolution.error) {
      throw new Error(
        `GCP Secret Manager: ${resolution.error}. Nothing was read from or written to another project.`
      );
    }
    return resolution.projectId;
  }

  /** `project <id>`, plus the manifest line when a repository named it. */
  private projectLabel(projectId: string): string {
    const resolution = this.resolution;
    if (resolution?.source === 'manifest' && resolution.projectId === projectId) {
      return `project ${projectId} (named by ${resolution.from})`;
    }
    return `project ${projectId}`;
  }

  /**
   * Get or refresh an OAuth2 access token.
   * Supports both service account keys (JWT) and ADC (refresh token).
   */
  private async ensureAccessToken(): Promise<string> {
    // Return cached token if still valid (with 60s buffer)
    if (this.accessToken && Date.now() < this.tokenExpiry - 60_000) {
      return this.accessToken;
    }

    const keyPath = this.keyFilePath ?? process.env.GOOGLE_APPLICATION_CREDENTIALS;

    if (keyPath && fs.existsSync(keyPath)) {
      // Service account key -- use JWT exchange
      const raw = fs.readFileSync(keyPath, 'utf-8');
      const key = JSON.parse(raw) as ServiceAccountKey;

      if (key.type !== 'service_account') {
        throw new Error(`Expected service account key, got type: ${key.type}`);
      }

      const token = await this.exchangeJwtForToken(key.client_email, key.private_key);
      return token;
    }

    // Try Application Default Credentials (ADC)
    const adcPath = path.join(os.homedir(), '.config', 'gcloud', 'application_default_credentials.json');
    if (fs.existsSync(adcPath)) {
      const raw = fs.readFileSync(adcPath, 'utf-8');
      const adc = JSON.parse(raw) as ADCCredentials;

      if (adc.type === 'authorized_user' && adc.refresh_token) {
        const token = await this.refreshADCToken(adc);
        return token;
      }
    }

    throw new Error(
      'GCP authentication failed. Run `gcloud auth application-default login` ' +
      'or set GOOGLE_APPLICATION_CREDENTIALS to a service account key file.'
    );
  }

  /**
   * Exchange a signed JWT for an access token (service account flow).
   * Reuses JWT signing utilities similar to src/scope/gcp.ts.
   */
  private async exchangeJwtForToken(clientEmail: string, privateKey: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    const header = { alg: 'RS256', typ: 'JWT' };
    const payload = {
      iss: clientEmail,
      sub: clientEmail,
      aud: OAUTH2_TOKEN_URL,
      iat: now,
      exp: now + TOKEN_LIFETIME_SECONDS,
      scope: OAUTH2_SCOPE,
    };

    const headerB64 = base64UrlEncode(JSON.stringify(header));
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    const unsigned = `${headerB64}.${payloadB64}`;

    const sign = crypto.createSign('RSA-SHA256');
    sign.update(unsigned);
    const signature = sign.sign(privateKey);
    const signatureB64 = base64UrlEncodeBuffer(signature);
    const jwt = `${unsigned}.${signatureB64}`;

    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    });

    const response = await this.fetchWithTimeout('POST', OAUTH2_TOKEN_URL, {
      'Content-Type': 'application/x-www-form-urlencoded',
    }, body.toString());

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`GCP token exchange failed (HTTP ${response.status}): ${text}`);
    }

    const data = await response.json() as { access_token?: string; expires_in?: number };
    if (!data.access_token) {
      throw new Error('GCP token response missing access_token');
    }

    this.accessToken = data.access_token;
    this.tokenExpiry = Date.now() + (data.expires_in ?? 3600) * 1000;
    return this.accessToken;
  }

  /**
   * Refresh an access token using ADC refresh token flow.
   */
  private async refreshADCToken(adc: ADCCredentials): Promise<string> {
    const body = new URLSearchParams({
      client_id: adc.client_id,
      client_secret: adc.client_secret,
      refresh_token: adc.refresh_token,
      grant_type: 'refresh_token',
    });

    const response = await this.fetchWithTimeout('POST', OAUTH2_TOKEN_URL, {
      'Content-Type': 'application/x-www-form-urlencoded',
    }, body.toString());

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`GCP ADC token refresh failed (HTTP ${response.status}): ${text}`);
    }

    const data = await response.json() as { access_token?: string; expires_in?: number };
    if (!data.access_token) {
      throw new Error('GCP token response missing access_token');
    }

    this.accessToken = data.access_token;
    this.tokenExpiry = Date.now() + (data.expires_in ?? 3600) * 1000;
    return this.accessToken;
  }

  /**
   * Get the latest version of a secret's value.
   */
  private async getSecretValue(projectId: string, secretName: string, token: string): Promise<string> {
    const url = `${SM_BASE_URL}/v1/projects/${projectId}/secrets/${secretName}/versions/latest:access`;
    const response = await this.request('GET', url, token);

    if (response.status === 404) {
      throw new Error(`Secret '${secretName}' not found in ${this.projectLabel(projectId)}`);
    }

    if (response.status === 403) {
      throw new Error(
        `GCP Secret Manager: insufficient IAM permissions on ${this.projectLabel(projectId)}. Grant 'Secret Manager Secret Accessor' role.`
      );
    }

    if (!response.ok) {
      throw new Error(`GCP Secret Manager: read failed (HTTP ${response.status})`);
    }

    const body = await response.json() as {
      payload?: { data?: string };
    };

    const data = body.payload?.data;
    if (!data) {
      return '';
    }

    // GCP returns base64-encoded payload
    return Buffer.from(data, 'base64').toString('utf-8');
  }

  /**
   * Create a secret resource (without a version).
   * Returns true if created, false if it already exists.
   */
  private async createSecret(projectId: string, secretName: string, token: string): Promise<boolean> {
    const url = `${SM_BASE_URL}/v1/projects/${projectId}/secrets?secretId=${secretName}`;
    const response = await this.request('POST', url, token, {
      replication: { automatic: {} },
    });

    if (response.status === 409) {
      // Already exists -- that's fine
      return false;
    }

    if (response.status === 403) {
      throw new Error(
        `GCP Secret Manager: insufficient IAM permissions on ${this.projectLabel(projectId)}. Grant 'Secret Manager Admin' role.`
      );
    }

    if (!response.ok) {
      throw new Error(`GCP Secret Manager: create secret failed (HTTP ${response.status})`);
    }

    return true;
  }

  /**
   * Add a new version to an existing secret. Returns the version's resource name.
   */
  private async addSecretVersion(
    projectId: string,
    secretName: string,
    value: string,
    token: string,
  ): Promise<string> {
    const url = `${SM_BASE_URL}/v1/projects/${projectId}/secrets/${secretName}:addVersion`;
    const encoded = Buffer.from(value, 'utf-8').toString('base64');

    const response = await this.request('POST', url, token, {
      payload: { data: encoded },
    });

    if (response.status === 403) {
      throw new Error(
        `GCP Secret Manager: insufficient IAM permissions on ${this.projectLabel(projectId)}. Grant 'Secret Manager Admin' role.`
      );
    }

    if (!response.ok) {
      throw new Error(`GCP Secret Manager: add version failed (HTTP ${response.status})`);
    }

    // The new version's resource name only; the response carries no payload.
    const body = await response.json().catch(() => undefined) as { name?: unknown } | undefined;
    return typeof body?.name === 'string' ? body.name : `projects/${projectId}/secrets/${secretName}/versions/unknown`;
  }

  /**
   * List all secrets in the project and read their values.
   * Used as a fallback when resolve() doesn't find an exact match.
   */
  private async listPrefix(
    projectId: string,
    prefix: string,
    token: string,
  ): Promise<Record<string, string>> {
    const results: Record<string, string> = {};
    let pageToken: string | undefined;

    do {
      const params = new URLSearchParams({ pageSize: '100' });
      if (pageToken) params.set('pageToken', pageToken);

      const url = `${SM_BASE_URL}/v1/projects/${projectId}/secrets?${params}`;
      const response = await this.request('GET', url, token);

      if (!response.ok) {
        // A project named by a repository manifest that cannot be listed is
        // reported, not read as "no secrets": an empty answer would look like
        // missing names rather than a project these credentials cannot use.
        if (this.resolution?.source === 'manifest') {
          throw new Error(
            `GCP Secret Manager: cannot list secrets in ${this.projectLabel(projectId)} (HTTP ${response.status}). `
            + `Verify access: gcloud secrets list --project ${projectId} --limit 1`
          );
        }
        return results;
      }

      const body = await response.json() as {
        secrets?: Array<{ name?: string }>;
        nextPageToken?: string;
      };

      const secrets = body.secrets ?? [];
      for (const secret of secrets) {
        if (!secret.name) continue;

        // Extract secret name from full resource path
        // Format: projects/{project}/secrets/{name}
        const parts = secret.name.split('/');
        const name = parts[parts.length - 1];

        try {
          const value = await this.getSecretValue(projectId, name, token);
          results[`${prefix}/${name}`] = value;
        } catch {
          // Skip secrets we can't read (permission issues, no versions, etc.)
        }
      }

      pageToken = body.nextPageToken;
    } while (pageToken);

    return results;
  }

  /**
   * Make an authenticated API request with timeout.
   */
  private async request(
    method: string,
    url: string,
    token: string,
    body?: unknown,
  ): Promise<BoundedResponse> {
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${token}`,
      'User-Agent': 'secretless-ai/1.0',
    };

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    return this.fetchWithTimeout(
      method,
      url,
      headers,
      body !== undefined ? JSON.stringify(body) : undefined,
    );
  }

  /**
   * One request, bounded end to end: the headers and the body read share one
   * deadline, and a request that misses it throws an error that says what to
   * do.
   */
  private async fetchWithTimeout(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: string,
  ): Promise<BoundedResponse> {
    return boundedFetch(url, { method, headers, body }, {
      timeoutMs: REQUEST_TIMEOUT_MS,
      onTimeout: () => gcpTimeoutError(method, url, REQUEST_TIMEOUT_MS),
    });
  }
}

// --- Utility functions (same as scope/gcp.ts) ---

function base64UrlEncode(str: string): string {
  return Buffer.from(str, 'utf-8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlEncodeBuffer(buf: Buffer): string {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Check if GCP credentials are available via ADC or service account key.
 */
export function isGCPAvailable(): { available: boolean; message: string } {
  // Check GOOGLE_APPLICATION_CREDENTIALS
  const keyPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (keyPath && fs.existsSync(keyPath)) {
    return { available: true, message: 'Service account key found' };
  }

  // Check ADC path
  const adcPath = path.join(
    os.homedir(),
    '.config',
    'gcloud',
    'application_default_credentials.json',
  );
  if (fs.existsSync(adcPath)) {
    return { available: true, message: 'Application Default Credentials found' };
  }

  return {
    available: false,
    message: 'Run `gcloud auth application-default login` or set GOOGLE_APPLICATION_CREDENTIALS',
  };
}
