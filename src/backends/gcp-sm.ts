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
import type { WritableSecretBackend, BackendHealth, ResolveOptions, StoreScopeLine } from './types';
import { boundedFetch, describeRequest, type BoundedResponse } from './bounded-fetch';
import { resolveGcpProject } from './gcp-project';
import type { GcpProjectResolution } from './gcp-project';
import { escapeForDisplay } from '../display-safe';

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
const MAX_SECRET_NAME_LENGTH = 255;

/**
 * `secret set NAME` stores the key `secret/NAME` (SecretStore). Such a key, and
 * a key with no '/', is stored under the bare name NAME: the project's own
 * secrets are this backend's plain secrets, named as every release named them.
 */
const PLAIN_KEY_PREFIX = 'secret/';

/**
 * Every other key, an MCP server's `mcp/<client>/<server>/<ENV>` among them, is
 * stored under a name derived from the whole key (encodeStoreKey), on a secret
 * created with this label. A secret of such a name without the label was not
 * created by this backend: a read under a key never returns it, and a write or
 * a delete never touches it. A secret with the label is held for an MCP server
 * binding: a plain key that names it is refused, so a read by a plain key never
 * returns its value, and a write or a delete by one never touches it.
 */
const STORE_KEY_LABEL = 'secretless-ai';
const STORE_KEY_LABEL_VALUE = 'store-key';

/** Between the encoded segments of a key. No encoded segment holds a '-'. */
const SEGMENT_SEPARATOR = '--';

/** The segments encodeSegment writes: letters, digits, `__`, and `_` with two upper-case hex digits. */
const ENCODED_SEGMENT = /^(?:[A-Za-z0-9]|__|_[0-9A-F]{2})*$/;

/**
 * Strict UTF-8 that keeps a U+FEFF at the start of the bytes (ignoreBOM): a
 * segment that starts with one decodes back to itself, so its key keeps its
 * binding.
 */
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function validateSecretName(name: string): void {
  if (!SECRET_NAME_REGEX.test(name)) {
    throw new Error(
      `Invalid secret name '${name}'. ` +
      `GCP Secret Manager names must match: [a-zA-Z0-9_-]{1,255}. ` +
      `Use dashes or underscores instead of slashes or dots.`
    );
  }
}

/**
 * The bare name a plain key is stored under: the key itself when it holds no
 * '/', NAME for `secret/NAME`, and undefined for every other key.
 */
function plainName(key: string): string | undefined {
  if (!key.includes('/')) return key;
  const name = key.slice(PLAIN_KEY_PREFIX.length);
  return key.startsWith(PLAIN_KEY_PREFIX) && !name.includes('/') ? name : undefined;
}

/**
 * One '/'-separated segment of a key, in letters, digits and '_': a letter or
 * digit stands for itself, '_' is written `__`, and every other UTF-8 byte is
 * '_' and two upper-case hex digits ('-' is `_2D`). Undefined for a segment
 * that is not well-formed Unicode, which no name can give back.
 */
function encodeSegment(segment: string): string | undefined {
  const bytes = Buffer.from(segment, 'utf-8');
  if (bytes.toString('utf-8') !== segment) return undefined;
  let encoded = '';
  for (const byte of bytes) {
    const alphanumeric = (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a);
    if (alphanumeric) encoded += String.fromCharCode(byte);
    else if (byte === 0x5f) encoded += '__';
    else encoded += `_${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return encoded;
}

/** The segment encodeSegment wrote as `encoded`, or undefined when it writes no such text. */
function decodeSegment(encoded: string): string | undefined {
  if (!ENCODED_SEGMENT.test(encoded)) return undefined;
  const bytes: number[] = [];
  for (let i = 0; i < encoded.length;) {
    if (encoded[i] !== '_') {
      bytes.push(encoded.charCodeAt(i));
      i += 1;
    } else if (encoded[i + 1] === '_') {
      bytes.push(0x5f);
      i += 2;
    } else {
      bytes.push(parseInt(encoded.slice(i + 1, i + 3), 16));
      i += 3;
    }
  }
  try {
    return UTF8_STRICT.decode(Uint8Array.from(bytes));
  } catch {
    return undefined;
  }
}

/**
 * The Secret Manager name a store key is stored under.
 *
 * A plain key (`secret/NAME`, or a key with no '/') keeps its bare name. Every
 * other key is each of its '/'-separated segments encoded (encodeSegment) and
 * joined with `--`, so `mcp/cursor/github/GITHUB_TOKEN` is
 * `mcp--cursor--github--GITHUB__TOKEN`. No encoded segment holds a '-', so a
 * name splits back into exactly the segments it was made of: decodeStoreKey
 * returns the key, and two keys never share a name.
 *
 * Throws, and nothing is sent, for a key no name can hold: a plain name outside
 * [a-zA-Z0-9_-]{1,255}, a key that is not well-formed Unicode, or one whose
 * name would be longer than the 255 characters the API allows.
 */
export function encodeStoreKey(key: string): string {
  const plain = plainName(key);
  if (plain !== undefined) {
    validateSecretName(plain);
    return plain;
  }
  const segments = key.split('/').map(encodeSegment);
  if (segments.some((segment) => segment === undefined)) {
    throw new Error(
      `GCP Secret Manager: the key '${escapeForDisplay(key)}' is not well-formed Unicode, so no secret name can hold it. Nothing was written.`,
    );
  }
  const name = segments.join(SEGMENT_SEPARATOR);
  if (name.length > MAX_SECRET_NAME_LENGTH) {
    throw new Error(
      `GCP Secret Manager: the key '${escapeForDisplay(key)}' would be stored under a name of ${name.length} characters, `
      + `over the ${MAX_SECRET_NAME_LENGTH} a secret name may have. Nothing was written. Use a shorter client, server or env name.`,
    );
  }
  return name;
}

/**
 * The store key `name` stands for when encodeStoreKey derives `name` from it,
 * and undefined for every other name: a bare name, or text encodeStoreKey
 * never writes.
 */
export function decodeStoreKey(name: string): string | undefined {
  const parts = name.split(SEGMENT_SEPARATOR);
  if (parts.length < 2) return undefined;
  const segments = parts.map(decodeSegment);
  if (segments.some((segment) => segment === undefined)) return undefined;
  const key = segments.join('/');
  if (plainName(key) !== undefined) return undefined;
  try {
    return encodeStoreKey(key) === name ? key : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether a path names one plain secret, `secret/NAME`. It is read as an exact
 * read: the keys stored under `secret/` are one name deep (SecretStore).
 */
function isPlainEntry(resolvePath: string): boolean {
  return resolvePath.startsWith(PLAIN_KEY_PREFIX) && plainName(resolvePath) !== undefined;
}

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

/**
 * Who a gcp-sm backend reads as, for the value cache's scope, from the file
 * ensureAccessToken would sign with: the service account a key file names,
 * otherwise the Application Default Credentials' account and their refresh
 * token as its SHA-256, which tells two logins apart where the file leaves
 * the account empty. File reads only.
 */
function gcpCredentialIdentity(keyPath: string | undefined): StoreScopeLine[] {
  if (keyPath && fs.existsSync(keyPath)) {
    try {
      const key = JSON.parse(fs.readFileSync(keyPath, 'utf-8')) as Partial<ServiceAccountKey>;
      return [['service-account', String(key.client_email ?? '')]];
    } catch {
      return [['service-account-key-unreadable', path.resolve(keyPath)]];
    }
  }
  const adcPath = path.join(os.homedir(), '.config', 'gcloud', 'application_default_credentials.json');
  try {
    const adc = JSON.parse(fs.readFileSync(adcPath, 'utf-8')) as Partial<ADCCredentials> & { account?: string };
    return [
      ['adc-account', String(adc.account ?? '')],
      ['adc-refresh-token-sha256', crypto.createHash('sha256').update(String(adc.refresh_token ?? ''), 'utf-8').digest('hex')],
    ];
  } catch {
    return [['credential', 'none']];
  }
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
   * The project this backend reads, where it was named, and the identity of
   * the credential it reads with, for the value cache's scope (cacheScope).
   * File reads only; no request is made. A backend that cannot name its
   * project yet is given a scope no other backend has, so nothing it caches
   * once a project is named is served to another.
   */
  describeStore(): StoreScopeLine[] {
    const project = this.describeProject();
    const lines: StoreScopeLine[] = [
      ['project', project.projectId ?? ''],
      ['project-source', project.source],
      ...gcpCredentialIdentity(this.keyFilePath ?? process.env.GOOGLE_APPLICATION_CREDENTIALS),
    ];
    if (!project.projectId) lines.push(['unresolved', crypto.randomBytes(16).toString('hex')]);
    return lines;
  }

  /**
   * Resolve secrets from GCP Secret Manager.
   *
   * - An exact read (`{ exact: true }`), and a read of `secret/NAME`, reads the
   *   one secret the key is stored under (encodeStoreKey) and returns
   *   `{ [path]: value }`, or `{}` when there is none. It lists nothing. A
   *   plain key that names a secret held for an MCP server binding is
   *   refused, and no value is read.
   * - Any other path is a prefix: the project's secret names are listed, and a
   *   value is read only for each secret whose key is the path or lies under
   *   `path/` (every key for ''). A secret's key comes from its name and label
   *   (listKeys), so resolve("secret") returns the project's plain secrets and
   *   no MCP server's, and resolve("mcp/<client>/<server>") returns that
   *   server's secrets and no other value in the project.
   */
  async resolve(resolvePath: string, options?: ResolveOptions): Promise<Record<string, string>> {
    const { projectId, token } = await this.ensureAuth();
    if (options?.exact || isPlainEntry(resolvePath)) {
      return this.readKey(projectId, resolvePath, token);
    }
    return this.readUnder(projectId, resolvePath, token);
  }

  async store(key: string, value: string): Promise<void> {
    const secretName = encodeStoreKey(key);
    const { projectId, token } = await this.ensureAuth();

    if (plainName(key) !== undefined) {
      // A plain secret is created when absent, and a version is added to it. A
      // secret that already exists gets one only when it does not carry the
      // store-key label: one held for an MCP server binding is refused.
      const created = await this.createSecret(projectId, secretName, token);
      if (!created && await this.storeKeyState(projectId, secretName, token) === 'stored-key') {
        throw this.heldForServerError(projectId, key, secretName, 'written');
      }
      await this.addSecretVersion(projectId, secretName, value, token);
      return;
    }

    // A secret named after a whole key is created with the store-key label, and
    // a version is added to an existing one only when it carries the label.
    const created = await this.createSecret(projectId, secretName, token, {
      [STORE_KEY_LABEL]: STORE_KEY_LABEL_VALUE,
    });
    if (!created) {
      const state = await this.storeKeyState(projectId, secretName, token);
      if (state === 'other') {
        throw new Error(
          [
            `GCP Secret Manager: ${this.projectLabel(projectId)} holds a secret named ${secretName} that secretless-ai did not create `
            + `for the key '${escapeForDisplay(key)}': it has no ${STORE_KEY_LABEL}=${STORE_KEY_LABEL_VALUE} label. Nothing was written to it.`,
            '',
            `  Verify:  gcloud secrets describe ${secretName} --project ${projectId}`,
            `  Fix:     if it holds this key's value, label it: gcloud secrets update ${secretName} --project ${projectId} --update-labels=${STORE_KEY_LABEL}=${STORE_KEY_LABEL_VALUE}`,
          ].join('\n'),
        );
      }
      if (state === 'absent') {
        throw new Error(
          `GCP Secret Manager: the secret ${secretName} in ${this.projectLabel(projectId)} was deleted while it was being written. `
          + 'Nothing was written; run the command again.',
        );
      }
    }
    await this.addSecretVersion(projectId, secretName, value, token);
  }

  /**
   * Store `value` as a new version of the secret `secretName`, creating the
   * secret first when it does not exist, and return the version's resource
   * name (`projects/<n>/secrets/<name>/versions/<v>`). The bare name is the
   * plain key `secret/<secretName>`'s, and it is written as store() writes a
   * plain key: a secret that already exists gets a version only when it does
   * not carry the store-key label, and one held for an MCP server binding is
   * refused before the value is sent.
   */
  async storeVersion(secretName: string, value: string): Promise<string> {
    this.validateSecretName(secretName);
    const { projectId, token } = await this.ensureAuth();
    const created = await this.createSecret(projectId, secretName, token);
    if (!created && await this.storeKeyState(projectId, secretName, token) === 'stored-key') {
      throw this.heldForServerError(projectId, `${PLAIN_KEY_PREFIX}${secretName}`, secretName, 'written');
    }
    return this.addSecretVersion(projectId, secretName, value, token);
  }

  /**
   * Whether storeVersion would add a version to an existing secret
   * `secretName`: false when there is none, and true when there is one
   * without the store-key label. One that carries the label is held for an
   * MCP server binding, and storeVersion's refusal is thrown. Reads the
   * secret's resource, which carries no payload, never a version's value.
   */
  async hasPlainSecret(secretName: string): Promise<boolean> {
    this.validateSecretName(secretName);
    const { projectId, token } = await this.ensureAuth();
    const state = await this.storeKeyState(projectId, secretName, token);
    if (state === 'stored-key') {
      throw this.heldForServerError(projectId, `${PLAIN_KEY_PREFIX}${secretName}`, secretName, 'written');
    }
    return state === 'other';
  }

  /** Obtain a token and return the project requests go to. */
  async authenticate(): Promise<string> {
    const { projectId } = await this.ensureAuth();
    return projectId;
  }

  async delete(key: string): Promise<boolean> {
    let secretName: string;
    try {
      secretName = encodeStoreKey(key);
    } catch {
      return false; // no secret can be stored under this key
    }

    const { projectId, token } = await this.ensureAuth();

    // A secret named after a whole key is deleted only when it carries the
    // store-key label: one secretless-ai did not create is left as it is. A
    // plain key's delete of a secret that carries it is refused.
    if (!await this.keyReaches(projectId, key, secretName, token, 'deleted')) {
      return false;
    }

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
    validateSecretName(name);
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
   * The value of a secret's latest version, or undefined when the secret does
   * not exist or holds no version.
   */
  private async getSecretValue(projectId: string, secretName: string, token: string): Promise<string | undefined> {
    const url = `${SM_BASE_URL}/v1/projects/${projectId}/secrets/${secretName}/versions/latest:access`;
    const response = await this.request('GET', url, token);

    if (response.status === 404) {
      return undefined;
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
   * Create a secret resource (without a version), with `labels` when given.
   * Returns true if created, false if it already exists.
   */
  private async createSecret(
    projectId: string,
    secretName: string,
    token: string,
    labels?: Record<string, string>,
  ): Promise<boolean> {
    const url = `${SM_BASE_URL}/v1/projects/${projectId}/secrets?secretId=${secretName}`;
    const response = await this.request('POST', url, token, {
      replication: { automatic: {} },
      ...(labels ? { labels } : {}),
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
   * The one secret `key` is stored under, as `{ [key]: value }`, or `{}` when
   * there is none. A name derived from a whole key is read only on a secret
   * that carries the store-key label, and a plain key's read of a secret that
   * carries it is refused. Nothing is listed.
   */
  private async readKey(projectId: string, key: string, token: string): Promise<Record<string, string>> {
    let secretName: string;
    try {
      secretName = encodeStoreKey(key);
    } catch {
      return {}; // no secret can be stored under this key
    }
    if (!await this.keyReaches(projectId, key, secretName, token, 'read')) {
      return {};
    }
    const value = await this.getSecretValue(projectId, secretName, token);
    return value === undefined ? {} : { [key]: value };
  }

  /**
   * Each key that is `prefix` or lies under `prefix/` (every key for ''), with
   * its value. Names are listed (listKeys), and a value is read only for a key
   * selected here.
   */
  private async readUnder(projectId: string, prefix: string, token: string): Promise<Record<string, string>> {
    const results: Record<string, string> = {};
    for (const { key, secretName } of await this.listKeys(projectId, token)) {
      if (prefix !== '' && key !== prefix && !key.startsWith(`${prefix}/`)) continue;
      try {
        const value = await this.getSecretValue(projectId, secretName, token);
        if (value !== undefined) results[key] = value;
      } catch {
        // Skip secrets we can't read (permission issues, etc.)
      }
    }
    return results;
  }

  /**
   * Whether the secret `secretName` exists and carries the store-key label.
   * Reads the secret's resource, which carries no payload, never a version's
   * value.
   */
  private async storeKeyState(
    projectId: string,
    secretName: string,
    token: string,
  ): Promise<'absent' | 'stored-key' | 'other'> {
    const url = `${SM_BASE_URL}/v1/projects/${projectId}/secrets/${secretName}`;
    const response = await this.request('GET', url, token);

    if (response.status === 404) return 'absent';
    if (response.status === 403) {
      throw new Error(
        `GCP Secret Manager: insufficient IAM permissions on ${this.projectLabel(projectId)}. Grant 'Secret Manager Viewer' role.`
      );
    }
    if (!response.ok) {
      throw new Error(`GCP Secret Manager: read failed (HTTP ${response.status})`);
    }
    const body = await response.json() as { labels?: Record<string, string> };
    return body.labels?.[STORE_KEY_LABEL] === STORE_KEY_LABEL_VALUE ? 'stored-key' : 'other';
  }

  /**
   * Whether `key` reaches the secret `secretName` it is stored under, from the
   * secret's label, read before its value is read or it is deleted. A name
   * derived from a whole key reaches only a secret that carries the store-key
   * label, and a plain key only one that does not: a plain key that names a
   * secret held for an MCP server binding is refused. No key reaches an absent
   * secret.
   */
  private async keyReaches(
    projectId: string,
    key: string,
    secretName: string,
    token: string,
    refused: 'deleted' | 'read',
  ): Promise<boolean> {
    const state = await this.storeKeyState(projectId, secretName, token);
    if (state === 'absent') return false;
    if (plainName(key) === undefined) return state === 'stored-key';
    if (state === 'stored-key') throw this.heldForServerError(projectId, key, secretName, refused);
    return true;
  }

  /**
   * The refusal of a plain key's write, delete or read of a secret held for an
   * MCP server binding. Names the secret, the key it is held for and the plain
   * key; never a value.
   */
  private heldForServerError(
    projectId: string,
    key: string,
    secretName: string,
    refused: 'written' | 'deleted' | 'read',
  ): Error {
    const serverKey = decodeStoreKey(secretName);
    const binding = serverKey === undefined
      ? 'an MCP server binding'
      : `an MCP server binding, the key '${escapeForDisplay(serverKey)}'`;
    return new Error(
      [
        `GCP Secret Manager: the secret ${secretName} in ${this.projectLabel(projectId)} is held for ${binding}: `
        + `it carries the ${STORE_KEY_LABEL}=${STORE_KEY_LABEL_VALUE} label, and the plain key '${escapeForDisplay(key)}' `
        + `does not reach it. Nothing was ${refused}.`,
        '',
        `  Verify:  gcloud secrets describe ${secretName} --project ${projectId}`,
        `  Fix:     use a plain name no MCP server's secret is held under; the server's secret is reached only by its own key`,
      ].join('\n'),
    );
  }

  /**
   * The key of each secret in the project, from a listing of names and labels;
   * no value is read. A secret with the store-key label whose name
   * decodeStoreKey reads is that key, and every other secret is the plain key
   * `secret/<name>`. Keys are selected by the caller on the decoded key, not
   * with the list API's filter, so a selection never depends on how the API
   * matches a name.
   */
  private async listKeys(
    projectId: string,
    token: string,
  ): Promise<Array<{ key: string; secretName: string }>> {
    const keys: Array<{ key: string; secretName: string }> = [];
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
        return keys;
      }

      const body = await response.json() as {
        secrets?: Array<{ name?: string; labels?: Record<string, string> }>;
        nextPageToken?: string;
      };

      const secrets = body.secrets ?? [];
      for (const secret of secrets) {
        if (!secret.name) continue;

        // Extract secret name from full resource path
        // Format: projects/{project}/secrets/{name}
        const parts = secret.name.split('/');
        const secretName = parts[parts.length - 1];

        const storedKey = secret.labels?.[STORE_KEY_LABEL] === STORE_KEY_LABEL_VALUE
          ? decodeStoreKey(secretName)
          : undefined;
        keys.push({ key: storedKey ?? `${PLAIN_KEY_PREFIX}${secretName}`, secretName });
      }

      pageToken = body.nextPageToken;
    } while (pageToken);

    return keys;
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
