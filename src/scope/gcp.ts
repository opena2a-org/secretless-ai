/**
 * GCP scope discovery via Cloud Resource Manager testIamPermissions.
 *
 * Uses the testIamPermissions API to discover what IAM permissions a service
 * account key actually holds. This API requires ZERO additional permissions --
 * just a valid service account credential. It is the lowest-friction
 * self-inspection API in any cloud provider.
 *
 * Zero SDK dependency -- uses raw HTTPS with native fetch and JWT self-signing
 * via Node.js built-in crypto.
 */

import * as crypto from 'crypto';
import type { ScopeProvider } from './types';

/**
 * AI-relevant GCP permissions to probe.
 *
 * All permissions are validated against the Cloud Resource Manager
 * testIamPermissions API (project-level). The generativelanguage.*
 * permissions are NOT valid for this endpoint and will cause 400 errors.
 */
const AI_RELEVANT_PERMISSIONS = [
  // Vertex AI / AI Platform
  'aiplatform.endpoints.predict',
  'aiplatform.endpoints.list',
  'aiplatform.models.list',
  'aiplatform.models.get',
  'aiplatform.datasets.list',
  // Legacy ML Engine
  'ml.models.predict',
  'ml.models.list',
  // Storage (training data, model artifacts)
  'storage.objects.get',
  'storage.objects.list',
  'storage.buckets.list',
  // BigQuery (data pipelines)
  'bigquery.jobs.create',
  'bigquery.tables.getData',
  // Secret Manager
  'secretmanager.versions.access',
  // Compute / deployment
  'cloudfunctions.functions.invoke',
  'run.routes.invoke',
  // IAM (privilege escalation indicators)
  'iam.serviceAccounts.actAs',
  'iam.serviceAccounts.list',
  'iam.roles.list',
  // Project-level
  'resourcemanager.projects.get',
  'resourcemanager.projects.getIamPolicy',
  'serviceusage.services.list',
  // Observability
  'logging.logEntries.list',
  'monitoring.timeSeries.list',
];

const GCP_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const CRM_BASE_URL = 'https://cloudresourcemanager.googleapis.com/v1/projects';
const TOKEN_LIFETIME_SECONDS = 300; // 5 minutes
const REQUEST_TIMEOUT_MS = 10_000;

interface ServiceAccountKey {
  type: string;
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  client_id: string;
  auth_uri: string;
  token_uri: string;
}

/**
 * Parse a GCP service account key JSON string.
 * Validates required fields.
 */
export function parseServiceAccountKey(credential: string): ServiceAccountKey {
  let parsed: unknown;
  try {
    parsed = JSON.parse(credential);
  } catch {
    throw new Error('Invalid JSON: credential is not valid JSON');
  }

  const key = parsed as Record<string, unknown>;
  if (key.type !== 'service_account') {
    throw new Error(`Expected type "service_account", got "${key.type}"`);
  }
  if (typeof key.project_id !== 'string' || !key.project_id) {
    throw new Error('Missing or empty project_id');
  }
  if (typeof key.private_key !== 'string' || !key.private_key) {
    throw new Error('Missing or empty private_key');
  }
  if (typeof key.client_email !== 'string' || !key.client_email) {
    throw new Error('Missing or empty client_email');
  }

  return key as unknown as ServiceAccountKey;
}

/**
 * Create a signed JWT for Google OAuth2 service account authentication.
 * Uses RS256 (RSA-SHA256) signing with Node.js built-in crypto.
 */
export function createSignedJwt(
  clientEmail: string,
  privateKey: string,
  scope: string,
): string {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: 'RS256',
    typ: 'JWT',
  };

  const payload = {
    iss: clientEmail,
    sub: clientEmail,
    aud: GCP_TOKEN_ENDPOINT,
    iat: now,
    exp: now + TOKEN_LIFETIME_SECONDS,
    scope,
  };

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const unsignedToken = `${headerB64}.${payloadB64}`;

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(unsignedToken);
  const signature = sign.sign(privateKey);
  const signatureB64 = base64UrlEncodeBuffer(signature);

  return `${unsignedToken}.${signatureB64}`;
}

/**
 * Exchange a signed JWT for a Google OAuth2 access token.
 */
async function getAccessToken(
  clientEmail: string,
  privateKey: string,
  signal?: AbortSignal,
): Promise<string> {
  const jwt = createSignedJwt(
    clientEmail,
    privateKey,
    'https://www.googleapis.com/auth/cloud-platform',
  );

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
  });

  const response = await fetch(GCP_TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    signal,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Token exchange failed (HTTP ${response.status}): ${text}`);
  }

  const data = await response.json() as { access_token?: string };
  if (!data.access_token) {
    throw new Error('Token response missing access_token');
  }

  return data.access_token;
}

/**
 * Call testIamPermissions on a GCP project to discover which permissions
 * the service account holds.
 */
async function testIamPermissions(
  projectId: string,
  accessToken: string,
  permissions: string[],
  signal?: AbortSignal,
): Promise<string[]> {
  const url = `${CRM_BASE_URL}/${projectId}:testIamPermissions`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'User-Agent': 'secretless-ai-scope/1.0',
    },
    body: JSON.stringify({ permissions }),
    signal,
  });

  if (response.status === 403) {
    throw new Error('Service account does not have access to the project');
  }

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`testIamPermissions failed (HTTP ${response.status}): ${text}`);
  }

  const data = await response.json() as { permissions?: string[] };
  return data.permissions ?? [];
}

/**
 * GCP scope discovery provider.
 *
 * Takes a service account key JSON string and discovers the effective
 * IAM permissions the service account holds on its project.
 */
export class GCPScopeProvider implements ScopeProvider {
  readonly name = 'gcp';

  private key: ServiceAccountKey | null = null;
  private credential: string;

  constructor(credential: string) {
    this.credential = credential;
  }

  async discover(credential?: string): Promise<string[]> {
    const cred = credential ?? this.credential;
    const key = parseServiceAccountKey(cred);
    this.key = key;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const accessToken = await getAccessToken(
        key.client_email,
        key.private_key,
        controller.signal,
      );

      const grantedPermissions = await testIamPermissions(
        key.project_id,
        accessToken,
        AI_RELEVANT_PERMISSIONS,
        controller.signal,
      );

      return grantedPermissions.sort();
    } finally {
      clearTimeout(timeout);
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      const key = this.key ?? parseServiceAccountKey(this.credential);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      try {
        await getAccessToken(key.client_email, key.private_key, controller.signal);
        return true;
      } finally {
        clearTimeout(timeout);
      }
    } catch {
      return false;
    }
  }
}

// --- Utility functions ---

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
