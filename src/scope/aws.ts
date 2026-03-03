/**
 * AWS scope discovery via IAM policy introspection.
 *
 * Uses STS GetCallerIdentity, IAM GetUser, ListAttachedUserPolicies,
 * GetPolicy, and GetPolicyVersion to discover what IAM permissions an
 * AWS access key actually holds. Filters results to AI-relevant permissions.
 *
 * Zero SDK dependency -- uses raw HTTPS with SigV4 signing via Node.js
 * built-in crypto.
 */

import * as crypto from 'crypto';
import type { ScopeProvider } from './types';

/**
 * AI-relevant AWS permissions to detect in policy documents.
 * Includes Bedrock, SageMaker, S3, Lambda, Secrets Manager, IAM, STS, and KMS.
 */
const AI_RELEVANT_PERMISSIONS = [
  // Bedrock (managed AI models)
  'bedrock:InvokeModel',
  'bedrock:InvokeModelWithResponseStream',
  'bedrock:ListFoundationModels',
  // SageMaker (custom AI models)
  'sagemaker:InvokeEndpoint',
  'sagemaker:ListModels',
  'sagemaker:CreateModel',
  // S3 (training data, model artifacts)
  's3:GetObject',
  's3:PutObject',
  's3:ListBucket',
  // Lambda (serverless compute)
  'lambda:InvokeFunction',
  'lambda:ListFunctions',
  // Secrets Manager
  'secretsmanager:GetSecretValue',
  'secretsmanager:ListSecrets',
  // IAM (privilege escalation indicators)
  'iam:PassRole',
  'iam:CreateRole',
  'iam:AttachRolePolicy',
  // STS
  'sts:AssumeRole',
  // KMS (encryption)
  'kms:Decrypt',
  'kms:Encrypt',
];

const REQUEST_TIMEOUT_MS = 10_000;

interface CallerIdentity {
  account: string;
  arn: string;
  userId: string;
}

interface PolicyVersion {
  document: string;
  versionId: string;
  isDefaultVersion: boolean;
}

/**
 * Sign an AWS API request using Signature Version 4.
 *
 * Implements the AWS SigV4 signing algorithm using Node.js built-in crypto.
 * Returns a new headers object with Authorization, X-Amz-Date, and
 * optionally X-Amz-Security-Token headers added.
 */
export function signV4(
  method: string,
  url: URL,
  headers: Record<string, string>,
  body: string,
  accessKeyId: string,
  secretAccessKey: string,
  region: string,
  service: string,
  sessionToken?: string,
): Record<string, string> {
  const now = new Date();
  const dateStamp = now.toISOString().replace(/[-:]/g, '').slice(0, 8);
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');

  const signedHeaders: Record<string, string> = {
    ...headers,
    host: url.hostname,
    'x-amz-date': amzDate,
  };

  if (sessionToken) {
    signedHeaders['x-amz-security-token'] = sessionToken;
  }

  // Sort header keys for canonical headers
  const sortedHeaderKeys = Object.keys(signedHeaders)
    .map(k => k.toLowerCase())
    .sort();

  const canonicalHeaders = sortedHeaderKeys
    .map(k => `${k}:${signedHeaders[Object.keys(signedHeaders).find(
      hk => hk.toLowerCase() === k,
    )!]!.trim()}`)
    .join('\n') + '\n';

  const signedHeadersStr = sortedHeaderKeys.join(';');

  const payloadHash = crypto.createHash('sha256').update(body).digest('hex');

  // Canonical request
  const canonicalPath = url.pathname || '/';
  const canonicalQuery = url.searchParams.toString();
  const canonicalRequest = [
    method,
    canonicalPath,
    canonicalQuery,
    canonicalHeaders,
    signedHeadersStr,
    payloadHash,
  ].join('\n');

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');

  // Derive signing key
  const kDate = hmacSha256(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, 'aws4_request');

  const signature = hmacSha256Hex(kSigning, stringToSign);

  const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

  const result: Record<string, string> = {
    ...signedHeaders,
    Authorization: authHeader,
  };

  return result;
}

/**
 * Call AWS STS GetCallerIdentity to verify credentials and retrieve
 * account ID and user ARN.
 */
async function getCallerIdentity(
  accessKeyId: string,
  secretAccessKey: string,
  region: string,
  sessionToken?: string,
  signal?: AbortSignal,
): Promise<CallerIdentity> {
  const url = new URL('https://sts.amazonaws.com/');
  const body = 'Action=GetCallerIdentity&Version=2011-06-15';

  const headers = signV4(
    'POST',
    url,
    { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'secretless-ai-scope/1.0' },
    body,
    accessKeyId,
    secretAccessKey,
    region,
    'sts',
    sessionToken,
  );

  const response = await fetch(url.toString(), {
    method: 'POST',
    headers,
    body,
    signal,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`STS GetCallerIdentity failed (HTTP ${response.status}): ${text}`);
  }

  const xml = await response.text();
  const account = extractXmlValue(xml, 'Account');
  const arn = extractXmlValue(xml, 'Arn');
  const userId = extractXmlValue(xml, 'UserId');

  if (!account || !arn) {
    throw new Error('GetCallerIdentity response missing Account or Arn');
  }

  return { account, arn, userId: userId ?? '' };
}

/**
 * Call IAM GetUser to get the user name from the ARN.
 */
async function getUser(
  accessKeyId: string,
  secretAccessKey: string,
  region: string,
  sessionToken?: string,
  signal?: AbortSignal,
): Promise<string> {
  const url = new URL('https://iam.amazonaws.com/');
  const body = 'Action=GetUser&Version=2010-05-08';

  const headers = signV4(
    'POST',
    url,
    { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'secretless-ai-scope/1.0' },
    body,
    accessKeyId,
    secretAccessKey,
    region,
    'iam',
    sessionToken,
  );

  const response = await fetch(url.toString(), {
    method: 'POST',
    headers,
    body,
    signal,
  });

  if (response.status === 403) {
    // User may not have iam:GetUser permission -- not fatal
    return '';
  }

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`IAM GetUser failed (HTTP ${response.status}): ${text}`);
  }

  const xml = await response.text();
  return extractXmlValue(xml, 'UserName') ?? '';
}

/**
 * List attached managed policies for a user.
 */
async function listAttachedUserPolicies(
  userName: string,
  accessKeyId: string,
  secretAccessKey: string,
  region: string,
  sessionToken?: string,
  signal?: AbortSignal,
): Promise<string[]> {
  const url = new URL('https://iam.amazonaws.com/');
  const body = `Action=ListAttachedUserPolicies&UserName=${encodeURIComponent(userName)}&Version=2010-05-08`;

  const headers = signV4(
    'POST',
    url,
    { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'secretless-ai-scope/1.0' },
    body,
    accessKeyId,
    secretAccessKey,
    region,
    'iam',
    sessionToken,
  );

  const response = await fetch(url.toString(), {
    method: 'POST',
    headers,
    body,
    signal,
  });

  if (response.status === 403) {
    return [];
  }

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`IAM ListAttachedUserPolicies failed (HTTP ${response.status}): ${text}`);
  }

  const xml = await response.text();
  return extractXmlValues(xml, 'PolicyArn');
}

/**
 * Get the default policy version ID for a managed policy.
 */
async function getPolicy(
  policyArn: string,
  accessKeyId: string,
  secretAccessKey: string,
  region: string,
  sessionToken?: string,
  signal?: AbortSignal,
): Promise<string> {
  const url = new URL('https://iam.amazonaws.com/');
  const body = `Action=GetPolicy&PolicyArn=${encodeURIComponent(policyArn)}&Version=2010-05-08`;

  const headers = signV4(
    'POST',
    url,
    { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'secretless-ai-scope/1.0' },
    body,
    accessKeyId,
    secretAccessKey,
    region,
    'iam',
    sessionToken,
  );

  const response = await fetch(url.toString(), {
    method: 'POST',
    headers,
    body,
    signal,
  });

  if (response.status === 403) {
    return '';
  }

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`IAM GetPolicy failed (HTTP ${response.status}): ${text}`);
  }

  const xml = await response.text();
  return extractXmlValue(xml, 'DefaultVersionId') ?? '';
}

/**
 * Get the policy document for a specific policy version.
 */
async function getPolicyVersion(
  policyArn: string,
  versionId: string,
  accessKeyId: string,
  secretAccessKey: string,
  region: string,
  sessionToken?: string,
  signal?: AbortSignal,
): Promise<PolicyVersion> {
  const url = new URL('https://iam.amazonaws.com/');
  const body = `Action=GetPolicyVersion&PolicyArn=${encodeURIComponent(policyArn)}&VersionId=${encodeURIComponent(versionId)}&Version=2010-05-08`;

  const headers = signV4(
    'POST',
    url,
    { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'secretless-ai-scope/1.0' },
    body,
    accessKeyId,
    secretAccessKey,
    region,
    'iam',
    sessionToken,
  );

  const response = await fetch(url.toString(), {
    method: 'POST',
    headers,
    body,
    signal,
  });

  if (response.status === 403) {
    return { document: '', versionId, isDefaultVersion: false };
  }

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`IAM GetPolicyVersion failed (HTTP ${response.status}): ${text}`);
  }

  const xml = await response.text();
  const encodedDocument = extractXmlValue(xml, 'Document') ?? '';
  const document = decodeURIComponent(encodedDocument);
  const isDefault = extractXmlValue(xml, 'IsDefaultVersion') === 'true';

  return { document, versionId, isDefaultVersion: isDefault };
}

/**
 * Extract actions from a policy document and filter to AI-relevant ones.
 * Handles wildcards (e.g., "bedrock:*", "s3:*", "*").
 */
export function extractAiRelevantActions(policyDocument: string): string[] {
  if (!policyDocument) return [];

  let policy: { Statement?: Array<{ Effect?: string; Action?: string | string[] }> };
  try {
    policy = JSON.parse(policyDocument);
  } catch {
    return [];
  }

  if (!policy.Statement || !Array.isArray(policy.Statement)) {
    return [];
  }

  const matched = new Set<string>();

  for (const statement of policy.Statement) {
    if (statement.Effect !== 'Allow') continue;

    const actions = Array.isArray(statement.Action)
      ? statement.Action
      : statement.Action ? [statement.Action] : [];

    for (const action of actions) {
      if (action === '*') {
        // Full admin -- all AI-relevant permissions apply
        for (const perm of AI_RELEVANT_PERMISSIONS) {
          matched.add(perm);
        }
        continue;
      }

      // Check for service-level wildcards like "bedrock:*"
      if (action.endsWith(':*')) {
        const servicePrefix = action.slice(0, -1); // e.g., "bedrock:"
        for (const perm of AI_RELEVANT_PERMISSIONS) {
          if (perm.startsWith(servicePrefix)) {
            matched.add(perm);
          }
        }
        continue;
      }

      // Check for suffix wildcards like "s3:Get*"
      if (action.endsWith('*')) {
        const prefix = action.slice(0, -1);
        for (const perm of AI_RELEVANT_PERMISSIONS) {
          if (perm.startsWith(prefix)) {
            matched.add(perm);
          }
        }
        continue;
      }

      // Exact match
      if (AI_RELEVANT_PERMISSIONS.includes(action)) {
        matched.add(action);
      }
    }
  }

  return Array.from(matched).sort();
}

/**
 * AWS scope discovery provider.
 *
 * Reads AWS credentials from environment variables and discovers
 * IAM permissions by introspecting attached user policies.
 */
export class AWSScopeProvider implements ScopeProvider {
  readonly name = 'aws';

  private accessKeyId: string;
  private secretAccessKey: string;
  private sessionToken?: string;
  private region: string;

  constructor(
    accessKeyId?: string,
    secretAccessKey?: string,
    sessionToken?: string,
    region?: string,
  ) {
    this.accessKeyId = accessKeyId ?? process.env.AWS_ACCESS_KEY_ID ?? '';
    this.secretAccessKey = secretAccessKey ?? process.env.AWS_SECRET_ACCESS_KEY ?? '';
    this.sessionToken = sessionToken ?? process.env.AWS_SESSION_TOKEN;
    this.region = region ?? process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION ?? 'us-east-1';
  }

  async discover(): Promise<string[]> {
    if (!this.accessKeyId || !this.secretAccessKey) {
      throw new Error(
        'AWS credentials not configured. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.',
      );
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      // Step 1: Verify credentials and get identity
      const identity = await getCallerIdentity(
        this.accessKeyId,
        this.secretAccessKey,
        this.region,
        this.sessionToken,
        controller.signal,
      );

      // Step 2: Get user name from IAM
      let userName = '';
      // Extract username from ARN (arn:aws:iam::123456789012:user/username)
      const arnMatch = identity.arn.match(/:user\/(.+)$/);
      if (arnMatch) {
        userName = arnMatch[1];
      }

      // If we could not extract from ARN, try GetUser
      if (!userName) {
        userName = await getUser(
          this.accessKeyId,
          this.secretAccessKey,
          this.region,
          this.sessionToken,
          controller.signal,
        );
      }

      if (!userName) {
        // Cannot determine user name -- return empty (might be a role, not a user)
        return [];
      }

      // Step 3: List attached policies
      const policyArns = await listAttachedUserPolicies(
        userName,
        this.accessKeyId,
        this.secretAccessKey,
        this.region,
        this.sessionToken,
        controller.signal,
      );

      if (policyArns.length === 0) {
        return [];
      }

      // Step 4: For each policy, get the policy document and extract actions
      const allPermissions = new Set<string>();

      for (const policyArn of policyArns) {
        const defaultVersionId = await getPolicy(
          policyArn,
          this.accessKeyId,
          this.secretAccessKey,
          this.region,
          this.sessionToken,
          controller.signal,
        );

        if (!defaultVersionId) continue;

        const version = await getPolicyVersion(
          policyArn,
          defaultVersionId,
          this.accessKeyId,
          this.secretAccessKey,
          this.region,
          this.sessionToken,
          controller.signal,
        );

        const actions = extractAiRelevantActions(version.document);
        for (const action of actions) {
          allPermissions.add(action);
        }
      }

      return Array.from(allPermissions).sort();
    } finally {
      clearTimeout(timeout);
    }
  }

  async healthCheck(): Promise<boolean> {
    if (!this.accessKeyId || !this.secretAccessKey) return false;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      try {
        await getCallerIdentity(
          this.accessKeyId,
          this.secretAccessKey,
          this.region,
          this.sessionToken,
          controller.signal,
        );
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

function hmacSha256(key: string | Buffer, data: string): Buffer {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function hmacSha256Hex(key: Buffer, data: string): string {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

/**
 * Extract a single XML element value by tag name.
 * Simple regex-based extraction -- sufficient for AWS response parsing.
 */
function extractXmlValue(xml: string, tagName: string): string | null {
  const match = xml.match(new RegExp(`<${tagName}>([^<]*)</${tagName}>`));
  return match ? match[1] : null;
}

/**
 * Extract all XML element values by tag name.
 */
function extractXmlValues(xml: string, tagName: string): string[] {
  const values: string[] = [];
  const regex = new RegExp(`<${tagName}>([^<]*)</${tagName}>`, 'g');
  let match: RegExpExecArray | null;
  while ((match = regex.exec(xml)) !== null) {
    values.push(match[1]);
  }
  return values;
}
