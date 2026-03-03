import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AWSScopeProvider, signV4, extractAiRelevantActions } from './aws';

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const FAKE_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const FAKE_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const FAKE_SESSION_TOKEN = 'FwoGZXIvYXdzEBYaDHqa0AP84T9EXAMPLE';

function stsGetCallerIdentityXml(account = '123456789012', arn = 'arn:aws:iam::123456789012:user/testuser'): string {
  return `<GetCallerIdentityResponse>
    <GetCallerIdentityResult>
      <Account>${account}</Account>
      <Arn>${arn}</Arn>
      <UserId>AIDACKCEVSQ6C2EXAMPLE</UserId>
    </GetCallerIdentityResult>
  </GetCallerIdentityResponse>`;
}

function iamGetUserXml(userName = 'testuser'): string {
  return `<GetUserResponse>
    <GetUserResult>
      <User>
        <UserName>${userName}</UserName>
        <UserId>AIDACKCEVSQ6C2EXAMPLE</UserId>
        <Arn>arn:aws:iam::123456789012:user/${userName}</Arn>
      </User>
    </GetUserResult>
  </GetUserResponse>`;
}

function iamListAttachedPoliciesXml(arns: string[]): string {
  const members = arns.map(a =>
    `<member><PolicyArn>${a}</PolicyArn><PolicyName>policy</PolicyName></member>`
  ).join('');
  return `<ListAttachedUserPoliciesResponse>
    <ListAttachedUserPoliciesResult>
      <AttachedPolicies>${members}</AttachedPolicies>
    </ListAttachedUserPoliciesResult>
  </ListAttachedUserPoliciesResponse>`;
}

function iamGetPolicyXml(versionId = 'v1'): string {
  return `<GetPolicyResponse>
    <GetPolicyResult>
      <Policy>
        <DefaultVersionId>${versionId}</DefaultVersionId>
      </Policy>
    </GetPolicyResult>
  </GetPolicyResponse>`;
}

function iamGetPolicyVersionXml(document: string): string {
  return `<GetPolicyVersionResponse>
    <GetPolicyVersionResult>
      <PolicyVersion>
        <Document>${encodeURIComponent(document)}</Document>
        <VersionId>v1</VersionId>
        <IsDefaultVersion>true</IsDefaultVersion>
      </PolicyVersion>
    </GetPolicyVersionResult>
  </GetPolicyVersionResponse>`;
}

describe('signV4', () => {
  it('produces valid Authorization header format', () => {
    const url = new URL('https://sts.amazonaws.com/');
    const headers = signV4(
      'POST',
      url,
      { 'Content-Type': 'application/x-www-form-urlencoded' },
      'Action=GetCallerIdentity&Version=2011-06-15',
      FAKE_ACCESS_KEY,
      FAKE_SECRET_KEY,
      'us-east-1',
      'sts',
    );

    expect(headers.Authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIA/);
    expect(headers.Authorization).toContain('SignedHeaders=');
    expect(headers.Authorization).toContain('Signature=');
    expect(headers['x-amz-date']).toMatch(/^\d{8}T\d{6}Z$/);
    expect(headers.host).toBe('sts.amazonaws.com');
  });

  it('includes session token header when provided', () => {
    const url = new URL('https://sts.amazonaws.com/');
    const headers = signV4(
      'POST',
      url,
      { 'Content-Type': 'application/x-www-form-urlencoded' },
      'Action=GetCallerIdentity&Version=2011-06-15',
      'ASIAIOSEXAMPLE1234567',
      FAKE_SECRET_KEY,
      'us-east-1',
      'sts',
      FAKE_SESSION_TOKEN,
    );

    expect(headers['x-amz-security-token']).toBe(FAKE_SESSION_TOKEN);
    expect(headers.Authorization).toContain('x-amz-security-token');
  });
});

describe('extractAiRelevantActions', () => {
  it('extracts exact-match AI-relevant actions', () => {
    const doc = JSON.stringify({
      Statement: [{
        Effect: 'Allow',
        Action: ['bedrock:InvokeModel', 's3:GetObject', 'ec2:DescribeInstances'],
        Resource: '*',
      }],
    });
    const result = extractAiRelevantActions(doc);
    expect(result).toEqual(['bedrock:InvokeModel', 's3:GetObject']);
  });

  it('expands service-level wildcards', () => {
    const doc = JSON.stringify({
      Statement: [{
        Effect: 'Allow',
        Action: 'bedrock:*',
        Resource: '*',
      }],
    });
    const result = extractAiRelevantActions(doc);
    expect(result).toContain('bedrock:InvokeModel');
    expect(result).toContain('bedrock:InvokeModelWithResponseStream');
    expect(result).toContain('bedrock:ListFoundationModels');
    expect(result).toHaveLength(3);
  });

  it('expands full admin wildcard to all AI permissions', () => {
    const doc = JSON.stringify({
      Statement: [{
        Effect: 'Allow',
        Action: '*',
        Resource: '*',
      }],
    });
    const result = extractAiRelevantActions(doc);
    expect(result.length).toBeGreaterThan(10);
    expect(result).toContain('bedrock:InvokeModel');
    expect(result).toContain('kms:Decrypt');
  });

  it('expands prefix wildcards like s3:Get*', () => {
    const doc = JSON.stringify({
      Statement: [{
        Effect: 'Allow',
        Action: 's3:Get*',
        Resource: '*',
      }],
    });
    const result = extractAiRelevantActions(doc);
    expect(result).toEqual(['s3:GetObject']);
  });

  it('ignores Deny statements', () => {
    const doc = JSON.stringify({
      Statement: [{
        Effect: 'Deny',
        Action: '*',
        Resource: '*',
      }],
    });
    const result = extractAiRelevantActions(doc);
    expect(result).toEqual([]);
  });

  it('returns empty for empty policy document', () => {
    expect(extractAiRelevantActions('')).toEqual([]);
  });

  it('returns empty for invalid JSON', () => {
    expect(extractAiRelevantActions('not json')).toEqual([]);
  });

  it('returns empty for policy with no Statement', () => {
    expect(extractAiRelevantActions(JSON.stringify({ Version: '2012-10-17' }))).toEqual([]);
  });
});

describe('AWSScopeProvider', () => {
  it('healthCheck succeeds with valid GetCallerIdentity response', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => stsGetCallerIdentityXml(),
    });

    const provider = new AWSScopeProvider(FAKE_ACCESS_KEY, FAKE_SECRET_KEY);
    const healthy = await provider.healthCheck();
    expect(healthy).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('healthCheck fails with network error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const provider = new AWSScopeProvider(FAKE_ACCESS_KEY, FAKE_SECRET_KEY);
    const healthy = await provider.healthCheck();
    expect(healthy).toBe(false);
  });

  it('healthCheck returns false when credentials are empty', async () => {
    const provider = new AWSScopeProvider('', '');
    const healthy = await provider.healthCheck();
    expect(healthy).toBe(false);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('discover returns permissions from policy documents', async () => {
    const policyDoc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [{
        Effect: 'Allow',
        Action: ['bedrock:InvokeModel', 's3:GetObject', 'ec2:RunInstances'],
        Resource: '*',
      }],
    });

    // 1. GetCallerIdentity
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => stsGetCallerIdentityXml(),
    });
    // 2. ListAttachedUserPolicies
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => iamListAttachedPoliciesXml(['arn:aws:iam::123456789012:policy/TestPolicy']),
    });
    // 3. GetPolicy
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => iamGetPolicyXml('v1'),
    });
    // 4. GetPolicyVersion
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => iamGetPolicyVersionXml(policyDoc),
    });

    const provider = new AWSScopeProvider(FAKE_ACCESS_KEY, FAKE_SECRET_KEY);
    const permissions = await provider.discover();
    expect(permissions).toEqual(['bedrock:InvokeModel', 's3:GetObject']);
    // ec2:RunInstances is not AI-relevant, should not appear
    expect(permissions).not.toContain('ec2:RunInstances');
  });

  it('discover handles wildcard actions (bedrock:*)', async () => {
    const policyDoc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Action: 'bedrock:*', Resource: '*' }],
    });

    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => stsGetCallerIdentityXml(),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => iamListAttachedPoliciesXml(['arn:aws:iam::123456789012:policy/BedrockFull']),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => iamGetPolicyXml('v1'),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => iamGetPolicyVersionXml(policyDoc),
    });

    const provider = new AWSScopeProvider(FAKE_ACCESS_KEY, FAKE_SECRET_KEY);
    const permissions = await provider.discover();
    expect(permissions).toContain('bedrock:InvokeModel');
    expect(permissions).toContain('bedrock:InvokeModelWithResponseStream');
    expect(permissions).toContain('bedrock:ListFoundationModels');
  });

  it('discover handles denied IAM calls gracefully (returns partial results)', async () => {
    // GetCallerIdentity succeeds
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => stsGetCallerIdentityXml(),
    });
    // ListAttachedUserPolicies denied
    mockFetch.mockResolvedValueOnce({
      ok: false, status: 403,
      text: async () => 'AccessDenied',
    });

    const provider = new AWSScopeProvider(FAKE_ACCESS_KEY, FAKE_SECRET_KEY);
    const permissions = await provider.discover();
    // Should return empty array rather than throwing
    expect(permissions).toEqual([]);
  });

  it('handles STS temporary credentials (with session token)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => stsGetCallerIdentityXml('123456789012', 'arn:aws:sts::123456789012:assumed-role/test-role/session'),
    });
    // GetUser for role-based credential -- returns 403
    mockFetch.mockResolvedValueOnce({
      ok: false, status: 403,
      text: async () => 'AccessDenied',
    });

    const provider = new AWSScopeProvider(
      'ASIAIOSEXAMPLE1234567',
      FAKE_SECRET_KEY,
      FAKE_SESSION_TOKEN,
    );
    const permissions = await provider.discover();
    // Role-based credentials without user path in ARN go to GetUser which returns 403
    // Then userName is empty, so returns []
    expect(permissions).toEqual([]);

    // Verify session token was included in request
    const [, requestOpts] = mockFetch.mock.calls[0];
    expect(requestOpts.headers['x-amz-security-token']).toBe(FAKE_SESSION_TOKEN);
  });

  it('handles expired credentials', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      text: async () => '<ErrorResponse><Error><Code>ExpiredToken</Code><Message>The security token included in the request is expired</Message></Error></ErrorResponse>',
    });

    const provider = new AWSScopeProvider(FAKE_ACCESS_KEY, FAKE_SECRET_KEY);
    await expect(provider.discover()).rejects.toThrow('STS GetCallerIdentity failed');
  });

  it('handles region from constructor', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => stsGetCallerIdentityXml(),
    });

    const provider = new AWSScopeProvider(FAKE_ACCESS_KEY, FAKE_SECRET_KEY, undefined, 'eu-west-1');
    await provider.healthCheck();

    // Verify the request was made (region affects SigV4 signing, not URL for global STS)
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('empty policy documents return empty permissions', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => stsGetCallerIdentityXml(),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => iamListAttachedPoliciesXml(['arn:aws:iam::123456789012:policy/EmptyPolicy']),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => iamGetPolicyXml('v1'),
    });
    // GetPolicyVersion returns empty document
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => iamGetPolicyVersionXml(''),
    });

    const provider = new AWSScopeProvider(FAKE_ACCESS_KEY, FAKE_SECRET_KEY);
    const permissions = await provider.discover();
    expect(permissions).toEqual([]);
  });

  it('throws when credentials are not configured', async () => {
    const provider = new AWSScopeProvider('', '');
    await expect(provider.discover()).rejects.toThrow('AWS credentials not configured');
  });

  it('discover returns empty when no policies attached', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => stsGetCallerIdentityXml(),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true, status: 200,
      text: async () => iamListAttachedPoliciesXml([]),
    });

    const provider = new AWSScopeProvider(FAKE_ACCESS_KEY, FAKE_SECRET_KEY);
    const permissions = await provider.discover();
    expect(permissions).toEqual([]);
  });
});
