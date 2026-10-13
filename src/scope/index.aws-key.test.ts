/**
 * `scope discover` / `scope check` on an AWS credential must profile THAT
 * credential's key, never whatever key the environment holds.
 *
 * The stored value of an AWS credential is its access key ID. Discovery used to
 * build the provider with no arguments, so it signed every request with the
 * environment's AWS_ACCESS_KEY_ID, and the permissions of that other principal
 * were saved as the named credential's baseline. A later scope check then
 * compared against the wrong identity's permissions.
 */

import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest';
import * as fs from 'fs';

const home = vi.hoisted(() => ({ dir: '' }));

// Baselines are written under os.homedir(), resolved when the module loads, so
// the temporary home is created inside the mock factory, before that happens.
vi.mock('os', async () => {
  const actual = await vi.importActual<typeof import('os')>('os');
  const realFs = await vi.importActual<typeof import('fs')>('fs');
  const realPath = await vi.importActual<typeof import('path')>('path');
  home.dir = realFs.mkdtempSync(realPath.join(actual.tmpdir(), 'scope-aws-key-'));
  return { ...actual, homedir: () => home.dir };
});

import { discoverScope, loadBaseline, resetBaseline, AWSScopeProvider } from './index';

// Assembled at runtime: shaped like access key IDs so the provider is detected,
// without a literal key in the file.
const NAMED_KEY_ID = 'AK' + 'IA' + 'NAMEDKEY00000001';
const AMBIENT_KEY_ID = 'AK' + 'IA' + 'AMBIENTKEY000002';
const NOT_A_SECRET = 'not-a-real-secret';

const AWS_ENV = [
  'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
  'AWS_REGION', 'AWS_DEFAULT_REGION',
];

/**
 * Answers the IAM/STS calls discovery makes as one IAM user holding one policy
 * that allows bedrock:InvokeModel, and records the Authorization header of
 * every request so a test can see which access key signed it.
 */
const signedWith: string[] = [];
const fetchMock = vi.fn(async (_url: string, init: { headers: Record<string, string>; body: string }) => {
  const auth = init.headers.Authorization ?? '';
  signedWith.push(/Credential=([^/]+)\//.exec(auth)?.[1] ?? '');
  const action = /Action=([A-Za-z]+)/.exec(init.body)?.[1];
  const doc = JSON.stringify({ Statement: [{ Effect: 'Allow', Action: 'bedrock:InvokeModel', Resource: '*' }] });
  const xml: Record<string, string> = {
    GetCallerIdentity: '<Account>111122223333</Account><Arn>arn:aws:iam::111122223333:user/someone</Arn><UserId>u</UserId>',
    ListAttachedUserPolicies: '<PolicyArn>arn:aws:iam::111122223333:policy/p</PolicyArn>',
    GetPolicy: '<DefaultVersionId>v1</DefaultVersionId>',
    GetPolicyVersion: `<Document>${encodeURIComponent(doc)}</Document><VersionId>v1</VersionId><IsDefaultVersion>true</IsDefaultVersion>`,
  };
  return { ok: true, status: 200, text: async () => xml[action ?? ''] ?? '' };
});

beforeEach(() => {
  signedWith.length = 0;
  fetchMock.mockClear();
  vi.stubGlobal('fetch', fetchMock);
  for (const name of AWS_ENV) vi.stubEnv(name, undefined);
  resetBaseline('NAMED_AWS_KEY');
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

afterAll(() => {
  fs.rmSync(home.dir, { recursive: true, force: true });
});

describe('scope discovery of an AWS credential', () => {
  it('refuses, and saves no baseline, when the environment key pair belongs to a different access key', async () => {
    vi.stubEnv('AWS_ACCESS_KEY_ID', AMBIENT_KEY_ID);
    vi.stubEnv('AWS_SECRET_ACCESS_KEY', NOT_A_SECRET);

    await expect(discoverScope('NAMED_AWS_KEY', NAMED_KEY_ID)).rejects.toThrow(
      /AWS_ACCESS_KEY_ID in the environment names a different access key/,
    );
    expect(fetchMock).not.toHaveBeenCalled();
    expect(loadBaseline('NAMED_AWS_KEY')).toBeUndefined();
  });

  it('does not put either access key ID in the refusal', async () => {
    vi.stubEnv('AWS_ACCESS_KEY_ID', AMBIENT_KEY_ID);
    vi.stubEnv('AWS_SECRET_ACCESS_KEY', NOT_A_SECRET);

    const err = await discoverScope('NAMED_AWS_KEY', NAMED_KEY_ID).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).not.toContain(NAMED_KEY_ID);
    expect((err as Error).message).not.toContain(AMBIENT_KEY_ID);
  });

  it('signs every request with the named access key when the environment holds only its secret', async () => {
    vi.stubEnv('AWS_SECRET_ACCESS_KEY', NOT_A_SECRET);

    const result = await discoverScope('NAMED_AWS_KEY', NAMED_KEY_ID);

    expect(result.provider).toBe('aws');
    expect(result.currentPermissions).toEqual(['bedrock:InvokeModel']);
    expect(signedWith.length).toBeGreaterThan(0);
    expect(new Set(signedWith)).toEqual(new Set([NAMED_KEY_ID]));
    expect(loadBaseline('NAMED_AWS_KEY')?.permissions).toEqual(['bedrock:InvokeModel']);
  });

  it('signs with the named access key when the environment names that same key', async () => {
    vi.stubEnv('AWS_ACCESS_KEY_ID', NAMED_KEY_ID);
    vi.stubEnv('AWS_SECRET_ACCESS_KEY', NOT_A_SECRET);

    await discoverScope('NAMED_AWS_KEY', `  ${NAMED_KEY_ID}\n`, { saveAsBaseline: false });

    expect(new Set(signedWith)).toEqual(new Set([NAMED_KEY_ID]));
  });
});

describe('AWSScopeProvider.discover(credential)', () => {
  it('refuses a credential that is not the access key it signs with, before any request', async () => {
    const provider = new AWSScopeProvider(AMBIENT_KEY_ID, NOT_A_SECRET);

    await expect(provider.discover(NAMED_KEY_ID)).rejects.toThrow(/signs with a different access key/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('accepts the access key it signs with', async () => {
    const provider = new AWSScopeProvider(NAMED_KEY_ID, NOT_A_SECRET);

    await expect(provider.discover(NAMED_KEY_ID)).resolves.toEqual(['bedrock:InvokeModel']);
    expect(new Set(signedWith)).toEqual(new Set([NAMED_KEY_ID]));
  });
});
