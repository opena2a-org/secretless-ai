import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { PassThrough } from 'stream';
import { runStatus, runVerify } from './core';
import { runSecret, runSecretSync } from './secrets';
import { runImport } from './env-run';
import { runSetup } from '../setup';
import { exportBundle } from '../bundle-transfer';
import { LocalBackend } from '../backends/local';
import { SecretStore } from '../secret-store';
import type { SecretBackend } from '../backends/types';

// #177: `status` shows which GCP project applies and why; `verify` names the
// project each manifest name resolves from. File reads only: no request.

let root: string;
let originalHome: string | undefined;
let originalKey: string | undefined;

function repo(rel: string, manifest: string): string {
  const dir = path.join(root, rel);
  fs.mkdirSync(path.join(dir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.secretless'), manifest);
  return dir;
}

function captureConsole(): string[] {
  const out: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  return out;
}

function useBackend(backend: string): void {
  const dir = path.join(root, 'home', '.secretless-ai');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ backend, gcp: { projectId: 'personal-proj' } }));
}

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-report-')));
  originalHome = process.env.HOME;
  originalKey = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  process.env.HOME = path.join(root, 'home');
  delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
  vi.stubGlobal('fetch', () => { throw new Error('status and verify must not make a request'); });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  process.env.HOME = originalHome;
  if (originalKey === undefined) delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
  else process.env.GOOGLE_APPLICATION_CREDENTIALS = originalKey;
  fs.rmSync(root, { recursive: true, force: true });
});

describe('status reports the GCP project and why (#177)', () => {
  it('each repository reports its own project in --json', async () => {
    useBackend('gcp-sm');
    const a = repo('org-a/app', 'gcp.projectId: acme-org-a\nDATABASE_URL\n');
    const b = repo('org-b/app', 'DATABASE_URL\n');

    let out = captureConsole();
    await runStatus(a, { json: true });
    expect(JSON.parse(out.join('\n')).gcpProject).toEqual({
      projectId: 'acme-org-a',
      source: 'manifest',
      from: `${path.join(a, '.secretless')} line 1`,
    });

    vi.restoreAllMocks();
    out = captureConsole();
    await runStatus(b, { json: true });
    expect(JSON.parse(out.join('\n')).gcpProject).toMatchObject({ projectId: 'personal-proj', source: 'user-config' });
  });

  it('the human view names the project and the manifest line', async () => {
    useBackend('gcp-sm');
    const a = repo('org-a/app', 'gcp.projectId: acme-org-a\n');
    const out = captureConsole();
    await runStatus(a);
    expect(out.join('\n')).toContain(`✓ GCP project acme-org-a (named by ${path.join(a, '.secretless')} line 1)`);
  });

  it('CONTROL: another backend reports no GCP project', async () => {
    useBackend('vault');
    const out = captureConsole();
    await runStatus(repo('org-a/app', 'gcp.projectId: acme-org-a\n'), { json: true });
    expect(JSON.parse(out.join('\n')).gcpProject).toBeNull();
  });
});

describe('verify names the project per manifest name (#177)', () => {
  it('two repositories each name their own project', () => {
    useBackend('gcp-sm');
    for (const [rel, project] of [['org-a/app', 'acme-org-a'], ['org-b/app', 'acme-org-b']]) {
      const dir = repo(rel, `gcp.projectId: ${project}\nDATABASE_URL\nSENTRY_DSN optional\n`);
      vi.restoreAllMocks();
      const out = captureConsole();
      runVerify(dir);
      const text = out.join('\n');
      expect(text).toContain(`DATABASE_URL  project ${project}`);
      expect(text).toContain(`SENTRY_DSN    project ${project}`);
      expect(text).toContain(`Project ${project} named by ${path.join(dir, '.secretless')} line 1`);
      expect(text).toContain(`Verify access: gcloud secrets list --project ${project} --limit 1`);
    }
  });

  it('an unusable gcp.projectId is shown, not replaced by the user-wide project', () => {
    useBackend('gcp-sm');
    const dir = repo('bad', 'gcp.projectId: ../escape\nDATABASE_URL\n');
    const out = captureConsole();
    runVerify(dir);
    const text = out.join('\n');
    expect(text).toContain(`${path.join(dir, '.secretless')} line 1: gcp.projectId value is not a GCP project id`);
    expect(text).not.toContain('personal-proj');
  });
});

describe('secret set and secret list say when a repository chose the project (#177)', () => {
  // A throwaway service account generated per run, so the real token exchange
  // path signs a JWT; every request is answered here and recorded.
  function gcpStub(): string[] {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keyFile = path.join(root, 'home', 'test-sa.json');
    fs.writeFileSync(keyFile, JSON.stringify({
      type: 'service_account',
      client_email: 'test@example.iam.gserviceaccount.com',
      private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    }));
    process.env.GOOGLE_APPLICATION_CREDENTIALS = keyFile;
    const urls: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      urls.push(String(url));
      if (String(url).includes('/versions/latest:access')) return { ok: false, status: 404, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => ({ access_token: 'test-token', expires_in: 3600, secrets: [] }) };
    });
    return urls;
  }

  it('secret set writes to the repository\'s project and says so', async () => {
    useBackend('gcp-sm');
    const urls = gcpStub();
    const a = repo('org-a/app', 'gcp.projectId: acme-org-a\n');
    vi.spyOn(process, 'cwd').mockReturnValue(a);
    const out = captureConsole();
    expect(await runSecret(['set', 'DATABASE_URL=placeholder-value'])).toBe(0);
    expect(out.join('\n')).toContain(`In GCP project acme-org-a, named by ${path.join(a, '.secretless')} line 1`);
    expect(urls.filter((u) => u.includes('secretmanager'))).toEqual([
      'https://secretmanager.googleapis.com/v1/projects/acme-org-a/secrets?secretId=DATABASE_URL',
      'https://secretmanager.googleapis.com/v1/projects/acme-org-a/secrets/DATABASE_URL:addVersion',
    ]);
  });

  it('CONTROL: a repository that names no project prints as before', async () => {
    useBackend('gcp-sm');
    gcpStub();
    vi.spyOn(process, 'cwd').mockReturnValue(repo('plain', 'DATABASE_URL\n'));
    const out = captureConsole();
    expect(await runSecret(['set', 'DATABASE_URL=placeholder-value'])).toBe(0);
    expect(out.join('\n')).not.toContain('In GCP project');
  });

  it('secret list says the list belongs to this repository', async () => {
    useBackend('gcp-sm');
    gcpStub();
    const a = repo('org-a/app', 'gcp.projectId: acme-org-a\n');
    vi.spyOn(process, 'cwd').mockReturnValue(a);
    const out = captureConsole();
    expect(await runSecret(['list'])).toBe(0);
    expect(out.join('\n')).toContain(
      `Scope: this repository (gcp-sm backend, project acme-org-a named by ${path.join(a, '.secretless')} line 1)`,
    );
  });
});

describe('every write to a project the repository named prints that project first (#177)', () => {
  // One ordered log of what was printed and which writes were sent, so each
  // test shows the project line comes before the first write request.
  let events: string[];
  let repoDir: string;
  let note: string;

  beforeEach(() => {
    events = [];
    useBackend('gcp-sm');
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keyFile = path.join(root, 'home', 'test-sa.json');
    fs.writeFileSync(keyFile, JSON.stringify({
      type: 'service_account',
      client_email: 'test@example.iam.gserviceaccount.com',
      private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    }));
    process.env.GOOGLE_APPLICATION_CREDENTIALS = keyFile;
    // Keeps what was written, so a read-back after the write finds it.
    const stored = new Map<string, string>();
    vi.stubGlobal('fetch', async (url: string, init?: { method?: string; body?: string }) => {
      const u = String(url);
      if (u.startsWith('https://secretmanager.googleapis.com/') && init?.method === 'POST') {
        events.push(`WRITE ${u}`);
        const version = u.match(/\/secrets\/([^/:]+):addVersion$/);
        if (version) stored.set(version[1], (JSON.parse(String(init.body)) as { payload: { data: string } }).payload.data);
      }
      const read = u.match(/\/secrets\/([^/]+)\/versions\/latest:access$/);
      if (read) {
        const data = stored.get(read[1]);
        return data === undefined
          ? { ok: false, status: 404, json: async () => ({}) }
          : { ok: true, status: 200, json: async () => ({ payload: { data } }) };
      }
      return { ok: true, status: 200, json: async () => ({ access_token: 'test-token', expires_in: 3600, secrets: [] }) };
    });
    repoDir = repo('org-a/app', 'gcp.projectId: acme-org-a\nDATABASE_URL\n');
    vi.spyOn(process, 'cwd').mockReturnValue(repoDir);
    note = `In GCP project acme-org-a, named by ${path.join(repoDir, '.secretless')} line 1`;
    const capture = (...a: unknown[]): void => { events.push(a.map(String).join(' ')); };
    vi.spyOn(console, 'log').mockImplementation(capture);
    vi.spyOn(console, 'error').mockImplementation(capture);
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => { events.push(String(chunk)); return true; });
  });

  function expectProjectNamedBeforeFirstWrite(): void {
    const named = events.findIndex((e) => e.includes(note));
    const firstWrite = events.findIndex((e) => e.startsWith('WRITE '));
    expect(named).toBeGreaterThanOrEqual(0);
    expect(firstWrite).toBeGreaterThan(named);
    expect(events[firstWrite]).toContain('/v1/projects/acme-org-a/');
  }

  it('secret set', async () => {
    expect(await runSecret(['set', 'DATABASE_URL=placeholder-value'])).toBe(0);
    expectProjectNamedBeforeFirstWrite();
  });

  it('secret sync names it under the To: line', async () => {
    const source: SecretBackend = {
      name: '1password',
      resolve: async (key): Promise<Record<string, string>> => (key === 'secret/DATABASE_URL' ? { [key]: 'placeholder-value' } : {}),
      healthCheck: async () => ({ healthy: true, latencyMs: 0, message: 'ok' }),
    };
    expect(await runSecretSync(['--from', '1password', '--only', 'DATABASE_URL'], { createSource: () => source })).toBe(0);
    expectProjectNamedBeforeFirstWrite();
    const to = events.findIndex((e) => e.startsWith('  To:     gcp-sm (this machine)'));
    expect(to).toBeGreaterThanOrEqual(0);
    expect(events[to + 1]).toBe(`          ${note}`);
  });

  it('import of a bundle, and both result lines name the project', async () => {
    const source = new LocalBackend({ storeDir: path.join(root, 'source-store'), key: 'test-key' });
    await new SecretStore({ backend: source }).setSecret('DATABASE_URL', 'placeholder-value');
    const bundle = path.join(root, 'team.secretless-bundle');
    await exportBundle(bundle, 'test-passphrase', { backend: source, kdf: { n: 2 ** 14, r: 8, p: 1 } });

    expect(await runImport([bundle], { env: {}, readPassphrase: async () => 'test-passphrase' })).toBe(0);
    expectProjectNamedBeforeFirstWrite();
    expect(events.join('\n')).toContain('Imported 1 secret(s) from team.secretless-bundle into gcp-sm (GCP project acme-org-a):');
  });

  it('import of a bundle that does not read back names the project on that line too', async () => {
    const source = new LocalBackend({ storeDir: path.join(root, 'source-store'), key: 'test-key' });
    await new SecretStore({ backend: source }).setSecret('DATABASE_URL', 'placeholder-value');
    const bundle = path.join(root, 'team.secretless-bundle');
    await exportBundle(bundle, 'test-passphrase', { backend: source, kdf: { n: 2 ** 14, r: 8, p: 1 } });
    // Every read answers "not found", so the imported name does not read back.
    const writes = vi.fn(async (url: string) => {
      if (String(url).includes('latest:access')) return { ok: false, status: 404, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => ({ access_token: 'test-token', expires_in: 3600, secrets: [] }) };
    });
    vi.stubGlobal('fetch', writes);

    expect(await runImport([bundle], { env: {}, readPassphrase: async () => 'test-passphrase' })).toBe(1);
    expect(events.join('\n')).toContain('These names do not read back from gcp-sm (GCP project acme-org-a) with the imported value: DATABASE_URL');
  });

  it('import of a .env file', async () => {
    const envFile = path.join(repoDir, 'team.env');
    fs.writeFileSync(envFile, 'DATABASE_URL=placeholder-value\n');
    expect(await runImport([envFile])).toBe(0);
    expectProjectNamedBeforeFirstWrite();
  });

  it('import --detect names it once for every file it imports', async () => {
    fs.writeFileSync(path.join(repoDir, '.env'), 'DATABASE_URL=placeholder-value\n');
    fs.writeFileSync(path.join(repoDir, '.env.local'), 'API_TOKEN=placeholder-value-2\n');
    expect(await runImport(['--detect'])).toBe(0);
    expectProjectNamedBeforeFirstWrite();
    expect(events.filter((e) => e.includes(note))).toHaveLength(1);
  });

  it('setup names it before the first prompt', async () => {
    const input = new PassThrough();
    const original = Object.getOwnPropertyDescriptor(process, 'stdin')!;
    Object.defineProperty(process, 'stdin', { value: input, configurable: true });
    try {
      const pending = runSetup(repoDir);
      input.end('placeholder-value\n');
      const result = await pending;
      expect(result.set).toBe(1);
    } finally {
      Object.defineProperty(process, 'stdin', original);
    }
    expectProjectNamedBeforeFirstWrite();
    const named = events.findIndex((e) => e.includes(note));
    const prompt = events.findIndex((e) => e.startsWith('  DATABASE_URL'));
    expect(prompt).toBeGreaterThan(named);
  });

  it('CONTROL: a repository that names no project prints no project line on any path', async () => {
    const plain = repo('plain', 'DATABASE_URL\n');
    vi.spyOn(process, 'cwd').mockReturnValue(plain);
    const envFile = path.join(plain, 'team.env');
    fs.writeFileSync(envFile, 'DATABASE_URL=placeholder-value\n');
    expect(await runSecret(['set', 'DATABASE_URL=placeholder-value'])).toBe(0);
    expect(await runImport([envFile])).toBe(0);
    expect(events.some((e) => e.startsWith('WRITE '))).toBe(true);
    expect(events.join('\n')).not.toContain('In GCP project');
  });
});
