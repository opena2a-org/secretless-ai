import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  resolveGcpProject,
  readGcpProjectSetting,
  projectManifestCandidates,
  isGcpProjectRef,
} from './gcp-project';
import { createBackend } from './factory';
import { GCPSecretManagerBackend } from './gcp-sm';

// #177: the gcp-sm backend resolved one project per machine. A repository's
// .secretless can now name its own, and a repository that names one never
// falls back to another.

let root: string;
let originalHome: string | undefined;
let originalKey: string | undefined;

function write(rel: string, content: string): string {
  const p = path.join(root, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  return p;
}

function repo(rel: string, manifest?: string): string {
  const dir = path.join(root, rel);
  fs.mkdirSync(path.join(dir, '.git'), { recursive: true });
  if (manifest !== undefined) fs.writeFileSync(path.join(dir, '.secretless'), manifest);
  return dir;
}

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-project-')));
  originalHome = process.env.HOME;
  originalKey = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  process.env.HOME = path.join(root, 'home');
  delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
  write('home/.secretless-ai/config.json', JSON.stringify({ backend: 'gcp-sm', gcp: { projectId: 'personal-proj' } }));
});

afterEach(() => {
  process.env.HOME = originalHome;
  if (originalKey === undefined) delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
  else process.env.GOOGLE_APPLICATION_CREDENTIALS = originalKey;
  vi.unstubAllGlobals();
  fs.rmSync(root, { recursive: true, force: true });
});

describe('resolveGcpProject — a repository can name its own project (#177)', () => {
  it('two repositories on one machine resolve from their own projects', () => {
    const a = repo('org-a/app', 'gcp.projectId: acme-org-a\nDATABASE_URL\n');
    const b = repo('org-b/app', 'gcp.projectId: acme-org-b\nDATABASE_URL\n');

    expect(resolveGcpProject({ projectDir: a })).toEqual({
      projectId: 'acme-org-a',
      source: 'manifest',
      from: `${path.join(a, '.secretless')} line 1`,
    });
    expect(resolveGcpProject({ projectDir: b })).toMatchObject({ projectId: 'acme-org-b', source: 'manifest' });
  });

  it('CONTROL: a repository whose manifest names no project uses the user config, as before', () => {
    const plain = repo('plain', 'DATABASE_URL\n');
    expect(resolveGcpProject({ projectDir: plain })).toMatchObject({
      projectId: 'personal-proj',
      source: 'user-config',
    });
  });

  it('applies to commands run in a subdirectory of the repository', () => {
    const a = repo('org-a/app', 'gcp.projectId: acme-org-a\n');
    const sub = path.join(a, 'packages', 'api');
    fs.mkdirSync(sub, { recursive: true });
    expect(resolveGcpProject({ projectDir: sub })).toMatchObject({ projectId: 'acme-org-a', source: 'manifest' });
  });

  it('a nearer manifest without the setting defers to the repository root manifest', () => {
    const a = repo('mono', 'gcp.projectId: acme-mono\n');
    write('mono/packages/api/.secretless', 'STRIPE_KEY\n');
    expect(resolveGcpProject({ projectDir: path.join(a, 'packages', 'api') })).toMatchObject({
      projectId: 'acme-mono',
      from: `${path.join(a, '.secretless')} line 1`,
    });
  });

  it('never reads a manifest above the repository root', () => {
    write('.secretless', 'gcp.projectId: planted-above\n');
    const inner = repo('inner', 'DATABASE_URL\n');
    expect(resolveGcpProject({ projectDir: inner })).toMatchObject({ projectId: 'personal-proj' });
  });

  it('outside a repository, only the directory itself is consulted', () => {
    write('shared/.secretless', 'gcp.projectId: planted-shared\n');
    const work = path.join(root, 'shared', 'work');
    fs.mkdirSync(work, { recursive: true });
    expect(projectManifestCandidates(work)).toEqual([path.join(work, '.secretless')]);
    expect(resolveGcpProject({ projectDir: work })).toMatchObject({ projectId: 'personal-proj' });
  });

  it('an unusable gcp.projectId is an error, never a fallback to the user-wide project', () => {
    for (const manifest of [
      'gcp.projectId: ../other/secrets\n',
      'gcp.projectId: acme?x=1\n',
      'gcp.projectId: Acme-Prod\n',
      'gcp.projectId:\n',
      'gcp.projectId: acme-one acme-two\n',
      'gcp.projectId: acme-one\ngcp.projectId: acme-two\n',
    ]) {
      const dir = repo(`bad-${Math.random().toString(36).slice(2)}`, manifest);
      const r = resolveGcpProject({ projectDir: dir });
      expect(r.projectId, manifest).toBeUndefined();
      expect(r.source).toBe('manifest');
      expect(r.error).toContain(path.join(dir, '.secretless'));
    }
  });

  it('the explicit backend config still wins', () => {
    const a = repo('org-a/app', 'gcp.projectId: acme-org-a\n');
    expect(resolveGcpProject({ projectDir: a, explicit: 'from-config' })).toMatchObject({
      projectId: 'from-config',
      source: 'explicit',
    });
  });

  it('reports none when nothing names a project', () => {
    fs.rmSync(path.join(root, 'home', '.secretless-ai', 'config.json'));
    expect(resolveGcpProject({ projectDir: repo('empty') })).toEqual({ source: 'none' });
  });
});

describe('readGcpProjectSetting', () => {
  it('reads the line number and project, ignoring a trailing comment', () => {
    expect(readGcpProjectSetting('# header\nGITHUB_TOKEN\ngcp.projectId: acme-prod   # org A\n'))
      .toEqual({ line: 3, projectId: 'acme-prod' });
  });

  it('accepts a numeric project number', () => {
    expect(isGcpProjectRef('123456789012')).toBe(true);
    expect(isGcpProjectRef('0123')).toBe(false);
  });

  it('names the second line when the setting appears twice', () => {
    expect(readGcpProjectSetting('gcp.projectId: acme-one\ngcp.projectId: acme-two\n'))
      .toEqual({ line: 2, reason: 'gcp.projectId is set twice (first on line 1); keep one' });
  });
});

describe('createBackend — a manifest-named project bypasses the name-keyed cache (#177)', () => {
  function stubGcp(): string[] {
    process.env.GOOGLE_APPLICATION_CREDENTIALS = write('home/fake-key.json', '{}');
    const urls: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      urls.push(String(url));
      return {
        ok: true,
        status: 200,
        json: async () => ({ payload: { data: Buffer.from('placeholder').toString('base64') } }),
      };
    });
    return urls;
  }

  async function resolveIn(projectDir: string): Promise<void> {
    const backend = createBackend('gcp-sm', { projectDir });
    const inner = ((backend as unknown as { inner?: object }).inner ?? backend) as Record<string, unknown>;
    inner.accessToken = 'test-token';
    inner.tokenExpiry = Date.now() + 3600_000;
    await backend.resolve('secret/DATABASE_URL');
  }

  it('the same name in two repositories is read from each repository\'s project', async () => {
    const urls = stubGcp();
    await resolveIn(repo('org-a/app', 'gcp.projectId: acme-org-a\nDATABASE_URL\n'));
    await resolveIn(repo('org-b/app', 'gcp.projectId: acme-org-b\nDATABASE_URL\n'));
    expect(urls).toEqual([
      'https://secretmanager.googleapis.com/v1/projects/acme-org-a/secrets/DATABASE_URL/versions/latest:access',
      'https://secretmanager.googleapis.com/v1/projects/acme-org-b/secrets/DATABASE_URL/versions/latest:access',
    ]);
  });

  it('CONTROL: the user-wide project keeps the cache', () => {
    stubGcp();
    expect(createBackend('gcp-sm', { projectDir: repo('plain', 'DATABASE_URL\n') }).name).toBe('cached(gcp-sm)');
    expect(createBackend('gcp-sm', { projectDir: repo('named', 'gcp.projectId: acme-org-a\n') }).name).toBe('gcp-sm');
  });

  it('an unusable gcp.projectId fails the read and makes no request', async () => {
    const urls = stubGcp();
    const dir = repo('bad', 'gcp.projectId: ../escape\n');
    await expect(resolveIn(dir)).rejects.toThrow(/line 1: gcp\.projectId value is not a GCP project id.*Nothing was read from or written to another project/);
    expect(urls).toEqual([]);
  });
});

describe('GCPSecretManagerBackend — a manifest-named project is never silent (#177)', () => {
  function backendIn(projectDir: string, status: number): GCPSecretManagerBackend {
    vi.stubGlobal('fetch', async () => ({ ok: status < 300, status, json: async () => ({}) }));
    const backend = new GCPSecretManagerBackend({ projectDir });
    (backend as unknown as Record<string, unknown>).accessToken = 'test-token';
    (backend as unknown as Record<string, unknown>).tokenExpiry = Date.now() + 3600_000;
    return backend;
  }

  it('a permission error names the project and the manifest line that chose it', async () => {
    const a = repo('org-a/app', '\ngcp.projectId: acme-org-a\n');
    await expect(backendIn(a, 403).resolve('secret/DATABASE_URL')).rejects.toThrow(
      `insufficient IAM permissions on project acme-org-a (named by ${path.join(a, '.secretless')} line 2)`,
    );
  });

  it('a project the credentials cannot list is an error, not an empty answer', async () => {
    const a = repo('org-a/app', 'gcp.projectId: acme-org-a\n');
    await expect(backendIn(a, 404).resolve('secret/DATABASE_URL')).rejects.toThrow(
      'cannot list secrets in project acme-org-a',
    );
  });

  it('CONTROL: the user-wide project keeps the old empty answer for a name it does not hold', async () => {
    const plain = repo('plain', 'DATABASE_URL\n');
    await expect(backendIn(plain, 404).resolve('secret/DATABASE_URL')).resolves.toEqual({});
  });
});
