/**
 * Encrypted export and import between machines (#175).
 *
 * Before this, `export` was an unknown command and a bundle path given to
 * `import` was parsed as a .env file. The round trip here runs against an
 * in-memory backend standing in for each machine's store; the keychain itself
 * is never reached.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { sealBundle, openBundle, isBundleFile, BUNDLE_TOKEN, type KdfParams } from './bundle';
import { exportBundle, importBundle } from './bundle-transfer';
import { runExport } from './commands/bundle';
import { runImport } from './commands/env-run';
import { scan } from './scan';
import { scanTranscriptFile } from './transcript';
import type { WritableSecretBackend } from './backends/types';

/** The cheapest scrypt cost `openBundle` accepts, so the suite stays fast. */
const FAST: KdfParams = { n: 2 ** 14, r: 8, p: 1 };
const PASS = 'correct horse battery staple';

function memoryStore(initial: Record<string, string> = {}, opts: { dropWrites?: boolean } = {}) {
  const data = new Map(Object.entries(initial).map(([k, v]) => [`secret/${k}`, v]));
  const writes: string[] = [];
  const backend: WritableSecretBackend = {
    name: 'memory',
    resolve: async (p) => Object.fromEntries([...data].filter(([k]) => k === p || k.startsWith(`${p}/`))),
    healthCheck: async () => ({ healthy: true, latencyMs: 0 }),
    store: async (k, v) => {
      writes.push(k);
      if (!opts.dropWrites) data.set(k, v);
    },
    delete: async (k) => data.delete(k),
  };
  return { backend, data, writes };
}

const tmpDirs: string[] = [];
function tmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-bundle-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of tmpDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

const SOURCE = { ALPHA_TOKEN: 'alpha-value-1', BETA_KEY: 'beta value with spaces', GAMMA_URL: 'postgres://u@h/db' };

describe('bundle format', () => {
  it('round-trips names, values and manifest fields, and holds no plaintext', async () => {
    const entries = [
      { name: 'ALPHA_TOKEN', value: 'alpha-value-1', required: true, description: 'deploys' },
      { name: 'BETA_KEY', value: 'unicode é中' },
    ];
    const sealed = await sealBundle(entries, PASS, FAST);
    expect(sealed).not.toContain('ALPHA_TOKEN');
    expect(sealed).not.toContain('alpha-value-1');
    expect(sealed).not.toContain('deploys');
    expect(sealed.trim().split('\n')).toHaveLength(1);
    expect(BUNDLE_TOKEN.test(sealed)).toBe(true);
    expect(await openBundle(sealed, PASS)).toEqual(entries);
  });

  it('refuses a wrong passphrase', async () => {
    const sealed = await sealBundle([{ name: 'A', value: 'v' }], PASS, FAST);
    await expect(openBundle(sealed, 'not the passphrase')).rejects.toThrow(/passphrase is wrong/);
  });

  it('refuses a changed ciphertext byte and a changed header parameter', async () => {
    const sealed = (await sealBundle([{ name: 'A', value: 'v' }], PASS, FAST)).trim();
    const [prefix, version, header, ct, tag] = sealed.split('.');
    const flipped = ct.slice(0, -2) + (ct.charAt(ct.length - 2) === 'A' ? 'B' : 'A') + ct.slice(-1);
    await expect(openBundle([prefix, version, header, flipped, tag].join('.'), PASS)).rejects.toThrow(/could not be decrypted/);

    const h = JSON.parse(Buffer.from(header, 'base64url').toString('utf-8'));
    const weaker = Buffer.from(JSON.stringify({ ...h, r: 1 })).toString('base64url');
    await expect(openBundle([prefix, version, weaker, ct, tag].join('.'), PASS)).rejects.toThrow(/could not be decrypted/);
  });

  it('refuses a truncated tag and an out-of-range scrypt cost before deriving a key', async () => {
    const sealed = (await sealBundle([{ name: 'A', value: 'v' }], PASS, FAST)).trim();
    const [prefix, version, header, ct, tag] = sealed.split('.');
    await expect(openBundle([prefix, version, header, ct, tag.slice(0, 8)].join('.'), PASS)).rejects.toThrow(/tag is truncated/);

    const h = JSON.parse(Buffer.from(header, 'base64url').toString('utf-8'));
    const huge = Buffer.from(JSON.stringify({ ...h, n: 2 ** 30 })).toString('base64url');
    await expect(openBundle([prefix, version, huge, ct, tag].join('.'), PASS)).rejects.toThrow(/outside the supported range/);
  });
});

describe('export and import between two stores', () => {
  it('every exported name resolves identically after import', async () => {
    const dir = tmpDir();
    const a = memoryStore(SOURCE);
    const b = memoryStore();
    const out = path.join(dir, 'team.secretless-bundle');

    const exported = await exportBundle(out, PASS, { backend: a.backend, kdf: FAST, projectDir: dir });
    expect(exported.names).toEqual(Object.keys(SOURCE).sort());
    expect(fs.statSync(out).mode & 0o777).toBe(0o600);
    expect(fs.readFileSync(out, 'utf-8')).not.toContain('alpha-value-1');

    const imported = await importBundle(out, PASS, { backend: b.backend });
    expect(imported.unresolved).toEqual([]);
    expect(imported.replaced).toEqual([]);
    for (const [name, value] of Object.entries(SOURCE)) {
      expect(b.data.get(`secret/${name}`)).toBe(value);
    }
  });

  it('carries the exporting project\'s .secretless metadata for the names it declares', async () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, '.secretless'), 'ALPHA_TOKEN   # deploy token\nBETA_KEY optional\n');
    const out = path.join(dir, 'm.secretless-bundle');
    await exportBundle(out, PASS, { backend: memoryStore(SOURCE).backend, kdf: FAST, projectDir: dir });
    const { entries } = await importBundle(out, PASS, { backend: memoryStore().backend });
    const byName = Object.fromEntries(entries.map((e) => [e.name, e]));
    expect(byName.ALPHA_TOKEN).toMatchObject({ required: true, description: 'deploy token' });
    expect(byName.BETA_KEY).toMatchObject({ required: false });
    expect(byName.GAMMA_URL.required).toBeUndefined();
  });

  it('--only exports just the named secrets, and an unknown name writes nothing', async () => {
    const dir = tmpDir();
    const out = path.join(dir, 'only.secretless-bundle');
    const exported = await exportBundle(out, PASS, { backend: memoryStore(SOURCE).backend, kdf: FAST, projectDir: dir, only: ['alpha_token'] });
    expect(exported.names).toEqual(['ALPHA_TOKEN']);

    const missing = path.join(dir, 'missing.secretless-bundle');
    await expect(exportBundle(missing, PASS, { backend: memoryStore(SOURCE).backend, kdf: FAST, projectDir: dir, only: ['ALPHA_TOKEN', 'NOPE'] }))
      .rejects.toThrow(/Not in the store: NOPE/);
    expect(fs.existsSync(missing)).toBe(false);
  });

  it('refuses an existing file, a missing extension and a short passphrase', async () => {
    const dir = tmpDir();
    const store = memoryStore(SOURCE).backend;
    const existing = path.join(dir, 'old.secretless-bundle');
    fs.writeFileSync(existing, 'keep me');
    await expect(exportBundle(existing, PASS, { backend: store, kdf: FAST, projectDir: dir })).rejects.toThrow(/already exists/);
    expect(fs.readFileSync(existing, 'utf-8')).toBe('keep me');

    await expect(exportBundle(path.join(dir, 'x.json'), PASS, { backend: store, kdf: FAST, projectDir: dir }))
      .rejects.toThrow(/must end in \.secretless-bundle/);
    await expect(exportBundle(path.join(dir, 'y.secretless-bundle'), 'short', { backend: store, kdf: FAST, projectDir: dir }))
      .rejects.toThrow(/shorter than 12/);
    expect(fs.readdirSync(dir)).toEqual(['old.secretless-bundle']);
  });

  it('a wrong passphrase is refused before any write', async () => {
    const dir = tmpDir();
    const out = path.join(dir, 'w.secretless-bundle');
    await exportBundle(out, PASS, { backend: memoryStore(SOURCE).backend, kdf: FAST, projectDir: dir });
    const b = memoryStore();
    await expect(importBundle(out, 'a different passphrase', { backend: b.backend })).rejects.toThrow(/passphrase is wrong/);
    expect(b.writes).toEqual([]);
  });

  it('refuses to overwrite an existing name unless forced', async () => {
    const dir = tmpDir();
    const out = path.join(dir, 'f.secretless-bundle');
    await exportBundle(out, PASS, { backend: memoryStore(SOURCE).backend, kdf: FAST, projectDir: dir });

    const b = memoryStore({ BETA_KEY: 'older value' });
    await expect(importBundle(out, PASS, { backend: b.backend })).rejects.toThrow(/Already in this machine's store: BETA_KEY/);
    expect(b.writes).toEqual([]);
    expect(b.data.get('secret/BETA_KEY')).toBe('older value');

    const forced = await importBundle(out, PASS, { backend: b.backend, force: true });
    expect(forced.replaced).toEqual(['BETA_KEY']);
    expect(b.data.get('secret/BETA_KEY')).toBe('beta value with spaces');
  });

  it('reports names that do not read back after writing', async () => {
    const dir = tmpDir();
    const out = path.join(dir, 'r.secretless-bundle');
    await exportBundle(out, PASS, { backend: memoryStore({ ALPHA_TOKEN: 'a-value' }).backend, kdf: FAST, projectDir: dir });
    const result = await importBundle(out, PASS, { backend: memoryStore({}, { dropWrites: true }).backend });
    expect(result.unresolved).toEqual(['ALPHA_TOKEN']);
  });
});

describe('the export and import commands', () => {
  function capture() {
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    return out;
  }

  it('export refuses inside an AI agent runtime and writes nothing', async () => {
    const dir = tmpDir();
    const out = capture();
    const file = path.join(dir, 'agent.secretless-bundle');
    const code = await runExport(['--out', file], {
      env: { CLAUDECODE: '1' },
      readPassphrase: async () => PASS,
      storeOptions: { backend: memoryStore(SOURCE).backend },
      kdf: FAST,
    });
    expect(code).toBe(1);
    expect(out.join('\n')).toContain('Refused');
    expect(fs.existsSync(file)).toBe(false);
  });

  it('export without --out is a usage error', async () => {
    capture();
    expect(await runExport(['--only', 'A'], { env: {}, readPassphrase: async () => PASS })).toBe(2);
  });

  it('export refuses a bad --out file name before asking for a passphrase (#242)', async () => {
    const dir = tmpDir();
    const existing = path.join(dir, 'old.secretless-bundle');
    fs.writeFileSync(existing, 'keep me');
    for (const [file, refusal] of [
      [path.join(dir, 'a.txt'), 'must end in .secretless-bundle'],
      [existing, 'already exists'],
    ]) {
      const out = capture();
      const readPassphrase = vi.fn(async () => null);
      const code = await runExport(['--out', file], {
        env: {}, readPassphrase, storeOptions: { backend: memoryStore(SOURCE).backend }, kdf: FAST,
      });
      expect(code).toBe(1);
      expect(readPassphrase).not.toHaveBeenCalled();
      expect(out.join('\n')).toContain(refusal);
      expect(out.join('\n')).not.toContain('No passphrase');
      vi.restoreAllMocks();
    }
    expect(fs.readdirSync(dir)).toEqual(['old.secretless-bundle']);
    expect(fs.readFileSync(existing, 'utf-8')).toBe('keep me');
  });

  it('import dispatches a bundle to the bundle path and prints names, never values', async () => {
    const dir = tmpDir();
    const file = path.join(dir, 'cli.secretless-bundle');
    const b = memoryStore();
    const out = capture();
    expect(await runExport(['--out', file], {
      env: {}, readPassphrase: async () => PASS, storeOptions: { backend: memoryStore(SOURCE).backend }, kdf: FAST,
    })).toBe(0);
    expect(await runImport([file], { env: {}, readPassphrase: async () => PASS, storeOptions: { backend: b.backend } })).toBe(0);
    const text = out.join('\n');
    for (const name of Object.keys(SOURCE)) expect(text).toContain(name);
    for (const value of Object.values(SOURCE)) expect(text).not.toContain(value);
    expect(text).toContain('All 3 resolve');
    expect(b.data.size).toBe(3);
  });

  it('no passphrase source writes nothing', async () => {
    const dir = tmpDir();
    const file = path.join(dir, 'np.secretless-bundle');
    await exportBundle(file, PASS, { backend: memoryStore(SOURCE).backend, kdf: FAST, projectDir: dir });
    const b = memoryStore();
    const out = capture();
    expect(await runImport([file], { env: {}, readPassphrase: async () => null, storeOptions: { backend: b.backend } })).toBe(1);
    expect(out.join('\n')).toContain('No passphrase');
    expect(b.writes).toEqual([]);
  });

  it('--force on a .env import is refused, since that path already replaces names', async () => {
    const dir = tmpDir();
    const envFile = path.join(dir, 'plain.env');
    fs.writeFileSync(envFile, 'A_NAME=a-value\n');
    capture();
    expect(isBundleFile(envFile)).toBe(false);
    expect(await runImport([envFile, '--force'])).toBe(2);
  });

  it('a missing bundle with --force is reported as not found', async () => {
    const out = capture();
    const missing = path.join(tmpDir(), 'gone.secretless-bundle');
    expect(await runImport(['--force', missing])).toBe(1);
    expect(out.join('\n')).toContain(`File not found: ${missing}`);
  });
});

describe('scan and clean treat a bundle as a secret file', () => {
  it('scan flags a .secretless-bundle file by its presence', async () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'team.secretless-bundle'), await sealBundle([{ name: 'A', value: 'v' }], PASS, FAST));
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.some((f) => f.patternId === 'secretless-bundle' && f.file === 'team.secretless-bundle')).toBe(true);
  });

  it('clean redacts a bundle printed into a transcript', async () => {
    const dir = tmpDir();
    const sealed = (await sealBundle([{ name: 'A', value: 'v' }], PASS, FAST)).trim();
    const transcript = path.join(dir, 'session.jsonl');
    fs.writeFileSync(transcript, JSON.stringify({ type: 'tool_result', content: `$ cat team.secretless-bundle\n${sealed}\n` }) + '\n');
    const { findings, redactedLines } = scanTranscriptFile(transcript, false);
    expect(findings.map((f) => f.patternId)).toContain('secretless-bundle');
    expect(redactedLines).not.toBeNull();
    expect(redactedLines!.join('\n')).not.toContain(sealed.split('.')[3]);
    expect(redactedLines!.join('\n')).toContain('[REDACTED:secretless-bundle]');
  });
});
