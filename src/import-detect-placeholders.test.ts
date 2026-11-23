import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runImport } from './commands/env-run';
import { importEnvFile } from './env-import';
import { LocalBackend } from './backends/local';
import { SecretStore } from './secret-store';
import { CLI } from './commands/utils';

/**
 * From a fresh-install walkthrough (#410): `import --detect` stored
 * `PLACEHOLDER_KEY=your-key-here` as if it were a secret, and ended at the
 * total with no word that the `.env` files still hold every value it stored.
 */

let root: string;
let originalHome: string | undefined;

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sls-import-detect-')));
  originalHome = process.env.HOME;
  process.env.HOME = path.join(root, 'home');
  const configDir = path.join(root, 'home', '.secretless-ai');
  fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ backend: 'local' }));
  vi.spyOn(process, 'cwd').mockReturnValue(path.join(root, 'project'));
  fs.mkdirSync(path.join(root, 'project'));
});

afterEach(() => {
  vi.restoreAllMocks();
  process.env.HOME = originalHome;
  fs.rmSync(root, { recursive: true, force: true });
});

async function detect(): Promise<{ code: number; lines: string[] }> {
  const out: string[] = [];
  const push = (...a: unknown[]): void => { out.push(a.map(String).join(' ')); };
  vi.spyOn(console, 'log').mockImplementation(push);
  vi.spyOn(console, 'error').mockImplementation(push);
  const code = await runImport(['--detect']);
  return { code, lines: out.join('\n').split('\n') };
}

function write(name: string, content: string): void {
  fs.writeFileSync(path.join(root, 'project', name), content);
}

describe('import --detect skips placeholders (#410)', () => {
  it('stores the real entry, not the placeholder, and names the one it skipped', async () => {
    write('.env', 'DATABASE_URL=stored-value\nPLACEHOLDER_KEY=your-key-here\n');
    const { code, lines } = await detect();

    expect(code).toBe(0);
    expect(lines).toContain('  .env: 1 imported');
    expect(lines).toContain('    (1 skipped — placeholder values: PLACEHOLDER_KEY)');
    expect(lines).toContain('  Total: 1 secret(s) imported.');

    const store = new SecretStore();
    expect(await store.getSecret('DATABASE_URL')).toBe('stored-value');
    expect(await store.getSecret('PLACEHOLDER_KEY')).toBeUndefined();
  });

  it('CONTROL: importing the file by name stores the placeholder as before', async () => {
    write('.env', 'PLACEHOLDER_KEY=your-key-here\n');
    vi.spyOn(console, 'log').mockImplementation(() => {});
    expect(await runImport([path.join(root, 'project', '.env')])).toBe(0);
    expect(await new SecretStore().getSecret('PLACEHOLDER_KEY')).toBe('your-key-here');
  });
});

describe('import --detect says the .env files still hold the values (#410)', () => {
  it('names each file a value was stored from and the next step', async () => {
    write('.env', 'DATABASE_URL=stored-value\n');
    write('.env.local', 'API_TOKEN=stored-value-2\n');
    write('.env.production', 'PLACEHOLDER_KEY=your-key-here\n');
    const { lines } = await detect();

    const total = lines.indexOf('  Total: 2 secret(s) imported.');
    expect(total).toBeGreaterThanOrEqual(0);
    expect(lines.slice(total + 2, total + 4)).toEqual([
      '  .env, .env.local still hold these values in plaintext.',
      `  Next: delete the imported lines from them, and start the app with ${CLI} run -- <command>.`,
    ]);
  });

  it('one file is named on its own', async () => {
    write('.env', 'DATABASE_URL=stored-value\n');
    const { lines } = await detect();
    expect(lines).toContain('  .env still holds these values in plaintext.');
    expect(lines).toContain(`  Next: delete the imported lines from it, and start the app with ${CLI} run -- <command>.`);
  });

  it('CONTROL: nothing stored, no next step about the files', async () => {
    write('.env', 'PLACEHOLDER_KEY=your-key-here\n');
    const { lines } = await detect();
    expect(lines).toContain('  Total: 0 secret(s) imported.');
    expect(lines.join('\n')).not.toContain('plaintext');
  });
});

describe('importEnvFile skipPlaceholders', () => {
  it('lists placeholders apart from invalid names, and only when asked', async () => {
    const backend = new LocalBackend({ storeDir: path.join(root, 'store'), key: 'test-key' });
    const envPath = path.join(root, 'project', '.env');
    write('.env', 'GOOD=stored-value\nPLACEHOLDER_KEY=your-key-here\nBAD NAME=stored-value\nEMPTY=\n');

    const skipping = await importEnvFile(envPath, { backend, skipPlaceholders: true });
    expect(skipping).toEqual({ imported: 2, skipped: 1, entries: ['GOOD', 'EMPTY'], placeholders: ['PLACEHOLDER_KEY'] });

    const all = await importEnvFile(envPath, { backend });
    expect(all).toEqual({ imported: 3, skipped: 1, entries: ['GOOD', 'PLACEHOLDER_KEY', 'EMPTY'], placeholders: [] });
  });
});
