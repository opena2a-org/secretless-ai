import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { parseEnvFile, importEnvFile, detectEnvFiles } from './env-import';
import { LocalBackend } from './backends/local';
import { SecretStore } from './secret-store';

describe('parseEnvFile', () => {
  it('parses basic KEY=VALUE pairs', () => {
    const entries = parseEnvFile('FOO=bar\nBAZ=qux');
    expect(entries).toEqual([
      { name: 'FOO', value: 'bar' },
      { name: 'BAZ', value: 'qux' },
    ]);
  });

  it('handles double-quoted values', () => {
    const entries = parseEnvFile('KEY="hello world"');
    expect(entries).toEqual([{ name: 'KEY', value: 'hello world' }]);
  });

  it('handles single-quoted values', () => {
    const entries = parseEnvFile("KEY='hello world'");
    expect(entries).toEqual([{ name: 'KEY', value: 'hello world' }]);
  });

  it('strips export prefix', () => {
    const entries = parseEnvFile('export MY_VAR=value');
    expect(entries).toEqual([{ name: 'MY_VAR', value: 'value' }]);
  });

  it('skips comments and blank lines', () => {
    const content = `
# This is a comment
KEY1=val1

# Another comment
KEY2=val2
`;
    const entries = parseEnvFile(content);
    expect(entries).toEqual([
      { name: 'KEY1', value: 'val1' },
      { name: 'KEY2', value: 'val2' },
    ]);
  });

  it('handles values with = signs', () => {
    const entries = parseEnvFile('DATABASE_URL=postgres://user:pass@host/db?ssl=true');
    expect(entries).toEqual([{
      name: 'DATABASE_URL',
      value: 'postgres://user:pass@host/db?ssl=true',
    }]);
  });

  it('handles empty values', () => {
    const entries = parseEnvFile('EMPTY=');
    expect(entries).toEqual([{ name: 'EMPTY', value: '' }]);
  });

  it('strips inline comments for unquoted values', () => {
    const entries = parseEnvFile('KEY=value # this is a comment');
    expect(entries).toEqual([{ name: 'KEY', value: 'value' }]);
  });

  it('skips lines without = sign', () => {
    const entries = parseEnvFile('NOT_A_PAIR\nKEY=val');
    expect(entries).toEqual([{ name: 'KEY', value: 'val' }]);
  });
});

describe('importEnvFile', () => {
  let tmpDir: string;
  let backend: LocalBackend;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-import-test-'));
    backend = new LocalBackend({ storeDir: tmpDir, key: 'test-key' });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('imports secrets from .env file', async () => {
    const envPath = path.join(tmpDir, '.env');
    fs.writeFileSync(envPath, 'API_KEY=secret123\nDB_URL=postgres://localhost/db\n');

    const result = await importEnvFile(envPath, { backend });
    expect(result.imported).toBe(2);
    expect(result.entries).toEqual(['API_KEY', 'DB_URL']);

    const store = new SecretStore({ backend });
    expect(await store.getSecret('API_KEY')).toBe('secret123');
    expect(await store.getSecret('DB_URL')).toBe('postgres://localhost/db');
  });

  it('skips invalid secret names', async () => {
    const envPath = path.join(tmpDir, '.env');
    fs.writeFileSync(envPath, 'VALID_KEY=ok\nINVALID KEY=bad\n');

    const result = await importEnvFile(envPath, { backend });
    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(1);
  });
});

describe('detectEnvFiles', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-detect-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('finds existing .env files', () => {
    fs.writeFileSync(path.join(tmpDir, '.env'), 'KEY=val');
    fs.writeFileSync(path.join(tmpDir, '.env.local'), 'KEY=val');

    const found = detectEnvFiles(tmpDir);
    expect(found).toHaveLength(2);
    expect(found[0]).toBe(path.join(tmpDir, '.env'));
    expect(found[1]).toBe(path.join(tmpDir, '.env.local'));
  });

  it('returns empty array when no .env files exist', () => {
    const found = detectEnvFiles(tmpDir);
    expect(found).toEqual([]);
  });
});
