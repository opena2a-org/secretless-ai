import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { parseManifest, readManifest, checkManifest } from './manifest';
import { LocalBackend } from './backends/local';
import { SecretStore } from './secret-store';

describe('parseManifest', () => {
  it('parses required secret entries', () => {
    const entries = parseManifest('GITHUB_TOKEN\nDATABASE_URL');
    expect(entries).toEqual([
      { name: 'GITHUB_TOKEN', required: true, description: '' },
      { name: 'DATABASE_URL', required: true, description: '' },
    ]);
  });

  it('parses optional secrets', () => {
    const entries = parseManifest('SENTRY_DSN  optional');
    expect(entries).toEqual([
      { name: 'SENTRY_DSN', required: false, description: '' },
    ]);
  });

  it('parses descriptions from inline comments', () => {
    const entries = parseManifest('API_KEY  # GitHub API access');
    expect(entries).toEqual([
      { name: 'API_KEY', required: true, description: 'GitHub API access' },
    ]);
  });

  it('parses optional with description', () => {
    const entries = parseManifest('STRIPE_KEY  optional  # Payment processing');
    expect(entries).toEqual([
      { name: 'STRIPE_KEY', required: false, description: 'Payment processing' },
    ]);
  });

  it('skips blank lines and full-line comments', () => {
    const content = `
# Required secrets
GITHUB_TOKEN

# Optional
SENTRY_DSN  optional
`;
    const entries = parseManifest(content);
    expect(entries).toHaveLength(2);
    expect(entries[0].name).toBe('GITHUB_TOKEN');
    expect(entries[1].name).toBe('SENTRY_DSN');
  });

  it('returns empty array for empty content', () => {
    expect(parseManifest('')).toEqual([]);
    expect(parseManifest('# Just comments')).toEqual([]);
  });
});

describe('readManifest', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-manifest-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('reads and parses .secretless file', () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'API_KEY  # Required\n');
    const entries = readManifest(tmpDir);
    expect(entries).toEqual([
      { name: 'API_KEY', required: true, description: 'Required' },
    ]);
  });

  it('returns null when no manifest exists', () => {
    expect(readManifest(tmpDir)).toBeNull();
  });
});

describe('checkManifest', () => {
  let tmpDir: string;
  let storeDir: string;
  let backend: LocalBackend;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-check-test-'));
    storeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-check-store-'));
    backend = new LocalBackend({ storeDir, key: 'test-key' });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(storeDir, { recursive: true, force: true });
  });

  it('identifies missing required secrets', async () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'GITHUB_TOKEN\nDB_URL\n');

    const store = new SecretStore({ backend });
    await store.setSecret('GITHUB_TOKEN', 'ghp_abc');

    const result = await checkManifest(tmpDir, { backend });
    expect(result.satisfied).toHaveLength(1);
    expect(result.satisfied[0].name).toBe('GITHUB_TOKEN');
    expect(result.missing).toHaveLength(1);
    expect(result.missing[0].name).toBe('DB_URL');
  });

  it('categorizes optional missing secrets', async () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'REQUIRED_KEY\nOPTIONAL_KEY  optional\n');

    const result = await checkManifest(tmpDir, { backend });
    expect(result.missing).toHaveLength(1);
    expect(result.missing[0].name).toBe('REQUIRED_KEY');
    expect(result.optional).toHaveLength(1);
    expect(result.optional[0].name).toBe('OPTIONAL_KEY');
  });

  it('returns empty results when no manifest exists', async () => {
    const result = await checkManifest(tmpDir, { backend });
    expect(result.missing).toEqual([]);
    expect(result.optional).toEqual([]);
    expect(result.satisfied).toEqual([]);
  });
});
