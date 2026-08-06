import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { parseManifest, parseManifestDetailed, readManifest, checkManifest } from './manifest';
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

describe('parseManifestDetailed — an unrecognised manifest is an error, not names (issue #112)', () => {
  it('rejects the YAML-shaped guess instead of inventing three names', () => {
    // Verbatim from the issue. It used to report "Missing: 3 required" and list
    // `required:`, `-`, `-` — not one of which appears in the file as a name.
    const { entries, errors } = parseManifestDetailed('required:\n  - ANTHROPIC_API_KEY\n  - SOME_SECRET\n');

    expect(entries).toEqual([]);
    expect(errors).toHaveLength(3);
    expect(errors.map(e => e.line)).toEqual([1, 2, 3]);
    // Never present punctuation as a secret name.
    expect(errors.map(e => e.text)).not.toContain('ANTHROPIC_API_KEY');
  });

  it('names the offending character in the reason', () => {
    const { errors } = parseManifestDetailed('required:\n');
    expect(errors[0].reason).toContain('":"');
  });

  it('rejects a dotenv-shaped guess', () => {
    // KEY=value is the other obvious wrong guess, since `import` takes it.
    const { entries, errors } = parseManifestDetailed('ANTHROPIC_API_KEY=sk-ant-xxx\n');
    expect(entries).toEqual([]);
    expect(errors).toHaveLength(1);
    expect(errors[0].reason).toContain('"="');
  });

  it('rejects a JSON-shaped guess', () => {
    const { entries, errors } = parseManifestDetailed('{\n  "required": ["A"]\n}\n');
    expect(entries).toEqual([]);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('rejects an unexpected token after a valid name', () => {
    // Otherwise the original defect just moves one token to the right.
    const { entries, errors } = parseManifestDetailed('API_KEY required\n');
    expect(entries).toEqual([]);
    expect(errors[0].reason).toContain('required');
  });

  it('reports the line number of each bad line, counting comments and blanks', () => {
    const { entries, errors } = parseManifestDetailed('# comment\n\nGOOD_NAME\nbad:line\n');
    expect(entries.map(e => e.name)).toEqual(['GOOD_NAME']);
    expect(errors).toHaveLength(1);
    expect(errors[0].line).toBe(4);
  });

  // ---- controls: the documented format must keep parsing ----

  it('CONTROL: the working format still parses', () => {
    const { entries, errors } = parseManifestDetailed('ANTHROPIC_API_KEY\nSOME_SECRET\n');
    expect(errors).toEqual([]);
    expect(entries.map(e => e.name)).toEqual(['ANTHROPIC_API_KEY', 'SOME_SECRET']);
  });

  it('CONTROL: optional markers and comments still parse', () => {
    const { entries, errors } = parseManifestDetailed(
      '# header\nGITHUB_TOKEN     # required, API access\nSTRIPE_KEY  optional  # payments only\n',
    );
    expect(errors).toEqual([]);
    expect(entries).toEqual([
      { name: 'GITHUB_TOKEN', required: true, description: 'required, API access' },
      { name: 'STRIPE_KEY', required: false, description: 'payments only' },
    ]);
  });

  it('CONTROL: names with dashes and digits are valid', () => {
    const { entries, errors } = parseManifestDetailed('MY-KEY_2\n');
    expect(errors).toEqual([]);
    expect(entries.map(e => e.name)).toEqual(['MY-KEY_2']);
  });

  it('CONTROL: parseManifest keeps its array shape for library consumers', () => {
    expect(parseManifest('A\nB')).toEqual([
      { name: 'A', required: true, description: '' },
      { name: 'B', required: true, description: '' },
    ]);
  });
});
