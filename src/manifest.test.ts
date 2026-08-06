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

  it('names the YAML shape rather than only the offending character', () => {
    // The reason used to quote the bad character. Naming the shape is both more
    // actionable and leak-free, which is what makes redacting the line
    // affordable — the user loses the echo but gains the diagnosis.
    const { errors } = parseManifestDetailed('required:\n');
    expect(errors[0].reason).toContain('YAML');
  });

  it('still names the offending character when the shape is not a known one', () => {
    // The character list is the fallback and must not have been dropped.
    const { errors } = parseManifestDetailed('BAD!NAME\n');
    expect(errors[0].reason).toContain('"!"');
  });

  it('rejects a dotenv-shaped guess', () => {
    // KEY=value is the other obvious wrong guess, since `import` takes it.
    const { entries, errors } = parseManifestDetailed('ANTHROPIC_API_KEY=sk-ant-xxx\n');
    expect(entries).toEqual([]);
    expect(errors).toHaveLength(1);
    expect(errors[0].reason).toContain('dotenv');
    // The name is still identified; only the value position is dropped.
    expect(errors[0].text).toContain('ANTHROPIC_API_KEY');
    expect(errors[0].text).not.toContain('sk-ant-xxx');
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
    expect(errors).toHaveLength(1);
    // The reason used to interpolate the extra token. In `GITHUB_TOKEN ghp_live…`
    // that token IS the value, and nothing distinguishes it from a second name,
    // so it is described rather than echoed.
    expect(errors[0].reason).toContain('unexpected text after the name');
    expect(errors[0].reason).not.toContain('required');
    // The line is still located and the declared name still shown.
    expect(errors[0].line).toBe(1);
    expect(errors[0].text).toContain('API_KEY');
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

describe('checkManifest surfaces manifest errors to library consumers (#112)', () => {
  it('does not report an unparseable manifest as all-satisfied', async () => {
    // Without `errors`, a consumer sees missing:[] and concludes everything is
    // present, when in fact nothing was checked. Same fail-open shape as the
    // original defect, one layer up.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'manifest-badcheck-'));
    fs.writeFileSync(path.join(dir, '.secretless'), 'required:\n  - A\n');
    const backend = new LocalBackend({ storeDir: dir, key: 'k' });

    const result = await checkManifest(dir, { backend });

    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.missing).toEqual([]);
    expect(result.satisfied).toEqual([]);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('CONTROL: a valid manifest reports no errors', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'manifest-goodcheck-'));
    fs.writeFileSync(path.join(dir, '.secretless'), 'SOME_KEY\n');
    const backend = new LocalBackend({ storeDir: dir, key: 'k' });

    const result = await checkManifest(dir, { backend });

    expect(result.errors).toEqual([]);
    expect(result.missing.map(e => e.name)).toEqual(['SOME_KEY']);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

describe('parseManifestDetailed — a parse error never echoes a credential VALUE', () => {
  // `.secretless` is documented "safe to commit" and `scan` does not look inside
  // it, so the parse-error path is the ONLY surface that reads the file — and it
  // printed the file back verbatim. `setup --check` stderr is exactly what lands
  // in CI logs. Two shapes leaked: `NAME=VALUE` echoed the line, and
  // `NAME VALUE` echoed it TWICE (once as `text`, once interpolated into
  // `reason`).
  //
  // Note the values below are name-shaped (`SAFE_NAME` is /^[a-zA-Z0-9_-]+$/), so
  // no charset rule can tell them from a name. Only position and role can.
  const ANTHROPIC = ['sk-ant-api03-', 'FAKEvalueLEAKEDdonotprint'].join('');
  const GITHUB = ['ghp_', 'FAKEtokenLEAKEDdonotprint'].join('');

  it('does not echo the value from a NAME=VALUE line', () => {
    const { errors } = parseManifestDetailed(`ANTHROPIC_API_KEY=${ANTHROPIC}\n`);
    expect(errors.length).toBe(1);
    expect(JSON.stringify(errors[0])).not.toContain(ANTHROPIC);
  });

  it('does not echo the value from a NAME VALUE line — in text OR reason', () => {
    const { errors } = parseManifestDetailed(`GITHUB_TOKEN ${GITHUB}\n`);
    expect(errors.length).toBe(1);
    expect(errors[0].text).not.toContain(GITHUB);
    expect(errors[0].reason).not.toContain(GITHUB);
  });

  it('does not echo a value hidden in a trailing comment', () => {
    const { errors } = parseManifestDetailed(`GITHUB_TOKEN oops # ${GITHUB}\n`);
    expect(errors.length).toBe(1);
    expect(JSON.stringify(errors[0])).not.toContain(GITHUB);
  });

  it('still identifies WHICH line and WHICH declared name', () => {
    // Redaction must not turn the error into a dead end. The name is the part
    // the user wrote as a name, so it stays; only the value position is dropped.
    const { errors } = parseManifestDetailed(`OK_NAME\nGITHUB_TOKEN ${GITHUB}\n`);
    expect(errors[0].line).toBe(2);
    expect(errors[0].text).toContain('GITHUB_TOKEN');
  });

  it('names the dotenv shape instead of echoing it', () => {
    const { errors } = parseManifestDetailed(`ANTHROPIC_API_KEY=${ANTHROPIC}\n`);
    expect(errors[0].reason.toLowerCase()).toContain('value');
    // The declared name is safe and useful; the value is not.
    expect(errors[0].text).toContain('ANTHROPIC_API_KEY');
  });

  it('bounds the reason as well as the text (a 200 KB token must not flood stderr)', () => {
    // MAX_ECHOED_LINE bounded `text` but not the sibling `reason`, so a
    // pathological token still flooded stderr through the second field.
    const huge = 'A'.repeat(200_000);
    const { errors } = parseManifestDetailed(`GITHUB_TOKEN ${huge}\n`);
    expect(errors.length).toBe(1);
    expect(errors[0].reason.length).toBeLessThan(1000);
    expect(errors[0].text.length).toBeLessThan(1000);
  });

  it('CONTROL: a valid manifest still parses, so redaction did not break the happy path', () => {
    const { entries, errors } = parseManifestDetailed(
      'GITHUB_TOKEN            # required\nSTRIPE_SECRET_KEY optional  # payments\n',
    );
    expect(errors).toEqual([]);
    expect(entries.map(e => e.name)).toEqual(['GITHUB_TOKEN', 'STRIPE_SECRET_KEY']);
    expect(entries[1].required).toBe(false);
  });
});

describe('near-miss hint is bounded (self-review, not from an issue)', () => {
  it('does not walk a quadratic edit distance on very long names', async () => {
    const long = 'A'.repeat(20000);
    const store = new SecretStore({
      backend: {
        name: 'fake',
        resolve: async () => ({ [`secret/${long}`]: 'v' }),
        store: async () => {},
        delete: async () => false,
      },
    });
    const started = Date.now();
    await expect(store.loadSecrets([long.slice(0, 19999)])).rejects.toThrow();
    // Unbounded, this is ~4e8 cell updates. The guard makes it constant time.
    expect(Date.now() - started).toBeLessThan(2000);
  });
});
