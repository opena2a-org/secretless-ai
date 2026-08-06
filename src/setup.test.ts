import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runSetup } from './setup';
import { LocalBackend } from './backends/local';
import { SecretStore } from './secret-store';

describe('runSetup', () => {
  let tmpDir: string;
  let storeDir: string;
  let backend: LocalBackend;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-setup-test-'));
    storeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-setup-store-'));
    backend = new LocalBackend({ storeDir, key: 'test-key' });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(storeDir, { recursive: true, force: true });
  });

  it('reports no manifest found', async () => {
    const result = await runSetup(tmpDir, { backend });
    expect(result.complete).toBe(true);
    expect(result.set).toBe(0);
  });

  it('check mode fails when no manifest exists', async () => {
    const result = await runSetup(tmpDir, { backend, check: true });
    expect(result.complete).toBe(false);
  });

  it('reports manifestFound=false without a manifest, true with one', async () => {
    const without = await runSetup(tmpDir, { backend, check: true });
    expect(without.manifestFound).toBe(false);

    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'API_KEY\n');
    const withManifest = await runSetup(tmpDir, { backend, check: true });
    expect(withManifest.manifestFound).toBe(true);
  });

  it('check mode returns complete when all secrets satisfied', async () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'API_KEY\n');
    const store = new SecretStore({ backend });
    await store.setSecret('API_KEY', 'value');

    const result = await runSetup(tmpDir, { backend, check: true });
    expect(result.complete).toBe(true);
    expect(result.existing).toBe(1);
  });

  it('check mode returns incomplete when required secrets missing', async () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'MISSING_KEY\n');

    const result = await runSetup(tmpDir, { backend, check: true });
    expect(result.complete).toBe(false);
    expect(result.existing).toBe(0);
  });

  it('check mode counts optional secrets as skipped', async () => {
    fs.writeFileSync(
      path.join(tmpDir, '.secretless'),
      'REQUIRED\nOPTIONAL_KEY  optional\n',
    );

    const result = await runSetup(tmpDir, { backend, check: true });
    expect(result.complete).toBe(false);
    expect(result.skipped).toBe(1);
  });

  it('returns all existing when nothing is missing', async () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'A\nB\n');
    const store = new SecretStore({ backend });
    await store.setSecret('A', '1');
    await store.setSecret('B', '2');

    const result = await runSetup(tmpDir, { backend, check: true });
    expect(result.complete).toBe(true);
    expect(result.existing).toBe(2);
  });
});

// Issue #97: `setup --check` in a directory with no manifest printed a
// contradictory report — "Missing: 0 required", an empty "Missing secrets:"
// block, and a FAIL telling the user to configure secrets the same output
// said don't exist. The no-manifest check path must stop after the
// create-a-manifest hint with a single FAIL line (exit 1 unchanged).
describe('runSetupCommand --check without a manifest', () => {
  let tmpDir: string;
  let savedCwd: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-setup-cmd-'));
    savedCwd = process.cwd();
    process.chdir(tmpDir);
  });

  afterEach(() => {
    process.chdir(savedCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('prints one FAIL line, no satisfied/missing tally, exits 1', async () => {
    const { runSetupCommand } = await import('./commands/env-run');
    const lines: string[] = [];
    const spy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
      lines.push(a.map(String).join(' '));
    });
    try {
      const code = await runSetupCommand(['--check']);
      const out = lines.join('\n');

      expect(code).toBe(1);
      expect(out).toContain('FAIL: No .secretless manifest to check against.');
      expect(out).not.toContain('Satisfied:');
      expect(out).not.toContain('Missing:');
      expect(out).not.toContain('Missing secrets:');
      expect(out).not.toContain('Run `secretless-ai setup`');
    } finally {
      spy.mockRestore();
    }
  });
});

describe('runSetup — an unparseable manifest is not a missing-secrets count (#112)', () => {
  let tmpDir: string;
  let storeDir: string;
  let backend: LocalBackend;
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-setup-bad-'));
    storeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-setup-bad-store-'));
    backend = new LocalBackend({ storeDir, key: 'test-key' });
    errSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    errSpy.mockRestore();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(storeDir, { recursive: true, force: true });
  });

  it('reports manifest errors and counts nothing', async () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'),
      'required:\n  - ANTHROPIC_API_KEY\n  - SOME_SECRET\n');

    const result = await runSetup(tmpDir, { check: true, backend });

    expect(result.manifestErrors).toBeDefined();
    expect(result.manifestErrors!.length).toBe(3);
    expect(result.complete).toBe(false);
    // The whole defect: "Missing: 3 required" was a measurement of punctuation.
    expect(result.missing).toBe(0);
    expect(result.missingNames).toEqual([]);
    expect(result.existing).toBe(0);
  });

  it('names the offending line and shows the expected format on stderr', async () => {
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'ANTHROPIC_API_KEY\nbad:line\n');
    await runSetup(tmpDir, { check: true, backend });

    const printed = errSpy.mock.calls.flat().join('');
    expect(printed).toContain('line 2');
    // The line itself is NOT echoed: a manifest line is where a pasted
    // credential lands, and this stderr is what CI logs capture. The line
    // number plus the reason locate it without reading the file back.
    expect(printed).toContain('one secret name per line');
    // Must not imply the store was consulted.
    expect(printed).toContain('No secrets were checked');
  });

  it('does not echo a credential VALUE from an unparseable manifest to stderr', async () => {
    // `.secretless` is documented "safe to commit", so this parse-error path is
    // the surface that reads it — and `setup --check` stderr is exactly what
    // lands in CI logs. Both leaking shapes are covered: NAME=VALUE and
    // NAME VALUE (which leaked twice, text and reason).
    const ANTHROPIC = ['sk-ant-api03-', 'FAKEvalueLEAKEDdonotprint'].join('');
    const GITHUB = ['ghp_', 'FAKEtokenLEAKEDdonotprint'].join('');
    fs.writeFileSync(path.join(tmpDir, '.secretless'),
      `ANTHROPIC_API_KEY=${ANTHROPIC}\nGITHUB_TOKEN ${GITHUB}\n`);

    await runSetup(tmpDir, { check: true, backend });

    const printed = errSpy.mock.calls.flat().join('');
    expect(printed).not.toContain(ANTHROPIC);
    expect(printed).not.toContain(GITHUB);
    // Still actionable: both lines are located, and the line whose NAME position
    // holds a real name still shows it. The `NAME=VALUE` line does not, because
    // `=` is also base64 padding and the left side can be the whole secret.
    expect(printed).toContain('line 1');
    expect(printed).toContain('line 2');
    expect(printed).toContain('dotenv');
    expect(printed).toContain('GITHUB_TOKEN');
  });

  it('CONTROL: a valid manifest still produces a real count', async () => {
    const store = new SecretStore({ backend });
    await store.setSecret('PRESENT_KEY', 'v');
    fs.writeFileSync(path.join(tmpDir, '.secretless'), 'PRESENT_KEY\nABSENT_KEY\n');

    const result = await runSetup(tmpDir, { check: true, backend });

    expect(result.manifestErrors).toBeUndefined();
    expect(result.existing).toBe(1);
    expect(result.missing).toBe(1);
    expect(result.missingNames).toEqual(['ABSENT_KEY']);
  });
});
