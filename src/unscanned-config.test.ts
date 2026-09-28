import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from './commands/core';
import { isConfigShaped } from './patterns';

/**
 * #124 — a config-format file whose NAME is not on `CONFIG_FILES` was read by
 * no walk, and the scan said nothing.
 *
 * The config walk matches names (`config.json`, `docker-compose.yml`); the
 * source walk matches source extensions. `secrets.json`, `.npmrc`,
 * `values.yaml`, `app.toml` and `Dockerfile` are neither, so a tree whose only
 * key sat in one of them scanned to `total: 0`, exit 0, and the text report
 * read "No hardcoded credentials found." with no line about the file. Each is
 * detected when named directly, so this is file SELECTION, not detection.
 *
 * Now: such files are a declared boundary (`summary.unscannedConfig`, named in
 * the text report with the command that reads them), NON-GATING like the other
 * boundaries, and `--include-config` scans them.
 *
 * RED-ON-BASE cells fail on main before this change. SCOPE cells pin what the
 * new boundary leaves out (they need the new field, so they cannot run on
 * main). The CONTROL cell passes on both.
 */

function tree(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unscanned-config-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

// Assembled at runtime so no literal token sits in the source.
const TOKEN = ['ghp_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');

async function capture(target: string, opts: Parameters<typeof runScan>[1]) {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  const code = await runScan(target, opts);
  return { out: lines.join('\n'), code };
}

async function json(target: string, extra: Parameters<typeof runScan>[1] = {}) {
  const { out, code } = await capture(target, { json: true, ...extra });
  return { doc: JSON.parse(out), code };
}

const OFF_LIST = {
  'secrets.json': `{"token":"${TOKEN}"}\n`,
  '.npmrc': `//registry.npmjs.org/:_authToken=${TOKEN}\n`,
  'values.yaml': `token: "${TOKEN}"\n`,
  'app.toml': `token = "${TOKEN}"\n`,
  'Dockerfile': `ENV TOKEN=${TOKEN}\n`,
};

describe('#124 config files off the built-in list', () => {
  afterEach(() => vi.restoreAllMocks());

  it('RED-ON-BASE: a key only in secrets.json is reported as an unscanned config file, not as clean', async () => {
    const dir = tree({ 'secrets.json': `{"token":"${TOKEN}"}\n` });
    const { doc, code } = await json(dir);
    expect(doc.summary.total).toBe(0);
    expect(doc.summary.unscannedConfig).toBe(1);
    expect(doc.unscannedConfigFiles).toEqual(['secrets.json']);
    // A boundary, not a broken claim: the exit code is unchanged.
    expect(code).toBe(0);
  });

  it('RED-ON-BASE: every off-list format is counted and named', async () => {
    const dir = tree(OFF_LIST);
    const { doc } = await json(dir);
    expect(doc.summary.unscannedConfig).toBe(5);
    expect(new Set(doc.unscannedConfigFiles)).toEqual(new Set(Object.keys(OFF_LIST)));
    const reasons = new Set(doc.skippedUnsupportedFiles.map((f: { reason: string }) => f.reason));
    expect(reasons).toEqual(new Set(['config file not on the built-in list (--include-config)']));
  });

  it('RED-ON-BASE: the text report names the file, the flag and the one-file command', async () => {
    const dir = tree({ 'secrets.json': `{"token":"${TOKEN}"}\n`, 'app.js': 'module.exports = 1;\n' });
    const { out, code } = await capture(dir, {});
    expect(code).toBe(0);
    expect(out).toContain('No hardcoded credentials found.');
    expect(out).toContain('1 config file not scanned');
    expect(out).toContain('its name is not on the built-in config list, so not known to be clean.');
    expect(out).toMatch(/Fix:\s+npx secretless-ai scan \S+ --include-config/);
    expect(out).toMatch(/Scan one:\s+npx secretless-ai scan \S*secrets\.json/);
  });

  it('RED-ON-BASE: --include-config scans them, and nothing is left to report', async () => {
    const dir = tree(OFF_LIST);
    const { doc, code } = await json(dir, { includeConfig: true });
    const files = new Set(doc.findings.map((f: { file: string }) => path.basename(f.file)));
    expect(files).toEqual(new Set(Object.keys(OFF_LIST)));
    expect(doc.summary.unscannedConfig).toBe(0);
    expect(code).toBe(1);
  });

  it('RED-ON-BASE: a config file the config walk read is not also counted as "not opened"', async () => {
    const dir = tree({ 'config.json': `{"token":"${TOKEN}"}\n`, 'config.yaml': `token: "${TOKEN}"\n` });
    const { doc } = await json(dir);
    expect(doc.summary.total).toBe(2);
    expect(doc.summary.skippedUnsupported).toBe(0);
    expect(doc.summary.unscannedConfig).toBe(0);
  });

  it('CONTROL: the named file is detected when scanned directly (selection, not detection)', async () => {
    const dir = tree({ 'secrets.json': `{"token":"${TOKEN}"}\n` });
    const { doc } = await json(path.join(dir, 'secrets.json'));
    expect(doc.summary.total).toBe(1);
  });

  it('SCOPE: lockfiles, docs and default-ignored fixtures are not unscanned config', async () => {
    const dir = tree({
      'package-lock.json': '{"lockfileVersion":3}\n',
      'pnpm-lock.yaml': 'lockfileVersion: 9\n',
      'README.md': '# readme\n',
      'test/fixtures/secrets.json': `{"token":"${TOKEN}"}\n`,
    });
    const { doc } = await json(dir);
    expect(doc.summary.unscannedConfig).toBe(0);
    expect(doc.unscannedConfigFiles).toEqual([]);
  });

  it('SCOPE: the config-format predicate', () => {
    for (const n of ['secrets.json', 'appsettings.json', 'values.yaml', 'serverless.yml', 'app.toml', 'app.ini',
      'web.config', 'settings.xml', 'main.tf', 'prod.tfvars', '.npmrc', '.pypirc', 'Dockerfile', 'Dockerfile.prod', 'api.Dockerfile']) {
      expect(isConfigShaped(n), n).toBe(true);
    }
    for (const n of ['package-lock.json', 'pnpm-lock.yaml', 'Cargo.lock', 'README.md', 'app.ts', 'image.png', '.gitignore', 'Makefile']) {
      expect(isConfigShaped(n), n).toBe(false);
    }
  });
});
