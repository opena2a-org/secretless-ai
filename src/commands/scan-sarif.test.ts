import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { pathToFileURL } from 'url';
import { runScan } from './core';
import { SARIF_SCHEMA_URL, SARIF_VERSION, SRCROOT, type SarifLog } from '../sarif';

/**
 * `scan --format sarif` is `scan --json` written as SARIF 2.1.0: the same
 * findings, the same summary, the same exit code, and one document on stdout
 * with nothing else. Built from the same report, so the two cannot disagree
 * about a finding.
 */

// The same real-looking key src/commands/scan-json.test.ts plants, joined at
// run time so that no source line has the shape of a provider token.
const REAL = ['sk-ant-api03-', 'aB3kP9xQ2mZvW7nY4tL6rJ8sH1cF5gD0eAbCdEfGhIjKlMnOpQr'].join('');

const made: string[] = [];

function tmpProjectWith(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-sarif-'));
  made.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

/** `runScan` with stdout and stderr captured. */
async function run(dir: string, options: Parameters<typeof runScan>[1]): Promise<{ code: number; stdout: string; stderr: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const log = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
  const error = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.map(String).join(' ')); });
  try {
    const code = await runScan(dir, options);
    return { code, stdout: out.join('\n'), stderr: err.join('\n') };
  } finally {
    log.mockRestore();
    error.mockRestore();
  }
}

describe('runScan --format sarif', () => {
  it('writes the findings of --json on the same tree as SARIF 2.1.0, with the same exit code', async () => {
    const dir = tmpProjectWith({
      'config.js': `const k = "${REAL}";\n`,
      '.env': `ANTHROPIC_API_KEY=${REAL}\n`,
    });

    const json = await run(dir, { json: true });
    const sarif = await run(dir, { format: 'sarif' });
    const report = JSON.parse(json.stdout);
    const doc = JSON.parse(sarif.stdout) as SarifLog;

    expect(json.code).toBe(1);
    expect(sarif.code).toBe(1);
    expect(sarif.stderr).toBe('');
    expect(doc.$schema).toBe(SARIF_SCHEMA_URL);
    expect(doc.version).toBe(SARIF_VERSION);
    expect(doc.runs[0].tool.driver.name).toBe('secretless-ai');
    expect(doc.runs[0].tool.driver.version).toBe(report.version);

    // One result per finding, each with the file, line and pattern id of its finding.
    expect(report.findings.length).toBeGreaterThanOrEqual(2);
    expect(doc.runs[0].results).toHaveLength(report.findings.length);
    report.findings.forEach((f: { file: string; line: number; patternId: string; severity: string }, i: number) => {
      const result = doc.runs[0].results[i];
      expect(result.ruleId).toBe(f.patternId);
      expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe(f.file);
      expect(result.locations[0].physicalLocation.region.startLine).toBe(f.line);
      expect(result.properties.severity).toBe(f.severity);
      expect(doc.runs[0].tool.driver.rules[result.ruleIndex].id).toBe(f.patternId);
    });

    // One rule per pattern id, at the highest severity the pattern was found at.
    const ids = [...new Set(report.findings.map((f: { patternId: string }) => f.patternId))];
    expect(doc.runs[0].tool.driver.rules.map((r) => r.id)).toEqual(ids);
    for (const rule of doc.runs[0].tool.driver.rules) {
      const critical = report.findings.some((f: { patternId: string; severity: string }) => f.patternId === rule.id && f.severity === 'critical');
      expect(rule.properties['security-severity']).toBe(critical ? '9.0' : '7.0');
    }
    expect(new Set(report.findings.map((f: { severity: string }) => f.severity))).toEqual(new Set(['critical', 'high']));

    expect(doc.runs[0].properties.summary).toEqual(report.summary);
    expect(doc.runs[0].originalUriBaseIds).toEqual({ [SRCROOT]: { uri: `${pathToFileURL(dir).href}/` } });
  });

  it('holds neither the credential value nor the preview line', async () => {
    const dir = tmpProjectWith({ 'config.js': `const k = "${REAL}";\n` });
    const { stdout } = await run(dir, { format: 'sarif' });
    expect(stdout).toContain('"ruleId": "anthropic"');
    expect(stdout).not.toContain(REAL);
    expect(stdout).not.toContain('REDACTED');
  });

  it('is an empty results list at exit 0 for a clean tree, with no banner', async () => {
    const dir = tmpProjectWith({ 'index.ts': 'export const x = 1;\n' });
    const { code, stdout } = await run(dir, { format: 'sarif' });
    const doc = JSON.parse(stdout) as SarifLog;
    expect(code).toBe(0);
    expect(doc.runs[0].results).toEqual([]);
    expect(doc.runs[0].tool.driver.rules).toEqual([]);
    expect(doc.runs[0].properties.summary).toMatchObject({ total: 0, truncated: false });
    expect(stdout).not.toContain('Secretless Scanner');
  });

  it('keeps the findings in their --json shape under --explain', async () => {
    const dir = tmpProjectWith({ 'config.js': `const k = "${REAL}";\n` });
    const { stdout } = await run(dir, { format: 'sarif', explain: true });
    expect(JSON.parse(stdout).runs[0].results.length).toBeGreaterThan(0);
    expect(stdout).not.toContain('confidenceFactors');
  });

  it('refuses a missing target on stderr with nothing on stdout, as --json does', async () => {
    const missing = path.join(tmpProjectWith({}), 'missing');
    const { code, stdout, stderr } = await run(missing, { format: 'sarif' });
    expect(code).toBe(1);
    expect(stdout).toBe('');
    expect(stderr).toBe(`Directory not found: ${missing}`);
  });
});
