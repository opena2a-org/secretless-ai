import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan, runStatus, runVerify } from './core';

// #125: a command that could not do what it was asked must not print a clean
// verdict and exit 0. Not-found and suppressed-by-filter are distinct from
// clean, and each is visible in the output and (where the user did not ask
// for it) in the exit code. Not-a-repo for scan-staged is covered in
// src/scan-staged.test.ts, which already mocks git.

function tmpProjectWith(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'third-state-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

function captureConsole(): { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.map(String).join(' ')); });
  return { out, err };
}

const MISSING = path.join(os.tmpdir(), 'secretless-125-does-not-exist', 'nested');

describe('status and verify on a directory that does not exist (#125)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('status refuses with scan\'s message and exit 1, printing no verdict', async () => {
    const { out, err } = captureConsole();
    const code = await runStatus(MISSING);
    expect(code).toBe(1);
    expect(err.join('\n')).toContain(`Directory not found: ${MISSING}`);
    expect(out.join('\n')).not.toContain('Verdict');
  });

  it('status --json keeps stdout empty and exits 1', async () => {
    const { out, err } = captureConsole();
    const code = await runStatus(MISSING, { json: true });
    expect(code).toBe(1);
    expect(out).toEqual([]);
    expect(err.join('\n')).toContain('Directory not found');
  });

  it('verify refuses instead of printing PASS', () => {
    const { out, err } = captureConsole();
    const code = runVerify(MISSING);
    expect(code).toBe(1);
    expect(err.join('\n')).toContain(`Directory not found: ${MISSING}`);
    expect(out.join('\n')).not.toContain('PASS');
  });
});

describe('scan --min-confidence discloses what it filtered (#125)', () => {
  afterEach(() => vi.restoreAllMocks());

  // Split so this file does not itself match a credential pattern.
  const REAL = ['sk-ant-api03-', 'aB3kP9xQ2mZvW7nY4tL6rJ8sH1cF5gD0eAbCdEfGhIjKlMnOpQr'].join('');

  it('--json reports minConfidence and confidenceSuppressed', async () => {
    const dir = tmpProjectWith({ 'config.js': `const k = "${REAL}";\n` });

    const unfiltered = captureConsole();
    await runScan(dir, { json: true });
    const base = JSON.parse(unfiltered.out.join('\n'));
    vi.restoreAllMocks();
    expect(base.summary.total).toBe(1);
    expect(base.summary.minConfidence).toBe(0);
    expect(base.summary.confidenceSuppressed).toBe(0);
    // The threshold below only filters if the finding scores under 1.
    expect(base.findings[0].confidence).toBeLessThan(1);

    const filtered = captureConsole();
    const code = await runScan(dir, { json: true, minConfidence: 1 });
    const doc = JSON.parse(filtered.out.join('\n'));
    expect(doc.summary.total).toBe(0);
    expect(doc.summary.minConfidence).toBe(1);
    expect(doc.summary.confidenceSuppressed).toBe(1);
    // The user asked for the filter, so, like placeholders, it does not fail the run.
    expect(code).toBe(0);
  });

  it('the human report does not claim "No hardcoded credentials found" over a filtered match', async () => {
    const dir = tmpProjectWith({ 'config.js': `const k = "${REAL}";\n` });
    const { out } = captureConsole();
    await runScan(dir, { minConfidence: 1 });
    const text = out.join('\n');
    expect(text).not.toContain('No hardcoded credentials found');
    expect(text).toContain('No credentials found at or above confidence 1.');
    expect(text).toContain('1 match scored below --min-confidence 1 and was hidden.');
  });

  it('prints no filter line when nothing was filtered', async () => {
    const dir = tmpProjectWith({ 'index.ts': 'export const x = 1;\n' });
    const { out } = captureConsole();
    const code = await runScan(dir, { minConfidence: 0.5 });
    const text = out.join('\n');
    expect(code).toBe(0);
    expect(text).toContain('No hardcoded credentials found.');
    expect(text).not.toContain('--min-confidence');
  });
});
