import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan, parseFileSize } from './core';

function tmpProjectWith(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-json-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

// Issue #63: `scan --json` must emit a single valid JSON document, not the human report.
describe('runScan --json', () => {
  afterEach(() => vi.restoreAllMocks());

  it('emits valid parseable JSON with findings and a summary', async () => {
    const REAL = ['sk-ant-api03-', 'aB3kP9xQ2mZvW7nY4tL6rJ8sH1cF5gD0eAbCdEfGhIjKlMnOpQr'].join('');
    const dir = tmpProjectWith({ 'config.js': `const k = "${REAL}";\n` });
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    const code = await runScan(dir, { json: true });
    const doc = JSON.parse(lines.join('\n')); // throws if not valid JSON

    expect(code).toBe(1); // findings present -> exit 1 for CI gating
    expect(doc.tool).toBe('secretless-ai');
    expect(typeof doc.version).toBe('string');
    expect(doc.summary.total).toBe(doc.findings.length);
    expect(doc.findings.length).toBeGreaterThan(0);
    expect(doc.findings[0]).toHaveProperty('confidence');
    expect(doc.findings[0]).toHaveProperty('patternId');
  });

  it('emits valid JSON (empty findings, exit 0) for a clean directory', async () => {
    const dir = tmpProjectWith({ 'index.ts': 'export const x = 1;\n' });
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    const code = await runScan(dir, { json: true });
    const doc = JSON.parse(lines.join('\n'));

    expect(code).toBe(0);
    expect(doc.summary.total).toBe(0);
    expect(doc.findings).toEqual([]);
  });

  it('does NOT print the human "Secretless Scanner" banner in JSON mode', async () => {
    const dir = tmpProjectWith({ 'index.ts': 'export const x = 1;\n' });
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    await runScan(dir, { json: true });
    expect(lines.join('\n')).not.toContain('Secretless Scanner');
  });
});

describe('parseFileSize (--max-file-size)', () => {
  it('parses a bare byte count', () => {
    expect(parseFileSize('2048')).toBe(2048);
  });

  it.each([
    ['20mb', 20 * 1024 * 1024],
    ['20MB', 20 * 1024 * 1024],
    ['20m', 20 * 1024 * 1024],
    ['500kb', 500 * 1024],
    ['1gb', 1024 * 1024 * 1024],
    ['1.5mb', Math.floor(1.5 * 1024 * 1024)],
    [' 20 mb ', 20 * 1024 * 1024],
  ])('parses %s', (input, expected) => {
    expect(parseFileSize(input)).toBe(expected);
  });

  it.each([
    ['0'],            // a zero cap would skip everything
    ['-5mb'],
    ['20abc'],        // parseInt would have silently returned 20
    ['1e6'],          // parseInt would have silently returned 1
    ['mb'],
    [''],
    ['20 mb extra'],
  ])('returns null for %s rather than guessing', (input) => {
    // Returning a default here would ignore the flag without saying so, which
    // is the same silent-shortfall class the flag exists to fix.
    expect(parseFileSize(input)).toBeNull();
  });
});
