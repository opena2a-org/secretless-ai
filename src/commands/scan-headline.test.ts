import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from './core';

// #410: the human report's headline counted only the critical findings, so
// `3 critical credentials exposed` stood over a list of 7. The headline now
// gives the total the list holds, with the critical count labelled on it.

function tmpProjectWith(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-headline-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

function captureConsole(): string[] {
  const out: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  return out;
}

// Split so this file does not itself match a credential pattern. Severity
// follows the file: a key in `.env` is critical, the same key in source high.
const ANTHROPIC = ['sk-ant-api03-', 'aB3kP9xQ2mZvW7nY4tL6rJ8sH1cF5gD0eAbCdEfGhIjKlMnOpQr'].join('');

async function severities(dir: string): Promise<{ total: number; critical: number }> {
  const out = captureConsole();
  await runScan(dir, { json: true });
  vi.restoreAllMocks();
  const doc = JSON.parse(out.join('\n')) as { findings: { severity: string }[] };
  return {
    total: doc.findings.length,
    critical: doc.findings.filter((f) => f.severity === 'critical').length,
  };
}

async function humanReport(dir: string): Promise<string> {
  const out = captureConsole();
  await runScan(dir);
  vi.restoreAllMocks();
  return out.join('\n');
}

describe('scan headline agrees with the findings it lists (#410)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('with critical and high findings, the headline gives the total and labels the critical count', async () => {
    const dir = tmpProjectWith({
      'config.js': `const k = "${ANTHROPIC}";\n`,
      '.env': `ANTHROPIC_API_KEY=${ANTHROPIC}\n`,
    });
    const { total, critical } = await severities(dir);
    // The case under test: some findings are critical and some are not.
    expect(critical).toBeGreaterThan(0);
    expect(critical).toBeLessThan(total);

    const text = await humanReport(dir);
    expect(text).toContain(`${total} credentials exposed, ${critical} critical`);
    expect(text).not.toMatch(new RegExp(`^\\s*${critical} critical credentials? exposed`, 'm'));
  });

  it('with only critical findings, the headline count is the total', async () => {
    const dir = tmpProjectWith({ '.env': `ANTHROPIC_API_KEY=${ANTHROPIC}\n` });
    const { total, critical } = await severities(dir);
    expect(critical).toBe(total);
    const text = await humanReport(dir);
    expect(text).toContain(`${total} critical credential${total > 1 ? 's' : ''} exposed`);
  });

  it('with no critical finding, the headline count is the total', async () => {
    const dir = tmpProjectWith({ 'config.js': `const k = "${ANTHROPIC}";\n` });
    const { total, critical } = await severities(dir);
    expect(critical).toBe(0);
    const text = await humanReport(dir);
    expect(text).toContain(`${total} credential${total > 1 ? 's' : ''} found`);
  });
});
