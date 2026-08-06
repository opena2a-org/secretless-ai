/**
 * Regression cover for the 0.21.0 release-test P1: `scan --explain` dropped the
 * deterministic `Fix:` line and printed raw model output in its place.
 *
 * The trigger was probabilistic (the local engine usually returns an empty
 * string, so the bug only showed when it happened to produce text) but the
 * defect itself is deterministic: ANY non-null explanation replaced the fix.
 * These tests drive the render path with a forced non-null explanation, which
 * is the state the bug needs.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

vi.mock('../nanomind', () => ({
  isEngineAvailable: vi.fn(async () => true),
  explainFinding: vi.fn(async () => 'An attacker could bill API usage to your account and read stored data.'),
}));

import { runScan } from './core';
import { explainFinding } from '../nanomind';

const REAL_OPENAI_KEY = ['sk-proj-', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2'].join('');

function tmpProjectWith(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-explain-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

describe('scan --explain — generated text never replaces the verified fix', () => {
  let out: string[];
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    out = [];
    logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      out.push(args.join(' '));
    });
  });

  afterEach(() => {
    logSpy.mockRestore();
    vi.mocked(explainFinding).mockResolvedValue(
      'An attacker could bill API usage to your account and read stored data.',
    );
  });

  it('prints the deterministic Fix line even when the model returns text', async () => {
    const dir = tmpProjectWith({ 'src/client.js': `const k = "${REAL_OPENAI_KEY}";\n` });
    await runScan(dir, { explain: true });
    const text = out.join('\n');

    // The core assertion. Pre-fix this was an `else if`, so a non-null
    // explanation meant the user saw no remediation at all.
    expect(text).toContain('Fix: Move to env var OPENAI_API_KEY');
  });

  it('labels model output as generated and unverified', async () => {
    const dir = tmpProjectWith({ 'src/client.js': `const k = "${REAL_OPENAI_KEY}";\n` });
    await runScan(dir, { explain: true });
    const text = out.join('\n');

    expect(text).toContain('Context (generated, unverified):');
    // The generated sentence must appear only on the labelled line — never
    // bare, where it would read as the tool's own guidance.
    const bare = out.filter(l => l.includes('An attacker could bill API usage')
      && !l.includes('Context (generated, unverified):'));
    expect(bare, 'generated text appeared outside its label').toEqual([]);
  });

  it('still prints the Fix line when the model returns nothing', async () => {
    vi.mocked(explainFinding).mockResolvedValue(null);
    const dir = tmpProjectWith({ 'src/client.js': `const k = "${REAL_OPENAI_KEY}";\n` });
    await runScan(dir, { explain: true });
    const text = out.join('\n');

    expect(text).toContain('Fix: Move to env var OPENAI_API_KEY');
    expect(text).not.toContain('Context (generated, unverified):');
  });

  it('does not publish an unverifiable check count in the explain footer', async () => {
    const dir = tmpProjectWith({ 'src/client.js': `const k = "${REAL_OPENAI_KEY}";\n` });
    await runScan(dir, { explain: true });
    const text = out.join('\n');

    expect(text).toContain('npx hackmyagent secure');
    // "147+ checks" was stale by ~176 checks. A number in user-facing output
    // has to trace to something we measure; this one traced to nothing.
    expect(text).not.toMatch(/\d+\+?\s+checks/);
  });
});
