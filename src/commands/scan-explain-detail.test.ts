/**
 * `scan --explain` is documented as a "detailed per-finding view with
 * remediation". It used to print the plain `scan` view plus a notice to install
 * @nanomind/engine whenever the engine was not ready, and the engine reports
 * ready only when its model file and runtime exist, which installing the package
 * does not provide. So the flag added nothing, and the notice named a package
 * that was already installed.
 *
 * These tests run the real NanoMind module, not a mock: the view must not
 * depend on the engine.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { runScan } from './core';
import { isEngineAvailable } from '../nanomind';

const OPENAI_KEY = ['sk-proj-', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2'].join('');
const AWS_KEY = ['AKIA', 'Q7XK2M9PLR4TWZ3B'].join('');

function tmpProjectWith(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-explain-detail-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

/** The operand of the first `Verify: <cmd> <operand>` line, resolved from cwd. */
function verifyTarget(lines: string[], cmd: string): string {
  const line = lines.find(l => l.trim().startsWith(`Verify: ${cmd} `));
  expect(line, `no "Verify: ${cmd}" line`).toBeDefined();
  const operand = line!.trim().slice(`Verify: ${cmd} `.length);
  return fs.realpathSync(path.resolve(process.cwd(), operand));
}

describe('scan --explain — a detailed view that does not need the engine', () => {
  let out: string[];
  let dirs: string[];

  beforeEach(() => {
    out = [];
    dirs = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      out.push(args.join(' '));
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.SECRETLESS_NANOMIND_EXPLAIN;
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  });

  const project = (files: Record<string, string>) => {
    const dir = tmpProjectWith(files);
    dirs.push(dir);
    return dir;
  };

  it('prints the pattern, the confidence factors, the path rule, Fix and Verify for each finding', async () => {
    const dir = project({ 'src/client.js': `const k = "${OPENAI_KEY}";\n` });
    const code = await runScan(dir, { explain: true });
    const text = out.join('\n');

    expect(code).toBe(1);
    expect(text).toContain('Pattern: openai-proj, matching /sk-proj-[a-zA-Z0-9]{20,}/');
    expect(text).toMatch(/Confidence: high \(0\.\d\d\) from pattern \d\.\d\d, entropy \d\.\d\d, length \d\.\d\d, path 0\.85/);
    expect(text).toContain('Path: source file (0.85): no test, fixture, docs or config marker in its path');
    expect(text).toContain('Fix: Move to env var OPENAI_API_KEY');
    expect(text).toContain('Confidence weighs the pattern 35%');
    // A Verify command that runs from where the user is, on the flagged file.
    expect(verifyTarget(out, 'npx secretless-ai scan')).toBe(fs.realpathSync(path.join(dir, 'src/client.js')));
    expect(text).not.toContain(OPENAI_KEY);
  });

  it('does not tell the user to install the engine, or fall back to the plain view', async () => {
    const dir = project({ 'src/client.js': `const k = "${OPENAI_KEY}";\n` });
    await runScan(dir, { explain: true });
    const text = out.join('\n');

    expect(text).not.toContain('Install @nanomind/engine');
    expect(text).not.toContain('Falling back to standard output');
    expect(text).not.toContain('NanoMind engine not available');
  });

  it('says when a structural pattern raised the score to high', async () => {
    const dir = project({ 'src/aws.js': `const id = "${AWS_KEY}";\n` });
    await runScan(dir, { explain: true });

    expect(out.join('\n')).toContain("raised to high: the pattern's fixed structure is conclusive");
  });

  it('explains a named file by the path rule its score used, and verifies that file', async () => {
    const dir = project({ 'notes.md': `export OPENAI_API_KEY=${OPENAI_KEY}\n` });
    const file = path.join(dir, 'notes.md');
    await runScan(file, { explain: true });

    expect(out.join('\n')).toContain('Path: documentation file (0.40): a credential here is usually an example');
    expect(verifyTarget(out, 'npx secretless-ai scan')).toBe(fs.realpathSync(file));
  });

  it('explains a file flagged for existing, and verifies it with a listing', async () => {
    const dir = project({ 'keys/store.p12': 'binary keystore stand-in\n' });
    await runScan(dir, { explain: true });
    const text = out.join('\n');

    expect(text).toContain('Pattern: pkcs12-keystore, matched by file type, not content');
    expect(text).toContain("Confidence: high (0.95), fixed: the file's presence is the finding");
    expect(text).not.toContain('Path: ');
    expect(verifyTarget(out, 'ls -l')).toBe(fs.realpathSync(path.join(dir, 'keys/store.p12')));
  });

  it('names a missing model, not a missing package, when generated context is asked for', async (ctx) => {
    // Only the not-ready state is under test; a machine with a model set up has nothing to show here.
    if (await isEngineAvailable()) ctx.skip();
    process.env.SECRETLESS_NANOMIND_EXPLAIN = '1';
    const dir = project({ 'src/client.js': `const k = "${OPENAI_KEY}";\n` });
    await runScan(dir, { explain: true });
    const text = out.join('\n');

    let installed = true;
    try { require.resolve('@nanomind/engine'); } catch { installed = false; }
    expect(text).toContain(installed
      ? '@nanomind/engine is installed, but its local model is missing.'
      : '@nanomind/engine is not installed.');
    expect(text).toContain('The detailed view below does not use the engine.');
    // The view itself is unchanged by the missing engine.
    expect(text).toContain('Pattern: openai-proj');
    expect(text).toContain('Fix: Move to env var OPENAI_API_KEY');
    expect(text).not.toContain('Context (generated, unverified):');
  });

  it('keeps --json findings in their documented shape', async () => {
    const dir = project({ 'src/client.js': `const k = "${OPENAI_KEY}";\n` });
    await runScan(dir, { json: true, explain: true });

    const doc = JSON.parse(out.join('\n'));
    expect(doc.findings).toHaveLength(1);
    expect(doc.findings[0]).not.toHaveProperty('confidenceFactors');
  });
});
