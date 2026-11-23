/**
 * The default `scan` view printed a Fix for each finding but no command that
 * shows the fix worked; only `--explain` did. Each finding in the default view
 * carries the same `Verify:` line `--explain` gives it.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { runScan } from './core';

const OPENAI_KEY = ['sk-proj-', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2'].join('');
const AWS_KEY = ['AKIA', 'Q7XK2M9PLR4TWZ3B'].join('');

// eslint-disable-next-line no-control-regex
const plain = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');

/** The operands of every `│ Verify: <cmd> <operand>` line, resolved from cwd. */
function verifyTargets(lines: string[], cmd: string): string[] {
  const prefix = `│ Verify: ${cmd} `;
  return lines
    .map(l => plain(l).trim())
    .filter(l => l.startsWith(prefix))
    .map(l => fs.realpathSync(path.resolve(process.cwd(), l.slice(prefix.length))));
}

describe('scan — the default view gives each finding a Verify line', () => {
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
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  });

  const project = (files: Record<string, string>) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-default-verify-'));
    dirs.push(dir);
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return dir;
  };

  it('prints one Verify per finding, re-scanning the flagged file from where the user is', async () => {
    const dir = project({
      'src/client.js': `const k = "${OPENAI_KEY}";\n`,
      'src/aws.js': `const id = "${AWS_KEY}";\n`,
    });
    const code = await runScan(dir);

    expect(code).toBe(1);
    const targets = verifyTargets(out, 'npx secretless-ai scan').sort();
    expect(targets).toEqual([
      fs.realpathSync(path.join(dir, 'src/aws.js')),
      fs.realpathSync(path.join(dir, 'src/client.js')),
    ]);
    expect(out.join('\n')).not.toContain(OPENAI_KEY);
  });

  it('verifies a file flagged for existing with a listing', async () => {
    const dir = project({ 'keys/store.p12': 'binary keystore stand-in\n' });
    await runScan(dir);

    expect(verifyTargets(out, 'ls -l')).toEqual([fs.realpathSync(path.join(dir, 'keys/store.p12'))]);
  });

  it('re-scans the named file when the target is a file', async () => {
    const dir = project({ 'notes.md': `export OPENAI_API_KEY=${OPENAI_KEY}\n` });
    const file = path.join(dir, 'notes.md');
    await runScan(file);

    expect(verifyTargets(out, 'npx secretless-ai scan')).toEqual([fs.realpathSync(file)]);
  });
});
