/**
 * What the shipped description of `vault exec` says it keeps private.
 *
 * `vault exec` sets the credential in the child's environment and starts the
 * child with inherited standard streams. Earlier README, help and type
 * declaration text said the agent, the AI tool's context and any process
 * listing never see the value; a child that prints its environment proves
 * that wrong. This suite reads the surfaces a user and an editor see (the
 * README, every built declaration, the built help text) and fails if any of
 * the old statements comes back, or if the stated limit is removed.
 *
 * It reads `dist/`, which `npm test` builds first (the `pretest` script). A
 * missing build fails here rather than skipping, so the check cannot pass by
 * not running.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..');
const DIST = path.join(ROOT, 'dist');

const OLD_CLAIMS = /never sees|see nothing|never in agent context|never enter the agent|pipes\/fds|CR-0[0-9]+/i;

function declarationFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...declarationFiles(full));
    else if (entry.name.endsWith('.d.ts')) out.push(full);
  }
  return out;
}

function hits(file: string): string[] {
  return fs
    .readFileSync(file, 'utf-8')
    .split('\n')
    .map((line, i) => ({ line, n: i + 1 }))
    .filter(({ line }) => OLD_CLAIMS.test(line))
    .map(({ line, n }) => `${path.relative(ROOT, file)}:${n}: ${line.trim()}`);
}

describe('vault exec claim surface', () => {
  it('the build exists, so the declarations and help text below are read', () => {
    expect(fs.existsSync(path.join(DIST, 'vault-core.d.ts')), 'run `npm run build` first').toBe(true);
    expect(fs.existsSync(path.join(DIST, 'commands', 'vault.js')), 'run `npm run build` first').toBe(true);
  });

  it('the README does not say the agent or a process listing never sees the value', () => {
    expect(hits(path.join(ROOT, 'README.md'))).toEqual([]);
  });

  it('no built type declaration says it', () => {
    const files = declarationFiles(DIST);
    expect(files.length).toBeGreaterThan(0);
    expect(files.flatMap(hits)).toEqual([]);
  });

  it('the built `vault` help text does not say it', () => {
    expect(hits(path.join(DIST, 'commands', 'vault.js'))).toEqual([]);
  });

  it("the README states that the child's output is not masked", () => {
    const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf-8');
    expect(readme).toContain("does not mask the child's output");
  });
});
