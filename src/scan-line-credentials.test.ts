import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scan, newScanStats } from './scan';

/**
 * Each credential on a line is a finding of its own (#471). A line used to be
 * one finding at most, for the first pattern in list order with a match, so a
 * line holding an npm token and a Google API key listed the npm token alone.
 */

const NPM = ['npm_', 'aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5'].join('');
const GKEY = ['AIzaSy', 'B7xK2mNvPwQ4tZ8hLcDfGjHkMnOpQrStU'].join('');
const GKEY2 = ['AIzaSy', 'D-1234567890abcdefghijklmnopqrstuv'].join('');

const dirs: string[] = [];
function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-line-creds-'));
  dirs.push(dir);
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

const byPattern = (a: { patternId: string }, b: { patternId: string }): number => a.patternId.localeCompare(b.patternId);

describe('a line with several credentials is a finding for each (#471)', () => {
  const LINE = `a="${NPM}";b="${GKEY}"`;

  it('an npm token and a Google key on one source line are two findings, in a directory scan and a named file', () => {
    const dir = project({ 'client.js': `${LINE}\n` });
    for (const target of [dir, path.join(dir, 'client.js')]) {
      const findings = scan(target, { scanGlobal: false }).sort(byPattern);
      expect(findings.map((f) => [f.patternId, f.line]), target).toEqual([['google', 1], ['npm', 1]]);
      for (const f of findings) {
        expect(f.preview).toContain('[npm Access Token REDACTED]');
        expect(f.preview).toContain('[Google API Key REDACTED]');
        expect(f.preview).not.toContain(NPM);
        expect(f.preview).not.toContain(GKEY);
      }
      expect(findings.find((f) => f.patternId === 'google')!.fix).toContain('GOOGLE_API_KEY');
      expect(findings.find((f) => f.patternId === 'npm')!.fix).toContain('NPM_TOKEN');
    }
  });

  it('the same in a config file the config walk reads', () => {
    const dir = project({ '.env': `TOKENS=${NPM},${GKEY}\n` });
    const findings = scan(dir, { scanGlobal: false }).sort(byPattern);
    expect(findings.map((f) => [f.file, f.patternId, f.severity])).toEqual([
      ['.env', 'google', 'critical'], ['.env', 'npm', 'critical'],
    ]);
  });

  it('two Google keys on one line are two findings, not collapsed as one place in the file', () => {
    const dir = project({ 'client.js': `const keys = ["${GKEY}", "${GKEY2}"];\n` });
    for (const target of [dir, path.join(dir, 'client.js')]) {
      const findings = scan(target, { scanGlobal: false });
      expect(findings.map((f) => [f.patternId, f.line]), target).toEqual([['google', 1], ['google', 1]]);
    }
  });

  it('a credential under one marker is still one finding: a known example beside it is hidden and counted once', () => {
    const dir = project({ 'client.js': `const id = "AKIAIOSFODNN7EXAMPLE"; const npm = "${NPM}";\n` });
    const stats = newScanStats();
    const findings = scan(dir, { scanGlobal: false }, stats);
    expect(findings.map((f) => f.patternId)).toEqual(['npm']);
    expect(stats.placeholdersSuppressed).toBe(1);
  });
});
