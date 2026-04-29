import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { isKnownExample, findRealMatch, scan } from './scan';
import { CREDENTIAL_PATTERNS } from './patterns';
import { buildMatcher } from './secretlessignore';

function patternByName(name: string) {
  const p = CREDENTIAL_PATTERNS.find(p => p.name === name);
  if (!p) throw new Error(`pattern ${name} not found`);
  return p;
}

describe('isKnownExample (issue #50 — comment-marker precedence)', () => {
  it('does NOT treat a line with # but no "example" as a known example', () => {
    // Python comment line with a credential-shaped value but no "example" marker.
    // Previous buggy precedence `(A && B) || C` would enter the inner block on any
    // line containing `#`. Regression guard: must return false here.
    const line = '# TODO: rotate AKIAREALKEY1234567890 next sprint';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(false);
  });

  it('DOES treat a line with "example //" as a known example', () => {
    const line = 'const key = "AKIASOMEOTHERKEY12345"; // example placeholder';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('treats the AKIAIOSFODNN7EXAMPLE public example as a known example', () => {
    const line = 'See AKIAIOSFODNN7EXAMPLE in the AWS docs.';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(isKnownExample(line, match)).toBe(true);
  });
});

describe('findRealMatch (issue #51 — known-example shadowing)', () => {
  it('mixed-pattern line: AWS example + real GitHub PAT returns the PAT', () => {
    // Intentionally NO `//` or `#` markers — we're testing that the KNOWN_EXAMPLE_KEYS
    // match for AKIAIOSFODNN7EXAMPLE does not shadow the real GitHub PAT later on
    // the same line. (Lines with comment+example context are an orthogonal case
    // handled by isKnownExample directly.)
    const line = 'const old = "AKIAIOSFODNN7EXAMPLE"; const new_ = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";';
    const awsPattern = patternByName('AWS Access Key');
    const ghPattern = patternByName('GitHub Token');

    // AWS pattern: only match is the public example -> no real match
    expect(findRealMatch(line, awsPattern)).toBeNull();
    // GitHub pattern: match is real
    const ghMatch = findRealMatch(line, ghPattern);
    expect(ghMatch).not.toBeNull();
    expect(ghMatch![0]).toBe('ghp_abcdefghijklmnopqrstuvwxyz1234567890');
  });

  it('multi-match same-pattern line: example AKIAIOSFODNN7EXAMPLE before real AKIA key returns the real one', () => {
    // AWS Access Key pattern ships without /g; findRealMatch must still iterate
    // every match on the line and skip the example to find the real key.
    const line = 'const keys = ["AKIAIOSFODNN7EXAMPLE", "AKIAREALKEY1234567890"];';
    const awsPattern = patternByName('AWS Access Key');
    const match = findRealMatch(line, awsPattern);
    expect(match).not.toBeNull();
    // AWS regex is AKIA[0-9A-Z]{16} — match is exactly 20 chars, trailing digits truncated.
    expect(match![0]).toBe('AKIAREALKEY123456789');
  });

  it('returns null when every match on the line is a known example', () => {
    const line = '// examples: AKIAIOSFODNN7EXAMPLE';
    const awsPattern = patternByName('AWS Access Key');
    expect(findRealMatch(line, awsPattern)).toBeNull();
  });
});

describe('scan() — .secretlessignore integration', () => {
  function tmpProjectWith(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-ignore-'));
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return dir;
  }

  // Real-shape OpenAI project key constructed via [].join('') so GitHub
  // Push Protection (and our own scanner if it ever scans this test file)
  // doesn't flag the literal string at commit time.
  const REAL_OPENAI_KEY = ['sk-proj-', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2'].join('');

  it('default-ignore suppresses findings under fixture dirs (docs/vhs)', () => {
    const dir = tmpProjectWith({
      'docs/vhs/setup-lab.sh': `OPENAI_API_KEY=${REAL_OPENAI_KEY}\n`,
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings).toEqual([]);
  });

  it('default-ignore suppresses findings under test-server/', () => {
    const dir = tmpProjectWith({
      'test-server/agents.js': `const k = '${REAL_OPENAI_KEY}';\n`,
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings).toEqual([]);
  });

  it('--no-ignore (ignore: false) re-enables findings inside fixture dirs', () => {
    const dir = tmpProjectWith({
      'docs/vhs/setup-lab.sh': `const k = '${REAL_OPENAI_KEY}';\n`,
    });
    const findings = scan(dir, { scanGlobal: false, ignore: false });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].file).toBe('docs/vhs/setup-lab.sh');
  });

  it('user-provided matcher takes precedence over loading from disk', () => {
    const dir = tmpProjectWith({
      'src/cred.ts': `const k = '${REAL_OPENAI_KEY}';\n`,
      // A user .secretlessignore that ignores src/ would suppress findings.
      // We pass a custom matcher that does NOT ignore src/ — assert it wins.
      '.secretlessignore': 'src/\n',
    });
    const m = buildMatcher([]); // empty matcher = nothing ignored
    const findings = scan(dir, { scanGlobal: false, ignore: m });
    expect(findings.length).toBeGreaterThan(0);
  });

  it('user-defined patterns add to defaults', () => {
    const dir = tmpProjectWith({
      'src/cred.ts': `const k = '${REAL_OPENAI_KEY}';\n`,
      '.secretlessignore': 'src/\n',
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings).toEqual([]);
  });

  it('default-ignore does NOT suppress non-fixture dirs (src/, lib/, root)', () => {
    const dir = tmpProjectWith({
      'src/cred.ts': `const k = '${REAL_OPENAI_KEY}';\n`,
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].file).toBe('src/cred.ts');
  });
});
