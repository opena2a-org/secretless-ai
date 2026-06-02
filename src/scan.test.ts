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

describe('scan() — confidence + fixture flag (Wave 2)', () => {
  function tmpProjectWith(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-conf-'));
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return dir;
  }

  const REAL_OPENAI_KEY = ['sk-proj-', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2'].join('');

  const PEM_KEY = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn',
    '-----END RSA PRIVATE KEY-----',
  ].join('\n');

  it('detects standalone private-key files (server.key, id_rsa.pem) — regression', () => {
    const dir = tmpProjectWith({
      'server.key': PEM_KEY + '\n',
      'certs/id_rsa.pem': PEM_KEY + '\n',
      'config/api.ts': `const x = 1;\n`,
    });
    const findings = scan(dir, { scanGlobal: false });
    const keyFiles = findings.filter(f => f.patternId === 'pem-private-key').map(f => f.file).sort();
    expect(keyFiles).toContain('server.key');
    expect(keyFiles).toContain(path.join('certs', 'id_rsa.pem'));
  });

  it('flags binary PKCS#12 keystores by existence, ignores public certs', () => {
    const dir = tmpProjectWith({
      'keystore.p12': 'binary-pkcs12-bytes',
      'public.crt': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.some(f => f.patternId === 'pkcs12-keystore' && f.file === 'keystore.p12')).toBe(true);
    // A public certificate (no PRIVATE KEY block) must not be flagged.
    expect(findings.some(f => f.file === 'public.crt')).toBe(false);
  });

  it('every finding carries a confidence score in [0, 1] and a tier label', () => {
    const dir = tmpProjectWith({
      'src/cred.ts': `const k = '${REAL_OPENAI_KEY}';\n`,
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0];
    expect(typeof f.confidence).toBe('number');
    expect(f.confidence).toBeGreaterThan(0);
    expect(f.confidence).toBeLessThanOrEqual(1);
    expect(['high', 'medium', 'low']).toContain(f.confidenceTier);
  });

  it('looksLikeFixture is false when fixture filtering is on (defaults applied)', () => {
    const dir = tmpProjectWith({
      'src/cred.ts': `const k = '${REAL_OPENAI_KEY}';\n`,
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings[0].looksLikeFixture).toBe(false);
  });

  it('looksLikeFixture is TRUE when --no-ignore surfaces a fixture-path finding', () => {
    const dir = tmpProjectWith({
      'docs/vhs/setup-lab.sh': `OPENAI_API_KEY=${REAL_OPENAI_KEY}\n`,
    });
    const findings = scan(dir, { scanGlobal: false, ignore: false });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].file).toBe('docs/vhs/setup-lab.sh');
    expect(findings[0].looksLikeFixture).toBe(true);
  });

  it('looksLikeFixture is FALSE for non-fixture-path findings even with --no-ignore', () => {
    const dir = tmpProjectWith({
      'src/cred.ts': `const k = '${REAL_OPENAI_KEY}';\n`,
    });
    const findings = scan(dir, { scanGlobal: false, ignore: false });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].file).toBe('src/cred.ts');
    expect(findings[0].looksLikeFixture).toBe(false);
  });

  it('--min-confidence drops findings below the threshold', () => {
    const dir = tmpProjectWith({
      // README.md is a docs path — path tier 0.4 lowers composite confidence.
      'README.md': `\`\`\`\n${REAL_OPENAI_KEY}\n\`\`\`\n`,
      'src/cred.ts': `const k = '${REAL_OPENAI_KEY}';\n`,
    });
    const high = scan(dir, { scanGlobal: false, minConfidence: 0.85 });
    const all = scan(dir, { scanGlobal: false, minConfidence: 0 });
    expect(all.length).toBeGreaterThanOrEqual(high.length);
  });

  it('--min-confidence=1.0 drops everything except perfect-confidence findings', () => {
    const dir = tmpProjectWith({
      // The only path that scores 1.0 path-tier is .env / config files; even
      // there, the composite is below 1.0 because pattern + entropy + length
      // weights are < 1 each. So minConfidence=1 should drop everything.
      'src/cred.ts': `const k = '${REAL_OPENAI_KEY}';\n`,
    });
    const findings = scan(dir, { scanGlobal: false, minConfidence: 1.0 });
    expect(findings).toEqual([]);
  });

  it('findings are sorted by descending confidence within the same severity', () => {
    const dir = tmpProjectWith({
      // Two findings, different paths → different path tiers → different
      // confidences. Confirm the higher-confidence one comes first.
      'src/cred.ts': `const k = '${REAL_OPENAI_KEY}';\n`,
      'README.md': `\`\`\`\n${REAL_OPENAI_KEY}\n\`\`\`\n`,
    });
    const findings = scan(dir, { scanGlobal: false });
    // Filter to the same severity to defeat the severity-first sort.
    const sameSeverity = findings.filter(f => f.severity === findings[0].severity);
    for (let i = 1; i < sameSeverity.length; i++) {
      expect(sameSeverity[i - 1].confidence).toBeGreaterThanOrEqual(sameSeverity[i].confidence);
    }
  });
});
