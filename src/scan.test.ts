import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { isKnownExample, findRealMatch, scan, fixFor } from './scan';
import { CREDENTIAL_PATTERNS } from './patterns';
import { buildMatcher, loadSecretlessIgnore } from './secretlessignore';

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

  it('scans private-key files inside hidden directories (.ssh/, .certs/)', () => {
    const dir = tmpProjectWith({
      '.ssh/id_rsa.pem': PEM_KEY + '\n',
      '.certs/server.key': PEM_KEY + '\n',
      'config/prod.key': PEM_KEY + '\n',
    });
    const found = scan(dir, { scanGlobal: false })
      .filter(f => f.patternId === 'pem-private-key')
      .map(f => f.file.replace(/\\/g, '/')).sort();
    expect(found).toContain('.ssh/id_rsa.pem');
    expect(found).toContain('.certs/server.key');
    expect(found).toContain('config/prod.key');
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

  it('counts placeholder-suppressed matches via the stats out-param', () => {
    const FAKE = ['sk-ant-api03-', 'FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE12'].join('');
    const dir = tmpProjectWith({ 'config.js': `const k = "${FAKE}";\n` });
    const stats = { placeholdersSuppressed: 0 };
    const findings = scan(dir, { scanGlobal: false }, stats);
    expect(findings.length).toBe(0);                    // suppressed from the result
    expect(stats.placeholdersSuppressed).toBeGreaterThan(0); // but counted for the hint
  });

  it('showPlaceholders surfaces values normally hidden as placeholders', () => {
    const FAKE = ['sk-ant-api03-', 'FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE12'].join('');
    const dir = tmpProjectWith({ 'config.js': `const k = "${FAKE}";\n` });
    const hidden = scan(dir, { scanGlobal: false });
    const shown = scan(dir, { scanGlobal: false, showPlaceholders: true });
    expect(hidden.length).toBe(0);
    expect(shown.length).toBeGreaterThan(0);
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

describe('scan() — project-scope MCP configs (release-test P1: .mcp.json blind spot)', () => {
  function tmpProjectWith(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-mcpjson-'));
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return dir;
  }

  const REAL_ANTHROPIC_KEY = ['sk-ant-api03-', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2'].join('');

  function mcpConfigWith(key: string): string {
    return JSON.stringify(
      {
        mcpServers: {
          demo: { command: 'npx', args: ['-y', 'demo-mcp'], env: { ANTHROPIC_API_KEY: key } },
        },
      },
      null,
      2,
    );
  }

  it('finds credentials in project-scope .mcp.json (Claude Code MCP config)', () => {
    const dir = tmpProjectWith({ '.mcp.json': mcpConfigWith(REAL_ANTHROPIC_KEY) });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.some(f => f.file === '.mcp.json' && f.patternId === 'anthropic')).toBe(true);
  });

  it('finds credentials in .cursor/mcp.json (was unreachable via the ".curse" typo)', () => {
    const dir = tmpProjectWith({ '.cursor/mcp.json': mcpConfigWith(REAL_ANTHROPIC_KEY) });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.some(f => f.file === '.cursor/mcp.json' && f.patternId === 'anthropic')).toBe(true);
  });

  it('does NOT flag a credential-free connection string in .mcp.json (canonical Postgres MCP layout)', () => {
    const dir = tmpProjectWith({
      '.mcp.json': JSON.stringify(
        {
          mcpServers: {
            postgres: {
              command: 'npx',
              args: ['-y', '@modelcontextprotocol/server-postgres', 'postgresql://localhost:5432/mydb'],
            },
          },
        },
        null,
        2,
      ),
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag an env-var-interpolated password (the recommended secure shape)', () => {
    const dir = tmpProjectWith({
      'docker-compose.yml': 'services:\n  api:\n    environment:\n      DATABASE_URL: postgres://app:${POSTGRES_PASSWORD}@db:5432/app\n',
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings).toHaveLength(0);
  });

  it('DOES flag a real redis password even when the same line interpolates the host', () => {
    // Pre-fix, the quick-check derived "rediss" from rediss?, so a plain
    // redis:// line containing ${REDIS_HOST} was skipped before scanning.
    const dir = tmpProjectWith({
      'config.yaml': 'cache: redis://:s3cretRedisPw99Xy@${REDIS_HOST}:6379/0\n',
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.some(f => f.patternId === 'redis')).toBe(true);
  });

  it('does NOT flag minified JSON where a later @ sits on the same line as a credential-free URI', () => {
    const dir = tmpProjectWith({
      '.mcp.json': '{"mcpServers":{"cache":{"command":"npx","args":["redis-mcp","redis://localhost:6379"],"env":{"OWNER":"ops@corp.io"}}}}',
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings).toHaveLength(0);
  });

  it('DOES flag a connection string with an embedded password in .mcp.json', () => {
    const dir = tmpProjectWith({
      '.mcp.json': JSON.stringify(
        {
          mcpServers: {
            postgres: {
              command: 'npx',
              args: ['-y', '@modelcontextprotocol/server-postgres', 'postgresql://svc:s3cretpw@db.internal:5432/mydb'],
            },
          },
        },
        null,
        2,
      ),
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.some(f => f.file === '.mcp.json' && f.patternId === 'postgres')).toBe(true);
  });

  it('every database connection-string finding carries a Fix line (no dead ends)', () => {
    const dir = tmpProjectWith({
      'config.yaml': [
        'cache: redis://:s3cretRedisPw99Xy@cache.internal:6379/0',
        'db: postgres://svc:s3cretpw@db.internal:5432/app',
        'legacy: mysql://svc:s3cretpw@db.internal:3306/app',
        'docs: mongodb://svc:s3cretpw@mongo.internal:27017/app',
      ].join('\n'),
    });
    const findings = scan(dir, { scanGlobal: false });
    for (const id of ['redis', 'postgres', 'mysql', 'mongodb']) {
      const f = findings.find(f => f.patternId === id);
      expect(f, `expected a ${id} finding`).toBeDefined();
      expect(f!.fix, `${id} finding has no fix line — dead end`).toBeTruthy();
    }
  });
});

describe('scan() — --include-tests actually includes test files', () => {
  function tmpProjectWith(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-tests-'));
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return dir;
  }

  const KEY = ['sk-proj-', 'Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3H2G1F0E9D8'].join('');
  const CRED_LINE = `const client = new OpenAI({ apiKey: "${KEY}" });\n`;

  it('finds a credential under test/ when includeTests is set', () => {
    // The reported P1. Two independent gates suppressed this path — the
    // walker's TEST_DIRS and the default-ignore list's `test/` — and the flag
    // only opened the first, so `--include-tests` was a silent no-op here.
    const dir = tmpProjectWith({ 'test/fixture.test.js': CRED_LINE });
    const findings = scan(dir, { scanGlobal: false, includeTests: true });
    expect(findings.map(f => f.file)).toEqual(['test/fixture.test.js']);
  });

  it('still suppresses that credential by default', () => {
    const dir = tmpProjectWith({ 'test/fixture.test.js': CRED_LINE });
    expect(scan(dir, { scanGlobal: false })).toEqual([]);
  });

  it('CONTROL: a test-named file OUTSIDE a test dir was already reachable', () => {
    // Proves the previous test is not vacuous: gate 1 (the filename check)
    // always worked, so a failure there would be a different defect.
    const dir = tmpProjectWith({ 'src/fixture.test.js': CRED_LINE });
    expect(scan(dir, { scanGlobal: false })).toEqual([]);
    const withFlag = scan(dir, { scanGlobal: false, includeTests: true });
    expect(withFlag.map(f => f.file)).toEqual(['src/fixture.test.js']);
  });

  it('reaches every test-path default, not just test/', () => {
    const dir = tmpProjectWith({
      'tests/a.js': CRED_LINE,
      '__tests__/b.js': CRED_LINE,
      '__fixtures__/c.js': CRED_LINE,
      'test-server/d.js': CRED_LINE,
      'e2e/e.js': CRED_LINE,
    });
    expect(scan(dir, { scanGlobal: false })).toEqual([]);
    const found = scan(dir, { scanGlobal: false, includeTests: true }).map(f => f.file).sort();
    expect(found).toEqual(['__fixtures__/c.js', '__tests__/b.js', 'e2e/e.js', 'test-server/d.js', 'tests/a.js']);
  });

  it('does NOT re-enable non-test default-ignore dirs', () => {
    // `examples/` and `docs/vhs/` are held back ONLY by the default-ignore
    // list, so this fixture actually exercises the layer includeTests changes.
    //
    // node_modules/dist/build are deliberately NOT used here: they are also in
    // walkSourceFiles' SOURCE_SKIP_DIRS, which answers first, so a test built on
    // them stays green even if the ignore layer is removed entirely. Mutation
    // testing caught exactly that — see the matcher-level test below, which is
    // what actually pins the generated-tree defaults.
    const dir = tmpProjectWith({
      'examples/demo.js': CRED_LINE,
      'docs/vhs/setup.sh': CRED_LINE,
    });
    expect(scan(dir, { scanGlobal: false, includeTests: true })).toEqual([]);
  });

  it('includeTests keeps every non-test default in the matcher', () => {
    // Tests the ignore matcher directly, because the scan-level assertion above
    // cannot distinguish this layer from SOURCE_SKIP_DIRS.
    const dir = tmpProjectWith({ 'src/a.js': '\n' });
    const m = loadSecretlessIgnore(dir, { includeTests: true });

    for (const p of ['node_modules/pkg/index.js', 'dist/bundle.js', 'build/out.js',
                     'examples/demo.js', 'docs/vhs/setup.sh']) {
      expect(m.matches(p), `${p} must stay ignored under includeTests`).toBe(true);
    }
    // ...and the test defaults are genuinely released.
    for (const p of ['test/a.js', 'tests/b.js', '__tests__/c.js', '__fixtures__/d.js',
                     'test-server/e.js', 'e2e/f.js']) {
      expect(m.matches(p), `${p} must be reachable under includeTests`).toBe(false);
    }
  });

  it('does NOT override an explicit user .secretlessignore entry', () => {
    // The defaults are ours to relax; a line the user wrote is their decision.
    // `--no-ignore` remains the way to override that.
    const dir = tmpProjectWith({
      'test/fixture.test.js': CRED_LINE,
      '.secretlessignore': 'test/\n',
    });
    expect(scan(dir, { scanGlobal: false, includeTests: true })).toEqual([]);
  });
});

describe('scan() — every finding carries a fix (no dead ends)', () => {
  function tmpProjectWith(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-fix-'));
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return dir;
  }

  it('fixFor() returns non-empty guidance for EVERY credential pattern', () => {
    // 40 of 57 patterns had no entry in FIX_GUIDANCE and rendered a finding
    // with no remediation. Asserting over the real pattern list means a newly
    // added pattern cannot reintroduce a dead end.
    const dead = CREDENTIAL_PATTERNS.filter(p => !fixFor(p) || fixFor(p).trim().length === 0);
    expect(dead.map(p => p.id)).toEqual([]);
  });

  it('every derived fallback names the env var and invents no URL', () => {
    // Hand-written FIX_GUIDANCE entries are exempt — some legitimately point at
    // a credential chain rather than an env var (aws-sts). This pins the
    // DERIVED text, which is what the 40 fix-less patterns now get.
    let exercised = 0;
    for (const p of CREDENTIAL_PATTERNS) {
      const fix = fixFor(p);
      if (!fix.includes('Revoke and reissue this')) continue;
      exercised++;
      expect(fix, `${p.id} fallback must name its env var`).toContain(p.envPrefix);
      // A derived fix must not carry a rotation URL we never verified.
      expect(fix, `${p.id} fallback must not invent a URL`).not.toMatch(/https?:\/\/|www\./);
    }
    // Guard against the assertion silently covering nothing if the fallback
    // wording changes.
    expect(exercised, 'no derived fallbacks were exercised').toBeGreaterThan(0);
  });

  it('an aws-secret finding carries a fix and keeps the variable name in the preview', () => {
    // Reported P1-3. The name-gated regex SPANS the variable name, so
    // whole-match redaction erased it and the preview rendered as a bare quote.
    // 40 chars, no placeholder marker — the AWS docs key contains "EXAMPLE"
    // and is correctly suppressed by isKnownExample.
    const secret = ['kQ7bY2nR9vX4mL6pT8wZ', '3cF5hJ1dG0sA7eU2iO4y'].join('');
    const dir = tmpProjectWith({ 'src/aws.js': `const AWS_SECRET_ACCESS_KEY = "${secret}";\n` });
    const findings = scan(dir, { scanGlobal: false });

    const f = findings.find(f => f.patternId === 'aws-secret');
    expect(f, 'expected an aws-secret finding').toBeDefined();
    expect(f!.fix).toBeTruthy();
    expect(f!.fix).toContain('AWS_SECRET_ACCESS_KEY');
    expect(f!.preview).toContain('AWS_SECRET_ACCESS_KEY');
    expect(f!.preview).toContain('[AWS Secret Access Key REDACTED]');
    // The secret itself must never survive into the preview.
    expect(f!.preview).not.toContain(secret);
  });

  it('previously fix-less patterns now render guidance end to end', () => {
    const npmTok = ['npm_', 'aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5'].join('');
    const ghTok = ['gho_', 'aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5'].join('');
    const glTok = ['glpat-', 'aB3dE5gH7jK9mN1pQ3sT'].join('');
    const dir = tmpProjectWith({
      'src/tokens.js': [
        `const a = "${npmTok}";`,
        `const b = "${ghTok}";`,
        `const c = "${glTok}";`,
      ].join('\n') + '\n',
    });
    const findings = scan(dir, { scanGlobal: false });
    for (const id of ['npm', 'github-oauth', 'gitlab']) {
      const f = findings.find(f => f.patternId === id);
      expect(f, `expected a ${id} finding`).toBeDefined();
      expect(f!.fix, `${id} finding has no fix — dead end`).toBeTruthy();
    }
  });
});
