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

describe('scan() — an explicitly named FILE is scanned (release-test P1)', () => {
  function tmpProjectWith(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-file-'));
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return dir;
  }

  const KEY = ['sk-proj-', 'Q1W2E3R4T5Y6U7I8O9P0A1S2D3F4G5H6J7K8L9Z0X1C2'].join('');

  it('finds a credential when the target is the file itself', () => {
    // `scan src/config.ts` accepted the path, checked it existed, then walked it
    // as a directory and reported "No hardcoded credentials found" with exit 0.
    // In CI that is a green pass over a live credential.
    const dir = tmpProjectWith({ 'single.js': `const s = "${KEY}";\n` });
    const findings = scan(path.join(dir, 'single.js'), { scanGlobal: false });
    expect(findings.length).toBe(1);
    expect(path.basename(findings[0].file)).toBe('single.js');
    // Whatever form the path takes, it must point at a real file.
    expect(fs.existsSync(findings[0].file)).toBe(true);
  });

  it('CONTROL: the same file via its directory was always found', () => {
    // Proves the test above is about the file target, not the pattern.
    const dir = tmpProjectWith({ 'single.js': `const s = "${KEY}";\n` });
    expect(scan(dir, { scanGlobal: false }).length).toBe(1);
  });

  it('scans an explicitly named file even inside a suppressed directory', () => {
    // Naming a path is an explicit instruction; default suppression is a
    // heuristic for directory walks. The explicit instruction wins.
    const dir = tmpProjectWith({ 'test/fixture.test.js': `const s = "${KEY}";\n` });
    const findings = scan(path.join(dir, 'test/fixture.test.js'), { scanGlobal: false });
    expect(findings.length).toBe(1);
  });

  it('scans an explicitly named CONFIG file', () => {
    const dir = tmpProjectWith({ 'config.json': `{"apiKey": "${KEY}"}\n` });
    const findings = scan(path.join(dir, 'config.json'), { scanGlobal: false });
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('a file with no credential is still clean', () => {
    const dir = tmpProjectWith({ 'clean.js': 'const x = 1;\n' });
    expect(scan(path.join(dir, 'clean.js'), { scanGlobal: false })).toEqual([]);
  });
});

describe('scan() — config files are found below the root (release-test P1)', () => {
  function tmpProjectWith(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-cfgrec-'));
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return dir;
  }

  const GKEY = ['AIzaSy', 'B7xK2mNvPwQ4tZ8hLcDfGjHkMnOpQrStU'].join('');

  it('finds a credential in a nested config.json', () => {
    // Source files recursed; config files only matched at the scan root, so a
    // monorepo reported clean at exactly the invocation everyone runs first.
    const dir = tmpProjectWith({ 'sub/config.json': `{"key": "${GKEY}"}\n` });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.map(f => f.file)).toEqual(['sub/config.json']);
  });

  it('finds a nested docker-compose.yml two levels down', () => {
    const dir = tmpProjectWith({
      'deploy/prod/docker-compose.yml': `services:\n  api:\n    environment:\n      GOOGLE_API_KEY: ${GKEY}\n`,
    });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.map(f => f.file)).toEqual(['deploy/prod/docker-compose.yml']);
  });

  it('finds a nested tool config in a dot-directory', () => {
    // Dot-dirs are skipped for source files but are exactly where tool configs
    // live, so the config walk must not blanket-skip them.
    const dir = tmpProjectWith({ 'pkg/.cursor/mcp.json': `{"token": "${GKEY}"}\n` });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.map(f => f.file)).toEqual(['pkg/.cursor/mcp.json']);
  });

  it('CONTROL: a root config file still works', () => {
    const dir = tmpProjectWith({ 'config.json': `{"key": "${GKEY}"}\n` });
    expect(scan(dir, { scanGlobal: false }).map(f => f.file)).toEqual(['config.json']);
  });

  it('does NOT descend into node_modules, dist, or build', () => {
    const dir = tmpProjectWith({
      'node_modules/pkg/config.json': `{"key": "${GKEY}"}\n`,
      'dist/config.json': `{"key": "${GKEY}"}\n`,
      'build/config.json': `{"key": "${GKEY}"}\n`,
    });
    expect(scan(dir, { scanGlobal: false })).toEqual([]);
  });

  it('does NOT descend into generated trees even with --no-ignore', () => {
    // The assertion above cannot distinguish the walker's SOURCE_SKIP_DIRS from
    // the default-ignore list, because both cover these directories — mutation
    // testing caught it staying green with the walker's check removed. With
    // `ignore: false` the ignore layer is gone, so the walker is the only thing
    // left, and scanning a dependency tree would bury the report.
    const dir = tmpProjectWith({
      'node_modules/pkg/config.json': `{"key": "${GKEY}"}\n`,
      'dist/config.json': `{"key": "${GKEY}"}\n`,
      'build/config.json': `{"key": "${GKEY}"}\n`,
    });
    expect(scan(dir, { scanGlobal: false, ignore: false })).toEqual([]);
  });

  it('honours .secretlessignore for nested config files', () => {
    const dir = tmpProjectWith({
      'sub/config.json': `{"key": "${GKEY}"}\n`,
      '.secretlessignore': 'sub/\n',
    });
    expect(scan(dir, { scanGlobal: false })).toEqual([]);
  });

  it('reports a nested config file exactly once', () => {
    // The source-file pass must not re-report a file the config pass covered.
    const dir = tmpProjectWith({ 'sub/package.json': `{"token": "${GKEY}"}\n` });
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(1);
  });
});

describe('scan() — a symlinked config file or directory is followed (0.21.1 regression)', () => {
  // `walkConfigFiles` classifies with Dirent.isDirectory()/isFile(), which are
  // LSTAT-based: a symlink is neither, so it fell through both branches and was
  // dropped. 0.21.0 reached config files via existsSync/statSync, which FOLLOW
  // symlinks — making the walk recursive silently removed symlink support, and a
  // symlinked `.claude/` (what a dotfile manager or a shared monorepo config
  // produces) reported "No hardcoded credentials found." with exit 0.
  const GKEY = ['AIzaSy', 'B7xK2mNvPwQ4tZ8hLcDfGjHkMnOpQrStU'].join('');

  function tmpdir(prefix: string): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  }

  it('follows a symlinked config DIRECTORY', () => {
    const dir = tmpdir('scan-symdir-');
    fs.mkdirSync(path.join(dir, 'shared-claude'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'shared-claude/settings.json'), `{"key": "${GKEY}"}\n`);
    fs.symlinkSync('shared-claude', path.join(dir, '.claude'), 'dir');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.map(f => f.file)).toContain('.claude/settings.json');
  });

  it('follows a symlinked config FILE', () => {
    const dir = tmpdir('scan-symfile-');
    fs.mkdirSync(path.join(dir, 'real'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'real/payload.json'), `{"key": "${GKEY}"}\n`);
    fs.symlinkSync('real/payload.json', path.join(dir, 'config.json'));

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.map(f => f.file)).toContain('config.json');
  });

  it('follows a symlinked config file nested below the root', () => {
    const dir = tmpdir('scan-symnest-');
    fs.mkdirSync(path.join(dir, 'real'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'pkg/a'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'real/payload.json'), `{"key": "${GKEY}"}\n`);
    fs.symlinkSync(path.join(dir, 'real/payload.json'), path.join(dir, 'pkg/a/config.json'));

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.map(f => f.file)).toContain('pkg/a/config.json');
  });

  it('CONTROL: the same file reached without a symlink is found', () => {
    // Pins that the assertions above measure symlink FOLLOWING and not merely
    // "the walker finds config.json", which would pass with the fix reverted.
    const dir = tmpdir('scan-symctl-');
    fs.writeFileSync(path.join(dir, 'config.json'), `{"key": "${GKEY}"}\n`);
    expect(scan(dir, { scanGlobal: false }).map(f => f.file)).toEqual(['config.json']);
  });

  it('a symlink CYCLE terminates and reports the file once', () => {
    // Note on what this does and does not prove: the OS bounds a symlink loop
    // with ELOOP after ~32 hops, so a walk with NO cycle guard at all still
    // terminates (measured at 7ms). The timing bound below is therefore a
    // smoke check, not the assertion that matters. What the guard buys is the
    // COUNT: without it the same file is collected once per lap (measured 16).
    const dir = tmpdir('scan-symloop-');
    fs.mkdirSync(path.join(dir, 'a'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'a/config.json'), `{"key": "${GKEY}"}\n`);
    fs.symlinkSync(path.join(dir, 'a'), path.join(dir, 'a/loop'), 'dir');

    const started = process.hrtime.bigint();
    const findings = scan(dir, { scanGlobal: false });
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    // Terminating at all is the assertion; the bound catches a walk that only
    // ends because it hit the 5000-file cap after thousands of stat calls.
    expect(elapsedMs).toBeLessThan(5000);
    expect(findings.map(f => f.file)).toContain('a/config.json');
    // And it must be reported ONCE, not once per lap around the cycle.
    expect(findings.filter(f => f.file.endsWith('config.json')).length).toBe(1);
  });

  it('an out-of-root symlinked FILE is still read', () => {
    // Containment applies to directories, not files. Reading one file the repo
    // explicitly names is bounded work, and `pkg/.env -> ../../shared/.env` is
    // what stow/chezmoi and monorepo-root env files actually produce — refusing
    // it would drop a credential the repo is asking us to treat as its own.
    const outside = tmpdir('scan-symout-target-');
    fs.writeFileSync(path.join(outside, 'payload.json'), `{"key": "${GKEY}"}\n`);
    const dir = tmpdir('scan-symout-');
    fs.symlinkSync(path.join(outside, 'payload.json'), path.join(dir, 'config.json'));

    const stats = { placeholdersSuppressed: 0, truncated: false, outOfRoot: [] as string[] };
    expect(scan(dir, { scanGlobal: false }, stats).map(f => f.file)).toContain('config.json');
    expect(stats.outOfRoot).toEqual([]);
  });

  it('an out-of-root symlinked DIRECTORY is not traversed', () => {
    const outside = tmpdir('scan-symoutdir-target-');
    fs.mkdirSync(path.join(outside, 'deep'), { recursive: true });
    fs.writeFileSync(path.join(outside, 'deep/config.json'), `{"key": "${GKEY}"}\n`);
    const dir = tmpdir('scan-symoutdir-');
    fs.symlinkSync(outside, path.join(dir, 'link'), 'dir');

    const stats = { placeholdersSuppressed: 0, truncated: false, outOfRoot: [] as string[] };
    expect(scan(dir, { scanGlobal: false }, stats)).toEqual([]);
    expect(stats.outOfRoot).toEqual(['link']);
  });

  it('follows a symlinked config dir whose TARGET is also inside the tree', () => {
    // The cycle guard was a GLOBAL visited-realpath set, so whichever path BFS
    // reached first won and the other was dropped. Here the real directory is
    // in-tree and sorts first, so it was marked seen and `pkg/.claude` skipped —
    // and only the `.claude` path matches the `.claude/settings.json` config
    // entry, because `settings.json` is not a bare basename in CONFIG_FILES.
    // Result: the exact case the changelog advertises reported clean, exit 0,
    // and which way it fell depended on readdir order.
    const dir = tmpdir('scan-symdual-');
    fs.mkdirSync(path.join(dir, 'shared'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'pkg'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'shared/settings.json'), `{"key": "${GKEY}"}\n`);
    fs.symlinkSync(path.join(dir, 'shared'), path.join(dir, 'pkg/.claude'), 'dir');

    expect(scan(dir, { scanGlobal: false }).map(f => f.file)).toContain('pkg/.claude/settings.json');
  });

  it('reports ONE finding for a credential reachable by several in-tree paths', () => {
    // Following links means the same real file is reachable more than once, and
    // per-ancestry cycle detection deliberately walks each route. A monorepo
    // where 12 packages each link to a shared config turned one leaked key into
    // 13 criticals, so `summary.total` counted PATHS, not credentials.
    const dir = tmpdir('scan-dupe-');
    fs.mkdirSync(path.join(dir, 'common'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'common/config.json'), `{"key": "${GKEY}"}\n`);
    for (const pkg of ['a', 'b', 'c', 'd']) {
      fs.mkdirSync(path.join(dir, 'packages', pkg), { recursive: true });
      fs.symlinkSync(path.join(dir, 'common'), path.join(dir, 'packages', pkg, 'shared'), 'dir');
    }
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(1);
  });

  it('does NOT report a pruned directory as an out-of-root boundary', () => {
    // The containment check used to run before the skip filters, so a
    // `node_modules -> /pnpm-store` link was reported as an unfollowed boundary
    // and the user was told to go scan their whole package store — about a
    // directory that was never going to be walked.
    const outside = tmpdir('scan-store-');
    fs.writeFileSync(path.join(outside, 'config.json'), `{"key": "${GKEY}"}\n`);
    const dir = tmpdir('scan-pruned-');
    fs.symlinkSync(outside, path.join(dir, 'node_modules'), 'dir');

    const stats = { placeholdersSuppressed: 0, truncated: false, outOfRoot: [] as string[] };
    expect(scan(dir, { scanGlobal: false }, stats)).toEqual([]);
    expect(stats.outOfRoot).toEqual([]);
  });

  it('bounds a lattice of links instead of walking exponentially many paths', () => {
    // A 31-directory link lattice produced 2047 traversals, 45s and 289 MB.
    // A repo is a hostile input; the multiplicity cap makes this bounded, and
    // crossing it must SAY so rather than pass silently.
    const dir = tmpdir('scan-lattice-');
    let prev = dir;
    for (let level = 0; level < 12; level++) {
      const next = path.join(prev, 'd');
      fs.mkdirSync(next, { recursive: true });
      fs.symlinkSync(next, path.join(prev, 'l1'), 'dir');
      fs.symlinkSync(next, path.join(prev, 'l2'), 'dir');
      prev = next;
    }
    fs.writeFileSync(path.join(prev, 'config.json'), `{"key": "${GKEY}"}\n`);

    const started = process.hrtime.bigint();
    const stats = { placeholdersSuppressed: 0, truncated: false };
    const findings = scan(dir, { scanGlobal: false }, stats);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    expect(elapsedMs).toBeLessThan(10_000);
    // One real credential, however many routes reach it.
    expect(findings.length).toBe(1);
  });

  it('finds an in-root symlink target when the scan path differs in CASE', () => {
    // Containment compares resolved paths as strings. If resolution does not
    // canonicalise case, scanning `ROOT` when the directory is `root` leaves an
    // in-tree link resolving to a differently-cased string, which fails the
    // prefix test and silently drops the subtree. On a case-sensitive volume the
    // uppercase path simply does not exist, so the case is skipped there rather
    // than asserted the other way.
    const parent = tmpdir('scan-case-');
    fs.mkdirSync(path.join(parent, 'root/inner'), { recursive: true });
    fs.writeFileSync(path.join(parent, 'root/inner/config.json'), `{"key": "${GKEY}"}\n`);
    fs.symlinkSync(path.join(parent, 'root/inner'), path.join(parent, 'root/link'), 'dir');

    const upper = path.join(parent, 'ROOT');
    let caseInsensitive = true;
    try { fs.readdirSync(upper); } catch { caseInsensitive = false; }
    if (!caseInsensitive) return;

    const stats = { placeholdersSuppressed: 0, truncated: false, outOfRoot: [] as string[] };
    const findings = scan(upper, { scanGlobal: false }, stats);
    // The credential is reachable, and the in-root link must not be reported as
    // pointing outside the root.
    expect(findings.length).toBeGreaterThan(0);
    expect(stats.outOfRoot).toEqual([]);
  });

  it('an unreadable DIRECTORY is reported, not counted as clean', () => {
    // readdirSync failure used to `continue` with nothing recorded, so the scan
    // asserted truncated:false / unreadable:0 over a subtree it never opened.
    if (process.platform === 'win32' || (process.getuid?.() === 0)) return;
    const dir = tmpdir('scan-noreaddir-');
    fs.mkdirSync(path.join(dir, 'locked'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'locked/config.json'), `{"key": "${GKEY}"}\n`);
    fs.chmodSync(path.join(dir, 'locked'), 0o000);
    try {
      const stats = { placeholdersSuppressed: 0, truncated: false, unreadable: [] as string[] };
      expect(scan(dir, { scanGlobal: false }, stats)).toEqual([]);
      expect(stats.unreadable).toContain('locked');
    } finally {
      fs.chmodSync(path.join(dir, 'locked'), 0o755);
    }
  });

  it('a BROKEN symlink does not throw and does not report a finding', () => {
    const dir = tmpdir('scan-symbroken-');
    fs.symlinkSync(path.join(dir, 'does-not-exist.json'), path.join(dir, 'config.json'));
    expect(() => scan(dir, { scanGlobal: false })).not.toThrow();
    expect(scan(dir, { scanGlobal: false })).toEqual([]);
  });
});

describe('scan() — an unreadable file is not reported as clean (#116 P2-1)', () => {
  // "Could not read" is a third state. Rendering it as "clean" is the same
  // fail-open class as the truncation defect: the same content, readable,
  // produces a finding, so silence here is an answer we never got.
  const KEY = ['sk-proj-', 'M1N2B3V4C5X6Z7L8K9J0H1G2F3D4S5A6P7O8I9U0Y1T2'].join('');

  // chmod 000 does not restrict root, and CI often runs as root.
  const canDenyReads = (() => {
    if (process.platform === 'win32') return false;
    try {
      return typeof process.getuid === 'function' && process.getuid() !== 0;
    } catch {
      return false;
    }
  })();

  function tmpWithUnreadable(): { dir: string; file: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-noread-'));
    const file = path.join(dir, 'noread.js');
    fs.writeFileSync(file, `const k = "${KEY}";\n`);
    fs.chmodSync(file, 0o000);
    return { dir, file };
  }

  it.skipIf(!canDenyReads)('flags an unreadable file in a DIRECTORY scan', () => {
    const { dir, file } = tmpWithUnreadable();
    try {
      const stats = { placeholdersSuppressed: 0, truncated: false, unreadable: [] as string[] };
      const findings = scan(dir, { scanGlobal: false }, stats);
      // The credential is genuinely unreachable, so no finding is correct...
      expect(findings).toEqual([]);
      // ...but silence about it is not.
      expect(stats.unreadable.length).toBe(1);
    } finally {
      fs.chmodSync(file, 0o644);
    }
  });

  it.skipIf(!canDenyReads)('flags an unreadable file named DIRECTLY', () => {
    const { dir, file } = tmpWithUnreadable();
    try {
      const stats = { placeholdersSuppressed: 0, truncated: false, unreadable: [] as string[] };
      scan(file, { scanGlobal: false }, stats);
      expect(stats.unreadable.length).toBe(1);
    } finally {
      fs.chmodSync(file, 0o644);
    }
  });

  it.skipIf(!canDenyReads)('CONTROL: the same file, readable, produces a finding and no warning', () => {
    // Pins that the assertions above measure READABILITY and not merely "a .js
    // file exists" — without this the fix could pass by warning on everything.
    const { dir, file } = tmpWithUnreadable();
    fs.chmodSync(file, 0o644);
    const stats = { placeholdersSuppressed: 0, truncated: false, unreadable: [] as string[] };
    const findings = scan(dir, { scanGlobal: false }, stats);
    expect(findings.length).toBe(1);
    expect(stats.unreadable).toEqual([]);
  });
});

describe('scan() — a truncated scan does not render as a clean scan (fail-open)', () => {
  // walkConfigFiles stops at maxFiles and returns quietly, so an incomplete scan
  // was indistinguishable from a complete one: fewer findings, no signal, exit 0.
  const GKEY = ['AIzaSy', 'B7xK2mNvPwQ4tZ8hLcDfGjHkMnOpQrStU'].join('');

  function tmpProjectWith(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-trunc-'));
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return dir;
  }

  const THREE_CONFIGS = {
    'a/config.json': `{"key": "${GKEY}"}\n`,
    'b/config.json': `{"key": "${GKEY}"}\n`,
    'c/config.json': `{"key": "${GKEY}"}\n`,
  };

  it('CONTROL: uncapped, all three config files are found and nothing is flagged', () => {
    const dir = tmpProjectWith(THREE_CONFIGS);
    const stats = { placeholdersSuppressed: 0, truncated: false };
    const findings = scan(dir, { scanGlobal: false }, stats);
    expect(findings.length).toBe(3);
    expect(stats.truncated).toBe(false);
  });

  it('sets the truncation flag when the config walk hits the cap', () => {
    const dir = tmpProjectWith(THREE_CONFIGS);
    const stats = { placeholdersSuppressed: 0, truncated: false };
    const findings = scan(dir, { scanGlobal: false, maxSourceFiles: 2 }, stats);
    // The dropped file is the defect; the FLAG is what makes it visible.
    expect(findings.length).toBeLessThan(3);
    expect(stats.truncated).toBe(true);
  });

  it('sets the truncation flag when the SOURCE walk hits the cap', () => {
    const SKEY = ['sk-proj-', 'M1N2B3V4C5X6Z7L8K9J0H1G2F3D4S5A6P7O8I9U0Y1T2'].join('');
    const dir = tmpProjectWith({
      'a.js': `const k = "${SKEY}";\n`,
      'b.js': `const k = "${SKEY}";\n`,
      'c.js': `const k = "${SKEY}";\n`,
    });
    const stats = { placeholdersSuppressed: 0, truncated: false };
    scan(dir, { scanGlobal: false, maxSourceFiles: 2 }, stats);
    expect(stats.truncated).toBe(true);
  });

  it('sets the truncation flag when the KEY-file walk hits the cap', () => {
    const dir = tmpProjectWith({
      'a.pem': 'x\n', 'b.pem': 'x\n', 'c.pem': 'x\n',
      'd.pem': 'x\n', 'e.pem': 'x\n', 'f.pem': 'x\n',
    });
    const stats = { placeholdersSuppressed: 0, truncated: false };
    scan(dir, { scanGlobal: false, maxSourceFiles: 2 }, stats);
    expect(stats.truncated).toBe(true);
  });
});

describe('scan() — a single-file finding reports a path that resolves (re-test P2)', () => {
  it('reports the path relative to cwd, not the bare basename', () => {
    // The basename alone does not resolve from the caller's cwd, so a CI job
    // annotating file:line from --json pointed at the wrong file or nothing.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-relpath-'));
    fs.mkdirSync(path.join(dir, 'deploy/prod'), { recursive: true });
    const KEY = ['sk-proj-', 'M1N2B3V4C5X6Z7L8K9J0H1G2F3D4S5A6P7O8I9U0Y1T2'].join('');
    fs.writeFileSync(path.join(dir, 'deploy/prod/app.js'), `const k = "${KEY}";\n`);

    const cwd = process.cwd();
    try {
      process.chdir(dir);
      const findings = scan(path.join(dir, 'deploy/prod/app.js'), { scanGlobal: false });
      expect(findings.length).toBe(1);
      // Must match what a directory scan of the same tree reports.
      expect(findings[0].file).toBe('deploy/prod/app.js');
      // And it must actually exist relative to cwd.
      expect(fs.existsSync(findings[0].file)).toBe(true);
    } finally {
      process.chdir(cwd);
    }
  });

  it('falls back to the absolute path for a target outside cwd', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-outside-'));
    const KEY = ['sk-proj-', 'M1N2B3V4C5X6Z7L8K9J0H1G2F3D4S5A6P7O8I9U0Y1T2'].join('');
    const target = path.join(dir, 'outside.js');
    fs.writeFileSync(target, `const k = "${KEY}";\n`);

    const cwd = process.cwd();
    try {
      process.chdir(os.homedir());
      const findings = scan(target, { scanGlobal: false });
      expect(findings.length).toBe(1);
      // Whatever form it takes, it must point at a real file.
      expect(fs.existsSync(findings[0].file)).toBe(true);
    } finally {
      process.chdir(cwd);
    }
  });
});

// #120. A file over the per-file size cap was dropped with no `truncated`, no
// `unreadable` and no warning: an 11 MB config.json with a live-shaped key on
// line 1 scanned to `total: 0`, `truncated: false`, exit 0. The cap is a
// resource guard, not a judgement about content — the same bytes under it
// produce a finding — so a skip has to be reported like any other coverage gap.
describe('scan() — files skipped for size are reported, not dropped (#120)', () => {
  const GOOGLE_KEY = ['AIzaSy', 'D-1234567890abcdefghijklmnopqrstuv'].join('');

  function freshStats() {
    return {
      placeholdersSuppressed: 0, truncated: false,
      unreadable: [] as string[], outOfRoot: [] as string[],
      oversize: [] as Array<{ path: string; bytes: number; capBytes: number }>,
    };
  }

  function projectWith(fileName: string, padBytes: number): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-oversize-'));
    fs.writeFileSync(
      path.join(dir, fileName),
      `{"googleKey": "${GOOGLE_KEY}",\n"pad": "${'x'.repeat(padBytes)}"}\n`,
    );
    return dir;
  }

  it('finds the credential when the same file is UNDER the cap', () => {
    const dir = projectWith('config.json', 1024);
    const stats = freshStats();

    const findings = scan(dir, { scanGlobal: false }, stats);

    // The control direction: nothing about this file is unscannable, so a
    // report of "skipped for size" below is about the cap and nothing else.
    expect(findings.some(f => f.patternId === 'google')).toBe(true);
    expect(stats.oversize).toHaveLength(0);
  });

  it('reports a config file over the default 10MB cap instead of dropping it', () => {
    const dir = projectWith('config.json', 11 * 1024 * 1024);
    const stats = freshStats();

    const findings = scan(dir, { scanGlobal: false }, stats);

    // Zero findings is the pre-existing behaviour and is fine on its own. What
    // was missing is any signal that a file went unread.
    expect(findings.some(f => f.patternId === 'google')).toBe(false);
    expect(stats.oversize).toHaveLength(1);
    expect(stats.oversize[0].path).toBe('config.json');
    expect(stats.oversize[0].bytes).toBeGreaterThan(10 * 1024 * 1024);
    expect(stats.oversize[0].capBytes).toBe(10 * 1024 * 1024);
    // Not conflated with the other two coverage gaps — each has its own fix.
    expect(stats.truncated).toBe(false);
    expect(stats.unreadable).toHaveLength(0);
  });

  it('reports a source file over the 1MB source cap', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-oversize-src-'));
    fs.writeFileSync(
      path.join(dir, 'big.js'),
      `const k = "${GOOGLE_KEY}";\n// ${'x'.repeat(2 * 1024 * 1024)}\n`,
    );
    const stats = freshStats();

    const findings = scan(dir, { scanGlobal: false }, stats);

    expect(findings.some(f => f.patternId === 'google')).toBe(false);
    expect(stats.oversize.map(o => o.path)).toContain('big.js');
    expect(stats.oversize[0].capBytes).toBe(1 * 1024 * 1024);
  });

  it('scans the file once --max-file-size raises the cap above it', () => {
    const dir = projectWith('config.json', 11 * 1024 * 1024);
    const stats = freshStats();

    // The `Fix:` line the coverage warning prints must actually work; a fix
    // command that does not change the outcome is a dead end.
    const findings = scan(dir, { scanGlobal: false, maxFileSizeBytes: 13 * 1024 * 1024 }, stats);

    expect(findings.some(f => f.patternId === 'google')).toBe(true);
    expect(stats.oversize).toHaveLength(0);
  });

  it('applies one --max-file-size to source files too, not just config', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-oversize-both-'));
    fs.writeFileSync(
      path.join(dir, 'big.js'),
      `const k = "${GOOGLE_KEY}";\n// ${'x'.repeat(2 * 1024 * 1024)}\n`,
    );
    const stats = freshStats();

    // "Scan files up to 4 MB" must not leave source still capped at 1 MB.
    const findings = scan(dir, { scanGlobal: false, maxFileSizeBytes: 4 * 1024 * 1024 }, stats);

    expect(findings.some(f => f.patternId === 'google')).toBe(true);
    expect(stats.oversize).toHaveLength(0);
  });

  it('reports an explicitly named file that is over the cap', () => {
    const dir = projectWith('config.json', 11 * 1024 * 1024);
    const stats = freshStats();

    const findings = scan(path.join(dir, 'config.json'), { scanGlobal: false }, stats);

    // A named target used to return zero findings and exit 0 — a green CI gate
    // over a file nobody read.
    expect(findings).toHaveLength(0);
    expect(stats.oversize).toHaveLength(1);
  });

  it('lowering the cap below a normal file reports it, proving the cap is read', () => {
    const dir = projectWith('config.json', 1024);
    const stats = freshStats();

    // Guards against a cap that is plumbed but never consulted: the same file
    // that produced a finding above must now be reported as skipped.
    const findings = scan(dir, { scanGlobal: false, maxFileSizeBytes: 64 }, stats);

    expect(findings.some(f => f.patternId === 'google')).toBe(false);
    expect(stats.oversize.map(o => o.path)).toContain('config.json');
    expect(stats.oversize[0].capBytes).toBe(64);
  });
});
