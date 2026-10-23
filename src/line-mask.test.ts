/**
 * Every preview the tool prints replaces each credential on the line, through
 * the end of its trailing credential characters, with `[<pattern name>
 * REDACTED]`, and keeps no character of any value. `clean-history` rewrites
 * every pattern's matches on a line.
 *
 * The fixture lines hold two credentials of different types each. One is a
 * project-key shape that runs past its pattern: a `_` after 24 characters, then
 * a 100-character tail. Each line also holds an ordinary token, which must come
 * back as it went in.
 *
 * Values are built at run time from fragments. Each body alternates a digit
 * with a letter from a set no other body uses, so a run of one value cannot
 * appear in another value or in the tool's own text, and a hit names the value
 * it came from. Residue is judged with `leaksAny`, the module's own detector:
 * any run of four characters of a body anywhere in the output is a leak.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { maskCredentials, markerAt } from './line-mask';
import { leaksAny } from './redact';
import { scan, matchedValueOf, type ScanFinding } from './scan';
import { runScan } from './commands/core';
import { runScanHistory } from './commands/transcript';
import { runDiff, gitDiscoveryFreeEnv } from './commands/diff';
import { cleanHistory } from './history';
import { deepScan, type TranscriptFinding } from './transcript';

/** `n` characters, a letter of `letters` and a digit in turn. */
function body(n: number, letters: string): string {
  let s = '';
  for (let i = 0; s.length < n; i++) {
    s += i % 2 === 0 ? letters[(i * 5) % letters.length] : String((i * 7) % 10);
  }
  return s;
}

const GH_BODY = body(36, 'abcdefghijklm');
const PROJ_BODY = body(24, 'nopqrstuvwxyz');
const PROJ_TAIL = body(100, 'ABCDEFGHIJKLM');
const ANTH_BODY = body(40, 'NOPQRSTUVWXYZ');

const GH = ['gh', 'p_', GH_BODY].join('');
/** The pattern stops at the `_`; the tail is credential characters it never matched. */
const PROJ = ['s', 'k-proj-', PROJ_BODY, '_', PROJ_TAIL].join('');
const ANTH = ['s', 'k-ant-api03-', ANTH_BODY].join('');

const NON_SECRET = 'trace=ci_build-20261018';
const LINE_A = `gh=${GH} key=${PROJ} ${NON_SECRET}`;
const LINE_B = `gh=${GH} anth=${ANTH} ${NON_SECRET}`;

const BODIES: Record<string, string> = {
  'GitHub token body': GH_BODY,
  'project key body': PROJ_BODY,
  'project key tail': PROJ_TAIL,
  'Anthropic key body': ANTH_BODY,
};

/** The planted values any run of which survives in `text`. */
function leaked(text: string): string[] {
  return Object.entries(BODIES).filter(([, b]) => leaksAny(text, [b])).map(([name]) => name);
}

/** Everything `fn` writes through console, as one string. */
async function printed(fn: () => unknown): Promise<string> {
  const out: string[] = [];
  const keep = (...a: unknown[]) => { out.push(a.map(String).join(' ')); };
  const spies = [
    vi.spyOn(console, 'log').mockImplementation(keep),
    vi.spyOn(console, 'error').mockImplementation(keep),
    vi.spyOn(console, 'warn').mockImplementation(keep),
  ];
  try {
    await fn();
  } finally {
    for (const s of spies) s.mockRestore();
  }
  return out.join('\n');
}

const TMP_PREFIX = 'secretless-line-mask-';
const made: string[] = [];
function tmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), TMP_PREFIX));
  made.push(dir);
  return dir;
}

let homeBefore: string | undefined;
beforeEach(() => {
  homeBefore = process.env.HOME;
});
afterEach(() => {
  if (homeBefore === undefined) delete process.env.HOME;
  else process.env.HOME = homeBefore;
  for (const dir of made.splice(0)) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});

describe('the fixture is what it claims to be', () => {
  it('each line holds both credentials and the ordinary token', () => {
    for (const line of [LINE_A, LINE_B]) {
      expect(line).toContain(GH);
      expect(line).toContain(NON_SECRET);
    }
    expect(LINE_A).toContain(PROJ);
    expect(LINE_B).toContain(ANTH);
    // Guard the guard: the oracle must see every body in the raw lines, or
    // every assertion below would pass over output it cannot read.
    expect(leaked(`${LINE_A}\n${LINE_B}`)).toEqual(Object.keys(BODIES));
  });
});

describe('maskCredentials', () => {
  it('masks both credentials on a line, the tail with its key, and keeps the ordinary token', () => {
    const out = maskCredentials(LINE_A);
    expect(leaked(out)).toEqual([]);
    expect(out).toBe(`gh=[GitHub Token REDACTED] key=[OpenAI Project Key REDACTED] ${NON_SECRET}`);
    expect(maskCredentials(LINE_B)).toBe(`gh=[GitHub Token REDACTED] anth=[Anthropic API Key REDACTED] ${NON_SECRET}`);
  });

  it('returns the ordinary token unchanged', () => {
    expect(maskCredentials(NON_SECRET)).toBe(NON_SECRET);
  });

  it('masks the whole of a credential that another pattern matches inside', () => {
    // A PyPI token whose body holds a Hugging Face token shape part way in.
    const head = body(20, 'nopqrstuvwxyz');
    const inner = ['h', 'f_', body(40, 'abcdefghijklm')].join('');
    const pypi = ['py', 'pi-', head, inner].join('');
    const out = maskCredentials(`token=${pypi} ${NON_SECRET}`);
    expect(leaksAny(out, [head])).toBe(false);
    expect(leaksAny(out, [inner])).toBe(false);
    expect(out).toBe(`token=[PyPI API Token REDACTED] ${NON_SECRET}`);
  });
});

describe('a scan finding names the credential its preview marker names (#459)', () => {
  // A PyPI token whose body holds a Hugging Face token shape part way in. The
  // Hugging Face pattern comes before the PyPI pattern in the list, and the
  // PyPI token starts first on the line.
  const head = body(20, 'nopqrstuvwxyz');
  const inner = ['h', 'f_', body(40, 'abcdefghijklm')].join('');
  const pypi = ['py', 'pi-', head, inner].join('');
  const line = `token=${pypi}`;

  function only(findings: ScanFinding[]): ScanFinding {
    expect(findings).toHaveLength(1);
    return findings[0];
  }

  function expectPyPI(finding: ScanFinding, preview: string): void {
    expect(finding.preview).toBe(preview);
    expect(finding.patternId).toBe('pypi');
    expect(finding.patternName).toBe('PyPI API Token');
    expect(finding.fix).toContain('PYPI_API_TOKEN');
  }

  it('markerAt gives the one PyPI marker over the whole token, at the Hugging Face shape too', () => {
    const at = line.indexOf(inner);
    expect(at).toBeGreaterThan(line.indexOf(pypi));
    const marker = markerAt(line, at);
    expect(marker?.pattern.id).toBe('pypi');
    expect(marker?.from).toBe(line.indexOf(pypi));
    expect(marker?.to).toBe(line.length);
    expect(markerAt(line, 0)).toBeUndefined();
  });

  it('in a source file', () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'app.js'), `${line}\n`);
    expectPyPI(only(scan(dir, { scanGlobal: false })), 'token=[PyPI API Token REDACTED]');
  });

  it('in a config file', () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'config.json'), `{"token": "${pypi}"}\n`);
    const finding = only(scan(dir, { scanGlobal: false }));
    expect(finding.severity).toBe('critical');
    expectPyPI(finding, '{"token": "[PyPI API Token REDACTED]"}');
  });

  it('in a file named as the scan target', () => {
    const dir = tmpDir();
    const file = path.join(dir, 'app.js');
    fs.writeFileSync(file, `${line}\n`);
    expectPyPI(only(scan(file, { scanGlobal: false })), 'token=[PyPI API Token REDACTED]');
  });

  it('keeps the matched value of the PyPI token for the validity check', () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'app.js'), `${line}\n`);
    const finding = only(scan(dir, { scanGlobal: false, retainValues: true }));
    expect(finding.patternId).toBe('pypi');
    expect(matchedValueOf(finding)).toBe(pypi);
  });
});

describe('every channel prints no character of any planted value', () => {
  function project(): string {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'app.js'), `${LINE_A}\n${LINE_B}\n`);
    return dir;
  }

  it('scan, text', async () => {
    const dir = project();
    const out = await printed(() => runScan(dir));
    expect(out).toContain('OpenAI Project Key');
    expect(out).toContain('Anthropic API Key');
    expect(leaked(out)).toEqual([]);
  });

  it('scan --explain, text', async () => {
    const dir = project();
    const out = await printed(() => runScan(dir, { explain: true }));
    expect(out).toContain('OpenAI Project Key');
    expect(leaked(out)).toEqual([]);
  });

  it('scan --json, every field', async () => {
    const dir = project();
    const out = await printed(() => runScan(dir, { json: true }));
    const doc = JSON.parse(out);
    expect(doc.findings.length).toBeGreaterThanOrEqual(2);
    expect(leaked(out)).toEqual([]);
  });

  function historyHome(lines: string[]): string {
    const home = tmpDir();
    fs.writeFileSync(path.join(home, '.bash_history'), lines.join('\n') + '\n');
    process.env.HOME = home;
    return home;
  }

  it('scan-history, text', async () => {
    historyHome(['ls', LINE_A, LINE_B]);
    const out = await printed(() => runScanHistory());
    expect(out).toContain('[OpenAI Project Key REDACTED]');
    expect(out).toContain('[Anthropic API Key REDACTED]');
    expect(leaked(out)).toEqual([]);
  });

  it('clean-history rewrites every pattern on a line and leaves the ordinary token', async () => {
    const home = historyHome(['ls', LINE_A, LINE_B]);
    const result = await cleanHistory(false);
    expect(result.linesRedacted).toBe(2);
    const written = fs.readFileSync(path.join(home, '.bash_history'), 'utf-8');
    expect(leaked(written)).toEqual([]);
    expect(written.split('\n')).toEqual([
      'ls',
      `gh=[REDACTED:github-pat] key=[REDACTED:openai-proj] ${NON_SECRET}`,
      `gh=[REDACTED:github-pat] anth=[REDACTED:anthropic] ${NON_SECRET}`,
      '',
    ]);
  });

  it('diff', async () => {
    const dir = tmpDir();
    const git = (args: string[]) => {
      if (!path.basename(dir).startsWith(TMP_PREFIX)) throw new Error(`refused: ${dir} is not a test directory`);
      execFileSync('git', args, {
        cwd: dir,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...gitDiscoveryFreeEnv(), GIT_AUTHOR_NAME: 'test', GIT_AUTHOR_EMAIL: 'test@example.com', GIT_COMMITTER_NAME: 'test', GIT_COMMITTER_EMAIL: 'test@example.com' },
      });
    };
    git(['init', '-q', '-b', 'main']);
    fs.mkdirSync(path.join(dir, '.claude'));
    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), '{}\n');
    git(['add', '.claude/settings.json']);
    git(['commit', '-q', '-m', 'init']);
    fs.writeFileSync(
      path.join(dir, '.claude', 'settings.json'),
      `{"env":{"GH":"${GH}","OPENAI":"${PROJ}"},"note":"${NON_SECRET}"}\n`,
    );

    const cwd = process.cwd();
    let out: string;
    try {
      process.chdir(dir);
      out = await printed(() => runDiff([]));
    } finally {
      process.chdir(cwd);
    }
    expect(out).toContain('[GitHub Token REDACTED]');
    expect(out).toContain('[OpenAI Project Key REDACTED]');
    expect(out).toContain(NON_SECRET);
    expect(leaked(out)).toEqual([]);
  });

  it('TranscriptFinding.preview', () => {
    for (const line of [LINE_A, LINE_B]) {
      const findings: TranscriptFinding[] = [];
      deepScan(line, '$.message', findings, { file: 'session.jsonl', line: 1 });
      expect(findings.length).toBe(2);
      for (const f of findings) expect(leaked(f.preview), f.patternId).toEqual([]);
    }
  });
});

describe('scan-history previews keep the command around a masked value', () => {
  async function preview(line: string): Promise<string> {
    const home = tmpDir();
    fs.writeFileSync(path.join(home, '.bash_history'), line + '\n');
    process.env.HOME = home;
    const out = await printed(() => runScanHistory());
    return out;
  }

  it('an export of a known format shows the variable and the format\'s marker', async () => {
    const out = await preview(`export GITHUB_TOKEN=${GH}`);
    expect(out).toContain(`export GITHUB_TOKEN=[GitHub Token REDACTED]`);
    expect(leaked(out)).toEqual([]);
  });

  it('an export of a value no format matches is masked by the export form', async () => {
    const value = body(32, 'NOPQRSTUVWXYZ');
    const out = await preview(`export DB_PASSWORD="${value}"`);
    expect(out).toContain('[Secret in export REDACTED]');
    expect(leaksAny(out, [value])).toBe(false);
  });

  it('a value after a known format on an export is masked with it', async () => {
    const rest = body(30, 'ABCDEFGHIJKLM');
    const out = await preview(`export GH_TOKEN="${GH}",${rest}`);
    expect(leaked(out)).toEqual([]);
    expect(leaksAny(out, [rest])).toBe(false);
  });
});
