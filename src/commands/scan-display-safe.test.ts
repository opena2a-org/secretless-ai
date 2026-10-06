/**
 * `scan` prints names and excerpts taken from the scanned repository. A control
 * character in one of them must reach the terminal as a visible escape, never
 * as the raw byte: a line feed in a directory name printed a forged
 * `Scan one:` line, and an ESC byte in a name or an excerpt reached the
 * terminal as a control sequence.
 *
 * Every Unicode Cc character (U+0000-U+001F, U+007F-U+009F) is checked, the
 * line feed included. Colour is off under the test runner (stdout is not a
 * TTY), so any Cc character in the captured output came from the repository.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

vi.mock('../nanomind', () => ({
  isEngineAvailable: vi.fn(async () => true),
  explainFinding: vi.fn(async () => null),
}));

import { runScan } from './core';
import { explainFinding } from '../nanomind';
import {
  escapeForDisplay,
  escapePathForDisplay,
  excerptLinesForDisplay,
  hasDisplayHazard,
} from '../display-safe';

const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);
const LF = String.fromCharCode(0x0a);
const TAB = String.fromCharCode(0x09);
const CC = /[\u0000-\u001f\u007f-\u009f]/;

const TOKEN = ['ghp_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');
// 40 characters, the shape the name-gated AWS secret pattern captures. Not
// marked FAKE: a marked value is hidden as a placeholder, and this test needs
// the finding printed.
const AWS_SECRET = ['Qx7vN2pL9rT4', 'wK8mZ3bY6cH1', 'sD5fG0jR', 'aB2cD7eF'].join('');

const FORGED_DIR = `.x${LF}  Scan one: npx secretless-ai scan elsewhere`;
const OSC_DIR = `cfg${ESC}]52;c;ZXZpbA==${BEL}`;

function tree(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-display-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

describe('display-safe escaping', () => {
  it('maps every Cc character to printable ASCII', () => {
    for (let code = 0; code <= 0x9f; code++) {
      if (code > 0x1f && code < 0x7f) continue;
      const ch = String.fromCharCode(code);
      const out = escapeForDisplay(`a${ch}b`);
      expect(out, `U+${code.toString(16)}`).not.toMatch(CC);
      expect(hasDisplayHazard(ch)).toBe(true);
    }
  });

  it('uses the named escapes for the common controls', () => {
    expect(escapeForDisplay(`a${LF}b${TAB}c${ESC}[2Kd`)).toBe('a\\nb\\tc\\e[2Kd');
    expect(escapeForDisplay(`x${BEL}`)).toBe('x\\x07');
    expect(escapeForDisplay('x\u0085')).toBe('x\\x85');
  });

  it('returns ordinary text unchanged', () => {
    for (const s of ['src/app.ts', 'a b/c.json', "it's.env.example", 'a\\b.txt', 'notes \u2014 caf\u00e9']) {
      expect(escapeForDisplay(s)).toBe(s);
      expect(escapePathForDisplay(s)).toBe(s);
      expect(hasDisplayHazard(s)).toBe(false);
    }
  });

  it('renders a name with a literal backslash-n apart from one with a line feed', () => {
    const literal = escapePathForDisplay('dir\\nx');
    const control = escapePathForDisplay(`dir${LF}x`);
    expect(literal).toBe('dir\\\\nx');
    expect(control).toBe('dir\\nx');
    expect(literal).not.toBe(control);
  });

  it('splits an excerpt into lines and escapes a carriage return inside one', () => {
    expect(excerptLinesForDisplay(`one${LF}two\r${LF}th\rree`)).toEqual(['one', 'two', 'th\\rree']);
  });
});

describe('scan prints names and excerpts from the repository escaped', () => {
  let out: string[];
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    out = [];
    logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      out.push(args.map(String).join(' '));
    });
  });

  afterEach(() => {
    logSpy.mockRestore();
    delete process.env.SECRETLESS_NANOMIND_EXPLAIN;
    vi.mocked(explainFinding).mockResolvedValue(null);
  });

  // The report's own line breaks are line feeds in the strings it logs, so the
  // check runs per printed line. A line feed from the repository is caught by
  // the assertions on the lines it would have forged.
  function expectNoControlBytes() {
    for (const line of out.flatMap((l) => l.split(LF))) {
      expect(line, JSON.stringify(line)).not.toMatch(CC);
    }
  }

  it('a line feed in a directory name does not print a second Scan one: line', async () => {
    const dir = tree({ [path.join(FORGED_DIR, 'a.ts')]: 'export {};\n' });
    await runScan(dir);

    expectNoControlBytes();
    expect(out.join(LF)).not.toContain(FORGED_DIR);
    // The only directory listed cannot be printed as itself, so no command is
    // offered for it.
    const scanOne = out.flatMap((l) => l.split(LF)).filter((l) => l.trimStart().startsWith('Scan one:'));
    expect(scanOne).toEqual([]);
    // The name is still listed, as a visible escape.
    expect(out.join('\n')).toContain('.x\\n  Scan one: npx secretless-ai scan elsewhere: hidden directory');
  });

  it('Scan one: names a listed directory that prints as itself, when there is one', async () => {
    const dir = tree({
      [path.join(FORGED_DIR, 'a.ts')]: 'export {};\n',
      'node_modules/pkg/index.js': 'module.exports = {};\n',
    });
    await runScan(dir);

    expectNoControlBytes();
    expect(out.join(LF)).not.toContain(FORGED_DIR);
    const scanOne = out.flatMap((l) => l.split(LF)).filter((l) => l.trimStart().startsWith('Scan one:'));
    expect(scanOne).toHaveLength(1);
    expect(scanOne[0]).toMatch(/^ {2}Scan one: npx secretless-ai scan \S*node_modules$/);
  });

  it('an escape sequence in a finding name and in its excerpt prints escaped', async () => {
    const dir = tree({
      [path.join(OSC_DIR, 'app.ts')]: `const t = "${TOKEN}"; // ${ESC}[2K${ESC}[1A\n`,
    });
    const code = await runScan(dir);

    expect(code).toBe(1);
    expectNoControlBytes();
    const text = out.join('\n');
    expect(text).toContain('cfg\\e]52;c;ZXZpbA==\\x07/app.ts:1');
    expect(text).toContain('[GitHub Token REDACTED]"; // \\e[2K\\e[1A');
    expect(text).not.toContain(TOKEN);
  });

  it('a credential behind a tab in its gate is still found and still masked', async () => {
    const dir = tree({
      'src/aws.ts': `const aws_secret_access_key =${TAB}"${AWS_SECRET}"; // ${ESC}[2K\n`,
    });
    await runScan(dir);

    expectNoControlBytes();
    const text = out.join('\n');
    expect(text).toContain('AWS Secret Access Key');
    expect(text).toContain('const aws_secret_access_key =\\t"[AWS Secret Access Key REDACTED]"; // \\e[2K');
    expect(text).not.toContain(AWS_SECRET);
  });

  it('--explain prints the name, the excerpt and the generated context escaped, line by line', async () => {
    process.env.SECRETLESS_NANOMIND_EXPLAIN = '1';
    vi.mocked(explainFinding).mockResolvedValue(
      `A token in ${OSC_DIR} grants repository access.${LF}  Scan one: npx secretless-ai scan elsewhere`,
    );
    const dir = tree({
      [path.join(OSC_DIR, 'app.ts')]: `const t = "${TOKEN}"; // ${ESC}[2K\n`,
    });
    await runScan(dir, { explain: true });

    expectNoControlBytes();
    const text = out.join('\n');
    expect(text).toContain('         cfg\\e]52;c;ZXZpbA==\\x07/app.ts:1');
    expect(text).toContain('[GitHub Token REDACTED]"; // \\e[2K');
    expect(out).toContain('         Context (generated, unverified): A token in cfg\\e]52;c;ZXZpbA==\\x07 grants repository access.');
    // The second line of the generated text sits under the block's indent.
    expect(out).toContain('           Scan one: npx secretless-ai scan elsewhere');
    expect(text).not.toContain(TOKEN);
  });

  it('CONTROL: --json keeps the raw name, so detection and coverage data are unchanged', async () => {
    const dir = tree({
      [path.join(FORGED_DIR, 'a.ts')]: 'export {};\n',
      [path.join(OSC_DIR, 'app.ts')]: `const t = "${TOKEN}";\n`,
    });
    await runScan(dir, { json: true });

    const doc = JSON.parse(out.join('\n'));
    expect(doc.findings.map((f: { file: string }) => f.file)).toEqual([`${OSC_DIR}/app.ts`]);
    expect(doc.notEnteredDirs.map((d: { path: string }) => d.path)).toContain(FORGED_DIR);
  });
});
