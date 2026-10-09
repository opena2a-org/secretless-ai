/**
 * `scan` prints names and excerpts taken from the scanned repository. A control
 * character in one of them must reach the terminal as a visible escape, never
 * as the raw byte: a line feed in an unscanned config file's name printed a
 * forged `Scan one:` line, and an ESC byte in a name or an excerpt reached the
 * terminal as a control sequence. `vault scan` prints the same names.
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
import { vaultScan } from '../vault-core';
import { explainFinding } from '../nanomind';
import {
  escapeForDisplay,
  escapePathForDisplay,
  excerptLinesForDisplay,
  hasDisplayHazard,
  quotePathForDisplay,
  withSlashSeparators,
} from '../display-safe';

const ESC = String.fromCharCode(0x1b);
const BEL = String.fromCharCode(0x07);
const LF = String.fromCharCode(0x0a);
const TAB = String.fromCharCode(0x09);
const CC = /[\u0000-\u001f\u007f-\u009f]/;
const BACKSLASH = '\\';

const TOKEN = ['ghp_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');
// 40 characters, the shape the name-gated AWS secret pattern captures. Not
// marked FAKE: a marked value is hidden as a placeholder, and this test needs
// the finding printed.
const AWS_SECRET = ['Qx7vN2pL9rT4', 'wK8mZ3bY6cH1', 'sD5fG0jR', 'aB2cD7eF'].join('');

const FORGED_DIR = `.x${LF}  Scan one: npx secretless-ai scan elsewhere`;
// Config-shaped by its extension and off the built-in list, so it is named in
// the "config files not scanned" block, whose `Scan one:` line once printed the
// first such name raw: the line feed ended that line and the rest of the name
// printed as a second one.
const FORGED_CONFIG = `sec${LF}  Scan one: npx secretless-ai scan elsewhere.json`;
const OSC_DIR = `cfg${ESC}]52;c;ZXZpbA==${BEL}`;
// An escaped name holding the separator a list prints between a name and its
// reason.
const COLON_DIR = `.a${ESC}: test directory (--include-tests)`;

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

  it('escapes format characters: bidi controls, zero-width characters, the tag block', () => {
    // U+202E reverses what follows it: `invoice<U+202E>fdp.exe` reads as
    // `invoiceexe.pdf`.
    expect(escapeForDisplay('invoice\u202Efdp.exe')).toBe('invoice\\u202efdp.exe');
    const formatCharacters: Array<[string, string]> = [
      ['\u00AD', '\\xad'],
      ['\u200B', '\\u200b'],
      ['\u200E', '\\u200e'],
      ['\u2066', '\\u2066'],
      ['\uFEFF', '\\ufeff'],
      ['\u{E0041}', '\\u{e0041}'],
    ];
    for (const [ch, shown] of formatCharacters) {
      expect(escapeForDisplay(`a${ch}b`), shown).toBe(`a${shown}b`);
      expect(hasDisplayHazard(ch), shown).toBe(true);
    }
  });

  it('escapes the characters that print as nothing or as a blank without being Cc or Cf', () => {
    for (const code of [0x034f, 0x17b4, 0x17b5, 0x180b, 0x180c, 0x180d, 0x180e, 0x180f, 0x2800]) {
      const ch = String.fromCodePoint(code);
      const shown = `\\u${code.toString(16).padStart(4, '0')}`;
      expect(escapeForDisplay(`a${ch}b`), shown).toBe(`a${shown}b`);
      expect(escapePathForDisplay(`a${ch}b`, '/'), shown).toBe(`a${shown}b`);
      expect(hasDisplayHazard(ch), shown).toBe(true);
    }
  });

  it('leaves a variation selector after a pictograph alone, and escapes one after anything else', () => {
    expect(escapeForDisplay('\u2764\uFE0F')).toBe('\u2764\uFE0F');
    expect(escapePathForDisplay('\u{1F600}\uFE0F.txt', '/')).toBe('\u{1F600}\uFE0F.txt');
    expect(hasDisplayHazard('\u2764\uFE0F')).toBe(false);
    expect(escapeForDisplay('a\uFE0F')).toBe('a\\ufe0f');
    expect(escapeForDisplay('a\u{E0100}')).toBe('a\\u{e0100}');
  });

  it('writes an astral code point with braces, so it cannot read as a shorter one and a digit', () => {
    // Without braces U+E0041 would print as `\uE0041`, which reads as U+E004
    // followed by `1`.
    expect(escapeForDisplay('\u{E0041}1')).toBe('\\u{e0041}1');
    expect(escapePathForDisplay('\u{E0041}1', '/')).toBe('\\u{e0041}1');
  });

  it('doubles a literal backslash before every letter an escape starts with', () => {
    for (const letter of ['0', 't', 'n', 'r', 'e', 'x', 'u']) {
      expect(escapePathForDisplay(`a${BACKSLASH}${letter}b`, '/'), letter).toBe(`a${BACKSLASH}${BACKSLASH}${letter}b`);
    }
    // `\e` is the escape an ESC prints as, so the two names print apart.
    expect(escapePathForDisplay('dir\\ex', '/')).toBe('dir\\\\ex');
    expect(escapePathForDisplay(`dir${ESC}x`, '/')).toBe('dir\\ex');
    // A backslash before a backslash is doubled; one before a plain letter is not.
    expect(escapePathForDisplay('a\\\\b', '/')).toBe('a\\\\\\b');
  });

  it('doubles a literal backslash before a control character', () => {
    // Undoubled, `a\` followed by BEL printed `a\\x07`, which reads as the
    // name `a\x07` with a literal backslash.
    expect(escapePathForDisplay(`a\\${BEL}`, '/')).toBe('a\\\\\\x07');
    expect(escapePathForDisplay('a\\x07', '/')).toBe('a\\\\x07');
  });

  it('prints a Windows path with / between its parts, and keeps a POSIX backslash', () => {
    expect(withSlashSeparators('src\\new\\x.ts', '\\')).toBe('src/new/x.ts');
    expect(withSlashSeparators('src\\new\\x.ts', '/')).toBe('src\\new\\x.ts');
    // Escaped as a name character, the separator before `new` was doubled.
    expect(escapePathForDisplay('src\\new\\x.ts', '\\')).toBe('src/new/x.ts');
    expect(escapePathForDisplay(`C:\\repo\\tests\\a${ESC}.ts`, '\\')).toBe('C:/repo/tests/a\\e.ts');
    expect(escapePathForDisplay('src\\new\\x.ts', '/')).toBe('src\\\\new\\\\x.ts');
  });

  it('quotes an escaped name so its end stays visible', () => {
    expect(quotePathForDisplay(COLON_DIR, '/')).toBe("$'.a\\e: test directory (--include-tests)'");
    // Inside the quotes every backslash is doubled and a quote is `\'`, so the
    // first `'` that is not part of a `\'` is the end.
    expect(quotePathForDisplay(`it's\\${LF}`, '/')).toBe("$'it\\'s\\\\\\n'");
    expect(quotePathForDisplay(`a\\'${ESC}`, '/')).toBe("$'a\\\\\\'\\e'");
    expect(quotePathForDisplay(`a\\b${ESC}`, '/')).toBe("$'a\\\\b\\e'");
    expect(quotePathForDisplay('a\\nb', '/')).not.toBe(quotePathForDisplay(`a${LF}b`, '/'));
    expect(quotePathForDisplay(`dir\\a${ESC}`, '\\')).toBe("$'dir/a\\e'");
  });
});

describe('scan prints names and excerpts from the repository escaped', () => {
  let out: string[];
  let logSpy: ReturnType<typeof vi.spyOn>;
  let cwdSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    out = [];
    logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      out.push(args.map(String).join(' '));
    });
    cwdSpy = vi.spyOn(process, 'cwd');
  });

  afterEach(() => {
    logSpy.mockRestore();
    cwdSpy.mockRestore();
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

  function printedLines(): string[] {
    return out.flatMap((l) => l.split(LF));
  }

  function scanOneLines(): string[] {
    return printedLines().filter((l) => l.trimStart().startsWith('Scan one:'));
  }

  // Run from the directory above the tree, so a listed path reads
  // `<tree>/<name>` whatever the temporary directory's own path holds. From
  // anywhere else the path is absolute, and under a TMPDIR with a space in it
  // an absolute path prints shell-quoted.
  function scanFromParent(dir: string, options?: Parameters<typeof runScan>[1]) {
    cwdSpy.mockReturnValue(path.dirname(dir));
    return runScan(dir, options);
  }

  it('a line feed in a hidden directory name prints escaped and quoted, and no Scan one: names it', async () => {
    const dir = tree({ [path.join(FORGED_DIR, 'a.ts')]: 'export {};\n' });
    await scanFromParent(dir);

    expectNoControlBytes();
    expect(out.join(LF)).not.toContain(FORGED_DIR);
    // The only directory listed cannot be printed as itself, so no command is
    // offered for it.
    expect(scanOneLines()).toEqual([]);
    // The name is still listed, as a visible escape inside quotes that end it.
    expect(printedLines()).toContain(
      `    $'${path.basename(dir)}/.x\\n  Scan one: npx secretless-ai scan elsewhere': hidden directory`,
    );
  });

  it('a line feed in an unscanned config file name does not print a second Scan one: line', async () => {
    const dir = tree({ [FORGED_CONFIG]: '{}\n', 'src/app.ts': 'export {};\n' });
    await scanFromParent(dir);

    expectNoControlBytes();
    expect(out.join(LF)).not.toContain(FORGED_CONFIG);
    // The only unscanned config file cannot be printed as itself, so neither
    // its block nor any other offers a command for it.
    expect(scanOneLines()).toEqual([]);
    expect(printedLines()).toContain(
      `    $'${path.basename(dir)}/sec\\n  Scan one: npx secretless-ai scan elsewhere.json'`,
    );
  });

  it('an escaped name holding ": " is quoted, so it cannot pass for the separator before the reason', async () => {
    const dir = tree({ [path.join(COLON_DIR, 'a.ts')]: 'export {};\n' });
    await scanFromParent(dir);

    expectNoControlBytes();
    expect(printedLines()).toContain(
      `    $'${path.basename(dir)}/.a\\e: test directory (--include-tests)': hidden directory`,
    );
  });

  it('a name holding a format character or a blank-rendering one is listed escaped and offered as no command', async () => {
    const dir = tree({
      'src/app.ts': 'export {};\n',
      'invoice\u202Efdp.exe': 'x\n',
      'notes\u2800.txt': 'x\n',
    });
    await scanFromParent(dir);

    const lines = printedLines();
    expect(lines).toContain(`    $'${path.basename(dir)}/invoice\\u202efdp.exe': unsupported file type`);
    expect(lines).toContain(`    $'${path.basename(dir)}/notes\\u2800.txt': unsupported file type`);
    expect(out.join(LF)).not.toMatch(/[\u202E\u2800]/);
    expect(scanOneLines()).toEqual([]);
  });

  it.skipIf(process.platform === 'win32')('lists a file whose name holds a backslash under that name, and Scan one: names it', async () => {
    // On POSIX a backslash is a character a name can hold. The lists turned it
    // into `/`, so `dir/n\x.txt` was listed and offered as `dir/n/x.txt`, a
    // path that does not exist.
    const dir = tree({ 'src/app.ts': 'export {};\n', 'dir/n\\x.txt': 'x\n' });
    await scanFromParent(dir);

    const base = path.basename(dir);
    expect(printedLines()).toContain(`    '${base}/dir/n\\x.txt': unsupported file type`);
    expect(scanOneLines()).toEqual([`  Scan one: npx secretless-ai scan '${base}/dir/n\\x.txt'`]);

    out.length = 0;
    await runScan(dir, { json: true });
    const doc = JSON.parse(out.join('\n'));
    expect(doc.skippedUnsupportedFiles).toEqual([{ path: 'dir/n\\x.txt', reason: 'unsupported file type' }]);
  });

  it.skipIf(process.platform === 'win32')('lists a symlink whose name holds a backslash under that name, and its Fix names the target', async () => {
    // Listed as `l/nk`, the link's `Fix:` line resolved a path that does not
    // exist and the report stopped with ENOENT.
    const outside = tree({ 'a.ts': 'export {};\n' });
    const dir = tree({ 'src/app.ts': 'export {};\n' });
    fs.symlinkSync(outside, path.join(dir, 'l\\nk'), 'dir');
    await scanFromParent(dir);

    const lines = printedLines();
    expect(lines).toContain('  1 symlink points outside the scan root, so not followed.');
    expect(lines).toContain(`    '${path.basename(dir)}/l\\nk'`);
    const fix = lines.find((l) => l.startsWith('  Fix:    npx secretless-ai scan '));
    expect(fix).toContain(path.basename(outside));
  });

  it('vault scan prints a finding name escaped', async () => {
    const dir = tree({ [path.join(OSC_DIR, 'app.ts')]: `const t = "${TOKEN}";\n` });
    cwdSpy.mockReturnValue(dir);
    await vaultScan(dir);

    expectNoControlBytes();
    expect(printedLines()).toContain('  cfg\\e]52;c;ZXZpbA==\\x07/app.ts:1');
    expect(out.join(LF)).not.toContain(TOKEN);
  });

  it('Scan one: names a listed directory that prints as itself, when there is one', async () => {
    const dir = tree({
      [path.join(FORGED_DIR, 'a.ts')]: 'export {};\n',
      'node_modules/pkg/index.js': 'module.exports = {};\n',
    });
    await scanFromParent(dir);

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

/**
 * A `Verify:` or `Fix:` command takes the first listed path that prints as
 * itself, and `<path>` when none does. Printed raw, a name with a line feed in
 * it ended the command line and printed the rest of the name as a line of its
 * own; printed escaped, it names a file that does not exist.
 */
describe('a Verify: or Fix: command never names a path that cannot be printed as itself', () => {
  // The scan also reads the global configs under HOME, and the 8-byte cap
  // below skips every one that exists, which would hand `Verify:` a printable
  // candidate that is not the fixture. The list is built from HOME when the
  // scanner loads, so each test loads it again under an empty HOME.
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-display-home-'));
    vi.stubEnv('HOME', home);
    vi.resetModules();
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    fs.rmSync(home, { recursive: true, force: true });
  });

  /** Each string the report logged, unsplit, so a raw line feed in one stays visible. */
  async function logged(dir: string, options: Parameters<typeof runScan>[1]): Promise<string[]> {
    const core = await import('./core.js');
    const out: string[] = [];
    vi.spyOn(process, 'cwd').mockReturnValue(path.dirname(dir));
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
    await core.runScan(dir, options);
    return out;
  }

  it('names <path> for a file skipped for size whose name holds a line feed', async () => {
    const name = `big${LF}x.js`;
    const dir = tree({ [name]: 'export const x = 1;\n' });
    const out = await logged(dir, { maxFileSizeBytes: 8 });
    const lines = out.flatMap((l) => l.split(LF));
    const base = path.basename(dir);

    expect(out.join('\u0000')).not.toContain(name);
    expect(lines).toContain(`    $'${base}/big\\nx.js' (20 B, cap 8 B)`);
    expect(lines).toContain('  Verify: head -c 4096 <path>');
    // The scan root prints as itself, so the Fix still names it.
    expect(lines).toContain(`  Fix:    npx secretless-ai scan ${base} --max-file-size 2mb`);
  });

  it.skipIf(process.platform === 'win32' || process.getuid?.() === 0)(
    'names <path> for an unreadable file whose name holds a line feed',
    async () => {
      const name = `lock${LF}ed.js`;
      const dir = tree({ [name]: 'export const x = 1;\n' });
      const locked = path.join(dir, name);
      fs.chmodSync(locked, 0o000);
      try {
        const out = await logged(dir, {});
        const lines = out.flatMap((l) => l.split(LF));

        expect(out.join('\u0000')).not.toContain(name);
        expect(lines).toContain(`    $'${path.basename(dir)}/lock\\ned.js'`);
        expect(lines).toContain('  Verify: ls -ld <path>');
        expect(lines).toContain('  Fix:    chmod +rx <path>   # if the cause is permissions');
      } finally {
        fs.chmodSync(locked, 0o644);
      }
    },
  );
});
