import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SOURCE_FILE_CAP_BYTES } from '../scan';

// The coverage section of `scan` joined each header to its consequence with an
// em dash ("1 file skipped for size — not scanned, ...") and each not-entered
// directory to its reason the same way, while `vault scan` already printed
// "Scan incomplete: ..." and "..., so they are not known to be clean." The two
// commands report the same gaps, so they use the same separators: `: ` after a
// header that names the state, `, so` before the consequence, `<path>: <reason>`
// for a listed name.

const EM_DASH = '—';

// chmod 000 does not stop root, so the unreadable block is only produced, and
// only asserted, where the lock holds.
const canLock = process.platform !== 'win32' && process.getuid?.() !== 0;

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function captureLog(): string[] {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(stripAnsi(a.map(String).join(' '))); });
  return lines;
}

const dirs: string[] = [];
function tmp(prefix: string): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  dirs.push(d);
  return d;
}

/** One file or link behind every coverage block `scan` prints. No credential anywhere. */
function treeWithEveryGap(bigBytes: number): string {
  const dir = tmp('coverage-sep-');
  fs.writeFileSync(path.join(dir, 'a.js'), 'const a = 1;\n');
  fs.writeFileSync(path.join(dir, 'b.js'), 'const b = 2;\n');
  fs.writeFileSync(path.join(dir, 'big.js'), '// x\n' + 'a'.repeat(bigBytes));
  fs.writeFileSync(path.join(dir, 'notes.txt'), 'notes\n');
  fs.writeFileSync(path.join(dir, 'secrets.json'), '{}\n');
  fs.mkdirSync(path.join(dir, 'node_modules', 'pkg'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'node_modules', 'pkg', 'index.js'), 'x\n');
  fs.symlinkSync(tmp('coverage-sep-outside-'), path.join(dir, 'outlink'));
  if (canLock) {
    const locked = path.join(dir, 'locked.js');
    fs.writeFileSync(locked, 'const c = 3;\n');
    fs.chmodSync(locked, 0o000);
  }
  return dir;
}

// The scan also reads the global configs under HOME (`~/.claude/CLAUDE.md`,
// `~/.claude.json`, ...), and the 200-byte cap below skips every one that
// exists, so on a machine that has them the size count is not the fixture's.
// The list is built from HOME when the scanner loads, so each test loads it
// again under an empty HOME.
async function load() {
  const core = await import('./core.js');
  const vault = await import('../vault-core.js');
  return { runScan: core.runScan, vaultScan: vault.vaultScan };
}

beforeEach(() => {
  vi.stubEnv('HOME', tmp('coverage-sep-home-'));
  vi.resetModules();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  for (const d of dirs.splice(0)) {
    const locked = path.join(d, 'locked.js');
    if (fs.existsSync(locked)) fs.chmodSync(locked, 0o644);
    fs.rmSync(d, { recursive: true, force: true });
  }
});

describe('the coverage section prints no em dash', () => {
  it('scan: every header, the cause line and the not-entered and not-opened lines', async () => {
    const { runScan } = await load();
    const dir = treeWithEveryGap(300);
    // From the directory above the tree a listed path reads `<tree>/<name>`.
    // From anywhere else it is absolute, and under a TMPDIR with a space in it
    // an absolute path prints shell-quoted.
    vi.spyOn(process, 'cwd').mockReturnValue(path.dirname(dir));
    const lines = captureLog();

    expect(await runScan(dir, { maxFileSizeBytes: 200 })).toBe(1);
    expect(await runScan(dir, { maxFiles: 1 })).toBe(1);
    const out = lines.join('\n');

    // Each block was printed, so the em-dash check below covers it.
    expect(out).toContain('Scan incomplete: stopped at the 1-file cap, so files were left unscanned.');
    if (canLock) {
      expect(out).toContain('1 path could not be read, so not known to be clean.');
      expect(out).toContain('Cause differs by path: permissions, a broken or looping symlink, or an I/O error.');
    }
    expect(out).toContain('1 symlink points outside the scan root, so not followed.');
    expect(out).toContain('1 file skipped for size, so not known to be clean.');
    expect(out).toContain('1 directory not entered for source files: declared boundaries, not findings.');
    expect(out).toContain('node_modules: dependency or build output');
    expect(out).toContain('1 config file not scanned: its name is not on the built-in config list, so not known to be clean.');
    // `secrets.json` is listed once, in the block above; `notes.txt` is the one
    // file left here.
    expect(out).toContain('1 file not opened: declared boundaries, not findings.');
    expect(out).toContain('notes.txt: unsupported file type');

    expect(out.split(EM_DASH).length - 1).toBe(0);
  });

  it('vault scan: the same gaps, the same separators', async () => {
    const { vaultScan } = await load();
    const dir = treeWithEveryGap(SOURCE_FILE_CAP_BYTES + 1024);
    const lines = captureLog();

    await vaultScan(dir);
    const out = lines.join('\n');

    expect(out).toContain('1 file(s) skipped for size, so they are not known to be clean.');
    if (canLock) expect(out).toContain('1 path(s) could not be read, so they are not known to be clean.');

    expect(out.split(EM_DASH).length - 1).toBe(0);
  });
});
