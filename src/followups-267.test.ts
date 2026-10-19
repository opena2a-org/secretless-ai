import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { listedPath, pathOperand, runScan } from './commands/core';
import { namedFilePath } from './scan';

/**
 * Follow-ups to #266 (#267): a single named file reports its path with `/`
 * between the parts of a Windows path when it lies outside the current
 * directory, as it did inside it, and keeps a backslash in its name on Linux
 * and macOS; and on Windows a list of paths `scan` did not read names each
 * path with `/`, whether the name prints as itself or escaped.
 */

const LF = '\n';
// A name on Windows cannot hold a backslash, so a case with one is POSIX-only.
const itPosix = process.platform === 'win32' ? it.skip : it;

const made: string[] = [];
/** A temporary directory by its real path, so a path from cwd is relative. */
function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

describe('the path a single named file reports', () => {
  it('Windows: the path as given is reported with `/` between its parts', () => {
    // No file is there, so the path cannot be resolved against cwd and the
    // one given is reported: the branch a file outside cwd takes.
    expect(namedFilePath('C:\\other\\x.env', '\\')).toBe('C:/other/x.env');
  });

  itPosix('POSIX: a file inside cwd whose name holds a backslash reports that name, in --json too', async () => {
    const dir = tmp('followups-267-');
    const file = path.join(dir, 'n\\x.txt');
    fs.writeFileSync(file, 'xx\n');
    vi.spyOn(process, 'cwd').mockReturnValue(dir);

    expect(namedFilePath(file)).toBe('n\\x.txt');

    // Over the size cap, the file is listed under the same path.
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
    const code = await runScan(file, { json: true, maxFileSizeBytes: 1 });
    expect(JSON.parse(out.join(LF)).oversizeFiles).toEqual([{ path: 'n\\x.txt', bytes: 3, capBytes: 1 }]);
    expect(code).toBe(1);
  });

  itPosix('CONTROL: a file outside cwd reports the path as given, backslash included', () => {
    const dir = tmp('followups-267-');
    const file = path.join(dir, 'n\\x.txt');
    fs.writeFileSync(file, 'xx\n');
    vi.spyOn(process, 'cwd').mockReturnValue(tmp('followups-267-cwd-'));

    expect(namedFilePath(file)).toBe(file);
  });
});

describe('a list of paths scan did not read names each path with one separator', () => {
  it('Windows: a name that prints as itself and one shown escaped both use `/`', () => {
    expect(listedPath('fx\\notes.txt', '\\')).toBe('fx/notes.txt');
    expect(listedPath(`fx\\n${LF}x.txt`, '\\')).toBe("$'fx/n\\nx.txt'");
    expect(listedPath('C:\\work\\a b\\notes.txt', '\\')).toBe("'C:/work/a b/notes.txt'");
  });

  it('Windows: a listed name and the command operand under the list spell it alike', () => {
    for (const p of ['fx\\notes.txt', 'C:\\work\\a b\\notes.txt']) {
      expect(listedPath(p, '\\')).toBe(pathOperand(p, '\\'));
    }
  });

  it('POSIX: a backslash is a character of the name and is kept, quoted or escaped', () => {
    expect(listedPath('fx/n\\x.txt', '/')).toBe("'fx/n\\x.txt'");
    expect(listedPath(`fx/n\\${LF}x.txt`, '/')).toBe("$'fx/n\\\\\\nx.txt'");
  });
});
