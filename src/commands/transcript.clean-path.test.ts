import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runClean } from './transcript';

// `clean --path` given a path that is not there, or a file that is not a
// transcript, printed "Scanned: 0 files" and "Transcripts are clean" at exit 0,
// and a non-transcript file read the default ~/.claude/projects instead. Each
// is now refused before anything is read, and 0 files is never called clean.
describe('runClean --path targets it does not read', () => {
  let home: string;
  let sibling: string;
  let out: string[];
  let err: string[];
  const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'clean-path-'));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    const projectDir = path.join(home, '.claude', 'projects', 'x');
    fs.mkdirSync(projectDir, { recursive: true });
    sibling = path.join(projectDir, 's1.jsonl');
    fs.writeFileSync(sibling, JSON.stringify({ role: 'user', content: 'hello' }) + '\n');
    out = [];
    err = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { out.push(args.join(' ')); });
    vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { err.push(args.join(' ')); });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(home, { recursive: true, force: true });
  });

  const all = (): string => [...out, ...err].join('\n');

  it('a missing path exits 1 and reads nothing', async () => {
    const missing = path.join(home, 'nope');
    const code = await runClean(['--dry-run', '--path', missing]);
    expect(code).toBe(1);
    expect(err.join('\n')).toContain(`Error: ${missing} was not found. Nothing was read.`);
    expect(err.join('\n')).toContain(`Verify: ls -ld ${missing}`);
    // The Fix line ends at the command; its remark is the line under it (#471).
    expect(err.join('\n')).toMatch(/Fix: {4}.* clean --dry-run$/m);
    expect(all()).not.toContain('Transcripts are clean');
    expect(all()).not.toContain('Scanned');
    expect(all()).not.toContain('Scanning transcripts at');
  });

  it('an existing .log file exits 1 and does not read the default directory', async () => {
    const log = path.join(home, 'transcript.log');
    fs.writeFileSync(log, '');
    const code = await runClean(['--dry-run', '--path', log]);
    expect(code).toBe(1);
    expect(err.join('\n')).toContain(`Error: ${log} is not a transcript (.jsonl or .md). Nothing was read.`);
    expect(err.join('\n')).toContain(`Verify: ls -ld ${log}`);
    expect(all()).not.toContain('Transcripts are clean');
    expect(all()).not.toContain('Scanned');
    expect(all()).not.toContain('s1.jsonl');
  });

  it('a .txt file beside a session exits 1 and does not report that session', async () => {
    const txt = path.join(path.dirname(sibling), 'notes.txt');
    fs.writeFileSync(txt, 'notes');
    const code = await runClean(['--dry-run', '--path', txt]);
    expect(code).toBe(1);
    expect(err.join('\n')).toContain('is not a transcript (.jsonl or .md). Nothing was read.');
    expect(all()).not.toContain('s1.jsonl');
    expect(all()).not.toContain('Transcripts are clean');
  });

  it.skipIf(process.platform === 'win32')('a path whose lookup fails exits 1 and names the error code', async () => {
    const a = path.join(home, 'loop-a');
    fs.symlinkSync(path.join(home, 'loop-b'), a);
    fs.symlinkSync(a, path.join(home, 'loop-b'));
    const code = await runClean(['--dry-run', '--path', a]);
    expect(code).toBe(1);
    expect(err.join('\n')).toContain(`Error: ${a} could not be read (ELOOP). Nothing was read.`);
    expect(all()).not.toContain('Transcripts are clean');
    expect(all()).not.toContain('s1.jsonl');
  });

  it('an empty directory reports 0 files and is not called clean', async () => {
    const empty = path.join(home, 'emptydir');
    fs.mkdirSync(empty);
    const code = await runClean(['--dry-run', '--path', empty]);
    expect(code).toBe(0);
    expect(out.join('\n')).toContain('Scanned: 0 files — nothing to report.');
    expect(all()).not.toContain('Transcripts are clean');
    expect(err).toEqual([]);
  });

  it('CONTROL: a directory holding a clean transcript is still called clean', async () => {
    const code = await runClean(['--dry-run', '--path', path.dirname(sibling)]);
    expect(code).toBe(0);
    expect(out.join('\n')).toContain('Scanned: 1 files');
    expect(out.join('\n')).toContain('No credentials found. Transcripts are clean.');
  });

  it('CONTROL: a .jsonl file given directly is read', async () => {
    const code = await runClean(['--dry-run', '--path', sibling]);
    expect(code).toBe(0);
    expect(out.join('\n')).toContain('Scanned: 1 files');
    expect(out.join('\n')).toContain('Transcripts are clean');
  });
});
