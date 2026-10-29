import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  BINDING_HOME_ID_FILE,
  BindingHomeIdError,
  bindingHomeId,
  ensureBindingHomeId,
  readBindingHomeId,
} from './binding-home-id';

/**
 * The secretless home's id (binding-home-id.ts): 32 lowercase hex digits
 * from 16 random bytes in `binding-home-id`, read without being created,
 * created with flag `wx` and mode 0600 where it is absent, and never
 * overwritten. Every directory is a scratch one under the system temp
 * directory; values are made at run time.
 */

let root: string;
let dir: string;
let file: string;

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-home-id-')));
  dir = path.join(root, '.secretless-ai');
  file = path.join(dir, BINDING_HOME_ID_FILE);
});

afterEach(() => {
  // A cell may leave a file without read permission behind.
  if (fs.existsSync(file)) fs.chmodSync(file, 0o600);
  fs.rmSync(root, { recursive: true, force: true });
});

const hex = (bytes: number) => crypto.randomBytes(bytes).toString('hex');
const mode = (p: string) => fs.statSync(p).mode & 0o777;

describe('bindingHomeId and readBindingHomeId read the id and never create it', () => {
  it('a home with no file: absent, and nothing is created', () => {
    expect(readBindingHomeId(dir)).toEqual({ state: 'absent' });
    expect(bindingHomeId(dir)).toBeUndefined();
    expect(fs.existsSync(dir)).toBe(false);
  });

  it('a file of 32 lowercase hex digits, with or without one newline: that id', () => {
    fs.mkdirSync(dir, { mode: 0o700 });
    for (const end of ['', '\n']) {
      const id = hex(16);
      fs.writeFileSync(file, `${id}${end}`);
      expect(readBindingHomeId(dir)).toEqual({ state: 'present', id });
      expect(bindingHomeId(dir)).toBe(id);
    }
  });

  const malformed: Array<[string, () => string | Buffer]> = [
    ['empty', () => ''],
    ['31 digits', () => hex(16).slice(1)],
    ['33 digits', () => `${hex(16)}a`],
    ['capital digits', () => hex(16).toUpperCase()],
    ['two newlines', () => `${hex(16)}\n\n`],
    ['a carriage return', () => `${hex(16)}\r\n`],
    ['leading space', () => ` ${hex(16)}`],
    ['words', () => 'not an id at all'],
    ['more than 33 bytes', () => hex(64)],
  ];
  for (const [name, content] of malformed) {
    it(`a file holding ${name} is malformed, and its content is never in the error`, () => {
      fs.mkdirSync(dir, { mode: 0o700 });
      const held = content();
      fs.writeFileSync(file, held);
      const read = readBindingHomeId(dir);
      expect(read.state).toBe('unusable');
      if (read.state !== 'unusable') return;
      expect(read.error.problem).toEqual({ kind: 'malformed' });
      expect(read.error.file).toBe(file);
      if (held.length > 0) expect(read.error.message).not.toContain(String(held).trim());
      expect(bindingHomeId(dir)).toBeUndefined();
    });
  }

  it('a directory at the path is malformed', () => {
    fs.mkdirSync(file, { recursive: true });
    const read = readBindingHomeId(dir);
    expect(read.state === 'unusable' && read.error.problem.kind).toBe('malformed');
  });

  it('a FIFO at the path is malformed and the read does not wait on it', () => {
    fs.mkdirSync(dir, { mode: 0o700 });
    execFileSync('mkfifo', [file]);
    const read = readBindingHomeId(dir);
    expect(read.state === 'unusable' && read.error.problem.kind).toBe('malformed');
  });

  it('a file that cannot be read is unusable, with its errno code', () => {
    if (process.getuid?.() === 0) return;
    fs.mkdirSync(dir, { mode: 0o700 });
    fs.writeFileSync(file, `${hex(16)}\n`);
    fs.chmodSync(file, 0o000);
    const read = readBindingHomeId(dir);
    expect(read).toEqual({ state: 'unusable', error: expect.any(BindingHomeIdError) });
    expect(read.state === 'unusable' && read.error.problem).toEqual({ kind: 'unusable', code: 'EACCES' });
  });
});

describe('ensureBindingHomeId creates the id where it is absent and never overwrites a file', () => {
  it('absent: the directory is made with mode 0700, the file with mode 0600 and 32 hex digits and a newline', () => {
    const id = ensureBindingHomeId(dir);
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(mode(dir)).toBe(0o700);
    expect(mode(file)).toBe(0o600);
    expect(fs.readFileSync(file, 'latin1')).toBe(`${id}\n`);
    expect(bindingHomeId(dir)).toBe(id);
  });

  it('a file of mode 0600 even where the process umask is wider', () => {
    const before = process.umask(0o000);
    try {
      ensureBindingHomeId(dir);
    } finally {
      process.umask(before);
    }
    expect(mode(file)).toBe(0o600);
  });

  it('an existing directory keeps its mode', () => {
    fs.mkdirSync(dir, { mode: 0o755 });
    fs.chmodSync(dir, 0o755);
    ensureBindingHomeId(dir);
    expect(mode(dir)).toBe(0o755);
  });

  it('present: the id is read and the file is unchanged', () => {
    fs.mkdirSync(dir, { mode: 0o700 });
    const id = hex(16);
    fs.writeFileSync(file, id);
    const before = fs.statSync(file).mtimeMs;
    expect(ensureBindingHomeId(dir)).toBe(id);
    expect(fs.readFileSync(file, 'latin1')).toBe(id);
    expect(fs.statSync(file).mtimeMs).toBe(before);
  });

  it('two calls give one id', () => {
    expect(ensureBindingHomeId(dir)).toBe(ensureBindingHomeId(dir));
  });

  it('malformed: throws, and the file is unchanged', () => {
    fs.mkdirSync(dir, { mode: 0o700 });
    const held = hex(16).toUpperCase();
    fs.writeFileSync(file, held);
    expect(() => ensureBindingHomeId(dir)).toThrow(BindingHomeIdError);
    expect(fs.readFileSync(file, 'latin1')).toBe(held);
  });

  it('a home that is a file: throws with the errno code, and creates nothing', () => {
    fs.writeFileSync(dir, '');
    let thrown: unknown;
    try {
      ensureBindingHomeId(dir);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(BindingHomeIdError);
    expect((thrown as BindingHomeIdError).problem.kind).toBe('unusable');
    expect((thrown as BindingHomeIdError).problem).toEqual({ kind: 'unusable', code: expect.stringMatching(/^E[A-Z]+$/) });
    expect(fs.statSync(dir).isFile()).toBe(true);
  });

  it('a symbolic link at the path, dangling, is not written through', () => {
    fs.mkdirSync(dir, { mode: 0o700 });
    const target = path.join(root, 'elsewhere');
    fs.symlinkSync(target, file);
    expect(() => ensureBindingHomeId(dir)).toThrow(BindingHomeIdError);
    expect(fs.existsSync(target)).toBe(false);
  });

  it('is not the telemetry install id, which it neither reads nor changes', () => {
    const telemetry = path.join(root, '.config', 'opena2a', 'telemetry.json');
    fs.mkdirSync(path.dirname(telemetry), { recursive: true });
    const installId = hex(16);
    const text = JSON.stringify({ enabled: false, installId });
    fs.writeFileSync(telemetry, text);
    const id = ensureBindingHomeId(dir);
    expect(id).not.toBe(installId);
    expect(fs.readFileSync(telemetry, 'utf-8')).toBe(text);
  });
});
