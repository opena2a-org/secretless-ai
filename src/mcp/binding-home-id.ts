/**
 * The id of a secretless home (`~/.secretless-ai`): the writer of each
 * binding protect-mcp stores (McpBinding.boundOn).
 *
 * The id is 32 lowercase hex digits from 16 random bytes, kept in
 * BINDING_HOME_ID_FILE in the secretless home, the directory the store keeps
 * its files in. bindingHomeId reads it and never creates it. protect-mcp runs
 * ensureBindingHomeId before the first binding it stores in a run, which
 * creates the file where it is absent and never overwrites one.
 *
 * It is not the telemetry install id, and no other value is read for it: a
 * binding in a store several machines read is read by everyone with access to
 * that store. Copying the secretless home to another machine copies the id.
 * It stops one home's protect-mcp and mcp-unprotect from changing a binding
 * another home stored, and it authenticates nothing: anything that runs as
 * the operator can write the file. Nothing prints it.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { errorCode } from './discover';

/** The file in the secretless home that holds its id. */
export const BINDING_HOME_ID_FILE = 'binding-home-id';

/** 32 lowercase hex digits and at most one trailing newline: everything the file may hold. */
const HOME_ID_CONTENT = /^[0-9a-f]{32}\n?$/;

/** The most bytes the file may hold: 32 digits and a newline. */
const HOME_ID_MAX_BYTES = 33;

/**
 * Why the home id file could not be used: it holds something other than an
 * id (`malformed`: other content, more than HOME_ID_MAX_BYTES, or not a
 * regular file), or it could not be read or created (`unusable`, with the
 * error's errno code as errorCode gives it). Its message names the file and
 * never what the file holds.
 */
export class BindingHomeIdError extends Error {
  constructor(
    readonly file: string,
    readonly problem: { kind: 'malformed' } | { kind: 'unusable'; code: string },
  ) {
    super(problem.kind === 'malformed'
      ? `${file} does not hold a secretless home id`
      : `${file} could not be read or created (${problem.code})`);
    this.name = 'BindingHomeIdError';
  }
}

/** What the home id file holds: an id, nothing (absent), or what could not be used, with why. */
export type BindingHomeIdRead =
  | { state: 'present'; id: string }
  | { state: 'absent' }
  | { state: 'unusable'; error: BindingHomeIdError };

/** The path of the home id file in the secretless home `dir`. */
export function bindingHomeIdFile(dir: string): string {
  return path.join(dir, BINDING_HOME_ID_FILE);
}

/** A path that does not exist: it, or a directory on the way to it, is absent. */
function isAbsent(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException).code;
  return code === 'ENOENT' || code === 'ENOTDIR';
}

/**
 * The id the secretless home `dir` holds, read without creating or changing
 * anything. The file is opened without blocking and read only when it is a
 * regular file of at most HOME_ID_MAX_BYTES, so a FIFO or a large file is
 * `malformed` and never hangs or fills the read.
 */
export function readBindingHomeId(dir: string): BindingHomeIdRead {
  const file = bindingHomeIdFile(dir);
  let fd: number;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  } catch (err) {
    if (isAbsent(err)) return { state: 'absent' };
    return { state: 'unusable', error: new BindingHomeIdError(file, { kind: 'unusable', code: errorCode(err) }) };
  }
  const malformed = (): BindingHomeIdRead => ({ state: 'unusable', error: new BindingHomeIdError(file, { kind: 'malformed' }) });
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > HOME_ID_MAX_BYTES) return malformed();
    // One byte more than the bound, so a file that grew after the check is seen.
    const buffer = Buffer.alloc(HOME_ID_MAX_BYTES + 1);
    let total = 0;
    for (;;) {
      const read = fs.readSync(fd, buffer, total, buffer.length - total, null);
      if (read === 0) break;
      total += read;
      if (total > HOME_ID_MAX_BYTES) return malformed();
    }
    const text = buffer.subarray(0, total).toString('latin1');
    if (!HOME_ID_CONTENT.test(text)) return malformed();
    return { state: 'present', id: text.slice(0, 32) };
  } catch (err) {
    return { state: 'unusable', error: new BindingHomeIdError(file, { kind: 'unusable', code: errorCode(err) }) };
  } finally {
    fs.closeSync(fd);
  }
}

/** The id the secretless home `dir` holds, or undefined when it holds none that can be read. Never creates the file. */
export function bindingHomeId(dir: string): string | undefined {
  const read = readBindingHomeId(dir);
  return read.state === 'present' ? read.id : undefined;
}

/**
 * The id of the secretless home `dir`, created where the file is absent: 16
 * random bytes as 32 lowercase hex digits and a newline, written with flag
 * `wx` and mode 0600 inside the directory, made with mode 0700 when it is
 * absent. A file another run created first (EEXIST) is read. A file that
 * holds anything else, or one that cannot be read or created, throws
 * BindingHomeIdError, and is never overwritten; a file this call created and
 * could not finish writing is removed, so it never leaves one that holds part
 * of an id.
 */
export function ensureBindingHomeId(dir: string): string {
  const read = readBindingHomeId(dir);
  if (read.state === 'present') return read.id;
  if (read.state === 'unusable') throw read.error;
  const file = bindingHomeIdFile(dir);
  const unusable = (err: unknown) => new BindingHomeIdError(file, { kind: 'unusable', code: errorCode(err) });
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch (err) {
    throw unusable(err);
  }
  const id = crypto.randomBytes(16).toString('hex');
  let fd: number;
  try {
    fd = fs.openSync(file, 'wx', 0o600);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw unusable(err);
    const again = readBindingHomeId(dir);
    if (again.state === 'present') return again.id;
    throw again.state === 'unusable' ? again.error : unusable(err);
  }
  try {
    fs.fchmodSync(fd, 0o600);
    fs.writeSync(fd, `${id}\n`);
    fs.fsyncSync(fd);
  } catch (err) {
    fs.closeSync(fd);
    try {
      fs.unlinkSync(file);
    } catch {
      // The error below names the file.
    }
    throw unusable(err);
  }
  fs.closeSync(fd);
  return id;
}
