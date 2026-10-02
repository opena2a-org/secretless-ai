/**
 * Recorder programs that stand in for `security`, `secret-tool`, `which` and
 * `op` in tests. Each is a real executable, so the backend's real child
 * process path runs: the recorder writes its argv, its environment and its
 * stdin to a file the test reads back. No lane and no CI job has a macOS
 * Keychain, so this is how the store's argv and stdin are observed on Linux.
 *
 * Excluded from the build (tsconfig: `*.test-support.ts`) and from the test
 * glob (`*.test.ts`), so it ships in neither.
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';

export interface RecordedCall {
  pid: number;
  argv: string[];
  env: Record<string, string | undefined>;
  stdin: string;
}

/** How the recorder behaves on its next invocation. */
export type RecorderMode =
  | { kind: 'ok' }
  /** Exit with `status`, printing `stderr` and `stdout`, storing nothing. */
  | { kind: 'fail'; status: number; stderr: string; stdout?: string }
  /** Never exit. Writes its pid to `hang.pid` first. */
  | { kind: 'hang' }
  /** Exit 0 without storing: the write that reports success and did not land. */
  | { kind: 'drop' }
  /** Store a different value from the one given, then exit 0. */
  | { kind: 'wrong' }
  /** Answer `-w` but fail the `-g` encoding probe (security only). */
  | { kind: 'probe-fails' };

export interface Recorder {
  /** Directory holding the program, its records and its state. */
  dir: string;
  /** Absolute path of the executable. */
  program: string;
  calls(): RecordedCall[];
  setMode(mode: RecorderMode): void;
  /** Pid written by a hanging invocation, or null if none hung. */
  hangPid(): number | null;
  cleanup(): void;
}

/**
 * Programs live under the repository's own cache, not under os.tmpdir(): a
 * temp directory mounted `noexec` (this lane's is) makes every spawn fail with
 * EACCES, and a test that then reads "the planted program never ran" would
 * pass for the wrong reason. `node_modules/.cache` is where the package's
 * other test harnesses already put scratch files, and vitest itself runs from
 * `node_modules`, so execution there is known to be allowed.
 */
function makeDir(prefix: string): string {
  const base = path.resolve(process.cwd(), 'node_modules', '.cache', 'secretless-child-recorders');
  fs.mkdirSync(base, { recursive: true });
  return fs.mkdtempSync(path.join(base, prefix));
}

/**
 * Write an executable CommonJS script. The shebang names this very node
 * binary, so no PATH lookup is involved in starting the recorder itself.
 */
export function writeProgram(dir: string, name: string, body: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, `#!${process.execPath}\n'use strict';\n${body}`, { mode: 0o755 });
  return file;
}

function recorderPrologue(dir: string): string {
  return `
const fs = require('fs');
const path = require('path');
const DIR = ${JSON.stringify(dir)};
const argv = process.argv.slice(2);
const stdin = (() => { try { return fs.readFileSync(0, 'utf-8'); } catch { return ''; } })();
fs.appendFileSync(path.join(DIR, 'calls.jsonl'),
  JSON.stringify({ pid: process.pid, argv, env: process.env, stdin }) + '\\n');
const control = (() => {
  try { return JSON.parse(fs.readFileSync(path.join(DIR, 'control.json'), 'utf-8')); }
  catch { return { kind: 'ok' }; }
})();
const statePath = path.join(DIR, 'state.json');
const state = (() => {
  try { return JSON.parse(fs.readFileSync(statePath, 'utf-8')); } catch { return {}; }
})();
const save = () => fs.writeFileSync(statePath, JSON.stringify(state));
if (control.kind === 'hang') {
  fs.writeFileSync(path.join(DIR, 'hang.pid'), String(process.pid));
  setInterval(() => {}, 1000);
  return;
}
if (control.kind === 'fail') {
  process.stdout.write(control.stdout || '');
  process.stderr.write(control.stderr || '');
  process.exit(control.status);
}
`;
}

function makeRecorder(prefix: string, name: string, body: string): Recorder {
  const dir = makeDir(prefix);
  const program = writeProgram(dir, name, recorderPrologue(dir) + body);
  const callsPath = path.join(dir, 'calls.jsonl');
  return {
    dir,
    program,
    calls() {
      if (!fs.existsSync(callsPath)) return [];
      return fs.readFileSync(callsPath, 'utf-8')
        .split('\n')
        .filter(l => l.length > 0)
        .map(l => JSON.parse(l) as RecordedCall);
    },
    setMode(mode) {
      fs.writeFileSync(path.join(dir, 'control.json'), JSON.stringify(mode));
    },
    hangPid() {
      const p = path.join(dir, 'hang.pid');
      return fs.existsSync(p) ? Number(fs.readFileSync(p, 'utf-8')) : null;
    },
    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

/**
 * Stands in for `/usr/bin/security`.
 *
 * Models what M1 measured: `-i` reads one command per line from stdin and
 * exits with the status of the LAST one; operands are double-quoted with `\"`
 * and `\\` escapes; `-X` carries the password as hex; `find-generic-password
 * -w` prints a value with a non-printable byte as hex, and `-g` says which on
 * its `password:` line; an absent item exits 44.
 */
export function makeSecurityRecorder(): Recorder {
  return makeRecorder('secretless-security-recorder-', 'security', `
function opt(args, flag) { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; }
function tokenize(line) {
  const out = []; let cur = ''; let inQ = false; let has = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQ) {
      if (c === '\\\\' && i + 1 < line.length) cur += line[++i];
      else if (c === '"') inQ = false;
      else cur += c;
    } else if (c === '"') { inQ = true; has = true; }
    else if (c === ' ' || c === '\\t') { if (has || cur.length) { out.push(cur); cur = ''; has = false; } }
    else { cur += c; has = true; }
  }
  if (has || cur.length) out.push(cur);
  return out;
}
const NOT_FOUND = 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\\n';
function keyOf(s, a) { return String(s) + '\\u0000' + String(a); }
function run(cmd) {
  const sub = cmd[0];
  const s = opt(cmd, '-s'), a = opt(cmd, '-a');
  if (sub === 'add-generic-password') {
    const hex = opt(cmd, '-X');
    const w = opt(cmd, '-w');
    let data = hex !== undefined ? hex : (w !== undefined ? Buffer.from(w, 'utf-8').toString('hex') : null);
    if (data === null) { process.stderr.write('security: no password given\\n'); return 2; }
    if (control.kind === 'drop') return 0;
    if (control.kind === 'wrong') data = Buffer.from('a-different-value', 'utf-8').toString('hex');
    state[keyOf(s, a)] = { hex: data, label: opt(cmd, '-l') };
    save();
    return 0;
  }
  if (sub === 'find-generic-password') {
    const item = state[keyOf(s, a)];
    if (!item) { process.stderr.write(NOT_FOUND); return 44; }
    const bytes = Buffer.from(item.hex, 'hex');
    const printable = [...bytes].every(b => b >= 0x20 && b <= 0x7e);
    if (cmd.includes('-g')) {
      if (control.kind === 'probe-fails') { process.stderr.write('security: User interaction is not allowed.\\n'); return 1; }
      process.stdout.write('keychain: "/Users/x/Library/Keychains/login.keychain-db"\\n    "svce"<blob>="' + s + '"\\n');
      process.stderr.write(printable
        ? 'password: "' + bytes.toString('utf-8') + '"\\n'
        : 'password: 0x' + item.hex.toUpperCase() + '  "' + bytes.toString('latin1').replace(/\\n/g, '\\\\012') + '"\\n');
      return 0;
    }
    if (cmd.includes('-w')) {
      process.stdout.write((printable ? bytes.toString('utf-8') : item.hex) + '\\n');
      return 0;
    }
    return 0;
  }
  if (sub === 'delete-generic-password') {
    const k = keyOf(s, a);
    if (!state[k]) { process.stderr.write(NOT_FOUND); return 44; }
    delete state[k];
    save();
    return 0;
  }
  if (sub === 'default-keychain') {
    process.stdout.write('    "/Users/x/Library/Keychains/login.keychain-db"\\n');
    return 0;
  }
  process.stderr.write('security: unknown command "' + sub + '"\\n');
  return 1;
}
if (argv[0] === '-i') {
  const lines = stdin.split('\\n').filter(l => l.length > 0);
  let status = 0;
  for (const line of lines) status = run(tokenize(line));
  process.exit(status);
}
process.exit(run(argv));
`);
}

/**
 * Stands in for `secret-tool`: `store` reads the value from stdin, `lookup`
 * prints it with no trailing newline, `clear` removes it and exits 0 either
 * way, as libsecret's tool does.
 */
export function makeSecretToolRecorder(): Recorder {
  return makeRecorder('secretless-secret-tool-recorder-', 'secret-tool', `
function attrs(args) {
  const out = {};
  for (let i = 0; i + 1 < args.length; i += 2) out[args[i]] = args[i + 1];
  return out;
}
function keyOf(a) { return String(a.service) + '\\u0000' + String(a.account); }
const sub = argv[0];
if (sub === 'store') {
  const rest = argv.slice(1).filter(x => !x.startsWith('--label='));
  state[keyOf(attrs(rest))] = stdin;
  save();
  process.exit(0);
}
if (sub === 'lookup') {
  const v = state[keyOf(attrs(argv.slice(1)))];
  if (v === undefined) process.exit(1);
  process.stdout.write(v);
  process.exit(0);
}
if (sub === 'clear') {
  delete state[keyOf(attrs(argv.slice(1)))];
  save();
  process.exit(0);
}
process.stderr.write('secret-tool: unknown command\\n');
process.exit(2);
`);
}

/**
 * A program that never exits. `pid()` reads the pid it wrote at start, so a
 * test can confirm the child is gone after the bound.
 */
export function makeHangingProgram(name: string): {
  dir: string;
  program: string;
  pid(): number | null;
  cleanup(): void;
} {
  const dir = makeDir('secretless-hang-');
  const pidPath = path.join(dir, 'hang.pid');
  const program = writeProgram(dir, name, `
const fs = require('fs');
try { fs.readFileSync(0); } catch {}
fs.writeFileSync(${JSON.stringify(pidPath)}, String(process.pid));
setInterval(() => {}, 1000);
`);
  return {
    dir,
    program,
    pid: () => (fs.existsSync(pidPath) ? Number(fs.readFileSync(pidPath, 'utf-8')) : null),
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * A program that records that it ran, and nothing else. Planted first on
 * PATH under the name `security`, it is the thing that must never run.
 */
export function makeMarkerProgram(name: string): {
  dir: string;
  program: string;
  ran(): boolean;
  /**
   * Positive control: run the program directly, confirm it leaves its marker,
   * and clear the marker. A "never ran" assertion is only meaningful after
   * this has shown the program can run at all.
   */
  controlRun(): boolean;
  cleanup(): void;
} {
  const dir = makeDir('secretless-marker-');
  const markerPath = path.join(dir, 'ran.marker');
  const program = writeProgram(dir, name, `
const fs = require('fs');
fs.writeFileSync(${JSON.stringify(markerPath)}, JSON.stringify(process.argv.slice(2)));
process.exit(0);
`);
  return {
    dir,
    program,
    ran: () => fs.existsSync(markerPath),
    controlRun: () => {
      const res = spawnSync(program, ['control'], { stdio: 'pipe', timeout: 10_000 });
      const ok = res.status === 0 && fs.existsSync(markerPath);
      fs.rmSync(markerPath, { force: true });
      return ok;
    },
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

/** True when no process with this pid exists any more. */
export function processIsGone(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'ESRCH';
  }
}

/** Run `fn` with `dir` first on PATH, restoring PATH after. */
export async function withPathPrefix<T>(dir: string, fn: () => Promise<T> | T): Promise<T> {
  const previous = process.env.PATH;
  process.env.PATH = `${dir}${path.delimiter}${previous ?? ''}`;
  try {
    return await fn();
  } finally {
    process.env.PATH = previous;
  }
}

/** Run `fn` with `process.platform` reporting `platform`, restoring it after. */
export async function withPlatform<T>(platform: NodeJS.Platform, fn: () => Promise<T> | T): Promise<T> {
  const original = Object.getOwnPropertyDescriptor(process, 'platform')!;
  Object.defineProperty(process, 'platform', { value: platform, configurable: true });
  try {
    return await fn();
  } finally {
    Object.defineProperty(process, 'platform', original);
  }
}

/** A random value of `length` bytes in a URL-safe alphabet. */
export function randomValue(length: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let out = '';
  for (let i = 0; i < length; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  return out;
}
