/**
 * Every backend child process is bounded in time, from one named source.
 *
 * The OS keychain CLIs (`security`, `secret-tool`) and the 1Password CLI all
 * have one slow path: a locked store, where the CLI blocks on an unlock or
 * approval dialog that a human may never answer. A `run` that resolves a
 * secret inside such a call then hangs with no output, and the user's command
 * never starts. A bound turns that into a visible failure with a Verify and a
 * Fix line.
 *
 * The value is the builder's, with its basis:
 *
 *   30 seconds. Long enough for a person at the machine to type the login
 *   password or touch the sensor when the dialog does appear, and the same
 *   window the 1Password backend has used since its own bound was added, so a
 *   locked store fails the same way whichever backend holds it. Short enough
 *   that an unattended invocation fails in well under the two-minute hang that
 *   motivated the bound.
 *
 * Nothing reads this from the environment, config or a flag: the bound is a
 * property of the code. Tests that need a shorter window pass one through a
 * constructor or function parameter, which no caller outside a test reaches.
 */

import { spawn, execFileSync, type ExecFileSyncOptions } from 'child_process';

export const BACKEND_CHILD_TIMEOUT_MS = 30_000;

/**
 * `SECRETLESS_OS_KEYCHAIN=off` refuses to start the OS credential-store CLIs.
 * It can only refuse: a refused call is a thrown error at the call site, never
 * a null, an empty result or a different store. It cannot name a program or a
 * bound. Exact program match, so the recorder seam is unaffected.
 */
export const OS_KEYCHAIN_SWITCH = 'SECRETLESS_OS_KEYCHAIN';
const OS_KEYCHAIN_PROGRAMS: ReadonlySet<string> = new Set(['/usr/bin/security', 'secret-tool']);

export function osKeychainRefused(program: string, args: readonly string[]): boolean {
  if (process.env.SECRETLESS_OS_KEYCHAIN !== 'off') return false;
  if (OS_KEYCHAIN_PROGRAMS.has(program)) return true;
  // The Secret Service probes run `which secret-tool`; refused with it, so no
  // probe reports a store the next call will refuse.
  return program === 'which' && args.length === 1 && OS_KEYCHAIN_PROGRAMS.has(args[0]);
}

/**
 * The refusal, as its own class so a caller that turns other probe failures
 * into "not available" can pass this one's reason through instead.
 */
export class OsKeychainRefusedError extends Error {
  override readonly name = 'OsKeychainRefusedError';
}

export function osKeychainRefusedError(program: string): OsKeychainRefusedError {
  return new OsKeychainRefusedError([
    `${program} was not started: ${OS_KEYCHAIN_SWITCH}=off is set in this process.`,
    '',
    '  Nothing was read from or written to any store.',
    '',
    `  Verify:  printenv ${OS_KEYCHAIN_SWITCH}`,
    `  Fix:     unset ${OS_KEYCHAIN_SWITCH}`,
  ].join('\n'));
}

/**
 * Signal used when the bound elapses. SIGKILL rather than SIGTERM: the point of
 * the bound is that the child is gone when the call returns, and a child that
 * is blocked inside a system dialog is exactly the kind that may not act on a
 * SIGTERM.
 */
export const BACKEND_CHILD_KILL_SIGNAL = 'SIGKILL' as const;

export interface BoundedChildResult {
  /** Exit status, or null when the child ended on a signal or never started. */
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  /** True when the bound elapsed and the child was killed. */
  timedOut: boolean;
  /** Set when the child could not be started at all (ENOENT, EACCES). */
  spawnError: NodeJS.ErrnoException | null;
}

export interface BoundedChildOptions {
  /** The bound, in milliseconds. Always passed explicitly: the caller names its source. */
  timeoutMs: number;
  /** Written to the child's stdin, then stdin is closed. Omitted: stdin is closed at once. */
  input?: string;
}

/**
 * Run `program` with `args`, collecting both output streams, and resolve once
 * the child is gone. For a child that was attempted it never rejects: a failure
 * to start, a non-zero exit and a timeout are all reported in the result. The
 * one rejection is the `SECRETLESS_OS_KEYCHAIN=off` refusal, which no caller
 * may read as "absent".
 *
 * The child's argv is exactly `args`; the only data path for anything that must
 * stay off the command line is `input`.
 */
export function runBoundedChild(
  program: string,
  args: readonly string[],
  opts: BoundedChildOptions,
): Promise<BoundedChildResult> {
  if (osKeychainRefused(program, args)) return Promise.reject(osKeychainRefusedError(program));
  return new Promise((resolve) => {
    let settled = false;
    let stdout = '';
    let stderr = '';
    let spawnError: NodeJS.ErrnoException | null = null;

    const settle = (status: number | null, signal: NodeJS.Signals | null, child: { killed: boolean }) => {
      if (settled) return;
      settled = true;
      resolve({
        status,
        signal,
        stdout,
        stderr,
        timedOut: child.killed && signal !== null,
        spawnError,
      });
    };

    const child = spawn(program, [...args], {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: opts.timeoutMs,
      killSignal: BACKEND_CHILD_KILL_SIGNAL,
    });

    child.stdout.setEncoding('utf-8');
    child.stdout.on('data', (chunk: string) => { stdout += chunk; });
    child.stderr.setEncoding('utf-8');
    child.stderr.on('data', (chunk: string) => { stderr += chunk; });

    // A child that exits before reading its stdin makes the write fail with
    // EPIPE. That is not an error of ours; the exit status says what happened.
    child.stdin.on('error', () => { /* reported through status */ });

    child.on('error', (err: NodeJS.ErrnoException) => {
      spawnError = err;
      // When the process never started there is no 'close' to wait for.
      if (child.pid === undefined) settle(null, null, child);
    });

    child.on('close', (status, signal) => settle(status, signal, child));

    if (opts.input !== undefined) {
      child.stdin.end(opts.input);
    } else {
      child.stdin.end();
    }
  });
}

/**
 * Synchronous counterpart for the factory's availability probes, which are
 * called from synchronous code. Throws exactly as `execFileSync` does; the
 * bound is the one addition, so a probe of a locked or wedged tool returns a
 * "not available" answer instead of never returning.
 */
export function execFileSyncBounded(
  program: string,
  args: readonly string[],
  timeoutMs: number,
  opts?: Omit<ExecFileSyncOptions, 'timeout' | 'killSignal'>,
): Buffer | string {
  if (osKeychainRefused(program, args)) throw osKeychainRefusedError(program);
  return execFileSync(program, [...args], {
    stdio: 'pipe',
    ...opts,
    timeout: timeoutMs,
    killSignal: BACKEND_CHILD_KILL_SIGNAL,
  });
}
