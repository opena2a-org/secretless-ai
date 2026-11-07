import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { init } from './init';

// The guard hook reaches the same verdict when bash cannot write a temporary
// file, as on a full disk or under a sandbox that refuses the write. bash backs
// a here-document and a here-string with a temporary file: always on bash 3.2,
// the /bin/bash of macOS, and on bash 5 when BASH_COMPAT is 50 or the text is
// larger than a pipe holds. The guard feeds no command through either, so no
// rule depends on that file, and a rule it cannot check makes it exit 2.
//
// The condition below is a file-size limit of zero with SIGXFSZ ignored: bash
// can create its temporary file but cannot write it, so the redirection fails
// as it does when the write is refused, on Linux and on macOS alike.
// BASH_COMPAT=50 makes bash 5 back every here-document with a file, as bash
// 3.2 does. Each case runs with and without the limit, and both runs must
// reach the expected verdict. Each run starts bash and python3, so the bound
// is raised for a loaded machine.

const NO_TEMP_FILE = "trap '' XFSZ; ulimit -f 0; ";
const HERE_DOC_FAILURE = /cannot create temp file for here.document/;

const hasPython3 = (() => {
  try { execSync('command -v python3', { stdio: 'ignore' }); return true; } catch { return false; }
})();

// The rule a deny reason names: the text after "Secretless: " up to the end of
// its first clause, as the verdict snapshot reads it.
function reasonClass(reason: string): string {
  const text = reason.replace(/^Secretless: /, '');
  const end = text.search(/[.:](\s|$)/);
  return end === -1 ? text : text.slice(0, end);
}

function verdictOf(status: number | null, stdout: string): string {
  if (status !== 0) return `error: exit ${String(status)}`;
  if (!stdout.trim()) return 'allow';
  try {
    const hso = JSON.parse(stdout).hookSpecificOutput;
    if (hso.permissionDecision === 'deny') return `deny: ${reasonClass(String(hso.permissionDecisionReason))}`;
  } catch { /* reported below */ }
  return 'error: output is not a deny decision';
}

// Run the hook as a settings file runs it, a shell executing the file, which
// starts the bash its first line names.
function runHook(
  hook: string, payload: object, env: NodeJS.ProcessEnv, cwd: string, noTempFile: boolean,
): { verdict: string; stderr: string } {
  const r = spawnSync('/bin/sh', ['-c', `${noTempFile ? NO_TEMP_FILE : ''}exec "$0"`, hook], {
    input: JSON.stringify(payload), env, cwd, encoding: 'utf-8', timeout: 60_000,
  });
  return { verdict: verdictOf(r.status, r.stdout ?? ''), stderr: r.stderr ?? '' };
}

interface Case {
  name: string;
  payload: (dir: string) => object;
  python3: boolean;
  env?: NodeJS.ProcessEnv;
  verdict: string;
}

const CASES: Case[] = [
  {
    name: 'a Read of a .env path is refused',
    payload: (dir) => ({ tool_name: 'Read', tool_input: { file_path: path.join(dir, 'absent', '.env') } }),
    python3: true,
    verdict: "deny: blocked access to secret file matching pattern '.env'",
  },
  {
    // README.md sorts before absent/.env, so the loop passes a benign
    // candidate before it reaches the secret one.
    name: 'a secret path nested after a benign top-level path is refused',
    payload: () => ({ tool_name: 'Edit', tool_input: { path: 'README.md', edits: [{ file_path: 'absent/.env' }] } }),
    python3: true,
    verdict: "deny: blocked access to secret file matching pattern '.env'",
  },
  {
    // keys/server.pem exists (see beforeAll), so a candidate expanded as a glob
    // would be refused for its extension. The tool opens the path as given.
    name: 'a candidate path holding * is judged as given, not expanded',
    payload: () => ({ tool_name: 'Read', tool_input: { file_path: 'keys/*' } }),
    python3: true,
    verdict: 'allow',
  },
  {
    // The candidates are sorted: A.md, B/.env, [1]=README.md. A split that
    // read [1]=README.md as an array element assignment would put README.md
    // in the place of B/.env, and no candidate would be refused.
    name: 'a candidate shaped like an array element assignment is judged as a path and leaves the others in place',
    payload: () => ({
      tool_name: 'Edit',
      tool_input: { file_path: 'A.md', edits: [{ file_path: 'B/.env' }, { path: '[1]=README.md' }] },
    }),
    python3: true,
    verdict: "deny: blocked access to secret file matching pattern '.env'",
  },
  {
    name: 'npm run env is refused by the command analyzer',
    payload: () => ({ tool_name: 'Bash', tool_input: { command: 'npm run env' } }),
    python3: true,
    verdict: 'deny: blocked a command that can print the environment, credentials included',
  },
  {
    name: 'sudo printenv is refused without python3',
    payload: () => ({ tool_name: 'Bash', tool_input: { command: 'sudo printenv' } }),
    python3: false,
    verdict: 'deny: blocked a command that may print the environment',
  },
  {
    name: 'a node one-liner naming process.env in an ssh argument is refused, whatever GUARD_ANALYZER the environment holds',
    payload: () => ({ tool_name: 'Bash', tool_input: { command: 'ssh host node -e "console.log(process.env)"' } }),
    python3: true,
    env: { GUARD_ANALYZER: 'import sys\nsys.stdout.write("PASS:")\n' },
    verdict: 'deny: blocked script command that reads environment variables',
  },
  {
    name: 'a grep for process.env in source is allowed',
    payload: () => ({ tool_name: 'Bash', tool_input: { command: 'grep -rn process.env src' } }),
    python3: true,
    verdict: 'allow',
  },
];

describe('guard verdicts when bash cannot write a temporary file', { timeout: 60_000 }, () => {
  let dir = '';
  let bin = '';
  let failingGrep = '';
  let hook = '';

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-no-temp-'));
    bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-no-temp-nopy-'));
    failingGrep = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-no-temp-grep-'));
    init(dir);
    hook = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
    // An empty file whose name the guard refuses, for the glob case.
    fs.mkdirSync(path.join(dir, 'keys'));
    fs.writeFileSync(path.join(dir, 'keys', 'server.pem'), '');
    // The programs the hook calls, and no python3.
    for (const tool of ['bash', 'cat', 'cut', 'grep', 'head', 'sed', 'sort', 'tr', 'basename', 'readlink']) {
      fs.symlinkSync(execSync(`command -v ${tool}`, { encoding: 'utf-8' }).trim(), path.join(bin, tool));
    }
    // A grep that fails with status 2 when called as text_matches calls it,
    // with -- before the pattern, and is the real grep otherwise.
    const realGrep = execSync('command -v grep', { encoding: 'utf-8' }).trim();
    fs.writeFileSync(
      path.join(failingGrep, 'grep'),
      `#!/bin/sh\nfor a in "$@"; do\n  if [ "$a" = -- ]; then exit 2; fi\ndone\nexec '${realGrep}' "$@"\n`,
      { mode: 0o755 },
    );
  });

  afterAll(() => {
    for (const d of [dir, bin, failingGrep]) if (d) fs.rmSync(d, { recursive: true, force: true });
  });

  it('the condition leaves bash unable to write the temporary file of a here-document', () => {
    const script = 'cat <<EOF\nwritten\nEOF\n';
    const run = (noTempFile: boolean) => spawnSync('/bin/sh', ['-c', `${noTempFile ? NO_TEMP_FILE : ''}exec /bin/bash -c "$0"`, script], {
      env: { PATH: process.env.PATH, BASH_COMPAT: '50' }, encoding: 'utf-8', timeout: 60_000,
    });
    expect(run(false).stdout).toBe('written\n');
    const limited = run(true);
    expect(limited.stdout).toBe('');
    expect(limited.stderr).toMatch(HERE_DOC_FAILURE);
  });

  it('python3 is not reachable on the PATH of the cases without it', () => {
    expect(
      () => execSync('command -v python3', { env: { PATH: bin }, shell: path.join(bin, 'bash'), stdio: 'ignore' }),
    ).toThrow();
  });

  for (const c of CASES) {
    (c.python3 && !hasPython3 ? it.skip : it)(`${c.name}, with or without a writable temporary file`, () => {
      const env: NodeJS.ProcessEnv = {
        PATH: c.python3 ? process.env.PATH : bin,
        HOME: dir,
        BASH_COMPAT: '50',
        HARNESS_NO_LIVE_TRANSPORT: '1',
        ...c.env,
      };
      const writable = runHook(hook, c.payload(dir), env, dir, false);
      const limited = runHook(hook, c.payload(dir), env, dir, true);
      expect(writable.verdict, 'with a writable temporary file').toBe(c.verdict);
      expect(limited.verdict, 'when no temporary file can be written').toBe(c.verdict);
      expect(limited.stderr, 'the hook feeds no command through a temporary file').not.toMatch(HERE_DOC_FAILURE);
    });
  }

  // A rule that could not be checked is a refusal: exit 2 blocks the call when
  // the hook is wired directly, and any non-zero exit fails a wrapper that runs
  // the hook.
  (hasPython3 ? it : it.skip)('a grep that cannot check a rule makes the hook exit 2', () => {
    const runs = [
      { command: 'ssh host node -e "console.log(process.env)"', PATH: `${failingGrep}:${process.env.PATH}` },
      { command: 'sudo printenv', PATH: `${failingGrep}:${bin}` },
    ];
    for (const r of runs) {
      const env: NodeJS.ProcessEnv = { PATH: r.PATH, HOME: dir, HARNESS_NO_LIVE_TRANSPORT: '1' };
      const run = runHook(hook, { tool_name: 'Bash', tool_input: { command: r.command } }, env, dir, false);
      expect(run.verdict, r.command).toBe('error: exit 2');
      expect(run.stderr, r.command).toMatch(/Secretless: blocked a call the guard could not check: grep exited 2\./);
    }
  });
});
