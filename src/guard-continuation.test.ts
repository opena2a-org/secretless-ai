import { describe, it, expect, afterAll } from 'vitest';
import { execFile, execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';

// bash removes a backslash-newline pair before it splits a command into words,
// so `cat \` on one line and a secret path on the next is the same read as the
// one-line form. The guard matched the command text with the pair still in it,
// and admitted the split form while it refused the one-line form. Each row runs
// through the generated hook with python3 on PATH and again without it.
//
// The rows are built from fragments, so this file names no secret file in a
// form a reader of the source would take for one.
const NL = '\n';
const BS = '\\';
const PEM = ['.', 'pem'].join('');
const KEY = ['.', 'key'].join('');
const ENV = ['.', 'env'].join('');

const mustDeny: Array<[string, string]> = [
  ['cat split before an id_rsa PEM path', `cat ${BS}${NL}/tmp/x/id_rsa${PEM}`],
  ['head -c split before a server key path', `head -c 100 ${BS}${NL}/tmp/x/server${KEY}`],
  ['cat split before the env file', `cat ${BS}${NL}${ENV}`],
  ['the env file name split in two', `cat .e${BS}${NL}nv`],
  ['the verb split in two (corpus row)', `ca${BS}${NL}t ${ENV}`],
  // A backslash at the end of a comment does not continue it, so bash runs the
  // read on the next line. Joined, the read would sit inside the comment; the
  // command as written is judged too, and refuses it.
  ['a read after a comment that ends in a backslash', `# note ${BS}${NL}cat ${ENV}`],
];

const mustAllow: Array<[string, string]> = [
  ['echo split across lines', `echo one ${BS}${NL}two`],
  ['the ruled CA-bundle git config step', `git config --global http.sslCAInfo /opt/homebrew/etc/ca-certificates/cert${PEM}`],
];

// Removing a pair can leave a new one: of two backslashes before two line
// breaks, the inner pair goes first and leaves the outer one. The hook removes
// pairs until none is left, then runs itself once on that text, and that run
// does not join again. It used to remove one layer per run and run itself
// again for the next, so the command set how many times the hook ran.
const DEPTH = 16;
const nested: Array<['deny' | 'allow', string, string]> = [
  ['deny', 'the verb split by nested pairs', `ca${BS.repeat(DEPTH)}${NL.repeat(DEPTH)}t ${ENV}`],
  ['allow', 'echo split by nested pairs', `echo ${BS.repeat(DEPTH)}${NL.repeat(DEPTH)}x`],
];

function bashPath(): string {
  return execSync('command -v bash', { encoding: 'utf-8' }).trim();
}

const hasPython3 = (() => {
  try { execSync('command -v python3', { stdio: 'ignore' }); return true; } catch { return false; }
})();

function decide(hookPath: string, command: string, env: NodeJS.ProcessEnv, cwd: string, args: string[] = []): Promise<string> {
  return new Promise((resolve) => {
    const child = execFile(bashPath(), [hookPath, ...args], { env, cwd, encoding: 'utf-8', maxBuffer: 1 << 20 },
      (error, stdout) => {
        if (error) return resolve(`error: exit ${String((error as { code?: unknown }).code)}`);
        if (!stdout.trim()) return resolve('allow');
        try {
          const hso = JSON.parse(stdout).hookSpecificOutput;
          if (hso.permissionDecision === 'deny') return resolve('deny');
        } catch { /* reported below */ }
        resolve('error: output is not a deny decision');
      });
    child.stdin!.end(JSON.stringify({ tool_name: 'Bash', tool_input: { command } }));
  });
}

// The decision and the number of times bash ran the hook. bash reads the file
// BASH_ENV names before it runs a script, so each run of the hook, the first
// one and every run on joined text, adds a line to the log.
async function decideCountingRuns(
  hookPath: string, command: string, env: NodeJS.ProcessEnv, cwd: string, args: string[] = [],
): Promise<[string, number]> {
  const log = path.join(cwd, 'runs.log');
  const counter = path.join(cwd, 'count-run.sh');
  fs.writeFileSync(counter, `printf 'run\\n' >> "$GUARD_RUN_LOG"\n`);
  fs.writeFileSync(log, '');
  const decision = await decide(hookPath, command, { ...env, BASH_ENV: counter, GUARD_RUN_LOG: log }, cwd, args);
  return [decision, fs.readFileSync(log, 'utf-8').split('\n').filter(Boolean).length];
}

(hasPython3 ? describe : describe.skip)('guard hook joins backslash-newline continuations', () => {
  let dir = '';
  let bin = '';
  let hookPath = '';

  const legs: Array<[string, () => NodeJS.ProcessEnv]> = [
    ['with python3', () => ({ PATH: process.env.PATH, HOME: dir })],
    ['without python3', () => ({ PATH: bin, HOME: dir })],
  ];

  const setup = (): void => {
    if (hookPath) return;
    dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-continuation-')));
    bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-continuation-nopy-'));
    init(dir);
    hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
    for (const tool of ['bash', 'cat', 'cut', 'grep', 'head', 'sed', 'sort', 'tr', 'basename', 'readlink']) {
      fs.symlinkSync(execSync(`command -v ${tool}`, { encoding: 'utf-8' }).trim(), path.join(bin, tool));
    }
    expect(
      () => execSync('command -v python3', { env: { PATH: bin }, shell: path.join(bin, 'bash'), stdio: 'ignore' }),
      'python3 must not be reachable on the PATH of the run without it',
    ).toThrow();
  };

  for (const [legName, envOf] of legs) {
    for (const [name, command] of mustDeny) {
      it(`denies ${name}, ${legName}`, { timeout: 60_000 }, async () => {
        setup();
        expect(await decide(hookPath, command, envOf(), dir)).toBe('deny');
      });
    }
    for (const [name, command] of mustAllow) {
      it(`allows ${name}, ${legName}`, { timeout: 60_000 }, async () => {
        setup();
        expect(await decide(hookPath, command, envOf(), dir)).toBe('allow');
      });
    }
    for (const [verdict, name, command] of nested) {
      it(`${verdict === 'deny' ? 'denies' : 'allows'} ${name} and runs itself once, ${legName}`, { timeout: 60_000 }, async () => {
        setup();
        const [decision, runs] = await decideCountingRuns(hookPath, command, envOf(), dir);
        expect(decision).toBe(verdict);
        expect(runs, 'one run on the command and one on its joined text').toBe(2);
      });
    }
    it(`does not run itself when given --joined-run, ${legName}`, { timeout: 60_000 }, async () => {
      setup();
      const [decision, runs] = await decideCountingRuns(hookPath, `echo one ${BS}${NL}two`, envOf(), dir, ['--joined-run']);
      expect(decision).toBe('allow');
      expect(runs, 'the run on joined text does not join again').toBe(1);
    });
  }

  afterAll(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    if (bin) fs.rmSync(bin, { recursive: true, force: true });
  });
});
