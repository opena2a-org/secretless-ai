import { describe, it, expect } from 'vitest';
import { execFile, execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';

// The guard hook is a few thousand lines of generated bash and python, and a
// change to one rule can refuse or allow commands far from the one it was
// written for. A reviewer could only see that by running the old and the new
// hook by hand. This test runs the generated hook over every command in
// fixtures/guard-corpus.txt, once with python3 on PATH and once without, and
// compares the verdict of each with fixtures/guard-verdicts.txt. A verdict is
// allow, or deny with the first clause of the deny reason, which names the
// rule that refused. Any difference fails the test and names the commands.
//
// A change meant to alter what the guard refuses records the new verdicts:
//
//   SECRETLESS_UPDATE_GUARD_SNAPSHOT=1 npx vitest run src/guard-verdict-snapshot.test.ts
//
// and commits fixtures/guard-verdicts.txt with it, so the diff of that file
// lists every command whose verdict the change moved.
const CORPUS = path.join(__dirname, 'fixtures', 'guard-corpus.txt');
const SNAPSHOT = path.join(__dirname, 'fixtures', 'guard-verdicts.txt');
const UPDATE = process.env.SECRETLESS_UPDATE_GUARD_SNAPSHOT === '1';
const SEP = ' | ';

const hasPython3 = (() => {
  try { execSync('command -v python3', { stdio: 'ignore' }); return true; } catch { return false; }
})();

interface Entry { line: string; command: string }

function readCorpus(): Entry[] {
  const entries: Entry[] = [];
  for (const line of fs.readFileSync(CORPUS, 'utf-8').split('\n')) {
    if (line === '' || line.startsWith('#')) continue;
    entries.push({ line, command: line.startsWith('json:') ? JSON.parse(line.slice(5)) : line });
  }
  return entries;
}

// verdict with python3, verdict without, by corpus line.
function readSnapshot(): Map<string, [string, string]> {
  const verdicts = new Map<string, [string, string]>();
  if (!fs.existsSync(SNAPSHOT)) return verdicts;
  for (const line of fs.readFileSync(SNAPSHOT, 'utf-8').split('\n')) {
    if (line === '' || line.startsWith('#')) continue;
    const a = line.indexOf(SEP);
    const b = line.indexOf(SEP, a + SEP.length);
    verdicts.set(line.slice(b + SEP.length), [line.slice(0, a), line.slice(a + SEP.length, b)]);
  }
  return verdicts;
}

// The rule a deny reason names: the text after "Secretless: " up to the end of
// its first clause, without the matched command or the safe path.
function reasonClass(reason: string): string {
  const text = reason.replace(/^Secretless: /, '');
  const end = text.search(/[.:](\s|$)/);
  return end === -1 ? text : text.slice(0, end);
}

function verdictOf(error: (Error & { code?: unknown }) | null, stdout: string): string {
  if (error) return `error: exit ${String(error.code)}`;
  if (!stdout.trim()) return 'allow';
  try {
    const hso = JSON.parse(stdout).hookSpecificOutput;
    if (hso.permissionDecision === 'deny') return `deny: ${reasonClass(String(hso.permissionDecisionReason))}`;
  } catch { /* reported below */ }
  return 'error: output is not a deny decision';
}

function decide(hookPath: string, command: string, env: NodeJS.ProcessEnv, cwd: string): Promise<string> {
  return new Promise((resolve) => {
    const child = execFile(bashPath(), [hookPath], { env, cwd, encoding: 'utf-8', maxBuffer: 1 << 20 },
      (error, stdout) => resolve(verdictOf(error, stdout)));
    child.stdin!.end(JSON.stringify({ tool_name: 'Bash', tool_input: { command } }));
  });
}

async function decideAll(hookPath: string, commands: string[], env: NodeJS.ProcessEnv, cwd: string): Promise<string[]> {
  const verdicts: string[] = new Array(commands.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < commands.length) {
      const i = next++;
      verdicts[i] = await decide(hookPath, commands[i], env, cwd);
    }
  };
  await Promise.all(Array.from({ length: Math.max(2, os.availableParallelism()) }, worker));
  return verdicts;
}

describe('guard hook verdicts over the command corpus', () => {
  (hasPython3 ? it : it.skip)('match the recorded snapshot, with and without python3', { timeout: 300_000 }, async () => {
    const corpus = readCorpus();
    const lines = corpus.map((e) => e.line);
    expect(new Set(lines).size, 'a command is listed twice in the corpus').toBe(lines.length);
    expect(corpus.length).toBeGreaterThanOrEqual(600);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-snapshot-'));
    const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-snapshot-nopy-'));
    try {
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
      // env-link in the corpus names this link, a path with no secret word in
      // it that reaches .env.
      fs.writeFileSync(path.join(dir, '.env'), 'EXAMPLE=placeholder\n');
      fs.symlinkSync('.env', path.join(dir, 'env-link'));
      // The programs the hook calls, and no python3.
      for (const tool of ['bash', 'cat', 'cut', 'grep', 'head', 'sed', 'sort', 'tr', 'basename', 'readlink']) {
        fs.symlinkSync(execSync(`command -v ${tool}`, { encoding: 'utf-8' }).trim(), path.join(bin, tool));
      }
      expect(
        () => execSync('command -v python3', { env: { PATH: bin }, shell: path.join(bin, 'bash'), stdio: 'ignore' }),
        'python3 must not be reachable on the PATH of the run without it',
      ).toThrow();

      const commands = corpus.map((e) => e.command);
      const withPython = await decideAll(hookPath, commands, { PATH: process.env.PATH, HOME: dir }, dir);
      const withoutPython = await decideAll(hookPath, commands, { PATH: bin, HOME: dir }, dir);

      if (UPDATE) {
        fs.writeFileSync(SNAPSHOT, [
          '# Verdicts of the guard hook over fixtures/guard-corpus.txt, written by',
          '# src/guard-verdict-snapshot.test.ts: with python3 | without python3 | command.',
          ...corpus.map((e, i) => [withPython[i], withoutPython[i], e.line].join(SEP)),
        ].join('\n') + '\n');
        return;
      }

      const recorded = readSnapshot();
      const changes: string[] = [];
      corpus.forEach((e, i) => {
        const now = [withPython[i], withoutPython[i]];
        const was = recorded.get(e.line);
        if (!was) {
          changes.push(`new command ${e.line}\n  now: ${now.join(SEP)}`);
        } else if (was[0] !== now[0] || was[1] !== now[1]) {
          changes.push(`${e.line}\n  was: ${was.join(SEP)}\n  now: ${now.join(SEP)}`);
        }
        recorded.delete(e.line);
      });
      for (const line of recorded.keys()) changes.push(`no longer in the corpus ${line}`);
      expect(
        changes.join('\n'),
        `${changes.length} command(s) differ from fixtures/guard-verdicts.txt (with python3 | without python3). ` +
          'If the change is meant, record it with SECRETLESS_UPDATE_GUARD_SNAPSHOT=1 and commit the snapshot.',
      ).toBe('');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(bin, { recursive: true, force: true });
    }
  });
});

function bashPath(): string {
  return execSync('command -v bash', { encoding: 'utf-8' }).trim();
}
