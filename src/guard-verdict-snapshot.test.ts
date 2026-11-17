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
// A second leg runs the same corpus through the hook init writes under the
// custom rules in fixtures/guard-custom-rules.yaml, and compares with
// fixtures/guard-verdicts-custom-rules.txt. Custom rules change what the hook
// generator emits, so a verdict can move under them while every verdict of
// the default hook stays put.
//
// A change meant to alter what the guard refuses records the new verdicts of
// both legs:
//
//   SECRETLESS_UPDATE_GUARD_SNAPSHOT=1 npx vitest run src/guard-verdict-snapshot.test.ts
//
// and commits fixtures/guard-verdicts.txt and
// fixtures/guard-verdicts-custom-rules.txt with it, so the diff of those files
// lists every command whose verdict the change moved.
const CORPUS = path.join(__dirname, 'fixtures', 'guard-corpus.txt');
const SNAPSHOT = path.join(__dirname, 'fixtures', 'guard-verdicts.txt');
const CUSTOM_RULES = path.join(__dirname, 'fixtures', 'guard-custom-rules.yaml');
const CUSTOM_RULES_SNAPSHOT = path.join(__dirname, 'fixtures', 'guard-verdicts-custom-rules.txt');
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
function readSnapshot(file: string): Map<string, [string, string]> {
  const verdicts = new Map<string, [string, string]>();
  if (!fs.existsSync(file)) return verdicts;
  for (const line of fs.readFileSync(file, 'utf-8').split('\n')) {
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

interface Leg {
  // Written as the project's .secretless-rules.yaml before init, when given.
  rules?: string;
  snapshot: string;
  header: string[];
}

const DEFAULT_LEG: Leg = {
  snapshot: SNAPSHOT,
  header: [
    '# Verdicts of the guard hook over fixtures/guard-corpus.txt, written by',
    '# src/guard-verdict-snapshot.test.ts: with python3 | without python3 | command.',
  ],
};

const CUSTOM_RULES_LEG: Leg = {
  rules: fs.readFileSync(CUSTOM_RULES, 'utf-8'),
  snapshot: CUSTOM_RULES_SNAPSHOT,
  header: [
    '# Verdicts of the guard hook init writes under fixtures/guard-custom-rules.yaml',
    '# over fixtures/guard-corpus.txt, written by src/guard-verdict-snapshot.test.ts:',
    '# with python3 | without python3 | command.',
  ],
};

// A new project init has run in, with `rules` as its .secretless-rules.yaml
// when given, and the path of the guard hook init wrote there. The caller
// removes the project.
function initProject(prefix: string, rules?: string): { dir: string; hookPath: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    if (rules !== undefined) fs.writeFileSync(path.join(dir, '.secretless-rules.yaml'), rules);
    const result = init(dir);
    expect(result.rulesFileProblem, 'the rules file must load in full').toBeUndefined();
  } catch (err) {
    fs.rmSync(dir, { recursive: true, force: true });
    throw err;
  }
  return { dir, hookPath: path.join(dir, '.claude', 'hooks', 'secretless-guard.sh') };
}

function hookBytes(rules?: string): Buffer {
  const { dir, hookPath } = initProject('secretless-guard-snapshot-hook-', rules);
  try {
    return fs.readFileSync(hookPath);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe('guard hook verdicts over the command corpus', () => {
  (hasPython3 ? it : it.skip)('match the recorded snapshot, with and without python3', { timeout: 300_000 }, async () => {
    await checkLeg(DEFAULT_LEG);
  });

  (hasPython3 ? it : it.skip)(
    'under the custom rules in fixtures/guard-custom-rules.yaml, match their recorded snapshot, with and without python3',
    { timeout: 300_000 },
    async () => {
      // Without this the leg could pass by judging the default hook a second time.
      expect(
        hookBytes(CUSTOM_RULES_LEG.rules).equals(hookBytes()),
        'the custom rules must change the hook init writes',
      ).toBe(false);
      await checkLeg(CUSTOM_RULES_LEG);
    },
  );
});

async function checkLeg(leg: Leg): Promise<void> {
  const corpus = readCorpus();
  const lines = corpus.map((e) => e.line);
  expect(new Set(lines).size, 'a command is listed twice in the corpus').toBe(lines.length);
  expect(corpus.length).toBeGreaterThanOrEqual(600);

  const { dir, hookPath } = initProject('secretless-guard-snapshot-', leg.rules);
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-snapshot-nopy-'));
  try {
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
      fs.writeFileSync(leg.snapshot, [
        ...leg.header,
        ...corpus.map((e, i) => [withPython[i], withoutPython[i], e.line].join(SEP)),
      ].join('\n') + '\n');
      return;
    }

    const recorded = readSnapshot(leg.snapshot);
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
      `${changes.length} command(s) differ from fixtures/${path.basename(leg.snapshot)} (with python3 | without python3). ` +
        'If the change is meant, record it with SECRETLESS_UPDATE_GUARD_SNAPSHOT=1 and commit the snapshot.',
    ).toBe('');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(bin, { recursive: true, force: true });
  }
}

function bashPath(): string {
  return execSync('command -v bash', { encoding: 'utf-8' }).trim();
}
