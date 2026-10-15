/**
 * Every `Fix:` line the `secret` commands print that gives a `secret` command
 * runs as printed. Each case in secret-push.test.ts pins one input; this file
 * runs the printed lines themselves, over a generated set of inputs to
 * `secret set`, `secret list --needs-rotation`, `secret show`, `secret sync`
 * and `secret push`, with the store, the sync source, the clipboard, stdin and
 * the push target held in memory.
 *
 * For each Fix line it:
 *   1. takes the command from the CLI name to the end of the line, or to two
 *      spaces, which set a command apart from the words around it;
 *   2. splits it into words as a POSIX shell would, without starting one; a
 *      character a shell reads as an operator, an expansion or a pattern fails
 *      the line, since the words the shell ran would not be the ones printed;
 *   3. fills each `<name>` placeholder with a name nothing else uses;
 *   4. runs the words as the CLI does: argv normalisation, the help check,
 *      then the entry point the input went through, with the same state.
 *
 * It fails a line that is refused for its usage, a name or a placeholder; a
 * `secret sync` or `secret push` Fix whose `--dry-run` differs from the
 * input's; a `secret set` or `secret sync --only` Fix that names a secret the
 * input and the stores never mention, or that `secret set` reads only part of;
 * and a `secret push` Fix that writes two secrets under one name.
 *
 * A Fix that gives no `secret` command (`copy something else to replace it.`,
 * an install hint, a target's `az login`) is counted and not run.
 */
import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PassThrough } from 'stream';
import { prepareArgv } from './argv';
import { AzureKeyVaultTarget } from './backends/azure-kv';
import { GCPSecretManagerBackend } from './backends/gcp-sm';
import type { BackendHealth, ResolveOptions, WritableSecretBackend } from './backends/types';
import { VaultBackend } from './backends/vault';
import { Clipboard } from './clipboard';
import type { ClipboardRunner } from './clipboard';
import { runSecret, runSecretPush, runSecretSync } from './commands/secrets';
import { CLI, CLI_BARE } from './commands/utils';
import { fixCommand, NAME_PLACEHOLDER, shellQuote } from './fix-command';
import type { FixNames } from './fix-command';
import type { TtyInput } from './hidden-line';
import { GcpPushTarget, VaultPushTarget } from './secret-push';
import type { PushTarget, PushTargetType } from './secret-push';
import { SecretStore } from './secret-store';

// --- In-memory state ----------------------------------------------------------

/** A store held in memory, keyed `secret/<name>` as every backend keys it. */
class MemoryBackend implements WritableSecretBackend {
  readonly entries = new Map<string, string>();

  constructor(readonly name: string, values: Readonly<Record<string, string>>) {
    for (const [name, value] of Object.entries(values)) this.entries.set(`secret/${name}`, value);
  }

  async resolve(key: string, options: ResolveOptions = {}): Promise<Record<string, string>> {
    const found: Record<string, string> = {};
    for (const [k, v] of this.entries) {
      if (k === key || (!options.exact && k.startsWith(`${key}/`))) found[k] = v;
    }
    return found;
  }

  async healthCheck(): Promise<BackendHealth> {
    return { healthy: true, latencyMs: 0 };
  }

  async store(key: string, value: string): Promise<void> {
    this.entries.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.entries.delete(key);
  }
}

/** The name rules of each real target. */
const RULES: Record<PushTargetType, (vaultName: string | undefined) => PushTarget> = {
  'azure-kv': (vaultName) => new AzureKeyVaultTarget(vaultName ?? 'kv-demo'),
  vault: () => new VaultPushTarget(new VaultBackend({ addr: 'https://vault.example.test', token: 'FAKE-vault-token' })),
  'gcp-sm': () => new GcpPushTarget(new GCPSecretManagerBackend({ projectId: 'demo-project' })),
};

interface MemoryTarget extends PushTarget {
  /** Each name written, folded as the target folds it, with every value written under it. */
  readonly written: Map<string, Set<string>>;
}

/** A target with a real target's name rules that writes into memory. */
function memoryTarget(type: PushTargetType, vaultName: string | undefined): MemoryTarget {
  const rules = RULES[type](vaultName);
  const written = new Map<string, Set<string>>();
  return {
    type: rules.type,
    label: rules.label,
    written,
    nameProblem: (remote) => rules.nameProblem(remote),
    suggestName: (local) => rules.suggestName(local),
    foldName: (remote) => rules.foldName(remote),
    prepare: async () => 'in memory',
    exists: async (remote) => written.has(rules.foldName(remote)),
    write: async (remote, value) => {
      const folded = rules.foldName(remote);
      const values = written.get(folded) ?? new Set<string>();
      values.add(value);
      written.set(folded, values);
      return { id: `memory/${remote}`, version: String(values.size) };
    },
    nextSteps: () => [],
  };
}

/** What the clipboard tool does when it is read. */
type ClipboardState = { text: string; clearFails?: boolean } | 'no-tool' | 'fails';

function memoryClipboard(state: ClipboardState): Clipboard {
  const run: ClipboardRunner = (_command, _args, capture) => {
    if (state === 'no-tool') return { status: null, stdout: '', errorCode: 'ENOENT' };
    if (state === 'fails') return { status: 1, stdout: '' };
    if (capture) return { status: 0, stdout: state.text };
    return { status: state.clearFails ? 1 : 0, stdout: '' };
  };
  return new Clipboard({ platform: 'darwin', env: {}, run });
}

/** The state a command runs against. */
interface World {
  /** This machine's store. */
  local: Readonly<Record<string, string>>;
  /** Names in `local` with an open exposure. */
  exposed?: readonly string[];
  /** The `secret sync` source. */
  source?: Readonly<Record<string, string>>;
  /** `.secretless` in the working directory; none when undefined. */
  manifest?: string;
  /** Whether stdin is a pipe or a file. */
  piped?: boolean;
  /** What stdin carries for `secret set NAME`. */
  stdin?: string;
  clipboard?: ClipboardState;
}

/**
 * The state a Fix runs against: the input's stores, at a terminal, with a key
 * on the clipboard and one typed at the prompt. A Fix that says to copy the
 * key again or to run without a pipe is run that way.
 */
function fixWorld(world: World): World {
  return { ...world, piped: false, stdin: 'FAKE-typed-again', clipboard: { text: 'FAKE-copied-again' } };
}

let tmp: string;
const cwds = new Map<string, string>();

/** A working directory holding `manifest` as `.secretless`, or none. */
function cwdFor(manifest: string | undefined): string {
  const key = manifest ?? '';
  let dir = cwds.get(key);
  if (dir === undefined) {
    dir = fs.mkdtempSync(path.join(tmp, 'cwd-'));
    if (manifest !== undefined) fs.writeFileSync(path.join(dir, '.secretless'), manifest);
    cwds.set(key, dir);
  }
  return dir;
}

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-fix-lines-'));
});

afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

// --- Running a command line as the CLI does ----------------------------------

interface Ran {
  code: number;
  lines: string[];
  /** Why the CLI ran no command at all, when it ran none. */
  notRun?: string;
  target?: MemoryTarget;
}

/**
 * `secretless-ai secret <argv>` as src/cli.ts runs it: argv normalised, help
 * printed instead for `-h` or `--help` anywhere, a flag error refused, then the
 * entry point for the subcommand with `world` in memory.
 */
async function cli(argv: readonly string[], world: World): Promise<Ran> {
  const prepared = prepareArgv('secret', ['secret', ...argv]);
  if (prepared.args.includes('--help') || prepared.args.includes('-h')) {
    return { code: 0, lines: [], notRun: 'the CLI reads "-h" or "--help" in it and prints help instead' };
  }
  if (prepared.errors.length > 0) return { code: 2, lines: [], notRun: `the CLI refuses its flags: ${prepared.errors[0]}` };
  const args = prepared.args.slice(1);

  const store = new SecretStore({ backend: new MemoryBackend('local', world.local) });
  for (const name of world.exposed ?? []) await store.recordExposure(name, 'pasted into a chat', new Date('2026-10-01T00:00:00Z'));

  const lines: string[] = [];
  const capture = (...a: unknown[]): void => { lines.push(...a.map(String).join(' ').split('\n')); };
  const spies = [
    vi.spyOn(console, 'log').mockImplementation(capture),
    vi.spyOn(console, 'error').mockImplementation(capture),
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => { capture(String(chunk)); return true; }),
  ];
  let target: MemoryTarget | undefined;
  try {
    let code: number;
    if (args[0] === 'push') {
      code = await runSecretPush(args.slice(1), {
        store,
        createTarget: (type, vaultName) => (target = memoryTarget(type, vaultName)),
      });
    } else if (args[0] === 'sync') {
      code = await runSecretSync(args.slice(1), {
        store,
        createSource: (type) => new MemoryBackend(type, world.source ?? {}),
        cwd: cwdFor(world.manifest),
      });
    } else {
      const stdin = new PassThrough();
      stdin.end(world.stdin ?? 'FAKE-typed-value');
      code = await runSecret(args, {
        json: args.includes('--json'),
        createStore: () => store,
        afterSet: () => {},
        stdin: stdin as unknown as TtyInput,
        stdinIsPiped: () => world.piped === true,
        clipboard: memoryClipboard(world.clipboard ?? { text: 'FAKE-copied-value' }),
      });
    }
    return { code, lines, target };
  } finally {
    for (const spy of spies) spy.mockRestore();
  }
}

// --- Reading a Fix line as a shell would -------------------------------------

/** Where the `secret` command on a line starts, after the CLI name, if it gives one. */
function commandStart(line: string): number | undefined {
  for (const prefix of [CLI, CLI_BARE]) {
    const at = line.indexOf(`${prefix} secret `);
    if (at !== -1) return at + prefix.length + 1;
  }
  return undefined;
}

type Words = { words: string[] } | { refused: string };

/**
 * The words a POSIX shell makes of `text`, read to its end or to two spaces.
 * No shell is started.
 */
function shellWords(text: string): Words {
  const words: string[] = [];
  let word: string | undefined;
  const add = (part: string): void => { word = (word ?? '') + part; };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === ' ' || c === '\t') {
      if (word !== undefined) words.push(word);
      word = undefined;
      if (text[i + 1] === ' ') break;
      continue;
    }
    if (c === "'") {
      const end = text.indexOf("'", i + 1);
      if (end === -1) return { refused: 'a single quote is not closed' };
      add(text.slice(i + 1, end));
      i = end;
      continue;
    }
    if (c === '"') {
      let part = '';
      let j = i + 1;
      for (; j < text.length && text[j] !== '"'; j++) {
        if (text[j] === '\\' && '$`"\\'.includes(text[j + 1] ?? '')) { part += text[++j]; continue; }
        if (text[j] === '$' || text[j] === '`') return { refused: `a shell expands "${text[j]}" inside double quotes` };
        part += text[j];
      }
      if (j >= text.length) return { refused: 'a double quote is not closed' };
      add(part);
      i = j;
      continue;
    }
    if (c === '\\') {
      if (i + 1 >= text.length) return { refused: 'the line ends in a backslash' };
      add(text[++i]);
      continue;
    }
    if ('|&;<>()'.includes(c)) return { refused: `a shell reads "${c}" as an operator` };
    if ('$`'.includes(c)) return { refused: `a shell expands "${c}"` };
    if ('*?[{}!'.includes(c)) return { refused: `a shell reads "${c}" as a pattern or a history reference` };
    if ((c === '#' || c === '~') && word === undefined) return { refused: `a shell reads "${c}" at the start of a word` };
    add(c);
  }
  if (word !== undefined) words.push(word);
  return { words };
}

/** A name for each `<...>` placeholder: one no store, input or target holds. */
function fillPlaceholders(words: readonly string[]): { words: string[]; filled: Set<string> } {
  const filled = new Set<string>();
  const out = words.map((word) => word.split(',').map((part) => {
    if (!/^<[^<>]*>$/.test(part)) return part;
    const name = `Filled${filled.size + 1}`;
    filled.add(name);
    return name;
  }).join(','));
  return { words: out, filled };
}

/** Each comma-separated part of a word, trimmed, as the commands read a name list. */
const listed = (word: string): string[] => word.split(',').map((n) => n.trim()).filter(Boolean);

/** Every name an input or its state mentions. */
function mentioned(argv: readonly string[], world: World): Set<string> {
  const names = new Set([...Object.keys(world.local), ...Object.keys(world.source ?? {})]);
  for (const line of (world.manifest ?? '').split('\n')) names.add(line.trim().split(/\s+/)[0]);
  for (const word of argv) {
    for (const part of listed(word)) names.add(part);
    if (word.includes('=')) names.add(word.slice(0, word.indexOf('=')));
  }
  return names;
}

/** The output of a refused run, which a Fix must not lead to. */
const REFUSAL = /Invalid secret name|is not a secret name|Usage:|placeholder|cannot name a secret|cannot be the first|needs a value|would both be pushed as|is taken by|takes no positional|is not read by|applies to/;

// --- The check ---------------------------------------------------------------

interface Case {
  argv: string[];
  world: World;
}

/** Distinct Fix lines run as commands, and those that give no `secret` command. */
const tally = { ran: new Set<string>(), prose: new Set<string>() };

/** Run `c`, then every Fix line it printed; return what each failed for. */
async function check(c: Case): Promise<{ fixes: number; failures: string[] }> {
  const ran = await cli(c.argv, c.world);
  const fixLines = ran.lines.filter((l) => l.startsWith('  Fix:'));
  const failures: string[] = [];
  for (const line of fixLines) {
    const start = commandStart(line);
    if (start === undefined) {
      tally.prose.add(line);
      continue;
    }
    const fail = (reason: string): void => {
      const state = [
        ...(c.world.piped ? ['stdin piped'] : []),
        ...(c.world.manifest !== undefined ? [`.secretless ${JSON.stringify(c.world.manifest)}`] : []),
      ];
      failures.push(`${JSON.stringify(c.argv)}${state.length > 0 ? ` (${state.join(', ')})` : ''}\n      ${line.trim()}\n      ${reason}`);
    };
    const split = shellWords(line.slice(start));
    if ('refused' in split) {
      fail(split.refused);
      continue;
    }
    tally.ran.add(line);
    const { words, filled } = fillPlaceholders(split.words.slice(1));
    const sub = words[0];
    const known = mentioned(c.argv, c.world);
    const unknown = (name: string): boolean => !filled.has(name) && !known.has(name);
    if (sub === 'set') {
      const operands = words.slice(1).filter((w) => !w.startsWith('--'));
      if (operands.length !== 1) fail(`\`secret set\` reads its first word as the name and drops the rest: ${JSON.stringify(operands)}`);
      else if (unknown(operands[0])) fail(`it stores "${operands[0]}", a name the input never gave`);
    }
    if (sub === 'sync') {
      const only = words.indexOf('--only');
      const named = only === -1 ? [] : listed(words[only + 1] ?? '');
      const stray = named.filter(unknown);
      if (stray.length > 0) fail(`it syncs ${JSON.stringify(stray)}, names the input never gave`);
    }
    if ((sub === 'sync' || sub === 'push') && sub === c.argv[0] && words.includes('--dry-run') !== c.argv.includes('--dry-run')) {
      fail(c.argv.includes('--dry-run') ? 'the input was a dry run, and this Fix writes' : 'the input was not a dry run, and this Fix is one');
    }
    const result = await cli(words, fixWorld(c.world));
    if (result.notRun !== undefined) {
      fail(result.notRun);
      continue;
    }
    const refusal = result.lines.find((l) => REFUSAL.test(l));
    if (result.code === 2 || refusal !== undefined) {
      fail(`run as printed, it is refused (exit ${result.code}): ${(refusal ?? result.lines.find((l) => l.trim() !== '') ?? '').trim()}`);
    }
    for (const [name, values] of result.target?.written ?? []) {
      if (values.size > 1) fail(`run as printed, it writes ${values.size} secrets under "${name}"`);
    }
  }
  return { fixes: fixLines.length, failures };
}

async function checkAll(cases: readonly Case[]): Promise<{ fixes: number; failures: string[] }> {
  let fixes = 0;
  const failures: string[] = [];
  for (const c of cases) {
    const result = await check(c);
    fixes += result.fixes;
    failures.push(...result.failures);
  }
  return { fixes, failures };
}

// --- Inputs -------------------------------------------------------------------

const value = (name: string): string => `FAKE-local-${name}`;
const stored = (...names: string[]): Record<string, string> => Object.fromEntries(names.map((n) => [n, value(n)]));

/**
 * Names given to `secret set`: one stored, one new, names the store holds and
 * `secret set` refuses, and names a shell or a terminal reads as more than a
 * word.
 */
const SET_NAMES = ['API_KEY', 'NEW_KEY', '9z', '-x', '_y', '', 'a b', 'x\ny', "it's", '<name>', '$HOME', '*', 'a;b'];
const SET_LOCAL = stored('API_KEY', 'DB_PASSWORD', '9z', '-x', '_y');

function setCases(): Case[] {
  const cases: Case[] = [];
  for (const name of SET_NAMES) {
    // NAME=VALUE together with --from-clipboard, and a piped stdin with it.
    cases.push({ argv: ['set', `${name}=FAKE-typed-value`, '--from-clipboard'], world: { local: SET_LOCAL } });
    cases.push({ argv: ['set', name, '--from-clipboard'], world: { local: SET_LOCAL, piped: true } });
    // A clipboard that is empty, cannot be read, has no tool, or is not cleared.
    for (const clipboard of [{ text: ' \n' }, 'fails', 'no-tool', { text: 'FAKE-copied-value', clearFails: true }] as ClipboardState[]) {
      cases.push({ argv: ['set', name, '--from-clipboard'], world: { local: SET_LOCAL, clipboard } });
    }
    cases.push({ argv: ['set', `${name}=FAKE-typed-value`], world: { local: SET_LOCAL } });
  }
  // The value already stored, given again for a name with an open exposure.
  const exposed = { local: SET_LOCAL, exposed: ['API_KEY'] };
  cases.push({ argv: ['set', `API_KEY=${value('API_KEY')}`], world: exposed });
  cases.push({ argv: ['set', 'API_KEY'], world: { ...exposed, stdin: value('API_KEY') } });
  cases.push({ argv: ['set', 'API_KEY', '--from-clipboard'], world: { ...exposed, clipboard: { text: value('API_KEY') } } });
  // Open exposures, listed.
  for (const extra of [[], ['--long'], ['--app', 'billing']]) {
    cases.push({ argv: ['list', '--needs-rotation', ...extra], world: { local: SET_LOCAL, exposed: ['API_KEY', '9z'] } });
  }
  for (const name of SET_NAMES) cases.push({ argv: ['show', name], world: { local: SET_LOCAL } });
  return cases;
}

/**
 * The source holds a value that differs from the local one (API_KEY, -x, 9z),
 * one that matches (DB_PASSWORD) and one not stored here (NEW_ONE). Neither
 * holds ABSENT, -q, 9q or _q.
 */
const SOURCE = {
  API_KEY: 'FAKE-source-API_KEY',
  DB_PASSWORD: value('DB_PASSWORD'),
  '-x': 'FAKE-source--x',
  '9z': 'FAKE-source-9z',
  NEW_ONE: 'FAKE-source-NEW_ONE',
};
const SYNC_LOCAL = stored('API_KEY', 'DB_PASSWORD', '-x', '9z', 'LOCAL_ONLY');
const ONLY = [
  'API_KEY', 'API_KEY,DB_PASSWORD', '-x', 'API_KEY,-x', '-x,API_KEY', 'DB_PASSWORD,-x', '9z', 'NEW_ONE',
  'ABSENT', 'ABSENT,-q,9q,_q', '-q,_q', 'API_KEY, ABSENT', 'LOCAL_ONLY',
];
const MANIFESTS = [undefined, 'API_KEY\nDB_PASSWORD\n', '-x\nABSENT\n', 'OPTIONAL_ONE optional\n'];

function syncCases(): Case[] {
  const cases: Case[] = [];
  const world = { local: SYNC_LOCAL, source: SOURCE };
  for (const from of ['vault', 'keychain']) {
    for (const only of ONLY) {
      for (const flags of [[], ['--dry-run'], ['--force'], ['--dry-run', '--force']]) {
        cases.push({ argv: ['sync', '--from', from, '--only', only, ...flags], world });
      }
    }
    for (const manifest of MANIFESTS) {
      for (const flags of [[], ['--dry-run']]) {
        cases.push({ argv: ['sync', '--from', from, ...flags], world: { ...world, manifest } });
        if (manifest !== undefined) cases.push({ argv: ['sync', '--from', from, '--manifest', '.secretless', ...flags], world: { ...world, manifest } });
      }
    }
  }
  return cases;
}

const LONG1 = 'L'.repeat(300);
const LONG2 = `${'L'.repeat(299)}M`;
const PUSH_LOCAL = stored('API_KEY', 'DB_PASSWORD', 'ab', 'AB', 'a_b', 'A-B', '9z', '_y', '-x', LONG1, LONG2);

/**
 * Names to push: one, two, a case clash Key Vault merges, a name whose Key
 * Vault spelling another holds, names `secret set` refuses (9z, _y, -x, -q,
 * 9q), names not stored, and two that Secret Manager cuts to one length.
 */
const PUSH_NAMES: string[][] = [
  ['API_KEY'],
  ['API_KEY', 'DB_PASSWORD'],
  ['ab', 'AB'],
  ['a_b', 'A-B'],
  ['9z'],
  ['_y'],
  ['API_KEY', '-x'],
  ['API_KEY', 'NOT_STORED'],
  ['API_KEY', '-q', '9q', 'NOT_STORED'],
  [LONG1, LONG2],
];

/**
 * `--as` values by count: placeholders, a bracketed name that is not one,
 * names each target refuses, whitespace, a line feed, shell characters, a
 * leading '-', case clashes, and a suggestion another name holds.
 */
const AS: Record<number, Array<string[] | undefined>> = {
  1: [undefined, ['<name>'], ['<names>'], ['<2fa>'], ['<>'], ['a.b'], ['a b'], ['9z'], ['_y'], ['x\ny'], ['API_KEY'], ['$HOME'], ["it's"], ['*'], ['-x']],
  2: [
    undefined, ['x', 'x'], ['ab', 'AB'], ['a_b', 'a.b'], ['a.b', 'a_b'], ['<name>', '<name>'], ['<names>', 'a.b'],
    ['a.b', '<2fa>'], ['x\ny', 'a.b'], ['x', '-y'], ['a b', 'a_b'], ['$HOME', 'x'], ['x', 'API_KEY'], ['_y', '-y'], ['a.b', 'A-B'],
  ],
  4: [undefined, ['a.b', 'a_b', 'A-B', 'x'], ['<name>', 'a.b', 'a_b', 'a_b'], ['x', 'X', 'x.y', 'x_y']],
};

function pushCases(): Case[] {
  const cases: Case[] = [];
  const world = { local: PUSH_LOCAL };
  for (const to of ['vault', 'gcp-sm', 'azure-kv']) {
    const target = to === 'azure-kv' ? ['--to', to, '--vault', 'kv-demo'] : ['--to', to];
    for (const names of PUSH_NAMES) {
      for (const spelling of [',', ', ']) {
        for (const as of AS[names.length]) {
          for (const dryRun of [false, true]) {
            cases.push({
              argv: ['push', names.join(spelling), ...target, ...(as ? ['--as', as.join(',')] : []), ...(dryRun ? ['--dry-run'] : [])],
              world,
            });
          }
        }
      }
    }
  }
  // A Key Vault given by its URL, and the flags in another order.
  cases.push({ argv: ['push', 'ab,AB', '--to', 'azure-kv', '--vault', 'https://kv-demo.vault.azure.net/'], world });
  cases.push({ argv: ['push', 'ab,AB', '--dry-run', '--as', 'a.b,A.B', '--vault=kv-demo', '--to=azure-kv'], world });
  return cases;
}

// --- Tests --------------------------------------------------------------------

describe('every Fix line the secret commands print runs as printed', () => {
  it('secret set, secret list --needs-rotation and secret show', async () => {
    const { fixes, failures } = await checkAll(setCases());
    expect(fixes).toBeGreaterThan(0);
    expect(failures).toEqual([]);
  }, 60_000);

  it('secret sync', async () => {
    const { fixes, failures } = await checkAll(syncCases());
    expect(fixes).toBeGreaterThan(0);
    expect(failures).toEqual([]);
  }, 60_000);

  it('secret push', async () => {
    const { fixes, failures } = await checkAll(pushCases());
    expect(fixes).toBeGreaterThan(0);
    expect(failures).toEqual([]);
  }, 120_000);

  it('ran Fix lines of each command, so a change that prints fewer is seen', () => {
    const commands = new Map<string, number>();
    for (const line of tally.ran) {
      const command = /^secret (\w+)/.exec(line.slice(commandStart(line)))?.[1] ?? '';
      commands.set(command, (commands.get(command) ?? 0) + 1);
    }
    // Measured when this file was written: set 14, sync 24, push 420 distinct
    // lines.
    expect(commands.get('set')).toBeGreaterThanOrEqual(10);
    expect(commands.get('sync')).toBeGreaterThanOrEqual(20);
    expect(commands.get('push')).toBeGreaterThanOrEqual(400);
    expect([...commands.keys()].sort()).toEqual(['push', 'set', 'sync']);
    // A line read as prose names no `secret` command, so none was skipped.
    expect([...tally.prose].filter((line) => /secret (set|sync|push)/.test(line))).toEqual([]);
  });
});

describe('fixCommand', () => {
  it('prints each word so a POSIX shell reads it back unchanged', () => {
    const words = ['secret', 'set', "it's", '', 'a b', 'a  b', '$HOME', '<name>', 'x\ny', '-x', '--from-clipboard', 'a=b', '=a', '~x', '#x', 'a*', '"q"', 'back\\slash'];
    const line = fixCommand(words, CLI_BARE);
    expect(line.startsWith(`${CLI_BARE} secret set `)).toBe(true);
    expect(shellWords(line.slice(CLI_BARE.length + 1))).toEqual({ words });
  });

  it('prints a name its command refuses as <name>, keeps a placeholder, and quotes each name of a list on its own', () => {
    const names: FixNames = { names: ['ok', '9z', '<names>', 'a.b'], accepts: (n) => /^[a-z]+$/.test(n) };
    expect(fixCommand(['secret', 'push', 'A', '--as', names])).toBe(`${CLI} secret push A --as ok,'${NAME_PLACEHOLDER}','<names>','${NAME_PLACEHOLDER}'`);
    expect(shellQuote('API_KEY')).toBe('API_KEY');
  });
});
