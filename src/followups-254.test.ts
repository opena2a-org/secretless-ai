import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { printCommandHelp } from './command-help';
import { runSecret } from './commands/secrets';

/**
 * #254: `secret set`, `secret show`, `secret get` and `secret rm` given no
 * NAME printed their usage line and exited 1, where `secret exposed`,
 * `secret sync` and `secret push` exit 2 for a usage error. A missing NAME
 * now exits 2 in each of the four, and `secret --help` names the code.
 *
 * The in-process cases give `runSecret` a store factory that throws, and
 * assert it was never called, so each refusal comes before the store is
 * opened and no case reaches the OS keychain. The cases that spawn the build
 * run in a fresh home with telemetry off.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;

/** The lines `secret --help` gives the exit code of a usage error. */
const USAGE_ERROR_NOTE = [
  '    A missing NAME, an unknown subcommand and an unknown option are usage',
  '    errors: each exits 2.',
];

describe('secret: a missing NAME is a usage error and exits 2 (#254)', () => {
  let out: string[];
  const createStore = vi.fn(() => {
    throw new Error('the store was opened');
  });

  beforeEach(() => {
    out = [];
    createStore.mockClear();
    const capture = (...a: unknown[]): void => { out.push(a.map(String).join(' ')); };
    vi.spyOn(console, 'log').mockImplementation(capture);
    vi.spyOn(console, 'error').mockImplementation(capture);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // [command line after `secret`, the usage line it prints]
  const cases: Array<[string[], RegExp]> = [
    [['set'], /Usage: .*secret set <NAME\[=VALUE\]>/],
    [['set', '--from-clipboard'], /Usage: .*secret set <NAME\[=VALUE\]>/],
    [['show'], /Usage: .*secret show <NAME>/],
    [['show', '--json'], /Usage: .*secret show <NAME>/],
    [['get'], /Usage: .*secret get <NAME>/],
    [['get', '--force'], /Usage: .*secret get <NAME>/],
    [['rm'], /Usage: .*secret rm <NAME>/],
    [['remove'], /Usage: .*secret rm <NAME>/],
    [['delete'], /Usage: .*secret rm <NAME>/],
  ];

  for (const [args, usage] of cases) {
    it(`\`secret ${args.join(' ')}\` prints its usage line and exits 2 before the store is opened`, async () => {
      expect(await runSecret(args, { createStore, env: {} })).toBe(2);
      expect(out.join('\n')).toMatch(usage);
      expect(createStore).not.toHaveBeenCalled();
    });
  }

  it('CONTROL: `secret exposed` and `secret push` given no NAME exit 2, as before', async () => {
    expect(await runSecret(['exposed'], { createStore })).toBe(2);
    expect(await runSecret(['exposed', '--where', 'pasted into a chat'], { createStore })).toBe(2);
    expect(await runSecret(['push'], { createStore })).toBe(2);
    expect(out.join('\n')).toContain('Name the secrets to push.');
    expect(createStore).not.toHaveBeenCalled();
  });
});

describe('`secret --help` names the exit code of a usage error (#254)', () => {
  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-254-home-'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(home, { recursive: true, force: true });
  });

  /** A fresh home, telemetry off, colour off, and the embedding prefix unset. */
  function cli(args: string[]) {
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' };
    delete env.SECRETLESS_CLI_PREFIX;
    const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: home,
      env,
    });
    return { status: res.status, stdout: res.stdout, stderr: res.stderr };
  }

  it('the help prints the note', () => {
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(...a.map(String).join(' ').split('\n')); });
    printCommandHelp('secret');
    const at = lines.indexOf(USAGE_ERROR_NOTE[0]);
    expect(at, lines.join('\n')).toBeGreaterThan(-1);
    expect(lines.slice(at, at + USAGE_ERROR_NOTE.length)).toEqual(USAGE_ERROR_NOTE);
  });

  itIfBuilt('each case the note names exits 2 from the build, in each subcommand its usage lines list', () => {
    const help = cli(['secret', '--help']);
    expect(help.status).toBe(0);
    expect(help.stdout).toContain(USAGE_ERROR_NOTE.join('\n'));

    // The subcommands the lines under `Usage:` name, and those that take a NAME.
    const lines = help.stdout.split('\n');
    const from = lines.indexOf('  Usage:') + 1;
    const usage = lines.slice(from, lines.indexOf('', from))
      .map((l) => / secret ([a-z]+)(.*)$/.exec(l))
      .filter((m): m is RegExpExecArray => m !== null);
    const subcommands = [...new Set(usage.map((m) => m[1]))];
    const takeName = [...new Set(usage.filter((m) => m[2].includes('<NAME')).map((m) => m[1]))];
    expect(subcommands).toEqual(['set', 'list', 'show', 'exposed', 'get', 'rm', 'sync', 'push']);
    expect(takeName).toEqual(['set', 'show', 'exposed', 'get', 'rm', 'push']);

    const exits: string[] = [];
    const record = (args: string[]): void => { exits.push(`${args.join(' ')} -> ${cli(args).status}`); };
    for (const sub of takeName) record(['secret', sub]);
    record(['secret', 'no-such-subcommand']);
    for (const sub of subcommands) record(['secret', sub, '--no-such-option']);

    expect(exits).toEqual([
      ...takeName.map((sub) => `secret ${sub} -> 2`),
      'secret no-such-subcommand -> 2',
      ...subcommands.map((sub) => `secret ${sub} --no-such-option -> 2`),
    ]);
  }, 60_000);
});
