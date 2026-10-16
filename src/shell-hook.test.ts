// The shell hook `secret set` installs runs `secretless-ai env` in every new
// shell. It called the bare `secretless-ai`, which a copy run through npx
// never puts on PATH, so new terminals exported nothing unless the CLI was
// installed globally (#333). These tests source the profile in a real shell
// whose PATH has neither `secretless-ai` nor `node`.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { PassThrough } from 'stream';
import { installShellHook, getShellHookLine, hookLineRuns, shellHookCommand, SHELL_HOOK_MARKER } from './env';
import { askOnTerminal, ensureShellHook, runSecret } from './commands/secrets';
import type { SecretStore } from './secret-store';

const BARE_HOOK_LINE = 'eval "$(secretless-ai env 2>/dev/null)"';
const SHELL_PATH = '/usr/bin:/bin';
const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');

let dir: string;
let home: string;
let script: string;
let emptyPath: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-hook-'));
  home = path.join(dir, 'home');
  emptyPath = path.join(dir, 'empty-bin');
  fs.mkdirSync(home);
  fs.mkdirSync(emptyPath);
  // Stands in for dist/cli.js: `env` prints what the real command prints.
  script = path.join(dir, 'pkg', 'cli.js');
  fs.mkdirSync(path.dirname(script));
  fs.writeFileSync(script, "if (process.argv[2] === 'env') console.log(\"export DEMO_KEY='demo-value'\");\n");
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

/** DEMO_KEY as a new bash shell sees it after reading ~/.bashrc. */
function demoKeyInNewShell(): string {
  const res = spawnSync('/bin/bash', ['-c', '. "$HOME/.bashrc"; printf %s "${DEMO_KEY:-unset}"'], {
    env: { HOME: home, PATH: SHELL_PATH },
    encoding: 'utf-8',
  });
  return res.stdout;
}

function install(options: { pathEnv?: string; command?: string[] } = {}) {
  return installShellHook({
    home,
    shell: '/bin/bash',
    platform: 'linux',
    command: options.command ?? [process.execPath, script],
    pathEnv: options.pathEnv ?? emptyPath,
  });
}

describe('installShellHook (#333)', () => {
  it('a new shell receives the stored secret without secretless-ai or node on PATH', () => {
    const change = install();
    expect(change).toMatchObject({ action: 'installed', cliOnPath: false });
    expect(change?.profilePath).toBe(path.join(home, '.bashrc'));
    expect(fs.readFileSync(path.join(home, '.bashrc'), 'utf-8'))
      .toBe(`\n${SHELL_HOOK_MARKER}\n${getShellHookLine([process.execPath, script])}\n`);
    expect(demoKeyInNewShell()).toBe('demo-value');
  });

  it('writes ~/.zshenv on macOS', () => {
    const change = installShellHook({ home, shell: '/bin/bash', platform: 'darwin', command: [process.execPath, script], pathEnv: emptyPath });
    expect(change?.profilePath).toBe(path.join(home, '.zshenv'));
  });

  it('replaces the bare hook line it wrote earlier when secretless-ai is not on PATH', () => {
    const profile = path.join(home, '.bashrc');
    fs.writeFileSync(profile, `alias ll='ls -l'\n\n${SHELL_HOOK_MARKER}\n${BARE_HOOK_LINE}\nexport EDITOR=vi\n`);
    expect(demoKeyInNewShell()).toBe('unset');

    expect(install()).toMatchObject({ action: 'repaired' });
    expect(fs.readFileSync(profile, 'utf-8')).toBe(
      `alias ll='ls -l'\n\n${SHELL_HOOK_MARKER}\n${getShellHookLine([process.execPath, script])}\nexport EDITOR=vi\n`,
    );
    expect(demoKeyInNewShell()).toBe('demo-value');
    expect(install()).toBeNull();
  });

  it('keeps the bare hook line when secretless-ai is on PATH', () => {
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'secretless-ai'), '#!/bin/sh\n', { mode: 0o755 });
    const before = `\n${SHELL_HOOK_MARKER}\n${BARE_HOOK_LINE}\n`;
    fs.writeFileSync(path.join(home, '.bashrc'), before);
    expect(install({ pathEnv: bin })).toBeNull();
    expect(fs.readFileSync(path.join(home, '.bashrc'), 'utf-8')).toBe(before);
  });

  it('replaces a hook line whose CLI copy was removed, and keeps one whose copy is there', () => {
    const gone = path.join(dir, 'npx-cache', 'cli.js');
    const profile = path.join(home, '.bashrc');
    fs.writeFileSync(profile, `\n${SHELL_HOOK_MARKER}\n${getShellHookLine([process.execPath, gone])}\n`);
    expect(install()).toMatchObject({ action: 'repaired' });
    expect(demoKeyInNewShell()).toBe('demo-value');

    const other = path.join(dir, 'pkg', 'other-cli.js');
    fs.copyFileSync(script, other);
    expect(install({ command: [process.execPath, other] })).toBeNull();
    expect(fs.readFileSync(profile, 'utf-8')).toContain(getShellHookLine([process.execPath, script]));
  });

  it('leaves a line the user wrote alone', () => {
    const before = 'eval "$(secretless-ai env)"\n';
    fs.writeFileSync(path.join(home, '.bashrc'), before);
    expect(install()).toBeNull();
    expect(fs.readFileSync(path.join(home, '.bashrc'), 'utf-8')).toBe(before);
  });
});

describe('hookLineRuns', () => {
  it('reads a quoted path that contains a single quote', () => {
    const quoted = path.join(dir, "it's");
    fs.mkdirSync(quoted);
    const cli = path.join(quoted, 'cli.js');
    fs.writeFileSync(cli, '');
    expect(hookLineRuns(getShellHookLine([process.execPath, cli]), emptyPath)).toBe(true);
    expect(hookLineRuns(getShellHookLine([process.execPath, `${cli}.missing`]), emptyPath)).toBe(false);
  });
});

describe('shellHookCommand', () => {
  it('prefers a node on PATH that is the same binary over the resolved one', () => {
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    fs.symlinkSync(process.execPath, path.join(bin, 'node'));
    expect(shellHookCommand(process.execPath, bin, script)).toEqual([path.join(bin, 'node'), script]);
    expect(shellHookCommand(process.execPath, emptyPath, script)).toEqual([process.execPath, script]);
  });

  it('points at the CLI script of this package', () => {
    const [, cli] = shellHookCommand();
    expect(path.isAbsolute(cli)).toBe(true);
    expect(path.basename(cli)).toBe('cli.js');
  });
});

describe('ensureShellHook', () => {
  it('says the hook runs this copy by its path when secretless-ai is not on PATH', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      await ensureShellHook({ home, shell: '/bin/bash', platform: 'linux', command: [process.execPath, script], pathEnv: emptyPath, ask: async () => true });
      const out = log.mock.calls.map((c) => String(c[0])).join('\n');
      expect(out).toContain('Shell hook installed in ~/.bashrc');
      expect(out).toContain('secretless-ai is not on PATH, so the hook runs this copy by its full path:');
      expect(out).toContain(script);
      expect(out).toContain('npm install -g secretless-ai');
    } finally {
      log.mockRestore();
    }
  });
});

// `secret set` appended the hook to the profile with no question and no way
// to decline, and the hook exports every stored secret into every new shell
// (#412).
describe('ensureShellHook asks before it edits the profile (#412)', () => {
  const profile = (): string => path.join(home, '.bashrc');

  async function offer(options: { noShellHook?: boolean; answer?: boolean | null } = {}) {
    const questions: string[] = [];
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      await ensureShellHook({
        home,
        shell: '/bin/bash',
        platform: 'linux',
        command: [process.execPath, script],
        pathEnv: emptyPath,
        name: 'DEMO_KEY',
        noShellHook: options.noShellHook,
        ask: async (question) => {
          questions.push(question);
          return options.answer ?? null;
        },
      });
      return { questions, out: log.mock.calls.map((c) => String(c[0])).join('\n') };
    } finally {
      log.mockRestore();
    }
  }

  it('asks on a terminal and writes the hook only after a yes', async () => {
    const { questions, out } = await offer({ answer: true });
    expect(questions).toEqual(['  Add a hook to ~/.bashrc that exports every stored secret in each new shell? [y/N] ']);
    expect(fs.readFileSync(profile(), 'utf-8')).toContain(SHELL_HOOK_MARKER);
    expect(out).toContain('Shell hook installed in ~/.bashrc');
    expect(out).toContain('secretless-ai run --only DEMO_KEY -- <command>');
  });

  it('a no leaves the profile unwritten and names run --only and --no-shell-hook', async () => {
    const { questions, out } = await offer({ answer: false });
    expect(questions).toHaveLength(1);
    expect(fs.existsSync(profile())).toBe(false);
    expect(out).toContain('Shell profile not changed.');
    expect(out).toContain('To give one command this secret:  secretless-ai run --only DEMO_KEY -- <command>');
    expect(out).toContain('secret set <NAME> --no-shell-hook');
    expect(out).not.toContain('Shell hook installed');
  });

  it('--no-shell-hook does not ask and leaves an existing profile byte for byte', async () => {
    const before = "alias ll='ls -l'\n";
    fs.writeFileSync(profile(), before);
    const { questions, out } = await offer({ noShellHook: true, answer: true });
    expect(questions).toEqual([]);
    expect(fs.readFileSync(profile(), 'utf-8')).toBe(before);
    expect(out).toContain('Shell profile not changed (--no-shell-hook).');
    expect(out).toContain('secretless-ai run --only DEMO_KEY -- <command>');
  });

  it('with no terminal to ask on, the profile is not written', async () => {
    const { questions, out } = await offer({ answer: null });
    expect(questions).toHaveLength(1);
    expect(fs.existsSync(profile())).toBe(false);
    expect(out).toContain('Shell profile not changed: there is no terminal to ask on before editing ~/.bashrc.');
    expect(out).toContain('secretless-ai run --only DEMO_KEY -- <command>');
  });

  it('asks before it replaces a hook line whose command was not found, and a no keeps it', async () => {
    const before = `\n${SHELL_HOOK_MARKER}\n${BARE_HOOK_LINE}\n`;
    fs.writeFileSync(profile(), before);
    const { questions, out } = await offer({ answer: false });
    expect(questions).toEqual(['  Point the hook in ~/.bashrc at this copy of secretless-ai? [y/N] ']);
    expect(out).toContain('The shell hook in ~/.bashrc runs a command that was not found, so new shells receive no secrets.');
    expect(fs.readFileSync(profile(), 'utf-8')).toBe(before);

    await offer({ answer: true });
    expect(fs.readFileSync(profile(), 'utf-8')).toContain(getShellHookLine([process.execPath, script]));
  });

  it('does not ask when the profile already has a working hook', async () => {
    await offer({ answer: true });
    const after = fs.readFileSync(profile(), 'utf-8');
    const { questions, out } = await offer({ answer: true });
    expect(questions).toEqual([]);
    expect(out).toBe('');
    expect(fs.readFileSync(profile(), 'utf-8')).toBe(after);
  });
});

describe('askOnTerminal (#412)', () => {
  function terminal(isTTY = true): { input: PassThrough & { isTTY?: boolean }; output: { isTTY: boolean; text: string; write(t: string): void } } {
    const input = Object.assign(new PassThrough(), { isTTY });
    const output = { isTTY, text: '', write(t: string) { this.text += t; } };
    return { input, output };
  }

  it.each([
    ['y\n', true],
    ['YES\n', true],
    ['\n', false],
    ['n\n', false],
    ['yep\n', false],
  ])('reads %j as %s', async (line, expected) => {
    const { input, output } = terminal();
    const answer = askOnTerminal('  Q? [y/N] ', input, output);
    input.write(line);
    expect(await answer).toBe(expected);
    expect(output.text).toBe('  Q? [y/N] ');
  });

  it('takes the end of input as a no', async () => {
    const { input, output } = terminal();
    const answer = askOnTerminal('  Q? [y/N] ', input, output);
    input.end();
    expect(await answer).toBe(false);
  });

  it('does not ask, and reads nothing, when stdin or the prompt stream is not a terminal', async () => {
    const piped = terminal(false);
    piped.input.write('y\n');
    expect(await askOnTerminal('  Q? [y/N] ', piped.input, piped.output)).toBeNull();
    expect(piped.output.text).toBe('');

    const { input } = terminal(true);
    const redirected = { isTTY: false, text: '', write(t: string) { this.text += t; } };
    expect(await askOnTerminal('  Q? [y/N] ', input, redirected)).toBeNull();
    expect(redirected.text).toBe('');
  });
});

describe('secret set --no-shell-hook (#412)', () => {
  it('passes the flag to the hook step and refuses it on another subcommand', async () => {
    const seen: Array<{ name: string; noShellHook: boolean }> = [];
    const store = { setSecret: async () => ({ rotation: { kind: 'none' } }), backendName: 'test' } as unknown as SecretStore;
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const afterSet = (context: { name: string; noShellHook: boolean }) => { seen.push(context); };
      expect(await runSecret(['set', 'DEMO_KEY=not-a-real-value', '--no-shell-hook'], { createStore: () => store, afterSet })).toBe(0);
      expect(await runSecret(['set', 'DEMO_KEY=not-a-real-value'], { createStore: () => store, afterSet })).toBe(0);
      expect(seen).toEqual([{ name: 'DEMO_KEY', noShellHook: true }, { name: 'DEMO_KEY', noShellHook: false }]);

      expect(await runSecret(['list', '--no-shell-hook'], { createStore: () => store, afterSet })).toBe(2);
      expect(err.mock.calls.map((c) => String(c[0])).join('\n')).toContain('--no-shell-hook is read by `secret set`, not by `secret list`');
    } finally {
      log.mockRestore();
      err.mockRestore();
    }
  });

  const hasBuild = fs.existsSync(CLI_PATH);
  const itIfBuilt = hasBuild ? it : it.skip;

  // The built CLI, as a user runs it: argv normalisation accepts the flag, and
  // a value piped in on a fresh home stores without editing ~/.zshenv.
  itIfBuilt.each([
    [['--no-shell-hook'], 'Shell profile not changed (--no-shell-hook).'],
    [[], 'Shell profile not changed: there is no terminal to ask on before editing ~/.zshenv.'],
  ])('leaves ~/.zshenv unwritten on a fresh home (flags %j)', (flags, expected) => {
    fs.mkdirSync(path.join(home, '.secretless-ai'));
    fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), '{"backend":"local"}\n');
    const res = spawnSync(process.execPath, [CLI_PATH, 'secret', 'set', 'DEMO_KEY', ...flags], {
      input: 'not-a-real-value',
      encoding: 'utf-8',
      cwd: dir,
      env: { PATH: process.env.PATH ?? '', HOME: home, SHELL: '/bin/zsh', SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off' },
    });
    expect(res.stderr).toBe('');
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('Stored: DEMO_KEY');
    expect(res.stdout).toContain(expected);
    expect(fs.existsSync(path.join(home, '.zshenv'))).toBe(false);
    expect(fs.existsSync(path.join(home, '.bashrc'))).toBe(false);
  });
});
