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
import { installShellHook, getShellHookLine, hookLineRuns, shellHookCommand, SHELL_HOOK_MARKER } from './env';
import { ensureShellHook } from './commands/secrets';

const BARE_HOOK_LINE = 'eval "$(secretless-ai env 2>/dev/null)"';
const SHELL_PATH = '/usr/bin:/bin';

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
  it('says the hook runs this copy by its path when secretless-ai is not on PATH', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      ensureShellHook({ home, shell: '/bin/bash', platform: 'linux', command: [process.execPath, script], pathEnv: emptyPath });
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
