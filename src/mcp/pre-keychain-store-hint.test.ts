import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * A server protected by a version before 0.12.3 has its secrets in the
 * encrypted file under ~/.secretless-ai/mcp-vault, and the wrapper, given
 * neither --vault-dir nor --vault-key, reads the OS keychain where one is
 * available. Its refusal names the step that reads that file again: the
 * server's args given --vault-dir with the directory's absolute path.
 *
 * The wrapper runs from the build (`dist/`), in a home of its own, with a
 * `secret-tool` on PATH so a Linux runner sees a likely keychain as macOS
 * always does. No keychain is run: the entry carries no binding, so the
 * wrapper refuses it before it reads the store.
 */

const WRAPPER_JS = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');

let home: string;
let bin: string;

beforeEach(() => {
  home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-prekeychain-home-')));
  bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-prekeychain-bin-'));
  fs.writeFileSync(path.join(bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
});

afterEach(() => {
  for (const dir of [home, bin]) fs.rmSync(dir, { recursive: true, force: true });
});

const vaultDir = (): string => path.join(home, '.secretless-ai', 'mcp-vault');

function oldStore(file = 'secrets.enc'): void {
  fs.mkdirSync(vaultDir(), { recursive: true });
  fs.writeFileSync(path.join(vaultDir(), file), 'not-a-real-store');
}

function runWrapper(wrapperArgs: string[]): { status: number | null; stderr: string } {
  const result = spawnSync(process.execPath, [WRAPPER_JS, ...wrapperArgs, '--', process.execPath, '-e', ''], {
    encoding: 'utf-8',
    env: {
      PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
      HOME: home,
      SECRETLESS_OS_KEYCHAIN: 'off',
      OPENA2A_TELEMETRY: 'off',
    },
  });
  return { status: result.status, stderr: result.stderr };
}

describe('the wrapper refusal names the store a version before 0.12.3 wrote', () => {
  it('names --vault-dir and the absolute path of ~/.secretless-ai/mcp-vault when an encrypted store is there', () => {
    oldStore();

    const { status, stderr } = runWrapper(['--client', 'cursor', '--server', 'github']);

    expect(status).toBe(1);
    expect(stderr).toContain('not bound to its stored secrets');
    expect(stderr).toContain(`add --vault-dir ${vaultDir()} to the server's args`);
    expect(path.isAbsolute(vaultDir())).toBe(true);
  });

  it('names it for any encrypted file in that directory', () => {
    oldStore('store.enc');

    expect(runWrapper(['--client', 'c', '--server', 's']).stderr).toContain(`--vault-dir ${vaultDir()}`);
  });

  it('CONTROL: says nothing of --vault-dir when no encrypted store is there', () => {
    fs.mkdirSync(vaultDir(), { recursive: true });

    const { status, stderr } = runWrapper(['--client', 'cursor', '--server', 'github']);

    expect(status).toBe(1);
    expect(stderr).not.toContain('--vault-dir');
  });

  it('CONTROL: says nothing of --vault-dir when the args already give it', () => {
    oldStore();

    const { status, stderr } = runWrapper(['--client', 'cursor', '--server', 'github', '--vault-dir', vaultDir()]);

    expect(status).toBe(1);
    expect(stderr).not.toContain('add --vault-dir');
  });
});
