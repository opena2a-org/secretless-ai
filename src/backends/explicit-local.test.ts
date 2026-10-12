/**
 * Issue #327: `backend set local` stored secrets in the macOS Keychain.
 *
 * `local` upgraded to the platform keychain whenever one was available, even
 * after the user chose it with `backend set local`, while the docs and
 * `backend set` itself describe `local` as the AES-256-GCM encrypted file.
 * There was no way to select that file on macOS, or on Linux with
 * `secret-tool` installed. Only the unconfigured default upgrades now.
 *
 * A `secret-tool` stand-in goes first on PATH so a Linux runner sees a likely
 * keychain as macOS always does: without one there is no upgrade to refuse,
 * and the explicit-local assertions would pass whether or not the fix is
 * present. The first test guards that precondition.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createBackend, effectiveBackendName } from './factory';
import { writeBackendConfig } from './config';
import type { SelectableBackendType } from './config';
import { LocalBackend } from './local';
import { SecretStore } from '../secret-store';
import { runBackend } from '../commands/backend';

const hasKeychainPath = process.platform === 'darwin' || process.platform === 'linux';

async function statusLines(): Promise<string> {
  const lines: string[] = [];
  const log = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    lines.push(args.map(String).join(' '));
  });
  try {
    expect(await runBackend([])).toBe(0);
  } finally {
    log.mockRestore();
  }
  return lines.join('\n');
}

describe.skipIf(!hasKeychainPath)('an explicit `backend set local` is honoured (#327)', () => {
  let dir: string;
  let originalHome: string | undefined;
  let originalPath: string | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-explicit-local-'));
    const home = path.join(dir, 'home');
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(home);
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    originalHome = process.env.HOME;
    originalPath = process.env.PATH;
    process.env.HOME = home;
    process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ''}`;
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    process.env.PATH = originalPath;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('still upgrades the unconfigured default to the platform keychain', () => {
    expect(effectiveBackendName('local')).toMatch(/^keychain-(macos|linux)$/);
  });

  it('builds the encrypted file for a configured local', () => {
    writeBackendConfig('local');
    const backend = createBackend('local');
    expect(backend).toBeInstanceOf(LocalBackend);
    expect(backend.name).toBe('local');
  });

  it('reports local as the effective backend, as `secret list` does', () => {
    writeBackendConfig('local');
    expect(effectiveBackendName('local')).toBe('local');
    expect(new SecretStore().backendName).toBe('local');
  });

  it('builds the encrypted file for a local named for one run, with no backend configured (#365)', () => {
    // `setup --backend local` names the file in place of the configured
    // store; with nothing configured it was upgraded to the keychain.
    expect(createBackend('local', undefined, true, { role: 'named' })).toBeInstanceOf(LocalBackend);
    expect(new SecretStore({ backendType: 'local', backendNamed: true }).backendName).toBe('local');
    // CONTROL: the same type, not named for the run, is still the default upgrade.
    expect(new SecretStore({ backendType: 'local' }).backendName).toMatch(/^keychain-(macos|linux)$/);
  });

  it('`backendNamed` without a `backendType` names nothing, so the store is the default one (#367)', () => {
    // With nothing named there is nothing to build in place of the configured
    // store. Read as naming the resolved `local`, it built the encrypted file.
    const unnamed = new SecretStore().backendName;
    expect(unnamed).toMatch(/^keychain-(macos|linux)$/);
    expect(new SecretStore({ backendNamed: true }).backendName).toBe(unnamed);
  });

  it('builds the encrypted file for `migrate --from local` beside another configured backend', () => {
    writeBackendConfig('keychain');
    expect(createBackend('local')).toBeInstanceOf(LocalBackend);
  });

  it("the README's backend switch migrates from the store the unconfigured default wrote to", () => {
    // README.md shows `backend set <target>` and then `migrate --from <source>
    // --to <target>`. Secrets stored before the switch went to the default
    // store, so once the switch is configured the source has to name that store.
    const readme = fs.readFileSync(path.resolve(__dirname, '..', '..', 'README.md'), 'utf-8');
    const set = /^npx secretless-ai backend set (\S+)/m.exec(readme);
    const migrate = /^npx secretless-ai migrate --from (\S+) --to (\S+)/m.exec(readme);
    if (!set || !migrate) throw new Error('README.md shows no `backend set` and `migrate --from` pair');
    expect(migrate[2]).toBe(set[1]);

    const writtenTo = createBackend('local').name;
    writeBackendConfig(set[1] as SelectableBackendType);
    expect(createBackend(migrate[1] as SelectableBackendType).name).toBe(writtenTo);
  });

  it('`backend` prints local as current once local is configured', async () => {
    writeBackendConfig('local');
    const out = await statusLines();
    expect(out).toMatch(/^ {2}Current: +local$/m);
    expect(out).not.toMatch(/Current:.*keychain/);
  });

  it('`backend` names the default upgrade and the command that selects the file', async () => {
    const out = await statusLines();
    expect(out).toMatch(/Current: +keychain-(macos|linux) +\(default, because a platform keychain is available; `.*backend set local` selects the encrypted file\)/);
    expect(out).not.toContain('configured: local');
  });
});
