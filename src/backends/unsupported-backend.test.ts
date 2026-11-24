/**
 * Issue #182 (part 1): a config naming a backend this version does not
 * implement was read as no config at all, so every secret command fell back
 * to the default store (the keychain upgrade included) without a word. A
 * secret written there is found by nothing that reads the store the user
 * chose. Secret commands now refuse, naming the backend, the installed
 * version and the first version that supports it; `status` shows it.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  BACKEND_FIRST_VERSION,
  UnsupportedBackendError,
  readUnsupportedBackend,
  resolveBackendType,
} from './config';
import { effectiveBackendName } from './factory';
import { SecretStore } from '../secret-store';
import { runSecret } from '../commands/secrets';
import { runStatus } from '../commands/core';
import { VERSION } from '../commands/utils';

describe('a configured backend this version does not implement (#182)', () => {
  let dir: string;
  let home: string;
  let originalHome: string | undefined;

  const writeConfig = (config: unknown): void => {
    fs.mkdirSync(path.join(home, '.secretless-ai'), { recursive: true });
    fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify(config));
  };

  const capture = async (run: () => Promise<number>): Promise<{ code: number; out: string; err: string }> => {
    const out: string[] = [];
    const err: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.map(String).join(' ')); });
    try {
      return { code: await run(), out: out.join('\n'), err: err.join('\n') };
    } finally {
      vi.restoreAllMocks();
    }
  };

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-unsupported-backend-'));
    home = path.join(dir, 'home');
    fs.mkdirSync(home);
    originalHome = process.env.HOME;
    process.env.HOME = home;
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('names no unsupported backend for a supported one, a missing file or no backend key', () => {
    expect(readUnsupportedBackend()).toBeUndefined();
    writeConfig({ cacheTtl: 0 });
    expect(readUnsupportedBackend()).toBeUndefined();
    for (const name of Object.keys(BACKEND_FIRST_VERSION)) {
      writeConfig({ backend: name });
      expect(readUnsupportedBackend()).toBeUndefined();
    }
  });

  it('resolves to no backend in place of the one configured', () => {
    writeConfig({ backend: 'aws-sm' });
    expect(readUnsupportedBackend()).toEqual({ name: 'aws-sm', installedVersion: VERSION, firstSupportedVersion: null });
    let thrown: unknown;
    try {
      resolveBackendType();
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(UnsupportedBackendError);
    const message = (thrown as Error).message;
    expect(message).toContain('"aws-sm"');
    expect(message).toContain(`secretless-ai ${VERSION}, the installed version`);
    expect(message).toContain(`the first that does is later than this one`);
    expect(() => new SecretStore()).toThrow(UnsupportedBackendError);
    // A backend named for one run is still that backend.
    expect(resolveBackendType('local')).toBe('local');
  });

  it('never upgrades to the keychain under it', () => {
    writeConfig({ backend: 'aws-sm' });
    expect(effectiveBackendName('local')).toBe('local');
  });

  it('refuses each secret command with the backend name and versions, and stores nothing', async () => {
    writeConfig({ backend: 'aws-sm' });
    // A subcommand either reports the refusal and returns non-zero, or throws
    // it, which the CLI prints as `Error: ...` with exit 1.
    for (const args of [['list'], ['set', 'FOO=bar'], ['rm', 'FOO'], ['show', 'FOO']]) {
      let thrown = '';
      const { code, out, err } = await capture(() => runSecret(args, { afterSet: () => {} }).catch((e: unknown) => {
        expect(e, args.join(' ')).toBeInstanceOf(UnsupportedBackendError);
        thrown = (e as Error).message;
        return 1;
      }));
      expect(code, args.join(' ')).not.toBe(0);
      const said = out + '\n' + err + '\n' + thrown;
      expect(said, args.join(' ')).toContain('Configured backend "aws-sm" is not supported');
      expect(said, args.join(' ')).toContain(VERSION);
    }
    expect(fs.readdirSync(path.join(home, '.secretless-ai'))).toEqual(['config.json']);
  });

  it('shows the backend as unsupported in status and status --json', async () => {
    writeConfig({ backend: 'aws-sm' });
    const project = path.join(dir, 'project');
    fs.mkdirSync(project);

    const text = await capture(() => runStatus(project));
    expect(text.code).toBe(0);
    expect(text.out).toContain(`backend: aws-sm (unsupported by secretless-ai ${VERSION})`);

    const json = await capture(() => runStatus(project, { json: true }));
    const doc = JSON.parse(json.out);
    expect(doc.backend).toBe(`aws-sm (unsupported by secretless-ai ${VERSION})`);
    expect(doc.configuredBackend).toBe('aws-sm');
    expect(doc.unsupportedBackend).toEqual({ name: 'aws-sm', installedVersion: VERSION, firstSupportedVersion: null });
  });

  it('reports no unsupported backend in status --json when the backend is supported', async () => {
    writeConfig({ backend: 'local' });
    const project = path.join(dir, 'project');
    fs.mkdirSync(project);
    const json = await capture(() => runStatus(project, { json: true }));
    expect(JSON.parse(json.out).unsupportedBackend).toBeNull();
  });
});
