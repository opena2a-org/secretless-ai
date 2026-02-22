import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { readBackendConfig, writeBackendConfig, resolveBackendType } from './config';

function setup(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-config-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('config manager', () => {
  let tmpHome: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    tmpHome = setup();
    originalHome = process.env.HOME;
    process.env.HOME = tmpHome;
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    cleanup(tmpHome);
  });

  it('returns undefined when no config file exists', () => {
    expect(readBackendConfig()).toBeUndefined();
  });

  it('writes and reads backend config', () => {
    writeBackendConfig('keychain');
    expect(readBackendConfig()).toBe('keychain');
  });

  it('writes and reads local backend config', () => {
    writeBackendConfig('local');
    expect(readBackendConfig()).toBe('local');
  });

  it('creates config directory with restricted permissions', () => {
    writeBackendConfig('local');
    const configDir = path.join(tmpHome, '.secretless-ai');
    const stats = fs.statSync(configDir);
    expect(stats.isDirectory()).toBe(true);
  });

  it('config file has restricted permissions', () => {
    writeBackendConfig('keychain');
    const configPath = path.join(tmpHome, '.secretless-ai', 'config.json');
    const stats = fs.statSync(configPath);
    expect(stats.mode & 0o777).toBe(0o600);
  });

  it('preserves existing config keys when writing', () => {
    const configDir = path.join(tmpHome, '.secretless-ai');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      path.join(configDir, 'config.json'),
      JSON.stringify({ someOtherKey: 'value', backend: 'local' }, null, 2),
    );

    writeBackendConfig('keychain');

    const raw = fs.readFileSync(path.join(configDir, 'config.json'), 'utf-8');
    const config = JSON.parse(raw);
    expect(config.backend).toBe('keychain');
    expect(config.someOtherKey).toBe('value');
  });

  it('resolveBackendType uses explicit flag over config', () => {
    writeBackendConfig('keychain');
    expect(resolveBackendType('local')).toBe('local');
  });

  it('resolveBackendType uses config when no flag', () => {
    writeBackendConfig('keychain');
    expect(resolveBackendType()).toBe('keychain');
  });

  it('resolveBackendType defaults to local', () => {
    expect(resolveBackendType()).toBe('local');
  });

  it('resolveBackendType ignores invalid flag values', () => {
    expect(resolveBackendType('invalid')).toBe('local');
  });

  it('handles corrupted config file gracefully', () => {
    const configDir = path.join(tmpHome, '.secretless-ai');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(path.join(configDir, 'config.json'), 'not json at all');
    expect(readBackendConfig()).toBeUndefined();
  });
});
