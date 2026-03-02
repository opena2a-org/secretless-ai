import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  readBackendConfig, writeBackendConfig, resolveBackendType,
  readCacheTtl, writeCacheTtl, parseDuration, formatTtl, DEFAULT_CACHE_TTL_SECONDS,
} from './config';

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

describe('cache TTL config', () => {
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

  it('returns default TTL when no config exists', () => {
    expect(readCacheTtl()).toBe(DEFAULT_CACHE_TTL_SECONDS);
  });

  it('writes and reads cache TTL', () => {
    writeCacheTtl(3600);
    expect(readCacheTtl()).toBe(3600);
  });

  it('writes 0 to disable cache', () => {
    writeCacheTtl(0);
    expect(readCacheTtl()).toBe(0);
  });

  it('preserves backend config when writing TTL', () => {
    writeBackendConfig('keychain');
    writeCacheTtl(600);
    expect(readBackendConfig()).toBe('keychain');
    expect(readCacheTtl()).toBe(600);
  });

  it('preserves TTL when writing backend config', () => {
    writeCacheTtl(1800);
    writeBackendConfig('1password');
    expect(readCacheTtl()).toBe(1800);
    expect(readBackendConfig()).toBe('1password');
  });
});

describe('parseDuration', () => {
  it('parses seconds', () => {
    expect(parseDuration('300')).toBe(300);
  });

  it('parses minutes', () => {
    expect(parseDuration('5m')).toBe(300);
  });

  it('parses hours', () => {
    expect(parseDuration('1h')).toBe(3600);
  });

  it('parses days', () => {
    expect(parseDuration('1d')).toBe(86400);
  });

  it('parses "off" as 0', () => {
    expect(parseDuration('off')).toBe(0);
  });

  it('parses "0" as 0', () => {
    expect(parseDuration('0')).toBe(0);
  });

  it('handles whitespace', () => {
    expect(parseDuration('  5m  ')).toBe(300);
  });

  it('is case insensitive', () => {
    expect(parseDuration('5M')).toBe(300);
    expect(parseDuration('OFF')).toBe(0);
  });

  it('returns -1 for invalid input', () => {
    expect(parseDuration('abc')).toBe(-1);
    expect(parseDuration('5x')).toBe(-1);
    expect(parseDuration('')).toBe(-1);
  });

  it('parses seconds with s suffix', () => {
    expect(parseDuration('30s')).toBe(30);
  });
});

describe('formatTtl', () => {
  it('formats 0 as "off"', () => {
    expect(formatTtl(0)).toBe('off');
  });

  it('formats seconds', () => {
    expect(formatTtl(30)).toBe('30s');
  });

  it('formats minutes', () => {
    expect(formatTtl(300)).toBe('5m');
  });

  it('formats hours', () => {
    expect(formatTtl(3600)).toBe('1h');
  });

  it('formats days', () => {
    expect(formatTtl(86400)).toBe('1d');
  });
});
