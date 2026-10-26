import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  VERSION_FILE_READ_LIMIT,
  WRAPPER_VERSION_FILE,
  packageVersionAbove,
  readWrapperVersion,
  writeWrapperVersion,
} from './wrapper-version';
import { BINDING_COPY_READ_LIMIT } from './discover';
import { wrapperBuild } from './protect';

/**
 * The version a wrapper reads, as protect-mcp's re-point and mcp-status read
 * it beside the wrapper a config's command names (wrapperBuild): its
 * wrapper-version.json, then a package.json at or above its directory. A file
 * there that is not a regular file, or is larger than the bound, is not read
 * and gives no version, so the wrapper reads as `unread`; a regular file
 * within the bound gives its version.
 *
 * No FIFO is made: a blocking read could hang the run.
 */

// The real fs, with each read and open of a path recorded, so a cell can say a file was not read.
vi.mock('fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs')>();
  return { ...actual, readFileSync: vi.fn(actual.readFileSync), openSync: vi.fn(actual.openSync) };
});

// The bound the cells size their files from; the first cell checks the source's equals it.
const LIMIT = 1024 * 1024;
const VERSION = '0.30.0';
// This build's wrapper, as protect-mcp names it: never the file a cell plants.
const THIS_WRAPPER = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');

let scratch: string;

beforeEach(() => {
  scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-wrapper-version-')));
  vi.mocked(fs.readFileSync).mockClear();
  vi.mocked(fs.openSync).mockClear();
});

afterEach(() => {
  fs.rmSync(scratch, { recursive: true, force: true });
});

/** A directory holding a wrapper file, as an install of another build leaves one; the command is its absolute path. */
function wrapperDir(): { dir: string; command: string } {
  const dir = path.join(scratch, 'bin');
  fs.mkdirSync(dir, { recursive: true });
  const command = path.join(dir, 'mcp-wrapper.js');
  fs.writeFileSync(command, '');
  return { dir, command };
}

/** JSON that gives VERSION as `secretless-ai`'s when read, padded with spaces to exactly `size` bytes. */
function versionJson(size: number): string {
  const text = JSON.stringify({ name: 'secretless-ai', version: VERSION });
  expect(size).toBeGreaterThanOrEqual(text.length);
  return text + ' '.repeat(size - text.length);
}

/** The paths read or opened through fs since the cell began. */
function touched(): string[] {
  return [...vi.mocked(fs.readFileSync).mock.calls, ...vi.mocked(fs.openSync).mock.calls].map((call) => String(call[0]));
}

describe('the version files beside a wrapper a config names are read only when regular and within the bound', () => {
  it('the bound is 1 MiB, the bound the start check reads a project-level config with', () => {
    expect(VERSION_FILE_READ_LIMIT).toBe(LIMIT);
    expect(VERSION_FILE_READ_LIMIT).toBe(BINDING_COPY_READ_LIMIT);
  });

  it(`a ${WRAPPER_VERSION_FILE} one byte over the bound is not read, and the wrapper reads as unread`, () => {
    const { dir, command } = wrapperDir();
    const file = path.join(dir, WRAPPER_VERSION_FILE);
    fs.writeFileSync(file, versionJson(LIMIT + 1));
    expect(fs.statSync(file).size).toBe(LIMIT + 1);
    expect(packageVersionAbove(dir), 'nothing at or above the directory gives a version').toBeNull();

    expect(wrapperBuild(command, THIS_WRAPPER)).toEqual({ build: 'unread' });
    expect(readWrapperVersion(dir)).toBe('unknown');
    expect(touched()).not.toContain(file);
  });

  it(`a directory at ${WRAPPER_VERSION_FILE} is not read, and the wrapper reads as unread`, () => {
    const { dir, command } = wrapperDir();
    const file = path.join(dir, WRAPPER_VERSION_FILE);
    fs.mkdirSync(file);
    expect(packageVersionAbove(dir), 'nothing at or above the directory gives a version').toBeNull();

    expect(wrapperBuild(command, THIS_WRAPPER)).toEqual({ build: 'unread' });
    expect(readWrapperVersion(dir)).toBe('unknown');
    expect(touched()).not.toContain(file);
  });

  it('a package.json one byte over the bound beside the wrapper is not read, and the wrapper reads as unread', () => {
    const { dir, command } = wrapperDir();
    const file = path.join(dir, 'package.json');
    fs.writeFileSync(file, versionJson(LIMIT + 1));
    expect(fs.statSync(file).size).toBe(LIMIT + 1);
    expect(packageVersionAbove(path.dirname(dir)), 'nothing above the directory gives a version').toBeNull();

    expect(wrapperBuild(command, THIS_WRAPPER)).toEqual({ build: 'unread' });
    expect(readWrapperVersion(dir)).toBe('unknown');
    expect(touched()).not.toContain(file);
  });

  it('a directory at package.json beside the wrapper is not read, and the wrapper reads as unread', () => {
    const { dir, command } = wrapperDir();
    const file = path.join(dir, 'package.json');
    fs.mkdirSync(file);
    expect(packageVersionAbove(path.dirname(dir)), 'nothing above the directory gives a version').toBeNull();

    expect(wrapperBuild(command, THIS_WRAPPER)).toEqual({ build: 'unread' });
    expect(readWrapperVersion(dir)).toBe('unknown');
    expect(touched()).not.toContain(file);
  });

  it(`control: a ${WRAPPER_VERSION_FILE} as the install writes it, and one of exactly the bound, give their version`, () => {
    const { dir, command } = wrapperDir();
    const file = path.join(dir, WRAPPER_VERSION_FILE);
    writeWrapperVersion(dir, VERSION);

    expect(wrapperBuild(command, THIS_WRAPPER)).toEqual({ build: 'version', version: VERSION });
    expect(touched()).toContain(file);

    fs.writeFileSync(file, versionJson(LIMIT));
    expect(fs.statSync(file).size).toBe(LIMIT);
    expect(wrapperBuild(command, THIS_WRAPPER)).toEqual({ build: 'version', version: VERSION });
  });

  it('control: a package.json beside the wrapper, small and of exactly the bound, gives its version', () => {
    const { dir, command } = wrapperDir();
    const file = path.join(dir, 'package.json');
    fs.writeFileSync(file, JSON.stringify({ name: 'secretless-ai', version: VERSION }, null, 2));

    expect(wrapperBuild(command, THIS_WRAPPER)).toEqual({ build: 'version', version: VERSION });
    expect(touched()).toContain(file);

    fs.writeFileSync(file, versionJson(LIMIT));
    expect(fs.statSync(file).size).toBe(LIMIT);
    expect(wrapperBuild(command, THIS_WRAPPER)).toEqual({ build: 'version', version: VERSION });
  });
});
