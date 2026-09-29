import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { installWrapper, getWrapperCommand } from './install-wrapper';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-install-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('installWrapper', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('installs wrapper script to target directory', () => {
    const result = installWrapper(dir);
    expect(result.command).toBeDefined();
    expect(result.args).toBeDefined();

    // The bin directory should exist with copied dist files
    const binDir = path.join(dir, 'bin');
    expect(fs.existsSync(binDir)).toBe(true);
  });

  it('copies mcp-wrapper.js to the bin directory', () => {
    installWrapper(dir);
    const wrapperPath = path.join(dir, 'bin', 'mcp-wrapper.js');
    expect(fs.existsSync(wrapperPath)).toBe(true);
  });

  it('copies dependency subdirectories (mcp/, backends/)', () => {
    installWrapper(dir);
    const binDir = path.join(dir, 'bin');

    // The wrapper imports ./mcp/vault which is compiled to dist/mcp/vault.js
    const mcpDir = path.join(binDir, 'mcp');
    expect(fs.existsSync(mcpDir)).toBe(true);

    // Vault imports from ../backends/ which is compiled to dist/backends/
    const backendsDir = path.join(binDir, 'backends');
    expect(fs.existsSync(backendsDir)).toBe(true);
  });

  it('returns command as process.execPath (absolute path to node)', () => {
    const result = installWrapper(dir);
    expect(result.command).toBe(process.execPath);
    expect(path.isAbsolute(result.command)).toBe(true);
  });

  it('returns args[0] as the absolute path to the copied wrapper', () => {
    const result = installWrapper(dir);
    expect(result.args.length).toBe(1);
    expect(result.args[0]).toBe(path.join(dir, 'bin', 'mcp-wrapper.js'));
    expect(path.isAbsolute(result.args[0])).toBe(true);
    expect(fs.existsSync(result.args[0])).toBe(true);
  });

  it('overwrites existing files on reinstall', () => {
    // First install
    installWrapper(dir);
    const wrapperPath = path.join(dir, 'bin', 'mcp-wrapper.js');
    const firstContent = fs.readFileSync(wrapperPath, 'utf-8');

    // Second install should not throw
    const result = installWrapper(dir);
    const secondContent = fs.readFileSync(wrapperPath, 'utf-8');

    expect(result.command).toBe(process.execPath);
    expect(secondContent).toBe(firstContent);
  });

  // #138: the copy has no package.json above it, so the version it was copied
  // from is recorded beside it for `secretless-mcp --version` to read.
  it('records the package version beside the copied wrapper', () => {
    installWrapper(dir);
    const recorded = JSON.parse(fs.readFileSync(path.join(dir, 'bin', 'wrapper-version.json'), 'utf-8'));
    expect(recorded).toEqual({ name: 'secretless-ai', version: JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8')).version });
  });
});

describe('getWrapperCommand', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('returns node + wrapper path for MCP config', () => {
    installWrapper(dir);
    const cmd = getWrapperCommand(dir);

    expect(cmd.command).toBe(process.execPath);
    expect(cmd.args.length).toBe(1);
    expect(cmd.args[0]).toBe(path.join(dir, 'bin', 'mcp-wrapper.js'));
  });

  it('returns the same command/args as installWrapper', () => {
    const installResult = installWrapper(dir);
    const getResult = getWrapperCommand(dir);

    expect(getResult.command).toBe(installResult.command);
    expect(getResult.args).toEqual(installResult.args);
  });

  it('does not require files to exist (for pre-check scenarios)', () => {
    // getWrapperCommand should not throw even if files are not installed yet
    const cmd = getWrapperCommand(dir);
    expect(cmd.command).toBe(process.execPath);
    expect(cmd.args[0]).toBe(path.join(dir, 'bin', 'mcp-wrapper.js'));
  });
});
