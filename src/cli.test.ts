import { describe, it, expect } from 'vitest';
import { execFileSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * Integration tests for the CLI dispatcher. Spawns the built entry point
 * (`dist/cli.js`) so behavior matches what a real user sees — relevant because
 * `secretless-ai scan --help` used to actually run `scan`, `init --help` used
 * to create a `--help/` directory, and `broker start --help` used to start the
 * daemon.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');

function runCli(args: string[], opts: { cwd?: string } = {}): string {
  return execFileSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: opts.cwd,
  });
}

describe('cli --help handling', () => {
  // Skip the whole suite if the build artifact is missing (CI order guard).
  const hasBuild = fs.existsSync(CLI_PATH);
  const itIfBuilt = hasBuild ? it : it.skip;

  itIfBuilt('prints top-level help for `--help`', () => {
    const out = runCli(['--help']);
    expect(out).toMatch(/Secretless v/);
    expect(out).toMatch(/Quick start:/);
  });

  itIfBuilt('subcommand `--help` does NOT execute the subcommand (regression guard)', () => {
    // init without the guard would scaffold files into cwd. Run from a fresh
    // temp dir and assert nothing was written.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-cli-help-'));
    try {
      const before = fs.readdirSync(tmp);
      const out = runCli(['init', '--help'], { cwd: tmp });
      const after = fs.readdirSync(tmp);
      expect(after).toEqual(before); // nothing created
      expect(out).toMatch(/Secretless v/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('`scan --help` prints help instead of scanning', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-cli-help-'));
    try {
      const out = runCli(['scan', '--help'], { cwd: tmp });
      expect(out).toMatch(/Secretless v/);
      expect(out).not.toMatch(/Secretless Scanner/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('`-h` short flag also intercepts', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-cli-help-'));
    try {
      const out = runCli(['scan', '-h'], { cwd: tmp });
      expect(out).toMatch(/Secretless v/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('init / status reject unknown flags as dir path (regression: release-test 2026-05-12 P1)', () => {
  const hasBuild = fs.existsSync(CLI_PATH);
  const itIfBuilt = hasBuild ? it : it.skip;

  function runCliSpawn(args: string[], cwd: string) {
    return spawnSync(process.execPath, [CLI_PATH, ...args], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd,
    });
  }

  itIfBuilt('`init --ci` does NOT create a `--ci/` directory', () => {
    // Pre-fix: secretless-ai init --ci scaffolded files into a literal `--ci/`
    // dir because dispatch took args[1] as projectDir without validation.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-init-flag-'));
    try {
      const before = fs.readdirSync(tmp);
      const res = runCliSpawn(['init', '--ci'], tmp);
      const after = fs.readdirSync(tmp);
      expect(after).toEqual(before); // nothing created
      expect(res.status).toBe(2);
      expect(res.stderr).toMatch(/Unknown option: --ci/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('`init --unknown` is rejected with actionable error', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-init-flag-'));
    try {
      const res = runCliSpawn(['init', '--unknown'], tmp);
      expect(fs.readdirSync(tmp)).toEqual([]);
      expect(res.status).toBe(2);
      expect(res.stderr).toMatch(/Unknown option: --unknown/);
      expect(res.stderr).toMatch(/Run `secretless-ai init --help` for usage/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('`status --foo` is rejected, not treated as dir', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-status-flag-'));
    try {
      const res = runCliSpawn(['status', '--foo'], tmp);
      expect(fs.readdirSync(tmp)).toEqual([]);
      expect(res.status).toBe(2);
      expect(res.stderr).toMatch(/Unknown option: --foo/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('`init ./valid-dir` still works (positive case)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-init-pos-'));
    try {
      const target = path.join(tmp, 'target');
      fs.mkdirSync(target);
      const res = runCliSpawn(['init', target], tmp);
      // init exits 0 on success and writes files into target.
      // Don't pin specific files — runInit's surface evolves — just assert
      // it created something in target.
      expect(res.status).toBe(0);
      expect(fs.readdirSync(target).length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
