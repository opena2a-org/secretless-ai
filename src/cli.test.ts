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

function runCli(args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}): string {
  return execFileSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: opts.cwd,
    env: opts.env ?? process.env,
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

describe('SECRETLESS_CLI_PREFIX rebrands citations + suppresses banner (#191)', () => {
  const hasBuild = fs.existsSync(CLI_PATH);
  const itIfBuilt = hasBuild ? it : it.skip;

  itIfBuilt('UNSET: help shows native `npx secretless-ai` citations + banner', () => {
    // Default behavior must be identical to before the env var existed.
    const env = { ...process.env };
    delete env.SECRETLESS_CLI_PREFIX;
    const out = runCli(['--help'], { env });
    expect(out).toMatch(/Secretless v/);
    expect(out).toMatch(/npx secretless-ai scan/);
  });

  itIfBuilt('SET: help rebrands citations to the prefix and drops the banner', () => {
    const env = { ...process.env, SECRETLESS_CLI_PREFIX: 'opena2a secrets' };
    const out = runCli(['--help'], { env });
    // Citations now read as the host command path.
    expect(out).toMatch(/opena2a secrets scan/);
    expect(out).toMatch(/opena2a secrets init/);
    // No standalone secretless command citations leak through. The
    // `https://opena2a.org/secretless-ai` URL is a product link, not a command
    // citation, so we match the command forms specifically: `npx secretless-ai`
    // and bare `secretless-ai <verb>`.
    expect(out).not.toMatch(/npx secretless-ai/);
    expect(out).not.toMatch(/^\s*secretless-ai\s/m);
    // Brand+version banner is suppressed under the host umbrella; tagline stays.
    expect(out).not.toMatch(/Secretless v/);
    expect(out).toMatch(/Keep secrets out of AI context\./);
  });

  itIfBuilt('SET: error hint rebrands to the prefix', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-prefix-hint-'));
    try {
      const res = spawnSync(process.execPath, [CLI_PATH, 'init', '--unknown'], {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: tmp,
        env: { ...process.env, SECRETLESS_CLI_PREFIX: 'opena2a secrets' },
      });
      expect(res.status).toBe(2);
      expect(res.stderr).toMatch(/Run `opena2a secrets init --help` for usage/);
      expect(res.stderr).not.toMatch(/secretless-ai/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('SET: `secret` no-arg usage rebrands to the prefix, no bare citations', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-secret-prefix-'));
    try {
      const res = spawnSync(process.execPath, [CLI_PATH, 'secret'], {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: tmp,
        env: { ...process.env, SECRETLESS_CLI_PREFIX: 'opena2a secrets' },
      });
      expect(res.status).toBe(0);
      expect(res.stdout).toMatch(/Usage: opena2a secrets secret <set\|list\|get\|rm>/);
      expect(`${res.stdout}${res.stderr}`).not.toMatch(/npx secretless-ai/);
      expect(`${res.stdout}${res.stderr}`).not.toMatch(/(^|\s)secretless-ai\s/m);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('SET: `secret set` usage hint rebrands to the prefix, no bare citations', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-secret-set-prefix-'));
    try {
      const res = spawnSync(process.execPath, [CLI_PATH, 'secret', 'set'], {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: tmp,
        env: { ...process.env, SECRETLESS_CLI_PREFIX: 'opena2a secrets' },
      });
      expect(res.status).toBe(1);
      expect(`${res.stdout}${res.stderr}`).toMatch(/Usage: opena2a secrets secret set/);
      expect(`${res.stdout}${res.stderr}`).not.toMatch(/npx secretless-ai/);
      expect(`${res.stdout}${res.stderr}`).not.toMatch(/(^|\s)secretless-ai\s/m);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('SET: `scope` no-arg usage rebrands to the prefix, no bare citations', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scope-prefix-'));
    try {
      const res = spawnSync(process.execPath, [CLI_PATH, 'scope'], {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: tmp,
        env: { ...process.env, SECRETLESS_CLI_PREFIX: 'opena2a secrets' },
      });
      expect(res.status).toBe(0);
      expect(res.stdout).toMatch(/Usage: opena2a secrets scope <discover\|check\|list\|reset>/);
      expect(`${res.stdout}${res.stderr}`).not.toMatch(/npx secretless-ai/);
      expect(`${res.stdout}${res.stderr}`).not.toMatch(/(^|\s)secretless-ai\s/m);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('SET: `scope reset` usage hint rebrands to the prefix, no bare citations', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scope-reset-prefix-'));
    try {
      const res = spawnSync(process.execPath, [CLI_PATH, 'scope', 'reset'], {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: tmp,
        env: { ...process.env, SECRETLESS_CLI_PREFIX: 'opena2a secrets' },
      });
      expect(res.status).toBe(1);
      expect(`${res.stdout}${res.stderr}`).toMatch(/Usage: opena2a secrets scope reset/);
      expect(`${res.stdout}${res.stderr}`).not.toMatch(/npx secretless-ai/);
      expect(`${res.stdout}${res.stderr}`).not.toMatch(/(^|\s)secretless-ai\s/m);
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

describe('scan warns on unknown flags / secret usage (regression: #80, #81)', () => {
  const hasBuild = fs.existsSync(CLI_PATH);
  const itIfBuilt = hasBuild ? it : it.skip;

  function runCliSpawn(args: string[], cwd: string) {
    return spawnSync(process.execPath, [CLI_PATH, ...args], {
      encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], cwd,
    });
  }

  itIfBuilt('`scan --show-placeholder` (typo) warns instead of silently no-opping (#81)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scan-flag-'));
    try {
      const res = runCliSpawn(['scan', '.', '--show-placeholder'], tmp);
      expect(res.stderr).toMatch(/ignoring unknown flag --show-placeholder/);
      expect(res.status).toBe(0); // warning is non-fatal; clean dir still exits 0
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('`scan --json` (known flag) produces NO unknown-flag warning (#81)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scan-known-'));
    try {
      const res = runCliSpawn(['scan', '.', '--json'], tmp);
      expect(res.stderr).not.toMatch(/unknown flag/i);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('`secret` with no subcommand prints usage cleanly, exit 0 (#80)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-secret-'));
    try {
      const res = runCliSpawn(['secret'], tmp);
      expect(res.status).toBe(0);
      expect(res.stdout).toMatch(/Usage: secretless-ai secret/);
      expect(`${res.stdout}${res.stderr}`).not.toMatch(/Unknown secret command/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('`secret bogus` (real unknown subcommand) still errors, exit 1 (#80)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-secret-bad-'));
    try {
      const res = runCliSpawn(['secret', 'bogus'], tmp);
      expect(res.status).toBe(1);
      expect(res.stderr).toMatch(/Unknown secret command: bogus/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('`scope` with no subcommand prints usage cleanly, exit 0', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scope-'));
    try {
      const res = runCliSpawn(['scope'], tmp);
      expect(res.status).toBe(0);
      expect(res.stdout).toMatch(/Usage: secretless-ai scope/);
      expect(`${res.stdout}${res.stderr}`).not.toMatch(/Unknown scope command/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('`scope bogus` (real unknown subcommand) still errors, exit 1', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scope-bad-'));
    try {
      const res = runCliSpawn(['scope', 'bogus'], tmp);
      expect(res.status).toBe(1);
      expect(res.stderr).toMatch(/Unknown scope command: bogus/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
