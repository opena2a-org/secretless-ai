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

  itIfBuilt('`scan --show-placeholder` (typo) is refused, not answered (#81, #137)', () => {
    // The tree is CLEAN and that is the point. Under the previous
    // warn-and-continue this exited 0 with "No hardcoded credentials found." —
    // the strongest clean claim the tool makes, over a scan whose scope the
    // user asked to change and did not get. The earlier evidence that warning
    // was safe read exit 1, but that 1 came from a tree that happened to hold a
    // credential; it was never the flag.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scan-flag-'));
    try {
      const res = runCliSpawn(['scan', '.', '--show-placeholder'], tmp);
      expect(res.status).toBe(2);
      expect(res.stderr).toMatch(/--show-placeholder/);
      expect(res.stderr).toMatch(/did you mean --show-placeholders/);
      // Nothing may read as a verdict on a run that did not happen.
      expect(res.stdout).not.toMatch(/No hardcoded credentials found/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  itIfBuilt('CONTROL: the same clean tree with NO typo still answers, exit 0', () => {
    // Without this, the test above passes just as well against a scan that
    // refuses everything.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-scan-clean-'));
    try {
      const res = runCliSpawn(['scan', '.'], tmp);
      expect(res.status).toBe(0);
      expect(res.stdout).toMatch(/No hardcoded credentials found/);
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

/**
 * Re-test P2: `scan a.js b.js` dropped every path after the first with no
 * warning. Because the first path's findings still set exit 1, the run looked
 * complete while an entire file went unscanned.
 */
describe('scan rejects more than one path', () => {
  const hasBuild = fs.existsSync(CLI_PATH);
  const itIfBuilt = hasBuild ? it : it.skip;

  itIfBuilt('refuses more than one path', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-multipath-'));
    const KEY = ['sk-proj-', 'R1T2Y3U4I5O6P7A8S9D0F1G2H3J4K5L6Z7X8C9V0B1N2'].join('');
    fs.writeFileSync(path.join(dir, 'a.js'), `const k = "${KEY}";\n`);
    fs.writeFileSync(path.join(dir, 'b.js'), `const k = "${KEY}";\n`);

    const res = spawnSync(process.execPath, [CLI_PATH, 'scan', 'a.js', 'b.js'], {
      encoding: 'utf-8', cwd: dir, stdio: ['pipe', 'pipe', 'pipe'],
    });

    expect(res.status).toBe(2);
    const err = res.stderr ?? '';
    expect(err).toContain('one path');
    // It must name what it was given, so the user can see what was refused.
    expect(err).toContain('a.js');
    expect(err).toContain('b.js');
  });

  itIfBuilt('CONTROL: a single path still scans', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-singlepath-'));
    const KEY = ['sk-proj-', 'R1T2Y3U4I5O6P7A8S9D0F1G2H3J4K5L6Z7X8C9V0B1N2'].join('');
    fs.writeFileSync(path.join(dir, 'a.js'), `const k = "${KEY}";\n`);

    const res = spawnSync(process.execPath, [CLI_PATH, 'scan', 'a.js'], {
      encoding: 'utf-8', cwd: dir, stdio: ['pipe', 'pipe', 'pipe'],
    });
    expect(res.status).toBe(1);
    expect(res.stdout).toContain('credential');
  });
});

/**
 * The argv layer (0.22.1).
 *
 * Every block below is an A/B on ONE variable: how a flag is spelled. The
 * CONTROL row passes on v0.22.0 and after, which is what proves the arm beside
 * it is measuring the fix rather than the harness. Each arm fails on v0.22.0 on
 * its OWN assertion — not on a missing import, and not on a timeout.
 *
 * These are the red-proofable half of the fix. `argv.test.ts` covers the
 * per-spelling matrix but cannot be red-proofed, because `src/argv.ts` does not
 * exist on v0.22.0 and every test there would fail on the import instead.
 */
describe('a flag never widens scope (0.22.1 argv layer)', () => {
  const hasBuild = fs.existsSync(CLI_PATH);
  const itIfBuilt = hasBuild ? it : it.skip;

  // Split so this file is not itself a credential-bearing file.
  const PAT = ['ghp_', 'R1T2Y3U4I5O6P7A8S9D0F1G2H3J4K5L6Z7X8'].join('');

  function transcriptFixture(): { dir: string; file: string; before: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-argv-clean-'));
    const file = path.join(dir, 'session.jsonl');
    fs.writeFileSync(file, JSON.stringify({ role: 'user', content: `token ${PAT}` }) + '\n');
    return { dir, file, before: fs.readFileSync(file, 'utf-8') };
  }

  function scanFixture(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-argv-scan-'));
    fs.writeFileSync(path.join(dir, 'leak.js'), `const k = "${PAT}";\n`);
    return dir;
  }

  function cli(args: string[], cwd?: string) {
    return spawnSync(process.execPath, [CLI_PATH, ...args], {
      encoding: 'utf-8', cwd, stdio: ['pipe', 'pipe', 'pipe'],
    });
  }

  // --- clean: the destructive verb, where the safety flag is the only thing
  // standing between a preview and an irreversible in-place rewrite ----------

  itIfBuilt('CONTROL: `clean --dry-run` previews and changes nothing', () => {
    const { dir, file, before } = transcriptFixture();
    try {
      const res = cli(['clean', '--dry-run', '--path', dir]);
      expect(res.status).toBe(0);
      expect(res.stdout).toContain('dry-run');
      expect(fs.readFileSync(file, 'utf-8')).toBe(before);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  itIfBuilt('`clean --dryrun` is refused, and the file is not rewritten', () => {
    const { dir, file, before } = transcriptFixture();
    try {
      const res = cli(['clean', '--dryrun', '--path', dir]);
      // On v0.22.0 this exits 0 having performed the redaction the user asked
      // to preview: `runClean` computes `args.includes('--dry-run')`, which is
      // false, and validates nothing else.
      expect(res.status).toBe(2);
      expect(fs.readFileSync(file, 'utf-8')).toBe(before);
      expect(res.stderr).toContain('--dry-run');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  // The pre-fix arm of this one walks the machine's whole transcript corpus,
  // which is the defect. Read-only (--dry-run) but slow, so the timeout is
  // raised: a red-proof that fails on the clock has not proved anything.
  itIfBuilt('`clean --path=DIR` scopes to DIR instead of the whole corpus', () => {
    const { dir } = transcriptFixture();
    try {
      const res = cli(['clean', `--path=${dir}`, '--dry-run']);
      expect(res.stdout).toContain(`Scanning transcripts at ${dir}`);
      expect(res.stdout).toContain('Scanned:  1 files');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  // --- scan: a flag's value silently eating the path ------------------------

  itIfBuilt('CONTROL: `--max-files 20000 <dir>` honours the path', () => {
    const dir = scanFixture();
    try {
      const res = cli(['scan', '--max-files', '20000', dir]);
      expect(res.status).toBe(1);
      expect(res.stdout).toContain('credential');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  itIfBuilt('`--max-files <dir>` refuses rather than silently scanning the cwd', () => {
    const dir = scanFixture();
    const emptyCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-argv-cwd-'));
    try {
      const res = cli(['scan', '--max-files', dir], emptyCwd);
      // On v0.22.0: exit 0 and "No hardcoded credentials found." — over a
      // directory the tool never opened, because the path was consumed as the
      // flag's value and the scan retargeted to the working directory.
      expect(res.status).toBe(2);
      expect(res.stdout).not.toContain('No hardcoded credentials found');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(emptyCwd, { recursive: true, force: true });
    }
  });

  itIfBuilt('`--max-files=N` binds the cap instead of being dropped as unknown', () => {
    const dir = scanFixture();
    try {
      const res = cli(['scan', dir, '--max-files=20000', '--json']);
      const summary = JSON.parse(res.stdout).summary;
      // On v0.22.0 this is 5000: the equals form was warned about as an unknown
      // flag and the scan silently ran at the default cap.
      expect(summary.maxFiles).toBe(20000);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  // --- run: the selector whose absence means "inject everything" ------------

  const ABSENT = 'SECRETLESS_ARGV_NO_SUCH_SECRET';

  itIfBuilt('CONTROL: `run --only NAME` fails closed on a name the store lacks', () => {
    const res = cli(['run', '--only', ABSENT, '--', process.execPath, '-e', 'process.exit(7)']);
    expect(res.status).not.toBe(7);
    expect(res.stderr).toContain(ABSENT);
  });

  itIfBuilt('`run --only=NAME` binds the selector rather than injecting the whole store', () => {
    const res = cli(['run', `--only=${ABSENT}`, '--', process.execPath, '-e', 'process.exit(7)']);
    // On v0.22.0 `--only=NAME` is unparsed, so `only` stays undefined, undefined
    // means "inject every credential in the store", and the child RUNS —
    // exiting 7. The selector naming a nonexistent secret is what makes this
    // observable without printing anything: bound, it must refuse and name it.
    expect(res.status).not.toBe(7);
    expect(res.stderr).toContain(ABSENT);
  });
});

/**
 * An unrecognised SUBCOMMAND is refused, not answered with the default view.
 *
 * `cache` and `backend` were the last two subcommand dispatchers in the tree
 * that fell through to their status page on a token they did not recognise —
 * eight siblings already refused it. `telemetry` was a third instance wearing a
 * different coat: it printed "Unknown action" to STDOUT and returned 0, so the
 * message existed and the exit code still said success.
 *
 * Measured on 0.22.1, every row exit 0: `cache zzz`, `cache clea`, `cache ttls`,
 * `backend lst`, `backend sett`, `backend purg`. The last is the sharp one — a
 * near miss of the DESTRUCTIVE `purge`, where nothing in the output or the exit
 * code separated "purged" from "never ran".
 */
describe('an unknown subcommand is refused rather than answered', () => {
  const CLI_PATH2 = path.resolve(__dirname, '..', 'dist', 'cli.js');
  const hasBuild = fs.existsSync(CLI_PATH2);
  const itIfBuilt = hasBuild ? it : it.skip;

  function run(args: string[]) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-subcmd-'));
    try {
      return spawnSync(process.execPath, [CLI_PATH2, ...args], {
        encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], cwd: tmp,
        env: { ...process.env, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
      });
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }

  // CONTROLS FIRST. Absent is not the same as unrecognised: a bare verb is an
  // exploration and still prints its status view at exit 0. If these went red,
  // the guard below would be "refuses everything" rather than "refuses what it
  // does not know", and every row under it would pass for the wrong reason.
  itIfBuilt.each(['cache', 'backend', 'telemetry'])(
    'CONTROL: bare `%s` still prints its status view at exit 0',
    (verb) => {
      const res = run([verb]);
      expect(res.status, `${verb} bare must stay exit 0`).toBe(0);
      expect(res.stderr).not.toMatch(/Unknown/);
    },
  );

  itIfBuilt('`cache zzz` is refused instead of showing the cache status', () => {
    const res = run(['cache', 'zzz']);
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/Unknown cache command: zzz/);
    expect(res.stdout).not.toMatch(/Secret Cache/);
  });

  itIfBuilt('`cache clea` names the command it nearly matched', () => {
    const res = run(['cache', 'clea']);
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/did you mean `clear`/);
  });

  itIfBuilt('`backend purg` — a near miss of a DESTRUCTIVE verb — is refused and named', () => {
    const res = run(['backend', 'purg']);
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/did you mean `purge`/);
    expect(res.stdout).not.toMatch(/Secretless Backend/);
  });

  itIfBuilt('`telemetry bogus` refuses and says the setting was not changed', () => {
    const res = run(['telemetry', 'bogus']);
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/Unknown telemetry action: bogus/);
    // The whole point: the exit code used to be 0 while nothing was applied.
    expect(res.stderr).toMatch(/NOT changed/);
  });

  /**
   * The class, not the instances. Named rather than derived, so a dispatcher
   * added later with a silent fall-through has to show up here as a deliberate
   * edit instead of slipping past a predicate.
   *
   * Every verb below is safe to invoke with an unrecognised token precisely
   * BECAUSE it refuses first — that is the property under test. None is ever
   * invoked bare, which for `install` would install a launch agent.
   */
  itIfBuilt.each([
    'secret', 'broker', 'vault', 'scope', 'hook', 'rules', 'watch', 'install', 'cache', 'backend',
  ])('%s refuses an unrecognised subcommand and does not act on it', (verb) => {
    const res = run([verb, 'zzz-not-a-subcommand']);
    expect(res.status, `${verb} answered an unknown subcommand with success`).not.toBe(0);
    expect(`${res.stdout}${res.stderr}`).toMatch(/Unknown/);
  });
});

/**
 * `secret list` takes no argument. It used to accept one and ignore it —
 * measured on 0.22.1, `secret list <token>` returned every stored name,
 * byte-identical to the unfiltered run, at exit 0. A user who believes they
 * filtered and sees every name reads that as "these all match".
 */
describe('secret list does not accept a filter it will not apply', () => {
  const CLI_PATH3 = path.resolve(__dirname, '..', 'dist', 'cli.js');
  const hasBuild = fs.existsSync(CLI_PATH3);
  const itIfBuilt = hasBuild ? it : it.skip;

  function run(args: string[]) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-seclist-'));
    try {
      return spawnSync(process.execPath, [CLI_PATH3, ...args], {
        encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], cwd: tmp,
        env: { ...process.env, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
      });
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }

  itIfBuilt('refuses a positional rather than silently listing everything', () => {
    const res = run(['secret', 'list', 'ZZZ_NO_SUCH_PREFIX']);
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/takes no arguments/);
    expect(res.stderr).toMatch(/NOT filtered/);
    // It must not have printed the store contents anyway.
    expect(res.stdout).not.toMatch(/secret\(s\):/);
  });

  itIfBuilt('CONTROL: `secret list` with no argument still lists, exit 0', () => {
    const res = run(['secret', 'list']);
    expect(res.status).toBe(0);
    expect(res.stderr).not.toMatch(/takes no arguments/);
  });
});
