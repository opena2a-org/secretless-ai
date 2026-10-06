import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Findings from the 0.21.3 fresh-user walkthrough (#127), each pinned as the
 * user sees it: the built entry point, a temporary HOME, no colour.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const hasBuild = fs.existsSync(CLI_PATH);
const itIfBuilt = hasBuild ? it : it.skip;

function cli(args: string[], opts: { cwd?: string; home?: string } = {}) {
  const home = opts.home ?? fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-walk-home-'));
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: opts.cwd ?? os.tmpdir(),
    env: { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr, all: res.stdout + res.stderr };
}

describe('`-V` prints the version like `-v` and `--version` (#127)', () => {
  itIfBuilt('`-V` exits 0 with the version line, not "Unknown command"', () => {
    const upper = cli(['-V']);
    const lower = cli(['-v']);

    expect(upper.status).toBe(0);
    expect(upper.all).not.toContain('Unknown command');
    expect(upper.stdout).toBe(lower.stdout);
  });
});

describe('`init` on a path that is not a directory (#127)', () => {
  itIfBuilt('a missing directory gets a plain message with Verify and Fix, not a raw ENOENT', () => {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-walk-init-'));
    const missing = path.join(parent, 'does', 'not', 'exist');
    try {
      const res = cli(['init', missing]);

      expect(res.status).toBe(1);
      expect(res.all).not.toContain('ENOENT');
      expect(res.stderr).toContain(`Directory not found: ${missing}`);
      expect(res.stderr).toContain('Verify:');
      expect(res.stderr).toContain('Fix:');
      // Nothing was created on the way to the error.
      expect(fs.existsSync(path.join(parent, 'does'))).toBe(false);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });

  itIfBuilt('a file path is named as not a directory, and the file is left alone', () => {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-walk-init-'));
    const file = path.join(parent, 'notes.txt');
    fs.writeFileSync(file, 'keep me\n');
    try {
      const res = cli(['init', file]);

      expect(res.status).toBe(1);
      expect(res.all).not.toContain('ENOTDIR');
      expect(res.stderr).toContain(`Not a directory: ${file}`);
      expect(res.stderr).toContain('Fix:');
      expect(fs.readFileSync(file, 'utf-8')).toBe('keep me\n');
      expect(fs.readdirSync(parent)).toEqual(['notes.txt']);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });
});

describe('the `--max-files` Fix clears the truncation it reports (#127)', () => {
  itIfBuilt('the suggested cap is the eligible count, and following it leaves nothing truncated', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-walk-cap-'));
    try {
      for (let i = 0; i < 30; i++) fs.writeFileSync(path.join(dir, `f${i}.js`), `const a${i} = 1;\n`);

      const capped = cli(['scan', dir, '--max-files', '2']);
      expect(capped.status).toBe(1);
      const fix = capped.stdout.match(/Fix:\s+npx secretless-ai scan \S+ --max-files (\d+)/);
      expect(fix).not.toBeNull();
      // The old suggestion was the cap times four: 8, which left 22 unscanned.
      expect(Number(fix![1])).toBe(30);

      const followed = cli(['scan', dir, '--max-files', fix![1], '--json']);
      expect(JSON.parse(followed.stdout).summary.truncated).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
