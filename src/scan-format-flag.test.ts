import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * `scan --format <json|sarif>` through the built CLI: `sarif` writes SARIF
 * 2.1.0, `json` writes what `--json` writes, and a value the tool does not
 * write, `--format` with no value, or `--json` beside `--format sarif` is
 * refused with exit 2 and nothing on stdout, like any other command line the
 * tool cannot bind. Before the flag existed, `scan --format sarif` was refused
 * as an unknown option.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;

// The same real-looking key src/commands/scan-json.test.ts plants, joined at
// run time so that no source line has the shape of a provider token.
const REAL = ['sk-ant-api03-', 'aB3kP9xQ2mZvW7nY4tL6rJ8sH1cF5gD0eAbCdEfGhIjKlMnOpQr'].join('');

const made: string[] = [];

function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

function cli(args: string[]) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: os.tmpdir(),
    // A temporary HOME: the home-directory files a scan also reads are absent
    // there, so the tree is the whole result.
    env: { ...process.env, HOME: tmp('scan-format-home-'), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

function tree(): string {
  const dir = tmp('scan-format-');
  fs.writeFileSync(path.join(dir, 'config.js'), `const k = "${REAL}";\n`);
  return dir;
}

describe('scan --format', () => {
  itIfBuilt('`--format sarif` writes one SARIF 2.1.0 document and exits 1 on a finding', () => {
    const res = cli(['scan', tree(), '--format', 'sarif']);
    expect(res.status).toBe(1);
    expect(res.stderr).toBe('');
    const doc = JSON.parse(res.stdout);
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs[0].results).toHaveLength(1);
    expect(doc.runs[0].results[0].ruleId).toBe('anthropic');
    expect(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('config.js');
    expect(doc.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(1);
  });

  itIfBuilt('`--format=sarif` binds like the spaced form', () => {
    const res = cli(['scan', tree(), '--format=sarif']);
    expect(res.status).toBe(1);
    expect(JSON.parse(res.stdout).version).toBe('2.1.0');
  });

  itIfBuilt('`--format json` writes what `--json` writes', () => {
    const dir = tree();
    const viaFormat = cli(['scan', dir, '--format', 'json']);
    const viaJson = cli(['scan', dir, '--json']);
    expect(viaFormat.status).toBe(1);
    expect(viaJson.status).toBe(1);
    expect(JSON.parse(viaFormat.stdout)).toEqual(JSON.parse(viaJson.stdout));
    expect(JSON.parse(viaFormat.stdout).findings).toHaveLength(1);
  });

  itIfBuilt('a format the tool does not write is refused with exit 2 before anything runs', () => {
    const res = cli(['scan', tree(), '--format', 'yaml']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain('--format needs json or sarif, e.g. --format sarif, but was given "yaml".');
    expect(res.stderr).toContain('`scan` was not run. Nothing was changed.');
  });

  itIfBuilt('`--format` with no value is refused with exit 2', () => {
    const res = cli(['scan', tree(), '--format']);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain('--format needs a value, but none was given.');
  });

  itIfBuilt('`--json` beside `--format sarif` is refused with exit 2, whichever comes first', () => {
    for (const args of [['--json', '--format', 'sarif'], ['--format', 'sarif', '--json']]) {
      const res = cli(['scan', tree(), ...args]);
      expect(res.status, args.join(' ')).toBe(2);
      expect(res.stdout, args.join(' ')).toBe('');
      expect(res.stderr).toContain('--json and --format sarif ask for two formats on one output; give one of them.');
      expect(res.stderr).toContain('`scan` was not run. Nothing was changed.');
    }
  });

  itIfBuilt('`scan --help` names --format with its values', () => {
    const res = cli(['scan', '--help']);
    expect(res.status).toBe(0);
    expect(res.stdout).toContain('--format <json|sarif>');
  });
});
