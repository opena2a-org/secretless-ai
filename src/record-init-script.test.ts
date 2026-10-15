import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { REPO_ROOT } from './tape.test-support';

/**
 * The render script itself, run with stand-ins for docker and npm so that no
 * image is built and nothing is packed. Two promises are held here: a render
 * never starts with a model API key in its environment, and `--dry-run` says
 * what a render would use and touches nothing.
 *
 *   docs/vhs/record-init.sh             renders the tape and writes the sidecar
 *   docs/vhs/record-init.sh --dry-run   prints what a render would use, then exits 0
 */

const SCRIPT = 'docs/vhs/record-init.sh';
const SIDECAR = 'docs/vhs/init.json';
const RECORDING = 'docs/vhs/init.gif';
const CAPTURE = 'docs/vhs/init-capture.txt';

const sha256 = (file: string) => createHash('sha256').update(fs.readFileSync(path.join(REPO_ROOT, file))).digest('hex');
const sidecar = () => JSON.parse(fs.readFileSync(path.join(REPO_ROOT, SIDECAR), 'utf-8'));
const packageVersion = () => JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf-8')).version;

let sandbox: string;
let calls: string;

/** What `npm view --json` prints and exits with, as npm 10 and 11 answer it. */
type NpmView = { stdout: string; status: number };
const PUBLISHED: NpmView = { stdout: '"sha512-FAKE-INTEGRITY"', status: 0 };
const NOT_PUBLISHED: NpmView = {
  stdout: JSON.stringify({ error: { code: 'E404', summary: 'No match found for version 0.0.0' } }),
  status: 1,
};
/** The view call the script makes; the stand-ins log it. */
const npmView = () => `npm view secretless-ai@${packageVersion()} dist.integrity --json`;

/** A stand-in that logs its arguments; `npm view` answers with `view` when given one, else exits 1. */
function standIn(name: string, view?: NpmView): string {
  const file = path.join(sandbox, 'bin', name);
  let answer = '';
  if (view) {
    const output = path.join(sandbox, `${name}-view.out`);
    fs.writeFileSync(output, `${view.stdout}\n`);
    answer = `[ "$1" = view ] && { cat "${output}"; exit ${view.status}; }\n`;
  }
  fs.writeFileSync(file, `#!/bin/sh\necho "${name} $*" >> "${calls}"\n${answer}exit 1\n`, { mode: 0o755 });
  return file;
}

/**
 * Runs the script with an environment built from nothing, so a key set in the
 * shell that runs the tests cannot reach it, and with the stand-ins first on
 * PATH. With `npm` set to 'real npm' there is no npm stand-in and the npm on
 * PATH answers. Returns the exit code, the output and every call the stand-ins
 * logged.
 */
function run(args: string[], extraEnv: Record<string, string> = {}, npm: NpmView | 'real npm' = NOT_PUBLISHED) {
  fs.rmSync(calls, { force: true });
  if (npm === 'real npm') fs.rmSync(path.join(sandbox, 'bin', 'npm'), { force: true });
  else standIn('npm', npm);
  const docker = standIn('docker');
  const result = spawnSync('bash', [path.join(REPO_ROOT, SCRIPT), ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf-8',
    env: {
      PATH: `${path.join(sandbox, 'bin')}:${process.env.PATH}`,
      HOME: path.join(sandbox, 'home'),
      DOCKER: docker,
      ...extraEnv,
    },
  });
  const logged = fs.existsSync(calls) ? fs.readFileSync(calls, 'utf-8').trim().split('\n') : [];
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, calls: logged };
}

/** The committed files a render writes, by hash, so a test can tell that none of them changed. */
const writtenFiles = () => [SIDECAR, RECORDING, CAPTURE].map(file => `${file} ${sha256(file)}`);

beforeAll(() => {
  sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'record-init-'));
  fs.mkdirSync(path.join(sandbox, 'bin'));
  fs.mkdirSync(path.join(sandbox, 'home'));
  calls = path.join(sandbox, 'calls.log');
});

afterAll(() => {
  fs.rmSync(sandbox, { recursive: true, force: true });
});

describe('record-init.sh refuses to start with a model API key in its environment', () => {
  for (const [name, args] of [
    ['ANTHROPIC_API_KEY', []],
    ['OPENAI_API_KEY', []],
    ['ANTHROPIC_API_KEY', ['--dry-run']],
  ] as const) {
    it(`exits 2 with ${name} set${args.length ? ` and ${args.join(' ')}` : ''}, before it calls npm or docker`, () => {
      const before = writtenFiles();
      const r = run([...args], { [name]: 'x' });
      expect(r.status).toBe(2);
      expect(r.stderr).toContain('ANTHROPIC_API_KEY or OPENAI_API_KEY is set');
      expect(r.calls).toEqual([]);
      expect(writtenFiles()).toEqual(before);
    });
  }

  it('counts a key that is set to the empty string as set', () => {
    const r = run([], { OPENAI_API_KEY: '' });
    expect(r.status).toBe(2);
    expect(r.calls).toEqual([]);
  });
});

describe('record-init.sh --dry-run', () => {
  it('names the image, the build, the tape, the fixture and the files a render writes, and exits 0', () => {
    const before = writtenFiles();
    const r = run(['--dry-run'], {}, PUBLISHED);
    expect(r.stderr).toBe('');
    expect(r.status).toBe(0);
    const s = sidecar();
    const version = packageVersion();
    expect(r.stdout).toContain(`secretless-vhs:${version}`);
    expect(r.stdout).toContain(`secretless-ai@${version} from npm (sha512-FAKE-INTEGRITY)`);
    for (const base of ['golang:1.26-trixie', 'node:22.20.0-trixie-slim', 'ghcr.io/charmbracelet/vhs:latest']) {
      expect(r.stdout).toContain(base);
    }
    expect(r.stdout).toContain(s.tape);
    expect(r.stdout).toContain(s.fixtureScript);
    for (const file of [s.outputs.gif.path, s.outputs.capture, SIDECAR, s.outputs.mp4.path]) {
      expect(r.stdout).toContain(file);
    }
    expect(r.stdout).toContain("docker    a configuration of the script's own, with no credential helper and no registry credentials");
    expect(writtenFiles()).toEqual(before);
  });

  it('asks npm which build is published and calls nothing else: no docker, no build, no pack', () => {
    const r = run(['--dry-run'], {}, PUBLISHED);
    expect(r.status).toBe(0);
    expect(r.calls).toEqual([npmView()]);
  });

  it('names the commit it would pack when npm answers E404 for the version', () => {
    const head = spawnSync('git', ['-C', REPO_ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf-8' }).stdout.trim();
    const r = run(['--dry-run'], {}, NOT_PUBLISHED);
    expect(r.stderr).toBe('');
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(`npm pack of commit ${head}`);
    expect(r.calls).toEqual([npmView()]);
  });
});

describe('record-init.sh when npm cannot say whether the version is published', () => {
  // Port 9 refuses at once, and npm makes no retry, so each run takes well under a second.
  const unreachable = { npm_config_registry: 'http://127.0.0.1:9/', npm_config_fetch_retries: '0' };

  for (const args of [['--dry-run'], []]) {
    it(`exits 1 naming the registry error and packs nothing when the registry refuses the connection${args.length ? ', with --dry-run' : ''}`, () => {
      const before = writtenFiles();
      const r = run(args, unreachable, 'real npm');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('ECONNREFUSED');
      expect(r.stderr).toContain('127.0.0.1:9');
      expect(r.stdout).not.toContain('npm pack of commit');
      expect(r.calls).toEqual([]);
      expect(writtenFiles()).toEqual(before);
    });
  }

  it('exits 1 when npm view fails and prints no error code', () => {
    const r = run(['--dry-run'], {}, { stdout: '', status: 1 });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('npm view secretless-ai@');
    expect(r.stdout).not.toContain('npm pack of commit');
    expect(r.calls).toEqual([npmView()]);
  });
});

describe('record-init.sh arguments', () => {
  it('refuses an argument it does not know, before it calls npm or docker', () => {
    const r = run(['--dryrun']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('usage: docs/vhs/record-init.sh [--dry-run]');
    expect(r.calls).toEqual([]);
  });
});
