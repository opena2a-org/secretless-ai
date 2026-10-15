import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { REPO_ROOT } from './tape.test-support';

/**
 * docs/vhs/record-init.sh before the render: what it measures on the host and
 * hands to the container that writes the sidecar (docs/vhs/init.json). Each
 * test runs a copy of the script in a new git repository that holds the files
 * the script reads, with `docker` and `npm` replaced by stand-ins, so nothing
 * is built, downloaded or rendered. The stand-in for `docker` writes down the
 * arguments of each call.
 *
 * The part of the script that runs inside the recording image is read, not
 * run: it starts with `cd /work`.
 */

const SCRIPT = 'docs/vhs/record-init.sh';
const FIXTURE_SCRIPT = 'docs/vhs/setup-fixture.sh';

const read = (file: string) => fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8');

let base: string;
let repo: string;
let dockerLog: string;

function write(file: string, content: string, mode = 0o644): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, { mode });
}

const childEnv = (): NodeJS.ProcessEnv => ({
  PATH: `${path.join(base, 'bin')}${path.delimiter}${process.env.PATH}`,
  HOME: path.join(base, 'home'),
  TMPDIR: path.join(base, 'tmp'),
  DOCKER: path.join(base, 'bin', 'docker'),
  DOCKER_LOG: dockerLog,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  SECRETLESS_OS_KEYCHAIN: 'off',
});

function git(...args: string[]): void {
  const result = spawnSync(
    'git',
    ['-C', repo, '-c', 'user.name=test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', ...args],
    { env: childEnv(), encoding: 'utf-8' },
  );
  expect(result.status, result.stderr).toBe(0);
}

const record = () => spawnSync('bash', [path.join(repo, SCRIPT)], { cwd: repo, env: childEnv(), encoding: 'utf-8' });

/** The arguments of each `docker` call, in order. */
function dockerCalls(): string[][] {
  if (!fs.existsSync(dockerLog)) return [];
  return fs.readFileSync(dockerLog, 'utf-8').split('--end--\n').filter(Boolean).map(call => call.split('\n').filter(Boolean));
}

/** The NAME=value pairs a `docker run` call passes with -e. */
const passedVariables = (call: string[]) => call.flatMap((arg, i) => (call[i - 1] === '-e' ? [arg] : []));

beforeEach(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), 'record-init-'));
  repo = path.join(base, 'repo');
  dockerLog = path.join(base, 'docker-calls.txt');
  fs.mkdirSync(path.join(base, 'home'));
  fs.mkdirSync(path.join(base, 'tmp'));
  write(path.join(base, 'bin', 'docker'), '#!/bin/sh\nfor arg in "$@"; do printf \'%s\\n\' "$arg"; done >> "$DOCKER_LOG"\necho --end-- >> "$DOCKER_LOG"\n', 0o755);
  // `npm view --json` prints a published version's integrity as a JSON string.
  write(path.join(base, 'bin', 'npm'), '#!/bin/sh\nif [ "$1" = view ]; then echo \'"sha512-FAKE-INTEGRITY"\'; exit 0; fi\nexit 1\n', 0o755);

  write(path.join(repo, SCRIPT), read(SCRIPT), 0o755);
  write(path.join(repo, FIXTURE_SCRIPT), read(FIXTURE_SCRIPT), 0o755);
  write(path.join(repo, 'package.json'), '{ "version": "0.0.0" }\n');
  write(path.join(repo, 'docs/vhs/docker/Dockerfile'), 'placeholder\n');
  write(path.join(repo, 'docs/vhs/docker/vhs-0.12.0-render-context.patch'), 'placeholder\n');
  git('init', '-q');
  git('add', '.');
  git('commit', '-q', '-m', 'fixture');
});

afterEach(() => {
  fs.rmSync(base, { recursive: true, force: true });
});

describe('docs/vhs/record-init.sh on the host', () => {
  it('passes the container the hash of the committed fixture script and the 0 that git status counts for it', () => {
    const result = record();
    expect(result.status, result.stderr).toBe(0);
    const run = dockerCalls().find(call => call[0] === 'run');
    expect(run, 'docker run was called').toBeDefined();
    const fixtureSha = createHash('sha256').update(fs.readFileSync(path.join(repo, FIXTURE_SCRIPT))).digest('hex');
    expect(passedVariables(run!)).toEqual(expect.arrayContaining([
      `FIXTURE_SHA=${fixtureSha}`,
      'FIXTURE_UNCOMMITTED_CHANGES=0',
    ]));
  });

  it('refuses to render when the fixture script has an uncommitted change, before any docker call', () => {
    fs.appendFileSync(path.join(repo, FIXTURE_SCRIPT), '# an edit that is not committed\n');
    const result = record();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`record-init.sh: git status reports uncommitted changes to ${FIXTURE_SCRIPT}`);
    expect(dockerCalls()).toEqual([]);
  });

  it('refuses a staged change to the fixture script that is not committed', () => {
    fs.appendFileSync(path.join(repo, FIXTURE_SCRIPT), '# an edit that is staged only\n');
    git('add', FIXTURE_SCRIPT);
    const result = record();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`record-init.sh: git status reports uncommitted changes to ${FIXTURE_SCRIPT}`);
    expect(dockerCalls()).toEqual([]);
  });
});

describe('docs/vhs/record-init.sh inside the recording image (read from the script)', () => {
  it('writes fixtureUncommittedChanges from the count the host passed, and records no render with another count', () => {
    const script = read(SCRIPT);
    expect(script).toContain('fixtureUncommittedChanges: Number(env.FIXTURE_UNCOMMITTED_CHANGES),');
    expect(script).toContain('if [ "${FIXTURE_UNCOMMITTED_CHANGES:-}" != "0" ]; then');
  });

  it('hashes the tape into one field only', () => {
    expect(read(SCRIPT).match(/sha\(env\.TAPE\)/g)).toEqual(['sha(env.TAPE)']);
  });
});
