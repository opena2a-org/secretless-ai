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
 * arguments of each call, and the DOCKER_CONFIG, the DOCKER_HOST and the
 * config.json each call ran with. It answers `docker context inspect` with
 * STAND_IN_CONTEXT_HOST, and `docker run` writes STAND_IN_SIDECAR as the
 * sidecar into the directory mounted at /work/docs/vhs, where the recording
 * container writes it; each is skipped when its value is empty.
 *
 * The part of the script that runs inside the recording image is read, not
 * run: it starts with `cd /work`.
 */

const SCRIPT = 'docs/vhs/record-init.sh';
const FIXTURE_SCRIPT = 'docs/vhs/setup-fixture.sh';
const CONTEXT_HOST = 'unix:///tmp/stand-in-docker.sock';
const SIDECAR_WRITTEN = { version: '0.0.0', meteredCostUsd: 0, wallClockSeconds: 27.1 };

const read = (file: string) => fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8');

let base: string;
let repo: string;
let dockerLog: string;
let dockerEnvLog: string;

function write(file: string, content: string, mode = 0o644): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, { mode });
}

const DOCKER_STAND_IN = `#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const args = process.argv.slice(2);
const env = process.env;
fs.appendFileSync(env.DOCKER_LOG, args.map(arg => arg + '\\n').join('') + '--end--\\n');
let config = null;
if (env.DOCKER_CONFIG) {
  try { config = fs.readFileSync(path.join(env.DOCKER_CONFIG, 'config.json'), 'utf-8'); } catch {}
}
const seen = { command: args[0], dockerConfig: env.DOCKER_CONFIG ?? null, dockerHost: env.DOCKER_HOST ?? null, config };
fs.appendFileSync(env.DOCKER_ENV_LOG, JSON.stringify(seen) + '\\n');
if (args[0] === 'context' && env.STAND_IN_CONTEXT_HOST) console.log(env.STAND_IN_CONTEXT_HOST);
if (args[0] === 'run' && env.STAND_IN_SIDECAR) {
  const mount = args.find(arg => arg.endsWith(':/work/docs/vhs'));
  fs.writeFileSync(path.join(mount.slice(0, -':/work/docs/vhs'.length), 'init.json'), env.STAND_IN_SIDECAR);
}
`;

const childEnv = (): NodeJS.ProcessEnv => ({
  PATH: `${path.join(base, 'bin')}${path.delimiter}${process.env.PATH}`,
  HOME: path.join(base, 'home'),
  TMPDIR: path.join(base, 'tmp'),
  DOCKER: path.join(base, 'bin', 'docker'),
  DOCKER_LOG: dockerLog,
  DOCKER_ENV_LOG: dockerEnvLog,
  STAND_IN_CONTEXT_HOST: CONTEXT_HOST,
  STAND_IN_SIDECAR: JSON.stringify(SIDECAR_WRITTEN, null, 2) + '\n',
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

const record = (env: NodeJS.ProcessEnv = {}) =>
  spawnSync('bash', [path.join(repo, SCRIPT)], { cwd: repo, env: { ...childEnv(), ...env }, encoding: 'utf-8' });

/** The arguments of each `docker` call, in order. */
function dockerCalls(): string[][] {
  if (!fs.existsSync(dockerLog)) return [];
  return fs.readFileSync(dockerLog, 'utf-8').split('--end--\n').filter(Boolean).map(call => call.split('\n').filter(Boolean));
}

/** What each `docker` call ran with, in order. */
type DockerSeen = { command: string; dockerConfig: string | null; dockerHost: string | null; config: string | null };
function dockerSeen(): DockerSeen[] {
  if (!fs.existsSync(dockerEnvLog)) return [];
  return fs.readFileSync(dockerEnvLog, 'utf-8').split('\n').filter(Boolean).map(line => JSON.parse(line));
}

/** The NAME=value pairs a `docker run` call passes with -e. */
const passedVariables = (call: string[]) => call.flatMap((arg, i) => (call[i - 1] === '-e' ? [arg] : []));

beforeEach(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), 'record-init-'));
  repo = path.join(base, 'repo');
  dockerLog = path.join(base, 'docker-calls.txt');
  dockerEnvLog = path.join(base, 'docker-seen.jsonl');
  fs.mkdirSync(path.join(base, 'home'));
  fs.mkdirSync(path.join(base, 'tmp'));
  write(path.join(base, 'bin', 'docker'), DOCKER_STAND_IN, 0o755);
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

describe('docs/vhs/record-init.sh and the docker configuration', () => {
  /** A caller configuration as Docker Desktop writes it: a credential helper for every registry, and one for ghcr.io. */
  const writeCallerConfig = (dir: string) =>
    write(path.join(dir, 'config.json'), JSON.stringify({ credsStore: 'desktop', credHelpers: { 'ghcr.io': 'desktop' } }) + '\n');

  it('runs docker build and docker run with a configuration of its own that names no credential helper and holds no registry credentials', () => {
    writeCallerConfig(path.join(base, 'home', '.docker'));
    const result = record();
    expect(result.status, result.stderr).toBe(0);
    const builds = dockerSeen().filter(seen => seen.command === 'build' || seen.command === 'run');
    expect(builds.map(seen => seen.command)).toEqual(['build', 'run']);
    for (const seen of builds) {
      expect(seen.dockerConfig).not.toBeNull();
      expect(seen.dockerConfig).not.toBe(path.join(base, 'home', '.docker'));
      // Exactly this and nothing else: no credsStore, no credHelpers, no auths.
      expect(JSON.parse(seen.config!)).toEqual({ cliPluginsExtraDirs: [path.join(base, 'home', '.docker', 'cli-plugins')] });
      expect(seen.dockerHost).toBe(CONTEXT_HOST);
    }
    expect(builds[1].dockerConfig).toBe(builds[0].dockerConfig);
  });

  it('reads the endpoint of the docker context in use with the caller configuration, before docker build', () => {
    const result = record();
    expect(result.status, result.stderr).toBe(0);
    expect(dockerCalls()[0]).toEqual(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}']);
    expect(dockerSeen()[0]).toMatchObject({ command: 'context', dockerConfig: null, dockerHost: null });
    expect(dockerCalls().map(call => call[0])).toEqual(['context', 'build', 'run']);
  });

  it('takes the plugin directory from the DOCKER_CONFIG the caller set', () => {
    const callerConfig = path.join(base, 'caller-docker-config');
    writeCallerConfig(callerConfig);
    const result = record({ DOCKER_CONFIG: callerConfig });
    expect(result.status, result.stderr).toBe(0);
    expect(dockerSeen()[0]).toMatchObject({ command: 'context', dockerConfig: callerConfig });
    const build = dockerSeen().find(seen => seen.command === 'build')!;
    expect(build.dockerConfig).not.toBe(callerConfig);
    expect(JSON.parse(build.config!)).toEqual({ cliPluginsExtraDirs: [path.join(callerConfig, 'cli-plugins')] });
  });

  it('keeps a DOCKER_HOST the caller set and does not ask docker for the context endpoint', () => {
    const result = record({ DOCKER_HOST: 'unix:///tmp/caller-docker.sock' });
    expect(result.status, result.stderr).toBe(0);
    expect(dockerCalls().map(call => call[0])).toEqual(['build', 'run']);
    for (const seen of dockerSeen()) expect(seen.dockerHost).toBe('unix:///tmp/caller-docker.sock');
  });

  it('refuses to build when docker names no endpoint for the context in use', () => {
    const result = record({ STAND_IN_CONTEXT_HOST: '' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('context inspect named no endpoint for the docker context in use; set DOCKER_HOST and run again.');
    expect(dockerCalls().map(call => call[0])).toEqual(['context']);
  });

  it('removes its docker configuration directory when the script ends', () => {
    const result = record();
    expect(result.status, result.stderr).toBe(0);
    const own = dockerSeen().find(seen => seen.command === 'build')!.dockerConfig;
    expect(own, 'docker build ran with a DOCKER_CONFIG of the script').toEqual(expect.any(String));
    // It held config.json while docker ran.
    expect(dockerSeen().find(seen => seen.command === 'build')!.config).not.toBeNull();
    expect(fs.existsSync(own!)).toBe(false);
  });
});

describe('docs/vhs/record-init.sh after the render', () => {
  it("ends with a line naming the sidecar's sha256, the version, meteredCostUsd and wallClockSeconds", () => {
    const result = record();
    expect(result.status, result.stderr).toBe(0);
    const sidecar = path.join(repo, 'docs/vhs/init.json');
    const digest = createHash('sha256').update(fs.readFileSync(sidecar)).digest('hex');
    expect(result.stdout.trimEnd().split('\n').pop()).toBe(
      `sidecar: docs/vhs/init.json sha256 ${digest}, version 0.0.0, meteredCostUsd 0, wallClockSeconds 27.1`,
    );
  });

  it('exits 1 when the render wrote no sidecar', () => {
    const result = record({ STAND_IN_SIDECAR: '' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('record-init.sh: the render wrote no docs/vhs/init.json.');
    expect(result.stdout).not.toContain('sidecar: ');
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
