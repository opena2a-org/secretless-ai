/**
 * Shared by the tests of the env rule (src/mcp/env-secrets.ts) across the
 * commands that read it. Each CLI run gets an environment of its own and
 * nothing inherited: PATH holding a `node` link and the system directories,
 * a fresh home with the `local` backend, the OS keychain switched off, and
 * `security` and `secret-tool` stand-ins first on PATH that fail any call
 * reaching them. Values are built at run time, so no file holds one whole.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { CREDENTIAL_PATTERNS, PLACEHOLDER_INDICATORS } from './patterns';
import { isKnownExample } from './scan';

export const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');

export interface Sandbox {
  root: string;
  bin: string;
  home: string;
  project: string;
  env: NodeJS.ProcessEnv;
}

export function makeSandbox(): Sandbox {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-env-')));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  fs.symlinkSync(process.execPath, path.join(bin, 'node'));
  for (const tool of ['security', 'secret-tool']) {
    fs.writeFileSync(path.join(bin, tool), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  }
  const home = path.join(root, 'home');
  fs.mkdirSync(path.join(home, '.secretless-ai'), { recursive: true });
  fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify({ backend: 'local' }));
  const project = path.join(root, 'project');
  fs.mkdirSync(project);
  const env: NodeJS.ProcessEnv = {
    PATH: `${bin}:/usr/bin:/bin:/usr/sbin:/sbin`,
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, '.config'),
    OPENA2A_TELEMETRY: 'off',
    SECRETLESS_OS_KEYCHAIN: 'off',
    NO_COLOR: '1',
    HARNESS_NO_LIVE_TRANSPORT: '1',
    GIT_AUTHOR_NAME: 'Test',
    GIT_AUTHOR_EMAIL: 'test@localhost',
    GIT_COMMITTER_NAME: 'Test',
    GIT_COMMITTER_EMAIL: 'test@localhost',
  };
  return { root, bin, home, project, env };
}

export function removeSandbox(sb: Sandbox): void {
  fs.rmSync(sb.root, { recursive: true, force: true });
}

export interface Run {
  code: number | null;
  stdout: string;
  /** stdout and stderr together. */
  out: string;
}

/** The built CLI, run through the sandbox's `node` link with its environment. */
export function runCli(sb: Sandbox, args: string[], cwd: string = sb.project): Run {
  const r = spawnSync(path.join(sb.bin, 'node'), [CLI_PATH, ...args], {
    cwd,
    env: sb.env,
    encoding: 'utf-8',
    timeout: 120_000,
    maxBuffer: 256 * 1024 * 1024,
  });
  return { code: r.status, stdout: r.stdout ?? '', out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

export function git(sb: Sandbox, args: string[], cwd: string = sb.project): Run {
  const r = spawnSync('git', ['-c', 'init.defaultBranch=main', '-c', 'commit.gpgsign=false', ...args], {
    cwd,
    env: sb.env,
    encoding: 'utf-8',
    timeout: 120_000,
  });
  return { code: r.status, stdout: r.stdout ?? '', out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

export function write(dir: string, relativePath: string, content: string): string {
  const full = path.join(dir, relativePath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

/** Letters and digits; no `x`, so no run of them spells a placeholder word made of it. */
const ALNUM = 'ABCDEFGHJKLMNPQRSTUVWYZabcdefghijkmnopqrstuvwyz23456789';

/** `length` characters of `alphabet` from a seeded generator (mulberry32): the same seed, the same value. */
export function seeded(seed: number, length: number, alphabet: string = ALNUM): string {
  let a = seed >>> 0;
  let out = '';
  for (let i = 0; i < length; i++) {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    out += alphabet[Math.floor((((t ^ (t >>> 14)) >>> 0) / 4294967296) * alphabet.length)];
  }
  return out;
}

/** No placeholder word, more than six distinct characters: no value rule can hide it. */
export function holdsNoPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  return !PLACEHOLDER_INDICATORS.some((word) => lower.includes(word.toLowerCase())) && new Set(value).size > 6;
}

/**
 * A literal no value rule hides and no credential pattern matches: what only
 * the env rule can report. The first seed from `seed` up that gives one.
 */
export function literalValue(seed: number, length = 40): string {
  for (let s = seed; ; s++) {
    const value = seeded(s, length);
    if (holdsNoPlaceholder(value) && !CREDENTIAL_PATTERNS.some((p) => p.regex.test(value))) return value;
  }
}

/** A GitHub token the `github-pat` pattern reports: a real match, not a known example. */
export function githubToken(seed: number): string {
  const pattern = CREDENTIAL_PATTERNS.find((p) => p.id === 'github-pat')!;
  const prefix = ['gh', 'p', '_'].join('');
  for (let s = seed; ; s++) {
    const value = prefix + seeded(s, 36);
    const match = value.match(pattern.regex);
    if (match && holdsNoPlaceholder(value) && !isKnownExample('', match)) return value;
  }
}

/** Whether `output` holds a run of `run` consecutive characters of any of `values`. */
export function leaksRun(output: string, values: readonly string[], run = 8): boolean {
  return values.some((value) => {
    for (let i = 0; i + run <= value.length; i++) {
      if (output.includes(value.slice(i, i + run))) return true;
    }
    return false;
  });
}

/** An MCP server entry with this env. */
export function server(env: Record<string, string>, command = 'npx'): Record<string, unknown> {
  return { command, args: ['-y', 'svc-mcp'], env };
}
