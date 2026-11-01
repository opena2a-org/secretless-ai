import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { performance } from 'perf_hooks';
import { type Sandbox, CLI_PATH, git, literalValue, makeSandbox, removeSandbox, server, write } from './mcp-env-secret.test-support';

/**
 * A project MCP config is read in one forward pass: the time a command takes
 * grows with the size of the config, not with the square of its env entries.
 * Held on a 2 MB `.mcp.json` of servers with ten env entries each, every
 * value distinct and none hidden by a value rule: `scan`, `scan-staged` and
 * `verify` each finish in under five seconds. `scan` is timed with `--json`,
 * so the time is the reading and the report, not the terminal writing a
 * block for each of the findings one by one.
 */
const CONFIG_BYTES = 2 * 1024 * 1024;
const ENTRIES_PER_SERVER = 10;
const BOUND_MS = 5_000;

/** `count` distinct literals, each one `literalValue` gives. */
function distinctLiterals(count: number, firstSeed: number): string[] {
  const values = new Set<string>();
  for (let seed = firstSeed; values.size < count; seed++) values.add(literalValue(seed));
  return [...values];
}

/** A `.mcp.json` of at least `bytes` bytes, as `JSON.stringify` writes it with two-space indents. */
function largeMcpConfig(bytes: number): string {
  const keys = Array.from({ length: ENTRIES_PER_SERVER }, (_, i) => `SVC${i}_API_KEY`);
  const one = JSON.stringify({ svc0: server(Object.fromEntries(keys.map((k) => [k, literalValue(1)]))) }, null, 2);
  const servers = Math.ceil(bytes / (one.length - 4)) + 1;
  const values = distinctLiterals(servers * ENTRIES_PER_SERVER, 900_000);
  const mcpServers: Record<string, unknown> = {};
  for (let s = 0; s < servers; s++) {
    mcpServers[`svc${s}`] = server(Object.fromEntries(keys.map((k, i) => [k, values[s * ENTRIES_PER_SERVER + i]])));
  }
  return JSON.stringify({ mcpServers }, null, 2);
}

/** The built CLI run once, its output to files, and the time it took. */
function timedRun(sb: Sandbox, args: string[], label: string): { code: number | null; signal: NodeJS.Signals | null; ms: number } {
  const out = fs.openSync(path.join(sb.root, `${label}.out`), 'w');
  const err = fs.openSync(path.join(sb.root, `${label}.err`), 'w');
  try {
    const start = performance.now();
    const r = spawnSync(path.join(sb.bin, 'node'), [CLI_PATH, ...args], {
      cwd: sb.project,
      env: sb.env,
      stdio: ['ignore', out, err],
      timeout: 120_000,
    });
    return { code: r.status, signal: r.signal, ms: performance.now() - start };
  } finally {
    fs.closeSync(out);
    fs.closeSync(err);
  }
}

let sb: Sandbox;
beforeAll(() => {
  sb = makeSandbox();
  const config = largeMcpConfig(CONFIG_BYTES);
  expect(Buffer.byteLength(config)).toBeGreaterThanOrEqual(CONFIG_BYTES);
  write(sb.project, '.mcp.json', config);
  expect(git(sb, ['init', '-q']).code).toBe(0);
  expect(git(sb, ['add', '.mcp.json']).code).toBe(0);
}, 120_000);
afterAll(() => {
  removeSandbox(sb);
});

describe('a 2 MB project MCP config with ten env entries a server', () => {
  it.each([
    ['scan', ['scan', '.', '--json']],
    ['scan-staged', ['scan-staged']],
    ['verify', ['verify']],
  ])('%s reads it in under five seconds', (label, args) => {
    const run = timedRun(sb, args, label);
    expect(run.signal, `${label} ended by a signal`).toBeNull();
    expect([0, 1], `${label} exit code`).toContain(run.code);
    expect(run.ms, `${label} took ${Math.round(run.ms)} ms`).toBeLessThan(BOUND_MS);
  }, 120_000);
});
