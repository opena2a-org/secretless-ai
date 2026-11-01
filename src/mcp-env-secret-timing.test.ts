import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { type Sandbox, CLI_PATH, git, literalValue, makeSandbox, removeSandbox, server, write } from './mcp-env-secret.test-support';

/**
 * A project MCP config is read in one forward pass: the time a command takes
 * grows with the size of the config, not with the square of its env entries.
 * Held on two `.mcp.json` files of servers with ten env entries each, every
 * value distinct and none hidden by a value rule, one of 2 MB and one an
 * eighth of that size: `scan`, `scan-staged` and `verify` each take less
 * than GROWTH_BOUND times as much CPU time on the large config as on the
 * small one. A pass linear in the size takes at most SIZE_RATIO times as
 * much (less, since the start of the command costs the same on both), and
 * one that reads the text again per entry takes the square of that.
 * Measured on a laptop, the three commands take four to five times as much.
 *
 * The measure is the CPU time of the command's own process, user and system
 * together, written at its exit by a module `NODE_OPTIONS` loads; the `git`
 * commands `scan-staged` runs are not in it. Wall-clock time is not the
 * measure: on a shared machine or a small CI runner it measures the load of
 * the machine as much as the command, and the first form of this test, five
 * seconds of wall-clock time on the 2 MB config, passed or failed by that
 * load. `scan` is timed with `--json`, so the time is the reading and the
 * report, not the terminal writing a block for each of the findings one by
 * one.
 */
const CONFIG_BYTES = 2 * 1024 * 1024;
const ENTRIES_PER_SERVER = 10;
/** The large config is this many times the size of the small one. */
const SIZE_RATIO = 8;
/** The large config may take at most this many times the CPU time of the small one. */
const GROWTH_BOUND = 12;
/** The variable in the command's environment that names the file its CPU time is written to. */
const CPU_TIME_FILE_VAR = 'MCP_ENV_TIMING_CPU_FILE';

/** `count` distinct literals, each one `literalValue` gives. */
function distinctLiterals(count: number, firstSeed: number): string[] {
  const values = new Set<string>();
  for (let seed = firstSeed; values.size < count; seed++) values.add(literalValue(seed));
  return [...values];
}

/** A `.mcp.json` of at least `bytes` bytes, as `JSON.stringify` writes it with two-space indents. */
function mcpConfig(bytes: number): string {
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

/**
 * The module each timed command loads before the CLI: when the process
 * exits, it writes the CPU time the process used, user and system together
 * in microseconds, to the file the environment names.
 */
function writeCpuTimeModule(sb: Sandbox): string {
  return write(sb.root, 'cpu-time.cjs', [
    "const fs = require('fs');",
    "process.on('exit', () => {",
    '  const usage = process.cpuUsage();',
    `  fs.writeFileSync(process.env.${CPU_TIME_FILE_VAR}, String(usage.user + usage.system));`,
    '});',
    '',
  ].join('\n'));
}

/** A sandbox whose project holds a staged `.mcp.json` of at least `bytes` bytes. */
function prepare(bytes: number): Sandbox {
  const sb = makeSandbox();
  const config = mcpConfig(bytes);
  expect(Buffer.byteLength(config)).toBeGreaterThanOrEqual(bytes);
  write(sb.project, '.mcp.json', config);
  writeCpuTimeModule(sb);
  expect(git(sb, ['init', '-q']).code).toBe(0);
  expect(git(sb, ['add', '.mcp.json']).code).toBe(0);
  return sb;
}

interface TimedRun {
  code: number | null;
  signal: NodeJS.Signals | null;
  /** The CPU time of the command's process, user and system together. */
  cpuMs: number;
}

/** The built CLI run once in `sb`'s project, its output to files, and the CPU time its process used. */
function timedRun(sb: Sandbox, args: string[], label: string): TimedRun {
  const cpuFile = path.join(sb.root, `${label}.cpu`);
  const out = fs.openSync(path.join(sb.root, `${label}.out`), 'w');
  const err = fs.openSync(path.join(sb.root, `${label}.err`), 'w');
  try {
    const r = spawnSync(path.join(sb.bin, 'node'), [CLI_PATH, ...args], {
      cwd: sb.project,
      env: { ...sb.env, NODE_OPTIONS: `--require "${path.join(sb.root, 'cpu-time.cjs')}"`, [CPU_TIME_FILE_VAR]: cpuFile },
      stdio: ['ignore', out, err],
      timeout: 120_000,
    });
    expect(fs.existsSync(cpuFile), `${label}: the CPU time file is written when the command exits`).toBe(true);
    return { code: r.status, signal: r.signal, cpuMs: Number(fs.readFileSync(cpuFile, 'utf-8')) / 1000 };
  } finally {
    fs.closeSync(out);
    fs.closeSync(err);
  }
}

let small: Sandbox;
let large: Sandbox;
beforeAll(() => {
  small = prepare(CONFIG_BYTES / SIZE_RATIO);
  large = prepare(CONFIG_BYTES);
}, 120_000);
afterAll(() => {
  removeSandbox(small);
  removeSandbox(large);
});

describe('a 2 MB project MCP config with ten env entries a server, and one an eighth of its size', () => {
  it.each([
    ['scan', ['scan', '.', '--json']],
    ['scan-staged', ['scan-staged']],
    ['verify', ['verify']],
  ])(`%s takes less than ${GROWTH_BOUND} times as much CPU time on the large config as on the small one`, (label, args) => {
    const onSmall = timedRun(small, args, label);
    const onLarge = timedRun(large, args, label);
    for (const [size, run] of [['small', onSmall], ['large', onLarge]] as const) {
      expect(run.signal, `${label} on the ${size} config ended by a signal`).toBeNull();
      expect([0, 1], `${label} on the ${size} config: exit code`).toContain(run.code);
      expect(run.cpuMs, `${label} on the ${size} config: CPU time`).toBeGreaterThan(0);
    }
    const took = `${label} took ${Math.round(onLarge.cpuMs)} ms of CPU time on the large config and ${Math.round(onSmall.cpuMs)} ms on the small one`;
    expect(onLarge.cpuMs / onSmall.cpuMs, took).toBeLessThan(GROWTH_BOUND);
  }, 120_000);
});
