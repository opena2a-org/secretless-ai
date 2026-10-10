import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * The usage event names the command that ran, and nothing typed in its place.
 *
 * The event's `name` field carries a command name. The first argument was sent
 * there as typed, so `secretless-ai ./some/dir` sent the path, and the run,
 * which printed "Unknown command" and did nothing, was recorded as a success.
 *
 * Each case prints the event with OPENA2A_TELEMETRY_DEBUG=print and sends it
 * to a closed port on this machine, with no proxy, so nothing leaves it.
 */

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;
const PREFIX = '[opena2a:telemetry] ';

const made: string[] = [];
function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

/** The events the CLI printed for `args`, parsed, and its exit code. */
function run(args: string[]): { status: number | null; events: Array<Record<string, unknown>> } {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: tmp('telemetry-home-'),
    NO_COLOR: '1',
    OPENA2A_TELEMETRY_DEBUG: 'print',
    OPENA2A_TELEMETRY_URL: 'http://127.0.0.1:9/',
  };
  // Telemetry has to be on for an event to be built at all.
  for (const name of ['OPENA2A_TELEMETRY', 'XDG_CONFIG_HOME', 'NODE_USE_ENV_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']) {
    delete env[name];
  }
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: tmp('telemetry-cwd-'),
    env,
  });
  const printed = res.stderr.split('\n').filter((l) => l.startsWith(PREFIX));
  return { status: res.status, events: printed.map((l) => JSON.parse(l.slice(PREFIX.length)) as Record<string, unknown>) };
}

describe('the usage event names the command that ran, not what was typed in its place', () => {
  itIfBuilt('a path given where a command goes is sent as `unknown`, and the run is not a success', () => {
    const dir = path.join(tmp('telemetry-'), 'private-proj');

    const res = run([dir]);

    expect(res.status).toBe(1);
    expect(res.events).toHaveLength(1);
    expect(res.events[0]).toMatchObject({ event: 'command', name: 'unknown', success: false });
    expect(JSON.stringify(res.events)).not.toContain('private-proj');
  });

  itIfBuilt('a mistyped command is sent as `unknown`', () => {
    const res = run(['scna', '.']);

    expect(res.status).toBe(1);
    expect(res.events).toHaveLength(1);
    expect(res.events[0]).toMatchObject({ event: 'command', name: 'unknown', success: false });
  });

  itIfBuilt('CONTROL: a command that ran is sent by its name, and a clean scan is a success', () => {
    const res = run(['scan', tmp('telemetry-scan-'), '--json']);

    expect(res.status).toBe(0);
    expect(res.events).toHaveLength(1);
    expect(res.events[0]).toMatchObject({ event: 'command', name: 'scan', success: true });
  });
});
