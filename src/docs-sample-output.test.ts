import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';

/**
 * The guides promise "expected output so you know it worked" (docs/USE-CASES.md).
 * A sample written by hand once and never run again drifts the first time the
 * command's output changes, and nothing tells the reader: #337 counted thirteen
 * guide blocks and one README block showing lines the tool no longer printed.
 *
 * Each test here runs the documented command against a fixture and compares
 * what it prints with the block that follows the command in the doc, line for
 * line. Values that differ on every run or machine (the temporary HOME, PIDs,
 * ports, times, the platform keychain's name) are mapped to what the doc shows;
 * nothing else is.
 *
 * Commands that write secrets run in this process against a local encrypted
 * store in a temporary directory, never against the OS keychain or a vault.
 * The rest run the built CLI with a temporary HOME, as a user would.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const CLI_PATH = path.join(REPO_ROOT, 'dist', 'cli.js');
const DAEMON_PATH = path.join(REPO_ROOT, 'dist', 'broker', 'daemon.js');
const hasBuild = fs.existsSync(CLI_PATH) && fs.existsSync(DAEMON_PATH);
const itIfBuilt = hasBuild ? it : it.skip;
const TEST_TIMEOUT_MS = 30_000;

const README = 'README.md';
const PROTECT_GUIDE = 'docs/use-cases/protect-my-credentials.md';
const MCP_GUIDE = 'docs/use-cases/secure-mcp-configs.md';
const TEAM_GUIDE = 'docs/use-cases/team-setup.md';
const DOTENV_GUIDE = 'docs/use-cases/migrate-from-dotenv.md';
const BROKER_GUIDE = 'docs/use-cases/run-broker.md';

/**
 * Where the in-process commands store secrets, the backend name that store
 * reports (empty keeps the file's own `local`), and what `setup` is typed.
 */
const fixture = vi.hoisted(() => ({
  storeDir: '',
  backendName: '',
  mcpHome: '',
  wrapperPath: '',
  answers: [] as string[],
}));

vi.mock('./backends/factory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./backends/factory')>();
  const { LocalBackend } = await vi.importActual<typeof import('./backends/local')>('./backends/local');
  return {
    ...actual,
    createBackend: () => {
      const backend = new LocalBackend({ storeDir: fixture.storeDir, key: 'docs-sample-output' });
      if (fixture.backendName) Object.defineProperty(backend, 'name', { value: fixture.backendName });
      return backend;
    },
  };
});

// The home directory, store and wrapper the built `protect-mcp` would use,
// pointed at the fixture.
vi.mock('./mcp/protect', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./mcp/protect')>();
  return {
    ...actual,
    protectMcp: (options: Parameters<typeof actual.protectMcp>[0]) => actual.protectMcp({
      ...options,
      homeDir: fixture.mcpHome,
      dataDir: path.join(fixture.mcpHome, '.secretless-ai'),
      backendType: 'local',
      wrapperPath: fixture.wrapperPath,
    }),
  };
});

// A terminal echoes what is typed after the prompt; `setup` reads from one.
vi.mock('readline', async (importOriginal) => {
  const actual = await importOriginal<typeof import('readline')>();
  const createInterface = (opts: { output: NodeJS.WritableStream }) => ({
    question(prompt: string, answer: (typed: string) => void) {
      const typed = fixture.answers.shift() ?? '';
      opts.output.write(`${prompt}${typed}\n`);
      answer(typed);
    },
    // `setup` listens for the input closing (Ctrl-D); typed answers never close it.
    on() { return this; },
    close() {},
  });
  return { ...actual, default: { ...actual, createInterface }, createInterface };
});

import { runProtectMcp } from './commands/mcp';
import { runImport, runSetupCommand } from './commands/env-run';

fixture.wrapperPath = path.join(REPO_ROOT, 'dist', 'mcp-wrapper.js');

const dirs: string[] = [];
const pids: number[] = [];
const savedHome = process.env.HOME;

afterEach(() => {
  vi.restoreAllMocks();
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  fixture.answers = [];
  fixture.backendName = '';
  for (const pid of pids.splice(0)) {
    try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ }
  }
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function tempDir(): string {
  // Short prefix: the broker's unix socket lives under HOME, and socket paths
  // are capped at 104 bytes on macOS.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sldoc-'));
  dirs.push(dir);
  return dir;
}

// ---------------------------------------------------------------------------
// Reading the docs
// ---------------------------------------------------------------------------

interface Block { start: number; body: string[] }

function fencedBlocks(file: string): { lines: string[]; blocks: Block[] } {
  const lines = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8').split('\n');
  const blocks: Block[] = [];
  let open: Block | null = null;
  lines.forEach((line, i) => {
    if (/^```/.test(line)) {
      if (open) {
        blocks.push(open);
        open = null;
      } else {
        open = { start: i, body: [] };
      }
    } else if (open) {
      (open as Block).body.push(line);
    }
  });
  return { lines, blocks };
}

/** The first fenced block after the first block that runs `npx secretless-ai <command>`. */
function sampleAfter(file: string, command: string): string {
  const { blocks } = fencedBlocks(file);
  const at = blocks.findIndex(b => b.body.some(l => l.trim() === `npx secretless-ai ${command}`));
  if (at === -1 || at + 1 >= blocks.length) {
    throw new Error(`${file}: no sample block follows \`npx secretless-ai ${command}\``);
  }
  return blocks[at + 1].body.join('\n');
}

/** The first fenced block after the first line containing `text`. */
function blockAfterText(file: string, text: string): string {
  const { lines, blocks } = fencedBlocks(file);
  const line = lines.findIndex(l => l.includes(text));
  const block = blocks.find(b => b.start > line);
  if (line === -1 || !block) throw new Error(`${file}: no block follows "${text}"`);
  return block.body.join('\n');
}

// ---------------------------------------------------------------------------
// Running the commands
// ---------------------------------------------------------------------------

/** What a user sees: no colour, the temporary HOME shown as the doc's, no trailing blanks. */
function normalize(output: string, home?: string): string {
  let text = output.replace(/\x1b\[[0-9;]*m/g, '');
  if (home) {
    for (const form of new Set([fs.realpathSync(home), home])) text = text.split(form).join('/Users/you');
  }
  return text
    .split('\n')
    .map(line => line.replace(/\s+$/, ''))
    .join('\n')
    .replace(/^\n+/, '')
    .replace(/\n+$/, '');
}

function envFor(home: string, extraPath?: string): NodeJS.ProcessEnv {
  return {
    ...process.env,
    HOME: home,
    OPENA2A_TELEMETRY: 'off',
    NO_COLOR: '1',
    ...(extraPath ? { PATH: `${extraPath}${path.delimiter}${process.env.PATH ?? ''}` } : {}),
  };
}

/** Run the built CLI; stdout and stderr share one file, so their order is the terminal's. */
function cli(args: string[], opts: { home: string; cwd?: string; extraPath?: string }): { status: number | null; output: string } {
  const outFile = path.join(tempDir(), 'output');
  const fd = fs.openSync(outFile, 'w');
  try {
    const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
      cwd: opts.cwd ?? opts.home,
      env: envFor(opts.home, opts.extraPath),
      stdio: ['ignore', fd, fd],
      timeout: 20_000,
    });
    return { status: res.status, output: fs.readFileSync(outFile, 'utf-8') };
  } finally {
    fs.closeSync(fd);
  }
}

/** Run a command in this process and collect what it writes, in order. */
async function inProcess(run: () => Promise<number>): Promise<{ code: number; output: string }> {
  let output = '';
  const line = (...args: unknown[]) => { output += `${args.map(String).join(' ')}\n`; };
  vi.spyOn(console, 'log').mockImplementation(line);
  vi.spyOn(console, 'error').mockImplementation(line);
  vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => {
    output += String(chunk);
    return true;
  }) as typeof process.stderr.write);
  const code = await run();
  vi.restoreAllMocks();
  return { code, output };
}

/** A fresh HOME, store and working directory for an in-process command. */
function inProcessFixture(): { home: string; cwd: string } {
  const home = tempDir();
  const cwd = tempDir();
  process.env.HOME = home;
  fixture.storeDir = path.join(home, 'store');
  fixture.mcpHome = home;
  vi.spyOn(process, 'cwd').mockReturnValue(cwd);
  return { home, cwd };
}

// Credential-shaped fixture values are assembled at run time, so the tree
// never carries one whole. The scan's confidence for a value depends on the
// value, so these are fixed rather than random.
const DOTENV = [
  `STRIPE_KEY=${['sk', 'live', '51HVpctaYJdjkDz6VLqFWoLuNviAUHw'].join('_')}`,
  `DATABASE_URL=postgres://app:${'DOKhLSP3' + 'G4UYfrOm'}@db.internal:5432/app`,
  `OPENAI_API_KEY=${['sk', 'proj', 'g4CBAP6dvTVan6gVJlwNwpvIKi69geBk5G4kKNhY4XaddT7b'].join('-')}`,
].join('\n') + '\n';
const DOTENV_LOCAL = [
  'SENTRY_DSN=https://3c1e7a9b@o4504.ingest.sentry.io/4504',
  `REDIS_URL=redis://default:${'p00f3aqv' + 'fLQ34ESj'}@cache.internal:6379`,
].join('\n') + '\n';

function writeDotenvProject(dir: string): void {
  fs.writeFileSync(path.join(dir, '.env'), DOTENV);
  fs.writeFileSync(path.join(dir, '.env.local'), DOTENV_LOCAL);
}

/** Claude Desktop's config with the three servers the MCP guide shows. */
function writeClaudeDesktopConfig(home: string): void {
  const dir = path.join(home, 'Library', 'Application Support', 'Claude');
  fs.mkdirSync(dir, { recursive: true });
  const config = {
    mcpServers: {
      browserbase: {
        command: 'npx',
        args: ['-y', '@browserbasehq/mcp-server'],
        env: {
          BROWSERBASE_API_KEY: ['bb', 'live', 'v2Ha0Wut3I14lUUGLtIX'].join('_'),
          BROWSERBASE_PROJECT_ID: 'proj-456',
        },
      },
      github: {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-github'],
        env: { GITHUB_PERSONAL_ACCESS_TOKEN: ['ghp', 'frOm1jboorKLTykcT4AWVpctaYJdjkDz6VLq'].join('_') },
      },
      stripe: {
        command: 'npx',
        args: ['-y', '@stripe/mcp'],
        env: { STRIPE_SECRET_KEY: ['sk', 'live', '51HKi69geBk5G4kKNhY4XaddT7b'].join('_') },
      },
    },
  };
  fs.writeFileSync(path.join(dir, 'claude_desktop_config.json'), JSON.stringify(config, null, 2));
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

/** Start the built CLI and resolve with what it printed once `marker` is on stdout. */
function startUntil(args: string[], home: string, marker: string): Promise<{ child: ChildProcess; output: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      cwd: home,
      env: envFor(home),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (child.pid) pids.push(child.pid);
    let out = '';
    let err = '';
    let done = false;
    const fail = (why: string) => {
      if (done) return;
      done = true;
      reject(new Error(`${why}\n--- stdout ---\n${out}\n--- stderr ---\n${err}`));
    };
    const timer = setTimeout(() => fail(`no "${marker}" within 20 s`), 20_000);
    child.stdout!.on('data', (chunk) => {
      out += chunk;
      if (!done && out.includes(marker)) {
        done = true;
        clearTimeout(timer);
        resolve({ child, output: out });
      }
    });
    child.stderr!.on('data', (chunk) => { err += chunk; });
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      fail(`exited before printing "${marker}" (code ${code}, signal ${signal})`);
    });
  });
}

// ---------------------------------------------------------------------------
// The samples
// ---------------------------------------------------------------------------

describe('reading the samples out of the docs', () => {
  it('takes the block after the command, not the command block or a later one', () => {
    expect(sampleAfter(BROKER_GUIDE, 'broker start')).toMatch(/^ {2}Secretless Broker\n/);
    expect(sampleAfter(BROKER_GUIDE, 'broker status')).toMatch(/^ {2}Secretless Broker Status\n/);
    expect(() => sampleAfter(BROKER_GUIDE, 'no-such-command')).toThrow(/no sample block/);
  });
});

describe('protect-my-credentials.md', () => {
  itIfBuilt('`status` after `init` in a project Claude Code and Cursor use', () => {
    const home = tempDir();
    const project = tempDir();
    fs.mkdirSync(path.join(project, '.claude'));
    fs.mkdirSync(path.join(project, '.cursor'));
    expect(cli(['init'], { home, cwd: project }).status).toBe(0);

    // The guide's reader is on macOS, where the default store is the keychain
    // and `status` reports the biometric session. Naming the keychain in the
    // config gives the same rows on Linux, without touching any keychain.
    fs.mkdirSync(path.join(home, '.secretless-ai'), { recursive: true });
    fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify({ backend: 'keychain' }));

    const res = cli(['status'], { home, cwd: project });
    expect(res.status).toBe(0);
    expect(normalize(res.output, home)).toBe(sampleAfter(PROTECT_GUIDE, 'status'));
  }, TEST_TIMEOUT_MS);
});

describe('secure-mcp-configs.md and the README', () => {
  it('`protect-mcp` on a Claude Desktop config with three servers', async () => {
    const { home } = inProcessFixture();
    writeClaudeDesktopConfig(home);

    const res = await inProcess(() => runProtectMcp([]));
    expect(res.code).toBe(0);
    const output = normalize(res.output, home);
    expect(output).toBe(sampleAfter(MCP_GUIDE, 'protect-mcp'));
    expect(output).toBe(sampleAfter(README, 'protect-mcp'));
  });

  itIfBuilt('`mcp-status` after `protect-mcp`', async () => {
    const { home } = inProcessFixture();
    writeClaudeDesktopConfig(home);
    expect((await inProcess(() => runProtectMcp([]))).code).toBe(0);

    const res = cli(['mcp-status'], { home, cwd: tempDir() });
    expect(res.status).toBe(0);
    // `Backend:` names the platform's keychain on macOS (the guide's reader),
    // and `keychain-linux` or `local` on Linux.
    const output = normalize(res.output, home)
      .replace(/^( {2}Backend: )(?:keychain-linux|local)$/m, '$1keychain-macos')
      .replace(/use the (?:keychain-linux|local) backend/, 'use the keychain-macos backend');
    expect(output).toBe(sampleAfter(MCP_GUIDE, 'mcp-status'));
  }, TEST_TIMEOUT_MS);
});

describe('team-setup.md', () => {
  const itWithShell = hasBuild && process.platform !== 'win32' ? it : it.skip;

  itWithShell('`backend set 1password` with the 1Password CLI installed and signed in', () => {
    const home = tempDir();
    const bin = tempDir();
    // Stands in for `op --version` and `op account get` succeeding.
    fs.writeFileSync(path.join(bin, 'op'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });

    const res = cli(['backend', 'set', '1password'], { home, extraPath: bin });
    expect(res.status).toBe(0);
    expect(normalize(res.output, home)).toBe(sampleAfter(TEAM_GUIDE, 'backend set 1password'));
  }, TEST_TIMEOUT_MS);

  it('`setup` with the guide\'s .secretless manifest, typing two values and skipping the optional one', async () => {
    const { cwd } = inProcessFixture();
    const manifest = blockAfterText(TEAM_GUIDE, 'Create a `.secretless` manifest');
    fs.writeFileSync(path.join(cwd, '.secretless'), manifest + '\n');
    fixture.answers = ['sk_live_...', 'postgres://...', ''];
    // setup names the store before the first prompt, and the guide's reader
    // set the 1password backend in Step 2.
    fixture.backendName = '1password';

    // The guide's reader types at a terminal, with none of the manifest's
    // names set in the environment. Without a terminal setup does not prompt,
    // and a name set in the environment is announced in its prompt (#330), so
    // neither may depend on how this test runs.
    const names = manifest.split('\n').map((line) => line.trim().split(/\s/)[0]).filter(Boolean);
    const savedEnv = names.map((name) => [name, process.env[name]] as const);
    for (const name of names) delete process.env[name];
    const savedIsTTY = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
    Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
    try {
      const res = await inProcess(() => runSetupCommand([]));
      expect(res.code).toBe(0);
      expect(normalize(res.output)).toBe(sampleAfter(TEAM_GUIDE, 'setup'));
    } finally {
      if (savedIsTTY) Object.defineProperty(process.stdin, 'isTTY', savedIsTTY);
      else delete (process.stdin as { isTTY?: boolean }).isTTY;
      for (const [name, value] of savedEnv) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });
});

describe('migrate-from-dotenv.md', () => {
  itIfBuilt('`scan` in a project with .env and .env.local', () => {
    const home = tempDir();
    const project = tempDir();
    writeDotenvProject(project);

    const res = cli(['scan'], { home, cwd: project });
    expect(res.status).toBe(1);
    expect(normalize(res.output, home)).toBe(sampleAfter(DOTENV_GUIDE, 'scan'));
  }, TEST_TIMEOUT_MS);

  it('`import --detect` in the same project', async () => {
    const { cwd } = inProcessFixture();
    writeDotenvProject(cwd);

    const res = await inProcess(() => runImport(['--detect']));
    expect(res.code).toBe(0);
    expect(normalize(res.output)).toBe(sampleAfter(DOTENV_GUIDE, 'import --detect'));
  });
});

describe('run-broker.md', () => {
  itIfBuilt('`broker start`, then `broker status` in a second terminal', async () => {
    const home = tempDir();
    const port = await freePort();
    const { child, output: started } = await startUntil(['broker', 'start', '--port', String(port)], home, 'Press Ctrl+C to stop.');

    // The guide runs the default port; this test takes a free one.
    const asDocumented = (text: string) => normalize(text, home)
      .replace(new RegExp(`^( {2}PID: +)${child.pid}$`, 'm'), '$112345')
      .replace(new RegExp(`^( {2}HTTP port: +)${port}$`, 'm'), '$119421');

    expect(asDocumented(started)).toBe(sampleAfter(BROKER_GUIDE, 'broker start'));

    const res = cli(['broker', 'status'], { home });
    expect(res.status).toBe(0);
    const status = asDocumented(res.output)
      .replace(/^( {2}Uptime: +)\S+$/m, '$15s')
      .replace(/^( {2}Started at: +)\d{4}-\d\d-\d\dT[\d:.]+Z$/m, '$12026-10-11T09:30:00.000Z');
    expect(status).toBe(sampleAfter(BROKER_GUIDE, 'broker status'));

    child.kill('SIGTERM');
  }, TEST_TIMEOUT_MS);
});
