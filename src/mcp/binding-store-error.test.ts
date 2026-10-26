import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { STORE_MESSAGE_WITHHELD, protectMcp } from './protect';
import { McpVault } from './vault';
import { createBackend } from '../backends/factory';
import { redactSecurityError } from '../backends/keychain-macos';
import { runMcpStatus, runProtectMcp } from '../commands/mcp';
import { MemoryStore } from './binding-store-double.test-support';

/**
 * The error a not-replaced or not-bound line prints. Each backend's store
 * error carries no binding id, no command digest and no stored value, and the
 * line has a backstop: a message holding the new id, the old id, the
 * record's command digest or a run of 32 or more hex characters is withheld,
 * and the line says so. A replacement whose bound entry's file cannot be
 * written and whose old binding cannot be stored back has its own line: the
 * store holds a binding no entry carries, so neither entry starts until
 * protect-mcp runs again where that file can be written.
 *
 * Every store is an in-memory double named as the backend it stands in for,
 * refusing the binding write with that backend's error as its source builds
 * it: no keychain, no `op`, no network. Values are assembled at run time and
 * are not credentials.
 */

vi.mock('../backends/factory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../backends/factory')>();
  return { ...actual, createBackend: vi.fn(actual.createBackend) };
});

const WRAPPER_PATH = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');
const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');
const ID = /^[0-9a-f]{32}$/;
const HEX_RUN = /[0-9a-f]{32}/i;

let home: string;
let scratch: string;
let memory: MemoryStore;
let saved: Record<'HOME' | 'USER', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-backstop-home-'));
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-backstop-dirs-'));
  saved = { HOME: process.env.HOME, USER: process.env.USER };
  process.env.HOME = home;
  delete process.env.USER;
  fs.mkdirSync(path.join(home, '.secretless-ai', 'mcp-vault'), { recursive: true });
  use('local', 'local');
});

afterEach(() => {
  vi.mocked(createBackend).mockReset();
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const d of [home, scratch]) fs.rmSync(d, { recursive: true, force: true });
});

/** The store every vault of the run builds: a double named `name`, with `backend` configured. */
function use(name: string, backend: string): void {
  write(path.join(home, '.secretless-ai', 'config.json'), { backend });
  memory = new MemoryStore(name);
  vi.mocked(createBackend).mockImplementation(() => memory);
}

function write(fullPath: string, content: unknown): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, JSON.stringify(content, null, 2));
  return fullPath;
}

function dir(...parts: string[]): string {
  const full = path.join(scratch, ...parts);
  fs.mkdirSync(full, { recursive: true });
  return full;
}

const vault = () => new McpVault({ backend: memory });
const plain = () => ({ command: process.execPath, args: ['-e', 'x'], env: { [NAME]: VALUE } });
const entryOf = (file: string): { command: string; args: string[] } => JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers.github;

/** The id an entry's args carry before the wrapper's `--`. */
function idOf(args: string[]): string | undefined {
  const own = args.slice(0, args.indexOf('--'));
  const at = own.indexOf('--binding');
  return at === -1 ? undefined : own[at + 1];
}

/** `github` in the home cursor config, protected by protect-mcp run in an empty directory: a home binding. */
async function homeBinding() {
  const file = write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { github: plain() } });
  await protectMcp({ projectDir: dir('setup'), wrapperPath: WRAPPER_PATH });
  const entry = entryOf(file);
  const id = idOf(entry.args);
  expect(ID.test(id ?? ''), 'the entry carries a binding id').toBe(true);
  const record = await vault().getBinding('cursor', 'github');
  expect(record?.id).toBe(id);
  return { file, entry, id: id!, digest: record!.commandDigest };
}

/** A home binding and a copy of its entry in W's .mcp.json, which protect-mcp run in W replaces. */
async function bindingWithCopy() {
  const bound = await homeBinding();
  const w = dir('w');
  write(path.join(w, '.mcp.json'), { mcpServers: { github: bound.entry } });
  return { ...bound, w };
}

/** A command of the CLI in this process, from `cwd`, with what it prints. */
async function run(command: () => Promise<number>, cwd: string): Promise<{ code: number; output: string }> {
  const lines: string[] = [];
  const capture = (...parts: unknown[]) => { lines.push(parts.map(String).join(' ')); };
  const log = vi.spyOn(console, 'log').mockImplementation(capture);
  const error = vi.spyOn(console, 'error').mockImplementation(capture);
  const at = vi.spyOn(process, 'cwd').mockReturnValue(cwd);
  try {
    const code = await command();
    return { code, output: lines.join('\n') };
  } finally {
    log.mockRestore();
    error.mockRestore();
    at.mockRestore();
  }
}

/** The one printed line holding `marker`. */
function lineOf(output: string, marker: string): string {
  const lines = output.split('\n').filter((line) => line.includes(marker));
  expect(lines, `one line holds "${marker}"`).toHaveLength(1);
  return lines[0];
}

/** The local backend's write error: the one fs gives for its store's temporary file in a directory it may not write. */
function localWriteError(): Error {
  const storeDir = path.join(home, '.secretless-ai', 'mcp-vault');
  fs.chmodSync(storeDir, 0o500);
  try {
    fs.writeFileSync(path.join(storeDir, 'secrets.enc.tmp'), 'stand-in', { mode: 0o600 });
  } catch (err) {
    return err as Error;
  } finally {
    fs.chmodSync(storeDir, 0o700);
  }
  throw new Error('the directory took the write');
}

/**
 * Each backend the wrapper takes, as its store refuses a binding write: the
 * double's name, the backend configured, and the error as the backend's
 * source builds it (keychain-macos.ts redactSecurityError over what
 * `security` reports, its stdin's hex included; keychain-linux.ts
 * secretToolStoreError; onepassword.ts op(); vault.ts storeVersion; gcp-sm.ts
 * addSecretVersion; local.ts store, through fs).
 */
const BACKENDS: Array<[string, string, (key: string, value: string) => Error]> = [
  ['keychain-macos', 'keychain', (key, value) => redactSecurityError(
    new Error([
      'security: SecKeychainItemCreateFromContent (<default>): User interaction is not allowed.',
      Buffer.from(value, 'utf-8').toString('hex'),
      'security exit status 1',
    ].join('\n')),
    value,
    key,
  )],
  ['keychain-linux', 'keychain', (key) => new Error([
    `Could not store "${key}" in the Linux Secret Service.`,
    '',
    '  secret-tool exit status: 1',
    '  Cannot autolaunch D-Bus without X11 $DISPLAY',
    '',
    '  The keyring is usually locked, or no Secret Service is running.',
    '',
    '  Verify:  secret-tool search service secretless',
    '  Fix:     unlock the login keyring and retry, or run',
    '           secretless-ai backend set local  to use the encrypted file store',
  ].join('\n'))],
  ['1password', '1password', () => new Error([
    '1Password command failed (op item create).',
    '  [ERROR] 2026/10/26 04:20:00 You are not currently signed in.',
    '  Verify: op account get',
  ].join('\n'))],
  ['vault', 'vault', (key) => new Error(`Vault: permission denied writing "${key}"`)],
  ['gcp-sm', 'gcp-sm', () => new Error("GCP Secret Manager: insufficient IAM permissions on project stand-in-project. Grant 'Secret Manager Admin' role.")],
  ['local', 'local', () => localWriteError()],
];

describe('X2-d: a not-replaced line carries the store\'s error and never the binding', () => {
  it.each(BACKENDS)(
    '%s refuses the new binding: the line names its error and carries no run of 32 hex characters, neither id, and no withheld phrase',
    async (name, backend, refusal) => {
      use(name, backend);
      const { id, w } = await bindingWithCopy();
      let newId: string | undefined;
      let first: string | undefined;
      memory.refuse = (key, value) => {
        newId = JSON.parse(value).id;
        const err = refusal(key, value);
        first = err.message.split('\n')[0];
        return err;
      };

      const { code, output } = await run(() => runProtectMcp([]), w);

      expect(code).toBe(0);
      expect(newId).toMatch(ID);
      expect(newId).not.toBe(id);
      const line = lineOf(output, 'a copy of a bound entry');
      expect(line).toContain(`The binding could not be replaced: the store refused the new binding (${first}).`);
      expect(HEX_RUN.test(line), 'a run of 32 hex characters is printed').toBe(false);
      expect(line.includes(newId!), 'the new id is printed').toBe(false);
      expect(line.includes(id), 'the old id is printed').toBe(false);
      expect(line.includes(STORE_MESSAGE_WITHHELD), 'the backend\'s own error was withheld').toBe(false);
      expect((await vault().getBinding('cursor', 'github'))?.id).toBe(id);
    },
  );

  const plantings: Array<[string, (values: { newId: string; oldId: string; digest: string }) => string]> = [
    ['the new id', ({ newId }) => `write rejected: ${newId}`],
    ['the old id', ({ oldId }) => `write rejected: ${oldId}`],
    ['the record\'s command digest', ({ digest }) => `write rejected: ${digest}`],
    ['another run of 32 hex characters, in capitals', () => `write rejected: ${crypto.randomBytes(16).toString('hex').toUpperCase()}`],
    ['the new id on a later line', ({ newId }) => `write rejected\nat ${newId}`],
  ];

  it.each(plantings)('a store message holding %s: the line prints the withheld phrase and nothing of the message', async (_label, message) => {
    const { id, digest, w } = await bindingWithCopy();
    let newId = '';
    memory.refuse = (_key, value) => {
      newId = JSON.parse(value).id;
      return new Error(message({ newId, oldId: id, digest }));
    };

    const { output } = await run(() => runProtectMcp([]), w);

    const line = lineOf(output, 'a copy of a bound entry');
    expect(line).toContain(`The binding could not be replaced: the store refused the new binding (${STORE_MESSAGE_WITHHELD}).`);
    expect(line).not.toContain('write rejected');
    expect(line.includes(newId) || line.includes(id) || line.includes(digest)).toBe(false);
    expect(HEX_RUN.test(output), 'a run of 32 hex characters is printed').toBe(false);
  });

  it('a store message holding a run of 31 hex characters is printed as it is: the bound is 32', async () => {
    const { w } = await bindingWithCopy();
    const shorter = crypto.randomBytes(16).toString('hex').slice(0, 31);
    memory.refuse = () => new Error(`write rejected at ${shorter}`);

    const { output } = await run(() => runProtectMcp([]), w);

    expect(lineOf(output, 'a copy of a bound entry')).toContain(`the store refused the new binding (write rejected at ${shorter}).`);
  });

  it('the store refusing a first binding: the line withholds a message that holds the new id', async () => {
    write(path.join(home, '.cursor', 'mcp.json'), { mcpServers: { github: plain() } });
    let newId = '';
    memory.refuse = (_key, value) => {
      newId = JSON.parse(value).id;
      return new Error(`write rejected: ${newId}`);
    };

    const { output } = await run(() => runProtectMcp([]), dir('w'));

    expect(newId).toMatch(ID);
    expect(output).toContain(`the binding could not be stored (${STORE_MESSAGE_WITHHELD}); run`);
    expect(output).not.toContain('write rejected');
    expect(HEX_RUN.test(output), 'a run of 32 hex characters is printed').toBe(false);
  });

  it('the store refusing the binding of an entry an earlier version wrapped: the not-bound line withholds a message that holds the new id', async () => {
    write(path.join(home, '.cursor', 'mcp.json'), {
      mcpServers: { github: { command: WRAPPER_PATH, args: ['--server', 'github', '--client', 'cursor', '--', process.execPath, '-e', 'x'], env: {} } },
    });
    await vault().storeServerSecrets('cursor', 'github', { [NAME]: VALUE });
    let newId = '';
    memory.refuse = (_key, value) => {
      newId = JSON.parse(value).id;
      return new Error(`write rejected: ${newId}`);
    };

    const { output } = await run(() => runProtectMcp([]), dir('w'));

    expect(newId).toMatch(ID);
    expect(lineOf(output, 'not bound:')).toContain(`the binding could not be stored (${STORE_MESSAGE_WITHHELD}); run`);
    expect(output).not.toContain('write rejected');
    expect(HEX_RUN.test(output), 'a run of 32 hex characters is printed').toBe(false);
  });
});

describe('X2-d: the bound entry\'s file cannot be written and the old binding cannot be stored back', () => {
  it('the copy\'s line names that file and says neither entry starts; mcp-status shows both states; a second run repairs the bound entry', async () => {
    const { file, id, w } = await bindingWithCopy();
    // The store takes the new binding, then refuses the old one stored back.
    let writes = 0;
    memory.refuse = (key) => (writes++ === 0 ? undefined : new Error(`Vault: permission denied writing "${key}"`));
    const folder = path.dirname(file);
    fs.chmodSync(file, 0o444);
    fs.chmodSync(folder, 0o555);
    let output = '';
    try {
      ({ output } = await run(() => runProtectMcp([]), w));
    } finally {
      fs.chmodSync(folder, 0o755);
      fs.chmodSync(file, 0o644);
    }

    const record = await vault().getBinding('cursor', 'github');
    expect(ID.test(record?.id ?? '') && record?.id !== id, 'the store holds the new binding').toBe(true);
    expect(idOf(entryOf(file).args), 'the bound entry carries the old id').toBe(id);
    const line = lineOf(output, 'a copy of a bound entry');
    expect(line).toContain(`The binding could not be replaced: ${file} could not be written (EACCES: permission denied`);
    expect(line).toContain('and the old binding could not be stored back, so the store now holds a binding that no entry carries.');
    expect(line).toContain(' runs again where ');
    expect(line).toContain('Neither that entry nor a copy of it starts until ');
    expect(line).not.toContain("gives it that server's secrets");
    expect(output).not.toContain('receive its secrets');
    expect(HEX_RUN.test(output), 'a run of 32 hex characters is printed').toBe(false);

    // mcp-status: the bound entry does not carry the binding stored for it, and the copy's secrets are bound elsewhere.
    memory.refuse = undefined;
    const status = await run(() => runMcpStatus(), w);
    expect(status.output).toContain('    ? github: protected, but it does not carry the binding stored for it, so the wrapper does not start it\n');
    expect(status.output).toContain(
      `    ? github: the secrets it reads are bound to the entry for server "github" in ${file}, so the wrapper does not start it\n`,
    );

    // protect-mcp run again where the file can be written: the bound entry carries the record's id.
    await protectMcp({ projectDir: w, wrapperPath: WRAPPER_PATH });
    expect(idOf(entryOf(file).args)).toBe(record!.id);
    expect((await vault().getBinding('cursor', 'github'))?.id).toBe(record!.id);
  });
});
