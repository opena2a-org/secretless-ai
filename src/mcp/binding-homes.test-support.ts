import { spawnSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { BackendHealth, ResolveOptions, WritableSecretBackend } from '../backends/types';

/**
 * Two secretless homes with equal paths: the cells of the binding's writer
 * identity (McpBinding.boundOn) run protect-mcp, mcp-status, mcp-unprotect
 * and the wrapper as two machines whose home directories and project
 * directories are the same paths, reading one store that several machines
 * read.
 *
 * Everything is under one scratch directory: HOME, a project directory D
 * outside it, the two prepared `.secretless-ai` directories A and B, of which
 * the one in use is moved into HOME and the other waits beside it, and the
 * store, a JSON file outside HOME that every reader opens on each call. The
 * wrapper is started as a child with a preload that hands it that store,
 * read only, in place of the backend it builds. Stand-ins for `op`,
 * `security` and `secret-tool` lead PATH and leave a tripwire file when they
 * run. Ids are made at run time; nothing here is a credential.
 */

export type HomeName = 'A' | 'B';

/** A store held in one JSON file, named as the backend it stands in for. Each binding write is recorded. */
export class FileStore implements WritableSecretBackend {
  /** The key and value of each binding write, in order. */
  readonly bindingWrites: Array<{ key: string; value: string }> = [];

  constructor(readonly file: string, readonly name: string) {}

  /** Every key and value the store holds. */
  all(): Record<string, string> {
    try {
      return JSON.parse(fs.readFileSync(this.file, 'utf-8')) as Record<string, string>;
    } catch {
      return {};
    }
  }

  /** The text stored under `key`, as stored. */
  raw(key: string): string | undefined {
    return this.all()[key];
  }

  /** Put `value` under `key` as it is, without a vault's checks: a record an earlier build stored. */
  put(key: string, value: string): void {
    fs.writeFileSync(this.file, JSON.stringify({ ...this.all(), [key]: value }));
  }

  async resolve(at: string, options?: ResolveOptions): Promise<Record<string, string>> {
    const found: Record<string, string> = {};
    for (const [key, value] of Object.entries(this.all())) {
      if (key === at || (!options?.exact && key.startsWith(`${at}/`))) found[key] = value;
    }
    return found;
  }

  async healthCheck(): Promise<BackendHealth> {
    return { healthy: true, latencyMs: 0 };
  }

  async store(key: string, value: string): Promise<void> {
    if (key.startsWith('mcp-binding/')) this.bindingWrites.push({ key, value });
    this.put(key, value);
  }

  async delete(key: string): Promise<boolean> {
    const all = this.all();
    if (!Object.prototype.hasOwnProperty.call(all, key)) return false;
    delete all[key];
    fs.writeFileSync(this.file, JSON.stringify(all));
    return true;
  }
}

/** The built backend factory the wrapper loads, which the preload replaces in it. */
const FACTORY_JS = path.resolve(__dirname, '..', '..', 'dist', 'backends', 'factory.js');

/** The built wrapper, started as a client starts an entry. */
export const WRAPPER_JS = path.resolve(__dirname, '..', '..', 'dist', 'mcp-wrapper.js');

/**
 * The preload a wrapper child is started with: in the built factory,
 * createBackend gives the store named `name` held in `storeFile`, read only,
 * and refuses to build any other backend.
 */
function preloadSource(storeFile: string, name: string): string {
  return [
    "'use strict';",
    "const fs = require('fs');",
    `const factory = require(${JSON.stringify(FACTORY_JS)});`,
    `const STORE = ${JSON.stringify(storeFile)};`,
    `const NAME = ${JSON.stringify(name)};`,
    'class ReadOnlyFileStore {',
    '  constructor() { this.name = NAME; }',
    '  async resolve(at, options) {',
    '    let all = {};',
    "    try { all = JSON.parse(fs.readFileSync(STORE, 'utf-8')); } catch (err) { all = {}; }",
    '    const found = {};',
    '    for (const [key, value] of Object.entries(all)) {',
    "      if (key === at || (!(options && options.exact) && key.startsWith(at + '/'))) found[key] = value;",
    '    }',
    '    return found;',
    '  }',
    '  async healthCheck() { return { healthy: true, latencyMs: 0 }; }',
    "  async store() { throw new Error('the wrapper stores nothing in this cell'); }",
    "  async delete() { throw new Error('the wrapper deletes nothing in this cell'); }",
    '}',
    'factory.createBackend = function (type) {',
    '  if (type === NAME) return new ReadOnlyFileStore();',
    "  throw new Error('this cell builds only its store double, not ' + type);",
    '};',
    '',
  ].join('\n');
}

/** The stand-ins that lead PATH: each leaves `<root>/tripwire-<name>` and exits 1. */
const STAND_INS = ['op', 'security', 'secret-tool'];

export interface Homes {
  /** The scratch directory everything is under. */
  root: string;
  /** HOME, one path for both homes. */
  home: string;
  /** A project directory D, outside HOME, one path for both homes. */
  project: string;
  /** The store both homes and the wrapper read. */
  store: FileStore;
  /** Each home's id, as its `binding-home-id` held it when the home was made. */
  ids: Record<HomeName, string>;
  /** The home in HOME now. */
  current(): HomeName;
  /** Move the home `name` into HOME, and the one there beside it. */
  use(name: HomeName): void;
  /** The `.secretless-ai` of the home in HOME. */
  dataDir(): string;
  /** The `binding-home-id` file of the home in HOME. */
  idFile(): string;
  /** A directory on PATH holding the stand-ins. */
  bin: string;
  /** The stand-ins that ran, by name. */
  tripped(): string[];
  /** The preload a wrapper child is started with. */
  preload: string;
  close(): void;
}

/**
 * Two homes, A and B, each a `.secretless-ai` with `config.json` naming
 * `backend`, an empty `mcp-vault`, and its own id in `binding-home-id`
 * (mode 0600), except where `withoutId` names it. A is in HOME.
 */
export function openHomes(backend: string, options: { withoutId?: HomeName[] } = {}): Homes {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-homes-')));
  const home = path.join(root, 'home');
  const project = path.join(root, 'project');
  const parked = path.join(root, 'parked');
  const bin = path.join(root, 'bin');
  for (const dir of [home, project, bin]) fs.mkdirSync(dir, { recursive: true });
  const ids = { A: crypto.randomBytes(16).toString('hex'), B: crypto.randomBytes(16).toString('hex') };
  for (const name of ['A', 'B'] as const) {
    const dir = path.join(parked, name, '.secretless-ai');
    fs.mkdirSync(path.join(dir, 'mcp-vault'), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ backend }));
    if (!options.withoutId?.includes(name)) fs.writeFileSync(path.join(dir, 'binding-home-id'), `${ids[name]}\n`, { mode: 0o600 });
  }
  for (const name of STAND_INS) {
    const trip = path.join(root, `tripwire-${name}`);
    fs.writeFileSync(path.join(bin, name), `#!/bin/sh\n: > ${JSON.stringify(trip)}\nexit 1\n`, { mode: 0o755 });
  }
  const storeFile = path.join(root, 'store.json');
  const preload = path.join(root, 'preload.cjs');
  fs.writeFileSync(preload, preloadSource(storeFile, backend));
  let current: HomeName | undefined;
  const dataDir = () => path.join(home, '.secretless-ai');
  const homes: Homes = {
    root,
    home,
    project,
    store: new FileStore(storeFile, backend),
    ids,
    current: () => current as HomeName,
    use(name: HomeName) {
      if (current === name) return;
      if (current !== undefined) fs.renameSync(dataDir(), path.join(parked, current, '.secretless-ai'));
      fs.renameSync(path.join(parked, name, '.secretless-ai'), dataDir());
      current = name;
    },
    dataDir,
    idFile: () => path.join(dataDir(), 'binding-home-id'),
    bin,
    tripped: () => STAND_INS.filter((name) => fs.existsSync(path.join(root, `tripwire-${name}`))),
    preload,
    close: () => fs.rmSync(root, { recursive: true, force: true }),
  };
  homes.use('A');
  return homes;
}

/** sha256 of a text, in hex: a record's bytes compared before and after a run. */
export function sha256(text: string | undefined): string | undefined {
  return text === undefined ? undefined : crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/** The key a pair's binding is stored under. */
export function bindingKey(client: string, server: string): string {
  return `mcp-binding/${client}/${server}`;
}

/** What a wrapper child printed and how it exited. */
export interface WrapperRun {
  status: number | null;
  output: string;
}

/**
 * The built wrapper started with `args` from `cwd` in the home now in HOME,
 * as a client starts an entry: its environment holds HOME, PATH with the
 * stand-ins first, and the switches the test recipe sets, and nothing else.
 */
export function startWrapper(homes: Homes, args: readonly string[], cwd: string): WrapperRun {
  const env: NodeJS.ProcessEnv = {
    PATH: `${homes.bin}${path.delimiter}${process.env.PATH ?? ''}`,
    HOME: homes.home,
    SECRETLESS_OS_KEYCHAIN: 'off',
    OPENA2A_TELEMETRY: 'off',
    HARNESS_NO_LIVE_TRANSPORT: '1',
  };
  const run = spawnSync(process.execPath, ['--require', homes.preload, WRAPPER_JS, ...args], {
    cwd,
    encoding: 'utf-8',
    env,
    timeout: 30_000,
  });
  return { status: run.status, output: `${run.stdout ?? ''}${run.stderr ?? ''}` };
}
