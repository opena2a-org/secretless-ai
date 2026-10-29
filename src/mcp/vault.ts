/**
 * MCP Vault — encrypted secret storage namespaced by client/server.
 *
 * Thin wrapper around a WritableSecretBackend that stores secrets with key
 * `mcp/{client}/{server}/{envKey}`, providing per-server isolation.
 *
 * By default uses the LocalBackend for backward compatibility.
 * Can be configured to use the OS keychain backend via backendType option.
 *
 * Beside a pair, `protect-mcp` stores its binding (McpBinding) under
 * `mcp-binding/{client}/{server}`, and the wrapper reads the pair's secrets
 * only for the config entry and command the binding names (checkLaunch).
 */

import * as crypto from 'crypto';
import { createBackend } from '../backends/factory';
import { resolveBackendType } from '../backends/config';
import type { WritableSecretBackend } from '../backends/types';
import type { SelectableBackendType } from '../backends/config';
import { findSecretValueProblem, listedName, unstorableMcpSecretError } from '../secret-value';

const MCP_PREFIX = 'mcp';

/**
 * The prefix of a pair's binding. It is outside MCP_PREFIX, so neither
 * getServerSecrets nor listEntries returns it, and the wrapper never gives it
 * to a server as an env var: a backend resolves a path to the key equal to it
 * and the keys under `<path>/`.
 */
const BINDING_PREFIX = 'mcp-binding';

/**
 * The config entry a stored client/server pair was taken from, and the
 * command it was bound with. `protect-mcp` stores it beside the pair and
 * writes `id` into the entry's wrapper args as `--binding <id>`: the id lives
 * only in that entry and here, so another config entry cannot carry it, and
 * the digest stops a changed command inside the entry. The id is a credential:
 * nothing prints it.
 */
export interface McpBinding {
  schema: 1;
  /** 32 lowercase hex digits: 16 random bytes (see newBindingId). */
  id: string;
  /** 'home' for a config in the home directory, 'project' for the project's .mcp.json. */
  scope: 'home' | 'project';
  /** The config file, as discovery found it: an absolute path. */
  file: string;
  /** For a server map kept for one project in ~/.claude.json: the key it is under. */
  projectKey?: string;
  /** The config's client. */
  client: string;
  /** The server's name as written in the config. */
  server: string;
  /** The command the wrapper starts, with its arguments: see commandDigest. */
  commandDigest: string;
  /** When it was stored: ISO 8601, UTC. */
  boundAt: string;
  /** The secretless-ai version that stored it. */
  boundBy: string;
  /**
   * The id of the secretless home whose protect-mcp stored it: 32 lowercase
   * hex digits (see binding-home-id.ts). Every binding this version stores
   * carries it; one an earlier version stored does not. The wrapper never
   * reads it, and nothing prints it.
   */
  boundOn?: string;
}

const BINDING_ID = /^[0-9a-f]{32}$/;
const COMMAND_DIGEST = /^sha256:[0-9a-f]{64}$/;

/** Whether `value` is a binding id: exactly 32 lowercase hex digits. */
export function isBindingId(value: unknown): value is string {
  return typeof value === 'string' && BINDING_ID.test(value);
}

/** A new binding id: 16 random bytes as 32 lowercase hex digits. */
export function newBindingId(): string {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * `sha256:` and the SHA-256, in lowercase hex, of the UTF-8 bytes of
 * JSON.stringify([command, ...args]): the command the wrapper starts, after
 * its own `--`, with its arguments.
 */
export function commandDigest(command: string, args: readonly string[]): string {
  return `sha256:${crypto.createHash('sha256').update(JSON.stringify([command, ...args]), 'utf8').digest('hex')}`;
}

/**
 * The binding in `text`, or undefined when it is not a schema-1 binding. A
 * `boundOn` that is not 32 lowercase hex digits is left out, and the binding
 * is read without it: the field never decides whether a binding is read.
 */
function parseBinding(text: string): McpBinding | undefined {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const b = value as Record<string, unknown>;
  const isText = (v: unknown): v is string => typeof v === 'string' && v !== '';
  if (b.schema !== 1 || !isBindingId(b.id) || (b.scope !== 'home' && b.scope !== 'project')) return undefined;
  if (!isText(b.file) || !isText(b.client) || !isText(b.server) || !isText(b.boundAt) || !isText(b.boundBy)) return undefined;
  if (typeof b.commandDigest !== 'string' || !COMMAND_DIGEST.test(b.commandDigest)) return undefined;
  if (b.projectKey !== undefined && typeof b.projectKey !== 'string') return undefined;
  return {
    schema: 1,
    id: b.id,
    scope: b.scope,
    file: b.file,
    ...(b.projectKey === undefined ? {} : { projectKey: b.projectKey }),
    client: b.client,
    server: b.server,
    commandDigest: b.commandDigest,
    boundAt: b.boundAt,
    boundBy: b.boundBy,
    ...(isBindingId(b.boundOn) ? { boundOn: b.boundOn } : {}),
  };
}

/**
 * The config entry a binding names, for a line: `server "<s>" in <file>`, and
 * `, project <key>` for a server map kept for one project in ~/.claude.json.
 * Each name and path is written as listedName writes it.
 */
export function boundEntryName(binding: Pick<McpBinding, 'server' | 'file' | 'projectKey'>): string {
  const project = binding.projectKey === undefined ? '' : `, project ${listedName(binding.projectKey)}`;
  return `server "${listedName(binding.server)}" in ${listedName(binding.file)}${project}`;
}

/** What a secretless-mcp wrapper is asked to start, read from its args. */
export interface McpLaunch {
  /** The client and server name it reads its secrets by: its --client and --server. */
  client: string;
  server: string;
  /** The value of its --binding, or undefined when its args give none. */
  binding: string | undefined;
  /** The command after its own `--`, and that command's arguments. */
  command: string;
  args: readonly string[];
}

/**
 * Whether the wrapper starts a launch with the secrets stored for its pair,
 * and when not, which check refused it. `binding` is the pair's binding, for
 * every check that read one.
 */
export type McpLaunchVerdict =
  | { refused: false; binding: McpBinding }
  /** The entry carries no well-formed --binding. */
  | { refused: 'entry-not-bound' }
  /** No schema-1 binding is stored for the pair. */
  | { refused: 'no-binding-stored' }
  /** The binding stored for the pair has another id: it is another entry's. */
  | { refused: 'other-binding'; binding: McpBinding }
  /** The binding's id is the entry's, and its command and arguments are not. */
  | { refused: 'other-command'; binding: McpBinding };

/** Whether two binding ids are equal, compared in constant time. */
function sameBindingId(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

/**
 * The checks the secretless-mcp wrapper runs before it reads a secret value,
 * in this order: the entry carries a well-formed --binding; a binding is
 * stored for the pair; its id is the entry's; its command digest is the
 * digest of the command and arguments after the entry's `--`. Only a launch
 * that passes all four is given the pair's secrets. `mcp-status` runs the
 * same function, so the two never disagree on whether an entry starts.
 */
export async function checkLaunch(vault: McpVault, launch: McpLaunch): Promise<McpLaunchVerdict> {
  if (!isBindingId(launch.binding)) return { refused: 'entry-not-bound' };
  const binding = await vault.getBinding(launch.client, launch.server);
  if (binding === undefined) return { refused: 'no-binding-stored' };
  if (!sameBindingId(binding.id, launch.binding)) return { refused: 'other-binding', binding };
  if (binding.commandDigest !== commandDigest(launch.command, launch.args)) return { refused: 'other-command', binding };
  return { refused: false, binding };
}

/**
 * The backends whose pairs and bindings are this machine's alone: a config
 * file absent here is absent for every entry that reads them. Every other
 * backend (1password, vault, gcp-sm) is shared between machines, and a pair
 * stored in it may be read by entries on other machines.
 */
const PER_MACHINE_BACKENDS: readonly string[] = ['local', 'keychain-macos', 'keychain-linux'];

/** Whether the store a vault reads, by its backend name (McpVault.backendName), is this machine's alone. */
export function isPerMachineStore(backendName: string): boolean {
  return PER_MACHINE_BACKENDS.includes(backendName);
}

/**
 * Whether a binding is this secretless home's to change: every binding in a
 * store that is this machine's alone (isPerMachineStore), and, in a store
 * several machines read, one whose `boundOn` is this home's id, `homeId` (see
 * binding-home-id.ts). In such a store a binding with no `boundOn`, or
 * another home's, is not, and neither is any binding while this home's id
 * cannot be read (`homeId` undefined): protect-mcp and mcp-unprotect leave it
 * as it is. The wrapper never asks.
 */
export function ownsBinding(backendName: string, binding: Pick<McpBinding, 'boundOn'>, homeId: string | undefined): boolean {
  if (isPerMachineStore(backendName)) return true;
  return isBindingId(homeId) && binding.boundOn === homeId;
}

/** The fields of a binding, every one compared by sameBinding. */
const BINDING_FIELDS = [
  'schema', 'id', 'scope', 'file', 'projectKey', 'client', 'server', 'commandDigest', 'boundAt', 'boundBy', 'boundOn',
] as const satisfies ReadonlyArray<keyof McpBinding>;

/** Whether two bindings are one, field by field, or both are absent. */
export function sameBinding(a: McpBinding | undefined, b: McpBinding | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return BINDING_FIELDS.every((field) => a[field] === b[field]);
}

/**
 * Thrown where a pair's binding would be written over or deleted and the
 * binding the store holds, read again just before, is not the one the caller
 * read (`changed`), or is one this secretless home did not store (`not-owned`,
 * see ownsBinding). Nothing was written or deleted. Its message names the
 * pair, never a value.
 */
export class BindingWriteRefusedError extends Error {
  constructor(
    readonly client: string,
    readonly server: string,
    readonly why: 'changed' | 'not-owned',
  ) {
    super(
      `The binding stored for ${listedName(`${client}/${server}`)} was left as it is: ${
        why === 'changed' ? 'it is not the one that was read' : 'this secretless home did not store it'
      }.`,
    );
    this.name = 'BindingWriteRefusedError';
  }
}

/**
 * The binding stored for a pair, read again, when it is `expected`, the one
 * the caller read, and this secretless home stored it or there is none:
 * otherwise BindingWriteRefusedError, so nothing writes over or deletes a
 * binding that changed since it was read or that another home stored. On a
 * store that is this machine's alone every binding is this home's.
 */
export async function expectBinding(
  vault: Pick<McpVault, 'backendName' | 'getBinding'>,
  reads: { client: string; server: string },
  expected: McpBinding | undefined,
  homeId: string | undefined,
): Promise<McpBinding | undefined> {
  const current = await vault.getBinding(reads.client, reads.server);
  if (!sameBinding(current, expected)) throw new BindingWriteRefusedError(reads.client, reads.server, 'changed');
  if (current !== undefined && !ownsBinding(vault.backendName, current, homeId)) {
    throw new BindingWriteRefusedError(reads.client, reads.server, 'not-owned');
  }
  return current;
}

/** Validates client/server names to prevent path traversal. */
const SAFE_NAME = /^[a-zA-Z0-9_\-]+$/;

function validateName(label: string, value: string): void {
  if (!SAFE_NAME.test(value)) {
    throw new Error(`Invalid ${label} name: "${value}". Only alphanumeric, dash, and underscore allowed.`);
  }
}

/**
 * Why the vault refuses `name` as a client or server name, or undefined when
 * it takes it: the rule validateName applies, for a caller that reports the
 * refusal and goes on.
 */
export function mcpNameProblem(name: string): string | undefined {
  if (name === '') return 'it is empty';
  return SAFE_NAME.test(name) ? undefined : 'it holds a character other than A-Z, a-z, 0-9, - or _';
}

export interface McpVaultOptions {
  /** Store directory for the backend (passed as config.storeDir) */
  storeDir?: string;
  /** Encryption key for the local backend (passed as config.key) */
  key?: string;
  /** Backend type to use. Resolved from config if not provided. */
  backendType?: SelectableBackendType;
  /** Pre-constructed backend instance (overrides backendType). For DI/testing. */
  backend?: WritableSecretBackend;
}

export class McpVault {
  private readonly backend: WritableSecretBackend;

  constructor(options?: McpVaultOptions | Record<string, unknown>) {
    // Support pre-constructed backend for DI/testing
    if (options && 'backend' in options && options.backend) {
      this.backend = options.backend as WritableSecretBackend;
      return;
    }

    // Build config for the backend constructor
    const config: Record<string, unknown> = {};
    if (options && 'storeDir' in options) config.storeDir = options.storeDir;
    if (options && 'key' in options) config.key = options.key;

    // Resolve backend type
    const backendType = (options && 'backendType' in options)
      ? resolveBackendType(options.backendType as string | undefined)
      : resolveBackendType();

    this.backend = createBackend(backendType, config);
  }

  /**
   * Name of the backend this vault reads and writes (`local`,
   * `keychain-macos`, `1password`, ...). The cache layer's `cached(<name>)` is
   * given as the name of the backend under it, as SecretStore.backendName is.
   */
  get backendName(): string {
    return this.backend.name.replace(/^cached\((.*)\)$/, '$1');
  }

  /**
   * Store secrets for a specific MCP server.
   * Each secret is stored with key `mcp/{client}/{server}/{envKey}`.
   *
   * Every value is checked before the first one is written, with the same rule
   * `secret set` applies: a value holding terminal escapes or U+FFFD is a
   * capture that already lost the credential, and storing it only moves the
   * failure to the server's first request (#104). Checking up front means a
   * refusal leaves nothing of this server behind.
   */
  async storeServerSecrets(
    client: string,
    server: string,
    secrets: Record<string, string>,
  ): Promise<void> {
    validateName('client', client);
    validateName('server', server);
    for (const [envKey, value] of Object.entries(secrets)) {
      const problem = findSecretValueProblem(value);
      if (problem) throw unstorableMcpSecretError(client, server, envKey, problem);
    }
    for (const [envKey, value] of Object.entries(secrets)) {
      const storeKey = `${MCP_PREFIX}/${client}/${server}/${envKey}`;
      await this.backend.store(storeKey, value);
    }
  }

  /**
   * Retrieve all secrets for a specific MCP server.
   * Returns a map of env var names to their values.
   */
  async getServerSecrets(
    client: string,
    server: string,
  ): Promise<Record<string, string>> {
    validateName('client', client);
    validateName('server', server);
    const prefix = `${MCP_PREFIX}/${client}/${server}`;
    const raw = await this.backend.resolve(prefix);

    const result: Record<string, string> = {};
    for (const [fullKey, value] of Object.entries(raw)) {
      // Strip prefix to get just the env var name
      const envKey = fullKey.slice(prefix.length + 1);
      if (envKey) {
        result[envKey] = value;
      }
    }
    return result;
  }

  /**
   * Delete the names stored under a client/server pair, then the pair's
   * binding, each when present: a binding with no name stored is deleted too.
   * The order is part of the rule. A delete that stops part way leaves a
   * binding with no names, which the wrapper refuses and a second call
   * deletes; it never leaves names without a binding, which protect-mcp reads
   * as an earlier version's pair and may bind to the one entry that reads it.
   */
  async removeServerSecrets(client: string, server: string): Promise<void> {
    validateName('client', client);
    validateName('server', server);
    const prefix = `${MCP_PREFIX}/${client}/${server}`;
    const existing = await this.backend.resolve(prefix);

    for (const key of Object.keys(existing)) {
      await this.backend.delete(key);
    }
    const bindingKey = `${BINDING_PREFIX}/${client}/${server}`;
    const binding = await this.backend.resolve(bindingKey, { exact: true });
    if (Object.prototype.hasOwnProperty.call(binding, bindingKey)) {
      await this.backend.delete(bindingKey);
    }
  }

  /**
   * Delete a pair as removeServerSecrets does, only where the binding stored
   * for it, read again, is `expected`, the one the caller read, and the
   * secretless home whose id is `homeId` stored it, or no binding is stored
   * (see expectBinding): otherwise nothing is deleted, and
   * BindingWriteRefusedError says why.
   */
  async removeOwnedPair(client: string, server: string, expected: McpBinding | undefined, homeId: string | undefined): Promise<void> {
    await expectBinding(this, { client, server }, expected, homeId);
    await this.removeServerSecrets(client, server);
  }

  /**
   * The binding stored for a client/server pair, or undefined when none is
   * stored or what is stored is not a schema-1 binding. One read of one key,
   * in the store the pair is in.
   */
  async getBinding(client: string, server: string): Promise<McpBinding | undefined> {
    validateName('client', client);
    validateName('server', server);
    const key = `${BINDING_PREFIX}/${client}/${server}`;
    const raw = await this.backend.resolve(key, { exact: true });
    if (!Object.prototype.hasOwnProperty.call(raw, key)) return undefined;
    return parseBinding(raw[key]);
  }

  /**
   * Store the binding of a client/server pair, replacing the one stored
   * before. protect-mcp stores it before the pair's secrets, so a store that
   * refuses it leaves no secret without a binding. A binding without a
   * well-formed `boundOn` is refused, so every binding stored names the
   * secretless home that stored it.
   */
  async storeBinding(client: string, server: string, binding: McpBinding): Promise<void> {
    validateName('client', client);
    validateName('server', server);
    const text = JSON.stringify(binding);
    const parsed = parseBinding(text);
    if (parsed === undefined) {
      throw new Error(`Invalid binding for ${listedName(`${client}/${server}`)}: not a schema-1 binding.`);
    }
    if (parsed.boundOn === undefined) {
      throw new Error(`Invalid binding for ${listedName(`${client}/${server}`)}: it names no secretless home.`);
    }
    await this.backend.store(`${BINDING_PREFIX}/${client}/${server}`, text);
  }

  /**
   * List all stored server entries, grouped by client and server.
   * Returns the number of secret keys stored for each client/server pair.
   */
  async listEntries(): Promise<Array<{ client: string; server: string; keyCount: number }>> {
    const all = await this.backend.resolve(MCP_PREFIX);

    // Group by client/server
    const groups = new Map<string, number>();

    for (const fullKey of Object.keys(all)) {
      // Keys are in format: mcp/{client}/{server}/{envKey}
      const parts = fullKey.split('/');
      if (parts.length < 4) continue;

      const groupKey = `${parts[1]}/${parts[2]}`;
      groups.set(groupKey, (groups.get(groupKey) ?? 0) + 1);
    }

    const entries: Array<{ client: string; server: string; keyCount: number }> = [];
    for (const [groupKey, keyCount] of groups) {
      const [client, server] = groupKey.split('/');
      entries.push({ client, server, keyCount });
    }

    return entries;
  }
}
