/**
 * Vault core orchestration — bridges secretless-ai CLI to @opena2a/aim-core vault module.
 *
 * @opena2a/aim-core is an optional peer dependency. All vault imports are dynamic
 * so secretless-ai works without it (just shows an actionable install message).
 *
 * A credential is resolved per call and handed to one child process in its
 * environment. See vaultExec for what that keeps private and what it does not.
 * No proxy and no sidecar.
 */

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import { escapeForDisplay, escapePathForDisplay } from './display-safe';
import { canReadHidden, readHiddenLine } from './hidden-line';
import type { PromptOutput, TtyInput } from './hidden-line';

// ── Types for the dynamically loaded aim-core vault module ──────────

/** Subset of aim-core vault module we consume */
interface AimCoreVault {
  VaultStore: new (vaultDir: string) => VaultStoreInstance;
  createNamespace: (vaultDir: string, opts: CreateNamespaceOpts) => VaultNamespace;
  listNamespaces: (vaultDir: string) => VaultNamespace[];
  getNamespace: (vaultDir: string, id: string) => VaultNamespace | null;
  revokeNamespace: (vaultDir: string, id: string) => boolean;
  readVaultAudit: (vaultDir: string, opts?: AuditReadOpts) => VaultAuditEvent[];
  logVaultEvent: (vaultDir: string, event: VaultAuditEventInput) => VaultAuditEvent;
  createResolutionRequest: (
    namespace: string,
    operation: VaultOperation,
    agentId: string,
    edSecretKey: Uint8Array,
  ) => VaultResolutionRequest;
  resolveWithPolicy: (
    request: VaultResolutionRequest,
    context: ResolutionContext,
  ) => VaultResolutionResult;
  zeroize: (data: Uint8Array) => void;
}

/** Subset of aim-core identity module we consume */
interface AimCoreIdentity {
  loadIdentity: (dataDir: string) => StoredIdentity | null;
  createIdentity: (dataDir: string, agentName: string) => StoredIdentity;
  getSecretKey: (dataDir: string) => Uint8Array | null;
  getPublicKey: (dataDir: string) => Uint8Array | null;
}

interface VaultStoreInstance {
  init(agentId: string, edSecretKey: Uint8Array): void;
  exists(): boolean;
  unlock(edSecretKey: Uint8Array): void;
  storeCredential(namespace: string, credential: Uint8Array): void;
  resolveCredential(namespace: string): Uint8Array;
  listCredentials(): Array<{ namespace: string; version: number; encryptedAt: string }>;
  deleteCredential(namespace: string): boolean;
  rotateCredential(namespace: string, newCredential: Uint8Array): void;
  getAgentId(): string;
  destroy(): void;
  lock(): void;
}

interface StoredIdentity {
  agentId: string;
  publicKey: string;
  secretKey: string;
  agentName: string;
  createdAt: string;
}

type VaultOperation = 'read' | 'write' | 'delete' | 'admin';
type NamespaceStatus = 'active' | 'revoked';

interface VaultNamespace {
  id: string;
  description: string;
  agentId: string;
  operations: VaultOperation[];
  urlPatterns: string[];
  status: NamespaceStatus;
  createdAt: string;
  updatedAt: string;
}

interface CreateNamespaceOpts {
  id: string;
  description: string;
  agentId: string;
  operations: VaultOperation[];
  urlPatterns: string[];
}

interface VaultResolutionRequest {
  namespace: string;
  operation: VaultOperation;
  signature: string;
  nonce: string;
  agentId: string;
}

interface VaultResolutionResult {
  success: boolean;
  credential?: Uint8Array;
  error?: string;
  namespace: string;
  version?: number;
}

interface ResolutionContext {
  vaultDir: string;
  store: VaultStoreInstance;
  edPublicKey: Uint8Array;
  checkCapability?: (capability: string) => boolean;
}

interface VaultAuditEvent {
  timestamp: string;
  agentId: string;
  namespace?: string;
  operation: string;
  result: 'granted' | 'denied' | 'error';
  denyReason?: string;
  metadata?: Record<string, unknown>;
}

type VaultAuditEventInput = Omit<VaultAuditEvent, 'timestamp'>;

interface AuditReadOpts {
  limit?: number;
  since?: string;
  namespace?: string;
}

// ── Paths ──────────────────────────────────────────────────────────

const HOME = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
const VAULT_DIR = path.join(HOME, '.aim', 'vault');
const AIM_DATA_DIR = path.join(HOME, '.opena2a', 'aim-core');

// The file in AIM_DATA_DIR that @opena2a/aim-core keeps the identity in.
const IDENTITY_FILE = path.join(AIM_DATA_DIR, 'identity.json');

// The same two directories, and the identity file, as messages show them.
const VAULT_DIR_SHOWN = '~/.aim/vault';
const AIM_DATA_DIR_SHOWN = '~/.opena2a/aim-core';
const IDENTITY_FILE_SHOWN = `${AIM_DATA_DIR_SHOWN}/identity.json`;

// ── Dynamic import ─────────────────────────────────────────────────

let cachedVault: AimCoreVault | null = null;
let cachedIdentity: AimCoreIdentity | null = null;

/**
 * Dynamically import @opena2a/aim-core vault module.
 * Throws an actionable error if the package is not installed.
 */
export async function loadAimCoreVault(): Promise<AimCoreVault> {
  if (cachedVault) return cachedVault;

  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('@opena2a/aim-core');
    cachedVault = mod.vault as unknown as AimCoreVault;
    return cachedVault;
  } catch {
    throw new Error(
      '@opena2a/aim-core is required for vault commands.\n' +
      '  Install it:  npm install @opena2a/aim-core\n' +
      '  Or link it:  npm link @opena2a/aim-core',
    );
  }
}

/**
 * Dynamically import @opena2a/aim-core identity functions.
 */
export async function loadAimCoreIdentity(): Promise<AimCoreIdentity> {
  if (cachedIdentity) return cachedIdentity;

  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('@opena2a/aim-core');
    cachedIdentity = {
      loadIdentity: mod.loadIdentity,
      createIdentity: mod.createIdentity,
      getSecretKey: mod.getSecretKey as AimCoreIdentity['getSecretKey'] ?? null,
      getPublicKey: mod.getPublicKey as AimCoreIdentity['getPublicKey'] ?? null,
    };

    // getSecretKey/getPublicKey may not be re-exported from index — fall back
    if (!cachedIdentity.getSecretKey) {
      cachedIdentity.getSecretKey = (dataDir: string) => {
        const stored = cachedIdentity!.loadIdentity(dataDir);
        if (!stored) return null;
        return Buffer.from(stored.secretKey, 'base64');
      };
      cachedIdentity.getPublicKey = (dataDir: string) => {
        const stored = cachedIdentity!.loadIdentity(dataDir);
        if (!stored) return null;
        return Buffer.from(stored.publicKey, 'base64');
      };
    }

    return cachedIdentity;
  } catch {
    throw new Error(
      '@opena2a/aim-core is required for vault commands.\n' +
      '  Install it:  npm install @opena2a/aim-core\n' +
      '  Or link it:  npm link @opena2a/aim-core',
    );
  }
}

// ── Agent identity helpers ─────────────────────────────────────────

/**
 * Get or create the agent's Ed25519 identity.
 * Returns the stored identity (including secret key for signing).
 *
 * An identity is created under agentName only when there is no
 * identity.json. One that cannot be read, is not JSON, or holds no agentId,
 * publicKey or secretKey is left in place, and the call rejects with the
 * error `vault init` gives in that state, which names the file.
 */
export async function getOrCreateAgent(agentName?: string): Promise<StoredIdentity> {
  const read = await readAgentIdentity();
  if (read.kind === 'found') return read.agent;
  if (read.kind === 'unusable') {
    const vault = await loadAimCoreVault();
    throw identityError(read, new vault.VaultStore(VAULT_DIR).exists());
  }
  const identity = await loadAimCoreIdentity();
  return identity.createIdentity(AIM_DATA_DIR, agentName ?? 'secretless-agent');
}

/**
 * What reading the agent identity found: an identity that holds the fields
 * the vault uses, no identity.json, or an identity.json that is there and
 * cannot be used, with what is wrong with it.
 */
type IdentityRead =
  | { kind: 'found'; agent: StoredIdentity }
  | { kind: 'missing' }
  | { kind: 'unusable'; problem: string };

const IDENTITY_FIELDS = ['agentId', 'publicKey', 'secretKey'] as const;

/** The fields of IDENTITY_FIELDS that value does not hold as a non-empty string. */
function missingIdentityFields(value: unknown): string[] {
  const record = (value !== null && typeof value === 'object' ? value : {}) as Record<string, unknown>;
  return IDENTITY_FIELDS.filter((field) => typeof record[field] !== 'string' || record[field] === '');
}

/** 'a', 'a or b', 'a, b or c'. */
function orList(items: string[]): string {
  return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} or ${items[items.length - 1]}`;
}

/**
 * Reads the agent identity in AIM_DATA_DIR. loadIdentity returns null both
 * when identity.json is absent and when it cannot be read or parsed, and
 * returns whatever JSON the file holds, so the file is read again here to
 * tell an absent file from one that is there and cannot be used.
 */
async function readAgentIdentity(): Promise<IdentityRead> {
  const identity = await loadAimCoreIdentity();
  const agent = identity.loadIdentity(AIM_DATA_DIR);
  if (agent && missingIdentityFields(agent).length === 0) return { kind: 'found', agent };

  let raw: string;
  try {
    raw = fs.readFileSync(IDENTITY_FILE, 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return { kind: 'missing' };
    return { kind: 'unusable', problem: `cannot be read (${code ?? 'read error'})` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { kind: 'unusable', problem: 'is not valid JSON' };
  }
  const missing = missingIdentityFields(parsed);
  // A file that holds an identity now was written after loadIdentity read it.
  if (missing.length === 0) return { kind: 'found', agent: parsed as StoredIdentity };
  return { kind: 'unusable', problem: `holds no agent identity (no ${orList(missing)})` };
}

/**
 * What is wrong when no identity can be used and the step that recovers from
 * it: the vault exists, or identity.json is there and cannot be used. A new
 * identity would not decrypt the credentials in a vault, and would replace
 * the key in an identity.json that other tools that use @opena2a/aim-core
 * can share, so neither state creates one. `vault init`, the other vault
 * commands and `vault test` give the same step. The last line of `fix` is
 * the command.
 */
function identityProblem(
  read: Exclude<IdentityRead, { kind: 'found' }>,
  vaultExists: boolean,
): { summary: string[]; reason: string; fix: string[] } {
  const fileProblem = read.kind === 'unusable' ? [`${IDENTITY_FILE_SHOWN} ${read.problem}.`] : [];
  const moveIdentity = `mv ${IDENTITY_FILE_SHOWN} ${IDENTITY_FILE_SHOWN}.old`;
  if (!vaultExists) {
    return {
      summary: fileProblem,
      reason: `Other tools that use @opena2a/aim-core can share ${AIM_DATA_DIR_SHOWN}, so no new identity was written over that file.`,
      fix: [
        'Restore it from a backup, or move it aside and start with a new identity:',
        `  ${moveIdentity} && secretless-ai vault init`,
      ],
    };
  }
  return {
    summary: [`Vault exists, but no agent identity could be read from ${AIM_DATA_DIR_SHOWN}.`, ...fileProblem],
    reason: "The credentials in the vault decrypt only with that identity's key, so no new identity was created.",
    fix: read.kind === 'unusable'
      ? [
        `Restore ${IDENTITY_FILE_SHOWN} from a backup, or move it and the vault aside and start a new vault,`,
        'which leaves the credentials in the old vault unreadable:',
        `  mv ${VAULT_DIR_SHOWN} ${VAULT_DIR_SHOWN}.old && ${moveIdentity} && secretless-ai vault init`,
      ]
      : [
        `Restore ${AIM_DATA_DIR_SHOWN} from a backup, or move the vault aside and start a new one,`,
        'which leaves the credentials in the old vault unreadable:',
        `  mv ${VAULT_DIR_SHOWN} ${VAULT_DIR_SHOWN}.old && secretless-ai vault init`,
      ],
  };
}

/** The refusal for the states identityProblem describes. */
function identityError(read: Exclude<IdentityRead, { kind: 'found' }>, vaultExists: boolean): Error {
  const { summary, reason, fix } = identityProblem(read, vaultExists);
  const [first, ...rest] = [...summary, reason, ...fix];
  return new Error([first, ...rest.map((line) => `  ${line}`)].join('\n'));
}

/**
 * The name an identity carries: its agentName when that is a non-empty
 * string. identity.json is read as it is, so agentName can be absent or not
 * a string in an identity that holds the agentId, publicKey and secretKey
 * the vault uses (#506).
 */
function agentNameOf(agent: StoredIdentity): string | undefined {
  const name: unknown = agent.agentName;
  return typeof name === 'string' && name !== '' ? name : undefined;
}

/** An identity as an `Agent:` line shows it: name and agentId, or agentId and `(no name)`. */
function agentShown(agent: StoredIdentity): string {
  const name = agentNameOf(agent);
  return name === undefined ? `${agent.agentId} (no name)` : `${escapeForDisplay(name)} (${agent.agentId})`;
}

/**
 * Get an unlocked VaultStore instance.
 *
 * Writes nothing: the vault is checked before the identity, and the identity
 * is read, never created. Only `vault init` creates one.
 */
export async function getVaultStore(): Promise<{
  store: VaultStoreInstance;
  agent: StoredIdentity;
  edSecretKey: Uint8Array;
  edPublicKey: Uint8Array;
}> {
  const vault = await loadAimCoreVault();
  const store = new vault.VaultStore(VAULT_DIR);
  if (!store.exists()) {
    throw new Error(
      'Vault not initialized. Run:\n' +
      '  secretless-ai vault init',
    );
  }

  const read = await readAgentIdentity();
  if (read.kind !== 'found') throw identityError(read, true);
  const agent = read.agent;
  const edSecretKey = Buffer.from(agent.secretKey, 'base64');
  const edPublicKey = Buffer.from(agent.publicKey, 'base64');

  store.unlock(edSecretKey);
  return { store, agent, edSecretKey, edPublicKey };
}

// ── Vault commands ─────────────────────────────────────────────────

/**
 * Initialize a new vault for the current agent identity.
 * Creates ~/.aim/vault/ with an empty encrypted vault file.
 *
 * Other tools that use @opena2a/aim-core can share ~/.opena2a/aim-core, so an
 * identity that can be read there is used as it is, never renamed or
 * replaced, and an agentName it does not carry is reported as not applied.
 * An identity is created under agentName only when there is no vault and no
 * identity.json. An identity.json that cannot be read, is not JSON, or holds
 * no agentId, publicKey or secretKey is left in place, and the command fails
 * naming it, as it does with a vault and no identity that can be read.
 */
export async function vaultInit(agentName?: string): Promise<void> {
  const vault = await loadAimCoreVault();
  const identity = await loadAimCoreIdentity();
  const store = new vault.VaultStore(VAULT_DIR);

  const read = await readAgentIdentity();
  let agent: StoredIdentity;
  if (read.kind === 'found') {
    agent = read.agent;
    if (agentName !== undefined && agentName !== agent.agentName) {
      const existing = agentNameOf(agent);
      const which = existing === undefined ? 'it carries no name' : `agent ${escapeForDisplay(existing)}`;
      console.log(
        `\n  An agent identity already exists in ${AIM_DATA_DIR_SHOWN} ` +
        `(${which}); --name ${escapeForDisplay(agentName)} was not applied.`,
      );
    }
  } else if (read.kind === 'missing' && !store.exists()) {
    agent = identity.createIdentity(AIM_DATA_DIR, agentName ?? 'secretless-agent');
  } else {
    throw identityError(read, store.exists());
  }
  const edSecretKey = Buffer.from(agent.secretKey, 'base64');

  if (store.exists()) {
    console.log(`\n  Vault already initialized for agent ${agent.agentId}\n`);
    console.log(`  Vault path:  ${VAULT_DIR}`);
    console.log(`  Agent:       ${agentShown(agent)}\n`);
    return;
  }

  store.init(agent.agentId, edSecretKey);

  vault.logVaultEvent(VAULT_DIR, {
    agentId: agent.agentId,
    operation: 'vault:init',
    result: 'granted',
  });

  console.log('\n  Identity Vault initialized.\n');
  console.log(`  Vault path:  ${VAULT_DIR}`);
  console.log(`  Agent:       ${agentShown(agent)}`);
  console.log(`  Crypto:      XSalsa20-Poly1305, Ed25519 identity-bound`);
  console.log(`  Identity:    ${AIM_DATA_DIR}\n`);
  console.log('  Next steps:');
  console.log('    secretless-ai vault register github        (prompts for the token)');
  console.log('    secretless-ai vault list');
  // The child is given the credential as $GITHUB; the example reads it in the
  // child's shell and passes it to curl on stdin, off the command line (#410).
  console.log(`    secretless-ai vault exec github -- sh -c 'printf "Authorization: Bearer %s\\n" "$GITHUB" | curl -s -H @- https://api.github.com/user'\n`);

  vault.zeroize(edSecretKey);
}

/**
 * Register a credential in a vault namespace.
 */
export async function vaultRegister(
  namespace: string,
  options: {
    value?: string;
    description?: string;
    operations?: VaultOperation[];
    urlPatterns?: string[];
    envVar?: string;
  },
): Promise<void> {
  const vault = await loadAimCoreVault();
  const { store, agent, edSecretKey } = await getVaultStore();

  // Get credential value
  let credentialValue: string;
  if (options.value !== undefined) {
    credentialValue = options.value;
  } else if (options.envVar) {
    const envVal = process.env[options.envVar];
    if (envVal === undefined) {
      throw new Error(`Environment variable ${options.envVar} is not set`);
    }
    credentialValue = envVal;
  } else {
    // Read from stdin (piped or prompt)
    credentialValue = await readCredentialFromStdin(namespace);
  }

  // An empty value is refused before the namespace, the store or the audit
  // log is touched, so stdin at end of input never registers a blank credential.
  if (credentialValue.trim() === '') {
    vault.zeroize(edSecretKey);
    store.lock();
    throw new Error('no value provided. Pipe the value on stdin, or use --env NAME.');
  }

  // Create namespace if it doesn't exist
  const existingNs = vault.getNamespace(VAULT_DIR, namespace);
  if (!existingNs) {
    vault.createNamespace(VAULT_DIR, {
      id: namespace,
      description: options.description ?? `Credentials for ${namespace}`,
      agentId: agent.agentId,
      operations: options.operations ?? ['read'],
      urlPatterns: options.urlPatterns ?? [],
    });
  }

  // Encrypt and store
  const credentialBytes = new TextEncoder().encode(credentialValue);
  store.storeCredential(namespace, credentialBytes);

  vault.logVaultEvent(VAULT_DIR, {
    agentId: agent.agentId,
    namespace,
    operation: 'store',
    result: 'granted',
  });

  console.log(`\n  Credential registered in namespace "${namespace}".`);
  console.log(`  Version: ${store.listCredentials().find(c => c.namespace === namespace)?.version ?? 1}`);
  console.log(`\n  Use it:  secretless-ai vault exec ${namespace} -- <command>\n`);

  // Zeroize sensitive material
  credentialBytes.fill(0);
  vault.zeroize(edSecretKey);
  store.lock();
}

/**
 * List all vault credentials (metadata only — no values).
 */
export async function vaultList(): Promise<void> {
  const vault = await loadAimCoreVault();
  const { store, edSecretKey } = await getVaultStore();

  const credentials = store.listCredentials();
  const namespaces = vault.listNamespaces(VAULT_DIR);

  if (credentials.length === 0) {
    console.log('\n  No credentials in vault.\n');
    console.log('  Register one:  secretless-ai vault register <namespace>   (prompts for the value)\n');
    vault.zeroize(edSecretKey);
    store.lock();
    return;
  }

  console.log('\n  Identity Vault Credentials\n');
  for (const cred of credentials) {
    const ns = namespaces.find(n => n.id === cred.namespace);
    const status = ns?.status ?? 'unknown';
    const statusLabel = status === 'active' ? 'active' : 'REVOKED';
    console.log(`  ${cred.namespace}`);
    console.log(`    Status:      ${statusLabel}`);
    console.log(`    Version:     ${cred.version}`);
    console.log(`    Encrypted:   ${cred.encryptedAt}`);
    if (ns?.operations.length) {
      console.log(`    Operations:  ${ns.operations.join(', ')}`);
    }
    if (ns?.urlPatterns.length) {
      console.log(`    URL patterns: ${ns.urlPatterns.join(', ')}`);
    }
    console.log();
  }

  vault.zeroize(edSecretKey);
  store.lock();
}

/**
 * Rotate a credential in a vault namespace.
 */
export async function vaultRotate(
  namespace: string,
  options: { value?: string; envVar?: string },
): Promise<void> {
  const vault = await loadAimCoreVault();
  const { store, agent, edSecretKey } = await getVaultStore();

  // Get new credential value
  let credentialValue: string;
  if (options.value !== undefined) {
    credentialValue = options.value;
  } else if (options.envVar) {
    const envVal = process.env[options.envVar];
    if (envVal === undefined) {
      throw new Error(`Environment variable ${options.envVar} is not set`);
    }
    credentialValue = envVal;
  } else {
    credentialValue = await readCredentialFromStdin(namespace);
  }

  // An empty value is refused before the store or the audit log is touched,
  // so stdin at end of input never replaces a working credential with a blank one.
  if (credentialValue.trim() === '') {
    vault.zeroize(edSecretKey);
    store.lock();
    throw new Error('no value provided. Pipe the value on stdin, or use --env NAME.');
  }

  const credentialBytes = new TextEncoder().encode(credentialValue);
  store.rotateCredential(namespace, credentialBytes);

  vault.logVaultEvent(VAULT_DIR, {
    agentId: agent.agentId,
    namespace,
    operation: 'rotate',
    result: 'granted',
  });

  const meta = store.listCredentials().find(c => c.namespace === namespace);
  console.log(`\n  Credential rotated for namespace "${namespace}".`);
  console.log(`  New version: ${meta?.version ?? '?'}\n`);

  credentialBytes.fill(0);
  vault.zeroize(edSecretKey);
  store.lock();
}

/**
 * Revoke a namespace — credentials can no longer be resolved.
 */
export async function vaultRevoke(namespace: string): Promise<void> {
  const vault = await loadAimCoreVault();
  const { store, agent, edSecretKey } = await getVaultStore();

  const revoked = vault.revokeNamespace(VAULT_DIR, namespace);
  if (revoked) {
    store.deleteCredential(namespace);

    vault.logVaultEvent(VAULT_DIR, {
      agentId: agent.agentId,
      namespace,
      operation: 'namespace:revoke',
      result: 'granted',
    });

    console.log(`\n  Namespace "${namespace}" revoked and credential deleted.\n`);
  } else {
    console.log(`\n  Namespace "${namespace}" was already revoked.\n`);
  }

  vault.zeroize(edSecretKey);
  store.lock();
}

/**
 * Show vault audit log.
 */
export async function vaultAudit(options: {
  limit?: number;
  since?: string;
  namespace?: string;
}): Promise<void> {
  const vault = await loadAimCoreVault();

  const events = vault.readVaultAudit(VAULT_DIR, {
    limit: options.limit ?? 50,
    since: options.since,
    namespace: options.namespace,
  });

  if (events.length === 0) {
    console.log('\n  No audit events found.\n');
    return;
  }

  console.log('\n  Vault Audit Log\n');
  for (const event of events) {
    const resultLabel = event.result === 'granted' ? 'OK' :
                        event.result === 'denied' ? 'DENIED' : 'ERROR';
    const ns = event.namespace ? ` [${event.namespace}]` : '';
    const reason = event.denyReason ? ` — ${event.denyReason}` : '';
    console.log(`  ${event.timestamp}  ${resultLabel}  ${event.operation}${ns}${reason}`);
  }
  console.log();
}

/**
 * Scan for hardcoded credentials and suggest vault migration.
 */
export async function vaultScan(targetDir?: string): Promise<void> {
  // Re-use secretless-ai's existing scan infrastructure
  const { scan, newScanStats, coverageIncomplete } = await import('./scan.js');
  const dir = targetDir ?? process.cwd();

  console.log(`\n  Scanning ${dir} for credentials to migrate to vault...\n`);

  // Coverage shortfalls are collected here too. `scan()` discards them when no
  // stats object is passed, so this command printed the same unqualified
  // "No hardcoded credentials found" over a truncated, unreadable or
  // oversize-skipped tree that `scan` itself was fixed to stop printing.
  const stats = newScanStats();
  const findings = scan(dir, { includeTests: false }, stats);
  const incomplete = coverageIncomplete(stats);
  if (findings.length === 0) {
    if (incomplete) {
      console.log('  No credentials found in the files scanned.');
      if (stats.truncated) console.log('  Scan incomplete: stopped at the file cap, so files were left unscanned.');
      if (stats.unreadable.length > 0) console.log(`  ${stats.unreadable.length} path(s) could not be read, so they are not known to be clean.`);
      if (stats.oversize.length > 0) console.log(`  ${stats.oversize.length} file(s) skipped for size, so they are not known to be clean.`);
      console.log('  Check coverage: secretless-ai scan --json | jq .summary\n');
      return;
    }
    console.log('  No hardcoded credentials found.\n');
    return;
  }

  console.log(`  Found ${findings.length} credential(s) that could be moved to the vault:\n`);
  for (const finding of findings) {
    const relPath = path.relative(dir, finding.file);
    // A name from the scanned tree, escaped as `scan` escapes it: printed raw,
    // an ESC or an OSC sequence in a directory name reached the terminal.
    console.log(`  ${escapePathForDisplay(relPath)}:${finding.line}`);
    console.log(`    Pattern:  ${finding.patternId}`);
    console.log(`    Migrate:  secretless-ai vault register ${finding.patternId.toLowerCase()}`);
    console.log();
  }

  console.log('  register prompts for the value, reads it from a pipe, or takes --env <VAR>,');
  console.log('  so the value stays out of shell history and the process list.\n');

  console.log('  After registering, use vault exec to inject credentials at runtime:');
  console.log('    secretless-ai vault exec <namespace> -- <command>\n');
}

/**
 * Run a command with one vault credential set in its environment.
 *
 * 1. Resolve the credential through the policy-checked flow (signed request).
 * 2. Start the child with the credential as an environment variable. The
 *    child inherits this process's standard streams.
 * 3. When the child exits, zeroize the credential bytes and the signing key.
 *    The decoded string handed to the child cannot be zeroized.
 *
 * The value is not exported to the calling shell and is not placed on a
 * command line. The child holds it in its environment while it runs. What
 * the child prints is not masked and reaches the caller, and another process
 * running as the same user can read a running child's environment.
 */
export async function vaultExec(
  namespace: string,
  command: string[],
  options?: { envName?: string },
): Promise<number> {
  if (command.length === 0) {
    throw new Error('No command specified. Usage: secretless-ai vault exec <namespace> -- <command>');
  }

  const vault = await loadAimCoreVault();
  const { store, agent, edSecretKey, edPublicKey } = await getVaultStore();

  // Step 1: Create signed resolution request
  const request = vault.createResolutionRequest(
    namespace,
    'read',
    agent.agentId,
    edSecretKey,
  );

  // Step 2: Resolve with policy enforcement
  const result = vault.resolveWithPolicy(request, {
    vaultDir: VAULT_DIR,
    store,
    edPublicKey,
  });

  if (!result.success || !result.credential) {
    vault.zeroize(edSecretKey);
    store.lock();
    throw new Error(`Vault resolution denied: ${result.error ?? 'unknown error'}`);
  }

  // Step 3: Decode credential to string for env var injection
  const credentialStr = new TextDecoder().decode(result.credential);

  // Determine env var name: --env-name flag, or uppercase namespace with dashes replaced
  const envName = options?.envName ?? namespace.toUpperCase().replace(/-/g, '_');

  // Step 4: Spawn child process with credential as env var
  const childEnv = { ...process.env, [envName]: credentialStr };

  const child = spawn(command[0], command.slice(1), {
    env: childEnv,
    stdio: 'inherit',
  });

  // Forward signals
  const signals: NodeJS.Signals[] = ['SIGTERM', 'SIGINT', 'SIGHUP'];
  const handlers: Array<() => void> = [];
  for (const sig of signals) {
    const handler = () => child.kill(sig);
    handlers.push(handler);
    process.on(sig, handler);
  }

  const exitCode = await new Promise<number>((resolve) => {
    child.on('close', (code) => {
      for (let i = 0; i < signals.length; i++) {
        process.removeListener(signals[i], handlers[i]);
      }
      resolve(code ?? 1);
    });

    child.on('error', (err) => {
      process.stderr.write(`secretless: Failed to start ${command[0]}: ${err.message}\n`);
      for (let i = 0; i < signals.length; i++) {
        process.removeListener(signals[i], handlers[i]);
      }
      resolve(1);
    });
  });

  // Step 5: Zeroize all credential material
  vault.zeroize(result.credential);
  vault.zeroize(edSecretKey);
  // credentialStr is a JS string — can't zeroize, but it was only in this process
  // and the child process's env was a copy. Both are cleaned up on exit.

  store.lock();
  return exitCode;
}

/**
 * Test vault functionality — verify init, register, resolve, zeroize cycle.
 * Resolves true after `All checks passed.`, and false after a `[FAIL]` line.
 */
export async function vaultTest(): Promise<boolean> {
  const vault = await loadAimCoreVault();

  console.log('\n  Vault Self-Test\n');

  // Check 1: aim-core available
  console.log('  [OK]  @opena2a/aim-core loaded');

  // Check 2: Identity exists. `vault init` creates one only when there is
  // neither a vault nor an identity.json; otherwise the step is the one
  // `vault init` gives when it refuses.
  const read = await readAgentIdentity();
  const store = new vault.VaultStore(VAULT_DIR);
  if (read.kind !== 'found') {
    if (read.kind === 'missing' && !store.exists()) {
      console.log('  [FAIL]  No agent identity found');
      console.log('          Fix: secretless-ai vault init\n');
      return false;
    }
    const { summary, fix } = identityProblem(read, store.exists());
    const [first, ...rest] = summary;
    console.log(`  [FAIL]  ${first}`);
    for (const line of rest) console.log(`          ${line}`);
    console.log(`          Fix: ${fix[0]}`);
    for (const line of fix.slice(1)) console.log(`               ${line}`);
    console.log('');
    return false;
  }
  const stored = read.agent;
  console.log(`  [OK]  Agent identity: ${stored.agentId}`);

  // Check 3: Vault exists
  if (!store.exists()) {
    console.log('  [FAIL]  Vault not initialized');
    console.log('          Fix: secretless-ai vault init\n');
    return false;
  }
  console.log('  [OK]  Vault exists at ~/.aim/vault/');

  // Check 4: Vault unlockable
  try {
    const edSecretKey = Buffer.from(stored.secretKey, 'base64');
    store.unlock(edSecretKey);
    console.log('  [OK]  Vault unlocks with agent identity');
    vault.zeroize(edSecretKey);
  } catch (err) {
    console.log(`  [FAIL]  Vault unlock failed: ${err instanceof Error ? err.message : String(err)}`);
    return false;
  }

  // Check 5: Credential count
  const creds = store.listCredentials();
  console.log(`  [OK]  ${creds.length} credential(s) stored`);

  // Check 6: Audit log accessible
  const events = vault.readVaultAudit(VAULT_DIR, { limit: 1 });
  console.log(`  [OK]  Audit log: ${events.length > 0 ? 'has events' : 'empty (new vault)'}`);

  store.lock();
  console.log('\n  All checks passed.\n');
  return true;
}

/**
 * Migrate credentials from secretless SecretStore to the identity vault.
 */
export async function vaultMigrate(options: {
  dryRun?: boolean;
  envFile?: string;
}): Promise<void> {
  const vault = await loadAimCoreVault();

  console.log('\n  Vault Migration\n');

  if (options.envFile) {
    // Migrate from .env file
    await migrateFromEnvFile(vault, options.envFile, options.dryRun ?? false);
    return;
  }

  // Migrate from SecretStore
  const { SecretStore } = await import('./secret-store.js');
  const secretStore = new SecretStore();
  const secretNames = await secretStore.listSecrets();

  if (secretNames.length === 0) {
    console.log('  No secrets found in SecretStore to migrate.\n');
    console.log('  To migrate from a .env file:');
    console.log('    secretless-ai vault migrate --env-file .env\n');
    return;
  }

  console.log(`  Found ${secretNames.length} secret(s) in SecretStore:\n`);

  const { store, agent, edSecretKey } = await getVaultStore();

  let migrated = 0;
  let skipped = 0;

  for (const name of secretNames) {
    const namespace = name.toLowerCase().replace(/_/g, '-');
    const existingNs = vault.getNamespace(VAULT_DIR, namespace);

    if (existingNs) {
      console.log(`  SKIP  ${name} -> ${namespace} (namespace already exists)`);
      skipped++;
      continue;
    }

    if (options.dryRun) {
      console.log(`  WOULD  ${name} -> ${namespace}`);
      migrated++;
      continue;
    }

    const value = await secretStore.getSecret(name);
    if (!value) {
      console.log(`  SKIP  ${name} (empty value)`);
      skipped++;
      continue;
    }

    // Create namespace and store credential
    vault.createNamespace(VAULT_DIR, {
      id: namespace,
      description: `Migrated from SecretStore: ${name}`,
      agentId: agent.agentId,
      operations: ['read'],
      urlPatterns: [],
    });

    const credentialBytes = new TextEncoder().encode(value);
    store.storeCredential(namespace, credentialBytes);
    credentialBytes.fill(0);

    vault.logVaultEvent(VAULT_DIR, {
      agentId: agent.agentId,
      namespace,
      operation: 'store',
      result: 'granted',
      metadata: { migratedFrom: 'SecretStore', originalName: name },
    });

    console.log(`  OK    ${name} -> ${namespace}`);
    migrated++;
  }

  vault.zeroize(edSecretKey);
  store.lock();

  console.log();
  if (options.dryRun) {
    console.log(`  Dry run: ${migrated} would migrate, ${skipped} skipped.`);
    console.log('  Run without --dry-run to execute.\n');
  } else {
    console.log(`  Migrated: ${migrated}, Skipped: ${skipped}`);
    console.log('\n  Verify: secretless-ai vault list\n');
  }
}

// ── Private helpers ────────────────────────────────────────────────

/**
 * @internal The credential `vault register` and `vault rotate` read when no
 * value or `--env` is given: stdin to its end when it is not a terminal, else
 * one line typed at a prompt on stderr. A terminal is read with echo off, as
 * `secret set` reads one (#234): read through readline, the typed value was
 * shown after the prompt and stayed in scrollback. Ctrl-C at that prompt, or
 * Ctrl-D while its line is empty, answers nothing, which the caller refuses as
 * it refuses an empty value.
 */
export async function readCredentialFromStdin(
  namespace: string,
  stdin: TtyInput = process.stdin,
  output: PromptOutput = process.stderr,
): Promise<string> {
  // If stdin is a pipe, read from it
  if (!stdin.isTTY) {
    return new Promise<string>((resolve, reject) => {
      let data = '';
      stdin.setEncoding('utf-8');
      stdin.on('data', (chunk) => { data += chunk; });
      stdin.on('end', () => resolve(data.trim()));
      stdin.on('error', reject);
    });
  }

  if (canReadHidden(stdin)) {
    const result = await readHiddenLine(stdin, output, `  Enter credential for "${namespace}" (input hidden): `);
    return result.kind === 'line' ? result.value.trim() : '';
  }

  // A terminal that cannot turn echo off is read as before.
  const rl = readline.createInterface({
    input: stdin,
    output: process.stderr, // Prompt on stderr so stdout stays clean
  });

  return new Promise<string>((resolve) => {
    rl.question(`  Enter credential for "${namespace}": `, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function migrateFromEnvFile(
  vault: AimCoreVault,
  envFilePath: string,
  dryRun: boolean,
): Promise<void> {
  const absPath = path.resolve(envFilePath);
  if (!fs.existsSync(absPath)) {
    throw new Error(`File not found: ${absPath}`);
  }

  const { parseEnvFile } = await import('./env-import.js');
  const entries = parseEnvFile(fs.readFileSync(absPath, 'utf-8'));

  if (entries.length === 0) {
    console.log('  No entries found in env file.\n');
    return;
  }

  console.log(`  Found ${entries.length} entries in ${envFilePath}:\n`);

  const { store, agent, edSecretKey } = await getVaultStore();

  let migrated = 0;
  let skipped = 0;

  for (const entry of entries) {
    const namespace = entry.name.toLowerCase().replace(/_/g, '-');
    const existingNs = vault.getNamespace(VAULT_DIR, namespace);

    if (existingNs) {
      console.log(`  SKIP  ${entry.name} -> ${namespace} (namespace already exists)`);
      skipped++;
      continue;
    }

    if (dryRun) {
      console.log(`  WOULD  ${entry.name} -> ${namespace}`);
      migrated++;
      continue;
    }

    vault.createNamespace(VAULT_DIR, {
      id: namespace,
      description: `Migrated from ${path.basename(envFilePath)}: ${entry.name}`,
      agentId: agent.agentId,
      operations: ['read'],
      urlPatterns: [],
    });

    const credentialBytes = new TextEncoder().encode(entry.value);
    store.storeCredential(namespace, credentialBytes);
    credentialBytes.fill(0);

    vault.logVaultEvent(VAULT_DIR, {
      agentId: agent.agentId,
      namespace,
      operation: 'store',
      result: 'granted',
      metadata: { migratedFrom: envFilePath, originalName: entry.name },
    });

    console.log(`  OK    ${entry.name} -> ${namespace}`);
    migrated++;
  }

  vault.zeroize(edSecretKey);
  store.lock();

  console.log();
  if (dryRun) {
    console.log(`  Dry run: ${migrated} would migrate, ${skipped} skipped.`);
    console.log('  Run without --dry-run to execute.\n');
  } else {
    console.log(`  Migrated: ${migrated}, Skipped: ${skipped}`);
    if (!dryRun && migrated > 0) {
      console.log(`\n  Consider removing credentials from ${envFilePath} now that they are in the vault.`);
    }
    console.log('\n  Verify: secretless-ai vault list\n');
  }
}

// ── Exported paths (for testing) ───────────────────────────────────

export const PATHS = {
  vaultDir: VAULT_DIR,
  aimDataDir: AIM_DATA_DIR,
} as const;
