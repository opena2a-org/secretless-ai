/**
 * Secret push — write named secrets from this machine's store to a cloud
 * secret store, so a deployment reads them from there (#235).
 *
 * The other way to do this is `secret get NAME` piped into a cloud CLI, which
 * puts the value on that CLI's command line: in process listings and in shell
 * history. Here the value goes from the local store into an HTTPS request body
 * inside this process. Nothing here returns, logs or formats a value: the
 * result names entries, the identifier and version each write produced, and a
 * failure is carried as text that holds no value.
 *
 * Order, so a refusal leaves the target as it was:
 *   1. every name is checked against this machine's store; one that is not
 *      stored fails the whole push before the target is contacted;
 *   2. the target authenticates;
 *   3. every value is read from the local store;
 *   4. the writes run in order, and the first one that fails stops the rest.
 * A dry run stops after asking the target, per name, whether it already holds
 * a version. It reads metadata only, never a value, and writes nothing.
 */

import type { SecretStore } from './secret-store';
import { isValidSecretName } from './secret-store';
import type { VaultBackend } from './backends/vault';
import type { GCPSecretManagerBackend } from './backends/gcp-sm';
import { CLI } from './commands/utils';

export type PushTargetType = 'azure-kv' | 'vault' | 'gcp-sm';
export const PUSH_TARGETS: readonly PushTargetType[] = ['azure-kv', 'vault', 'gcp-sm'];

/**
 * A failure that says what to check and what to run. The message names the
 * target and the entry, never a value, token or response body.
 */
export class PushError extends Error {
  override readonly name = 'PushError';
  constructor(
    message: string,
    readonly verify: readonly string[] = [],
    readonly fix: readonly string[] = [],
  ) {
    super(message);
  }
}

/** Names the push was asked for that this machine's store does not hold. */
export class MissingLocalNamesError extends PushError {
  constructor(readonly names: readonly string[]) {
    super(`Not stored on this machine: ${names.join(', ')}`);
  }
}

export interface PushedVersion {
  /** The full identifier of the version written (a URI, a path or a resource name). */
  id: string;
  /** The version alone, as the target names it. */
  version: string;
}

export interface PushTarget {
  readonly type: PushTargetType;
  /** How the output names the target. */
  readonly label: string;
  /** Why `remote` cannot name a secret here, or undefined when it can. */
  nameProblem(remote: string): string | undefined;
  /**
   * A name this target accepts, made from `local`, offered as the `--as` value.
   * `local` is any non-empty name, including one `nameProblem` refuses.
   */
  suggestName(local: string): string;
  /** The form two names are compared in: a target that ignores case folds it. */
  foldName(remote: string): string;
  /**
   * Authenticate before anything is read from it or written to it. Returns how
   * it authenticated, for the header, never the credential itself.
   */
  prepare(): Promise<string | undefined>;
  /** Whether `remote` already holds a version. Reads metadata only. */
  exists(remote: string): Promise<boolean>;
  /** Write `value` as a new version of `remote`. */
  write(remote: string, value: string): Promise<PushedVersion>;
  /** Lines that say how to use the pushed entries next. */
  nextSteps(entries: readonly PushEntry[]): string[];
}

export type PushAction =
  /** Dry run: the target holds no secret of this name. */
  | 'would-create'
  /** Dry run: the target holds this name; a push adds a version. */
  | 'would-add-version'
  /** Written; `id` and `version` say where. */
  | 'pushed'
  /** The write raised; see `error`. */
  | 'failed'
  /** Not attempted, because an earlier write failed. */
  | 'skipped';

export interface PushEntry {
  /** The name in this machine's store. */
  name: string;
  /** The name in the target. */
  remote: string;
  action: PushAction;
  id?: string;
  version?: string;
  /** First line of the failure, for `failed`. */
  error?: string;
}

export interface PushPlanItem {
  name: string;
  remote: string;
}

export interface PushResult {
  entries: PushEntry[];
  dryRun: boolean;
  /** How the target authenticated, as `prepare` reported it. */
  auth?: string;
  /** The failure that stopped the writes, with its Verify and Fix lines. */
  failure?: PushError;
  ok: boolean;
}

/**
 * Push `plan` from `store` to `target`.
 *
 * Throws, before anything is written, when a name is not stored here
 * (`MissingLocalNamesError`), when the target cannot authenticate, or when a
 * value cannot be read from the local store. A write that fails is returned in
 * the result, with every later entry `skipped`.
 */
export async function pushSecrets(
  store: SecretStore,
  target: PushTarget,
  plan: readonly PushPlanItem[],
  options: { dryRun?: boolean } = {},
): Promise<PushResult> {
  const dryRun = options.dryRun === true;

  const local = new Set(await store.listSecrets());
  const missing = plan.filter((p) => !local.has(p.name)).map((p) => p.name);
  if (missing.length > 0) throw new MissingLocalNamesError(missing);

  const auth = await target.prepare();

  if (dryRun) {
    const entries: PushEntry[] = [];
    for (const p of plan) {
      let held: boolean;
      try {
        held = await target.exists(p.remote);
      } catch (err) {
        const failure = asPushError(err);
        entries.push({ ...p, action: 'failed', error: firstLine(failure.message) });
        for (const rest of plan.slice(entries.length)) entries.push({ ...rest, action: 'skipped' });
        return { entries, dryRun, auth, failure, ok: false };
      }
      entries.push({ ...p, action: held ? 'would-add-version' : 'would-create' });
    }
    return { entries, dryRun, auth, ok: true };
  }

  // Every value is in hand before the first write, so a value that cannot be
  // read stops the push while the target is still as it was.
  const values: string[] = [];
  for (const p of plan) {
    let value: string | undefined;
    try {
      value = await store.getSecret(p.name);
    } catch (err) {
      throw new PushError(`Could not read ${p.name} from this machine's store: ${firstLine(asPushError(err).message)}`);
    }
    if (value === undefined) throw new MissingLocalNamesError([p.name]);
    values.push(value);
  }

  const entries: PushEntry[] = [];
  for (let i = 0; i < plan.length; i++) {
    const p = plan[i];
    try {
      const written = await target.write(p.remote, values[i]);
      entries.push({ ...p, action: 'pushed', id: written.id, version: written.version });
    } catch (err) {
      const failure = asPushError(err);
      entries.push({ ...p, action: 'failed', error: firstLine(failure.message) });
      for (const rest of plan.slice(i + 1)) entries.push({ ...rest, action: 'skipped' });
      return { entries, dryRun, auth, failure, ok: false };
    }
  }
  return { entries, dryRun, auth, ok: true };
}

/** An error from a target, kept if it already says what to do. */
function asPushError(err: unknown): PushError {
  if (err instanceof PushError) return err;
  return new PushError(err instanceof Error ? err.message : String(err));
}

export function firstLine(text: string): string {
  return (text.split('\n')[0] ?? '').replace(/\s+/g, ' ').trim();
}

/** The first line of a backend error. Backend errors name keys, never values. */
function errorText(err: unknown): string {
  return firstLine(err instanceof Error ? err.message : String(err));
}

// --- HashiCorp Vault (KV v2) -------------------------------------------------

/**
 * `--to vault`: each name is written at `<mount>/data/secret/<name>`, the key
 * `secret sync --from vault` reads, so a push on one machine is a sync on the
 * next. KV v2 keeps the earlier versions.
 */
export class VaultPushTarget implements PushTarget {
  readonly type = 'vault' as const;
  readonly label: string;

  constructor(private readonly backend: VaultBackend) {
    this.label = `Vault ${backend.origin || '(VAULT_ADDR not set)'}, KV v2 mount "${backend.kvMount}"`;
  }

  nameProblem(remote: string): string | undefined {
    return isValidSecretName(remote) ? undefined : 'names allow letters, digits, \'-\' and \'_\'';
  }

  suggestName(local: string): string {
    return local.replace(/[^a-zA-Z0-9_-]/g, '_');
  }

  foldName(remote: string): string {
    return remote;
  }

  async prepare(): Promise<string | undefined> {
    const missing = this.backend.missingSettings();
    if (missing.length > 0) {
      throw new PushError(
        `Vault is not configured: ${missing.join(' and ')} ${missing.length > 1 ? 'are' : 'is'} not set.`,
        ['vault token lookup'],
        ['export VAULT_ADDR=https://vault.example.com VAULT_TOKEN=<token>'],
      );
    }
    const health = await this.backend.healthCheck();
    if (!health.healthy) {
      throw new PushError(
        `Vault is not reachable: ${firstLine(health.message ?? 'health check failed')}`,
        ['vault status'],
        ['set VAULT_ADDR to the Vault server this machine can reach, and retry'],
      );
    }
    return 'VAULT_TOKEN';
  }

  async exists(remote: string): Promise<boolean> {
    try {
      return await this.backend.hasEntry(this.key(remote));
    } catch (err) {
      throw this.failure(err, remote, 'read');
    }
  }

  async write(remote: string, value: string): Promise<PushedVersion> {
    try {
      const version = await this.backend.storeVersion(this.key(remote), value);
      return { id: `${this.backend.kvMount}/data/${this.key(remote)}`, version: String(version) };
    } catch (err) {
      throw this.failure(err, remote, 'write');
    }
  }

  nextSteps(entries: readonly PushEntry[]): string[] {
    const remotes = entries.map((e) => e.remote);
    return [
      `  Verify:  vault kv metadata get -mount=${this.backend.kvMount} ${this.key(remotes[0])}`,
      '  Next:    on the machine that needs them',
      `           ${CLI} secret sync --from vault --only ${remotes.join(',')}`,
    ];
  }

  private key(remote: string): string {
    return `secret/${remote}`;
  }

  private failure(err: unknown, remote: string, op: 'read' | 'write'): PushError {
    const message = errorText(err);
    const path = `${this.backend.kvMount}/${op === 'read' ? 'metadata' : 'data'}/${this.key(remote)}`;
    if (/permission denied/i.test(message)) {
      return new PushError(
        `Vault refused to ${op === 'read' ? 'read the metadata of' : 'write'} ${remote}: permission denied (an invalid or expired token is refused the same way).`,
        ['vault token lookup', `vault token capabilities ${path}`],
        [`attach a policy granting path "${path}" capabilities ${op === 'read' ? '["read"]' : '["create", "update"]'} to this token`],
      );
    }
    return new PushError(`Vault: ${remote}: ${message}`, ['vault status']);
  }
}

// --- GCP Secret Manager ------------------------------------------------------

/**
 * `--to gcp-sm`: each name is a Secret Manager secret of the same name in the
 * configured project, which `secret sync --from gcp-sm` reads.
 */
export class GcpPushTarget implements PushTarget {
  readonly type = 'gcp-sm' as const;
  label: string;
  private project = '';

  constructor(private readonly backend: GCPSecretManagerBackend) {
    this.label = 'GCP Secret Manager';
  }

  nameProblem(remote: string): string | undefined {
    return /^[a-zA-Z0-9_-]{1,255}$/.test(remote)
      ? undefined
      : 'Secret Manager names allow letters, digits, \'-\' and \'_\', up to 255 characters';
  }

  suggestName(local: string): string {
    return local.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 255);
  }

  foldName(remote: string): string {
    return remote;
  }

  async prepare(): Promise<string | undefined> {
    try {
      this.project = await this.backend.authenticate();
    } catch (err) {
      const message = errorText(err);
      if (/project ID not configured/i.test(message)) {
        throw new PushError(
          `GCP Secret Manager: ${message}`,
          ['gcloud config get-value project'],
          ['add {"gcp": {"projectId": "<project>"}} to ~/.secretless-ai/config.json'],
        );
      }
      throw new PushError(
        `GCP Secret Manager: ${message}`,
        ['gcloud auth application-default print-access-token > /dev/null && echo signed in'],
        ['gcloud auth application-default login', 'or set GOOGLE_APPLICATION_CREDENTIALS to a service account key file'],
      );
    }
    this.label = `GCP Secret Manager, project ${this.project}`;
    return 'Application Default Credentials';
  }

  async exists(remote: string): Promise<boolean> {
    try {
      return await this.backend.hasSecret(remote);
    } catch (err) {
      throw this.failure(err, remote);
    }
  }

  async write(remote: string, value: string): Promise<PushedVersion> {
    try {
      const id = await this.backend.storeVersion(remote, value);
      return { id, version: id.split('/').pop() ?? '' };
    } catch (err) {
      throw this.failure(err, remote);
    }
  }

  nextSteps(entries: readonly PushEntry[]): string[] {
    const mapping = entries.map((e) => `${e.remote}=${e.remote}:latest`).join(',');
    return [
      `  Verify:  gcloud secrets versions list ${entries[0].remote} --project ${this.project} --limit 1`,
      '  Next:    reference them from a Cloud Run service (its service account needs',
      '           roles/secretmanager.secretAccessor on each secret):',
      `           gcloud run services update <service> --region <region> --update-secrets=${mapping}`,
    ];
  }

  private failure(err: unknown, remote: string): PushError {
    const message = errorText(err);
    if (/permission/i.test(message)) {
      return new PushError(
        `GCP Secret Manager refused ${remote} in project ${this.project}: insufficient IAM permissions.`,
        [`gcloud projects get-iam-policy ${this.project} --flatten=bindings --filter=bindings.role:roles/secretmanager --format="table(bindings.role,bindings.members)"`],
        [`gcloud projects add-iam-policy-binding ${this.project} --member=user:<you> --role=roles/secretmanager.admin`],
      );
    }
    return new PushError(`GCP Secret Manager: ${remote}: ${message}`, [`gcloud secrets list --project ${this.project} --limit 1`]);
  }
}
