/**
 * Azure Key Vault, as a `secret push` target (#235).
 *
 * Zero SDK dependency: raw HTTPS to the Key Vault REST API, with a token from
 * the standard Azure credential chain, tried in this order:
 *
 *   1. environment: AZURE_TENANT_ID and AZURE_CLIENT_ID with either
 *      AZURE_CLIENT_SECRET (a service principal) or AZURE_FEDERATED_TOKEN_FILE
 *      (workload identity);
 *   2. managed identity: the App Service / Container Apps endpoint named by
 *      IDENTITY_ENDPOINT and IDENTITY_HEADER, else the VM metadata service;
 *   3. the signed-in Azure CLI (`az account get-access-token`).
 *
 * A source that is not set up is skipped. A source that is set up and fails
 * stops the chain with its own error: a later source would sign in as a
 * different identity, and a write made as someone else is not the write the
 * user asked for.
 *
 * The value travels only in the body of the PUT request. Key Vault echoes it
 * back in the response, so a response is read for its `id` and its error codes
 * and nothing else, and no response text is ever reprinted. The token is never
 * printed either: output names which source answered, not what it returned.
 */

import * as fs from 'fs';
import { boundedFetch, describeRequest, type BoundedResponse } from './bounded-fetch';
import { runBoundedChild, BACKEND_CHILD_TIMEOUT_MS, type BoundedChildResult } from './bounded-child';
import { PushError } from '../secret-push';
import type { PushTarget, PushEntry, PushedVersion } from '../secret-push';

/** The resource a Key Vault token is issued for. */
export const KEY_VAULT_RESOURCE = 'https://vault.azure.net';
const KEY_VAULT_DNS_SUFFIX = '.vault.azure.net';
const API_VERSION = '7.4';
const DEFAULT_AUTHORITY = 'https://login.microsoftonline.com';
const REQUEST_TIMEOUT_MS = 10_000;
/**
 * The VM metadata service answers from the host in milliseconds. Off Azure the
 * address usually has no route and the request waits for the bound, so it is
 * short: a missing service costs one second before the Azure CLI is tried.
 */
const IMDS_TIMEOUT_MS = 1_000;
const IMDS_TOKEN_URL = 'http://169.254.169.254/metadata/identity/oauth2/token';
/** A listing that is still empty after this many pages is treated as a failure. */
const MAX_LIST_PAGES = 25;

/** The verify line for any token problem. Prints the expiry, never the token. */
const TOKEN_VERIFY = `az account get-access-token --resource ${KEY_VAULT_RESOURCE} --query expiresOn -o tsv`;

/** The seams a test replaces. Each defaults to the real thing. */
export interface AzureDeps {
  env?: NodeJS.ProcessEnv;
  runChild?: (program: string, args: readonly string[], opts: { timeoutMs: number }) => Promise<BoundedChildResult>;
  readFile?: (path: string) => string;
}

/**
 * Why `name` is not a Key Vault name, or undefined when it is one. Checked
 * before any request, because the name becomes part of a hostname that the
 * token is sent to.
 */
export function vaultNameProblem(name: string): string | undefined {
  if (!/^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$/.test(name) || name.includes('--')) {
    return 'Key Vault names are 3-24 letters, digits and single hyphens, start with a letter and end with a letter or digit';
  }
  return undefined;
}

/** `kv-prod` or `https://kv-prod.vault.azure.net/` -> `kv-prod`; anything else as given. */
export function vaultNameFromArg(arg: string): string {
  const m = /^https:\/\/([a-zA-Z0-9-]+)\.vault\.azure\.net\/?$/.exec(arg);
  return m ? m[1] : arg;
}

/** A token, and which source of the chain issued it. */
interface IssuedToken {
  token: string;
  source: string;
}

/** A chain source that is not set up on this machine. */
interface Skipped {
  skipped: string;
}

/**
 * Get a Key Vault token from the first source of the chain that is set up.
 * Throws a `PushError` when a set-up source fails or no source is set up.
 */
export async function acquireKeyVaultToken(deps: AzureDeps = {}): Promise<IssuedToken> {
  const env = deps.env ?? process.env;
  const tried: string[] = [];

  for (const source of [environmentToken, managedIdentityToken, azureCliToken]) {
    const got = await source(env, deps);
    if ('token' in got) return got;
    tried.push(got.skipped);
  }

  throw new PushError(
    [
      'No Azure credential was found for Key Vault.',
      ...tried.map((t) => `  ${t}`),
    ].join('\n'),
    [TOKEN_VERIFY],
    ['az login', 'or set AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET for a service principal'],
  );
}

async function environmentToken(env: NodeJS.ProcessEnv, deps: AzureDeps): Promise<IssuedToken | Skipped> {
  const tenant = env.AZURE_TENANT_ID;
  const clientId = env.AZURE_CLIENT_ID;
  const secret = env.AZURE_CLIENT_SECRET;
  const tokenFile = env.AZURE_FEDERATED_TOKEN_FILE;
  if (!tenant || !clientId || (!secret && !tokenFile)) {
    return { skipped: 'Environment: AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET (or AZURE_FEDERATED_TOKEN_FILE) are not all set.' };
  }

  const source = secret ? 'service principal (AZURE_CLIENT_SECRET)' : 'workload identity (AZURE_FEDERATED_TOKEN_FILE)';
  const authority = (env.AZURE_AUTHORITY_HOST ?? DEFAULT_AUTHORITY).replace(/\/+$/, '');
  if (!/^https:\/\/[a-zA-Z0-9.-]+$/.test(authority) || !/^[a-zA-Z0-9.-]+$/.test(tenant)) {
    throw new PushError(
      'AZURE_TENANT_ID or AZURE_AUTHORITY_HOST is not a tenant ID or an https host, so no token was requested.',
      ['printenv AZURE_TENANT_ID AZURE_AUTHORITY_HOST'],
      ['set AZURE_TENANT_ID to the directory (tenant) ID, and AZURE_AUTHORITY_HOST to an https host or leave it unset'],
    );
  }

  const form = new URLSearchParams({
    client_id: clientId,
    scope: `${KEY_VAULT_RESOURCE}/.default`,
    grant_type: 'client_credentials',
  });
  if (secret) {
    form.set('client_secret', secret);
  } else {
    let assertion: string;
    try {
      assertion = (deps.readFile ?? ((p: string) => fs.readFileSync(p, 'utf-8')))(tokenFile as string).trim();
    } catch (err) {
      throw new PushError(
        `Could not read AZURE_FEDERATED_TOKEN_FILE: ${(err as NodeJS.ErrnoException).code ?? 'read failed'}.`,
        ['printenv AZURE_FEDERATED_TOKEN_FILE'],
        ['point AZURE_FEDERATED_TOKEN_FILE at the projected service account token file'],
      );
    }
    form.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    form.set('client_assertion', assertion);
  }

  const url = `${authority}/${tenant}/oauth2/v2.0/token`;
  const res = await request('POST', url, { 'Content-Type': 'application/x-www-form-urlencoded' }, form.toString(),
    () => unreachable(`${new URL(authority).host} did not answer the token request`, `curl -sI ${authority}/`));
  const body = await res.json().catch(() => undefined) as
    { access_token?: unknown; error?: unknown; error_codes?: unknown } | undefined;
  if (res.ok && typeof body?.access_token === 'string' && body.access_token !== '') {
    return { token: body.access_token, source };
  }

  // `error` is an OAuth code and `error_codes` are numbers; the description
  // text is not reprinted.
  const oauthCode = typeof body?.error === 'string' && /^[a-z_]{1,64}$/.test(body.error) ? body.error : undefined;
  const aadsts = Array.isArray(body?.error_codes) && typeof body.error_codes[0] === 'number' ? body.error_codes[0] : undefined;
  const why = [oauthCode, aadsts !== undefined ? `AADSTS${aadsts}` : undefined].filter(Boolean).join(', ');
  throw new PushError(
    `Azure sign-in refused the ${source} for tenant ${tenant} (HTTP ${res.status}${why ? `, ${why}` : ''}).`,
    [`az ad sp show --id "$AZURE_CLIENT_ID" --query appId -o tsv`],
    [
      aadsts !== undefined
        ? `look up AADSTS${aadsts} at https://login.microsoftonline.com/error?code=${aadsts}, then correct AZURE_TENANT_ID, AZURE_CLIENT_ID or the credential`
        : 'correct AZURE_TENANT_ID, AZURE_CLIENT_ID or the credential',
    ],
  );
}

async function managedIdentityToken(env: NodeJS.ProcessEnv, _deps: AzureDeps): Promise<IssuedToken | Skipped> {
  const clientId = env.AZURE_CLIENT_ID;

  // App Service, Functions and Container Apps publish a local endpoint.
  const endpoint = env.IDENTITY_ENDPOINT;
  const header = env.IDENTITY_HEADER;
  if (endpoint && header) {
    if (!/^https?:\/\/[^\s?#]+$/.test(endpoint)) {
      throw new PushError(
        'IDENTITY_ENDPOINT is not an http(s) URL, so no managed identity token was requested.',
        ['printenv IDENTITY_ENDPOINT'],
      );
    }
    const params = new URLSearchParams({ 'api-version': '2019-08-01', resource: KEY_VAULT_RESOURCE });
    if (clientId) params.set('client_id', clientId);
    const res = await request('GET', `${endpoint}?${params}`, { 'X-IDENTITY-HEADER': header }, undefined,
      () => unreachable('The managed identity endpoint (IDENTITY_ENDPOINT) did not answer', 'printenv IDENTITY_ENDPOINT'));
    const body = await res.json().catch(() => undefined) as { access_token?: unknown } | undefined;
    if (res.ok && typeof body?.access_token === 'string' && body.access_token !== '') {
      return { token: body.access_token, source: 'managed identity (IDENTITY_ENDPOINT)' };
    }
    throw new PushError(
      `The managed identity endpoint refused the Key Vault token request (HTTP ${res.status}).`,
      ['az containerapp identity show -n <app> -g <rg>'],
      ['assign an identity to this app: az containerapp identity assign -n <app> -g <rg> --system-assigned'],
    );
  }

  // A VM's metadata service. Off Azure nothing answers, and that is a skip.
  const params = new URLSearchParams({ 'api-version': '2018-02-01', resource: KEY_VAULT_RESOURCE });
  if (clientId) params.set('client_id', clientId);
  let res: BoundedResponse;
  try {
    res = await boundedFetch(`${IMDS_TOKEN_URL}?${params}`, {
      method: 'GET',
      headers: { Metadata: 'true', 'User-Agent': 'secretless-ai/1.0' },
    }, {
      timeoutMs: IMDS_TIMEOUT_MS,
      onTimeout: () => new Error('no answer'),
    });
  } catch {
    return { skipped: 'Managed identity: IDENTITY_ENDPOINT is not set and no VM metadata service answered.' };
  }
  const body = await res.json().catch(() => undefined) as { access_token?: unknown } | undefined;
  if (res.ok && typeof body?.access_token === 'string' && body.access_token !== '') {
    return { token: body.access_token, source: 'managed identity (VM metadata service)' };
  }
  return { skipped: `Managed identity: the VM metadata service issued no token (HTTP ${res.status}).` };
}

async function azureCliToken(_env: NodeJS.ProcessEnv, deps: AzureDeps): Promise<IssuedToken | Skipped> {
  const run = deps.runChild ?? runBoundedChild;
  const result = await run('az', ['account', 'get-access-token', '--resource', KEY_VAULT_RESOURCE, '--output', 'json'], {
    timeoutMs: BACKEND_CHILD_TIMEOUT_MS,
  });
  if (result.spawnError) {
    return { skipped: 'Azure CLI: `az` is not installed or not on PATH.' };
  }
  if (result.timedOut) {
    throw new PushError(
      `The Azure CLI did not return a token within ${BACKEND_CHILD_TIMEOUT_MS / 1000}s.`,
      [TOKEN_VERIFY],
      ['az login'],
    );
  }
  const stderr = cleanLine(result.stderr.split('\n').find((l) => l.trim() !== '') ?? '');
  if (result.status !== 0) {
    if (/az login/i.test(result.stderr)) {
      return { skipped: `Azure CLI: not signed in (${stderr || 'az login is needed'}).` };
    }
    throw new PushError(
      `The Azure CLI could not issue a Key Vault token: ${stderr || `exit ${result.status}`}.`,
      [TOKEN_VERIFY],
      ['az login'],
    );
  }
  let parsed: { accessToken?: unknown } | undefined;
  try {
    parsed = JSON.parse(result.stdout) as { accessToken?: unknown };
  } catch {
    parsed = undefined;
  }
  if (typeof parsed?.accessToken !== 'string' || parsed.accessToken === '') {
    throw new PushError('The Azure CLI answered without a token.', [TOKEN_VERIFY], ['az login']);
  }
  return { token: parsed.accessToken, source: 'Azure CLI (az login)' };
}

/** One line of child output, with control characters removed and a length cap. */
function cleanLine(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 200);
}

function unreachable(what: string, verify: string): PushError {
  return new PushError(`${what} (bound: ${REQUEST_TIMEOUT_MS / 1000}s).`, [verify]);
}

/**
 * One bounded request. A network failure becomes the `onFailure` error, never
 * the runtime's own text, which names neither the target nor a next step.
 */
async function request(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: string | undefined,
  onFailure: () => PushError,
): Promise<BoundedResponse> {
  try {
    return await boundedFetch(url, {
      method,
      headers: { ...headers, 'User-Agent': 'secretless-ai/1.0' },
      body,
    }, {
      timeoutMs: REQUEST_TIMEOUT_MS,
      onTimeout: onFailure,
    });
  } catch (err) {
    if (err instanceof PushError) throw err;
    throw onFailure();
  }
}

/** `{ error: { code, innererror: { code } } }`, codes only. Key Vault codes are identifiers. */
async function errorCodes(res: BoundedResponse): Promise<{ code?: string; inner?: string }> {
  const body = await res.json().catch(() => undefined) as
    { error?: { code?: unknown; innererror?: { code?: unknown } } } | undefined;
  const pick = (v: unknown): string | undefined => (typeof v === 'string' && /^[A-Za-z]{1,64}$/.test(v) ? v : undefined);
  return { code: pick(body?.error?.code), inner: pick(body?.error?.innererror?.code) };
}

/**
 * `--to azure-kv --vault <name>`: each name becomes a Key Vault secret. A name
 * that exists gets a new version; the earlier versions are kept.
 */
export class AzureKeyVaultTarget implements PushTarget {
  readonly type = 'azure-kv' as const;
  readonly label: string;
  private readonly origin: string;
  private token: string | undefined;

  constructor(readonly vaultName: string, private readonly deps: AzureDeps = {}) {
    const problem = vaultNameProblem(vaultName);
    if (problem !== undefined) throw new PushError(`"${vaultName}" is not a Key Vault name: ${problem}.`);
    this.origin = `https://${vaultName.toLowerCase()}${KEY_VAULT_DNS_SUFFIX}`;
    this.label = `Azure Key Vault ${vaultName} (${this.origin})`;
  }

  nameProblem(remote: string): string | undefined {
    return /^[0-9a-zA-Z-]{1,127}$/.test(remote)
      ? undefined
      : 'Key Vault secret names allow letters, digits and \'-\' only, up to 127 characters';
  }

  suggestName(local: string): string {
    return local.replace(/[^0-9a-zA-Z-]/g, '-').slice(0, 127);
  }

  foldName(remote: string): string {
    // Key Vault secret names are not case-sensitive.
    return remote.toLowerCase();
  }

  async prepare(): Promise<string> {
    const issued = await acquireKeyVaultToken(this.deps);
    this.token = issued.token;
    return issued.source;
  }

  async exists(remote: string): Promise<boolean> {
    this.assertName(remote);
    // The versions listing carries identifiers and attributes, never a value.
    let url: string | undefined = `${this.origin}/secrets/${remote}/versions?api-version=${API_VERSION}`;
    for (let page = 0; url !== undefined && page < MAX_LIST_PAGES; page++) {
      const res = await this.call('GET', url, remote);
      if (res.status === 404) return false;
      if (!res.ok) throw await this.refusal(res, remote, 'list');
      const body = await res.json().catch(() => undefined) as { value?: unknown; nextLink?: unknown } | undefined;
      if (Array.isArray(body?.value) && body.value.length > 0) return true;
      // Key Vault can answer with an empty page and a link to the next one.
      // The token is only ever sent back to this vault.
      const next = typeof body?.nextLink === 'string' ? body.nextLink : undefined;
      url = next !== undefined && this.isOwnUrl(next) ? next : undefined;
    }
    if (url !== undefined) {
      throw new PushError(`Key Vault ${this.vaultName} listed ${MAX_LIST_PAGES} empty pages of versions for ${remote}; it was not classified.`);
    }
    return false;
  }

  async write(remote: string, value: string): Promise<PushedVersion> {
    this.assertName(remote);
    const url = `${this.origin}/secrets/${remote}?api-version=${API_VERSION}`;
    const res = await this.call('PUT', url, remote, JSON.stringify({ value }));
    if (!res.ok) throw await this.refusal(res, remote, 'set');
    // The response echoes the value; `id` is the only field read.
    const body = await res.json().catch(() => undefined) as { id?: unknown } | undefined;
    const id = typeof body?.id === 'string' && this.isOwnUrl(body.id, '/secrets/') ? body.id : undefined;
    if (id === undefined) {
      throw new PushError(
        `Key Vault ${this.vaultName} accepted ${remote} (HTTP ${res.status}) but returned no secret identifier.`,
        [`az keyvault secret list-versions --vault-name ${this.vaultName} --name ${remote} --query "[].id" -o tsv`],
      );
    }
    return { id, version: id.split('/').pop() ?? '' };
  }

  nextSteps(entries: readonly PushEntry[]): string[] {
    const refs = entries
      .map((e) => `${e.remote.toLowerCase()}=keyvaultref:${this.origin}/secrets/${e.remote},identityref:<identity-id>`)
      .join(' ');
    return [
      `  Verify:  az keyvault secret list-versions --vault-name ${this.vaultName} --name ${entries[0].remote} --query "[].id" -o tsv`,
      '  Next:    reference them from a container app. Its identity needs the',
      '           Key Vault Secrets User role on this vault; <identity-id> is that',
      '           identity\'s resource ID, or "system" for the system-assigned one:',
      `           az containerapp secret set -n <app> -g <rg> --secrets ${refs}`,
    ];
  }

  /** A name reaches a URL path only after it is checked here. */
  private assertName(remote: string): void {
    const problem = this.nameProblem(remote);
    if (problem !== undefined) throw new PushError(`"${remote}" cannot be pushed to Key Vault: ${problem}.`);
  }

  /** Whether `url` is on this vault (Key Vault may add `:443`), under `path` when given. */
  private isOwnUrl(url: string, path = '/'): boolean {
    try {
      const u = new URL(url);
      return u.origin === this.origin && u.pathname.startsWith(path);
    } catch {
      return false;
    }
  }

  private async call(method: string, url: string, remote: string, body?: string): Promise<BoundedResponse> {
    if (this.token === undefined) throw new PushError('Key Vault target used before it authenticated.');
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}` };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    try {
      return await boundedFetch(url, { method, headers: { ...headers, 'User-Agent': 'secretless-ai/1.0' }, body }, {
        timeoutMs: REQUEST_TIMEOUT_MS,
        onTimeout: () => new PushError(
          [
            `Key Vault ${this.vaultName} did not respond within ${REQUEST_TIMEOUT_MS / 1000}s (${describeRequest(method, url)}).`,
            '  A write that timed out may still have been applied by the server.',
          ].join('\n'),
          [`az keyvault secret list-versions --vault-name ${this.vaultName} --name ${remote} --query "[].id" -o tsv`],
          [`check the network path from this machine to ${this.origin}, and retry`],
        ),
      });
    } catch (err) {
      if (err instanceof PushError) throw err;
      throw this.networkFailure(err);
    }
  }

  /** A request that never got an HTTP answer. A name with no DNS record is a vault that does not exist. */
  private networkFailure(err: unknown): PushError {
    const cause = (err as { cause?: { code?: unknown } } | undefined)?.cause;
    const code = typeof cause?.code === 'string' ? cause.code : undefined;
    if (code === 'ENOTFOUND') {
      return new PushError(
        `Key Vault ${this.vaultName} was not found: ${new URL(this.origin).host} does not resolve.`,
        [`az keyvault show --name ${this.vaultName} --query properties.vaultUri -o tsv`],
        ['az keyvault list --query "[].name" -o tsv   (find the vault name)'],
      );
    }
    return new PushError(
      `Key Vault ${this.vaultName} could not be reached${code ? ` (${code})` : ''}.`,
      [`curl -sI ${this.origin}/`],
      [`check the network path from this machine to ${this.origin}, and retry`],
    );
  }

  /** A Key Vault refusal, with the role, rule or command that resolves it. */
  private async refusal(res: BoundedResponse, remote: string, op: 'list' | 'set'): Promise<PushError> {
    const { code, inner } = await errorCodes(res);
    const codes = [code, inner].filter(Boolean).join('/');
    const status = `HTTP ${res.status}${codes ? `, ${codes}` : ''}`;
    const scope = `"$(az keyvault show --name ${this.vaultName} --query id -o tsv)"`;
    const verb = op === 'set' ? `write ${remote}` : `list the versions of ${remote}`;

    if (res.status === 401) {
      return new PushError(
        `Key Vault ${this.vaultName} did not accept the token (${status}).`,
        [TOKEN_VERIFY, `az keyvault show --name ${this.vaultName} --query properties.tenantId -o tsv`],
        ['az login --tenant <the tenant ID the vault belongs to>'],
      );
    }
    if (res.status === 403 && inner === 'ForbiddenByFirewall') {
      return new PushError(
        `Key Vault ${this.vaultName} refused this machine's network address (${status}).`,
        [`az keyvault network-rule list --name ${this.vaultName}`],
        [`az keyvault network-rule add --name ${this.vaultName} --ip-address <this machine's public IP>`],
      );
    }
    if (res.status === 403) {
      // Secrets Officer can list and set. Key Vault Reader lists, which is all
      // a dry run needs, but the push it previews would then be refused.
      const fix = [`az role assignment create --role "Key Vault Secrets Officer" --assignee <your user or app ID> --scope ${scope}`];
      if (inner !== 'ForbiddenByRbac') {
        fix.push(`or, on a vault that uses access policies: az keyvault set-policy --name ${this.vaultName} --upn <you> --secret-permissions ${op === 'set' ? 'set' : 'list'}`);
      }
      return new PushError(
        `Key Vault ${this.vaultName} refused to ${verb}: missing permission (${status}).`,
        [`az role assignment list --assignee <your user or app ID> --scope ${scope} -o table`],
        fix,
      );
    }
    if (res.status === 409) {
      return new PushError(
        `Key Vault ${this.vaultName} holds a deleted ${remote} that is kept for recovery (${status}).`,
        [`az keyvault secret show-deleted --vault-name ${this.vaultName} --name ${remote} --query recoveryId -o tsv`],
        [
          `az keyvault secret recover --vault-name ${this.vaultName} --name ${remote}   (then push again)`,
          `or: az keyvault secret purge --vault-name ${this.vaultName} --name ${remote}   (removes the deleted versions for good)`,
        ],
      );
    }
    if (res.status === 429) {
      return new PushError(`Key Vault ${this.vaultName} is throttling requests (${status}).`, [], ['wait a minute and push again']);
    }
    return new PushError(
      `Key Vault ${this.vaultName} refused to ${verb} (${status}).`,
      [`az keyvault show --name ${this.vaultName} --query properties.vaultUri -o tsv`],
    );
  }
}
