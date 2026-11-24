/**
 * What `status` and `verify` say about the settings a command run here uses
 * (#181): the profile, the backend, the GCP project names resolve from and
 * the identity the backend reads as, each with the source it came from.
 *
 * A source is `flag`, `env`, `manifest`, `user-config` or `default`. File and
 * environment reads only: no request is made, no secret is read, and no token,
 * key or password value is ever part of the answer. An identity is named (a
 * service account's e-mail, a Google or 1Password account, the variable a
 * token is read from), never shown.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { backendConfigPath, readBackendConfig, resolveBackendType, type SelectableBackendType } from './backends/config';
import { effectiveBackendName } from './backends/factory';
import { resolveGcpProject, type GcpProjectResolution } from './backends/gcp-project';

export type SettingSource = 'flag' | 'env' | 'manifest' | 'user-config' | 'default';

export interface ResolvedSetting {
  /** What is in effect, for display. Never a secret value. */
  value: string;
  source: SettingSource;
  /** Where it was read (a file, a line, a variable), when there is one. */
  from?: string;
}

export interface ResolvedSettings {
  profile: ResolvedSetting;
  backend: ResolvedSetting;
  project: ResolvedSetting;
  identity: ResolvedSetting;
}

/** A path under the home directory as `~/...`. */
function homeForm(p: string): string {
  const home = os.homedir();
  return p === home || p.startsWith(home + path.sep) ? `~${p.slice(home.length)}` : p;
}

/**
 * The backend a command constructs: the configured type, or `local`, which
 * upgrades to the OS keychain while no backend is configured, as
 * `effectiveBackendName` reports and `status --json` prints as `backend`.
 */
function resolveBackend(type: SelectableBackendType, explicitFlag?: string): ResolvedSetting {
  const effective = effectiveBackendName(type);
  if (explicitFlag === type) return { value: effective, source: 'flag', from: '--backend' };
  if (readBackendConfig() === type) return { value: effective, source: 'user-config', from: homeForm(backendConfigPath()) };
  return effective === type
    ? { value: effective, source: 'default' }
    : { value: effective, source: 'default', from: `${type}, upgraded to the OS keychain while no backend is set` };
}

/** `resolveGcpProject`'s rule, as one of the five sources. */
function projectSource(project: GcpProjectResolution): SettingSource {
  switch (project.source) {
    case 'explicit': return 'flag';
    case 'manifest': return 'manifest';
    case 'user-config': return 'user-config';
    case 'service-account-key': return 'env';
    default: return 'default';
  }
}

function resolveProject(type: SelectableBackendType, projectDir: string): ResolvedSetting {
  if (type !== 'gcp-sm') return { value: `none, ${type} has no project`, source: 'default' };
  const project = resolveGcpProject({ projectDir });
  const from = project.source === 'service-account-key'
    ? `GOOGLE_APPLICATION_CREDENTIALS, ${project.from ? homeForm(project.from) : ''}`
    : project.from && homeForm(project.from);
  if (project.error) return { value: 'not usable', source: projectSource(project), from };
  if (!project.projectId) return { value: 'none, no GCP project is set', source: 'default' };
  return { value: project.projectId, source: projectSource(project), ...(from ? { from } : {}) };
}

function readJsonObject(file: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf-8')) as unknown;
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

/** An e-mail shaped account name, or undefined: nothing else read from a credential file is shown. */
function accountName(value: unknown): string | undefined {
  return typeof value === 'string' && /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}$/.test(value) ? value : undefined;
}

/** The credential gcp-sm signs with, in the order `ensureAccessToken` tries them. */
function gcpIdentity(): ResolvedSetting {
  const keyPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (keyPath && fs.existsSync(keyPath)) {
    const email = accountName(readJsonObject(keyPath)?.client_email);
    return {
      value: email ? `service account ${email}` : 'a key file with no service account e-mail that could be read',
      source: 'env',
      from: `GOOGLE_APPLICATION_CREDENTIALS (${homeForm(keyPath)})`,
    };
  }
  const adcPath = path.join(os.homedir(), '.config', 'gcloud', 'application_default_credentials.json');
  const adc = readJsonObject(adcPath);
  if (adc) {
    const account = accountName(adc.account);
    return { value: account ? `Google account ${account}` : 'Application Default Credentials', source: 'default', from: homeForm(adcPath) };
  }
  return { value: 'none, no GCP credential found', source: 'default' };
}

function resolveIdentity(type: SelectableBackendType): ResolvedSetting {
  const env = process.env;
  switch (type) {
    case 'gcp-sm':
      return gcpIdentity();
    case 'vault':
      return env.VAULT_TOKEN
        ? { value: 'the Vault token', source: 'env', from: 'VAULT_TOKEN' }
        : { value: 'none, VAULT_TOKEN is not set', source: 'default' };
    case '1password':
      if (env.OP_SERVICE_ACCOUNT_TOKEN) return { value: 'a 1Password service account', source: 'env', from: 'OP_SERVICE_ACCOUNT_TOKEN' };
      if (env.OP_ACCOUNT) return { value: `1Password account ${env.OP_ACCOUNT}`, source: 'env', from: 'OP_ACCOUNT' };
      return { value: 'the account the op CLI is signed in to', source: 'default' };
    default:
      return { value: 'this OS user', source: 'default' };
  }
}

/**
 * The settings a command run in `projectDir` resolves to. No profile is read
 * yet, so the profile is `none` from `default`.
 */
export function resolveSettings(projectDir: string, options: { backendFlag?: string } = {}): ResolvedSettings {
  const type = resolveBackendType(options.backendFlag);
  return {
    profile: { value: 'none', source: 'default' },
    backend: resolveBackend(type, options.backendFlag),
    project: resolveProject(type, projectDir),
    identity: resolveIdentity(type),
  };
}

/** `<value> (<source>: <from>)`, or `<value> (<source>)`. */
export function describeSetting(setting: ResolvedSetting): string {
  return `${setting.value} (${setting.source}${setting.from ? `: ${setting.from}` : ''})`;
}

/** The four lines `status` and `verify` print, without indent or colour. */
export function resolvedSettingsLines(settings: ResolvedSettings): string[] {
  return [
    `Profile   ${describeSetting(settings.profile)}`,
    `Backend   ${describeSetting(settings.backend)}`,
    `Project   ${describeSetting(settings.project)}`,
    `Identity  ${describeSetting(settings.identity)}`,
  ];
}
