import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { resolveSettings, resolvedSettingsLines } from './resolved-settings';
import { effectiveBackendName } from './backends/factory';
import { runStatus, runVerify } from './commands/core';

/**
 * `status` and `verify` name the profile, backend, project and identity a
 * command run here uses, and the source of each (#181), never a value.
 */

const ENV_KEYS = ['HOME', 'GOOGLE_APPLICATION_CREDENTIALS', 'VAULT_TOKEN', 'OP_SERVICE_ACCOUNT_TOKEN', 'OP_ACCOUNT'];
const saved: Record<string, string | undefined> = {};
const dirs: string[] = [];
let home: string;
let project: string;

function tempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

function writeConfig(config: Record<string, unknown>): void {
  fs.mkdirSync(path.join(home, '.secretless-ai'), { recursive: true });
  fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify(config));
}

/** console.log lines, without colour, until the spy is restored. */
function capture(): string[] {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
    lines.push(a.map(String).join(' ').replace(/\x1b\[[0-9;]*m/g, ''));
  });
  return lines;
}

beforeEach(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  home = tempDir('sl-resolved-home-');
  project = tempDir('sl-resolved-project-');
  fs.mkdirSync(path.join(project, '.git'));
  process.env.HOME = home;
});

afterEach(() => {
  vi.restoreAllMocks();
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('resolveSettings', () => {
  it('with nothing configured, each setting comes from the default, and the backend is the one a command builds', () => {
    const r = resolveSettings(project);
    expect(r.profile).toEqual({ value: 'none', source: 'default' });
    expect(r.backend.source).toBe('default');
    expect(r.backend.value).toBe(effectiveBackendName('local'));
    if (r.backend.value !== 'local') expect(r.backend.from).toBe('local, upgraded to the OS keychain while no backend is set');
    expect(r.project).toEqual({ value: 'none, local has no project', source: 'default' });
    expect(r.identity).toEqual({ value: 'this OS user', source: 'default' });
  });

  it('a backend set in the user config says so and names the file; a flag says so', () => {
    writeConfig({ backend: 'vault' });
    expect(resolveSettings(project).backend).toEqual({ value: 'vault', source: 'user-config', from: '~/.secretless-ai/config.json' });
    expect(resolveSettings(project, { backendFlag: 'gcp-sm' }).backend).toEqual({ value: 'gcp-sm', source: 'flag', from: '--backend' });
  });

  it('gcp-sm: the project the manifest names, and the service account the env names, without the key', () => {
    writeConfig({ backend: 'gcp-sm' });
    fs.writeFileSync(path.join(project, '.secretless'), 'gcp.projectId: acme-prod\n');
    const key = path.join(home, 'key.json');
    fs.writeFileSync(key, JSON.stringify({ type: 'service_account', client_email: 'ci@acme-prod.iam.gserviceaccount.com', private_key: 'PRIVATE-KEY-BODY' }));
    process.env.GOOGLE_APPLICATION_CREDENTIALS = key;

    const r = resolveSettings(project);
    expect(r.project).toMatchObject({ value: 'acme-prod', source: 'manifest' });
    expect(r.project.from).toMatch(/\.secretless line 1$/);
    expect(r.identity).toEqual({
      value: 'service account ci@acme-prod.iam.gserviceaccount.com',
      source: 'env',
      from: 'GOOGLE_APPLICATION_CREDENTIALS (~/key.json)',
    });
    expect(resolvedSettingsLines(r).join('\n')).not.toContain('PRIVATE-KEY-BODY');
  });

  it('gcp-sm: a project from the key file is from env, one from the user config says so, and ADC names its account but not its token', () => {
    writeConfig({ backend: 'gcp-sm' });
    const key = path.join(home, 'key.json');
    fs.writeFileSync(key, JSON.stringify({ type: 'service_account', project_id: 'key-project', client_email: 'not an e-mail' }));
    process.env.GOOGLE_APPLICATION_CREDENTIALS = key;
    let r = resolveSettings(project);
    expect(r.project).toEqual({ value: 'key-project', source: 'env', from: 'GOOGLE_APPLICATION_CREDENTIALS, ~/key.json (project_id)' });
    expect(r.identity.value).toBe('a key file with no service account e-mail that could be read');

    delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
    writeConfig({ backend: 'gcp-sm', gcp: { projectId: 'user-project' } });
    const adcDir = path.join(home, '.config', 'gcloud');
    fs.mkdirSync(adcDir, { recursive: true });
    fs.writeFileSync(path.join(adcDir, 'application_default_credentials.json'), JSON.stringify({
      type: 'authorized_user', account: 'dev@example.com', refresh_token: 'REFRESH-TOKEN-BODY',
    }));
    r = resolveSettings(project);
    expect(r.project).toMatchObject({ value: 'user-project', source: 'user-config' });
    expect(r.identity).toEqual({
      value: 'Google account dev@example.com',
      source: 'default',
      from: '~/.config/gcloud/application_default_credentials.json',
    });
    expect(resolvedSettingsLines(r).join('\n')).not.toContain('REFRESH-TOKEN-BODY');
  });

  it('vault and 1password name the variable a token is read from, never the token', () => {
    writeConfig({ backend: 'vault' });
    expect(resolveSettings(project).identity).toEqual({ value: 'none, VAULT_TOKEN is not set', source: 'default' });
    process.env.VAULT_TOKEN = 'hvs.TOKENVALUE';
    const vault = resolvedSettingsLines(resolveSettings(project)).join('\n');
    expect(vault).toContain('Identity  the Vault token (env: VAULT_TOKEN)');
    expect(vault).not.toContain('TOKENVALUE');

    writeConfig({ backend: '1password' });
    process.env.OP_SERVICE_ACCOUNT_TOKEN = 'ops_TOKENVALUE';
    const op = resolvedSettingsLines(resolveSettings(project)).join('\n');
    expect(op).toContain('Identity  a 1Password service account (env: OP_SERVICE_ACCOUNT_TOKEN)');
    expect(op).not.toContain('TOKENVALUE');
  });
});

describe('status and verify print the resolved settings', () => {
  it('status prints profile, backend, project and identity with their sources, and --json carries them', async () => {
    writeConfig({ backend: 'gcp-sm' });
    fs.writeFileSync(path.join(project, '.secretless'), 'gcp.projectId: acme-prod\n');
    let lines = capture();
    await runStatus(project);
    const out = lines.join('\n');
    expect(out).toContain('── Resolved');
    expect(out).toContain('  Profile   none (default)');
    expect(out).toContain('  Backend   gcp-sm (user-config: ~/.secretless-ai/config.json)');
    expect(out).toMatch(/ {2}Project {3}acme-prod \(manifest: .*\.secretless line 1\)/);
    expect(out).toContain('  Identity  none, no GCP credential found (default)');
    expect(out.indexOf('── Resolved')).toBeLessThan(out.indexOf('── Observations'));

    vi.restoreAllMocks();
    lines = capture();
    await runStatus(project, { json: true });
    const doc = JSON.parse(lines.join('\n'));
    expect(doc.resolved.profile).toEqual({ value: 'none', source: 'default' });
    expect(doc.resolved.backend).toMatchObject({ value: 'gcp-sm', source: 'user-config' });
    expect(doc.resolved.project).toMatchObject({ value: 'acme-prod', source: 'manifest' });
    expect(doc.resolved.identity).toEqual({ value: 'none, no GCP credential found', source: 'default' });
  });

  it('verify prints them under its scope line', () => {
    writeConfig({ backend: 'vault' });
    process.env.VAULT_TOKEN = 'hvs.TOKENVALUE';
    const lines = capture();
    runVerify(project);
    const out = lines.join('\n');
    expect(out).toContain('  Profile   none (default)');
    expect(out).toContain('  Backend   vault (user-config: ~/.secretless-ai/config.json)');
    expect(out).toContain('  Project   none, vault has no project (default)');
    expect(out).toContain('  Identity  the Vault token (env: VAULT_TOKEN)');
    expect(out).not.toContain('TOKENVALUE');
    expect(out.indexOf('Scope:')).toBeLessThan(out.indexOf('Profile'));
  });
});
