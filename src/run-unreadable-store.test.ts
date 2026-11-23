import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runRun } from './commands/env-run';
import { runWithSecrets } from './run';
import { GCPSecretManagerBackend } from './backends/gcp-sm';

/**
 * #182, part 2: a store that cannot be read is not an empty store.
 *
 * With expired Application Default Credentials, `run --only NAME -- <command>`
 * exits non-zero with Google's own words and the command that logs in again,
 * and the command is never started. A project that cannot be listed, or a
 * secret in it that cannot be read, is an error too, where it read as no
 * secrets ("No secrets found") or as a requested name not in the store.
 *
 * Every request is answered by a stubbed fetch; nothing reaches Google.
 */

const PROJECT = 'acme-run-182';
const REAUTH = 'gcloud auth application-default login';
const LIST_URL = `https://secretmanager.googleapis.com/v1/projects/${PROJECT}/secrets?pageSize=100`;

interface Answer { status: number; body: unknown }

let home: string;
let sentinel: string;
let stderr: string[];
let requests: string[];

/** Answer each request by URL from `routes`; anything else is a test failure. */
function stubFetch(routes: Record<string, Answer>): void {
  requests = [];
  vi.stubGlobal('fetch', async (url: string) => {
    requests.push(String(url));
    const answer = routes[String(url)];
    if (!answer) throw new Error(`unexpected request: ${String(url)}`);
    return {
      ok: answer.status < 300,
      status: answer.status,
      json: async () => answer.body,
      text: async () => JSON.stringify(answer.body),
    };
  });
}

/** A child that leaves a file behind when it runs. */
function child(): string[] {
  return ['node', '-e', `require('fs').writeFileSync(${JSON.stringify(sentinel)}, 'ran')`];
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-run-182-'));
  sentinel = path.join(home, 'child-ran');
  vi.stubEnv('HOME', home);
  vi.stubEnv('GOOGLE_APPLICATION_CREDENTIALS', '');
  fs.mkdirSync(path.join(home, '.secretless-ai'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.secretless-ai', 'config.json'),
    JSON.stringify({ backend: 'gcp-sm', cacheTtl: 0, gcp: { projectId: PROJECT } }),
  );
  fs.mkdirSync(path.join(home, '.config', 'gcloud'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.config', 'gcloud', 'application_default_credentials.json'),
    JSON.stringify({ type: 'authorized_user', client_id: 'cid', client_secret: 'csecret', refresh_token: 'stand-in-refresh' }),
  );
  stderr = [];
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { stderr.push(args.join(' ')); });
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    stderr.push(String(chunk));
    return true;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  fs.rmSync(home, { recursive: true, force: true });
});

describe('run against a store that cannot be read (#182)', () => {
  it('expired ADC: run --only NAME -- true exits non-zero and prints the reauthentication command', async () => {
    stubFetch({
      'https://oauth2.googleapis.com/token': {
        status: 400,
        body: { error: 'invalid_grant', error_description: 'Token has been expired or revoked.' },
      },
    });

    const code = await runRun(['--only', 'NAME', '--', 'true']);
    const out = stderr.join('\n');

    expect(code).not.toBe(0);
    expect(out).toContain('the Application Default Credentials were refused (HTTP 400)');
    expect(out).toContain('invalid_grant: Token has been expired or revoked.');
    expect(out).toContain(`Fix:     ${REAUTH}`);
    expect(out).not.toContain('No secrets found');
    expect(out).not.toContain('not found in the store');
    expect(out).not.toContain('stand-in-refresh');
    expect(out).not.toContain('csecret');
  });

  it('expired ADC without --only: the command is not started and "No secrets found" is not printed', async () => {
    stubFetch({
      'https://oauth2.googleapis.com/token': {
        status: 400,
        body: { error: 'invalid_grant', error_description: 'Token has been expired or revoked.' },
      },
    });

    const code = await runRun(['--', ...child()]);

    expect(code).toBe(1);
    expect(fs.existsSync(sentinel)).toBe(false);
    expect(stderr.join('\n')).toContain(REAUTH);
    expect(stderr.join('\n')).not.toContain('No secrets found');
  });

  describe('with a token', () => {
    function backend(): GCPSecretManagerBackend {
      const b = new GCPSecretManagerBackend({ projectId: PROJECT });
      (b as unknown as Record<string, unknown>).accessToken = 'stand-in-token';
      (b as unknown as Record<string, unknown>).tokenExpiry = Date.now() + 3600_000;
      return b;
    }

    it('a list answered 401 is the credential, with Google\'s words and the fix, not an empty store', async () => {
      stubFetch({
        [LIST_URL]: {
          status: 401,
          body: { error: { code: 401, status: 'UNAUTHENTICATED', message: 'Request had invalid authentication credentials.' } },
        },
      });

      const [cmd, ...args] = child();
      const err = await runWithSecrets(cmd, args, { backend: backend() }).then(() => undefined, (e: Error) => e);

      expect(err?.message).toContain(`the credentials were not accepted for a list in project ${PROJECT} (HTTP 401)`);
      expect(err?.message).toContain('Google:  UNAUTHENTICATED: Request had invalid authentication credentials.');
      expect(err?.message).toContain(`Fix:     ${REAUTH}`);
      expect(fs.existsSync(sentinel)).toBe(false);
      expect(stderr.join('\n')).not.toContain('No secrets found');
    });

    it('a list answered 403 on the user-wide project is a permission error with Google\'s words, not an empty store', async () => {
      stubFetch({
        [LIST_URL]: {
          status: 403,
          body: { error: { code: 403, status: 'PERMISSION_DENIED', message: "Permission 'secretmanager.secrets.list' denied" } },
        },
      });

      const [cmd, ...args] = child();
      const err = await runWithSecrets(cmd, args, { backend: backend(), only: ['NAME'] }).then(() => undefined, (e: Error) => e);

      expect(err?.message).toContain(`insufficient IAM permissions on project ${PROJECT}. Grant 'Secret Manager Viewer' role.`);
      expect(err?.message).toContain("PERMISSION_DENIED: Permission 'secretmanager.secrets.list' denied");
      expect(err?.message).toContain(`Verify:  gcloud secrets list --project ${PROJECT} --limit 1`);
      expect(err?.message).not.toContain('not found in the store');
      expect(fs.existsSync(sentinel)).toBe(false);
    });

    it('a secret that is listed but cannot be read is an error naming it, not a name missing from the store', async () => {
      stubFetch({
        [LIST_URL]: { status: 200, body: { secrets: [{ name: `projects/${PROJECT}/secrets/NAME` }] } },
        [`https://secretmanager.googleapis.com/v1/projects/${PROJECT}/secrets/NAME/versions/latest:access`]: {
          status: 403,
          body: { error: { code: 403, status: 'PERMISSION_DENIED', message: "Permission 'secretmanager.versions.access' denied" } },
        },
      });

      const [cmd, ...args] = child();
      const err = await runWithSecrets(cmd, args, { backend: backend(), only: ['NAME'] }).then(() => undefined, (e: Error) => e);

      expect(err?.message).toContain(
        `insufficient IAM permissions on project ${PROJECT} to read NAME. Grant 'Secret Manager Secret Accessor' role.`,
      );
      expect(err?.message).toContain("Permission 'secretmanager.versions.access' denied");
      expect(err?.message).not.toContain('not found in the store');
      expect(fs.existsSync(sentinel)).toBe(false);
    });

    it('CONTROL: a project that lists no secrets is an empty store, and the command runs', async () => {
      stubFetch({ [LIST_URL]: { status: 200, body: { secrets: [] } } });

      const [cmd, ...args] = child();
      const code = await runWithSecrets(cmd, args, { backend: backend() });

      expect(code).toBe(0);
      expect(fs.readFileSync(sentinel, 'utf-8')).toBe('ran');
      expect(stderr.join('\n')).toContain('No secrets found');
    });
  });
});
