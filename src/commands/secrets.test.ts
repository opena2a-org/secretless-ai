/**
 * `secret set` records what a credential is for, and `secret show` and
 * `secret list --long/--json/--app` read it back without the value (#172).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runSecret } from './secrets';
import { SecretStore } from '../secret-store';
import { LocalBackend } from '../backends/local';
import { prepareArgv } from '../argv';

const SECRET_VALUE = 'Wq8vN3kLz7RpT2xYc5Hd';
const ID_VALUE = '86exampleclientid42';

let dir: string;
let annotationsPath: string;

function store(): SecretStore {
  const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
  return new SecretStore({ backend, annotationsPath });
}

async function run(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const log = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  const error = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
  try {
    const json = args.includes('--json');
    const code = await runSecret(args, { json, createStore: store, afterSet: () => {} });
    return { code, out: out.join('\n'), err: err.join('\n') };
  } finally {
    log.mockRestore();
    error.mockRestore();
  }
}

/** The LinkedIn case from the issue: one app, its client id and secret, plus an unrelated key. */
async function seed(): Promise<void> {
  expect((await run([
    'set', `LINKEDIN_CLIENT_SECRET=${SECRET_VALUE}`,
    '--description', 'Client secret, marketing agent app',
    '--meta', 'provider=linkedin', '--meta', 'app=marketing_agent',
    '--meta', 'scopes=r_basicprofile,w_member_social', '--meta', 'tokenTtl=5184000',
  ])).code).toBe(0);
  expect((await run(['set', `LINKEDIN_CLIENT_ID=${ID_VALUE}`, '--meta', 'app=marketing_agent'])).code).toBe(0);
  expect((await run(['set', 'STRIPE_KEY=unrelated-value-1234'])).code).toBe(0);
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-secret-cmd-'));
  annotationsPath = path.join(dir, 'secret-annotations.json');
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('secret set --description / --meta', () => {
  it('stores the value and says what was recorded, without printing the value', async () => {
    const res = await run([
      'set', `LINKEDIN_CLIENT_SECRET=${SECRET_VALUE}`,
      '--description', 'Client secret', '--meta', 'app=marketing_agent', '--meta', 'provider=linkedin',
    ]);
    expect(res.code, res.err).toBe(0);
    expect(res.out).toContain('Stored: LINKEDIN_CLIENT_SECRET');
    expect(res.out).toContain('Recorded: a description and metadata app, provider');
    expect(res.out + res.err).not.toContain(SECRET_VALUE);
    expect(await store().getSecret('LINKEDIN_CLIENT_SECRET')).toBe(SECRET_VALUE);
  });

  it('refuses --meta without key=value and stores nothing', async () => {
    const res = await run(['set', `API_KEY=${SECRET_VALUE}`, '--meta', 'marketing_agent']);
    expect(res.code).toBe(2);
    expect(res.err).toMatch(/--meta takes key=value/);
    expect(await store().getSecret('API_KEY')).toBeUndefined();
  });

  it('refuses metadata that contains the value and stores nothing', async () => {
    const res = await run(['set', `API_KEY=${SECRET_VALUE}`, '--meta', `copy=${SECRET_VALUE}`]);
    expect(res.code).toBe(1);
    expect(res.err).toMatch(/--meta copy contains the secret's own value/);
    expect(res.err).not.toContain(SECRET_VALUE);
    expect(await store().getSecret('API_KEY')).toBeUndefined();
  });
});

describe('secret show', () => {
  it('prints description and metadata and never the value', async () => {
    await seed();
    const res = await run(['show', 'LINKEDIN_CLIENT_SECRET']);
    expect(res.code, res.err).toBe(0);
    expect(res.out).toContain('Description  Client secret, marketing agent app');
    for (const line of ['app=marketing_agent', 'provider=linkedin', 'scopes=r_basicprofile,w_member_social', 'tokenTtl=5184000']) {
      expect(res.out).toContain(line);
    }
    expect(res.out).toContain('stored (local backend), never printed');
    expect(res.out + res.err).not.toContain(SECRET_VALUE);
  });

  it('--json carries the same fields and no value', async () => {
    await seed();
    const res = await run(['show', 'LINKEDIN_CLIENT_SECRET', '--json']);
    expect(res.code, res.err).toBe(0);
    const body = JSON.parse(res.out);
    expect(body).toMatchObject({
      name: 'LINKEDIN_CLIENT_SECRET',
      stored: true,
      backend: 'local',
      description: 'Client secret, marketing agent app',
      meta: { app: 'marketing_agent', provider: 'linkedin', tokenTtl: '5184000' },
    });
    expect(res.out).not.toContain(SECRET_VALUE);
  });

  it('says so when nothing is recorded, and points at how to record it', async () => {
    await seed();
    const res = await run(['show', 'STRIPE_KEY']);
    expect(res.code).toBe(0);
    expect(res.out).toContain('No description or metadata recorded.');
    expect(res.out).toMatch(/secret set STRIPE_KEY --description/);
    expect(res.out).not.toContain('unrelated-value-1234');
  });

  it('exits 1 for a name that is not stored', async () => {
    const res = await run(['show', 'NO_SUCH_SECRET']);
    expect(res.code).toBe(1);
    expect(res.err).toContain('Secret not found: NO_SUCH_SECRET');
  });
});

describe('secret list --long / --json / --app', () => {
  it('--long shows descriptions and metadata and never a value', async () => {
    await seed();
    const res = await run(['list', '--long']);
    expect(res.code, res.err).toBe(0);
    expect(res.out).toContain('3 secret(s)');
    expect(res.out).toContain('Client secret, marketing agent app');
    expect(res.out).toContain('scopes=r_basicprofile,w_member_social');
    for (const v of [SECRET_VALUE, ID_VALUE, 'unrelated-value-1234']) expect(res.out).not.toContain(v);
  });

  it('--app lists the entries of one app as a set', async () => {
    await seed();
    const res = await run(['list', '--app', 'marketing_agent']);
    expect(res.code, res.err).toBe(0);
    expect(res.out).toContain('2 secret(s) with app=marketing_agent');
    expect(res.out).toContain('LINKEDIN_CLIENT_ID');
    expect(res.out).toContain('LINKEDIN_CLIENT_SECRET');
    expect(res.out).not.toContain('STRIPE_KEY');
  });

  it('--app with no match says so and names the apps that are recorded', async () => {
    await seed();
    const res = await run(['list', '--app', 'marketing']);
    expect(res.code).toBe(0);
    expect(res.out).toContain('No stored secret has app=marketing (3 secret(s) stored).');
    expect(res.out).toContain('Apps recorded: marketing_agent');
  });

  it('--json includes description and metadata, and honours --app', async () => {
    await seed();
    const res = await run(['list', '--json', '--app', 'marketing_agent']);
    expect(res.code, res.err).toBe(0);
    const body = JSON.parse(res.out);
    expect(body.count).toBe(2);
    expect(body.filter).toEqual({ app: 'marketing_agent' });
    expect(body.secrets.map((s: { name: string }) => s.name)).toEqual(['LINKEDIN_CLIENT_ID', 'LINKEDIN_CLIENT_SECRET']);
    expect(body.secrets[1].meta.scopes).toBe('r_basicprofile,w_member_social');
    for (const v of [SECRET_VALUE, ID_VALUE]) expect(res.out).not.toContain(v);
  });

  it('a plain list does not read the annotation file; --long refuses a damaged one', async () => {
    await seed();
    fs.writeFileSync(annotationsPath, 'not json');
    const plain = await run(['list']);
    expect(plain.code, plain.err).toBe(0);
    expect(plain.out).toContain('3 secret(s)');
    const long = await run(['list', '--long']);
    expect(long.code).toBe(1);
    expect(long.err).toMatch(/could not be read/);
  });

  it('CONTROL: a positional is still refused rather than ignored', async () => {
    const res = await run(['list', 'ZZZ_NO_SUCH_PREFIX']);
    expect(res.code).toBe(2);
    expect(res.err).toMatch(/takes no arguments/);
    expect(res.err).toMatch(/NOT filtered/);
  });
});

describe('secret rm', () => {
  it('removes the description and metadata with the value', async () => {
    await seed();
    expect((await run(['rm', 'LINKEDIN_CLIENT_SECRET'])).code).toBe(0);
    expect(store().getAnnotation('LINKEDIN_CLIENT_SECRET')).toBeUndefined();
    const show = await run(['show', 'LINKEDIN_CLIENT_SECRET']);
    expect(show.code).toBe(1);
  });
});

describe('a flag given to the wrong subcommand is refused, not ignored', () => {
  it.each([
    [['set', 'API_KEY=abcdefgh', '--long'], /--long is read by `secret list`, not by `secret set`/],
    [['get', 'API_KEY', '--json'], /--json is read by `secret list` and `secret show`, not by `secret get`/],
    [['rm', 'API_KEY', '--meta', 'a=b'], /--meta is read by `secret set`, not by `secret rm`/],
    [['show', 'API_KEY', '--description', 'x'], /--description is read by `secret set`, not by `secret show`/],
    [['list', '--meta', 'a=b'], /--meta is read by `secret set`, not by `secret list`/],
  ])('%j', async (args, message) => {
    const res = await run(args as string[]);
    expect(res.code).toBe(2);
    expect(res.err).toMatch(message);
  });

  it('CONTROL: an unknown subcommand is reported as one, whatever flag follows it', async () => {
    const res = await run(['describe', 'API_KEY', '--json']);
    expect(res.code).toBe(1);
    expect(res.err).toContain('Unknown secret command: describe');
  });

  it('a refused set stores nothing', async () => {
    await run(['set', 'API_KEY=abcdefgh', '--long']);
    expect(await store().getSecret('API_KEY')).toBeUndefined();
  });
});

describe('argv binds the secret flags', () => {
  it('--meta is repeatable', () => {
    const p = prepareArgv('secret', ['secret', 'set', 'A=b', '--meta', 'x=1', '--meta=y=2']);
    expect(p.errors).toEqual([]);
    expect(p.args).toEqual(['secret', 'set', 'A=b', '--meta', 'x=1', '--meta', 'y=2']);
  });

  it('CONTROL: --description and --app still refuse a repeat', () => {
    expect(prepareArgv('secret', ['secret', 'set', 'A=b', '--description', 'x', '--description', 'y']).errors[0])
      .toMatch(/--description was given more than once/);
    expect(prepareArgv('secret', ['secret', 'list', '--app', 'x', '--app', 'y']).errors[0])
      .toMatch(/--app was given more than once/);
  });
});
