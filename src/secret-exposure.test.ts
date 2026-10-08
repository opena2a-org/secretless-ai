/**
 * Exposed secrets are tracked until the stored value changes (#236):
 * `secret exposed`, `secret list --needs-rotation`, rotation on `secret set`,
 * and `clean` / `watch` marking a stored secret whose value they redacted.
 * No path may print, log or store a value.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runSecret } from './commands/secrets';
import { runClean } from './commands/transcript';
import { processFile } from './watch';
import { status } from './status';
import { SecretStore } from './secret-store';
import { LocalBackend } from './backends/local';
import { prepareArgv } from './argv';
import { redactMatches } from './redact';
import { parseExposureTime, storedSecretsIn, transcriptWhere } from './secret-exposure';

// Assembled from parts so the tree never carries a whole provider-shaped literal.
const STORED_KEY = ['sk-ant-api03', 'FAKE'.repeat(6) + 'exposure0test'].join('-');
const ROTATED_KEY = ['sk-ant-api03', 'FAKE'.repeat(6) + 'rotated00test'].join('-');
const OTHER_KEY = ['ghp', 'FAKE'.repeat(9)].join('_');

let dir: string;
let annotationsPath: string;

function store(): SecretStore {
  const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
  return new SecretStore({ backend, annotationsPath });
}

async function capture(fn: () => Promise<number>): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const log = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  const error = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
  try {
    const code = await fn();
    return { code, out: out.join('\n'), err: err.join('\n') };
  } finally {
    log.mockRestore();
    error.mockRestore();
  }
}

function secret(args: string[]) {
  return capture(() => runSecret(args, { json: args.includes('--json'), createStore: store, afterSet: () => {} }));
}

async function needsRotation(): Promise<{ code: number; body: { count: number; secrets: Array<Record<string, unknown>> } }> {
  const res = await secret(['list', '--needs-rotation', '--json']);
  return { code: res.code, body: JSON.parse(res.out) };
}

/** A transcript line with `text` in a message, as Claude Code writes them. */
function transcript(name: string, text: string): string {
  const file = path.join(dir, 'projects', 'p1', name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ uuid: 'u1', message: { content: [{ type: 'text', text }] } }) + '\n');
  return file;
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-exposure-'));
  annotationsPath = path.join(dir, 'secret-annotations.json');
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('secret exposed and secret list --needs-rotation', () => {
  it('records the exposure beside the store, lists it with exit 1, and never prints or stores the value', async () => {
    expect((await secret(['set', `ANTHROPIC_API_KEY=${STORED_KEY}`, '--meta', 'provider=anthropic'])).code).toBe(0);

    const exposed = await secret(['exposed', 'ANTHROPIC_API_KEY', '--where', 'pasted into a chat']);
    expect(exposed.code, exposed.err).toBe(0);
    expect(exposed.out).toMatch(/Recorded: ANTHROPIC_API_KEY exposed/);
    expect(exposed.out).toMatch(/secret set ANTHROPIC_API_KEY/);

    const { code, body } = await needsRotation();
    expect(code).toBe(1);
    expect(body.count).toBe(1);
    expect(body.secrets).toEqual([{
      name: 'ANTHROPIC_API_KEY',
      exposedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
      exposedWhere: 'pasted into a chat',
      provider: 'anthropic',
    }]);

    const text = await secret(['list', '--needs-rotation']);
    expect(text.code).toBe(1);
    expect(text.out).toMatch(/1 exposed secret\(s\) need rotation/);
    expect(text.out).toMatch(/pasted into a chat/);

    for (const res of [exposed, text]) expect(res.out + res.err).not.toContain(STORED_KEY);
    expect(fs.readFileSync(annotationsPath, 'utf-8')).not.toContain(STORED_KEY);
  });

  it('exits 0 and says so when nothing is open', async () => {
    expect((await secret(['set', `ANTHROPIC_API_KEY=${STORED_KEY}`])).code).toBe(0);
    const { code, body } = await needsRotation();
    expect(code).toBe(0);
    expect(body.count).toBe(0);
    const text = await secret(['list', '--needs-rotation']);
    expect(text.code).toBe(0);
    expect(text.out).toMatch(/No exposed secret is waiting for rotation/);
  });

  it('--at records the given date; a future or malformed date and a missing --where are refused', async () => {
    expect((await secret(['set', `ANTHROPIC_API_KEY=${STORED_KEY}`])).code).toBe(0);
    expect((await secret(['exposed', 'ANTHROPIC_API_KEY', '--where', 'screen share', '--at', '2026-01-02'])).code).toBe(0);
    expect((await needsRotation()).body.secrets[0].exposedAt).toBe('2026-01-02T00:00:00.000Z');

    expect((await secret(['exposed', 'ANTHROPIC_API_KEY', '--where', 'x', '--at', '2999-01-01'])).code).toBe(2);
    expect((await secret(['exposed', 'ANTHROPIC_API_KEY', '--where', 'x', '--at', 'yesterday'])).code).toBe(2);
    const noWhere = await secret(['exposed', 'ANTHROPIC_API_KEY']);
    expect(noWhere.code).toBe(2);
    expect(noWhere.err).toMatch(/--where is required/);
  });

  it('refuses a name that is not stored, and a note that holds the value, recording nothing', async () => {
    const missing = await secret(['exposed', 'NOT_STORED', '--where', 'chat']);
    expect(missing.code).toBe(1);
    expect(missing.err).toMatch(/Secret not found: NOT_STORED/);

    expect((await secret(['set', `ANTHROPIC_API_KEY=${STORED_KEY}`])).code).toBe(0);
    const leaky = await secret(['exposed', 'ANTHROPIC_API_KEY', '--where', `pasted ${STORED_KEY} in chat`]);
    expect(leaky.code).toBe(1);
    expect(leaky.err).toMatch(/--where/);
    expect(leaky.out + leaky.err).not.toContain(STORED_KEY);
    expect((await needsRotation()).body.count).toBe(0);
  });

  it('argv binds --where, --at and --needs-rotation, and the wrong subcommand refuses them', async () => {
    expect(prepareArgv('secret', ['secret', 'exposed', 'A', '--where', 'chat', '--at', '2026-01-02']).errors).toEqual([]);
    expect(prepareArgv('secret', ['secret', 'list', '--needs-rotation', '--json']).errors).toEqual([]);
    const misplaced = await secret(['set', 'A=b', '--where', 'chat']);
    expect(misplaced.code).toBe(2);
    expect(misplaced.err).toMatch(/--where is read by `secret exposed`/);
  });
});

describe('secret set closes an exposure only with a different value', () => {
  it('the same value leaves it open; a different value closes it and records rotatedAt', async () => {
    expect((await secret(['set', `ANTHROPIC_API_KEY=${STORED_KEY}`, '--meta', 'app=billing'])).code).toBe(0);
    expect((await secret(['exposed', 'ANTHROPIC_API_KEY', '--where', 'chat'])).code).toBe(0);

    const same = await secret(['set', `ANTHROPIC_API_KEY=${STORED_KEY}`]);
    expect(same.code, same.err).toBe(0);
    expect(same.out).toMatch(/Still exposed/);
    expect((await needsRotation()).code).toBe(1);

    const rotated = await secret(['set', `ANTHROPIC_API_KEY=${ROTATED_KEY}`]);
    expect(rotated.code, rotated.err).toBe(0);
    expect(rotated.out).toMatch(/Rotated: the exposure recorded .* is closed/);
    const after = await needsRotation();
    expect(after.code).toBe(0);
    expect(after.body.count).toBe(0);

    const meta = store().getAnnotation('ANTHROPIC_API_KEY')!.meta;
    expect(meta.rotatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(meta.exposedAt).toBeUndefined();
    expect(meta.app).toBe('billing');

    for (const res of [same, rotated]) expect(res.out + res.err).not.toMatch(/FAKEFAKE/);
    const file = fs.readFileSync(annotationsPath, 'utf-8');
    expect(file).not.toContain(STORED_KEY);
    expect(file).not.toContain(ROTATED_KEY);
  });

  it('without an open exposure the stored value is not read', async () => {
    const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
    const s = new SecretStore({ backend, annotationsPath });
    await s.setSecret('ANTHROPIC_API_KEY', STORED_KEY, { meta: { app: 'billing' } });
    const resolve = vi.spyOn(backend, 'resolve');
    const { rotation } = await s.setSecret('ANTHROPIC_API_KEY', ROTATED_KEY);
    expect(rotation.kind).toBe('none');
    expect(resolve).not.toHaveBeenCalled();
  });

  it('a damaged metadata file does not block a plain set, and says the exposure was not checked', async () => {
    fs.writeFileSync(annotationsPath, 'not json');
    const res = await secret(['set', `ANTHROPIC_API_KEY=${STORED_KEY}`]);
    expect(res.code, res.err).toBe(0);
    expect(res.out).toMatch(/Not checked: whether ANTHROPIC_API_KEY had an open exposure/);
    expect(fs.readFileSync(annotationsPath, 'utf-8')).toBe('not json');
  });
});

describe('clean marks a stored secret exposed when it redacts its value', () => {
  it('a transcript holding a stored value leaves that secret listed by --needs-rotation after clean', async () => {
    await store().setSecret('ANTHROPIC_API_KEY', STORED_KEY, { meta: { provider: 'anthropic' } });
    await store().setSecret('UNRELATED', 'not-in-any-transcript-0000');
    const file = transcript('session.jsonl', `here is my key ${STORED_KEY} and a token ${OTHER_KEY}`);

    const res = await capture(() => runClean(['--path', path.join(dir, 'projects')], { createStore: store }));
    expect(res.code, res.err).toBe(0);
    expect(res.out).toMatch(/Stored secrets among the redacted values: 1/);
    expect(res.out).toMatch(/ANTHROPIC_API_KEY {2}marked exposed \(transcript .*session\.jsonl line 1 \(found by clean\)\)/);
    expect(res.out).toMatch(/secret set NAME/);
    expect(res.out).not.toContain(STORED_KEY);
    expect(fs.readFileSync(file, 'utf-8')).not.toContain(STORED_KEY);

    const { code, body } = await needsRotation();
    expect(code).toBe(1);
    expect(body.secrets.map((s) => s.name)).toEqual(['ANTHROPIC_API_KEY']);
    expect(body.secrets[0].exposedWhere).toMatch(/session\.jsonl line 1 \(found by clean\)$/);
    expect(body.secrets[0].provider).toBe('anthropic');
    expect(fs.readFileSync(annotationsPath, 'utf-8')).not.toContain(STORED_KEY);

    // A second exposure of the same value keeps the first record.
    transcript('later.jsonl', `again ${STORED_KEY}`);
    const again = await capture(() => runClean(['--path', path.join(dir, 'projects')], { createStore: store }));
    expect(again.out).toMatch(/ANTHROPIC_API_KEY {2}already marked exposed since/);
    expect((await needsRotation()).body.secrets[0].exposedAt).toBe(body.secrets[0].exposedAt);
  });

  it('--dry-run names the secret and records nothing', async () => {
    await store().setSecret('ANTHROPIC_API_KEY', STORED_KEY);
    transcript('session.jsonl', `key ${STORED_KEY}`);
    const res = await capture(() => runClean(['--dry-run', '--path', path.join(dir, 'projects')], { createStore: store }));
    expect(res.out).toMatch(/ANTHROPIC_API_KEY {2}would be marked exposed/);
    expect((await needsRotation()).body.count).toBe(0);
  });

  it('does not open the store when nothing was redacted, and marks nothing for a credential that is not stored', async () => {
    transcript('clean.jsonl', 'nothing secret here');
    const createStore = vi.fn(store);
    await capture(() => runClean(['--path', path.join(dir, 'projects')], { createStore }));
    expect(createStore).not.toHaveBeenCalled();

    await store().setSecret('ANTHROPIC_API_KEY', STORED_KEY);
    transcript('other.jsonl', `token ${OTHER_KEY}`);
    const res = await capture(() => runClean(['--path', path.join(dir, 'projects')], { createStore: store }));
    expect(res.out).not.toMatch(/Stored secrets among/);
    expect((await needsRotation()).body.count).toBe(0);
  });

  it('a store that cannot be read is reported, and the redaction still happens', async () => {
    const file = transcript('session.jsonl', `key ${STORED_KEY}`);
    const res = await capture(() => runClean(['--path', path.join(dir, 'projects')], {
      createStore: () => { throw new Error('backend unavailable\nsecond line'); },
    }));
    expect(res.code).toBe(0);
    expect(res.out).toMatch(/Not checked: whether a redacted value is one of your stored secrets/);
    expect(res.out).toMatch(/Reason: {3}backend unavailable$/m);
    expect(fs.readFileSync(file, 'utf-8')).not.toContain(STORED_KEY);
  });
});

describe('watch marks a stored secret exposed when it redacts its value', () => {
  it('records the exposure and logs the name, never the value', async () => {
    await store().setSecret('ANTHROPIC_API_KEY', STORED_KEY);
    const file = transcript('session.jsonl', `key ${STORED_KEY}`);
    const logPath = path.join(dir, 'watch.log');
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      await processFile(file, logPath, store);
    } finally {
      stderr.mockRestore();
    }
    const log = fs.readFileSync(logPath, 'utf-8');
    expect(log).toMatch(/Stored secret ANTHROPIC_API_KEY marked exposed/);
    expect(log).not.toContain(STORED_KEY);
    const { body } = await needsRotation();
    expect(body.secrets[0].exposedWhere).toMatch(/\(found by watch\)$/);
  });
});

describe('status counts open exposures from the metadata file', () => {
  const savedHome = process.env.HOME;
  afterEach(() => { process.env.HOME = savedHome; });

  it('reports the open count, 0 with none, and null when the file cannot be read', async () => {
    const home = path.join(dir, 'home');
    const project = path.join(dir, 'project');
    fs.mkdirSync(path.join(home, '.secretless-ai'), { recursive: true });
    fs.mkdirSync(project);
    process.env.HOME = home;
    expect((await status(project)).exposuresOpen).toBe(0);

    annotationsPath = path.join(home, '.secretless-ai', 'secret-annotations.json');
    await store().setSecret('ANTHROPIC_API_KEY', STORED_KEY);
    await store().recordExposure('ANTHROPIC_API_KEY', 'chat', new Date());
    expect((await status(project)).exposuresOpen).toBe(1);

    fs.writeFileSync(annotationsPath, 'not json');
    expect((await status(project)).exposuresOpen).toBeNull();
  });
});

describe('helpers', () => {
  it('redactMatches hands over each replaced span, including the extended tail', () => {
    const spans: string[] = [];
    const out = redactMatches(`a ${OTHER_KEY}XYZ b`, /ghp_[a-zA-Z0-9]{36}/, '[R]', { onSpan: (s) => spans.push(s) });
    expect(out).toBe('a [R] b');
    expect(spans).toEqual([`${OTHER_KEY}XYZ`]);
  });

  it('storedSecretsIn matches a short value only by equality and a long one by containment', () => {
    const spans = [{ span: 'KEY="abcdefgh12345"', file: 'f', line: 3 }, { span: 'pin1', file: 'g', line: 1 }];
    expect(storedSecretsIn(spans, { LONG: 'abcdefgh12345', SHORT: 'pin1', PART: 'abc' }).map((m) => m.name))
      .toEqual(['LONG', 'SHORT']);
  });

  it('parseExposureTime accepts a date or ISO time and refuses anything else', () => {
    const now = new Date('2026-10-07T12:00:00Z');
    expect((parseExposureTime('2026-10-01', now) as Date).toISOString()).toBe('2026-10-01T00:00:00.000Z');
    expect((parseExposureTime('2026-10-07T11:00:00Z', now) as Date).toISOString()).toBe('2026-10-07T11:00:00.000Z');
    expect(parseExposureTime('2026-10-08', now)).toMatch(/future/);
    expect(parseExposureTime('2026-02-30', now)).toEqual(expect.any(String));
    expect(parseExposureTime('last week', now)).toMatch(/takes a date/);
  });

  it('transcriptWhere stays one printable line within the metadata limit', () => {
    const where = transcriptWhere(`~/x\n${'d/'.repeat(800)}s.jsonl`, 4, 'clean');
    expect(where.length).toBeLessThanOrEqual(1024);
    expect(where).not.toMatch(/\n/);
    expect(where).toMatch(/s\.jsonl line 4 \(found by clean\)$/);
  });
});
