/**
 * A stored secret can carry what it is for: a description and free-form
 * metadata, kept beside the store and never containing the value (#172).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SecretStore } from './secret-store';
import { LocalBackend } from './backends/local';
import { checkAnnotation, readAnnotations, SecretAnnotations, MAX_META_KEYS } from './secret-annotations';

const VALUE = 'Wq8vN3kLz7RpT2xYc5Hd';

describe('checkAnnotation', () => {
  it('accepts an OAuth app description', () => {
    expect(checkAnnotation({
      description: 'Client secret, marketing agent app',
      meta: {
        provider: 'linkedin',
        app: 'marketing_agent',
        scopes: 'r_organization_social,w_organization_social,rw_organization_admin',
        tokenTtl: '5184000',
        redirectUri: 'https://localhost:8765/linkedin/callback',
      },
    }, VALUE)).toBeNull();
  });

  it('refuses a description or field that contains the value, naming the field and not its content', () => {
    const inDescription = checkAnnotation({ description: `token is ${VALUE}` }, VALUE);
    expect(inDescription).toMatch(/--description contains the secret's own value/);
    expect(inDescription).not.toContain(VALUE);

    const inMeta = checkAnnotation({ meta: { note: VALUE } }, VALUE);
    expect(inMeta).toMatch(/--meta note contains the secret's own value/);
    expect(inMeta).not.toContain(VALUE);
  });

  it('refuses an annotation equal to a short value, but not one that merely contains it', () => {
    expect(checkAnnotation({ meta: { port: '42' } }, '42')).toMatch(/own value/);
    expect(checkAnnotation({ meta: { tokenTtl: '5184000' } }, '18')).toBeNull();
  });

  it('refuses a credential-shaped field without echoing it', () => {
    const token = 'ghp_' + 'a'.repeat(36);
    const reason = checkAnnotation({ meta: { accessToken: token } }, VALUE);
    expect(reason).toMatch(/--meta accessToken looks like a credential \(GitHub Token\)/);
    expect(reason).not.toContain(token);
  });

  it('refuses a bad key, a control character and an oversized field', () => {
    expect(checkAnnotation({ meta: { '1app': 'x' } }, VALUE)).toMatch(/key "1app" is not usable/);
    expect(checkAnnotation({ meta: { app: 'a\nb' } }, VALUE)).toMatch(/control character/);
    expect(checkAnnotation({ description: 'x\u001b[2J' }, VALUE)).toMatch(/control character/);
    expect(checkAnnotation({ description: 'x'.repeat(501) }, VALUE)).toMatch(/limit is 500/);
  });
});

describe('the annotation file', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-annot-'));
    file = path.join(dir, '.secretless-ai', 'secret-annotations.json');
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('reads as empty only when it does not exist', () => {
    expect(readAnnotations(file).size).toBe(0);
  });

  it('refuses a damaged file rather than reporting nothing recorded, and does not echo it', () => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, '{"version": 1, "secrets": {"API_KEY": "sk-not-json');
    expect(() => readAnnotations(file)).toThrow(/could not be read[\s\S]*not valid JSON/);
    try {
      readAnnotations(file);
    } catch (err) {
      expect((err as Error).message).not.toContain('sk-not-json');
    }
  });

  it('writes plain JSON readable by the owner only, and never creates a file on remove', () => {
    const annotations = new SecretAnnotations(file);
    expect(annotations.remove('API_KEY')).toBe(false);
    expect(fs.existsSync(file)).toBe(false);

    annotations.update('API_KEY', { meta: { app: 'billing' } });
    const body = JSON.parse(fs.readFileSync(file, 'utf-8'));
    expect(body.version).toBe(1);
    expect(body.secrets.API_KEY.meta).toEqual({ app: 'billing' });
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it('keeps __proto__ and constructor as ordinary names', () => {
    const annotations = new SecretAnnotations(file);
    annotations.update('__proto__', { description: 'odd but valid name' });
    annotations.update('constructor', { meta: { app: 'x' } });
    const read = readAnnotations(file);
    expect(read.get('__proto__')?.description).toBe('odd but valid name');
    expect(read.get('constructor')?.meta).toEqual({ app: 'x' });
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
  });

  it('merges metadata, removes a key given an empty value, and keeps recordedAt', () => {
    const annotations = new SecretAnnotations(file);
    const first = annotations.update('API_KEY', { description: 'd', meta: { app: 'a', scopes: 's1' } }, new Date('2026-01-01T00:00:00Z'));
    const second = annotations.update('API_KEY', { meta: { scopes: 's1,s2', app: '' } }, new Date('2026-02-01T00:00:00Z'));
    expect(first?.recordedAt).toBe('2026-01-01T00:00:00.000Z');
    expect(second).toEqual({
      description: 'd',
      meta: { scopes: 's1,s2' },
      recordedAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-02-01T00:00:00.000Z',
    });
    // Clearing the last field removes the record.
    expect(annotations.update('API_KEY', { description: '', meta: { scopes: '' } })).toBeUndefined();
    expect(readAnnotations(file).has('API_KEY')).toBe(false);
  });

  it('refuses more than the key limit before writing anything', () => {
    const annotations = new SecretAnnotations(file);
    const meta: Record<string, string> = {};
    for (let i = 0; i <= MAX_META_KEYS; i++) meta[`k${i}`] = 'v';
    expect(() => annotations.update('API_KEY', { meta })).toThrow(/at most 50 metadata keys/);
    expect(fs.existsSync(file)).toBe(false);
  });
});

describe('SecretStore records what a secret is for', () => {
  let dir: string;
  let annotationsPath: string;
  let store: SecretStore;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-annot-store-'));
    annotationsPath = path.join(dir, 'secret-annotations.json');
    const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
    store = new SecretStore({ backend, annotationsPath });
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('stores the value and the annotation, and the value never reaches the annotation file', async () => {
    await store.setSecret('LINKEDIN_CLIENT_SECRET', VALUE, {
      description: 'Client secret, marketing agent app',
      meta: { provider: 'linkedin', app: 'marketing_agent', scopes: 'r_basicprofile,w_member_social' },
    });
    expect(await store.getSecret('LINKEDIN_CLIENT_SECRET')).toBe(VALUE);
    expect(store.getAnnotation('LINKEDIN_CLIENT_SECRET')?.meta.app).toBe('marketing_agent');
    expect(fs.readFileSync(annotationsPath, 'utf-8')).not.toContain(VALUE);
  });

  it('keeps the annotation when the value is rotated without one', async () => {
    await store.setSecret('API_KEY', VALUE, { meta: { app: 'billing' } });
    await store.setSecret('API_KEY', 'rotated-value-0000');
    expect(await store.getSecret('API_KEY')).toBe('rotated-value-0000');
    expect(store.getAnnotation('API_KEY')?.meta).toEqual({ app: 'billing' });
  });

  it('stores nothing when the annotation is refused', async () => {
    await expect(store.setSecret('API_KEY', VALUE, { meta: { copy: VALUE } }))
      .rejects.toThrow(/own value[\s\S]*Nothing was stored/);
    expect(await store.getSecret('API_KEY')).toBeUndefined();
    expect(fs.existsSync(annotationsPath)).toBe(false);
  });

  it('stores nothing when the annotation file is unreadable', async () => {
    fs.writeFileSync(annotationsPath, 'not json');
    await expect(store.setSecret('API_KEY', VALUE, { meta: { app: 'billing' } }))
      .rejects.toThrow(/could not be read/);
    expect(await store.getSecret('API_KEY')).toBeUndefined();
  });

  it('a plain setSecret never touches the annotation file', async () => {
    fs.writeFileSync(annotationsPath, 'not json');
    await store.setSecret('API_KEY', VALUE);
    expect(await store.getSecret('API_KEY')).toBe(VALUE);
    expect(fs.readFileSync(annotationsPath, 'utf-8')).toBe('not json');
  });

  it('removeSecret removes the annotation with the value', async () => {
    await store.setSecret('API_KEY', VALUE, { description: 'billing key' });
    expect(await store.removeSecret('API_KEY')).toBe(true);
    expect(store.getAnnotation('API_KEY')).toBeUndefined();
  });

  it('removeSecret removes the value even when the annotation file is damaged, and says so', async () => {
    await store.setSecret('API_KEY', VALUE);
    fs.writeFileSync(annotationsPath, 'not json');
    await expect(store.removeSecret('API_KEY')).rejects.toThrow(/Removed API_KEY from the store, but its description and metadata were not removed/);
    expect(await store.getSecret('API_KEY')).toBeUndefined();
  });

  it('CONTROL: a store on an injected backend with no path keeps annotations in memory', async () => {
    const backend = new LocalBackend({ storeDir: path.join(dir, 'store2'), key: 'test-key' });
    const memoryStore = new SecretStore({ backend });
    await memoryStore.setSecret('API_KEY', VALUE, { meta: { app: 'billing' } });
    expect(memoryStore.getAnnotation('API_KEY')?.meta).toEqual({ app: 'billing' });
    expect(fs.readdirSync(dir).sort()).toEqual(['store', 'store2']);
  });
});
