import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { LocalBackend } from './local';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-local-test-'));
}

const KEY = 'fixed-test-key-material';

function backend(dir: string): LocalBackend {
  return new LocalBackend({ storeDir: dir, key: KEY });
}

/** A store file this build cannot decrypt, in the place the real one lives. */
function corruptStore(dir: string): string {
  const storePath = path.join(dir, 'secrets.enc');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(storePath, Buffer.from('not a valid aes-256-gcm payload at all'));
  return storePath;
}

/**
 * #104 §1 — an unreadable store read as an empty one. Exit 0, empty stderr, and
 * every consumer downstream believing the machine has no secrets.
 */
describe('LocalBackend fails closed on an unreadable store (#104)', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('resolve throws instead of reporting no secrets', async () => {
    corruptStore(dir);
    await expect(backend(dir).resolve('secret')).rejects.toThrow(/could not be decrypted/i);
  });

  it('resolve still returns nothing when there genuinely is no store', async () => {
    // The other direction. A backend that throws unconditionally would satisfy
    // every test above this one while making a first run impossible.
    expect(await backend(dir).resolve('secret')).toEqual({});
  });

  it('resolve returns stored secrets when the store is readable', async () => {
    const b = backend(dir);
    await b.store('secret/A', 'value-a');
    await b.store('secret/B', 'value-b');
    expect(await backend(dir).resolve('secret')).toEqual({
      'secret/A': 'value-a',
      'secret/B': 'value-b',
    });
  });

  it('store refuses to write over a store it could not read', async () => {
    const storePath = corruptStore(dir);
    const before = fs.readFileSync(storePath);

    await expect(backend(dir).store('secret/NEW', 'v')).rejects.toThrow(/could not be decrypted/i);

    // The failure mode this replaces was not a bad error message. It was
    // "Stored: NEW", exit 0, and every other secret gone.
    expect(fs.readFileSync(storePath).equals(before)).toBe(true);
  });

  it('delete throws rather than claiming the secret was not there', async () => {
    corruptStore(dir);
    await expect(backend(dir).delete('secret/A')).rejects.toThrow(/could not be decrypted/i);
  });

  it('delete still reports false for a secret that really is absent', async () => {
    const b = backend(dir);
    await b.store('secret/A', 'value-a');
    expect(await b.delete('secret/MISSING')).toBe(false);
    expect(await b.delete('secret/A')).toBe(true);
  });

  it('healthCheck reports unhealthy for a store it cannot decrypt', async () => {
    corruptStore(dir);
    const health = await backend(dir).healthCheck();
    // The check was `fs.existsSync(storePath)`, so the one state it needed to
    // catch — a store that is there and unreadable — was the state it called
    // healthy.
    expect(health.healthy).toBe(false);
  });

  it('healthCheck reports healthy for a store it can decrypt', async () => {
    const b = backend(dir);
    await b.store('secret/A', 'value-a');
    expect((await backend(dir).healthCheck()).healthy).toBe(true);
  });

  it('never puts store contents in the error, even when they decrypt', async () => {
    // A store that decrypts to something that is not JSON. `JSON.parse` quotes
    // the input it failed on, and the input here is the decrypted store — so
    // reporting the parse error verbatim writes secret material into an error
    // message. Same class as #117, reached through the integrity fix.
    const b = backend(dir);
    await b.store('secret/A', 'x');
    // Re-encrypt a non-JSON plaintext under the same key by going through the
    // backend's own writer, then corrupting the plaintext it wrote.
    //
    // Node quotes only the FIRST TEN characters of what it choked on:
    //   Unexpected token 's', "sk-live-NO"... is not valid JSON
    // so an assertion on a marker further into the string passes over a message
    // displaying the head of the credential. Measured, and it is why the check
    // below is on runs of the fixture rather than on chosen substrings.
    const plaintext = 'sk-live-QQ7ZX9WKPV4RJT2MHB6NDY8FGC3L';
    const enc = (b as unknown as { encrypt(s: string): Buffer }).encrypt(plaintext);
    fs.writeFileSync(path.join(dir, 'secrets.enc'), enc);

    const err = await backend(dir).resolve('secret').then(
      () => null,
      (e: Error) => e,
    );
    expect(err).not.toBeNull();
    for (let i = 0; i + 4 <= plaintext.length; i++) {
      expect(err!.message).not.toContain(plaintext.slice(i, i + 4));
    }
    expect(err!.message).toMatch(/not valid JSON/);
  });
});

/**
 * #104 §1 — "the CLI should detect a vault or entry format version it cannot
 * handle and fail closed". The version was written on every store and compared
 * nowhere.
 */
describe('LocalBackend store format version (#104)', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('stamps the format version on write, so there is something to check', async () => {
    await backend(dir).store('secret/A', 'value-a');
    const meta = JSON.parse(fs.readFileSync(path.join(dir, 'secrets.meta.json'), 'utf-8'));
    expect(meta.version).toBe('1');
  });

  it('refuses to read a store written in a newer format', async () => {
    const b = backend(dir);
    await b.store('secret/A', 'value-a');

    const metaPath = path.join(dir, 'secrets.meta.json');
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
    meta.version = '2';
    fs.writeFileSync(metaPath, JSON.stringify(meta));

    // Decryption would succeed here. That is the point: a format this build does
    // not know decodes to bytes that are not the stored value, and nothing
    // downstream can tell.
    await expect(backend(dir).resolve('secret')).rejects.toThrow(/version 2/);
  });

  it('reads a store that predates the metadata file', async () => {
    // Absent metadata is not a mismatch — a store carried over from a build that
    // never wrote one is fine, and failing closed on it would lock users out of
    // their own secrets on upgrade.
    const b = backend(dir);
    await b.store('secret/A', 'value-a');
    fs.unlinkSync(path.join(dir, 'secrets.meta.json'));

    expect(await backend(dir).resolve('secret')).toEqual({ 'secret/A': 'value-a' });
  });
});
