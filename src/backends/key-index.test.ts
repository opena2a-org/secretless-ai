import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { readKeyIndex } from './key-index';

/**
 * #104 — the index is the answer to "what secrets exist". An unreadable answer
 * was returned as an empty one, so `secret list` printed nothing and `run`
 * injected nothing over a keychain that still held every secret.
 */
describe('readKeyIndex fails closed on an unreadable index (#104)', () => {
  let dir: string;
  let indexPath: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-index-test-'));
    indexPath = path.join(dir, 'keychain-index.json');
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('returns nothing when the index does not exist yet', () => {
    // The one cause for which the old catch-all was right, and the reason this
    // cannot simply throw on every failure: a machine with no secrets yet.
    expect(readKeyIndex(indexPath)).toEqual([]);
  });

  it('returns the names when the index is readable', () => {
    fs.writeFileSync(indexPath, JSON.stringify(['secret/A', 'mcp/x/y/B']));
    expect(readKeyIndex(indexPath)).toEqual(['secret/A', 'mcp/x/y/B']);
  });

  it('throws on a truncated index instead of reporting no secrets', () => {
    fs.writeFileSync(indexPath, '["secret/A", "secret/');
    expect(() => readKeyIndex(indexPath)).toThrow(/could not be read/i);
  });

  it('throws when the index is not a list', () => {
    fs.writeFileSync(indexPath, JSON.stringify({ names: ['secret/A'] }));
    expect(() => readKeyIndex(indexPath)).toThrow(/not a JSON array/);
  });

  it('throws rather than silently dropping an entry that is not a name', () => {
    // Filtering the bad element out would lose a secret from every listing —
    // the same fail-open in a smaller shape.
    fs.writeFileSync(indexPath, JSON.stringify(['secret/A', 42, 'secret/B']));
    expect(() => readKeyIndex(indexPath)).toThrow(/not a name/);
  });

  it('does not put index contents in the error', () => {
    // The names are the user's; a parse error would quote them.
    fs.writeFileSync(indexPath, '["secret/PRIVATE_PROJECT_KEY", "secret/');
    try {
      readKeyIndex(indexPath);
      throw new Error('expected readKeyIndex to throw');
    } catch (err) {
      expect((err as Error).message).not.toContain('PRIVATE_PROJECT_KEY');
    }
  });
});
