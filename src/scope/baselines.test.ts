import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  saveBaseline,
  loadBaseline,
  listBaselines,
  compareToBaseline,
  resetBaseline,
} from './baselines';

const TEST_DIR = path.join(os.tmpdir(), `secretless-baselines-test-${Date.now()}`);
const BASELINES_FILE = path.join(TEST_DIR, 'scope-baselines.json');

// Override the config dir and baselines file via module mocking
vi.mock('os', async () => {
  const actual = await vi.importActual<typeof import('os')>('os');
  return {
    ...actual,
    homedir: () => path.join(os.tmpdir(), `secretless-baselines-test-${Date.now()}`),
  };
});

// Instead of mocking os.homedir (which changes per call with Date.now()),
// directly test by manipulating environment
describe('baselines', () => {
  let origHome: string | undefined;

  beforeEach(() => {
    origHome = process.env.HOME;
    process.env.HOME = TEST_DIR;
    fs.mkdirSync(path.join(TEST_DIR, '.secretless-ai'), { recursive: true });
  });

  afterEach(() => {
    if (origHome !== undefined) {
      process.env.HOME = origHome;
    }
    try {
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    } catch {
      // Cleanup best-effort
    }
  });

  it('saves and loads a baseline round-trip', () => {
    saveBaseline({
      credentialName: 'TEST_CRED',
      provider: 'gcp',
      permissions: ['storage.objects.get', 'bigquery.jobs.create'],
      checkedAt: '2026-03-01T10:00:00Z',
    });

    const loaded = loadBaseline('TEST_CRED');
    expect(loaded).toBeDefined();
    expect(loaded!.credentialName).toBe('TEST_CRED');
    expect(loaded!.provider).toBe('gcp');
    expect(loaded!.permissions).toEqual(['storage.objects.get', 'bigquery.jobs.create']);
  });

  it('returns undefined for non-existent baseline', () => {
    const loaded = loadBaseline('NON_EXISTENT');
    expect(loaded).toBeUndefined();
  });

  it('preserves previous permissions when updating', () => {
    saveBaseline({
      credentialName: 'MY_KEY',
      provider: 'gcp',
      permissions: ['perm.a', 'perm.b'],
      checkedAt: '2026-03-01T10:00:00Z',
    });

    saveBaseline({
      credentialName: 'MY_KEY',
      provider: 'gcp',
      permissions: ['perm.a', 'perm.b', 'perm.c'],
      checkedAt: '2026-03-02T10:00:00Z',
    });

    const loaded = loadBaseline('MY_KEY');
    expect(loaded!.permissions).toEqual(['perm.a', 'perm.b', 'perm.c']);
    expect(loaded!.previousPermissions).toEqual(['perm.a', 'perm.b']);
  });

  it('compare shows expansion (new permissions)', () => {
    saveBaseline({
      credentialName: 'EXPAND_TEST',
      provider: 'gcp',
      permissions: ['perm.a', 'perm.b'],
      checkedAt: '2026-03-01T10:00:00Z',
    });

    const result = compareToBaseline('EXPAND_TEST', 'gcp', ['perm.a', 'perm.b', 'perm.c']);

    expect(result.hasExpanded).toBe(true);
    expect(result.added).toEqual(['perm.c']);
    expect(result.removed).toEqual([]);
    expect(result.currentPermissions).toEqual(['perm.a', 'perm.b', 'perm.c']);
    expect(result.baselinePermissions).toEqual(['perm.a', 'perm.b']);
  });

  it('compare shows contraction (removed permissions)', () => {
    saveBaseline({
      credentialName: 'CONTRACT_TEST',
      provider: 'vault',
      permissions: ['perm.a', 'perm.b', 'perm.c'],
      checkedAt: '2026-03-01T10:00:00Z',
    });

    const result = compareToBaseline('CONTRACT_TEST', 'vault', ['perm.a']);

    expect(result.hasExpanded).toBe(false);
    expect(result.added).toEqual([]);
    expect(result.removed).toEqual(['perm.b', 'perm.c']);
  });

  it('compare shows no change', () => {
    saveBaseline({
      credentialName: 'STABLE_TEST',
      provider: 'gcp',
      permissions: ['perm.a', 'perm.b'],
      checkedAt: '2026-03-01T10:00:00Z',
    });

    const result = compareToBaseline('STABLE_TEST', 'gcp', ['perm.a', 'perm.b']);

    expect(result.hasExpanded).toBe(false);
    expect(result.added).toEqual([]);
    expect(result.removed).toEqual([]);
  });

  it('compare with missing baseline returns empty comparison', () => {
    const result = compareToBaseline('MISSING_BASELINE', 'gcp', ['perm.a']);

    expect(result.baselinePermissions).toEqual([]);
    expect(result.added).toEqual(['perm.a']);
    expect(result.hasExpanded).toBe(true);
  });

  it('reset clears baseline', () => {
    saveBaseline({
      credentialName: 'RESET_TEST',
      provider: 'gcp',
      permissions: ['perm.a'],
      checkedAt: '2026-03-01T10:00:00Z',
    });

    const cleared = resetBaseline('RESET_TEST');
    expect(cleared).toBe(true);

    const loaded = loadBaseline('RESET_TEST');
    expect(loaded).toBeUndefined();
  });

  it('reset returns false for non-existent baseline', () => {
    const cleared = resetBaseline('DOES_NOT_EXIST');
    expect(cleared).toBe(false);
  });

  it('lists all baselines', () => {
    saveBaseline({
      credentialName: 'CRED_A',
      provider: 'gcp',
      permissions: ['perm.a'],
      checkedAt: '2026-03-01T10:00:00Z',
    });

    saveBaseline({
      credentialName: 'CRED_B',
      provider: 'vault',
      permissions: ['perm.b'],
      checkedAt: '2026-03-01T11:00:00Z',
    });

    const baselines = listBaselines();
    expect(baselines).toHaveLength(2);

    const names = baselines.map(b => b.credentialName).sort();
    expect(names).toEqual(['CRED_A', 'CRED_B']);
  });
});
