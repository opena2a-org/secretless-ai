import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// The store and the baselines are stubbed: this file tests what `scope check`
// SAYS, and a real store on macOS is the OS keychain.
const getSecret = vi.fn();
vi.mock('../secret-store', () => ({
  SecretStore: class { getSecret = getSecret; },
}));
vi.mock('../backends/config', () => ({ resolveBackendType: () => 'local' }));

const loadBaseline = vi.fn();
const discoverScope = vi.fn();
vi.mock('../scope', () => ({
  discoverScope: (...a: unknown[]) => discoverScope(...a),
  listBaselines: vi.fn().mockReturnValue([]),
  resetBaseline: vi.fn(),
  loadBaseline: (...a: unknown[]) => loadBaseline(...a),
  detectProvider: vi.fn(),
}));

import { runScope } from './scope';
import { CLI_BARE } from './utils';

const BASELINE = {
  credentialName: 'GCP_SA_KEY',
  provider: 'gcp',
  permissions: ['storage.objects.get'],
  checkedAt: '2026-03-01T10:00:00Z',
};

let err: string[];
let out: string[];

beforeEach(() => {
  err = [];
  out = [];
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  getSecret.mockReset();
  loadBaseline.mockReset();
  discoverScope.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// #127. A baseline whose credential is gone from the store returned a bare
// "not found" and exit 1, while `scope list` still showed the baseline: two
// commands that disagree, and no step to reconcile them.
describe('scope check — a stored baseline with no stored credential (#127)', () => {
  it('names the baseline as stale and gives a cleanup step', async () => {
    loadBaseline.mockReturnValue(BASELINE);
    getSecret.mockResolvedValue(undefined);

    const code = await runScope(['check', 'GCP_SA_KEY']);

    const text = err.join('\n');
    expect(code).toBe(1);
    expect(text).toContain('Credential "GCP_SA_KEY" not found in secret store.');
    expect(text).toContain('stale');
    expect(text).toContain('scope reset GCP_SA_KEY');
    expect(text).toContain('secret set GCP_SA_KEY');
    expect(text).toContain('Verify:');
    expect(discoverScope).not.toHaveBeenCalled();
  });

  // #475. Each Fix line ended in a remark in parentheses, which bash refuses
  // when the line is pasted: ``syntax error near unexpected token `('``.
  it('says when each Fix applies on the line above it, and each Fix line ends at its command (#475)', async () => {
    loadBaseline.mockReturnValue(BASELINE);
    getSecret.mockResolvedValue(undefined);

    expect(await runScope(['check', 'GCP_SA_KEY'])).toBe(1);

    expect(err.join('\n').split('\n')).toEqual([
      '',
      '  Credential "GCP_SA_KEY" not found in secret store.',
      '  A scope baseline for it is still stored (from 2026-03-01T10:00:00Z), so the baseline is stale.',
      '  If the credential is gone, remove the baseline:',
      `  Fix:    ${CLI_BARE} scope reset GCP_SA_KEY`,
      '  If the credential moved, store it again:',
      `  Fix:    ${CLI_BARE} secret set GCP_SA_KEY`,
      `  Verify: ${CLI_BARE} scope list`,
      '',
    ]);
  });

  it('CONTROL: with no baseline, the first step is still discover', async () => {
    loadBaseline.mockReturnValue(null);

    const code = await runScope(['check', 'GCP_SA_KEY']);

    expect(code).toBe(1);
    expect(err.join('\n')).toContain('No baseline found for "GCP_SA_KEY".');
    expect(out.join('\n')).toContain('scope discover');
    expect(getSecret).not.toHaveBeenCalled();
  });
});
