import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../history', () => ({
  scanHistory: vi.fn(),
  cleanHistory: vi.fn(),
}));

import { scanHistory } from '../history';
import { runScanHistory } from './transcript';

const mockScanHistory = vi.mocked(scanHistory);

// `scan --history --json` (#458). The paths src/scan-history-json.test.ts
// cannot reach through the built CLI: a scan that fails, and a finding that
// carries a field the document does not name.
describe('runScanHistory --json', () => {
  let out: string[];
  let err: string[];

  beforeEach(() => {
    out = [];
    err = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.map(String).join(' ')); });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('a scan that fails writes the error to stderr and nothing to stdout, at exit 1 as the text report does', async () => {
    mockScanHistory.mockRejectedValue(new Error('history could not be read'));
    expect(await runScanHistory({ json: true })).toBe(1);
    expect(out).toEqual([]);
    expect(err.join('\n')).toContain('Error: history could not be read');

    // CONTROL: the text report answers the same failure with the same code.
    out = [];
    err = [];
    expect(await runScanHistory()).toBe(1);
    expect(out.join('\n')).toContain('Shell History Scanner');
    expect(err.join('\n')).toContain('Error: history could not be read');
  });

  it('writes the five fields of a finding and no other', async () => {
    const finding = {
      file: '~/.bash_history',
      line: 3,
      patternId: 'cmd-secret-set',
      patternName: 'Secret in secret set NAME=VALUE',
      preview: 'secret set A=[Secret in secret set NAME=VALUE REDACTED]',
      // A field the finding does not have today, standing for one added later.
      matched: 'not-a-real-value',
    };
    mockScanHistory.mockResolvedValue({ filesScanned: 1, findingCount: 1, findings: [finding] });
    expect(await runScanHistory({ json: true })).toBe(1);
    const doc = JSON.parse(out.join('\n'));
    expect(Object.keys(doc.findings[0]).sort()).toEqual(['file', 'line', 'patternId', 'patternName', 'preview']);
    expect(out.join('\n')).not.toContain('not-a-real-value');
  });
});
