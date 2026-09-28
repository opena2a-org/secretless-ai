import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../history', () => ({
  scanHistory: vi.fn(),
  cleanHistory: vi.fn(),
}));

import { cleanHistory } from '../history';
import { runCleanHistory } from './transcript';

const mockCleanHistory = vi.mocked(cleanHistory);

// `clean-history --dry-run` changes nothing on disk, so its summary must not
// say that files were modified or lines redacted; the real run still does.
describe('runCleanHistory summary wording', () => {
  let lines: string[];

  beforeEach(() => {
    lines = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      lines.push(args.join(' '));
    });
    mockCleanHistory.mockResolvedValue({
      filesScanned: 2,
      filesModified: 1,
      linesRedacted: 3,
      backupPaths: [],
    } as Awaited<ReturnType<typeof cleanHistory>>);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('a dry run reports what would change, not what changed', async () => {
    await runCleanHistory(true);
    const out = lines.join('\n');
    expect(mockCleanHistory).toHaveBeenCalledWith(true);
    expect(out).not.toMatch(/Files modified/);
    expect(out).not.toMatch(/Lines redacted/);
    expect(out).toMatch(/Files that would change:\s+1/);
    expect(out).toMatch(/Lines that would be redacted:\s+3/);
  });

  it('a real run reports what it modified', async () => {
    await runCleanHistory(false);
    const out = lines.join('\n');
    expect(mockCleanHistory).toHaveBeenCalledWith(false);
    expect(out).toMatch(/Files modified:\s+1/);
    expect(out).toMatch(/Lines redacted:\s+3/);
    expect(out).not.toMatch(/would/);
  });
});
