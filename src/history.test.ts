import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs/promises';
import * as os from 'os';
import { scanHistory, cleanHistory } from './history';

vi.mock('fs/promises');
vi.mock('os');

const mockReadFile = vi.mocked(fs.readFile);
const mockWriteFile = vi.mocked(fs.writeFile);
const mockHomedir = vi.mocked(os.homedir);

beforeEach(() => {
  mockHomedir.mockReturnValue('/home/testuser');
  mockReadFile.mockReset();
  mockWriteFile.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * Helper to set up mock file reads.
 * Returns content for the specified history files.
 */
function mockHistoryFiles(files: Record<string, string>): void {
  mockReadFile.mockImplementation(async (filePath: any) => {
    const p = typeof filePath === 'string' ? filePath : filePath.toString();
    if (p === '/home/testuser/.bash_history' && files['.bash_history'] !== undefined) {
      return files['.bash_history'];
    }
    if (p === '/home/testuser/.zsh_history' && files['.zsh_history'] !== undefined) {
      return files['.zsh_history'];
    }
    throw new Error('ENOENT: no such file or directory');
  });
}

describe('scanHistory', () => {
  it('detects credentials in .bash_history', async () => {
    mockHistoryFiles({
      '.bash_history': [
        'ls -la',
        'curl -H "Authorization: Bearer sk-ant-api03-abcdefghijklmnopqrstuv" https://api.example.com',
        'git push origin main',
      ].join('\n'),
    });

    const result = await scanHistory();
    expect(result.filesScanned).toBe(1);
    expect(result.findingCount).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].file).toBe('~/.bash_history');
    expect(result.findings[0].patternId).toBe('anthropic');
  });

  it('detects credentials in .zsh_history', async () => {
    mockHistoryFiles({
      '.zsh_history': [
        'echo hello',
        'export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx',
        'npm install',
      ].join('\n'),
    });

    const result = await scanHistory();
    expect(result.filesScanned).toBe(1);
    expect(result.findingCount).toBeGreaterThanOrEqual(1);
    const finding = result.findings.find(f => f.file === '~/.zsh_history');
    expect(finding).toBeDefined();
  });

  it('strips zsh timestamp prefix before matching', async () => {
    mockHistoryFiles({
      '.zsh_history': [
        ': 1234567890:0;export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890',
      ].join('\n'),
    });

    const result = await scanHistory();
    expect(result.findingCount).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].patternId).toBe('github-pat');
  });

  it('only reads last 10K lines', async () => {
    // Create a file with 12K lines, credential only in line 1 (before cutoff)
    const lines = Array(12000).fill('safe-command');
    lines[0] = 'export SECRET=sk-ant-api03-abcdefghijklmnopqrstuv';
    lines[11999] = 'export KEY=ghp_abcdefghijklmnopqrstuvwxyz1234567890';

    mockHistoryFiles({
      '.bash_history': lines.join('\n'),
    });

    const result = await scanHistory();
    // Only the last 10K lines should be scanned, so line 0 is NOT in scope
    // but line 11999 IS in scope
    const firstLineFound = result.findings.some(f => f.patternId === 'anthropic');
    const lastLineFound = result.findings.some(f => f.patternId === 'github-pat');
    expect(firstLineFound).toBe(false);
    expect(lastLineFound).toBe(true);
  });

  it('handles missing files gracefully', async () => {
    mockReadFile.mockRejectedValue(new Error('ENOENT: no such file or directory'));

    const result = await scanHistory();
    expect(result.filesScanned).toBe(0);
    expect(result.findingCount).toBe(0);
    expect(result.findings).toEqual([]);
  });

  it('detects curl Bearer token', async () => {
    mockHistoryFiles({
      '.bash_history': 'curl -X POST -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdef123456" https://api.example.com',
    });

    const result = await scanHistory();
    expect(result.findingCount).toBeGreaterThanOrEqual(1);
  });

  it('detects export commands with secrets', async () => {
    mockHistoryFiles({
      '.bash_history': 'export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    });

    const result = await scanHistory();
    expect(result.findingCount).toBeGreaterThanOrEqual(1);
    const finding = result.findings.find(f => f.patternId === 'cmd-export');
    expect(finding).toBeDefined();
  });

  it('skips lines that are too long', async () => {
    const longLine = 'export KEY=sk-ant-api03-' + 'x'.repeat(5000);
    mockHistoryFiles({
      '.bash_history': [
        longLine,
        'export KEY2=ghp_abcdefghijklmnopqrstuvwxyz1234567890',
      ].join('\n'),
    });

    const result = await scanHistory();
    // Only the second line should be detected (first line exceeds MAX_LINE_LENGTH)
    expect(result.findingCount).toBe(1);
    expect(result.findings[0].patternId).toBe('github-pat');
  });

  it('returns masked preview', async () => {
    mockHistoryFiles({
      '.bash_history': 'curl -H "x-api-key: ghp_abcdefghijklmnopqrstuvwxyz1234567890" https://api.example.com',
    });

    const result = await scanHistory();
    expect(result.findingCount).toBeGreaterThanOrEqual(1);
    const preview = result.findings[0].preview;
    // Preview should contain masking (asterisks)
    expect(preview).toContain('****');
    // Should not contain the full token
    expect(preview).not.toBe('curl -H "x-api-key: ghp_abcdefghijklmnopqrstuvwxyz1234567890" https://api.example.com');
  });

  it('scans both history files when present', async () => {
    mockHistoryFiles({
      '.bash_history': 'export KEY=ghp_abcdefghijklmnopqrstuvwxyz1234567890',
      '.zsh_history': 'export TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890',
    });

    const result = await scanHistory();
    expect(result.filesScanned).toBe(2);
    expect(result.findingCount).toBe(2);
    expect(result.findings.map(f => f.file)).toContain('~/.bash_history');
    expect(result.findings.map(f => f.file)).toContain('~/.zsh_history');
  });
});

describe('cleanHistory', () => {
  it('redacts credentials in-place', async () => {
    const originalContent = [
      'ls -la',
      'export KEY=ghp_abcdefghijklmnopqrstuvwxyz1234567890',
      'git push',
    ].join('\n');

    mockHistoryFiles({ '.bash_history': originalContent });
    mockWriteFile.mockResolvedValue(undefined);

    const result = await cleanHistory(false);
    expect(result.filesModified).toBe(1);
    expect(result.linesRedacted).toBe(1);

    // Verify backup was created
    expect(mockWriteFile).toHaveBeenCalledWith(
      '/home/testuser/.bash_history.bak',
      originalContent,
      'utf-8',
    );

    // Verify redacted content was written
    const redactedCall = mockWriteFile.mock.calls.find(
      c => c[0] === '/home/testuser/.bash_history',
    );
    expect(redactedCall).toBeDefined();
    const redactedContent = redactedCall![1] as string;
    expect(redactedContent).toContain('[REDACTED:github-pat]');
    expect(redactedContent).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz1234567890');
  });

  it('creates backup before modifying', async () => {
    mockHistoryFiles({
      '.bash_history': 'export KEY=ghp_abcdefghijklmnopqrstuvwxyz1234567890',
    });
    mockWriteFile.mockResolvedValue(undefined);

    const result = await cleanHistory(false);
    expect(result.backupPaths).toContain('~/.bash_history.bak');
  });

  it('dry-run does not modify files', async () => {
    mockHistoryFiles({
      '.bash_history': 'export KEY=ghp_abcdefghijklmnopqrstuvwxyz1234567890',
    });

    const result = await cleanHistory(true);
    expect(result.filesModified).toBe(1);
    expect(result.linesRedacted).toBe(1);
    expect(result.backupPaths).toEqual([]);
    expect(mockWriteFile).not.toHaveBeenCalled();
  });

  it('handles both history file types', async () => {
    mockHistoryFiles({
      '.bash_history': 'export KEY=ghp_abcdefghijklmnopqrstuvwxyz1234567890',
      '.zsh_history': 'export TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890',
    });
    mockWriteFile.mockResolvedValue(undefined);

    const result = await cleanHistory(false);
    expect(result.filesScanned).toBe(2);
    expect(result.filesModified).toBe(2);
    expect(result.linesRedacted).toBe(2);
    expect(result.backupPaths).toHaveLength(2);
  });

  it('does not modify files without findings', async () => {
    mockHistoryFiles({
      '.bash_history': 'ls -la\ngit status\nnpm install',
    });

    const result = await cleanHistory(false);
    expect(result.filesScanned).toBe(1);
    expect(result.filesModified).toBe(0);
    expect(result.linesRedacted).toBe(0);
    expect(mockWriteFile).not.toHaveBeenCalled();
  });
});
