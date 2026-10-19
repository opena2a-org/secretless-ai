import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs/promises';
import * as os from 'os';
import { scanHistory, cleanHistory } from './history';
import { leaksAny } from './redact';

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
      // Exercises the generic `cmd-export` command pattern: a secret-bearing
      // export whose value does NOT match a specific credential pattern (those
      // are matched first by matchLine — e.g. an AWS_SECRET_ACCESS_KEY value now
      // matches the `aws-secret` pattern, not `cmd-export`).
      '.bash_history': 'export DB_PASSWORD="s3cretP@sswordValue1234567890"',
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
    // The credential is replaced by the marker `scan` prints, and no character
    // of it is kept; the rest of the command is left as it was.
    expect(preview).toBe('curl -H "x-api-key: [GitHub Token REDACTED]" https://api.example.com');
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

/**
 * `secret set NAME=VALUE` puts the value in shell history (README.md); the
 * history scan reports that form whatever the value looks like (#413).
 */
describe('scanHistory — secret set NAME=VALUE', () => {
  const VALUE = 'not-a-real-value';
  /** The value's marker: the command and the name stay, no character of the value does. */
  const MARK = '[Secret in secret set NAME=VALUE REDACTED]';

  it('reports the line as cmd-secret-set and masks the whole value in the preview', async () => {
    mockHistoryFiles({
      '.bash_history': ['ls', `npx secretless-ai secret set STRIPE_KEY=${VALUE}`].join('\n'),
    });

    const result = await scanHistory();
    expect(result.findingCount).toBe(1);
    expect(result.findings[0]).toMatchObject({ file: '~/.bash_history', line: 2, patternId: 'cmd-secret-set' });
    expect(result.findings[0].preview).toBe(`npx secretless-ai secret set STRIPE_KEY=${MARK}`);
  });

  for (const [label, line, preview] of [
    ['a zsh timestamp and a short value', ': 1700000000:0;secretless-ai secret set PIN=abc', `secretless-ai secret set PIN=${MARK}`],
    ['a quoted value with a space', `secretless-ai secret set DB_PASSWORD='two words'`, `secretless-ai secret set DB_PASSWORD=${MARK}`],
    ['flags before the name', `secretless-ai secret set --description "Stripe key" --meta app=web STRIPE_KEY=${VALUE}`, `secretless-ai secret set --description "Stripe key" --meta app=web STRIPE_KEY=${MARK}`],
    ['a flag after the value', `secretless-ai secret set STRIPE_KEY=${VALUE} --meta app=web`, `secretless-ai secret set STRIPE_KEY=${MARK} --meta app=web`],
  ] as const) {
    it(`reports it with ${label}, and the preview carries no part of the value`, async () => {
      mockHistoryFiles({ '.zsh_history': line });

      const result = await scanHistory();
      expect(result.findingCount).toBe(1);
      expect(result.findings[0].patternId).toBe('cmd-secret-set');
      expect(result.findings[0].preview).toBe(preview);
    });
  }

  it('CONTROL: no value on the command line is not reported', async () => {
    mockHistoryFiles({
      '.bash_history': [
        'secretless-ai secret set STRIPE_KEY',
        'secretless-ai secret set STRIPE_KEY --from-clipboard',
        'secretless-ai secret set STRIPE_KEY --meta app=web',
        'secretless-ai secret set --meta app=web STRIPE_KEY',
        'secretless-ai secret set --meta=app=web STRIPE_KEY',
        'secretless-ai secret set STRIPE_KEY="$STRIPE_KEY"',
        'secretless-ai secret set STRIPE_KEY=$(pbpaste)',
        'secretless-ai secret set STRIPE_KEY=`pbpaste`',
        'secretless-ai secret set STRIPE_KEY=',
        'secretless-ai secret list',
      ].join('\n'),
    });

    const result = await scanHistory();
    expect(result.findings).toEqual([]);
  });

  // A quoted `--meta` argument once matched both the quoted and the unquoted
  // alternative, so a line of n such arguments and no NAME=VALUE explored 2^n
  // paths: 24 of them took about a second, 30 about twenty, and a line under
  // the 4096-character cap never returned.
  it('matches a line of forty quoted --meta arguments in under 50 ms', async () => {
    const flags = '--meta "a" '.repeat(40);
    mockHistoryFiles({
      '.bash_history': [
        `secretless-ai secret set ${flags}`,
        `secretless-ai secret set ${flags}STRIPE_KEY=${VALUE}`,
      ].join('\n'),
    });

    const started = performance.now();
    const result = await scanHistory();
    const elapsed = performance.now() - started;

    expect(elapsed).toBeLessThan(50);
    expect(result.findings.map(f => f.line)).toEqual([2]);
    expect(result.findings[0].patternId).toBe('cmd-secret-set');
    expect(result.findings[0].preview).toBe(`secretless-ai secret set ${flags}STRIPE_KEY=${MARK}`);
  });

  it('cleanHistory redacts the command and leaves no run of the value', async () => {
    mockHistoryFiles({ '.bash_history': `npx secretless-ai secret set STRIPE_KEY=${VALUE}` });
    mockWriteFile.mockResolvedValue(undefined);

    const result = await cleanHistory(false);
    expect(result.linesRedacted).toBe(1);
    const written = mockWriteFile.mock.calls.find(c => c[0] === '/home/testuser/.bash_history');
    expect(written, 'the history file was never rewritten').toBeDefined();
    expect(written![1]).toBe('npx secretless-ai [REDACTED:cmd-secret-set]');
    expect(leaksAny(written![1] as string, [VALUE])).toBe(false);
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

/**
 * The write path, pinned at the consumer rather than at the helper.
 *
 * `clean-history` is the remedy `scan-history` tells the user to run, so a
 * partial redaction here is reported to the user as a completed one. Measured
 * on 0.22.0: a `ghp_` value longer than the pattern's fixed 36-char quantifier
 * left its tail in the rewritten file while the command printed
 * `History cleaned.` and exit 0.
 *
 * Asserted with `leaksAny` — the module's own residue detector — rather than
 * with `not.toContain(value)`, because whole-value containment is exactly the
 * check that returns false over a message showing most of a credential.
 */
describe('cleanHistory — no residue for an over-length credential', () => {
  const CANONICAL = 'ghp_' + 'aB3xQ9zK7mR2tY5wL8pN4vC6hJ1sD0gF1234'.slice(0, 36);
  const OVERSHOOT = CANONICAL + 'TAILMARKER99';

  for (const [label, value] of [['canonical length', CANONICAL], ['over length', OVERSHOOT]] as const) {
    it(`writes no run of the credential back to disk — ${label}`, async () => {
      mockHistoryFiles({ '.bash_history': `export B=${value}` });
      mockWriteFile.mockResolvedValue(undefined);

      await cleanHistory(false);

      const written = mockWriteFile.mock.calls.find(c => c[0] === '/home/testuser/.bash_history');
      expect(written, 'the history file was never rewritten').toBeDefined();
      const content = written![1] as string;
      expect(content).toContain('[REDACTED:github-pat]');
      expect(leaksAny(content, [value])).toBe(false);
    });
  }
});
