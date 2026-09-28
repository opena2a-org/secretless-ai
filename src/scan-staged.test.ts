import { describe, it, expect, vi, beforeEach } from 'vitest';
import { scanStagedFiles } from './scan-staged';
import { buildMatcher } from './secretlessignore';

// Mock child_process to avoid requiring a real git repo
vi.mock('child_process', () => ({
  execFileSync: vi.fn(),
}));

import { execFileSync } from 'child_process';
const mockExecFileSync = vi.mocked(execFileSync);

describe('scanStagedFiles', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('detects staged .env files', () => {
    // First call: git diff --cached --name-only
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return '.env\0src/app.ts\0';
      }
      // git show :file — return safe content for app.ts
      return 'const x = 1;\n';
    });

    const result = scanStagedFiles();
    expect(result.blockedFiles).toContain('.env');
  });

  it('detects credential patterns in staged content', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'config.js\0';
      }
      // git show :config.js — contains a GitHub token
      if (args && args[0] === 'show') {
        return 'const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";\n';
      }
      return '';
    });

    const result = scanStagedFiles();
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].patternName).toBe('GitHub Token');
    expect(result.findings[0].file).toBe('config.js');
    expect(result.findings[0].line).toBe(1);
  });

  it('returns empty when no staged files', () => {
    mockExecFileSync.mockImplementation(() => {
      return '';
    });

    const result = scanStagedFiles();
    expect(result.findings).toEqual([]);
    expect(result.blockedFiles).toEqual([]);
  });

  it('reports a failed staged listing as an error, never as a clean result (#191)', () => {
    mockExecFileSync.mockImplementation(() => {
      throw new Error('not a git repo');
    });

    const result = scanStagedFiles();
    expect(result.findings).toEqual([]);
    expect(result.blockedFiles).toEqual([]);
    expect(result.error).toMatch(/could not list the staged files: not a git repo/);
  });

  it('lists staged paths NUL-separated and without submodule entries (#191)', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'caf\u00e9.pem\0src/app.ts\0';
      }
      return 'const x = 1;\n';
    });

    const result = scanStagedFiles();
    const listCall = mockExecFileSync.mock.calls.find(c => (c[1] as string[]).includes('--name-only'));
    expect(listCall?.[1]).toEqual(expect.arrayContaining(['-z', '--ignore-submodules=all']));
    expect(result.blockedFiles).toEqual(['caf\u00e9.pem']);
  });

  it('reports a file it cannot read instead of skipping it silently (#191)', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'big.bin\0small.js\0';
      }
      if (args && args[1] === ':big.bin') {
        throw Object.assign(new Error('spawnSync git ENOBUFS'), { code: 'ENOBUFS' });
      }
      return 'const x = 1;\n';
    });

    const result = scanStagedFiles();
    expect(result.unscannedFiles).toEqual([{ file: 'big.bin', reason: 'larger than 5 MB' }]);
  });

  it('scans a line longer than 4096 characters instead of skipping it (#191)', () => {
    const token = ['ghp', 'abcdefghijklmnopqrstuvwxyz1234567890'].join('_');
    // Straddles the 4096 boundary of the first window; the overlap catches it.
    const line = 'x'.repeat(4080) + ` "${token}" ` + 'y'.repeat(6000);
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'bundle.min.js\0';
      }
      return line + '\n';
    });

    const result = scanStagedFiles();
    expect(result.findings).toEqual([{ file: 'bundle.min.js', line: 1, patternName: 'GitHub Token' }]);
    expect(result.unscannedFiles).toEqual([]);
  });

  it('detects key files (*.pem, *.key)', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'certs/server.key\0certs/ca.pem\0src/index.ts\0';
      }
      return 'safe content\n';
    });

    const result = scanStagedFiles();
    expect(result.blockedFiles).toContain('certs/server.key');
    expect(result.blockedFiles).toContain('certs/ca.pem');
  });

  it('skips env var placeholders', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'config.yaml\0';
      }
      return 'api_key: ${GITHUB_TOKEN}\n';
    });

    const result = scanStagedFiles();
    expect(result.findings).toEqual([]);
  });

  it('skips public AWS example key AKIAIOSFODNN7EXAMPLE (doc references should not block commits)', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'CHANGELOG.md\0';
      }
      return '- Excluded example keys (AWS `AKIAIOSFODNN7EXAMPLE`).\n';
    });

    const result = scanStagedFiles();
    expect(result.findings).toEqual([]);
  });

  it('still flags real AWS access keys that are not known examples', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'config.js\0';
      }
      return 'const key = "AKIAREALKEY1234567890";\n';
    });

    const result = scanStagedFiles();
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('issue #51: does NOT let a known-example key shadow a real credential of another pattern on the same line', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'config.js\0';
      }
      // Same line: public AWS example + real GitHub PAT. Previously the AWS
      // example match triggered a `break` and the real PAT was never checked.
      return 'const old = "AKIAIOSFODNN7EXAMPLE"; const new_ = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";\n';
    });

    const result = scanStagedFiles();
    const names = result.findings.map(f => f.patternName);
    expect(names).toContain('GitHub Token');
  });

  it('respects an injected ignore matcher (default-ignore for fixture dirs)', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'docs/vhs/setup-lab.sh\0src/cli.ts\0';
      }
      // Both files: a real-shape GitHub PAT.
      return 'const t = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";\n';
    });
    // Inject a matcher that ignores docs/vhs only — same as the default list.
    const ignore = buildMatcher(['docs/vhs/']);
    const result = scanStagedFiles({ ignore });
    // src/cli.ts still flagged; docs/vhs/setup-lab.sh suppressed.
    expect(result.findings.map(f => f.file)).toEqual(['src/cli.ts']);
  });

  it('--no-ignore (noIgnore: true) bypasses both defaults and user file', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'docs/vhs/setup-lab.sh\0';
      }
      return 'const t = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";\n';
    });
    const result = scanStagedFiles({ noIgnore: true });
    // No filtering — the docs/vhs file is still scanned.
    expect(result.findings.map(f => f.file)).toEqual(['docs/vhs/setup-lab.sh']);
  });

  it('issue #51: does NOT let a known-example AWS key shadow a real AWS key later on the same line', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'config.js\0';
      }
      return 'const keys = ["AKIAIOSFODNN7EXAMPLE", "AKIAREALKEY1234567890"];\n';
    });

    const result = scanStagedFiles();
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].patternName).toBe('AWS Access Key');
  });
});
