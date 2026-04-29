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
        return '.env\nsrc/app.ts\n';
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
        return 'config.js\n';
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

  it('handles git command failure gracefully', () => {
    mockExecFileSync.mockImplementation(() => {
      throw new Error('not a git repo');
    });

    const result = scanStagedFiles();
    expect(result.findings).toEqual([]);
    expect(result.blockedFiles).toEqual([]);
  });

  it('detects key files (*.pem, *.key)', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'certs/server.key\ncerts/ca.pem\nsrc/index.ts\n';
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
        return 'config.yaml\n';
      }
      return 'api_key: ${GITHUB_TOKEN}\n';
    });

    const result = scanStagedFiles();
    expect(result.findings).toEqual([]);
  });

  it('skips public AWS example key AKIAIOSFODNN7EXAMPLE (doc references should not block commits)', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'CHANGELOG.md\n';
      }
      return '- Excluded example keys (AWS `AKIAIOSFODNN7EXAMPLE`).\n';
    });

    const result = scanStagedFiles();
    expect(result.findings).toEqual([]);
  });

  it('still flags real AWS access keys that are not known examples', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'config.js\n';
      }
      return 'const key = "AKIAREALKEY1234567890";\n';
    });

    const result = scanStagedFiles();
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('issue #51: does NOT let a known-example key shadow a real credential of another pattern on the same line', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'config.js\n';
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
        return 'docs/vhs/setup-lab.sh\nsrc/cli.ts\n';
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
        return 'docs/vhs/setup-lab.sh\n';
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
        return 'config.js\n';
      }
      return 'const keys = ["AKIAIOSFODNN7EXAMPLE", "AKIAREALKEY1234567890"];\n';
    });

    const result = scanStagedFiles();
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].patternName).toBe('AWS Access Key');
  });
});
