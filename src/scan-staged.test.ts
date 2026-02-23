import { describe, it, expect, vi, beforeEach } from 'vitest';
import { scanStagedFiles } from './scan-staged';

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
});
