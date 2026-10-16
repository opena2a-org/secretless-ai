import { describe, it, expect, vi, beforeEach } from 'vitest';
import { scanStagedFiles } from './scan-staged';
import { runScanStaged } from './commands/git';
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

  it('blocks a staged bundle written by export (#175)', () => {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) {
        return 'backup/Team.SECRETLESS-BUNDLE\nsrc/app.ts\n';
      }
      return 'const x = 1;\n';
    });

    const result = scanStagedFiles();
    expect(result.blockedFiles).toEqual(['backup/Team.SECRETLESS-BUNDLE']);
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
    // An empty index is a clean answer, not a failure to answer.
    expect(result.notARepo).toBeUndefined();
  });

  it('reports a git failure as notARepo instead of an empty clean result (#125)', () => {
    mockExecFileSync.mockImplementation(() => {
      throw new Error('not a git repo');
    });

    const result = scanStagedFiles();
    expect(result.findings).toEqual([]);
    expect(result.blockedFiles).toEqual([]);
    expect(result.notARepo).toBe(true);
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

// #125: outside a repository, `scan-staged` wrote nothing and exited 0, which
// is indistinguishable from "staged files scanned, nothing found".
describe('runScanStaged outside a git repository', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('says so and exits 2, the same as diff', () => {
    mockExecFileSync.mockImplementation(() => {
      throw new Error('fatal: not a git repository');
    });
    const err: string[] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.map(String).join(' ')); });
    try {
      expect(runScanStaged()).toBe(2);
    } finally {
      spy.mockRestore();
    }
    expect(err.join('\n')).toContain('Not a git repository');
  });

  it('still exits 0 on an empty index inside a repository', () => {
    mockExecFileSync.mockImplementation(() => '');
    expect(runScanStaged()).toBe(0);
  });
});

// #411: `scan` says how many values it hid as placeholders and how to see
// them; the pre-commit path hid the same values with no count at all.
describe('scan-staged placeholder disclosure (#411)', () => {
  const PAT = ['gh', 'p_', 'R1T2Y3U4I5O6P7A8S9D0F1G2H3J4K5L6Z7X8'].join('');

  beforeEach(() => {
    vi.clearAllMocks();
  });

  function stage(files: Record<string, string>) {
    mockExecFileSync.mockImplementation((cmd: string, args?: readonly string[]) => {
      if (args && args.includes('--name-only')) return Object.keys(files).join('\n') + '\n';
      if (args && args[0] === 'show') return files[String(args[1]).slice(1)] ?? '';
      return '';
    });
  }

  function captureStderr(fn: () => number): { code: number; err: string } {
    const lines: string[] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    try {
      return { code: fn(), err: lines.join('\n') };
    } finally {
      spy.mockRestore();
    }
  }

  it('counts the matches it hid as placeholders', () => {
    stage({
      'a.js': `const token = "${PAT}"; // example\n`,
      'b.js': `const token = "${PAT}";\n`,
      'c.js': 'const k = "AKIAIOSFODNN7EXAMPLE";\n',
    });
    const result = scanStagedFiles({ noIgnore: true });
    expect(result.findings.map(f => f.file)).toEqual(['b.js']);
    expect(result.placeholdersSuppressed).toBe(2);
  });

  it('reports zero when nothing was hidden', () => {
    stage({ 'b.js': `const token = "${PAT}";\n` });
    expect(scanStagedFiles({ noIgnore: true }).placeholdersSuppressed).toBe(0);
  });

  it('prints the hidden count and the --show-placeholders pointer on a clean pass', () => {
    stage({ 'a.js': `const token = "${PAT}"; // example\n` });
    const { code, err } = captureStderr(() => runScanStaged(['--no-ignore']));
    expect(code).toBe(0);
    expect(err).toContain('1 value looked like a placeholder and was hidden.');
    expect(err).toContain('npx secretless-ai scan --show-placeholders');
  });

  it('prints the hidden count beside the findings on a blocked commit', () => {
    stage({
      'a.js': `const token = "${PAT}"; // example\n`,
      'c.js': 'const k = "AKIAIOSFODNN7EXAMPLE";\n',
      'b.js': `const token = "${PAT}";\n`,
    });
    const { code, err } = captureStderr(() => runScanStaged(['--no-ignore']));
    expect(code).toBe(1);
    expect(err).toContain('GitHub Token in b.js:1');
    expect(err).toContain('2 values looked like a placeholder and were hidden.');
    expect(err).toContain('npx secretless-ai scan --show-placeholders');
  });

  it('prints no placeholder line when nothing was hidden', () => {
    stage({ 'b.js': `const token = "${PAT}";\n` });
    const { code, err } = captureStderr(() => runScanStaged(['--no-ignore']));
    expect(code).toBe(1);
    expect(err).not.toContain('looked like a placeholder');
  });
});
