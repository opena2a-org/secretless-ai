import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runRules } from './rules';
import { runInit } from './core';

function tmpProject(files: Record<string, string> = {}): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rules-diag-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

function captureLog(): string[] {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
  return lines;
}

// A rules file the parser could not fully read must fail `rules list` and
// `init` audibly. Exit 0 over dropped patterns is the defect these pin.
describe('rules list with unrecognised content', () => {
  afterEach(() => vi.restoreAllMocks());

  it('exits 0 on a clean rules file', () => {
    const dir = tmpProject({ '.secretless-rules.yaml': 'env:\n  - ACME_*\n' });
    const lines = captureLog();
    expect(runRules(['list'], dir)).toBe(0);
    expect(lines.join('\n')).toContain('ACME_*');
  });

  it('exits 1 and names the unread lines when a key is misspelled', () => {
    const dir = tmpProject({ '.secretless-rules.yaml': 'file:\n  - "*.corp-secret"\n' });
    const lines = captureLog();
    expect(runRules(['list'], dir)).toBe(1);
    const out = lines.join('\n');
    expect(out).toContain('not read');
    expect(out).toContain('did you mean "files"?');
    expect(out).toContain('The flagged lines generate no deny rules');
  });

  it('still lists what WAS read, marked as partial, and exits 1', () => {
    const dir = tmpProject({
      '.secretless-rules.yaml': 'env:\n  - ACME_*\nfile:\n  - "*.corp-secret"\n',
    });
    const lines = captureLog();
    expect(runRules(['list'], dir)).toBe(1);
    const out = lines.join('\n');
    expect(out).toContain('ACME_*');
    expect(out).toContain('from the lines that were read');
  });
});

describe('runInit with a rules file that cannot be fully honoured', () => {
  afterEach(() => vi.restoreAllMocks());

  // HOME is redirected so runInit's shell-profile fixer and backend-config
  // reads touch a throwaway home, never the real one.
  function withTmpHome<T>(fn: () => T): T {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'rules-diag-home-'));
    const prev = process.env.HOME;
    process.env.HOME = home;
    try {
      return fn();
    } finally {
      process.env.HOME = prev;
      fs.rmSync(home, { recursive: true, force: true });
    }
  }

  it('exits 1 and renders the unread lines with a fix path', () => {
    const dir = tmpProject({ '.secretless-rules.yaml': 'file:\n  - "*.corp-secret"\n' });
    const lines = captureLog();
    const code = withTmpHome(() => runInit(dir));
    expect(code).toBe(1);
    const out = lines.join('\n');
    expect(out).toContain('does not read');
    expect(out).toContain('did you mean "files"?');
    expect(out).toContain('secretless-ai rules list');
  });

  it('exits 1 when the rules file is refused outright', () => {
    const dir = tmpProject({ '.secretless-rules.yaml': 'env:\n  - "$(whoami)"\n' });
    const lines = captureLog();
    const code = withTmpHome(() => runInit(dir));
    expect(code).toBe(1);
    expect(lines.join('\n')).toContain('refused');
  });

  it('exits 0 on a clean rules file', () => {
    const dir = tmpProject({ '.secretless-rules.yaml': 'env:\n  - CORP_*\n' });
    captureLog();
    const code = withTmpHome(() => runInit(dir));
    expect(code).toBe(0);
  });
});
