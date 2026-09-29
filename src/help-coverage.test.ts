/**
 * The help must describe every layer that keeps a directory out of a scan
 * (#136). There are three: `.secretlessignore`, the default-ignore list, and
 * the dependency and build output directories (`node_modules/`, `dist/`,
 * `build/`, ...), which no flag enters. The help described the first two, so
 * `--no-ignore --include-tests` read as full coverage while a key baked into
 * `dist/bundle.js` stayed unread. The scan itself discloses those directories
 * as "not entered"; the help has to say the same thing before the run.
 */
import { describe, it, expect, vi } from 'vitest';
import { printHelp } from './commands/help';

function helpText(): string {
  const out: string[] = [];
  const spy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  try {
    printHelp();
  } finally {
    spy.mockRestore();
  }
  return out.join('\n');
}

describe('help names the directories no flag enters (#136)', () => {
  it('says --no-ignore still leaves dependency and build output unentered', () => {
    const text = helpText();
    const at = text.indexOf('--no-ignore              Disable');
    expect(at).toBeGreaterThan(-1);
    const entry = text.slice(at, text.indexOf('--min-confidence <n>', at));
    expect(entry).toContain('node_modules/');
    expect(entry).toContain('dist/');
    expect(entry).toContain('still not entered');
    expect(entry).toContain('scan one by its path');
  });

  it('lists scanning one of those directories by path under Scan Coverage', () => {
    const text = helpText();
    const coverage = text.slice(text.indexOf('Scan Coverage'), text.indexOf('Shell History'));
    expect(coverage).toMatch(/scan dist\s+Scan a dependency or build output directory/);
  });
});
