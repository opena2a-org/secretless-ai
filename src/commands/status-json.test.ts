import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runStatus } from './core';

function tmpProject(files: Record<string, string> = {}): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'status-json-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

// Issue #63: `status --json` must emit a single valid JSON document, not the
// human report. Assertions stay structural where a value depends on machine
// state (watcher, broker, transcripts) and exact where it is project-local.
describe('runStatus --json', () => {
  afterEach(() => vi.restoreAllMocks());

  it('emits valid parseable JSON with protection facts and a summary verdict', () => {
    const dir = tmpProject();
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    const code = runStatus(dir, { json: true });
    const doc = JSON.parse(lines.join('\n')); // throws if not valid JSON

    expect(code).toBe(0);
    expect(doc.tool).toBe('secretless-ai');
    expect(typeof doc.version).toBe('string');
    expect(typeof doc.isProtected).toBe('boolean');
    expect(typeof doc.hookInstalled).toBe('boolean');
    expect(typeof doc.denyRuleCount).toBe('number');
    expect(Array.isArray(doc.configuredTools)).toBe(true);
    expect(typeof doc.secretsFound).toBe('number');
    expect(doc.transcriptProtection).toHaveProperty('stopHookInstalled');
    expect(doc.transcriptProtection).toHaveProperty('watcherRunning');
    expect(doc.session).toHaveProperty('relevant');
    expect(doc.broker).toHaveProperty('installed');
    expect(doc.broker).toHaveProperty('running');
    expect(typeof doc.summary.warnings).toBe('number');
    expect(['not-protected', 'protected-clean', 'protected-warnings']).toContain(doc.summary.verdict);
  });

  it('reports not-protected for an empty project directory', () => {
    const dir = tmpProject();
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    runStatus(dir, { json: true });
    const doc = JSON.parse(lines.join('\n'));

    expect(doc.hookInstalled).toBe(false);
    expect(doc.isProtected).toBe(false);
    expect(doc.configuredTools).toEqual([]);
    expect(doc.summary.verdict).toBe('not-protected');
  });

  it('reports protected when the guard hook is installed', () => {
    const dir = tmpProject({
      '.claude/hooks/secretless-guard.sh': '#!/bin/bash\nexit 0\n',
    });
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    runStatus(dir, { json: true });
    const doc = JSON.parse(lines.join('\n'));

    expect(doc.hookInstalled).toBe(true);
    expect(doc.isProtected).toBe(true);
    expect(doc.summary.verdict).toMatch(/^protected-/);
  });

  it('does NOT print the human "Secretless Status" banner in JSON mode', () => {
    const dir = tmpProject();
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    runStatus(dir, { json: true });
    expect(lines.join('\n')).not.toContain('Secretless Status');
  });

  it('human mode is unchanged: banner, observations, verdict', () => {
    const dir = tmpProject();
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    const code = runStatus(dir);
    const out = lines.join('\n');

    expect(code).toBe(0);
    expect(out).toContain('Secretless Status');
    expect(out).toContain('Observations');
    expect(out).toContain('Verdict');
  });
});
