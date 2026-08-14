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

  it('emits valid parseable JSON with protection facts and a summary verdict', async () => {
    const dir = tmpProject();
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    const code = await runStatus(dir, { json: true });
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

  it('reports not-protected for an empty project directory', async () => {
    const dir = tmpProject();
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    await runStatus(dir, { json: true });
    const doc = JSON.parse(lines.join('\n'));

    expect(doc.hookInstalled).toBe(false);
    expect(doc.isProtected).toBe(false);
    expect(doc.configuredTools).toEqual([]);
    expect(doc.summary.verdict).toBe('not-protected');
  });

  it('reports protected when the guard hook is installed', async () => {
    const dir = tmpProject({
      '.claude/hooks/secretless-guard.sh': '#!/bin/bash\nexit 0\n',
    });
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    await runStatus(dir, { json: true });
    const doc = JSON.parse(lines.join('\n'));

    expect(doc.hookInstalled).toBe(true);
    expect(doc.isProtected).toBe(true);
    expect(doc.summary.verdict).toMatch(/^protected-/);
  });

  it('does NOT print the human "Secretless Status" banner in JSON mode', async () => {
    const dir = tmpProject();
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    await runStatus(dir, { json: true });
    expect(lines.join('\n')).not.toContain('Secretless Status');
  });

  it('human mode is unchanged: banner, observations, verdict', async () => {
    const dir = tmpProject();
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });

    const code = await runStatus(dir);
    const out = lines.join('\n');

    expect(code).toBe(0);
    expect(out).toContain('Secretless Status');
    expect(out).toContain('Observations');
    expect(out).toContain('Verdict');
  });
});

/**
 * A settings file that repeats a key does not say what it reads as.
 *
 * `JSON.parse` keeps the LAST copy of `permissions`, so a file carrying three
 * deny patterns in its first copy and none in its second loses all three — in
 * Claude Code, which is what enforces them. This tool's defect was reporting
 * that as `denyRuleCount: 0` with `settingsUnreadable: null`, byte-identical to
 * a project that configured none, and rendering a green check over it.
 *
 * Three states have to be distinguishable, and `denyRuleCount` is a number in
 * exactly one of them: a number implies a measurement.
 */
describe('a settings file whose keys collide is reported as unknown, not as zero', () => {
  afterEach(() => vi.restoreAllMocks());

  const THREE_DENY = '{"permissions":{"deny":["Read(./alpha/**)","Read(./bravo/**)","Bash(charlie --list)"]}}';
  const REPEATED = '{"permissions":{"deny":["Read(./alpha/**)","Read(./bravo/**)","Bash(charlie --list)"]},"permissions":{"deny":[]}}';

  async function statusOf(settings: string, extra: Record<string, string> = {}) {
    const dir = tmpProject({ '.claude/settings.json': settings, ...extra });
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    await runStatus(dir, { json: true });
    return JSON.parse(lines.join('\n'));
  }

  it('CONTROL: the same three deny patterns, written once, are counted', async () => {
    const doc = await statusOf(THREE_DENY);
    expect(doc.denyRuleCount).toBe(3);
    expect(doc.settingsAmbiguous).toBeNull();
    expect(doc.settingsUnreadable).toBeNull();
  });

  it('the repeated key is reported, and the count is null rather than 0', async () => {
    const doc = await statusOf(REPEATED);
    // The defect: this used to be 0, indistinguishable from "none configured".
    expect(doc.denyRuleCount).toBeNull();
    expect(doc.settingsAmbiguous).not.toBeNull();
    expect(doc.settingsAmbiguous.path).toBe('.claude/settings.json');
    // The key has to be named or the user has a warning and no way to act.
    expect(doc.settingsAmbiguous.reason).toContain('permissions');
    // It parsed fine, so it is NOT the unreadable state.
    expect(doc.settingsUnreadable).toBeNull();
  });

  it('a file that does not parse stays a DIFFERENT state, also with a null count', async () => {
    const doc = await statusOf('{"permissions": }');
    expect(doc.denyRuleCount).toBeNull();
    expect(doc.settingsUnreadable).not.toBeNull();
    expect(doc.settingsAmbiguous).toBeNull();
  });

  it('the three states are mutually distinguishable from the JSON alone', async () => {
    const measured = await statusOf(THREE_DENY);
    const ambiguous = await statusOf(REPEATED);
    const unreadable = await statusOf('{"permissions": }');
    const shape = (d: Record<string, unknown>) =>
      `${d.denyRuleCount === null ? 'null' : 'n'}/${d.settingsAmbiguous ? 'amb' : '-'}/${d.settingsUnreadable ? 'unr' : '-'}`;
    const shapes = [shape(measured), shape(ambiguous), shape(unreadable)];
    expect(new Set(shapes).size, `states collapsed: ${shapes.join(' ')}`).toBe(3);
  });

  it('does not render a green check over a file it could not read as configured', async () => {
    // The hook being installed is what produced the check. With the guard
    // script present AND the settings ambiguous, nothing about that file may
    // render green.
    const dir = tmpProject({
      '.claude/settings.json': REPEATED,
      '.claude/hooks/secretless-guard.sh': '#!/bin/sh\n# secretless-ai guard\n',
    });
    const lines: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
    await runStatus(dir);
    const out = lines.join('\n');

    expect(out).not.toMatch(/✓ Claude Code hook installed/);
    expect(out).toMatch(/repeats/);
    // No dead end: neither grep nor `node -e JSON.parse` can see a duplicate,
    // and this release's own notes say an escaped or case-variant collision
    // survives both. The action has to be something that actually re-checks.
    expect(out).toMatch(/secretless-ai status/);
    expect(out).not.toMatch(/JSON\.parse\(require/);
  });
});
