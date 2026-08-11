import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { runInit } from './commands/core';

/**
 * When `init` refuses a `.claude/settings.json` it cannot merge into, it prints a
 * `Verify:` command and a `Fix:` line. The user runs the Verify command. So the
 * test runs it too — asserting on the text would only prove we printed a string.
 *
 * Found by the 0.21.3 release test: every refusal printed the same
 * `JSON.parse(...)` verify step, but a file whose top level is `null`, an array
 * or a string is VALID JSON. For those three shapes the command the tool told
 * the user to run exited 0 and reported nothing wrong, under a `Fix:` telling
 * them to remove comments the file did not contain. The diagnosis above it was
 * correct; the two runnable lines contradicted it.
 */

function capture(fn: () => number): { code: number; out: string } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    lines.push(args.join(' '));
  });
  try {
    const code = fn();
    return { code, out: lines.join('\n').replace(/\[[0-9;]*m/g, '') };
  } finally {
    spy.mockRestore();
  }
}

/** The command the tool told the user to run, exactly as printed. */
function printedLine(out: string, label: 'Verify' | 'Fix'): string {
  const m = out.match(new RegExp(`^\\s*${label}:\\s*(.+)$`, 'm'));
  expect(m, `init printed no ${label}: line`).not.toBeNull();
  return m![1].trim();
}

function runInShell(command: string, cwd: string): number {
  const r = spawnSync('bash', ['-c', command], { cwd, encoding: 'utf-8' });
  return r.status ?? 1;
}

/** Settings shapes `init` must refuse, and what each one is. */
const REFUSED = [
  { name: 'jsonc comment', body: '{\n  // c\n  "model": "opus"\n}\n', kind: 'parse-error' },
  { name: 'trailing comma', body: '{\n  "model": "opus",\n}\n', kind: 'parse-error' },
  { name: 'null', body: 'null\n', kind: 'not-an-object' },
  { name: 'array', body: '[1,2]\n', kind: 'not-an-object' },
  { name: 'string', body: '"hello"\n', kind: 'not-an-object' },
  { name: 'number', body: '42\n', kind: 'not-an-object' },
] as const;

describe('init remediation for an unusable settings.json', () => {
  let dir: string;

  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-remediation-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  function writeSettings(body: string): void {
    fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), body);
  }

  for (const shape of REFUSED) {
    it(`prints a Verify command that actually reports the problem: ${shape.name}`, () => {
      writeSettings(shape.body);

      const { code, out } = capture(() => runInit(dir));
      expect(code).toBe(1);

      // The whole point: the command we printed must FAIL on this file. For the
      // not-an-object shapes a bare JSON.parse check exits 0, which is the bug.
      const verify = printedLine(out, 'Verify');
      expect(runInShell(verify, dir)).not.toBe(0);

      // And the advice must match the actual failure.
      const fix = printedLine(out, 'Fix');
      if (shape.kind === 'not-an-object') {
        expect(fix).toMatch(/JSON object/i);
        expect(fix).not.toMatch(/trailing comma|comments/i);
      } else {
        expect(fix).toMatch(/comment|trailing comma/i);
      }
    });
  }

  it('does not fire the not-an-object Verify command on a healthy settings file', () => {
    // Both directions. A verify step that fails on everything would pass every
    // assertion above while being useless.
    writeSettings('[1,2]\n');
    const { out } = capture(() => runInit(dir));
    const verify = printedLine(out, 'Verify');

    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), '{"model":"opus"}\n');
    expect(runInShell(verify, dir)).toBe(0);
  });

  it('re-running init after following the Fix actually configures the project', () => {
    writeSettings('[1,2]\n');
    expect(capture(() => runInit(dir)).code).toBe(1);

    // Follow the printed Fix: replace the contents with a JSON object.
    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), '{}\n');

    const second = capture(() => runInit(dir));
    expect(second.code).toBe(0);
    const settings = JSON.parse(
      fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8'),
    );
    expect(settings.permissions.deny.length).toBeGreaterThan(0);
  });
});
