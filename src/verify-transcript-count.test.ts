import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { VerifyResult } from './verify';

/**
 * `verify` grouped its transcript findings by credential type and printed the
 * number of findings as a number of files: two keys in one transcript printed
 * `GitHub Token in 2 transcript files`, where `clean --dry-run` on the same
 * home printed `2 credential(s) in 1 file(s)`. The values and the distinct
 * files are now counted apart. The verify result is stood in for, so no
 * credential-shaped value is needed.
 */

const fake = vi.hoisted(() => ({ result: null as VerifyResult | null }));
vi.mock('./verify', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./verify')>();
  return { ...actual, verify: (dir: string) => fake.result ?? actual.verify(dir) };
});

import { runVerify } from './commands/core';

const dirs: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  fake.result = null;
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

type Exposure = VerifyResult['exposedInTranscripts'][number];

const SESSION_1 = '~/.claude/projects/-work-demo/session-1.jsonl';
const SESSION_2 = '~/.claude/projects/-work-demo/session-2.jsonl';

function found(file: string, line: number, patternName = 'GitHub Token'): Exposure {
  return { file, line, jsonPath: 'message.content', patternName };
}

/** What `verify` prints for these transcript findings: the finding lines, all of it, and the exit code. */
function run(exposed: Exposure[]): { code: number; lines: string[]; text: string } {
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-verify-transcripts-'));
  dirs.push(project);
  fake.result = {
    envVars: { GITHUB_TOKEN: true },
    exposedInContext: [],
    exposedInTranscripts: exposed,
    placeholdersSuppressed: 0,
    passed: false,
  };
  let text = '';
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { text += `${a.map(String).join(' ')}\n`; });
  const code = runVerify(project);
  text = text.replace(/\x1b\[[0-9;]*m/g, '');
  const lines = text.split('\n').filter((l) => l.startsWith('  │ ! '));
  return { code, lines, text };
}

describe('verify counts transcript values and transcript files apart', () => {
  it('two values in one transcript: 2 in 1 transcript file, with both line numbers', () => {
    const { lines, text } = run([found(SESSION_1, 3), found(SESSION_1, 7)]);
    expect(lines).toEqual([`  │ ! GitHub Token 2 in 1 transcript file (${SESSION_1}: lines 3, 7)`]);
    expect(text).not.toContain('in 2 transcript files');
  });

  it('values in two transcripts: the number of files is the number of distinct files', () => {
    expect(run([found(SESSION_1, 3), found(SESSION_2, 1)]).lines)
      .toEqual(['  │ ! GitHub Token 2 in 2 transcript files']);
    expect(run([found(SESSION_1, 3), found(SESSION_1, 7), found(SESSION_2, 1)]).lines)
      .toEqual(['  │ ! GitHub Token 3 in 2 transcript files']);
  });

  it('one value: the file and line, as before', () => {
    expect(run([found(SESSION_1, 3)]).lines).toEqual([`  │ ! GitHub Token ${SESSION_1}:3`]);
  });

  it('line numbers are sorted and listed once; one line number reads "line"', () => {
    expect(run([found(SESSION_1, 7), found(SESSION_1, 3), found(SESSION_1, 7)]).lines)
      .toEqual([`  │ ! GitHub Token 3 in 1 transcript file (${SESSION_1}: lines 3, 7)`]);
    // Two values on one JSON line, in two of its fields.
    expect(run([found(SESSION_1, 4), found(SESSION_1, 4)]).lines)
      .toEqual([`  │ ! GitHub Token 2 in 1 transcript file (${SESSION_1}: line 4)`]);
  });

  it('each credential type is counted on its own, in the order first found; verdict and exit code unchanged', () => {
    const { code, lines, text } = run([
      found(SESSION_1, 3),
      found(SESSION_2, 5, 'OpenAI Project Key'),
      found(SESSION_1, 7),
    ]);
    expect(lines).toEqual([
      `  │ ! GitHub Token 2 in 1 transcript file (${SESSION_1}: lines 3, 7)`,
      `  │ ! OpenAI Project Key ${SESSION_2}:5`,
    ]);
    expect(code).toBe(1);
    expect(text).toContain('  FAIL Credentials found in AI context or transcripts.\n');
    expect(text).toContain('  Redact transcripts: npx secretless-ai clean\n');
  });
});
