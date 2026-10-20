import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { VerifyResult } from './verify';

/**
 * `verify` found a key in `.env` and printed `Protect context: npx
 * secretless-ai init`; `init` leaves the line where it is, so the step looped
 * (#471). For a `.env` finding it now prints the `import` step `scan` gives.
 * The verify result is stood in for, so no credential-shaped value is needed.
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

function run(files: string[], sub = ''): { code: number; text: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-verify-steps-'));
  dirs.push(root);
  const project = path.join(root, sub);
  fs.mkdirSync(project, { recursive: true });
  for (const file of files) fs.writeFileSync(path.join(project, file), 'PLACEHOLDER=1\n');
  fake.result = {
    envVars: { OPENAI_API_KEY: true },
    exposedInContext: files.map((file) => ({ envVar: 'OPENAI_API_KEY', patternName: 'OpenAI Project Key', file, line: 1 })),
    exposedInTranscripts: [],
    placeholdersSuppressed: 0,
    passed: false,
  };
  vi.spyOn(process, 'cwd').mockReturnValue(root);
  let text = '';
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { text += `${a.map(String).join(' ')}\n`; });
  const code = runVerify(project);
  return { code, text };
}

/** The column the commands start in: two spaces, then a 20-character label. */
const INDENT = ' '.repeat(22);
const THEN = `${INDENT}then delete those lines, and start the app with npx secretless-ai run -- <command>\n`;

describe('verify next steps (#471)', () => {
  it('a key in .env: the import step for that file, not init', () => {
    const { code, text } = run(['.env']);
    expect(code).toBe(1);
    expect(text).toContain(`  Store the keys:     npx secretless-ai import .env\n${THEN}`);
    expect(text).not.toContain('Protect context:');
  });

  it('keys in .env and .env.local: one import line for each file', () => {
    const { text } = run(['.env', '.env.local']);
    expect(text).toContain(`  Store the keys:     npx secretless-ai import .env\n${INDENT}npx secretless-ai import .env.local\n${THEN}`);
  });

  it('a key in CLAUDE.md keeps the init step; with a .env key beside it, both are printed', () => {
    expect(run(['CLAUDE.md']).text).toContain('  Protect context:    npx secretless-ai init\n');
    expect(run(['CLAUDE.md']).text).not.toContain('import');
    const both = run(['.env', 'CLAUDE.md']).text;
    expect(both).toContain('npx secretless-ai import .env\n');
    expect(both).toContain('  Protect context:    npx secretless-ai init\n');
  });

  it('verify of a subdirectory names the file from the working directory', () => {
    expect(run(['.env'], 'app').text).toContain('  Store the keys:     npx secretless-ai import app/.env\n');
  });
});
