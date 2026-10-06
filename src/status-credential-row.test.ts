import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * The credential row in `status` used to read "No credentials in config files"
 * and "N credentials detected in config files". The project scan covers source
 * files, .env files and a fixed list of config files, not every config file: a
 * key in values.yaml or main.tf is never read, and `status` printed
 *
 *     ✓ No credentials in config files
 *
 * over exactly that project. The row now names what it covers: findings are in
 * project files, and a clean result is a statement about the scanned files.
 *
 * Transcripts and the watcher are mocked so the output does not depend on the
 * operator's ~/.claude directory.
 */

vi.mock('./transcript', () => ({
  discoverTranscripts: () => [],
  scanTranscriptFile: () => ({ findings: [], redacted: '' }),
}));

vi.mock('./watch', () => ({ isWatchRunning: () => false }));

import { runStatus } from './commands/core';

// Built from parts so secret scanners do not flag the literal in this file.
const OPENAI_KEY = ['sk-proj-', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2'].join('');
const ANTHROPIC_KEY = ['sk-ant-api03-', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2'].join('');

async function statusOutput(dir: string): Promise<string> {
  const logs: string[] = [];
  const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    logs.push(args.join(' '));
  });
  try {
    await runStatus(dir);
  } finally {
    spy.mockRestore();
  }
  return logs.join('\n');
}

function write(dir: string, rel: string, content: string): void {
  const full = path.join(dir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
}

describe('status credential row wording', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-credrow-'));
  });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('does not call a project with keys in values.yaml and main.tf clean "config files"', async () => {
    write(dir, 'values.yaml', `openai:\n  apiKey: ${OPENAI_KEY}\n`);
    write(dir, 'main.tf', `variable "anthropic_key" {\n  default = "${ANTHROPIC_KEY}"\n}\n`);

    const out = await statusOutput(dir);

    expect(out).toContain('✓ No credentials detected in scanned files');
    expect(out).not.toContain('config files');
  });

  it('says a single finding is in project files', async () => {
    write(dir, 'src/client.ts', `export const key = "${OPENAI_KEY}";\n`);

    const out = await statusOutput(dir);

    expect(out).toContain('⚠ 1 credential detected in project files');
    expect(out).not.toContain('config files');
  });

  it('pluralises the count of findings in project files', async () => {
    write(dir, 'src/openai.ts', `export const key = "${OPENAI_KEY}";\n`);
    write(dir, 'src/anthropic.ts', `export const key = "${ANTHROPIC_KEY}";\n`);

    const out = await statusOutput(dir);

    expect(out).toContain('⚠ 2 credentials detected in project files');
    expect(out).not.toContain('config files');
  });
});
