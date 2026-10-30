import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SecretStore } from '../secret-store';
import { LocalBackend } from '../backends/local';
import { pathOperand } from './core';

// A session that is still running appends to its transcript between clean's
// read and its rename. `onRedacted` runs between the two, so the change a cell
// puts in `between.change` is made there, once, as a concurrent writer would.
const between = vi.hoisted(() => ({ change: null as null | (() => void) }));
vi.mock('../transcript', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../transcript')>();
  return {
    ...actual,
    cleanTranscripts: (options: Parameters<typeof actual.cleanTranscripts>[0] = {}) => actual.cleanTranscripts({
      ...options,
      onRedacted: (span, where) => {
        options.onRedacted?.(span, where);
        const change = between.change;
        between.change = null;
        change?.();
      },
    }),
  };
});

import { runClean } from './transcript';

describe('clean exits 1 with one line when a file changed while it was read', () => {
  const APPENDED = JSON.stringify({ type: 'user', seq: 3, message: { content: 'written while clean ran' } }) + '\n';
  let home: string;
  let projects: string;
  let file: string;
  let value: string;
  let before: string;
  let out: string[];
  let err: string[];
  const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };

  const store = (): SecretStore => new SecretStore({
    backend: new LocalBackend({ storeDir: path.join(home, 'store'), key: 'test-key' }),
    annotationsPath: path.join(home, 'annotations.json'),
  });

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'clean-abort-'));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    projects = path.join(home, '.claude', 'projects');
    fs.mkdirSync(path.join(projects, 'p'), { recursive: true });
    file = path.join(projects, 'p', 'live.jsonl');
    // A synthetic value, built at run time, for a secret-named variable.
    value = ['fixture', crypto.randomBytes(8).toString('hex')].join('');
    before = [
      JSON.stringify({ type: 'user', seq: 1, message: { content: `export SERVICE_API_KEY=${value}` } }),
      JSON.stringify({ type: 'assistant', seq: 2, message: { content: 'ok' } }),
    ].join('\n') + '\n';
    fs.writeFileSync(file, before);
    between.change = null;
    out = [];
    err = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { out.push(args.join(' ')); });
    vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { err.push(args.join(' ')); });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    between.change = null;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('a transcript appended to during the run keeps the line, and the abort is one line on stderr at exit 1', async () => {
    between.change = () => { fs.appendFileSync(file, APPENDED); };

    const code = await runClean(['--last', '--path', projects], { createStore: store });

    expect(fs.readFileSync(file, 'utf-8')).toBe(before + APPENDED);
    expect(fs.readdirSync(path.join(projects, 'p'))).toEqual(['live.jsonl']);
    expect(code).toBe(1);
    expect(err).toHaveLength(1);
    expect(err[0]).toMatch(/^ {2}Aborted: ~\/\.claude\/projects\/p\/live\.jsonl changed while it was being read and was left unchanged\. /);
    expect(err[0]).toContain(`clean --path ${pathOperand(file)}`);
    expect(out.join('\n')).toContain('Redacted: 0');
  });

  it('the dry run is unchanged: exit 0, no abort line, nothing rewritten', async () => {
    between.change = () => { fs.appendFileSync(file, APPENDED); };

    const code = await runClean(['--dry-run', '--last', '--path', projects], { createStore: store });

    expect(code).toBe(0);
    expect(err.join('\n')).not.toContain('Aborted');
    expect(fs.readFileSync(file, 'utf-8')).toBe(before + APPENDED);
  });

  it('CONTROL: a transcript nobody writes to is redacted at exit 0 with no abort line', async () => {
    const code = await runClean(['--last', '--path', projects], { createStore: store });

    expect(code).toBe(0);
    expect(err.join('\n')).not.toContain('Aborted');
    expect(out.join('\n')).toContain('Redacted: 1');
    const after = fs.readFileSync(file, 'utf-8');
    expect(after).not.toContain(value);
    expect(after).toContain('SERVICE_API_KEY=[REDACTED:secret-assignment]');
  });
});
