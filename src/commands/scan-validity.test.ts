/**
 * `runScan` under `--check-validity`.
 *
 * Without the flag nothing reaches the network and the output is the one the
 * command printed before: no `validity` key in `--json`, no `Validity:` line.
 * With it, each finding carries the issuing host's answer in both renderers
 * and in the explanation view, the value appears in no output, the same value
 * in two files is sent once, and severity, confidence and the exit code are
 * what they are without the flag.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

vi.mock('../nanomind', () => ({
  isEngineAvailable: vi.fn(async () => true),
  explainFinding: vi.fn(async () => null),
}));

import { runScan } from './core';
import type { ProbeFetch, ProbeFetchInit } from '../validity';

// Real-shape tokens joined at run time, as scan-json.test.ts does, so no
// source line has the shape of a provider token. Not marked FAKE: a marked
// value is hidden as a placeholder, and these tests need the findings.
const GITHUB = ['ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'].join('');
/** A GitLab token: a pattern no probe covers, so it reads "not checked". */
const GITLAB = ['glpat-', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'].join('');

interface Call { url: string; init: ProbeFetchInit }

function answering(status: number, calls: Call[] = []): ProbeFetch {
  return async (url, init) => {
    calls.push({ url, init });
    return { status, text: async () => '' };
  };
}

function tmpProjectWith(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-validity-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

describe('runScan --check-validity', () => {
  let out: string[];
  let logSpy: ReturnType<typeof vi.spyOn>;
  let fetchSpy: ReturnType<typeof vi.spyOn>;
  const dirs: string[] = [];

  function project(files: Record<string, string>): string {
    const dir = tmpProjectWith(files);
    dirs.push(dir);
    return dir;
  }

  beforeEach(() => {
    out = [];
    logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { out.push(args.map(String).join(' ')); });
    // The real fetch must not be reached by any case here; a stand-in is passed where a request is expected.
    fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => { throw new Error('the real fetch was called'); });
  });

  afterEach(() => {
    logSpy.mockRestore();
    fetchSpy.mockRestore();
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('without the flag: no request, no validity key in --json, no Validity line, exit 1 as before', async () => {
    const dir = project({ 'config.js': `const a = "${GITHUB}";\nconst b = "${GITLAB}";\n` });
    const code = await runScan(dir, { json: true });
    const doc = JSON.parse(out.join('\n'));
    expect(code).toBe(1);
    expect(doc.findings).toHaveLength(2);
    for (const f of doc.findings) expect(f).not.toHaveProperty('validity');
    expect(doc.summary).not.toHaveProperty('validity');

    out.length = 0;
    expect(await runScan(dir, {})).toBe(1);
    expect(out.join('\n')).not.toContain('Validity:');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('with the flag, --json carries the answer on each finding and counts in the summary, without the value, and exit stays 1', async () => {
    const dir = project({ 'config.js': `const a = "${GITHUB}";\nconst b = "${GITLAB}";\n` });
    const calls: Call[] = [];
    const code = await runScan(dir, { json: true, checkValidity: true, validityDeps: { fetchImpl: answering(200, calls) } });
    const text = out.join('\n');
    const doc = JSON.parse(text);
    expect(code).toBe(1);
    expect(text).not.toContain(GITHUB);
    expect(text).not.toContain(GITLAB);

    const github = doc.findings.find((f: { patternId: string }) => f.patternId === 'github-pat');
    const gitlab = doc.findings.find((f: { patternId: string }) => f.patternId === 'gitlab');
    expect(github.validity).toEqual({ state: 'live', host: 'api.github.com', status: 200, detail: 'api.github.com answered 200' });
    expect(gitlab.validity).toEqual({ state: 'unchecked', detail: 'no validity probe for GitLab PAT' });
    expect(doc.summary.validity).toEqual({ live: 1, rejected: 0, unknown: 0, unchecked: 1, hosts: ['api.github.com'] });

    // The value went to the issuing host, in the bearer header, and nowhere else.
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://api.github.com/user');
    expect(calls[0].init.headers.Authorization).toBe(`Bearer ${GITHUB}`);
    const { Authorization: _auth, ...otherHeaders } = calls[0].init.headers;
    expect(JSON.stringify({ url: calls[0].url, headers: otherHeaders })).not.toContain(GITHUB);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('a rejected answer leaves the finding, its severity, its confidence and the exit code as they are without the flag', async () => {
    const dir = project({ 'config.js': `const a = "${GITHUB}";\n` });
    expect(await runScan(dir, { json: true })).toBe(1);
    const before = JSON.parse(out.join('\n')).findings[0];

    out.length = 0;
    const code = await runScan(dir, { json: true, checkValidity: true, validityDeps: { fetchImpl: answering(401) } });
    const after = JSON.parse(out.join('\n')).findings[0];
    expect(code).toBe(1);
    expect(after.validity).toEqual({ state: 'rejected', host: 'api.github.com', status: 401, detail: 'api.github.com answered 401' });
    const { validity: _validity, ...rest } = after;
    expect(rest).toEqual(before);
  });

  it('the same value in two files is sent once, and both findings carry the answer', async () => {
    const dir = project({ 'config.js': `const a = "${GITHUB}";\n`, 'lib/other.js': `const b = "${GITHUB}";\n` });
    const calls: Call[] = [];
    await runScan(dir, { json: true, checkValidity: true, validityDeps: { fetchImpl: answering(200, calls) } });
    const doc = JSON.parse(out.join('\n'));
    expect(doc.findings).toHaveLength(2);
    expect(calls).toHaveLength(1);
    for (const f of doc.findings) expect(f.validity.state).toBe('live');
    expect(doc.summary.validity.live).toBe(2);
  });

  it('a scan with nothing found reports zero counts under the flag and sends nothing', async () => {
    const dir = project({ 'index.ts': 'export const x = 1;\n' });
    const calls: Call[] = [];
    const code = await runScan(dir, { json: true, checkValidity: true, validityDeps: { fetchImpl: answering(200, calls) } });
    const doc = JSON.parse(out.join('\n'));
    expect(code).toBe(0);
    expect(doc.findings).toEqual([]);
    expect(doc.summary.validity).toEqual({ live: 0, rejected: 0, unknown: 0, unchecked: 0, hosts: [] });
    expect(calls).toHaveLength(0);
  });

  it('the human report prints a Validity line under each finding and one in the header, without the value, and exit stays 1', async () => {
    const dir = project({ 'config.js': `const a = "${GITHUB}";\nconst b = "${GITLAB}";\n` });
    const code = await runScan(dir, { checkValidity: true, validityDeps: { fetchImpl: answering(200) } });
    const text = out.join('\n');
    expect(code).toBe(1);
    expect(text).not.toContain(GITHUB);
    expect(text).not.toContain(GITLAB);
    expect(text).toContain('Validity: 1 live, 1 not checked (asked api.github.com)');
    expect(text).toContain('Validity: live (api.github.com answered 200)');
    expect(text).toContain('Validity: not checked (no validity probe for GitLab PAT)');
    expect(text).toContain('Confidence:');
    expect(text).toContain('Fix:');
  });

  it('an unknown answer is printed with its reason', async () => {
    const dir = project({ 'config.js': `const a = "${GITHUB}";\n` });
    const refused: ProbeFetch = async () => { throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }); };
    await runScan(dir, { checkValidity: true, validityDeps: { fetchImpl: refused } });
    const text = out.join('\n');
    expect(text).toContain('Validity: 1 unknown (asked api.github.com)');
    expect(text).toContain('Validity: unknown (no answer from api.github.com (ECONNREFUSED))');
  });

  it('--explain prints the Validity line under each finding too', async () => {
    const dir = project({ 'config.js': `const a = "${GITHUB}";\n` });
    const code = await runScan(dir, { explain: true, checkValidity: true, validityDeps: { fetchImpl: answering(401) } });
    const text = out.join('\n');
    expect(code).toBe(1);
    expect(text).toContain('         Validity: rejected (api.github.com answered 401)');
    expect(text).toContain('         Fix: ');
    expect(text).not.toContain(GITHUB);
  });
});
