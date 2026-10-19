/**
 * `runScan` under `--check-validity`.
 *
 * Without the flag nothing reaches the network and the output is the one the
 * command printed before: no `validity` key in `--json`, no `Validity:` line.
 * With it, each finding carries the issuing host's answer in both renderers
 * and in the explanation view, the value appears in no output, the same value
 * in two files is sent once, an OpenAI project key value the pattern stopped
 * at a _ is not sent, an AWS key ID and its secret on one line are
 * checked as a pair, and severity, confidence and the exit code are what
 * they are without the flag.
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
import { CREDENTIAL_PATTERNS, KNOWN_EXAMPLE_KEYS } from '../patterns';

// Real-shape tokens joined at run time, as scan-json.test.ts does, so no
// source line has the shape of a provider token. Not marked FAKE: a marked
// value is hidden as a placeholder, and these tests need the findings.
const GITHUB = ['ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'].join('');
/** A GitLab token: checked at gitlab.com, sent in the PRIVATE-TOKEN header rather than as a bearer. */
const GITLAB = ['glpat-', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'].join('');
/** A Docker Hub token: a pattern no probe covers, so it reads "not checked". */
const DOCKERHUB = ['dckr_pat_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'].join('');
/** Webhook URLs as the scanner matches them, host and path: each is itself the credential and is sent as its own path. */
const DISCORD_HOOK = ['discord.com/api/webhooks/', '123456789012345678', '/', 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'].join('');
const SLACK_HOOK = ['hooks.slack.com/services/', 'T0A1B2C3D4E', '/', 'B5F6G7H8I9J', '/', 'ABCDEFGHIJKLMNOPQRSTUVWX'].join('');
/** The last path segment of a webhook URL: the part that must appear in no output and no header. */
const tokenOf = (hook: string): string => hook.slice(hook.lastIndexOf('/') + 1);
/**
 * An OpenAI project key value of 148 characters: sk-proj-, 130 letters, a _
 * and 9 letters. The pattern stops at the _ and keeps the 138 before it. The
 * part after the _, which the pattern does not keep, marks it a placeholder.
 */
const OPENAI_CUT = ['sk-proj-', 'a'.repeat(130), '_', 'FAKEVALUE'].join('');
/** sk-proj- and 156 letters, with no - or _: the pattern keeps all 164 characters. */
const OPENAI_WHOLE = ['sk-proj-', 'b'.repeat(156)].join('');
/**
 * The AWS documentation's example key pair, taken from the scanner's own list
 * of known examples so that no source line holds a key; a scan reports it
 * when told to show placeholders.
 */
const AWS_KEY_ID = [...KNOWN_EXAMPLE_KEYS].find((k) => CREDENTIAL_PATTERNS.find((p) => p.id === 'aws-access')!.regex.test(k))!;
const AWS_SECRET = [...KNOWN_EXAMPLE_KEYS].find((k) => k.length === 40)!;

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
    const dir = project({ 'config.js': `const a = "${GITHUB}";\nconst b = "${DOCKERHUB}";\n` });
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
    const dir = project({ 'config.js': `const a = "${GITHUB}";\nconst b = "${GITLAB}";\nconst c = "${DOCKERHUB}";\n` });
    const calls: Call[] = [];
    const code = await runScan(dir, { json: true, checkValidity: true, validityDeps: { fetchImpl: answering(200, calls) } });
    const text = out.join('\n');
    const doc = JSON.parse(text);
    expect(code).toBe(1);
    for (const value of [GITHUB, GITLAB, DOCKERHUB]) expect(text).not.toContain(value);

    const byId = (id: string) => doc.findings.find((f: { patternId: string }) => f.patternId === id);
    expect(byId('github-pat').validity).toEqual({ state: 'live', host: 'api.github.com', status: 200, detail: 'api.github.com answered 200' });
    expect(byId('gitlab').validity).toEqual({ state: 'live', host: 'gitlab.com', status: 200, detail: 'gitlab.com answered 200' });
    expect(byId('dockerhub').validity).toEqual({ state: 'unchecked', detail: 'no validity probe for Docker Hub PAT' });
    expect(doc.summary.validity).toEqual({ live: 2, rejected: 0, unknown: 0, unchecked: 1, hosts: ['api.github.com', 'gitlab.com'] });

    // Each value went to its issuing host, in the one header that host reads, and nowhere else.
    expect(calls).toHaveLength(2);
    const github = calls.find((call) => call.url === 'https://api.github.com/user');
    const gitlab = calls.find((call) => call.url === 'https://gitlab.com/api/v4/user');
    expect(github?.init.headers.Authorization).toBe(`Bearer ${GITHUB}`);
    expect(gitlab?.init.headers['PRIVATE-TOKEN']).toBe(GITLAB);
    expect(gitlab?.init.headers.Authorization).toBeUndefined();
    for (const call of calls) {
      const { Authorization: _auth, 'PRIVATE-TOKEN': _private, ...otherHeaders } = call.init.headers;
      const elsewhere = JSON.stringify({ url: call.url, headers: otherHeaders });
      for (const value of [GITHUB, GITLAB, DOCKERHUB]) expect(elsewhere).not.toContain(value);
    }
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

  it('an OpenAI project key value the pattern stopped at a _ is not sent, though it is longer than 132 characters, and the finding says why', async () => {
    const dir = project({ 'config.js': `const cut = "${OPENAI_CUT}";\nconst whole = "${OPENAI_WHOLE}";\n` });
    const kept = OPENAI_CUT.slice(0, OPENAI_CUT.indexOf('_'));
    expect([OPENAI_CUT.length, kept.length, OPENAI_WHOLE.length]).toEqual([148, 138, 164]);
    const calls: Call[] = [];
    // A provider that accepts each whole key and refuses anything else, such as the part of one before its _.
    const provider: ProbeFetch = async (url, init) => {
      calls.push({ url, init });
      const whole = [OPENAI_CUT, OPENAI_WHOLE].some((key) => init.headers.Authorization === `Bearer ${key}`);
      return { status: whole ? 200 : 401, text: async () => '' };
    };
    const detail = 'not sent: the pattern stopped at a _, which an OpenAI project key can hold, so the value may be only the part of a key before it';

    const code = await runScan(dir, { json: true, checkValidity: true, validityDeps: { fetchImpl: provider } });
    const text = out.join('\n');
    const doc = JSON.parse(text);
    expect(code).toBe(1);
    const byLine = (line: number) => doc.findings.find((f: { line: number }) => f.line === line);
    expect(byLine(1).patternId).toBe('openai-proj');
    expect(byLine(1).validity).toEqual({ state: 'unchecked', detail });
    expect(byLine(2).patternId).toBe('openai-proj');
    expect(byLine(2).validity).toEqual({ state: 'live', host: 'api.openai.com', status: 200, detail: 'api.openai.com answered 200' });
    expect(doc.summary.validity).toEqual({ live: 1, rejected: 0, unknown: 0, unchecked: 1, hosts: ['api.openai.com'] });
    for (const value of [kept, OPENAI_WHOLE]) expect(text).not.toContain(value);
    // Only the whole key was sent; the part before the _ went nowhere.
    expect(calls.map((call) => call.init.headers.Authorization)).toEqual([`Bearer ${OPENAI_WHOLE}`]);

    out.length = 0;
    expect(await runScan(dir, { checkValidity: true, validityDeps: { fetchImpl: provider } })).toBe(1);
    expect(out.join('\n')).toContain(`Validity: not checked (${detail})`);
    expect(calls).toHaveLength(2);
    expect(calls[1].init.headers.Authorization).toBe(`Bearer ${OPENAI_WHOLE}`);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('a webhook URL is sent as its own path to the host that serves it, with the answer read as that host states it', async () => {
    const dir = project({ 'hooks.js': `const discord = "https://${DISCORD_HOOK}";\nconst slack = "https://${SLACK_HOOK}";\n` });
    const calls: Call[] = [];
    const byHost: ProbeFetch = async (url, init) => {
      calls.push({ url, init });
      return new URL(url).host === 'hooks.slack.com'
        ? { status: 400, text: async () => 'no_text' }
        : { status: 404, text: async () => '{"message": "Unknown Webhook", "code": 10015}' };
    };
    const code = await runScan(dir, { json: true, checkValidity: true, validityDeps: { fetchImpl: byHost } });
    const text = out.join('\n');
    const doc = JSON.parse(text);
    expect(code).toBe(1);
    for (const hook of [DISCORD_HOOK, SLACK_HOOK]) expect(text).not.toContain(tokenOf(hook));

    const byId = (id: string) => doc.findings.find((f: { patternId: string }) => f.patternId === id);
    expect(byId('discord-webhook').validity).toEqual({ state: 'rejected', host: 'discord.com', status: 404, detail: 'discord.com answered 404 (Unknown Webhook, code 10015)' });
    expect(byId('slack-webhook').validity).toEqual({ state: 'live', host: 'hooks.slack.com', status: 400, detail: 'hooks.slack.com took the webhook and refused the empty message (no_text)' });
    expect(doc.summary.validity).toEqual({ live: 1, rejected: 1, unknown: 0, unchecked: 0, hosts: ['discord.com', 'hooks.slack.com'] });

    // Each URL went to its own host as its own path: a GET with no body for Discord, a POST of {} for Slack, and no header carries either.
    expect(calls).toHaveLength(2);
    const discord = calls.find((call) => call.url === `https://${DISCORD_HOOK}`);
    const slack = calls.find((call) => call.url === `https://${SLACK_HOOK}`);
    expect(discord?.init.method).toBe('GET');
    expect(discord?.init.body).toBeUndefined();
    expect(slack?.init.method).toBe('POST');
    expect(slack?.init.body).toBe('{}');
    expect(slack?.init.headers['Content-Type']).toBe('application/json');
    for (const call of calls) {
      expect(call.init.headers.Authorization).toBeUndefined();
      for (const hook of [DISCORD_HOOK, SLACK_HOOK]) expect(JSON.stringify(call.init.headers)).not.toContain(tokenOf(hook));
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('an AWS key ID and its secret on one line, reported as one finding, are checked as a pair: the key ID is named in the signature, and the secret is in no request and no output', async () => {
    const dir = project({ 'deploy.sh': `AWS_ACCESS_KEY_ID=${AWS_KEY_ID} AWS_SECRET_ACCESS_KEY=${AWS_SECRET} aws s3 ls\n` });
    expect(await runScan(dir, { json: true, showPlaceholders: true })).toBe(1);
    const before = JSON.parse(out.join('\n'));
    expect(before.findings.map((f: { patternId: string }) => f.patternId)).toEqual(['aws-access']);

    out.length = 0;
    const calls: Call[] = [];
    const code = await runScan(dir, { json: true, showPlaceholders: true, checkValidity: true, validityDeps: { fetchImpl: answering(200, calls) } });
    const text = out.join('\n');
    const after = JSON.parse(text);
    expect(code).toBe(1);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://sts.amazonaws.com/');
    expect(calls[0].init.headers.Authorization).toContain(`Credential=${AWS_KEY_ID}/`);
    expect(JSON.stringify({ url: calls[0].url, init: { ...calls[0].init, signal: undefined } })).not.toContain(AWS_SECRET);
    expect(text).not.toContain(AWS_SECRET);
    expect(after.findings).toHaveLength(1);
    const { validity, ...rest } = after.findings[0];
    expect(validity).toEqual({ state: 'live', host: 'sts.amazonaws.com', status: 200, detail: 'sts.amazonaws.com answered 200' });
    expect(rest).toEqual(before.findings[0]);
    expect(after.summary.validity).toEqual({ live: 1, rejected: 0, unknown: 0, unchecked: 0, hosts: ['sts.amazonaws.com'] });
    expect(fetchSpy).not.toHaveBeenCalled();
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
    const dir = project({ 'config.js': `const a = "${GITHUB}";\nconst b = "${DOCKERHUB}";\n` });
    const code = await runScan(dir, { checkValidity: true, validityDeps: { fetchImpl: answering(200) } });
    const text = out.join('\n');
    expect(code).toBe(1);
    expect(text).not.toContain(GITHUB);
    expect(text).not.toContain(DOCKERHUB);
    expect(text).toContain('Validity: 1 live, 1 not checked (asked api.github.com)');
    expect(text).toContain('Validity: live (api.github.com answered 200)');
    expect(text).toContain('Validity: not checked (no validity probe for Docker Hub PAT)');
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

  it('--format sarif carries the answer on each result, as --json carries it on each finding, without the value', async () => {
    const dir = project({ 'config.js': `const a = "${GITHUB}";\nconst b = "${DOCKERHUB}";\n` });
    const code = await runScan(dir, { format: 'sarif', checkValidity: true, validityDeps: { fetchImpl: answering(401) } });
    const text = out.join('\n');
    const run = JSON.parse(text).runs[0];
    expect(code).toBe(1);
    expect(text).not.toContain(GITHUB);
    expect(text).not.toContain(DOCKERHUB);

    const byRule = (id: string) => run.results.find((r: { ruleId: string }) => r.ruleId === id);
    expect(byRule('github-pat').properties.validity).toEqual({ state: 'rejected', host: 'api.github.com', status: 401, detail: 'api.github.com answered 401' });
    expect(byRule('dockerhub').properties.validity).toEqual({ state: 'unchecked', detail: 'no validity probe for Docker Hub PAT' });
    expect(run.properties.summary.validity).toEqual({ live: 0, rejected: 1, unknown: 0, unchecked: 1, hosts: ['api.github.com'] });
  });

  it('--format sarif without the flag writes no validity on any result', async () => {
    const dir = project({ 'config.js': `const a = "${GITHUB}";\n` });
    expect(await runScan(dir, { format: 'sarif' })).toBe(1);
    const run = JSON.parse(out.join('\n')).runs[0];
    expect(run.results).toHaveLength(1);
    for (const r of run.results) expect(r.properties).not.toHaveProperty('validity');
    expect(run.properties.summary).not.toHaveProperty('validity');
    expect(fetchSpy).not.toHaveBeenCalled();
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
