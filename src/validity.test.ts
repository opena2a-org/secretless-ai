/**
 * `scan --check-validity` (src/validity.ts). What these tests hold:
 *
 * - The registry covers real pattern ids, each by one probe, and names no
 *   probe for the types a request could not answer or would act on.
 * - A request goes to the probe's host over HTTPS with the value in exactly
 *   one header or the path, never the query, and redirects unfollowed.
 * - 200 is live, 401 is rejected, anything else, an error or a timeout is
 *   unknown with the status or reason named; Slack is decided on its body.
 * - A webhook URL is sent as its own path to the host that serves it, and
 *   to no other host; the Discord and Slack webhook answers are decided as
 *   those hosts state them, and a URL off the host or its path is not sent.
 * - No result string holds the value, even when an error message does.
 * - The scanner keeps a matched value only under `retainValues`, and never on
 *   the finding object.
 * - The help and docs/commands.md name what the flag contacts.
 */
import { describe, it, expect, vi } from 'vitest';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import {
  VALIDITY_PROBES, VALUE_MARKER, URL_PATH_MARKER, probeFor, buildProbeRequest, notSentReason, probeCredential, checkFindings,
  summarizeValidity, stateLabel, validityHelpLines, probeEndpoint,
  type ProbeFetch, type ProbeFetchInit, type ValidityProbe, type ValidityResult,
} from './validity';
import { scan, matchedValueOf, type ScanFinding } from './scan';
import { CREDENTIAL_PATTERNS } from './patterns';
import { VERBS, prepareArgv } from './argv';
import { printCommandHelp } from './command-help';

/** Not a credential: `probeCredential` takes any string, and this one is never scanned. */
const VALUE = 'not-a-real-token';

/** A value each probe sends: the plain token, or for a probe that takes a URL, a URL on its host under its prefix ending in that token. */
function sampleValueFor(probe: ValidityProbe): string {
  const at = probe.path.indexOf(URL_PATH_MARKER);
  return at < 0 ? VALUE : `${probe.host}${probe.path.slice(0, at)}${VALUE}`;
}

interface Call { url: string; init: ProbeFetchInit }

/** A fetch stand-in that answers every request with one status and body, recording each call. */
function answering(status: number, body = '', calls: Call[] = []): ProbeFetch {
  return async (url, init) => {
    calls.push({ url, init });
    return { status, text: async () => body };
  };
}

/**
 * A probe's row in the help, read as one line: the line that opens with its
 * label and the lines that continue it under the column. Undefined when no
 * line opens with the label.
 */
function helpRow(lines: string[], label: string): string | undefined {
  const start = lines.findIndex((l) => l.startsWith(`  ${label} `) || l === `  ${label}`);
  if (start < 0) return undefined;
  let end = start + 1;
  while (end < lines.length && /^ {3,}\S/.test(lines[end])) end++;
  return lines.slice(start, end).map((l) => l.trim()).join(' ');
}

function findingOf(patternId: string, file = 'a.js', line = 1): ScanFinding {
  const name = CREDENTIAL_PATTERNS.find((p) => p.id === patternId)?.name ?? patternId;
  return {
    file, line, patternId, patternName: name, severity: 'high', preview: '', fix: 'rotate it',
    confidence: 0.9, confidenceTier: 'high', looksLikeFixture: false,
  };
}

describe('the probe registry', () => {
  it('covers pattern ids that exist, each by one probe, and names a host and an absolute path per probe', () => {
    const ids = new Set(CREDENTIAL_PATTERNS.map((p) => p.id));
    const seen = new Set<string>();
    expect(VALIDITY_PROBES.length).toBeGreaterThan(0);
    for (const probe of VALIDITY_PROBES) {
      expect(probe.host).toMatch(/^[a-z0-9.-]+$/);
      expect(probe.path.startsWith('/')).toBe(true);
      expect(probe.patterns.length).toBeGreaterThan(0);
      for (const id of probe.patterns) {
        expect(ids.has(id), `${id} is not a credential pattern id`).toBe(true);
        expect(seen.has(id), `${id} is covered by two probes`).toBe(false);
        seen.add(id);
        expect(probeFor(id)).toBe(probe);
      }
    }
  });

  it('has no probe for the types a request could not answer on the value alone, or would act on', () => {
    for (const id of [
      // A connection string or a key file: no endpoint answers for it.
      'postgres', 'mysql', 'mongodb', 'redis', 'pem-private-key', 'gcp-service-account', 'secretless-bundle', 'pkcs12-keystore',
      // Needs a second value beside the one found: an AWS secret, an account or user name, a project host, the API a key is enabled for.
      'aws-access', 'aws-secret', 'aws-sts', 'azure', 'supabase', 'twilio', 'dockerhub', 'bitbucket', 'google', 'slack-app',
      // The one call these accept would act: rotate the token, run a pipeline; a Stripe webhook secret only signs.
      'stripe-webhook', 'github-refresh', 'gitlab-pipeline',
    ]) {
      expect(probeFor(id), id).toBeUndefined();
    }
  });

  it('carries one marker per probe: the value marker in the path or one header, or the URL-path marker ending the path', () => {
    for (const probe of VALIDITY_PROBES) {
      const carriers = [probe.path, ...Object.values(probe.headers)].filter((s) => s.includes(VALUE_MARKER) || s.includes(URL_PATH_MARKER));
      expect(carriers, probe.provider).toHaveLength(1);
      expect(carriers[0].split(VALUE_MARKER).length + carriers[0].split(URL_PATH_MARKER).length, probe.provider).toBe(3);
      if (carriers[0].includes(URL_PATH_MARKER)) {
        expect(carriers[0], `${probe.provider}: the URL-path marker belongs in the path`).toBe(probe.path);
        expect(probe.path.endsWith(URL_PATH_MARKER), probe.provider).toBe(true);
        expect(probe.path.length, `${probe.provider}: a URL probe names the path prefix a found URL must be under`).toBeGreaterThan(URL_PATH_MARKER.length + 1);
      } else {
        expect(probe.urlHosts, `${probe.provider}: urlHosts belongs to a URL probe`).toBeUndefined();
      }
      expect(probe.body ?? '', probe.provider).not.toContain(VALUE_MARKER);
      expect(probe.body ?? '', probe.provider).not.toContain(URL_PATH_MARKER);
    }
  });

  it('builds every request for the probe host over https, with the value in one place and never the query', () => {
    for (const probe of VALIDITY_PROBES) {
      const value = sampleValueFor(probe);
      expect(notSentReason(probe, value), probe.provider).toBeNull();
      const request = buildProbeRequest(probe, value);
      const url = new URL(request.url);
      expect(url.protocol, probe.provider).toBe('https:');
      expect(url.host, probe.provider).toBe(probe.host);
      expect(url.search, probe.provider).toBe('');
      const inHeaders = Object.values(request.headers).filter((v) => v.includes(VALUE)).length;
      const inPath = url.pathname.includes(VALUE) ? 1 : 0;
      expect(inHeaders + inPath, probe.provider).toBe(1);
      expect(request.headers['User-Agent']).toMatch(/^secretless-ai\/\d+\.\d+\.\d+/);
      expect(request.method).toBe(probe.method);
      expect(request.body, probe.provider).toBe(probe.body);
      if (request.body !== undefined) expect(request.body, probe.provider).not.toContain(VALUE);
    }
  });
});

describe('probeCredential', () => {
  it.each([
    [200, 'live'],
    [401, 'rejected'],
    [302, 'unknown'],
    [403, 'unknown'],
    [404, 'unknown'],
    [429, 'unknown'],
    [500, 'unknown'],
  ])('reports an answer of %i as %s, naming the host and the status', async (status, state) => {
    const result = await probeCredential('github-pat', VALUE, { fetchImpl: answering(status) });
    expect(result).toEqual({ state, host: 'api.github.com', status, detail: `api.github.com answered ${status}` });
  });

  it('sends a GitHub token as a bearer header to api.github.com/user, with redirects left unfollowed', async () => {
    const calls: Call[] = [];
    await probeCredential('github-pat', VALUE, { fetchImpl: answering(200, '', calls) });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://api.github.com/user');
    expect(calls[0].init.method).toBe('GET');
    expect(calls[0].init.redirect).toBe('manual');
    expect(calls[0].init.headers.Authorization).toBe(`Bearer ${VALUE}`);
    expect(calls[0].init.signal).toBeInstanceOf(AbortSignal);
  });

  it('sends an Anthropic key in x-api-key beside the API version header', async () => {
    const calls: Call[] = [];
    await probeCredential('anthropic', VALUE, { fetchImpl: answering(200, '', calls) });
    expect(calls[0].url).toBe('https://api.anthropic.com/v1/models');
    expect(calls[0].init.headers['x-api-key']).toBe(VALUE);
    expect(calls[0].init.headers['anthropic-version']).toBe('2023-06-01');
    expect(calls[0].init.headers.Authorization).toBeUndefined();
  });

  it('sends a Discord bot token with the Bot scheme', async () => {
    const calls: Call[] = [];
    await probeCredential('discord-bot', VALUE, { fetchImpl: answering(200, '', calls) });
    expect(calls[0].url).toBe('https://discord.com/api/v10/users/@me');
    expect(calls[0].init.headers.Authorization).toBe(`Bot ${VALUE}`);
  });

  it('URL-encodes a Telegram token into the path and sends it in no header', async () => {
    const calls: Call[] = [];
    const token = '12345678:not-a-real_token';
    await probeCredential('telegram-bot', token, { fetchImpl: answering(200, '', calls) });
    expect(calls[0].url).toBe('https://api.telegram.org/bot12345678%3Anot-a-real_token/getMe');
    expect(Object.values(calls[0].init.headers).some((v) => v.includes('not-a-real_token'))).toBe(false);
  });

  it('sends a GitLab token in the PRIVATE-TOKEN header to gitlab.com/api/v4/user, with no Authorization header', async () => {
    const calls: Call[] = [];
    await probeCredential('gitlab', VALUE, { fetchImpl: answering(200, '', calls) });
    expect(calls[0].url).toBe('https://gitlab.com/api/v4/user');
    expect(calls[0].init.method).toBe('GET');
    expect(calls[0].init.headers['PRIVATE-TOKEN']).toBe(VALUE);
    expect(calls[0].init.headers.Authorization).toBeUndefined();
  });

  it('sends a GitHub App installation token to the installation endpoint, not to /user', async () => {
    const calls: Call[] = [];
    const result = await probeCredential('github-app', VALUE, { fetchImpl: answering(200, '', calls) });
    expect(calls[0].url).toBe('https://api.github.com/installation/repositories');
    expect(calls[0].init.headers.Authorization).toBe(`Bearer ${VALUE}`);
    expect(calls[0].init.headers['X-GitHub-Api-Version']).toBe('2022-11-28');
    expect(result).toEqual({ state: 'live', host: 'api.github.com', status: 200, detail: 'api.github.com answered 200' });
  });

  it.each([
    ['openrouter', 'https://openrouter.ai/api/v1/auth/key'],
    ['fireworks', 'https://api.fireworks.ai/inference/v1/models'],
  ])('sends a %s key as a bearer header to %s', async (patternId, url) => {
    const calls: Call[] = [];
    const result = await probeCredential(patternId, VALUE, { fetchImpl: answering(401, '', calls) });
    expect(calls[0].url).toBe(url);
    expect(calls[0].init.method).toBe('GET');
    expect(calls[0].init.headers.Authorization).toBe(`Bearer ${VALUE}`);
    expect(result.state).toBe('rejected');
  });

  it('sends a Sentry token as a bearer header to sentry.io/api/0/organizations/, read by status', async () => {
    const calls: Call[] = [];
    const live = await probeCredential('sentry', VALUE, { fetchImpl: answering(200, '', calls) });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://sentry.io/api/0/organizations/');
    expect(calls[0].init.method).toBe('GET');
    expect(calls[0].init.redirect).toBe('manual');
    expect(calls[0].init.headers.Authorization).toBe(`Bearer ${VALUE}`);
    expect(live).toEqual({ state: 'live', host: 'sentry.io', status: 200, detail: 'sentry.io answered 200' });
    const rejected = await probeCredential('sentry', VALUE, { fetchImpl: answering(401, '{"detail":"Invalid token"}') });
    expect(rejected).toEqual({ state: 'rejected', host: 'sentry.io', status: 401, detail: 'sentry.io answered 401' });
  });

  it('sends a Linear key in the Authorization header with no scheme, as a POST of a fixed viewer query, read by status', async () => {
    const calls: Call[] = [];
    const live = await probeCredential('linear', VALUE, { fetchImpl: answering(200, '{"data":{"viewer":{"id":"u"}}}', calls) });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://api.linear.app/graphql');
    expect(calls[0].init.method).toBe('POST');
    expect(calls[0].init.body).toBe('{"query":"{ viewer { id } }"}');
    expect(calls[0].init.headers.Authorization).toBe(VALUE);
    expect(calls[0].init.headers['Content-Type']).toBe('application/json');
    expect(Object.values(calls[0].init.headers).filter((v) => v === `Bearer ${VALUE}`)).toHaveLength(0);
    expect(live).toEqual({ state: 'live', host: 'api.linear.app', status: 200, detail: 'api.linear.app answered 200' });
    const rejected = await probeCredential('linear', VALUE, { fetchImpl: answering(401, '{"errors":[{"message":"Authentication required, not authenticated"}]}') });
    expect(rejected).toEqual({ state: 'rejected', host: 'api.linear.app', status: 401, detail: 'api.linear.app answered 401' });
  });

  it('decides Linear on the status alone, not reading a 200 body that carries GraphQL errors', async () => {
    let reads = 0;
    const fetchImpl: ProbeFetch = async () => ({ status: 200, text: async () => { reads += 1; return '{"errors":[{"message":"x"}]}'; } });
    const result = await probeCredential('linear', VALUE, { fetchImpl });
    expect(result.state).toBe('live');
    expect(reads).toBe(0);
  });

  it.each([
    ['{"error":"invalid_token","error_description":"Invalid Value"}', 'rejected', 'oauth2.googleapis.com answered 400 (invalid_token)'],
    ['{"error":"invalid_request"}', 'unknown', 'oauth2.googleapis.com answered 400 (invalid_request)'],
    ['{"error":"<b>x</b>"}', 'unknown', 'oauth2.googleapis.com answered 400 (no error named)'],
    ['{}', 'unknown', 'oauth2.googleapis.com answered 400 (no error named)'],
    ['not json', 'unknown', 'oauth2.googleapis.com answered 400 with a body that is not JSON'],
  ])('decides a Google tokeninfo answer of 400 on its body: %s is %s', async (body, state, detail) => {
    const calls: Call[] = [];
    const result = await probeCredential('google-oauth', VALUE, { fetchImpl: answering(400, body, calls) });
    expect(result).toEqual({ state, host: 'oauth2.googleapis.com', status: 400, detail });
    expect(calls[0].url).toBe('https://oauth2.googleapis.com/tokeninfo');
    expect(calls[0].init.headers.Authorization).toBe(`Bearer ${VALUE}`);
  });

  it('decides a Google answer other than 400 by status, as every other probe does', async () => {
    expect(await probeCredential('google-oauth', VALUE, { fetchImpl: answering(200, '{"scope":"openid","expires_in":3599}') }))
      .toEqual({ state: 'live', host: 'oauth2.googleapis.com', status: 200, detail: 'oauth2.googleapis.com answered 200' });
    expect(await probeCredential('google-oauth', VALUE, { fetchImpl: answering(401, '') }))
      .toEqual({ state: 'rejected', host: 'oauth2.googleapis.com', status: 401, detail: 'oauth2.googleapis.com answered 401' });
    expect(await probeCredential('google-oauth', VALUE, { fetchImpl: answering(403, '{"error":"invalid_token"}') }))
      .toEqual({ state: 'unknown', host: 'oauth2.googleapis.com', status: 403, detail: 'oauth2.googleapis.com answered 403' });
  });

  it('reports a type without a probe as not checked and calls nothing', async () => {
    const calls: Call[] = [];
    const result = await probeCredential('postgres', 'anything', { fetchImpl: answering(200, '', calls) });
    expect(result).toEqual({ state: 'unchecked', detail: 'no validity probe for PostgreSQL Connection String' });
    expect(calls).toHaveLength(0);
  });

  it('does not send a Slack refresh token', async () => {
    const calls: Call[] = [];
    const refresh = ['xo', 'xr-', VALUE].join('');
    const result = await probeCredential('slack', refresh, { fetchImpl: answering(200, '{"ok":true}', calls) });
    expect(result.state).toBe('unchecked');
    expect(result.detail).toBe('not sent: an xoxr- value is a refresh token, and this probe is for access tokens');
    expect(calls).toHaveLength(0);
  });

  it.each([
    ['{"ok":true,"team":"t"}', 'live', 'slack.com answered ok: true'],
    ['{"ok":false,"error":"invalid_auth"}', 'rejected', 'slack.com answered ok: false (invalid_auth)'],
    ['{"ok":false,"error":"token_revoked"}', 'rejected', 'slack.com answered ok: false (token_revoked)'],
    ['{"ok":false,"error":"ratelimited"}', 'unknown', 'slack.com answered ok: false (ratelimited)'],
    ['{"ok":false,"error":"<b>x</b>"}', 'unknown', 'slack.com answered ok: false (no error named)'],
    ['{"ok":false}', 'unknown', 'slack.com answered ok: false (no error named)'],
    ['not json', 'unknown', 'slack.com answered 200 with a body that is not JSON'],
  ])('decides a Slack answer of 200 on its body: %s is %s', async (body, state, detail) => {
    const calls: Call[] = [];
    const result = await probeCredential('slack', VALUE, { fetchImpl: answering(200, body, calls) });
    expect(result).toEqual({ state, host: 'slack.com', status: 200, detail });
    expect(calls[0].url).toBe('https://slack.com/api/auth.test');
    expect(calls[0].init.method).toBe('POST');
  });

  it('decides a Slack answer other than 200 by status, as every other probe does', async () => {
    expect(await probeCredential('slack', VALUE, { fetchImpl: answering(429, '{"ok":false,"error":"ratelimited"}') }))
      .toEqual({ state: 'unknown', host: 'slack.com', status: 429, detail: 'slack.com answered 429' });
    expect(await probeCredential('slack', VALUE, { fetchImpl: answering(401, '') }))
      .toEqual({ state: 'rejected', host: 'slack.com', status: 401, detail: 'slack.com answered 401' });
  });

  it('reads the body only for a probe that decides on it', async () => {
    let reads = 0;
    const fetchImpl: ProbeFetch = async () => ({ status: 200, text: async () => { reads += 1; return '{"ok":true}'; } });
    expect((await probeCredential('github-pat', VALUE, { fetchImpl })).state).toBe('live');
    expect(reads).toBe(0);
    expect((await probeCredential('slack', VALUE, { fetchImpl })).state).toBe('live');
    expect(reads).toBe(1);
  });

  it('reports a failed request as unknown with the error code, and keeps the value out of the result even when the error names it', async () => {
    const refused: ProbeFetch = async () => {
      throw Object.assign(new Error(`connect refused for ${VALUE}`), { code: 'ECONNREFUSED' });
    };
    const result = await probeCredential('github-pat', VALUE, { fetchImpl: refused });
    expect(result).toEqual({ state: 'unknown', host: 'api.github.com', detail: 'no answer from api.github.com (ECONNREFUSED)' });
    expect(JSON.stringify(result)).not.toContain(VALUE);

    const failed: ProbeFetch = async () => {
      const err = new TypeError(`fetch failed ${VALUE}`);
      (err as TypeError & { cause?: unknown }).cause = { code: 'ENOTFOUND', message: VALUE };
      throw err;
    };
    const viaCause = await probeCredential('npm', VALUE, { fetchImpl: failed });
    expect(viaCause.detail).toBe('no answer from registry.npmjs.org (ENOTFOUND)');

    const bare: ProbeFetch = async () => { throw VALUE; };
    const noCode = await probeCredential('npm', VALUE, { fetchImpl: bare });
    expect(noCode.detail).toBe('no answer from registry.npmjs.org (error)');
  });

  it('reports no answer within the deadline as unknown, naming the bound, and aborts the request', async () => {
    let aborted = false;
    const stalled: ProbeFetch = (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => { aborted = true; reject(new Error(`aborted ${VALUE}`)); });
    });
    const result = await probeCredential('npm', VALUE, { fetchImpl: stalled, timeoutMs: 50 });
    expect(result).toEqual({ state: 'unknown', host: 'registry.npmjs.org', detail: 'no answer from registry.npmjs.org within 50 ms' });
    expect(aborted).toBe(true);
  });

  it('holds a body read to the same deadline', async () => {
    const stalledBody: ProbeFetch = async (_url, init) => ({
      status: 200,
      text: () => new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(new Error('aborted')));
      }),
    });
    const result = await probeCredential('slack', VALUE, { fetchImpl: stalledBody, timeoutMs: 50 });
    expect(result).toEqual({ state: 'unknown', host: 'slack.com', detail: 'no answer from slack.com within 50 ms' });
  });

  it('replaces the value in a detail a decider built from a body that echoed it', async () => {
    const echoing = answering(200, JSON.stringify({ ok: false, error: 'invalid_auth' }));
    const result = await probeCredential('slack', 'invalid_auth', { fetchImpl: echoing });
    expect(result.detail).toBe('slack.com answered ok: false ([value])');
  });
});

describe('a webhook URL is itself the credential', () => {
  // Webhook URLs as the scanner matches them: host and path, no scheme. Not
  // real: the id and the token are the words below.
  const DISCORD_HOOK = 'discord.com/api/webhooks/1/not-a-real-token';
  const SLACK_HOOK = 'hooks.slack.com/services/not-a-real-token';
  const DISCORD_NOT_SENT = 'the found URL is not an https URL on discord.com or discordapp.com under /api/webhooks/';

  it('sends a Discord webhook URL as a GET of its own path to discord.com, with no header carrying it and no body', async () => {
    const calls: Call[] = [];
    const result = await probeCredential('discord-webhook', DISCORD_HOOK, { fetchImpl: answering(200, '{"id":"1","name":"hook"}', calls) });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://discord.com/api/webhooks/1/not-a-real-token');
    expect(calls[0].init.method).toBe('GET');
    expect(calls[0].init.body).toBeUndefined();
    expect(calls[0].init.redirect).toBe('manual');
    expect(calls[0].init.headers.Authorization).toBeUndefined();
    expect(Object.values(calls[0].init.headers).some((v) => v.includes('not-a-real-token'))).toBe(false);
    expect(result).toEqual({ state: 'live', host: 'discord.com', status: 200, detail: 'discord.com answered 200' });
  });

  it('sends a discordapp.com webhook URL to discord.com, and takes only the path from the URL', async () => {
    const calls: Call[] = [];
    await probeCredential('discord-webhook', 'https://discordapp.com/api/webhooks/1/not-a-real-token?wait=true#x', { fetchImpl: answering(200, '{}', calls) });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://discord.com/api/webhooks/1/not-a-real-token');
  });

  it.each([
    ['{"message": "Unknown Webhook", "code": 10015}', 'rejected', 'discord.com answered 404 (Unknown Webhook, code 10015)'],
    ['{"message": "404: Not Found", "code": 0}', 'unknown', 'discord.com answered 404 (code 0)'],
    ['{"message": "x"}', 'unknown', 'discord.com answered 404 (no code named)'],
    ['{"code": "10015"}', 'unknown', 'discord.com answered 404 (no code named)'],
    ['<html>', 'unknown', 'discord.com answered 404 with a body that is not JSON'],
  ])('decides a Discord answer of 404 on its body: %s is %s', async (body, state, detail) => {
    const result = await probeCredential('discord-webhook', DISCORD_HOOK, { fetchImpl: answering(404, body) });
    expect(result).toEqual({ state, host: 'discord.com', status: 404, detail });
  });

  it('decides a Discord answer other than 404 by status, as every other probe does', async () => {
    expect(await probeCredential('discord-webhook', DISCORD_HOOK, { fetchImpl: answering(401, '{"message": "Invalid Webhook Token", "code": 50027}') }))
      .toEqual({ state: 'rejected', host: 'discord.com', status: 401, detail: 'discord.com answered 401' });
    expect(await probeCredential('discord-webhook', DISCORD_HOOK, { fetchImpl: answering(429, '{"message": "You are being rate limited."}') }))
      .toEqual({ state: 'unknown', host: 'discord.com', status: 429, detail: 'discord.com answered 429' });
  });

  it('sends a Slack webhook URL as a POST of {} to its own path on hooks.slack.com, as JSON, with no header carrying it', async () => {
    const calls: Call[] = [];
    const result = await probeCredential('slack-webhook', SLACK_HOOK, { fetchImpl: answering(400, 'no_text', calls) });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://hooks.slack.com/services/not-a-real-token');
    expect(calls[0].init.method).toBe('POST');
    expect(calls[0].init.body).toBe('{}');
    expect(calls[0].init.headers['Content-Type']).toBe('application/json');
    expect(calls[0].init.headers.Authorization).toBeUndefined();
    expect(Object.values(calls[0].init.headers).some((v) => v.includes('not-a-real-token'))).toBe(false);
    expect(result).toEqual({ state: 'live', host: 'hooks.slack.com', status: 400, detail: 'hooks.slack.com took the webhook and refused the empty message (no_text)' });
  });

  it.each([
    [400, 'no_text', 'live', 'hooks.slack.com took the webhook and refused the empty message (no_text)'],
    [400, 'invalid_payload\n', 'live', 'hooks.slack.com took the webhook and refused the empty message (invalid_payload)'],
    [400, 'missing_text_or_fallback_or_attachments', 'live', 'hooks.slack.com took the webhook and refused the empty message (missing_text_or_fallback_or_attachments)'],
    [400, 'user_not_found', 'unknown', 'hooks.slack.com answered 400 (user_not_found)'],
    [403, 'invalid_token', 'rejected', 'hooks.slack.com answered 403 (invalid_token)'],
    [403, 'action_prohibited', 'unknown', 'hooks.slack.com answered 403 (action_prohibited)'],
    [404, 'no_service', 'rejected', 'hooks.slack.com answered 404 (no_service)'],
    [404, 'no_team', 'rejected', 'hooks.slack.com answered 404 (no_team)'],
    [404, 'channel_not_found', 'unknown', 'hooks.slack.com answered 404 (channel_not_found)'],
    [404, '<html>Not Found</html>', 'unknown', 'hooks.slack.com answered 404 (no error named)'],
    [404, 'no_text', 'unknown', 'hooks.slack.com answered 404 (no_text)'],
  ])('decides a Slack webhook answer of %i on its body: %s is %s', async (status, body, state, detail) => {
    const result = await probeCredential('slack-webhook', SLACK_HOOK, { fetchImpl: answering(status, body) });
    expect(result).toEqual({ state, host: 'hooks.slack.com', status, detail });
  });

  it('decides a Slack webhook answer other than 400, 403 or 404 by status, as every other probe does', async () => {
    expect(await probeCredential('slack-webhook', SLACK_HOOK, { fetchImpl: answering(200, 'ok') }))
      .toEqual({ state: 'live', host: 'hooks.slack.com', status: 200, detail: 'hooks.slack.com answered 200' });
    expect(await probeCredential('slack-webhook', SLACK_HOOK, { fetchImpl: answering(410, 'channel_is_archived') }))
      .toEqual({ state: 'unknown', host: 'hooks.slack.com', status: 410, detail: 'hooks.slack.com answered 410' });
    expect(await probeCredential('slack-webhook', SLACK_HOOK, { fetchImpl: answering(500, 'rollup_error') }))
      .toEqual({ state: 'unknown', host: 'hooks.slack.com', status: 500, detail: 'hooks.slack.com answered 500' });
  });

  it.each([
    ['another host', 'discord.com.example.net/api/webhooks/1/not-a-real-token'],
    ['the host as a prefix of another', 'discord.community/api/webhooks/1/not-a-real-token'],
    ['a path off the webhook endpoint', 'discord.com/api/v10/users/@me'],
    ['the prefix with nothing after it', 'discord.com/api/webhooks/'],
    ['a port', 'discord.com:8443/api/webhooks/1/not-a-real-token'],
    ['userinfo', 'someone@discord.com/api/webhooks/1/not-a-real-token'],
    ['a plain http scheme', 'http://discord.com/api/webhooks/1/not-a-real-token'],
    ['a path that climbs out of the prefix', 'discord.com/api/webhooks/../../x'],
    ['not a URL at all', 'not-a-real-token'],
  ])('does not send a Discord webhook value with %s, and says why without the value', async (_what, value) => {
    const calls: Call[] = [];
    const result = await probeCredential('discord-webhook', value, { fetchImpl: answering(200, '{}', calls) });
    expect(calls).toHaveLength(0);
    expect(result).toEqual({ state: 'unchecked', detail: `not sent: ${DISCORD_NOT_SENT}` });
    expect(notSentReason(probeFor('discord-webhook')!, value)).toBe(DISCORD_NOT_SENT);
    expect(() => buildProbeRequest(probeFor('discord-webhook')!, value)).toThrow(/not a URL this probe sends/);
  });

  it('does not send a Slack webhook value on another host or off /services/', async () => {
    for (const value of ['slack.com/services/not-a-real-token', 'hooks.slack.com/api/auth.test', 'hooks.slack.com/services/']) {
      const calls: Call[] = [];
      const result = await probeCredential('slack-webhook', value, { fetchImpl: answering(400, 'no_text', calls) });
      expect(calls, value).toHaveLength(0);
      expect(result, value).toEqual({ state: 'unchecked', detail: 'not sent: the found URL is not an https URL on hooks.slack.com under /services/' });
    }
  });

  it('notSentReason is null for a probe with neither a URL marker nor a skip rule, and defers to a skip rule first', () => {
    expect(notSentReason(probeFor('github-pat')!, VALUE)).toBeNull();
    expect(notSentReason(probeFor('slack')!, ['xo', 'xr-', VALUE].join(''))).toBe('an xoxr- value is a refresh token, and this probe is for access tokens');
  });
});

describe('checkFindings', () => {
  it('asks once per distinct value and gives every finding that carries it the same answer', async () => {
    const calls: Call[] = [];
    const a = findingOf('github-pat', 'a.js');
    const b = findingOf('github-pat', 'b.js', 7);
    const other = findingOf('github-fine', 'c.js');
    const values = new Map<ScanFinding, string>([[a, VALUE], [b, VALUE], [other, 'another-not-real-token']]);
    const results = await checkFindings([a, b, other], (f) => values.get(f), { fetchImpl: answering(200, '', calls) });
    expect(calls).toHaveLength(2);
    expect(results.get(a)).toEqual({ state: 'live', host: 'api.github.com', status: 200, detail: 'api.github.com answered 200' });
    expect(results.get(b)).toEqual(results.get(a));
    expect(results.get(b)).not.toBe(results.get(a));
    expect(results.get(other)?.state).toBe('live');
  });

  it('marks a type without a probe, and a finding whose value was not kept, as not checked without a request', async () => {
    const calls: Call[] = [];
    const conn = findingOf('postgres');
    const kept = findingOf('github-pat');
    const results = await checkFindings([conn, kept], () => undefined, { fetchImpl: answering(200, '', calls) });
    expect(calls).toHaveLength(0);
    expect(results.get(conn)).toEqual({ state: 'unchecked', detail: 'no validity probe for PostgreSQL Connection String' });
    expect(results.get(kept)).toEqual({ state: 'unchecked', detail: 'the matched value was not kept for checking' });
  });

  it('asks at most `concurrency` hosts at a time', async () => {
    let inFlight = 0;
    let peak = 0;
    const slow: ProbeFetch = async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight -= 1;
      return { status: 200, text: async () => '' };
    };
    const findings = Array.from({ length: 6 }, (_, i) => findingOf('npm', `f${i}.js`));
    const results = await checkFindings(findings, (f) => `token-${f.file}`, { fetchImpl: slow, concurrency: 2 });
    expect(peak).toBe(2);
    expect([...results.values()].every((r) => r.state === 'live')).toBe(true);
  });

  it('returns an empty map, and sends nothing, for no findings', async () => {
    const calls: Call[] = [];
    const results = await checkFindings([], () => VALUE, { fetchImpl: answering(200, '', calls) });
    expect(results.size).toBe(0);
    expect(calls).toHaveLength(0);
  });
});

describe('summarizeValidity and stateLabel', () => {
  it('counts each state and lists the hosts asked, sorted and without repeats', () => {
    const results: ValidityResult[] = [
      { state: 'live', host: 'api.stripe.com', status: 200, detail: '' },
      { state: 'rejected', host: 'api.github.com', status: 401, detail: '' },
      { state: 'rejected', host: 'api.github.com', status: 401, detail: '' },
      { state: 'unknown', host: 'slack.com', detail: '' },
      { state: 'unchecked', detail: '' },
    ];
    expect(summarizeValidity(results)).toEqual({ live: 1, rejected: 2, unknown: 1, unchecked: 1, hosts: ['api.github.com', 'api.stripe.com', 'slack.com'] });
    expect(summarizeValidity([])).toEqual({ live: 0, rejected: 0, unknown: 0, unchecked: 0, hosts: [] });
  });

  it('prints unchecked as "not checked" and the other states as themselves', () => {
    expect(stateLabel('unchecked')).toBe('not checked');
    expect(stateLabel('live')).toBe('live');
    expect(stateLabel('rejected')).toBe('rejected');
    expect(stateLabel('unknown')).toBe('unknown');
  });
});

describe('over HTTP on the loopback interface', () => {
  async function loopback(handler: http.RequestListener): Promise<{ toLoopback: ProbeFetch; close: () => Promise<void> }> {
    const server = http.createServer(handler);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as net.AddressInfo;
    // The probe's URL names the provider host; this stand-in hands the same
    // path, method, headers and signal to the real fetch, aimed at the server.
    const toLoopback: ProbeFetch = (url, init) => fetch(`http://127.0.0.1:${port}${new URL(url).pathname}`, init);
    const close = () => new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    });
    return { toLoopback, close };
  }

  it('delivers the header through the real fetch, and reports a redirect as the answer instead of following it', async () => {
    const seen: Array<{ url: string | undefined; authorization: string | undefined }> = [];
    const { toLoopback, close } = await loopback((req, res) => {
      seen.push({ url: req.url, authorization: req.headers.authorization });
      if (req.url === '/user') {
        res.writeHead(302, { Location: '/elsewhere' });
        res.end();
        return;
      }
      res.writeHead(200);
      res.end('{}');
    });
    try {
      const result = await probeCredential('github-pat', VALUE, { fetchImpl: toLoopback });
      expect(seen).toEqual([{ url: '/user', authorization: `Bearer ${VALUE}` }]);
      expect(result).toEqual({ state: 'unknown', host: 'api.github.com', status: 302, detail: 'api.github.com answered 302' });
    } finally {
      await close();
    }
  });

  it('reads a Slack body through the real fetch', async () => {
    const { toLoopback, close } = await loopback((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(req.method === 'POST' && req.url === '/api/auth.test' ? '{"ok":false,"error":"invalid_auth"}' : '{"ok":true}');
    });
    try {
      const result = await probeCredential('slack', VALUE, { fetchImpl: toLoopback });
      expect(result).toEqual({ state: 'rejected', host: 'slack.com', status: 200, detail: 'slack.com answered ok: false (invalid_auth)' });
    } finally {
      await close();
    }
  });

  it('delivers a webhook request through the real fetch: the Slack POST carries {} as its body, the Discord GET carries none', async () => {
    const seen: Array<{ method: string | undefined; url: string | undefined; contentType: string | undefined; body: string }> = [];
    const { toLoopback, close } = await loopback((req, res) => {
      let body = '';
      req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
      req.on('end', () => {
        seen.push({ method: req.method, url: req.url, contentType: req.headers['content-type'], body });
        if (req.url?.startsWith('/services/')) {
          res.writeHead(400, { 'content-type': 'text/html' });
          res.end('no_text');
          return;
        }
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end('{"message": "Unknown Webhook", "code": 10015}');
      });
    });
    try {
      const slack = await probeCredential('slack-webhook', 'hooks.slack.com/services/not-a-real-token', { fetchImpl: toLoopback });
      const discord = await probeCredential('discord-webhook', 'discord.com/api/webhooks/1/not-a-real-token', { fetchImpl: toLoopback });
      expect(seen).toEqual([
        { method: 'POST', url: '/services/not-a-real-token', contentType: 'application/json', body: '{}' },
        { method: 'GET', url: '/api/webhooks/1/not-a-real-token', contentType: undefined, body: '' },
      ]);
      expect(slack).toEqual({ state: 'live', host: 'hooks.slack.com', status: 400, detail: 'hooks.slack.com took the webhook and refused the empty message (no_text)' });
      expect(discord).toEqual({ state: 'rejected', host: 'discord.com', status: 404, detail: 'discord.com answered 404 (Unknown Webhook, code 10015)' });
    } finally {
      await close();
    }
  });
});

describe('the scanner keeps a matched value only when asked', () => {
  // Real-shape token joined at run time, as scan.test.ts does, so no source
  // line has the shape of a provider token. Not marked FAKE: a marked value is
  // hidden as a placeholder, and these tests need the finding.
  const TOKEN = ['ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'].join('');

  function project(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'validity-scan-'));
    fs.writeFileSync(path.join(dir, 'config.js'), `const token = "${TOKEN}";\n`);
    return dir;
  }

  it('keeps nothing by default, and never puts the value on the finding', () => {
    const dir = project();
    try {
      const findings = scan(dir, { scanGlobal: false });
      expect(findings).toHaveLength(1);
      expect(matchedValueOf(findings[0])).toBeUndefined();
      expect(JSON.stringify(findings[0])).not.toContain(TOKEN);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('under retainValues, matchedValueOf returns the value for a directory scan and a named file, and the finding still does not carry it', () => {
    const dir = project();
    try {
      const walked = scan(dir, { scanGlobal: false, retainValues: true });
      expect(walked).toHaveLength(1);
      expect(matchedValueOf(walked[0])).toBe(TOKEN);
      expect(JSON.stringify(walked[0])).not.toContain(TOKEN);
      expect(Object.keys(walked[0])).not.toContain('value');

      const named = scan(path.join(dir, 'config.js'), { scanGlobal: false, retainValues: true });
      expect(named).toHaveLength(1);
      expect(matchedValueOf(named[0])).toBe(TOKEN);
      expect(JSON.stringify(named[0])).not.toContain(TOKEN);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('the flag, the help and docs/commands.md name what --check-validity contacts', () => {
  it('scan registers --check-validity as a flag without a value, so the parser accepts it', () => {
    expect(VERBS.scan.flags['--check-validity']).toBe(false);
    const prepared = prepareArgv('scan', ['scan', '--check-validity']);
    expect(prepared.errors).toEqual([]);
    expect(prepared.warnings).toEqual([]);
  });

  it('the help rows name every probe endpoint, provider and credential type, and say what is not sent', () => {
    const lines = validityHelpLines();
    const text = lines.join(' ').replace(/\s+/g, ' ');
    for (const probe of VALIDITY_PROBES) {
      const endpoint = probeEndpoint(probe);
      const opening = lines.filter((l) => l.startsWith(`  ${endpoint} `) || l === `  ${endpoint}`);
      expect(opening, `one row for ${endpoint}`).toHaveLength(1);
      const row = helpRow(lines, endpoint);
      expect(row).toContain(`${probe.provider}: `);
      for (const id of probe.patterns) {
        const name = CREDENTIAL_PATTERNS.find((p) => p.id === id)!.name;
        expect(row, `${endpoint} row names ${name}`).toContain(name);
      }
    }
    expect(probeEndpoint(probeFor('telegram-bot')!)).toBe('api.telegram.org/bot<value>/getMe');
    expect(probeEndpoint(probeFor('discord-webhook')!)).toBe('discord.com/api/webhooks/<from the found URL>');
    expect(probeEndpoint(probeFor('slack-webhook')!)).toBe('hooks.slack.com/services/<from the found URL>');
    expect(text).not.toContain(VALUE_MARKER);
    expect(text).not.toContain(URL_PATH_MARKER);
    expect(text).toContain('Discord: a GET of the webhook, its read-only endpoint');
    expect(text).toContain('Slack: a POST whose body is {}, a message with no text, which Slack refuses before posting anything');
    expect(text).toContain('Types not listed are reported as not checked, and nothing is sent for them. '
      + 'Without the flag, no credential is sent anywhere.');
    expect(text).toContain('a self-managed GitHub or GitLab instance issued still goes to api.github.com or gitlab.com');
  });

  it('every help line fits an 80-column terminal with the notes indent, and no type name is split', () => {
    const lines = validityHelpLines();
    expect(lines.filter((l) => `    ${l}`.length > 80)).toEqual([]);
    const names = VALIDITY_PROBES.flatMap((p) => p.patterns)
      .map((id) => CREDENTIAL_PATTERNS.find((p) => p.id === id)!.name);
    const split = names.filter((name) => !lines.some((l) => l.includes(name)));
    expect(split).toEqual([]);
  });

  it('an endpoint longer than the column takes a line of its own, with its types on the next line', () => {
    const lines = validityHelpLines();
    const endpoint = probeEndpoint(probeFor('github-app')!);
    const at = lines.indexOf(`  ${endpoint}`);
    expect(at).toBeGreaterThanOrEqual(0);
    expect(lines[at + 1].trim()).toBe('GitHub: GitHub App Installation Token');
    expect(lines[at + 1].indexOf('GitHub')).toBe(lines.find((l) => l.startsWith('  api.github.com/user '))!.indexOf('GitHub'));
  });

  it('scan --help prints those lines', () => {
    const out: string[] = [];
    const spy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    try {
      printCommandHelp('scan');
    } finally {
      spy.mockRestore();
    }
    const text = out.join('\n');
    expect(text).toContain('--check-validity');
    for (const probe of VALIDITY_PROBES) {
      expect(text, probe.host).toContain(probe.host);
    }
  });

  it('the docs/commands.md paragraph on --check-validity names every provider the registry contacts', () => {
    const doc = fs.readFileSync(path.resolve(__dirname, '..', 'docs', 'commands.md'), 'utf8');
    const paragraph = doc.split('\n').filter((l) => l.startsWith('`scan --check-validity`'));
    expect(paragraph, 'docs/commands.md must hold exactly one paragraph beginning "`scan --check-validity`"').toHaveLength(1);
    for (const probe of VALIDITY_PROBES) {
      expect(paragraph[0], probe.provider).toContain(probe.provider);
    }
    expect(doc).toContain('npx secretless-ai scan --check-validity');
  });
});
