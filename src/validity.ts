/**
 * `scan --check-validity`: ask the provider that issued a found credential
 * whether it still accepts it.
 *
 * A finding says a value has the shape of a credential. Whether the provider
 * still accepts it is a different question, and only that provider can answer
 * it. This module asks, for the credential types that have a read-only
 * endpoint whose answer depends on the credential alone (or, for a Slack
 * webhook URL, a request its endpoint refuses before it posts anything), and
 * reports the answer beside the finding.
 *
 * Opt-in, end to end. Nothing here runs unless `runScan` is given
 * `checkValidity`, and the scanner keeps no matched value unless it is asked
 * to (`retainValues` in scan.ts), so without the flag there is no value to
 * send and no code path that sends one.
 *
 * What a request is. The value is placed where the probe's `headers` or `path`
 * carries the `{value}` marker, and nowhere else. The request goes to the
 * probe's `host` over HTTPS, redirects are left unfollowed so a 3xx cannot
 * carry a header to another host, and the exchange is under one deadline. A
 * URL-shaped credential (a webhook URL) is itself the request: the part of
 * its path after the probe's prefix replaces the `{url-path}` marker, once the
 * URL is checked to be https, without port or userinfo, on the probe's `host`
 * or one of its `urlHosts`, and with its path under that prefix; nothing else
 * from the URL is used, and a URL that fails the check is not sent. A probe's
 * `body`, when it has one, is fixed text that never carries the value.
 *
 * What a result says. `live`: the host answered 200, or hooks.slack.com
 * refused the empty message a webhook probe sends (400 no_text), which it
 * states instead of a refusal of the URL. `rejected`: the host answered 401,
 * or stated a rejection in a body where its API does so (Slack in a 200,
 * Google's tokeninfo in a 400, Discord's webhook endpoint in a 404 whose code
 * is 10015, hooks.slack.com in a 403 or 404 naming invalid_token, no_service
 * or no_team). `unknown`: any other status, no connection, or no answer in
 * time, with the status or reason named. `unchecked`: no probe for the type,
 * or a value the probe does not send, and nothing was sent. A result describes
 * the host's answer to the request this module sends, not the credential's
 * history: a token a self-managed GitHub or GitLab instance issued still goes
 * to api.github.com or gitlab.com, which did not issue it. No result string
 * holds the value, including one built from an error message. The states are
 * reported beside a finding and change neither its severity, its confidence
 * nor the exit code.
 */
import { CREDENTIAL_PATTERNS } from './patterns';
import { VERSION, wrapList } from './commands/utils';
import type { ScanFinding } from './scan';

export type ValidityState = 'live' | 'rejected' | 'unknown' | 'unchecked';

export interface ValidityResult {
  state: ValidityState;
  /** The host a request was sent to. Absent when nothing was sent. */
  host?: string;
  /** The HTTP status the host answered. Absent when it did not answer. */
  status?: number;
  /** One line for a human. Never holds the credential. */
  detail: string;
}

export interface ValidityProbe {
  /** Pattern ids from src/patterns.ts this probe covers. */
  readonly patterns: readonly string[];
  /** The provider, as help text names it. */
  readonly provider: string;
  /** The only host this probe sends to. */
  readonly host: string;
  /**
   * For a probe whose path carries `{url-path}`: hosts a found URL may name
   * beside `host`. The request still goes to `host`.
   */
  readonly urlHosts?: readonly string[];
  readonly method: 'GET' | 'POST';
  /**
   * Request path. A `{value}` marker is replaced by the URL-encoded
   * credential. A `{url-path}` marker is replaced by the part of a URL-shaped
   * credential's path after the text before the marker, which the found URL's
   * path must begin with; see `foundUrlPath` for the rest of the check.
   */
  readonly path: string;
  /** Request headers. A `{value}` marker is replaced by the credential. */
  readonly headers: Readonly<Record<string, string>>;
  /** A fixed request body, for a POST. Never carries the value. */
  readonly body?: string;
  /** A reason not to send this value, or null to send it. */
  readonly skip?: (value: string) => string | null;
  /**
   * The state for an answer the default rule does not cover (200 live, 401
   * rejected, anything else unknown). Return null for the default rule.
   */
  readonly decide?: (status: number, body: string) => { state: ValidityState; detail: string } | null;
}

/** Marker in a probe's path or header value where the credential goes. */
export const VALUE_MARKER = '{value}';

/**
 * Marker in a probe's path where the rest of a URL-shaped credential's path
 * goes: the part after the probe's prefix, once the URL passes `foundUrlPath`.
 */
export const URL_PATH_MARKER = '{url-path}';

const BEARER: Readonly<Record<string, string>> = { Authorization: `Bearer ${VALUE_MARKER}` };

const GITHUB_HEADERS: Readonly<Record<string, string>> = { ...BEARER, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };

/** The `error` values in a Slack `ok: false` answer this probe counts as a rejection. */
const SLACK_REJECTIONS = new Set(['invalid_auth', 'not_authed', 'token_revoked', 'token_expired', 'account_inactive']);

/**
 * The errors hooks.slack.com states, as a plain-text body, when it refuses the
 * webhook URL itself: the token, the service it names or its workspace is
 * gone, disabled or invalid.
 */
const SLACK_WEBHOOK_REJECTIONS = new Set(['invalid_token', 'no_service', 'no_service_id', 'no_active_hooks', 'no_team', 'team_disabled']);

/**
 * The errors hooks.slack.com states when it refuses the payload after taking
 * the URL: the message sent has no text, which is the message this probe
 * sends on purpose, so each of these means the webhook is live.
 */
const SLACK_WEBHOOK_PAYLOAD_REFUSALS = new Set(['no_text', 'invalid_payload', 'missing_text_or_fallback_or_attachments']);

/** The Discord error code for a webhook id it does not have. */
const DISCORD_UNKNOWN_WEBHOOK = 10015;

/** What `parseJson` returns for a body that is not JSON. */
const NOT_JSON: unique symbol = Symbol('not JSON');

function parseJson(body: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    return NOT_JSON;
  }
}

/**
 * The `error` a parsed body names. It is printed, so only an identifier is
 * accepted as one; anything else reads as no error named.
 */
function errorNamedIn(parsed: unknown): string {
  const error = (parsed as { error?: unknown } | null)?.error;
  return typeof error === 'string' && /^[a-z_]+$/.test(error) ? error : 'no error named';
}

/**
 * The error a plain-text body names, as hooks.slack.com states one. It is
 * printed, so only a short identifier is accepted; anything else reads as no
 * error named.
 */
function plainErrorIn(body: string): string {
  const text = body.trim();
  return /^[a-z_]{1,64}$/.test(text) ? text : 'no error named';
}

export const VALIDITY_PROBES: readonly ValidityProbe[] = [
  {
    patterns: ['github-pat', 'github-fine', 'github-oauth'],
    provider: 'GitHub',
    host: 'api.github.com',
    method: 'GET',
    path: '/user',
    headers: GITHUB_HEADERS,
  },
  {
    // An installation token identifies an app installation, not a user, so
    // it goes to the installation's own read-only endpoint.
    patterns: ['github-app'],
    provider: 'GitHub',
    host: 'api.github.com',
    method: 'GET',
    path: '/installation/repositories',
    headers: GITHUB_HEADERS,
  },
  {
    patterns: ['gitlab'],
    provider: 'GitLab',
    host: 'gitlab.com',
    method: 'GET',
    path: '/api/v4/user',
    headers: { 'PRIVATE-TOKEN': VALUE_MARKER },
  },
  {
    patterns: ['anthropic'],
    provider: 'Anthropic',
    host: 'api.anthropic.com',
    method: 'GET',
    path: '/v1/models',
    headers: { 'x-api-key': VALUE_MARKER, 'anthropic-version': '2023-06-01' },
  },
  {
    patterns: ['openai-proj', 'openai-legacy'],
    provider: 'OpenAI',
    host: 'api.openai.com',
    method: 'GET',
    path: '/v1/models',
    headers: BEARER,
  },
  {
    patterns: ['groq'],
    provider: 'Groq',
    host: 'api.groq.com',
    method: 'GET',
    path: '/openai/v1/models',
    headers: BEARER,
  },
  {
    patterns: ['openrouter'],
    provider: 'OpenRouter',
    host: 'openrouter.ai',
    method: 'GET',
    path: '/api/v1/auth/key',
    headers: BEARER,
  },
  {
    patterns: ['fireworks'],
    provider: 'Fireworks AI',
    host: 'api.fireworks.ai',
    method: 'GET',
    path: '/inference/v1/models',
    headers: BEARER,
  },
  {
    patterns: ['huggingface'],
    provider: 'Hugging Face',
    host: 'huggingface.co',
    method: 'GET',
    path: '/api/whoami-v2',
    headers: BEARER,
  },
  {
    patterns: ['replicate'],
    provider: 'Replicate',
    host: 'api.replicate.com',
    method: 'GET',
    path: '/v1/account',
    headers: BEARER,
  },
  {
    patterns: ['slack'],
    provider: 'Slack',
    host: 'slack.com',
    method: 'POST',
    path: '/api/auth.test',
    headers: BEARER,
    // An xoxr- value is a refresh token; sending it to auth.test would read
    // as rejected whatever its state, so it is not sent.
    skip: (value) => (value.startsWith('xoxr-') ? 'an xoxr- value is a refresh token, and this probe is for access tokens' : null),
    // auth.test answers 200 either way and states the verdict in the body.
    decide: (status, body) => {
      if (status !== 200) return null;
      const parsed = parseJson(body);
      if (parsed === NOT_JSON) return { state: 'unknown', detail: 'slack.com answered 200 with a body that is not JSON' };
      if ((parsed as { ok?: unknown } | null)?.ok === true) return { state: 'live', detail: 'slack.com answered ok: true' };
      const error = errorNamedIn(parsed);
      const state: ValidityState = SLACK_REJECTIONS.has(error) ? 'rejected' : 'unknown';
      return { state, detail: `slack.com answered ok: false (${error})` };
    },
  },
  {
    // A webhook URL is the credential, and hooks.slack.com has no read-only
    // endpoint for it: the one request it takes is a POST of a message. The
    // body sent is {}, a message with no text, blocks or attachments, which
    // Slack refuses as no_text; it checks the URL first (a URL it does not
    // know is answered 404 no_team), so that refusal means the webhook is
    // live, and nothing is posted either way.
    patterns: ['slack-webhook'],
    provider: 'Slack',
    host: 'hooks.slack.com',
    method: 'POST',
    path: `/services/${URL_PATH_MARKER}`,
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
    // Errors come as a plain-text body with a 400, 403 or 404; each of those
    // is decided on the error named, and every other status takes the default rule.
    decide: (status, body) => {
      if (status !== 400 && status !== 403 && status !== 404) return null;
      const error = plainErrorIn(body);
      if (status === 400 && SLACK_WEBHOOK_PAYLOAD_REFUSALS.has(error)) {
        return { state: 'live', detail: `hooks.slack.com took the webhook and refused the empty message (${error})` };
      }
      const state: ValidityState = SLACK_WEBHOOK_REJECTIONS.has(error) ? 'rejected' : 'unknown';
      return { state, detail: `hooks.slack.com answered ${status} (${error})` };
    },
  },
  {
    patterns: ['discord-bot'],
    provider: 'Discord',
    host: 'discord.com',
    method: 'GET',
    path: '/api/v10/users/@me',
    headers: { Authorization: `Bot ${VALUE_MARKER}` },
  },
  {
    // A webhook URL is the credential. A GET of it is the webhook's own
    // read-only endpoint (Get Webhook with Token), which answers 200 with
    // the webhook and posts nothing. The path goes to discord.com whether
    // the found URL named discord.com or discordapp.com.
    patterns: ['discord-webhook'],
    provider: 'Discord',
    host: 'discord.com',
    urlHosts: ['discordapp.com'],
    method: 'GET',
    path: `/api/webhooks/${URL_PATH_MARKER}`,
    headers: {},
    // A webhook Discord no longer has is a 404 whose JSON body carries code
    // 10015 (Unknown Webhook); a wrong token is a 401, which the default rule reads.
    decide: (status, body) => {
      if (status !== 404) return null;
      const parsed = parseJson(body);
      if (parsed === NOT_JSON) return { state: 'unknown', detail: 'discord.com answered 404 with a body that is not JSON' };
      const code = (parsed as { code?: unknown } | null)?.code;
      if (code === DISCORD_UNKNOWN_WEBHOOK) return { state: 'rejected', detail: `discord.com answered 404 (Unknown Webhook, code ${code})` };
      return { state: 'unknown', detail: `discord.com answered 404 (${Number.isInteger(code) ? `code ${code}` : 'no code named'})` };
    },
  },
  {
    patterns: ['telegram-bot'],
    provider: 'Telegram',
    host: 'api.telegram.org',
    method: 'GET',
    path: `/bot${VALUE_MARKER}/getMe`,
    headers: {},
  },
  {
    patterns: ['sendgrid'],
    provider: 'SendGrid',
    host: 'api.sendgrid.com',
    method: 'GET',
    path: '/v3/scopes',
    headers: BEARER,
  },
  {
    patterns: ['npm'],
    provider: 'npm',
    host: 'registry.npmjs.org',
    method: 'GET',
    path: '/-/whoami',
    headers: BEARER,
  },
  {
    patterns: ['digitalocean'],
    provider: 'DigitalOcean',
    host: 'api.digitalocean.com',
    method: 'GET',
    path: '/v2/account',
    headers: BEARER,
  },
  {
    patterns: ['heroku'],
    provider: 'Heroku',
    host: 'api.heroku.com',
    method: 'GET',
    path: '/account',
    headers: { ...BEARER, Accept: 'application/vnd.heroku+json; version=3' },
  },
  {
    patterns: ['netlify'],
    provider: 'Netlify',
    host: 'api.netlify.com',
    method: 'GET',
    path: '/api/v1/user',
    headers: BEARER,
  },
  {
    patterns: ['stripe', 'stripe-test', 'stripe-restricted'],
    provider: 'Stripe',
    host: 'api.stripe.com',
    method: 'GET',
    path: '/v1/balance',
    headers: BEARER,
  },
  {
    patterns: ['google-oauth'],
    provider: 'Google',
    host: 'oauth2.googleapis.com',
    method: 'GET',
    path: '/tokeninfo',
    headers: BEARER,
    // tokeninfo states a rejection as a 400 whose body names invalid_token,
    // so a 400 is decided on its body; every other status takes the default rule.
    decide: (status, body) => {
      if (status !== 400) return null;
      const parsed = parseJson(body);
      if (parsed === NOT_JSON) return { state: 'unknown', detail: 'oauth2.googleapis.com answered 400 with a body that is not JSON' };
      const error = errorNamedIn(parsed);
      const state: ValidityState = error === 'invalid_token' ? 'rejected' : 'unknown';
      return { state, detail: `oauth2.googleapis.com answered 400 (${error})` };
    },
  },
];

const PROBE_BY_PATTERN: ReadonlyMap<string, ValidityProbe> = (() => {
  const map = new Map<string, ValidityProbe>();
  for (const probe of VALIDITY_PROBES) {
    for (const id of probe.patterns) map.set(id, probe);
  }
  return map;
})();

/** The probe for a credential pattern id, or undefined when the type is not checked. */
export function probeFor(patternId: string): ValidityProbe | undefined {
  return PROBE_BY_PATTERN.get(patternId);
}

function patternNameOf(patternId: string): string {
  return CREDENTIAL_PATTERNS.find((p) => p.id === patternId)?.name ?? patternId;
}

export interface ProbeRequest {
  url: string;
  method: 'GET' | 'POST';
  headers: Record<string, string>;
  /** The probe's fixed body, when it has one. */
  body?: string;
}

/** The text before `{url-path}` in a probe's path, which a found URL's path must begin with; null for a probe without the marker. */
function urlPathPrefix(probe: ValidityProbe): string | null {
  const at = probe.path.indexOf(URL_PATH_MARKER);
  return at < 0 ? null : probe.path.slice(0, at);
}

/**
 * The part of a URL-shaped credential's path that replaces `{url-path}`, or
 * null when the value is not an https URL, without port or userinfo, on the
 * probe's `host` or one of its `urlHosts`, with a path that begins with the
 * probe's prefix and goes on past it. A value with no scheme is read as
 * https. Only the path is taken from the URL: a query or fragment is dropped.
 */
function foundUrlPath(probe: ValidityProbe, value: string): string | null {
  const prefix = urlPathPrefix(probe);
  if (prefix === null) return null;
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(value) ? value : `https://${value}`);
  } catch {
    return null;
  }
  const hosts = [probe.host, ...(probe.urlHosts ?? [])];
  if (url.protocol !== 'https:' || !hosts.includes(url.hostname) || url.port !== '' || url.username !== '' || url.password !== '') return null;
  if (!url.pathname.startsWith(prefix) || url.pathname.length === prefix.length) return null;
  return url.pathname.slice(prefix.length);
}

/** The reason a probe would not send a value, or null when it would. */
export function notSentReason(probe: ValidityProbe, value: string): string | null {
  const own = probe.skip?.(value) ?? null;
  if (own !== null) return own;
  const prefix = urlPathPrefix(probe);
  if (prefix !== null && foundUrlPath(probe, value) === null) {
    return `the found URL is not an https URL on ${[probe.host, ...(probe.urlHosts ?? [])].join(' or ')} under ${prefix}`;
  }
  return null;
}

/**
 * The request a probe sends for a value: the markers filled in, and nothing
 * else added but a User-Agent. Throws for a value `notSentReason` names a
 * reason for, so check that first.
 */
export function buildProbeRequest(probe: ValidityProbe, value: string): ProbeRequest {
  const headers: Record<string, string> = { 'User-Agent': `secretless-ai/${VERSION}` };
  for (const [name, template] of Object.entries(probe.headers)) {
    headers[name] = template.split(VALUE_MARKER).join(value);
  }
  let path = probe.path.split(VALUE_MARKER).join(encodeURIComponent(value));
  if (urlPathPrefix(probe) !== null) {
    const rest = foundUrlPath(probe, value);
    if (rest === null) throw new Error(`${probe.provider}: the value is not a URL this probe sends`);
    path = path.split(URL_PATH_MARKER).join(rest);
  }
  const request: ProbeRequest = { url: `https://${probe.host}${path}`, method: probe.method, headers };
  if (probe.body !== undefined) request.body = probe.body;
  return request;
}

/** What a probe needs from `fetch`: the status, and the body for a probe that reads one. */
export interface ProbeResponse {
  readonly status: number;
  text(): Promise<string>;
}

export interface ProbeFetchInit {
  method: 'GET' | 'POST';
  headers: Record<string, string>;
  /** The probe's fixed body; present only for a probe that has one. */
  body?: string;
  /** Always `manual`: a 3xx is an answer, never a second request. */
  redirect: 'manual';
  signal: AbortSignal;
}

export type ProbeFetch = (url: string, init: ProbeFetchInit) => Promise<ProbeResponse>;

export interface ProbeDeps {
  /** Defaults to the global `fetch`. Tests pass a stand-in. */
  fetchImpl?: ProbeFetch;
  /** The bound for one exchange, request and body read together. Default 10 seconds. */
  timeoutMs?: number;
  /** How many hosts are asked at once. Default 4. */
  concurrency?: number;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_CONCURRENCY = 4;

const defaultFetch: ProbeFetch = (url, init) => fetch(url, init);

function defaultState(status: number): ValidityState {
  if (status === 200) return 'live';
  if (status === 401) return 'rejected';
  return 'unknown';
}

/** A short identifier for a failed request: an error code or name, never its message. */
function errorCode(err: unknown): string {
  const e = err as { code?: unknown; name?: unknown; cause?: { code?: unknown } } | null;
  const candidates = [e?.code, e?.cause?.code, e?.name];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && /^[A-Za-z0-9_]+$/.test(candidate)) return candidate;
  }
  return 'error';
}

function formatDeadline(timeoutMs: number): string {
  return timeoutMs >= 1000 ? `${Math.round(timeoutMs / 1000)} s` : `${timeoutMs} ms`;
}

/** The result with every occurrence of the value, should one have reached a string, replaced. */
function withoutValue(value: string, result: ValidityResult): ValidityResult {
  if (value === '' || !result.detail.includes(value)) return result;
  return { ...result, detail: result.detail.split(value).join('[value]') };
}

/**
 * Ask the issuing host about one value. Resolves to a result in every case; a
 * failed or slow request is `unknown`, never a thrown error.
 */
export async function probeCredential(patternId: string, value: string, deps: ProbeDeps = {}): Promise<ValidityResult> {
  const probe = probeFor(patternId);
  if (!probe) return { state: 'unchecked', detail: `no validity probe for ${patternNameOf(patternId)}` };
  const reason = notSentReason(probe, value);
  if (reason !== null) return withoutValue(value, { state: 'unchecked', detail: `not sent: ${reason}` });

  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = deps.fetchImpl ?? defaultFetch;
  const request = buildProbeRequest(probe, value);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let status: number;
  let body = '';
  try {
    const response = await fetchImpl(request.url, {
      method: request.method,
      headers: request.headers,
      ...(request.body !== undefined ? { body: request.body } : {}),
      redirect: 'manual',
      signal: controller.signal,
    });
    status = response.status;
    // Only a probe that decides on the body reads one; the deadline covers the read.
    if (probe.decide) body = await response.text();
  } catch (err) {
    const detail = controller.signal.aborted
      ? `no answer from ${probe.host} within ${formatDeadline(timeoutMs)}`
      : `no answer from ${probe.host} (${errorCode(err)})`;
    return withoutValue(value, { state: 'unknown', host: probe.host, detail });
  } finally {
    clearTimeout(timer);
  }

  const decided = probe.decide?.(status, body) ?? null;
  const result: ValidityResult = decided
    ? { state: decided.state, host: probe.host, status, detail: decided.detail }
    : { state: defaultState(status), host: probe.host, status, detail: `${probe.host} answered ${status}` };
  return withoutValue(value, result);
}

/**
 * A result for every finding. A type without a probe, or a finding whose
 * value was not kept, is `unchecked` and sends nothing. The same value found
 * in several places is one credential: its host is asked once, and each
 * finding that carries it receives that answer.
 */
export async function checkFindings(
  findings: readonly ScanFinding[],
  valueOf: (finding: ScanFinding) => string | undefined,
  deps: ProbeDeps = {},
): Promise<Map<ScanFinding, ValidityResult>> {
  const results = new Map<ScanFinding, ValidityResult>();
  const pending = new Map<string, { patternId: string; value: string; findings: ScanFinding[] }>();
  for (const finding of findings) {
    if (!probeFor(finding.patternId)) {
      results.set(finding, { state: 'unchecked', detail: `no validity probe for ${finding.patternName}` });
      continue;
    }
    const value = valueOf(finding);
    if (value === undefined || value === '') {
      results.set(finding, { state: 'unchecked', detail: 'the matched value was not kept for checking' });
      continue;
    }
    const key = `${finding.patternId}\u0000${value}`;
    const entry = pending.get(key);
    if (entry) entry.findings.push(finding);
    else pending.set(key, { patternId: finding.patternId, value, findings: [finding] });
  }

  const queue = [...pending.values()];
  const workers = Math.max(1, Math.min(deps.concurrency ?? DEFAULT_CONCURRENCY, queue.length));
  await Promise.all(Array.from({ length: workers }, async () => {
    for (let job = queue.shift(); job !== undefined; job = queue.shift()) {
      const result = await probeCredential(job.patternId, job.value, deps);
      for (const finding of job.findings) results.set(finding, { ...result });
    }
  }));
  return results;
}

export interface ValiditySummary {
  live: number;
  rejected: number;
  unknown: number;
  unchecked: number;
  /** Every host a request was sent to, sorted. */
  hosts: string[];
}

export function summarizeValidity(results: Iterable<ValidityResult>): ValiditySummary {
  const summary: ValiditySummary = { live: 0, rejected: 0, unknown: 0, unchecked: 0, hosts: [] };
  const hosts = new Set<string>();
  for (const result of results) {
    summary[result.state] += 1;
    if (result.host) hosts.add(result.host);
  }
  summary.hosts = [...hosts].sort();
  return summary;
}

/** The word printed for a state. */
export function stateLabel(state: ValidityState): string {
  return state === 'unchecked' ? 'not checked' : state;
}

/**
 * The endpoint a probe contacts, host and path, with the place a value takes
 * in the path shown as <value> and the rest of a found URL's path as
 * <from the found URL>.
 */
export function probeEndpoint(probe: ValidityProbe): string {
  return `${probe.host}${probe.path.split(VALUE_MARKER).join('<value>').split(URL_PATH_MARKER).join('<from the found URL>')}`;
}

/** A paragraph of the `scan --help` notes, wrapped to their width. */
function helpParagraph(text: string): string[] {
  return wrapList(text.split(' '), '');
}

/**
 * The longest endpoint `scan --help` prints beside the types it is asked
 * about. A longer one takes a line of its own, with its types on the next
 * line under the column, so the column leaves the types room for their names.
 */
const HELP_ENDPOINT_COLUMN = 33;

/**
 * The lines `scan --help` prints after its options: what --check-validity
 * contacts, per credential type. Each stays inside the notes' width
 * (NOTE_WIDTH, an 80-column terminal with their indent): the types an
 * endpoint is asked about continue under their own column when they do not
 * fit beside it, and the wrap falls between two type names, never inside one.
 */
export function validityHelpLines(): string[] {
  const endpoints = VALIDITY_PROBES.map(probeEndpoint);
  const width = Math.min(Math.max(...endpoints.map((e) => e.length)), HELP_ENDPOINT_COLUMN) + 2;
  const indent = ' '.repeat(2 + width);
  const rows = VALIDITY_PROBES.flatMap((probe, p) => {
    const names = probe.patterns.map(patternNameOf);
    const items = names.map((name, i) =>
      `${i === 0 ? `${probe.provider}: ` : ''}${name}${i < names.length - 1 ? ',' : ''}`);
    const endpoint = endpoints[p];
    return endpoint.length > HELP_ENDPOINT_COLUMN
      ? [`  ${endpoint}`, ...wrapList(items, indent)]
      : wrapList(items, indent, ' ', `  ${endpoint.padEnd(width)}`);
  });
  return [
    ...helpParagraph('--check-validity sends each found credential, over HTTPS, to the host that issued it and to no other:'),
    ...rows,
    ...helpParagraph('Types not listed are reported as not checked, and nothing is sent for them. Without the flag, '
      + 'no credential is sent anywhere. live: the host answered 200. rejected: it answered 401 (Slack: '
      + 'ok: false in a 200; Google: invalid_token in a 400). unknown: any other answer, or none.'),
    ...helpParagraph('A webhook URL is itself the credential: the path of the found URL goes to the host above, and '
      + 'nothing else from it. Discord: a GET of the webhook, its read-only endpoint, sent to discord.com '
      + 'whether the URL named discord.com or discordapp.com; 404 Unknown Webhook reads rejected. Slack: a '
      + 'POST whose body is {}, a message with no text, which Slack refuses before posting anything; a '
      + '400 for that refusal (no_text) reads live, and invalid_token, no_service or no_team read rejected.'),
    ...helpParagraph('A token a self-managed GitHub or GitLab instance issued still goes to api.github.com or gitlab.com, '
      + "which did not issue it; read the answer as that host's. The answer does not change the exit code."),
  ];
}
