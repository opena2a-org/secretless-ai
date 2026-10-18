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
 * or no_team, STS in a 403 naming InvalidClientTokenId or
 * SignatureDoesNotMatch). `unknown`: any other status, no connection, or no
 * answer in time, with the status or reason named; an STS refusal of the
 * request time is one. `unchecked`: no probe for the type, or a value the
 * probe does not send, and nothing was sent. A result describes the host's
 * answer to the request this module sends, not the credential's history: a
 * token a self-managed GitHub or GitLab instance issued still goes to
 * api.github.com or gitlab.com, which did not issue it, and a key from the
 * AWS China or GovCloud partition still goes to sts.amazonaws.com. No result
 * string holds the value, including one built from an error message. The
 * states are reported beside a finding and change neither its severity, its
 * confidence nor the exit code.
 *
 * An AWS key is two values: the access key ID and the secret access key from
 * one file are checked as a pair (`awsPairs`), by an STS request signed with
 * the secret (`signing`). The request names the key ID in its signature and
 * holds no part of the secret.
 */
import { CREDENTIAL_PATTERNS } from './patterns';
import { VERSION, wrapList } from './commands/utils';
import { signSigV4 } from './aws-sigv4';
import { matchedValueOf, charAfterValueOf, type ScanFinding } from './scan';

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
  /**
   * A reason not to send this value, or null to send it. `charAfter` is the
   * character after the value where the scanner found it, '' at the end of
   * its line; undefined when that is not known.
   */
  readonly skip?: (value: string, charAfter?: string) => string | null;
  /**
   * The state for an answer the default rule does not cover (200 live, 401
   * rejected, anything else unknown). Return null for the default rule.
   */
  readonly decide?: (status: number, body: string) => { state: ValidityState; detail: string } | null;
  /**
   * For a probe whose request is signed instead of carrying the credential:
   * AWS Signature Version 4 for this region and service. The value of
   * `keyIdPattern` is named in the signature; the value of `secretPattern`
   * keys it and goes in no part of the request. The two are taken from one
   * file (`awsPairs`), so a probe with `signing` never sends one value alone.
   */
  readonly signing?: {
    readonly region: string;
    readonly service: string;
    readonly keyIdPattern: string;
    readonly secretPattern: string;
  };
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

/** Linear's GraphQL takes a read-only viewer query; it carries no credential. */
const LINEAR_VIEWER_QUERY = JSON.stringify({ query: '{ viewer { id } }' });

/**
 * The shortest OpenAI project key the published scanner rules describe:
 * sk-proj-, then 58 or 74 characters, T3BlbkFJ, and 58 or 74 more, from an
 * alphabet that holds - and _ (gitleaks' openai-api-key rule; TruffleHog's
 * OpenAI detector names the same alphabet without a length). OpenAI
 * publishes no format. The openai-proj pattern stops at - or _, so a value
 * shorter than this may be only the part of a key before one of them, which
 * api.openai.com would refuse whatever the key's state; it is not sent. A
 * value of this length or more can be such a part too, of a key of 148 or
 * 164 characters whose first - or _ comes later: the scanner keeps the
 * character after the value, and a value found with a - or _ after it is not
 * sent either.
 */
const OPENAI_PROJECT_KEY_MIN_LENGTH = 132;

/** STS GetCallerIdentity as a form body. It carries no value. */
const STS_GET_CALLER_IDENTITY = 'Action=GetCallerIdentity&Version=2011-06-15';

/**
 * The errors STS names in a 403 for a pair it does not take: a key ID it does
 * not have, or a signature the found secret did not make for that key ID.
 */
const STS_REJECTIONS = new Set(['InvalidClientTokenId', 'SignatureDoesNotMatch']);

/**
 * How the message beside a SignatureDoesNotMatch begins when STS refuses the
 * request time, more than 15 minutes from its own, before it looks at the
 * key: a made-up key ID sent with a clock an hour off was answered this way,
 * not with InvalidClientTokenId. The answer is about this machine's clock.
 */
const STS_CLOCK_MESSAGES = ['Signature expired', 'Signature not yet current'];

/** The text of the first `name` element in an XML body, or null when it has none. */
function xmlText(body: string, name: string): string | null {
  const match = new RegExp(`<${name}>([^<]*)</${name}>`).exec(body);
  return match ? match[1] : null;
}

/**
 * How the AWS probe signs: Signature Version 4 for STS in us-east-1, the
 * region sts.amazonaws.com takes signatures for, with the AWS Access Key
 * finding as the key ID and the AWS Secret Access Key finding as the secret.
 */
const AWS_SIGNING = { region: 'us-east-1', service: 'sts', keyIdPattern: 'aws-access', secretPattern: 'aws-secret' } as const;

/**
 * An AWS key is two values found together: the access key ID, which the
 * request names, and the secret access key, which signs the request and goes
 * in no part of it (src/aws-sigv4.ts). GetCallerIdentity is read-only, and
 * AWS documents it as needing no permission and as answering even when a
 * policy attached to the caller denies it, so the answer is about the pair,
 * not its permissions. A 403 is decided on the error its XML body names;
 * every other status takes the default rule.
 */
const AWS_PROBE: ValidityProbe = {
  patterns: [AWS_SIGNING.keyIdPattern, AWS_SIGNING.secretPattern],
  provider: 'AWS',
  host: 'sts.amazonaws.com',
  method: 'POST',
  path: '/',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
  body: STS_GET_CALLER_IDENTITY,
  signing: AWS_SIGNING,
  decide: (status, body) => {
    if (status !== 403) return null;
    const code = xmlText(body, 'Code');
    const error = code !== null && /^[A-Za-z]{1,64}$/.test(code) ? code : 'no error named';
    const message = xmlText(body, 'Message') ?? '';
    const clock = error === 'SignatureDoesNotMatch' ? STS_CLOCK_MESSAGES.find((m) => message.startsWith(m)) : undefined;
    if (clock !== undefined) {
      return { state: 'unknown', detail: `sts.amazonaws.com answered 403 (SignatureDoesNotMatch: ${clock}); check this machine's clock` };
    }
    const state: ValidityState = STS_REJECTIONS.has(error) ? 'rejected' : 'unknown';
    return { state, detail: `sts.amazonaws.com answered 403 (${error})` };
  },
};

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
    // A project key can hold - or _, where its pattern stops. A value found
    // with one of them after it may be the part of a key before it, also at
    // 132 characters or more, as may a value too short to be a whole key;
    // neither is sent.
    skip: (value, charAfter) => {
      if (!value.startsWith('sk-proj-')) return null;
      if (charAfter === '-' || charAfter === '_') {
        return `the pattern stopped at a ${charAfter}, which an OpenAI project key can hold, so the value may be only the part of a key before it`;
      }
      return value.length < OPENAI_PROJECT_KEY_MIN_LENGTH
        ? `a value shorter than ${OPENAI_PROJECT_KEY_MIN_LENGTH} characters may be only the part of an OpenAI project key before a - or _, where the pattern stops`
        : null;
    },
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
  AWS_PROBE,
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
  {
    // Linear's GraphQL takes the key in the Authorization header with no
    // scheme (not Bearer). A viewer query is read-only; it answers 200 for a
    // key it accepts and 401 for one it rejects, so the default rule reads it,
    // and the fixed query body carries no value.
    patterns: ['linear'],
    provider: 'Linear',
    host: 'api.linear.app',
    method: 'POST',
    path: '/graphql',
    headers: { Authorization: VALUE_MARKER, 'Content-Type': 'application/json' },
    body: LINEAR_VIEWER_QUERY,
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

/**
 * The reason a probe would not send a value, or null when it would.
 * `charAfter` is the character after the value where it was found, when that
 * is known (`ValidityProbe.skip`).
 */
export function notSentReason(probe: ValidityProbe, value: string, charAfter?: string): string | null {
  const own = probe.skip?.(value, charAfter) ?? null;
  if (own !== null) return own;
  const prefix = urlPathPrefix(probe);
  if (prefix !== null && foundUrlPath(probe, value) === null) {
    return `the found URL is not an https URL on ${[probe.host, ...(probe.urlHosts ?? [])].join(' or ')} under ${prefix}`;
  }
  return null;
}

/** What a probe with `signing` signs its request with: the secret found with the key ID, and the time it is signed at. */
export interface SigningInput {
  secret: string;
  now: Date;
}

/**
 * The request a probe sends for a value: the markers filled in, and nothing
 * else added but a User-Agent and, for a probe with `signing`, the headers of
 * a signature made with `signWith.secret`, in which `value` is the key ID.
 * Throws for a value `notSentReason` names a reason for, so check that first,
 * and for a probe with `signing` given nothing to sign with.
 */
export function buildProbeRequest(probe: ValidityProbe, value: string, signWith?: SigningInput): ProbeRequest {
  const own: Record<string, string> = {};
  for (const [name, template] of Object.entries(probe.headers)) {
    own[name] = template.split(VALUE_MARKER).join(value);
  }
  let path = probe.path.split(VALUE_MARKER).join(encodeURIComponent(value));
  if (urlPathPrefix(probe) !== null) {
    const rest = foundUrlPath(probe, value);
    if (rest === null) throw new Error(`${probe.provider}: the value is not a URL this probe sends`);
    path = path.split(URL_PATH_MARKER).join(rest);
  }
  const headers: Record<string, string> = { 'User-Agent': `secretless-ai/${VERSION}`, ...own };
  if (probe.signing) {
    if (!signWith) throw new Error(`${probe.provider}: a signed probe needs the secret to sign with`);
    const { region, service } = probe.signing;
    Object.assign(headers, signSigV4(
      { method: probe.method, host: probe.host, path, headers: own, body: probe.body ?? '', region, service },
      { accessKeyId: value, secretAccessKey: signWith.secret },
      signWith.now,
    ));
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
  /**
   * The bound for one exchange, request and body read together. When it
   * passes before the exchange ends, the signal handed to `fetchImpl` aborts
   * and the result is `unknown`, whether or not `fetchImpl` honours that
   * signal. Default 10 seconds.
   */
  timeoutMs?: number;
  /** How many hosts are asked at once. Default 4. */
  concurrency?: number;
  /** The clock a signed request is dated by. Defaults to the system clock. Tests pass a fixed one. */
  now?: () => Date;
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

/** The result with every occurrence of each value, should one have reached a string, replaced. */
function withoutValues(values: readonly string[], result: ValidityResult): ValidityResult {
  let detail = result.detail;
  for (const value of values) {
    if (value !== '' && detail.includes(value)) detail = detail.split(value).join('[value]');
  }
  return detail === result.detail ? result : { ...result, detail };
}

/** Why `probeCredential` does not send a value a probe with `signing` covers. */
const PAIR_ONLY = 'an AWS key is checked as a pair, the access key ID with its secret access key, by probeAwsKeyPair';

/**
 * Ask the issuing host about one value. Resolves to a result in every case; a
 * failed or slow request is `unknown`, never a thrown error. A value a probe
 * with `signing` covers is half of a pair and is not sent alone. Only the
 * value is given here, so a probe's `skip` is not told the character after
 * it; `checkFindings` tells it that for a value the scanner kept.
 */
export async function probeCredential(patternId: string, value: string, deps: ProbeDeps = {}): Promise<ValidityResult> {
  const probe = probeFor(patternId);
  if (!probe) return { state: 'unchecked', detail: `no validity probe for ${patternNameOf(patternId)}` };
  if (probe.signing) return { state: 'unchecked', detail: `not sent: ${PAIR_ONLY}` };
  const reason = notSentReason(probe, value);
  if (reason !== null) return withoutValues([value], { state: 'unchecked', detail: `not sent: ${reason}` });
  return exchange(probe, buildProbeRequest(probe, value), [value], deps);
}

/**
 * Ask AWS about an access key ID and the secret access key found with it:
 * STS GetCallerIdentity, signed with the secret, which goes in no part of the
 * request. Resolves to a result in every case, as `probeCredential` does, and
 * no result string holds either value.
 */
export async function probeAwsKeyPair(accessKeyId: string, secretAccessKey: string, deps: ProbeDeps = {}): Promise<ValidityResult> {
  const now = deps.now?.() ?? new Date();
  const request = buildProbeRequest(AWS_PROBE, accessKeyId, { secret: secretAccessKey, now });
  return exchange(AWS_PROBE, request, [accessKeyId, secretAccessKey], deps);
}

/**
 * Send one built request under the deadline and read the answer as the probe
 * decides it. `hidden` holds the values no result string may carry.
 */
async function exchange(probe: ValidityProbe, request: ProbeRequest, hidden: readonly string[], deps: ProbeDeps): Promise<ValidityResult> {
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = deps.fetchImpl ?? defaultFetch;
  const controller = new AbortController();
  // The fetch is handed the signal, and the exchange is also raced against
  // its abort, so the deadline holds for a fetch that ignores the signal: an
  // answer that comes later is not taken as the verdict.
  const deadline = new Promise<never>((_resolve, reject) => {
    controller.signal.addEventListener('abort', () => reject(controller.signal.reason));
  });
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const exchange = async (): Promise<{ status: number; body: string }> => {
    const response = await fetchImpl(request.url, {
      method: request.method,
      headers: request.headers,
      ...(request.body !== undefined ? { body: request.body } : {}),
      redirect: 'manual',
      signal: controller.signal,
    });
    const status = response.status;
    // Only a probe that decides on the body reads one; the deadline covers the read.
    return { status, body: probe.decide ? await response.text() : '' };
  };
  let status: number;
  let body: string;
  try {
    ({ status, body } = await Promise.race([exchange(), deadline]));
  } catch (err) {
    const detail = controller.signal.aborted
      ? `no answer from ${probe.host} within ${formatDeadline(timeoutMs)}`
      : `no answer from ${probe.host} (${errorCode(err)})`;
    return withoutValues(hidden, { state: 'unknown', host: probe.host, detail });
  } finally {
    clearTimeout(timer);
  }

  const decided = probe.decide?.(status, body) ?? null;
  const result: ValidityResult = decided
    ? { state: decided.state, host: probe.host, status, detail: decided.detail }
    : { state: defaultState(status), host: probe.host, status, detail: `${probe.host} answered ${status}` };
  return withoutValues(hidden, result);
}

/**
 * The pattern ids of the AWS access key IDs the scanner matches. A temporary
 * key (aws-sts) has no probe, since STS takes it only with the session token
 * issued with it, which no built-in pattern matches; it still counts as a key
 * ID when a file is paired, so a secret beside it is paired with no other.
 */
const AWS_KEY_ID_PATTERNS: ReadonlySet<string> = new Set([AWS_SIGNING.keyIdPattern, 'aws-sts']);

/** An AWS access key ID and the secret access key paired with it. */
interface KeyPair {
  keyId: string;
  secret: string;
}

function counted(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * The pair each AWS finding is checked as, or the reason it is not sent. A
 * file is paired when its findings hold one access key ID and one secret
 * access key (one value on several lines counts once), and each finding of
 * either value in that file is checked as that pair. A key ID paired with
 * different secrets in different files is sent with none of them, as is a
 * secret paired with different key IDs, so AWS is never asked about one key
 * ID with two secrets, or one secret with two key IDs, in a scan. A pair
 * whose key ID and secret are both so paired is given the key ID's reason.
 */
function awsPairs(findings: readonly ScanFinding[], valueOf: (finding: ScanFinding) => string | undefined): Map<ScanFinding, KeyPair | string> {
  const { keyIdPattern, secretPattern } = AWS_SIGNING;
  const files = new Map<string, { keyIds: Map<string, string>; secrets: Set<string>; findings: ScanFinding[] }>();
  for (const finding of findings) {
    const isKeyId = AWS_KEY_ID_PATTERNS.has(finding.patternId);
    if (!isKeyId && finding.patternId !== secretPattern) continue;
    const value = valueOf(finding);
    if (value === undefined || value === '') continue;
    const file = files.get(finding.file) ?? { keyIds: new Map<string, string>(), secrets: new Set<string>(), findings: [] };
    files.set(finding.file, file);
    if (isKeyId) file.keyIds.set(value, finding.patternId);
    else file.secrets.add(value);
    file.findings.push(finding);
  }

  const outcomes = new Map<ScanFinding, KeyPair | string>();
  const secretsOfKeyId = new Map<string, Set<string>>();
  const keyIdsOfSecret = new Map<string, Set<string>>();
  for (const { keyIds, secrets, findings: inFile } of files.values()) {
    // [value, pattern id] of the file's one key ID, and its one secret.
    const onlyKeyId = keyIds.size === 1 ? [...keyIds][0] : undefined;
    const onlySecret = secrets.size === 1 ? [...secrets][0] : undefined;
    for (const finding of inFile) {
      const isSecret = finding.patternId === secretPattern;
      let outcome: KeyPair | string;
      if (isSecret && keyIds.size === 0) outcome = `the file has no ${patternNameOf(keyIdPattern)} finding to pair it with`;
      else if (!isSecret && secrets.size === 0) outcome = `the file has no ${patternNameOf(secretPattern)} finding to sign the request with`;
      else if (onlyKeyId === undefined || onlySecret === undefined) {
        outcome = `the file's findings hold ${counted(keyIds.size, 'AWS access key ID', 'AWS access key IDs')} and `
          + `${counted(secrets.size, 'secret access key', 'secret access keys')}, and a pair is formed only from one of each`;
      } else if (onlyKeyId[1] !== keyIdPattern) {
        outcome = `the file's access key ID is an ${patternNameOf(onlyKeyId[1])}, which STS takes only with its session token`;
      } else {
        outcome = { keyId: onlyKeyId[0], secret: onlySecret };
        secretsOfKeyId.set(onlyKeyId[0], (secretsOfKeyId.get(onlyKeyId[0]) ?? new Set<string>()).add(onlySecret));
        keyIdsOfSecret.set(onlySecret, (keyIdsOfSecret.get(onlySecret) ?? new Set<string>()).add(onlyKeyId[0]));
      }
      outcomes.set(finding, outcome);
    }
  }
  for (const [finding, outcome] of outcomes) {
    if (typeof outcome === 'string') continue;
    const secretCount = secretsOfKeyId.get(outcome.keyId)?.size ?? 1;
    const keyIdCount = keyIdsOfSecret.get(outcome.secret)?.size ?? 1;
    if (secretCount > 1) {
      outcomes.set(finding, `the access key ID is paired with ${secretCount} different secret access keys in the scanned files, and is sent with none of them`);
    } else if (keyIdCount > 1) {
      outcomes.set(finding, `the secret access key is paired with ${keyIdCount} different access key IDs in the scanned files, and is sent with none of them`);
    }
  }
  return outcomes;
}

/**
 * The character the scanner found after a finding's value, when `value` is
 * the one it kept for the finding (`retainValues` in scan.ts); undefined when
 * `value` differs from it, as a value a caller's `valueOf` supplies can.
 */
function charAfterFound(finding: ScanFinding, value: string): string | undefined {
  return matchedValueOf(finding) === value ? charAfterValueOf(finding) : undefined;
}

/**
 * A result for every finding. A type without a probe, or a finding whose
 * value was not kept, is `unchecked` and sends nothing, as is a value its
 * probe does not send, told the character the scanner found after it. That
 * is decided for each finding, since the character after one value can
 * differ from place to place. The same value found in several places and
 * sent is one credential: its host is asked once, and each finding that
 * carries it receives that answer. An AWS access key ID and secret access
 * key are one credential when `awsPairs` pairs them, and each finding of
 * either is given the pair's answer.
 */
export async function checkFindings(
  findings: readonly ScanFinding[],
  valueOf: (finding: ScanFinding) => string | undefined,
  deps: ProbeDeps = {},
): Promise<Map<ScanFinding, ValidityResult>> {
  const results = new Map<ScanFinding, ValidityResult>();
  const pending = new Map<string, { run: () => Promise<ValidityResult>; findings: ScanFinding[] }>();
  const pairs = awsPairs(findings, valueOf);
  for (const finding of findings) {
    const probe = probeFor(finding.patternId);
    if (!probe) {
      results.set(finding, { state: 'unchecked', detail: `no validity probe for ${finding.patternName}` });
      continue;
    }
    const value = valueOf(finding);
    if (value === undefined || value === '') {
      results.set(finding, { state: 'unchecked', detail: 'the matched value was not kept for checking' });
      continue;
    }
    let key: string;
    let run: () => Promise<ValidityResult>;
    if (probe.signing) {
      const pair = pairs.get(finding) ?? 'it was not paired';
      if (typeof pair === 'string') {
        results.set(finding, { state: 'unchecked', detail: `not sent: ${pair}` });
        continue;
      }
      // Pattern ids hold no NUL, so a pair's key never meets a single value's.
      key = `\u0000${pair.keyId}\u0000${pair.secret}`;
      run = () => probeAwsKeyPair(pair.keyId, pair.secret, deps);
    } else {
      const reason = notSentReason(probe, value, charAfterFound(finding, value));
      if (reason !== null) {
        results.set(finding, withoutValues([value], { state: 'unchecked', detail: `not sent: ${reason}` }));
        continue;
      }
      key = `${finding.patternId}\u0000${value}`;
      run = () => probeCredential(finding.patternId, value, deps);
    }
    const entry = pending.get(key);
    if (entry) entry.findings.push(finding);
    else pending.set(key, { run, findings: [finding] });
  }

  const queue = [...pending.values()];
  const workers = Math.max(1, Math.min(deps.concurrency ?? DEFAULT_CONCURRENCY, queue.length));
  await Promise.all(Array.from({ length: workers }, async () => {
    for (let job = queue.shift(); job !== undefined; job = queue.shift()) {
      const result = await job.run();
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
      + 'ok: false in a 200; Google: invalid_token in a 400; AWS: InvalidClientTokenId or '
      + 'SignatureDoesNotMatch in a 403). unknown: any other answer, or none.'),
    ...helpParagraph('A webhook URL is itself the credential: the path of the found URL goes to the host above, and '
      + 'nothing else from it. Discord: a GET of the webhook, its read-only endpoint, sent to discord.com '
      + 'whether the URL named discord.com or discordapp.com; 404 Unknown Webhook reads rejected. Slack: a '
      + 'POST whose body is {}, a message with no text, which Slack refuses before posting anything; a '
      + '400 for that refusal (no_text) reads live, and invalid_token, no_service or no_team read rejected.'),
    ...helpParagraph('An AWS key is checked as a pair: the access key ID and the secret access key found with it '
      + 'in one file, when the file holds exactly one of each. The request, GetCallerIdentity, is signed with '
      + 'the secret (Signature Version 4): the key ID and the signature are sent, and the secret is not. A '
      + 'SignatureDoesNotMatch that names the request time reads unknown; check the clock.'),
    ...helpParagraph('A token a self-managed GitHub or GitLab instance issued still goes to api.github.com or gitlab.com, '
      + 'which did not issue it, and a key from the AWS China or GovCloud partition still goes to '
      + "sts.amazonaws.com, whose partition did not issue it; read the answer as that host's. The answer "
      + 'does not change the exit code.'),
  ];
}
