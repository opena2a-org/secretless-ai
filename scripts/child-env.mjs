/**
 * child-env.mjs — the environment release-artifact-review.mjs starts each child
 * with.
 *
 * The review job's environment carries GH_TOKEN for one reader: the advisory
 * fetch. A child started with `{ ...process.env }` receives it anyway, along
 * with every other variable the job holds. Each child instead gets what tar,
 * node and the scanner need to run here — PATH, HOME, the temp directory, the
 * locale, the configuration directory, the proxy and CA variables, and the
 * scanner's telemetry opt-outs. Only npm's own children add npm's
 * configuration, and only the advisory fetch adds GH_TOKEN.
 */

const ALLOWED_NAMES = new Set([
  'PATH',
  'HOME',
  'TMPDIR',
  'TMP',
  'TEMP',
  // Outside a UTF-8 locale tar lists a non-ASCII entry name with octal
  // escapes.
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  // The scanner's telemetry reads its saved opt-out from
  // $XDG_CONFIG_HOME/opena2a/telemetry.json when this is set.
  'XDG_CONFIG_HOME',
  'NODE_EXTRA_CA_CERTS',
  'NODE_USE_ENV_PROXY',
  'OPENA2A_TELEMETRY',
  'OPENA2A_TELEMETRY_OPTOUT',
]);

// Proxies are honoured in upper and lower case alike.
const PROXY_PATTERN = /^(https?_proxy|no_proxy)$/i;

// npm reads npm_config_* in any case. These can carry a registry token, so
// they reach npm and no other child.
const NPM_CONFIG_PATTERN = /^npm_config_.+$/i;

/** True when a variable of this name may reach any child. */
export function isAllowedChildVariable(name) {
  return ALLOWED_NAMES.has(name) || PROXY_PATTERN.test(name);
}

function pick(env, allowed) {
  const out = {};
  for (const [name, value] of Object.entries(env)) {
    if (value !== undefined && allowed(name)) out[name] = value;
  }
  return out;
}

/** The allowlisted part of `env`, with `extra` added or overriding. */
export function childEnv(extra = {}, env = process.env) {
  return { ...pick(env, isAllowedChildVariable), ...extra };
}

/** An npm child's environment: the allowlist plus npm's configuration. */
export function npmChildEnv(extra = {}, env = process.env) {
  return {
    ...pick(env, (name) => isAllowedChildVariable(name) || NPM_CONFIG_PATTERN.test(name)),
    ...extra,
  };
}

/**
 * The advisory fetch's environment: the allowlist, GH_TOKEN when the job has
 * one, NODE_USE_ENV_PROXY so fetch honours HTTPS_PROXY, and the URL to read.
 */
export function fetchChildEnv(url, env = process.env) {
  return childEnv(
    {
      ...(env.GH_TOKEN === undefined ? {} : { GH_TOKEN: env.GH_TOKEN }),
      NODE_USE_ENV_PROXY: '1',
      REVIEW_GET_URL: url,
    },
    env,
  );
}

// GET REVIEW_GET_URL, sending GH_TOKEN as a bearer token when it is set, and
// print `{ status, text }`.
const FETCH_PROGRAM = [
  'const headers = { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "release-artifact-review" };',
  'if (process.env.GH_TOKEN) headers.authorization = `Bearer ${process.env.GH_TOKEN}`;',
  'const res = await fetch(process.env.REVIEW_GET_URL, { headers });',
  'const text = await res.text();',
  'console.log(JSON.stringify({ status: res.status, text }));',
].join('\n');

/** The advisory fetch child for `url`: the program to run and its environment. */
export function fetchChild(url, env = process.env) {
  return {
    command: process.execPath,
    args: ['--input-type=module', '-e', FETCH_PROGRAM],
    env: fetchChildEnv(url, env),
  };
}
