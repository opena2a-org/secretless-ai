/**
 * child-env.mjs — the environment release-artifact-review.mjs starts each child
 * with.
 *
 * The review job's environment carries GH_TOKEN for one reader: the advisory
 * fetch. A child started with `{ ...process.env }` receives it anyway, along
 * with every other variable the job holds. Each child instead gets what npm,
 * tar, node and the scanner need to run here — PATH, HOME, the temp
 * directory, the locale, npm's configuration, the proxy and CA variables, and
 * the scanner's telemetry opt-outs — and only the advisory fetch adds GH_TOKEN.
 */

const ALLOWED_NAMES = new Set([
  'PATH',
  'HOME',
  'TMPDIR',
  'TMP',
  'TEMP',
  // Outside a UTF-8 locale tar lists a non-ASCII entry name with octal
  // escapes, and the credential scan then finds no file of that name to copy.
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'NODE_EXTRA_CA_CERTS',
  'NODE_USE_ENV_PROXY',
  'OPENA2A_TELEMETRY',
  'OPENA2A_TELEMETRY_OPTOUT',
]);

// npm reads npm_config_* in any case, and proxies are honoured in upper and
// lower case alike.
const ALLOWED_PATTERN = /^(npm_config_.+|https?_proxy|no_proxy)$/i;

/** True when a variable of this name may reach a child. */
export function isAllowedChildVariable(name) {
  return ALLOWED_NAMES.has(name) || ALLOWED_PATTERN.test(name);
}

/** The allowlisted part of `env`, with `extra` added or overriding. */
export function childEnv(extra = {}, env = process.env) {
  const out = {};
  for (const [name, value] of Object.entries(env)) {
    if (value !== undefined && isAllowedChildVariable(name)) out[name] = value;
  }
  return { ...out, ...extra };
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
