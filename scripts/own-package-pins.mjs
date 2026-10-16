/**
 * own-package-pins.mjs: the dependency declarations in a package.json that
 * put a non-exact specifier on an own package.
 *
 * An own package is one the OpenA2A maintainers can publish: a name under
 * @opena2a/ or @nanomind/, or a name whose npm maintainers share a member
 * with REFERENCE_PACKAGE's. Own-ness is read from the registry, not from a
 * roster of names, so a name the project starts publishing is covered without
 * an edit here. Only a non-exact specifier is classified; an exact version is
 * accepted with no registry read.
 *
 * A name the registry answers E404 for is reported as `pin not served`, never
 * as not own. Maintainer names are compared here and returned nowhere: the
 * result carries dependency labels and counts only.
 */

export const OWN_SCOPES = ['@opena2a/', '@nanomind/'];

/** The package whose npm maintainers define who can publish an own package. */
export const REFERENCE_PACKAGE = 'hackmyagent';

/**
 * MAJOR.MINOR.PATCH with an optional prerelease suffix, then an optional build
 * suffix (semver 2.0.0 allows both, in that order), and nothing else.
 */
export const EXACT_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;

export const DEPENDENCY_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

// A name npm accepts for a package that already exists: only characters
// encodeURIComponent leaves as they are, no leading period, hyphen or
// underscore, and a scoped name's package part with no leading period.
// Capitals and ~'!()* are refused for new packages only, and the registry
// still serves older names that carry them (JSONStream). Anything else (a
// leading hyphen among it) is never passed to `npm view` as an argument.
const NPM_PACKAGE_NAME =/^(?:@[\w.~!'()*-]+\/(?!\.)[\w.~!'()*-]+|(?![._-])[\w.~!'()*-]+)$/;

/** True for a name under one of OWN_SCOPES. */
export function isOwnScope(name) {
  return OWN_SCOPES.some((prefix) => name.startsWith(prefix));
}

/**
 * The package a declaration installs and the specifier it installs it at: an
 * `npm:<name>@<range>` alias installs <name>, any other specifier installs
 * the declared name. An alias with no range installs `latest`.
 */
export function declaredTarget(name, spec) {
  const alias = /^npm:((?:@[^/@]+\/)?[^@]+)(?:@(.*))?$/.exec(spec);
  if (alias === null) return { name, range: spec };
  return { name: alias[1], range: alias[2] ?? '' };
}

/** The npm user names in `npm view <name> maintainers --json` output. */
function usersOf(parsed) {
  const entries = Array.isArray(parsed) ? parsed : [parsed];
  const users = new Set();
  for (const entry of entries) {
    const text = typeof entry === 'string' ? entry : typeof entry?.name === 'string' ? entry.name : '';
    const user = /^[^\s<]+/.exec(text.trim());
    if (user !== null) users.add(user[0]);
  }
  return users;
}

function errorCodeOf(result) {
  try {
    const code = JSON.parse(result.stdout ?? '')?.error?.code;
    if (typeof code === 'string') return code;
  } catch {
    // Not JSON: read npm's stderr instead.
  }
  return /npm (?:error|ERR!) code (\S+)/.exec(result.stderr ?? '')?.[1] ?? null;
}

/**
 * A maintainers reader over `runNpm(args)`, which returns spawnSync's result.
 * The reader answers `{ kind: 'served', users }`, `{ kind: 'not-served' }`
 * for E404, or `{ kind: 'unreadable', detail }`; a detail names the exit
 * status and npm's error code, never npm's output.
 */
export function npmMaintainersReader(runNpm) {
  return (name) => {
    const result = runNpm(['view', name, 'maintainers', '--json']);
    if (result.status === 0) {
      const stdout = (result.stdout ?? '').trim();
      if (stdout === '') return { kind: 'served', users: new Set() };
      try {
        return { kind: 'served', users: usersOf(JSON.parse(stdout)) };
      } catch {
        return { kind: 'unreadable', detail: 'npm view printed no JSON' };
      }
    }
    const code = errorCodeOf(result);
    if (code === 'E404') return { kind: 'not-served' };
    const how =
      result.status === null
        ? `npm view did not exit (${result.error?.code ?? result.signal ?? 'no status'})`
        : `npm view exited ${result.status}`;
    return { kind: 'unreadable', detail: code === null ? how : `${how}, ${code}` };
  };
}

/**
 * Every non-exact specifier on an own package in `pkg`, read through
 * `maintainersOf` (see npmMaintainersReader). Returns `loose` (own package,
 * non-exact specifier), `unserved` (the registry does not know the name),
 * `unread` (no answer, so not classified) and `classified` (how many
 * declarations were read from the registry). Each entry is
 * `<section>.<name>=<specifier>`, with a reason in parentheses where one applies.
 */
export function ownPackagePins(pkg, maintainersOf) {
  const loose = [];
  const unserved = [];
  const unread = [];
  let classified = 0;
  const reads = new Map();
  const read = (name) => {
    if (!reads.has(name)) reads.set(name, maintainersOf(name));
    return reads.get(name);
  };

  for (const section of DEPENDENCY_SECTIONS) {
    for (const [name, spec] of Object.entries(pkg?.[section] ?? {})) {
      const text = String(spec);
      const target = declaredTarget(name, text);
      if (EXACT_VERSION.test(target.range)) continue;
      const label = `${section}.${name}=${text}`;
      if (isOwnScope(name) || isOwnScope(target.name)) {
        loose.push(label);
        continue;
      }
      if (!NPM_PACKAGE_NAME.test(target.name)) {
        unserved.push(`${label} (not an npm package name)`);
        continue;
      }
      classified += 1;
      const answer = read(target.name);
      if (answer.kind === 'not-served') {
        unserved.push(label);
        continue;
      }
      if (answer.kind !== 'served') {
        unread.push(`${label} (${answer.detail})`);
        continue;
      }
      const reference = read(REFERENCE_PACKAGE);
      if (reference.kind !== 'served' || reference.users.size === 0) {
        const why =
          reference.kind === 'served'
            ? 'no maintainers listed'
            : reference.kind === 'not-served'
              ? 'not served'
              : reference.detail;
        unread.push(`${label} (${REFERENCE_PACKAGE} maintainers unread: ${why})`);
        continue;
      }
      if ([...answer.users].some((user) => reference.users.has(user))) loose.push(label);
    }
  }
  return { loose, unserved, unread, classified };
}
