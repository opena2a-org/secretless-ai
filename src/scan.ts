/**
 * Scan project files for hardcoded credentials.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CREDENTIAL_PATTERNS, CONFIG_FILES, CREDENTIAL_PREFIX_QUICK_CHECK, SOURCE_FILE_EXTENSIONS, SOURCE_SKIP_DIRS, KNOWN_EXAMPLE_KEYS, PLACEHOLDER_INDICATORS, isConfigShaped, type CredentialPattern } from './patterns';
import { redactMatches } from './redact';
import { maskCredentials } from './line-mask';
import { loadSecretlessIgnore, buildMatcher, defaultIgnoreLines, DEFAULT_IGNORE_PATTERNS, type IgnoreMatcher } from './secretlessignore';
import { scoreFinding, type ConfidenceBreakdown, type ConfidenceTier } from './confidence';
import { BUNDLE_EXTENSION } from './bundle';
import { withSlashSeparators, hasDisplayHazard, shellQuote } from './display-safe';

export interface ScanFinding {
  file: string;
  line: number;
  patternId: string;
  patternName: string;
  severity: 'critical' | 'high';
  preview: string;
  /**
   * Actionable fix guidance. ALWAYS non-empty — a finding without a fix is a
   * dead end, and 40 of 57 patterns used to produce one. `fixFor()` derives a
   * fallback from the pattern's own `envPrefix` when there is no verified
   * per-provider entry, so a newly added pattern cannot ship a dead end.
   */
  fix: string;
  /** Composite confidence score in [0, 1]. Higher = more likely a real credential. */
  confidence: number;
  /** Display tier derived from `confidence`: high / medium / low. */
  confidenceTier: ConfidenceTier;
  /**
   * True when `--no-ignore` surfaced a finding whose path matches the
   * default-ignore list. Used to render an inline "looks like a test fixture"
   * hint without re-suppressing the finding. False otherwise (so JSON
   * consumers can rely on the field being present).
   */
  looksLikeFixture: boolean;
  /**
   * The sub-scores and path rule behind `confidence`. Present only when
   * `ScanOptions.confidenceFactors` is set, and absent on findings whose
   * confidence is fixed because the file's presence is the finding.
   */
  confidenceFactors?: ConfidenceBreakdown;
}

/**
 * Matched values, kept only under `ScanOptions.retainValues`, each with the
 * character after it on its line (`keepMatchedValue`). A WeakMap keyed on the
 * finding object: not a property, so `JSON.stringify(finding)` and the
 * renderers never see it, and it is released with the finding.
 */
const MATCHED_VALUES = new WeakMap<ScanFinding, { value: string; charAfter: string | undefined }>();

/** The value a finding matched, when the scan was run with `retainValues`; undefined otherwise. */
export function matchedValueOf(finding: ScanFinding): string | undefined {
  return MATCHED_VALUES.get(finding)?.value;
}

/**
 * The character after a finding's matched value on its line, or '' when the
 * value ends the line, kept with the value under `retainValues`. For a
 * pattern that ends in an unbounded run of a character class, as openai-proj
 * does, it is the character the run stopped at, one outside the class; when
 * the credential can hold it, the value may be only the part of the
 * credential before it. Undefined when no value was kept, and for a value
 * taken from a pattern's capture group, whose end the match does not give.
 */
export function charAfterValueOf(finding: ScanFinding): string | undefined {
  return MATCHED_VALUES.get(finding)?.charAfter;
}

/** Keep a finding's matched value, as `retainValues` asks: the capture group when the pattern has one, else the match. */
function keepMatchedValue(finding: ScanFinding, match: RegExpMatchArray): void {
  const fromGroup = match[1] !== undefined;
  const charAfter = !fromGroup && match.index !== undefined && match.input !== undefined
    ? match.input.charAt(match.index + match[0].length)
    : undefined;
  MATCHED_VALUES.set(finding, { value: match[1] ?? match[0], charAfter });
}

/** Per-pattern fix guidance. Tells users exactly how to fix each finding. */
const FIX_GUIDANCE: Record<string, string> = {
  'anthropic': 'Move to env var ANTHROPIC_API_KEY. Rotate at console.anthropic.com > API Keys.',
  'openai-proj': 'Move to env var OPENAI_API_KEY. Rotate at platform.openai.com > API Keys.',
  'openai-legacy': 'Move to env var OPENAI_API_KEY. Rotate at platform.openai.com > API Keys.',
  'aws-access': 'Move to env var AWS_ACCESS_KEY_ID. Rotate in AWS IAM console.',
  'aws-secret': 'Move to env var AWS_SECRET_ACCESS_KEY. Rotate the access key in AWS IAM console > Users > Security credentials.',
  'aws-sts': 'STS tokens are temporary but should not be committed. Use AWS SDK credential chain.',
  'github-pat': 'Move to env var GITHUB_TOKEN. Rotate at github.com > Settings > Developer Settings > PATs.',
  'github-fine': 'Move to env var GITHUB_TOKEN. Rotate at github.com > Settings > Developer Settings > Fine-grained PATs.',
  'stripe': 'Move to env var STRIPE_SECRET_KEY. Rotate at dashboard.stripe.com > Developers > API Keys.',
  'stripe-test': 'Move to env var STRIPE_SECRET_KEY. Even test keys should not be committed.',
  'slack': 'Move to env var SLACK_TOKEN. Rotate at api.slack.com > Your Apps.',
  'postgres': 'Move to env var DATABASE_URL. Rotate the database password.',
  'mysql': 'Move to env var DATABASE_URL. Rotate the database password.',
  'mongodb': 'Move to env var MONGODB_URI. Rotate the database password.',
  'redis': 'Move to env var REDIS_URL. Rotate the Redis password (requirepass or ACL user).',
  'pem-private-key': 'Never commit private keys. Use secretless-ai secret set or a secrets manager.',
  'google': 'Move to env var GOOGLE_API_KEY. Restrict and rotate at console.cloud.google.com.',
  'supabase': 'Move to env var SUPABASE_SERVICE_ROLE_KEY. Rotate in Supabase dashboard > Settings > API.',
};

/**
 * Fix guidance for a pattern. Never returns empty.
 *
 * Patterns without a verified per-provider entry in FIX_GUIDANCE fall back to
 * guidance built from data we actually hold: the env var name is exact
 * (`pattern.envPrefix`), and the action is to revoke and reissue. The fallback
 * deliberately names NO console URL — an invented rotation URL is the same
 * class of harm as an invented package name, and can point a user at a domain
 * an attacker is free to register.
 *
 * `envFile` is the shell operand naming the real `.env` file the finding is
 * in, when it is in one (`envFileOperand`).
 */
export function fixFor(
  pattern: Pick<CredentialPattern, 'id' | 'name' | 'envPrefix'>,
  options?: { envFile?: string },
): string {
  const fix = FIX_GUIDANCE[pattern.id]
    ?? `Move to env var ${pattern.envPrefix}. Revoke and reissue this ${pattern.name} in the provider's dashboard.`;
  // In a `.env` file the value already is an env var, so "Move to env var"
  // sends the user where it is. The step left is the one `import` takes: into
  // the secret store, out of the file. The rotation text is kept as written.
  const moveStep = /^Move to env var \S+\. /.exec(fix);
  if (options?.envFile === undefined || !moveStep) return fix;
  return `Store it with npx secretless-ai import ${options.envFile}, delete the line, and start the app with npx secretless-ai run -- <command>. ${fix.slice(moveStep[0].length)}`;
}

/**
 * The operand of the `import` command in the fix for a finding in a real
 * `.env` file, or undefined for any other file.
 *
 * The scan root is not always the shell's cwd (`scan services/api`), so the
 * path is taken from cwd, absolute when it lies outside it or would read as a
 * flag. The name comes from the scanned repository and the fix is meant to be
 * pasted, so it is quoted for the shell, and replaced by `<file>` when it
 * holds a character that would reach the terminal as a control.
 */
function envFileOperand(filePath: string): string | undefined {
  if (!isEnvFile(path.basename(filePath))) return undefined;
  let shown = path.resolve(filePath);
  try {
    const rel = path.relative(fs.realpathSync(process.cwd()), fs.realpathSync(filePath));
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel) && !rel.startsWith('-')) shown = rel;
  } catch {
    // keep the absolute path
  }
  shown = withSlashSeparators(shown);
  return hasDisplayHazard(shown) ? '<file>' : shellQuote(shown);
}

/**
 * Mask the matches of one pattern in a line.
 *
 * Previews are not built here: a finding's preview goes through
 * `maskCredentials` (line-mask.ts), which masks every pattern on the line.
 *
 * For name-gated patterns the regex match SPANS the variable name (the name is
 * the gate, not a lookbehind), so replacing the whole match erased the name and
 * rendered `AWS_SECRET_ACCESS_KEY = "…"` as a bare `"`. When the pattern
 * captures the value in group 1, only that group is redacted, so the line
 * still shows which variable is exposed. Patterns with no capture group keep
 * whole-match redaction.
 */
export function maskLine(line: string, pattern: Pick<CredentialPattern, 'name' | 'regex'>): string {
  // redactMatches replaces each match through the credential characters that
  // follow it, as the transcript rewrite does and as `maskCredentials` does for
  // previews and the shell-history rewrite: replacing exactly the regex match
  // left the tail of any value longer than the pattern's fixed quantifier
  // (#133 — `ghp_` + 37 chars printed the 37th verbatim).
  return redactMatches(line, pattern.regex, `[${pattern.name} REDACTED]`, {
    preferCaptureGroup: true,
  });
}

export interface ScanOptions {
  /** Scan global config files like ~/.claude/CLAUDE.md (default: true) */
  scanGlobal?: boolean;
  /** Scan source code files for hardcoded credentials (default: true) */
  scanSource?: boolean;
  /** Include test files in source scan (default: false) */
  includeTests?: boolean;
  /**
   * Also scan config-format files whose names are not on `CONFIG_FILES`
   * (`secrets.json`, `values.yaml`, `.npmrc`; see `isConfigShaped`), with the
   * source-file rules. Default: false — they are reported in
   * `ScanStats.unscannedConfig` instead (#124).
   */
  includeConfig?: boolean;
  /** Max source files to scan before stopping (default: 5000) */
  maxSourceFiles?: number;
  /**
   * Skip files matched by `.secretlessignore` and the default-ignore list.
   * Default: true. Pass `false` to scan everything (includes fixture dirs).
   *
   * If `ignore` is provided as an `IgnoreMatcher`, that matcher is used
   * verbatim (callers wiring through `scan-staged` etc). If `true` (default)
   * and `projectDir` exists, `loadSecretlessIgnore(projectDir)` is called.
   */
  ignore?: boolean | IgnoreMatcher;
  /**
   * Drop findings whose composite confidence score is below this threshold.
   * Range [0, 1]. Default: 0 (no filtering). Useful for `--min-confidence`
   * CLI prioritisation on a noisy repo.
   */
  minConfidence?: number;
  /**
   * Surface values that would normally be suppressed as known examples /
   * placeholders (`AKIA…EXAMPLE`, `sk-…FAKE…`, `your_api_key`). Off by default.
   * When on, such matches are returned as findings so a user can verify what was
   * hidden. Backs the `scan --show-placeholders` flag.
   */
  showPlaceholders?: boolean;
  /**
   * Per-file size cap in bytes, applied to config AND source files alike.
   * Defaults to `CONFIG_FILE_CAP_BYTES` / `SOURCE_FILE_CAP_BYTES` respectively.
   * Backs `scan --max-file-size`, so a user told a file was skipped for size
   * has a way to scan it rather than only a way to learn it was missed.
   */
  maxFileSizeBytes?: number;
  /**
   * Attach each finding's confidence breakdown as `confidenceFactors`. Off by
   * default, so `scan --json` output keeps its shape. Backs `scan --explain`.
   */
  confidenceFactors?: boolean;
  /**
   * Keep each finding's matched value reachable through `matchedValueOf()`,
   * and the character after it through `charAfterValueOf()`.
   * Default: false, and then no value is kept anywhere. The value is held
   * beside the finding, never on it, so a finding printed or serialized to
   * JSON carries no more than it does without this option. Backs
   * `scan --check-validity`, which hands the value to the credential's own
   * provider, or for an AWS secret access key signs the request with it and
   * sends it nowhere (src/validity.ts).
   */
  retainValues?: boolean;
}

/** Optional out-param: counters the scan populates as a side channel. */
export interface ScanStats {
  /** Count of pattern matches suppressed as known examples / placeholders. */
  placeholdersSuppressed: number;
  /**
   * True when a file walk stopped at `maxSourceFiles` with tree left unvisited,
   * so the findings are a SUBSET and "no credentials found" is not a verdict.
   *
   * `scan()` writes this unconditionally (false on a complete walk), so a caller
   * that passes a bare object still gets a correct value rather than
   * `undefined` — an absent flag reads as falsy, which is the fail-open shape
   * this exists to close.
   */
  truncated: boolean;
  /**
   * How many files passed every filter in the largest walk that hit the file
   * cap, counted past the cap without being opened. 0 when no walk's cap
   * dropped a candidate; written on every scan, like `truncated`.
   *
   * This is what a `--max-files` suggestion is sized from. The suggestion used
   * to be the cap times four, which is a guess: 30 eligible files scanned with
   * a cap of 2 were told to use 8, and that run was still truncated. A cap of
   * this count clears every walk's cap in one run — unless
   * `walkBudgetExceeded` is also set, when the count is a lower bound.
   */
  eligibleFiles?: number;
  /**
   * True when a walk stopped on its directory budget (MAX_DIRS_VISITED, or
   * MAX_PATHS_PER_DIR routes to one directory) rather than on the file cap.
   * Raising `--max-files` cannot clear this, so a remediation must not say it
   * will. Written on every scan, like `truncated`.
   */
  walkBudgetExceeded?: boolean;
  /**
   * Paths that matched the scan but could not be read (permissions, I/O). "Could
   * not read" is a THIRD state: the same content, readable, produces a finding,
   * so dropping these silently reports a file we never opened as clean.
   *
   * Optional so an existing caller still compiles; `scan()` only appends when
   * the caller supplies the array, and the CLI always does.
   */
  unreadable?: string[];
  /**
   * Symlinks whose target resolves outside the scan root. These are NOT
   * followed — otherwise `link -> $HOME` makes `scan .` traverse the whole home
   * directory — but they are reported, because silently skipping them would be
   * the same fail-open in a new place. One link per directory reached: a
   * second link to the same directory is not added.
   */
  outOfRoot?: string[];
  /**
   * Files skipped for exceeding the per-file size cap (10 MB for config files,
   * 1 MB for source files).
   *
   * Same third state as `unreadable`: the cap is a resource guard, not a
   * judgement about content, and the same bytes under the cap produce a
   * finding. Before this was reported, an 11 MB `config.json` with a live key
   * on line 1 scanned to `total: 0`, `truncated: false`, exit 0 — a file we
   * never opened rendered as a clean scan (#120).
   */
  oversize?: Array<{ path: string; bytes: number; capBytes: number }>;
  /**
   * What the SOURCE walk chose not to look at, with the reason.
   *
   * DISCLOSURE, NOT A FAILURE. These are boundaries the scanner declared, not
   * claims it broke, so they do not set the exit code — the same class as
   * `outOfRoot`. Populated only by the source walk; the config and key walks
   * prune the same heavy directories and counting all three would treble the
   * number and bury the entry that matters.
   */
  skips?: CoverageSkips;
  /**
   * Matches dropped because their confidence score was below `minConfidence`.
   *
   * Same third state as `placeholdersSuppressed`: a filtered finding is not a
   * clean file. Before this was counted, `scan --min-confidence 1` turned a
   * one-finding repo into `total: 0` with nothing anywhere saying a filter had
   * removed anything, so a CI job read a suppressed finding as a clean repo
   * (#125). Optional so an existing caller still compiles; `scan()` counts only
   * when a filter is active.
   */
  confidenceSuppressed?: number;
  /**
   * Config-format files that no walk read (#124): not on the `CONFIG_FILES`
   * name list, not a source extension. Before this, a tree whose only key sat
   * in `secrets.json` scanned to `total: 0` with nothing said.
   *
   * A DECLARED BOUNDARY, like `skips`: it does not set the exit code, because
   * `tsconfig.json` alone would then fail every clean scan. A consumer that
   * wants to gate on it reads `summary.unscannedConfig`. `count` is the true
   * number; `files` is a sample capped like the skip samples.
   */
  unscannedConfig?: { count: number; files: string[] };
  /**
   * Paths the source walk did not read because the scanned tree's own
   * `.secretlessignore` matched them and the default-ignore list alone does
   * not (#414). Each is also counted in `skips`, with the ignore-rule reason.
   *
   * Unlike the rest of `skips`, a GAP for `scan`: the rule comes from the tree
   * being judged, so a committed `.secretlessignore` holding `*` turned a
   * scan of that tree into "No hardcoded credentials found." with exit 0.
   * Written only when non-zero, so an absent field is zero.
   */
  ignoreFileExcluded?: number;
}

/**
 * A stats object with every collector present. `scan()` appends only to the
 * collectors a caller supplies, so a hand-built object that leaves one out
 * reads that gap as clean: `status --json` reported `scanIncomplete: false`
 * over a file skipped for size because its object had no `oversize` array.
 * `Required<>` makes a collector added to `ScanStats` a compile error here
 * until it is filled in.
 */
export function newScanStats(): Required<ScanStats> {
  return {
    placeholdersSuppressed: 0, truncated: false, unreadable: [], outOfRoot: [],
    oversize: [], skips: emptySkips(), confidenceSuppressed: 0,
    unscannedConfig: { count: 0, files: [] }, eligibleFiles: 0, walkBudgetExceeded: false,
    ignoreFileExcluded: 0,
  };
}

/**
 * True when part of the tree was never read: the walk stopped at the file cap,
 * a path could not be opened, or a file was skipped for size. The findings are
 * then a subset, so zero of them is not a clean result. Out-of-root links and
 * declared skips are disclosures rather than gaps and do not count, the same
 * split `scan` uses for its exit code. `scan` also counts the paths in
 * `ignoreFileExcluded` as a gap; this function does not.
 */
export function coverageIncomplete(stats: ScanStats): boolean {
  return stats.truncated
    || (stats.unreadable?.length ?? 0) > 0
    || (stats.oversize?.length ?? 0) > 0;
}

/** Per-file size caps. A file above the cap is skipped and reported, never dropped silently. */
export const CONFIG_FILE_CAP_BYTES = 10 * 1024 * 1024;
export const SOURCE_FILE_CAP_BYTES = 1 * 1024 * 1024;

/**
 * Demo-tier passwords that combine with localhost-bound DB connection strings
 * to mark a value as a tutorial fixture, not a real credential. Local mirror
 * of the catalog @opena2a/credential-patterns 0.1.1 set — lockstep test gates.
 */
const DEMO_PASSWORDS = new Set([
  'password',
  'password123',
  'secret',
  'admin',
  'root',
  'demo',
  'test',
  'changeme',
]);

function isLocalhostDemoConnectionString(value: string): boolean {
  const protoEnd = value.indexOf('://');
  if (protoEnd === -1) return false;
  const atIdx = value.lastIndexOf('@');
  if (atIdx === -1 || atIdx <= protoEnd + 3) return false;
  const userInfo = value.slice(protoEnd + 3, atIdx);
  const host = value.slice(atIdx + 1);
  // Anchored host check defeats `localhost.evil.com` bypass. IPv4 loopback
  // `127.0.0.1`, IPv6 loopback `[::1]`, and the `localhost` literal accepted.
  if (!/^(\[::1\]|localhost|127\.0\.0\.1)(:|\/|$)/i.test(host)) return false;
  const colonIdx = userInfo.indexOf(':');
  if (colonIdx === -1) return false;
  // Password lookup is case-insensitive — capitalized demo passwords are
  // functionally the same fixture (`Password123` vs `password123`).
  const password = userInfo.slice(colonIdx + 1).toLowerCase();
  return DEMO_PASSWORDS.has(password);
}

/**
 * The comment text on `line`, as `[start, end)` spans: `//` and `#` to the end
 * of the line, a block comment (`/*`), an HTML comment (`<!--`, or a `-->` that
 * closes one from an earlier line), a `'''`/`"""` docstring and a JSDoc
 * continuation line. A `//` right after `:` is a URL scheme
 * (`https://example.com`), not a comment. A lone `'''`/`"""` may open or close
 * a docstring, so it marks the whole line.
 */
function commentSpans(line: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  let i = 0;
  // JSDoc continuation: line starts with optional whitespace then `*`.
  // Anchored so `x * y` (multiplication) does NOT match.
  const jsdoc = /^\s*\*/.exec(line);
  if (jsdoc) {
    const close = line.indexOf('*/', jsdoc[0].length - 1);
    i = close === -1 ? line.length : close + 2;
    spans.push([0, i]);
  }
  while (i < line.length) {
    let close: number;
    let width: number;
    if (line.startsWith('<!--', i)) {
      close = line.indexOf('-->', i + 4);
      width = 3;
    } else if (line.startsWith('/*', i)) {
      close = line.indexOf('*/', i + 2);
      width = 2;
    } else if (line.startsWith('"""', i) || line.startsWith("'''", i)) {
      close = line.indexOf(line.slice(i, i + 3), i + 3);
      if (close === -1) {
        spans.push([0, line.length]);
        break;
      }
      width = 3;
    } else if (line.startsWith('//', i) && line[i - 1] === ':') {
      i += 2;
      continue;
    } else if (line.startsWith('//', i) || line[i] === '#') {
      spans.push([i, line.length]);
      break;
    } else if (line.startsWith('-->', i)) {
      // Closes an HTML comment opened on an earlier line.
      spans.push([0, i + 3]);
      i += 3;
      continue;
    } else {
      i++;
      continue;
    }
    const end = close === -1 ? line.length : close + width;
    spans.push([i, end]);
    i = end;
  }
  return spans;
}

/**
 * True when a comment on `line` says "example". Only the comment text is
 * tested: "example" in code on the same line (an `https://example.com` string,
 * an identifier) does not make a value on that line a placeholder.
 */
function isExampleInComment(line: string): boolean {
  if (!line.toLowerCase().includes('example')) return false;
  return commentSpans(line).some(([start, end]) => line.slice(start, end).toLowerCase().includes('example'));
}

/**
 * Check if a matched credential is a known example or placeholder.
 * Returns true if the match should be excluded from results.
 *
 * Exported so scan-staged (and any other scanner) can apply the same
 * allowlist. Prevents the pre-commit hook from blocking docs that
 * legitimately reference public example keys like AKIAIOSFODNN7EXAMPLE.
 */
export function isKnownExample(line: string, match: RegExpMatchArray): boolean {
  // Lockstep with @opena2a/credential-patterns 0.1.2: prefer the captured value
  // (group 1) for name-gated patterns whose match[0] is "name = value", and add
  // a low-entropy floor so name-gated sentinels are not flagged.
  const value = match[1] ?? match[0];
  if (KNOWN_EXAMPLE_KEYS.has(value)) return true;
  const lower = value.toLowerCase();
  if (PLACEHOLDER_INDICATORS.some(p => lower.includes(p))) return true;
  // A name-gated value >=20 chars with <=6 distinct characters (0000…,
  // DEADBEEF…) is a placeholder; a real >=20-char secret never has so few.
  if (value.length >= 20 && new Set(value).size <= 6) return true;
  if (isLocalhostDemoConnectionString(value)) return true;
  if (isExampleInComment(line)) return true;
  return false;
}

/**
 * Return the first match in `line` for `pattern.regex` that is NOT a known
 * example, or null if every match is an example (or there are no matches).
 *
 * For /g regexes this iterates all matches via matchAll so that a known
 * example of a given pattern on a line does not shadow a real credential
 * of the same pattern later on that line. Non-global regexes fall back to
 * a single match check.
 *
 * Exported so scan-staged and any other scanner stays in lockstep.
 */
export function findRealMatch(
  line: string,
  pattern: CredentialPattern,
  opts?: {
    /** Return matches that would normally be suppressed as known examples/placeholders. */
    includeExamples?: boolean;
    /** Called once per match suppressed as a known example (for "N hidden" reporting). */
    onSuppressed?: () => void;
  },
): RegExpMatchArray | null {
  // matchAll requires /g. Promote non-/g patterns so we iterate EVERY match on
  // the line — otherwise a known-example match at position 0 would shadow a
  // real credential of the same pattern later on the same line.
  const globalRegex = pattern.regex.flags.includes('g')
    ? pattern.regex
    : new RegExp(pattern.regex.source, pattern.regex.flags + 'g');
  globalRegex.lastIndex = 0;
  for (const m of line.matchAll(globalRegex)) {
    if (opts?.includeExamples || !isKnownExample(line, m)) return m;
    opts?.onSuppressed?.();
  }
  return null;
}

/** Global config files that may contain secrets (outside project dir) */
const GLOBAL_CONFIG_FILES = [
  { dir: path.join(os.homedir(), '.claude'), file: 'CLAUDE.md', label: '~/.claude/CLAUDE.md' },
  { dir: path.join(os.homedir(), '.claude'), file: 'settings.json', label: '~/.claude/settings.json' },
  // The store `claude mcp add` writes user-scope mcpServers env into.
  { dir: os.homedir(), file: '.claude.json', label: '~/.claude.json' },
  { dir: path.join(os.homedir(), '.cursor'), file: 'mcp.json', label: '~/.cursor/mcp.json' },
];

/**
 * @internal The home-directory files every directory scan also reads, as
 * `scan --help` names them. Read by the help text, its tests, and the SARIF
 * writer, which gives a finding in one of them as an absolute URI.
 */
export const GLOBAL_CONFIG_LABELS: readonly string[] = GLOBAL_CONFIG_FILES.map((g) => g.label);

/**
 * Scan project config files for hardcoded credentials.
 * Also scans global AI tool configs (e.g. ~/.claude/CLAUDE.md).
 * Returns findings sorted by severity then file.
 */
/**
 * Scan a single explicitly-named file.
 *
 * Severity mirrors the directory scan: a config file is `critical` (they get
 * committed and read by tooling), source is `high`.
 */
function scanSingleFile(
  filePath: string,
  options: ScanOptions | undefined,
  matchOpts: { includeExamples: boolean; onSuppressed: () => void },
  stats?: ScanStats,
): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const name = path.basename(filePath);
  // Report a path the reader can act on. The basename alone does not resolve
  // from the caller's cwd, so a CI job annotating file:line from --json pointed
  // at the wrong file or at nothing. Prefer cwd-relative; fall back to the
  // absolute path when the target is outside the tree.
  // realpath both sides: on macOS the temp dir and /tmp are symlinks, so a
  // literal cwd-vs-path comparison escapes with `../../..` and loses the
  // relative form for paths that are genuinely inside the tree.
  const display = (() => {
    try {
      const rel = path.relative(fs.realpathSync(process.cwd()), fs.realpathSync(filePath));
      if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) return rel.replace(/\\/g, '/');
    } catch {
      // fall through to the path as given
    }
    return filePath;
  })();
  const isConfig = CONFIG_FILES.some(c => c === name || filePath.replace(/\\/g, '/').endsWith('/' + c));
  const severity: 'critical' | 'high' = isConfig ? 'critical' : 'high';
  const envFile = envFileOperand(filePath);
  const minConfidence = Math.max(0, Math.min(1, options?.minConfidence ?? 0));

  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return findings;
    const singleCap = options?.maxFileSizeBytes ?? CONFIG_FILE_CAP_BYTES;
    if (stat.size > singleCap) {
      // Skipping is fine; skipping silently is not. A named target over the
      // cap used to return zero findings and exit 0.
      stats?.oversize?.push({ path: display, bytes: stat.size, capBytes: singleCap });
      return findings;
    }
    const lines = fs.readFileSync(filePath, 'utf-8').split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 4096) continue;
      const trimmed = line.trim();
      if (trimmed.startsWith('//') && trimmed.includes('regex')) continue;
      if (/\$\{[A-Z_]+\}/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) continue;
      if (/process\.env\.[A-Z_]+/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) continue;
      if (/os\.environ/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) continue;

      for (const pattern of CREDENTIAL_PATTERNS) {
        const match = findRealMatch(line, pattern, matchOpts);
        if (match) {
          const breakdown = scoreFinding({
            pattern: { id: pattern.id, regex: pattern.regex },
            value: match[0],
            filePath: name,
          });
          if (breakdown.score < minConfidence) {
            if (stats) stats.confidenceSuppressed = (stats.confidenceSuppressed ?? 0) + 1;
          } else {
            const finding: ScanFinding = {
              file: display,
              line: i + 1,
              patternId: pattern.id,
              patternName: pattern.name,
              severity,
              preview: maskCredentials(line).trim().substring(0, 80),
              fix: fixFor(pattern, { envFile }),
              confidence: breakdown.score,
              confidenceTier: breakdown.tier,
              looksLikeFixture: false,
              ...(options?.confidenceFactors ? { confidenceFactors: breakdown } : {}),
            };
            if (options?.retainValues) keepMatchedValue(finding, match);
            findings.push(finding);
          }
          break;
        }
      }
    }
  } catch {
    // Unreadable — no findings rather than a crash, but say so. A named target
    // that cannot be opened used to print "No hardcoded credentials found" and
    // exit 0, which is a green CI gate over a file nobody read.
    stats?.unreadable?.push(display);
  }
  return findings;
}

export function scan(projectDir: string, options?: ScanOptions, stats?: ScanStats): ScanFinding[] {
  // Shared per-match options for the credential-pattern call sites: reveal or count
  // placeholder-suppressed matches so the CLI can tell the user what was hidden.
  const matchOpts = {
    includeExamples: options?.showPlaceholders === true,
    onSuppressed: () => { if (stats) stats.placeholdersSuppressed += 1; },
  };
  const findings: ScanFinding[] = [];
  const scanGlobal = options?.scanGlobal !== false;
  // One user-supplied cap overrides both defaults: `--max-file-size 20mb` means
  // "scan files up to 20 MB", not "20 MB for config and still 1 MB for source".
  const configCap = options?.maxFileSizeBytes ?? CONFIG_FILE_CAP_BYTES;
  const sourceCap = options?.maxFileSizeBytes ?? SOURCE_FILE_CAP_BYTES;
  // Written unconditionally so a complete walk actively reports "not truncated"
  // rather than leaving a stale or absent flag for the caller to misread.
  if (stats) {
    stats.truncated = false;
    stats.eligibleFiles = 0;
    stats.walkBudgetExceeded = false;
  }

  // A FILE target is scanned as that file. It used to be accepted, checked for
  // existence, then walked as a directory — which found nothing and reported
  // "No hardcoded credentials found" with exit 0, so `scan src/config.ts` in CI
  // was a green pass over a live credential.
  //
  // Naming a path is an explicit instruction, so neither the ignore list nor
  // the test-file heuristics apply: those exist to keep a directory WALK from
  // being noisy, and there is no walk here.
  try {
    if (fs.statSync(projectDir).isFile()) {
      return scanSingleFile(projectDir, options, matchOpts, stats);
    }
  } catch {
    // Unreadable/nonexistent — fall through to the directory path, which
    // reports the not-found error the CLI already renders.
  }

  // Resolve the ignore matcher. Default: load `<projectDir>/.secretlessignore`
  // plus the default-ignore list. `ignore: false` disables both.
  const ignore: IgnoreMatcher | null = (() => {
    if (options?.ignore === false) return null;
    if (options?.ignore && typeof options.ignore === 'object') return options.ignore;
    try {
      // `includeTests` must reach the matcher too, not just the walkers. The
      // default-ignore list carries `test/` independently of the walkers'
      // TEST_DIRS check, so passing the flag to only one of them left
      // `--include-tests` a silent no-op for every file under `test/`.
      return loadSecretlessIgnore(projectDir, { includeTests: options?.includeTests ?? false });
    } catch {
      return null;
    }
  })();

  // The default-ignore list alone, when `ignore` was loaded here from the
  // scanned tree: a path `ignore` matches and this does not was excluded by
  // that tree's `.secretlessignore` (#414). Null for a caller's own matcher.
  const ignoreDefaults: IgnoreMatcher | null = ignore && typeof options?.ignore !== 'object'
    ? buildMatcher(defaultIgnoreLines({ includeTests: options?.includeTests ?? false }))
    : null;

  // Defaults-only matcher used to flag `--no-ignore` findings whose path is
  // in the default-ignore list. Built lazily because it's only useful when
  // `ignore === null` (otherwise the path is already filtered out).
  const fixtureMatcher: IgnoreMatcher | null = ignore === null
    ? buildMatcher(DEFAULT_IGNORE_PATTERNS as readonly string[])
    : null;

  const minConfidence = Math.max(0, Math.min(1, options?.minConfidence ?? 0));
  const includeTestsOpt = options?.includeTests ?? false;

  // Helper: classify a match into a `ScanFinding` with confidence + fixture flag.
  function buildFinding(
    file: string,
    line: number,
    pattern: CredentialPattern,
    match: RegExpMatchArray,
    severity: 'critical' | 'high',
    masked: string,
  ): ScanFinding | null {
    const breakdown = scoreFinding({
      pattern: { id: pattern.id, regex: pattern.regex },
      value: match[0],
      filePath: file,
    });
    if (breakdown.score < minConfidence) {
      if (stats) stats.confidenceSuppressed = (stats.confidenceSuppressed ?? 0) + 1;
      return null;
    }
    const looksLikeFixture = !!(fixtureMatcher && fixtureMatcher.matches(file.replace(/\\/g, '/')));
    const finding: ScanFinding = {
      file,
      line,
      patternId: pattern.id,
      patternName: pattern.name,
      severity,
      preview: masked.trim().substring(0, 80),
      fix: fixFor(pattern, { envFile: envFileOperand(path.join(projectDir, file)) }),
      confidence: breakdown.score,
      confidenceTier: breakdown.tier,
      looksLikeFixture,
      ...(options?.confidenceFactors ? { confidenceFactors: breakdown } : {}),
    };
    if (options?.retainValues) keepMatchedValue(finding, match);
    return finding;
  }

  // Scan global config files (keys in ~/.claude/CLAUDE.md are in every session's context)
  for (const global of (scanGlobal ? GLOBAL_CONFIG_FILES : [])) {
    const fullPath = path.join(global.dir, global.file);
    if (!fs.existsSync(fullPath)) continue;
    try {
      const stat = fs.statSync(fullPath);
      if (!stat.isFile()) continue;
      if (stat.size > configCap) {
        stats?.oversize?.push({ path: global.label, bytes: stat.size, capBytes: configCap });
        continue;
      }
      const content = fs.readFileSync(fullPath, 'utf-8');
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 4096) continue;
        if (/\$\{[A-Z_]+\}/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) continue;
        for (const pattern of CREDENTIAL_PATTERNS) {
          const match = findRealMatch(line, pattern, matchOpts);
          if (match) {
            const masked = maskCredentials(line);
            const finding = buildFinding(global.label, i + 1, pattern, match, 'critical', masked);
            if (finding) findings.push(finding);
            break;
          }
        }
      }
    } catch { /* skip */ }
  }

  // Scan project-level config files, at any depth.
  //
  // These used to be looked up ONLY at the scan root, while source files
  // recursed — so a monorepo with `packages/*/config.json`, or anything under
  // `deploy/` or `infra/`, reported clean at exactly the invocation every user
  // runs first. A scanner that answers "clean" for a tree it never walked is
  // worse than one that errors.
  const scannedConfigFiles: string[] = [];
  /**
   * Fold every coverage shortfall a walk reported into the caller's stats.
   *
   * Deduplicated: the three walkers cover the same tree with different filters,
   * so one unreadable directory or one out-of-root link is seen by all three and
   * would otherwise be reported three times — turning "1 path could not be read"
   * into "3 paths could not be read" for a single underlying cause.
   */
  // Keyed on the RESOLVED path, not the path we walked: one unreadable directory
  // reachable through eight in-tree links reported nine separate entries, and
  // since a non-empty list sets exit 1, that is nine lines of noise for one
  // cause.
  const seenUnreadable = new Set<string>();
  const seenOutOfRoot = new Set<string>();
  const dedupeKey = (p: string) => realpathOrNull(path.resolve(projectDir, p)) ?? p;
  const absorbWalk = (walk: WalkResult) => {
    if (!stats) return;
    if (walk.truncated) stats.truncated = true;
    if (walk.budgetExceeded) stats.walkBudgetExceeded = true;
    // The walks apply the cap one at a time, so the cap that clears all of
    // them is the largest count among the walks that hit it.
    if (walk.eligible > walk.files.length) {
      stats.eligibleFiles = Math.max(stats.eligibleFiles ?? 0, walk.eligible);
    }
    for (const p of walk.unreadable) {
      const k = dedupeKey(p);
      if (stats.unreadable && !seenUnreadable.has(k)) { seenUnreadable.add(k); stats.unreadable.push(p); }
    }
    for (const p of walk.outOfRoot) {
      const k = dedupeKey(p);
      if (stats.outOfRoot && !seenOutOfRoot.has(k)) { seenOutOfRoot.add(k); stats.outOfRoot.push(p); }
    }
    // Only the disclosing walk contributes; the others return an empty set, so
    // this is an accumulate rather than a filter and cannot silently pick up a
    // second walk if one ever opts in.
    if (stats.skips) {
      stats.skips.dirCount += walk.skips.dirCount;
      stats.skips.fileCount += walk.skips.fileCount;
      for (const d of walk.skips.dirs) if (stats.skips.dirs.length < SKIP_SAMPLE_CAP) stats.skips.dirs.push(d);
      for (const f of walk.skips.files) if (stats.skips.files.length < SKIP_SAMPLE_CAP) stats.skips.files.push(f);
    }
  };

  const configWalk = walkConfigFiles(projectDir, options?.maxSourceFiles ?? 5000, includeTestsOpt, ignore);
  absorbWalk(configWalk);
  for (const configFile of configWalk.files) {
    if (ignore && ignore.matches(configFile)) continue;
    const fullPath = path.join(projectDir, configFile);
    // Was `!fs.existsSync`, which is also false for EACCES: a config file in a
    // directory this user can list but not search was dropped as absent, so it
    // was neither read nor listed (#392). Any failure other than absence
    // reaches the read below, whose catch lists the file.
    if (isAbsent(fullPath)) continue;
    scannedConfigFiles.push(configFile);

    try {
      const stat = fs.statSync(fullPath);
      if (!stat.isFile()) continue;
      if (stat.size > configCap) {
        stats?.oversize?.push({ path: configFile, bytes: stat.size, capBytes: configCap });
        continue;
      }

      const content = fs.readFileSync(fullPath, 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 4096) continue; // ReDoS protection

        // Skip env var references and placeholders
        if (/\$\{[A-Z_]+\}/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) {
          continue;
        }

        for (const pattern of CREDENTIAL_PATTERNS) {
          const match = findRealMatch(line, pattern, matchOpts);
          if (match) {
            // Mask every credential on the line in the preview
            const masked = maskCredentials(line);

            const finding = buildFinding(configFile, i + 1, pattern, match, 'critical', masked);
            if (finding) findings.push(finding);
            break; // One finding per line
          }
        }
      }
    } catch {
      // Not "clean" — a file we could not open. Silently dropping it from the
      // count is how an unreadable config rendered as a passing scan.
      stats?.unreadable?.push(configFile);
    }
  }

  // Scan source code files for hardcoded credentials
  if (options?.scanSource !== false) {
    const configFileSet = new Set(scannedConfigFiles);
    const maxFiles = options?.maxSourceFiles ?? 5000;
    const includeTests = options?.includeTests ?? false;
    const sourceWalk = walkSourceFiles(projectDir, maxFiles, includeTests, ignore, options?.includeConfig ?? false, ignoreDefaults);
    absorbWalk(sourceWalk);
    if (stats?.unscannedConfig) {
      stats.unscannedConfig.count += sourceWalk.unscannedConfig.count;
      for (const f of sourceWalk.unscannedConfig.files) {
        if (stats.unscannedConfig.files.length < SKIP_SAMPLE_CAP) stats.unscannedConfig.files.push(f);
      }
    }
    if (stats && sourceWalk.ignoreFileExcluded > 0) {
      stats.ignoreFileExcluded = (stats.ignoreFileExcluded ?? 0) + sourceWalk.ignoreFileExcluded;
    }

    for (const filePath of sourceWalk.files) {
      const relPath = path.relative(projectDir, filePath);
      // Skip files already covered by config scan
      if (configFileSet.has(relPath)) continue;
      // Apply user/default ignore filter at file level too — defends
      // against entries inside an otherwise-walked directory.
      if (ignore && ignore.matches(relPath.replace(/\\/g, '/'))) continue;

      try {
        const stat = fs.statSync(filePath);
        if (!stat.isFile()) continue;
        if (stat.size > sourceCap) {
          stats?.oversize?.push({
            path: withSlashSeparators(relPath),
            bytes: stat.size,
            capBytes: sourceCap,
          });
          continue;
        }

        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.length > 4096) continue;
          // Skip comments that are just documenting patterns (e.g. regex definitions)
          const trimmed = line.trim();
          if (trimmed.startsWith('//') && trimmed.includes('regex')) continue;
          // Skip env var references
          if (/\$\{[A-Z_]+\}/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) continue;
          // Skip process.env references
          if (/process\.env\.[A-Z_]+/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) continue;
          // Skip os.environ references (Python)
          if (/os\.environ/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) continue;

          for (const pattern of CREDENTIAL_PATTERNS) {
            const match = findRealMatch(line, pattern, matchOpts);
            if (match) {
              const masked = maskCredentials(line);

              const finding = buildFinding(relPath, i + 1, pattern, match, 'high', masked);
              if (finding) findings.push(finding);
              break;
            }
          }
        }
      } catch {
        stats?.unreadable?.push(withSlashSeparators(relPath));
      }
    }
  }

  // Scan standalone private-key files (server.key, id_rsa.pem, *.p12), and bundles
  // written by `export` (*.secretless-bundle), which are flagged by existence. These extensions
  // are in SECRET_FILE_PATTERNS (the block list) but were never fed to the scanner, so the
  // single most common private-key layout on disk reported clean. Text key files are
  // scanned for a PEM PRIVATE KEY block (public certs in .crt/.pem won't match); binary
  // PKCS#12 bundles (.p12/.pfx) are flagged by existence — they always carry a private key.
  if (options?.scanSource !== false) {
    const includeTests = options?.includeTests ?? false;
    const pemPattern = CREDENTIAL_PATTERNS.find(p => p.id === 'pem-private-key')!;
    const keyWalk = walkKeyFiles(projectDir, options?.maxSourceFiles ?? 5000, includeTests, ignore);
    absorbWalk(keyWalk);
    for (const filePath of keyWalk.files) {
      const relPath = path.relative(projectDir, filePath);
      if (ignore && ignore.matches(relPath.replace(/\\/g, '/'))) continue;
      try {
        const stat = fs.statSync(filePath);
        if (!stat.isFile()) continue;
        if (path.extname(filePath).toLowerCase() === BUNDLE_EXTENSION) {
          // A bundle from `export` holds every secret it was given, behind one
          // passphrase that can be guessed at offline. Presence is the finding,
          // so this is checked before the size cap and nothing is read.
          findings.push({
            file: relPath,
            line: 1,
            patternId: 'secretless-bundle',
            patternName: 'Secretless Encrypted Bundle',
            severity: 'high',
            preview: `${path.basename(filePath)} (encrypted secret bundle from export)`,
            fix: 'Import it on the machine it was made for, then delete it. Never commit a bundle.',
            confidence: 0.95,
            confidenceTier: 'high',
            looksLikeFixture: !!(fixtureMatcher && fixtureMatcher.matches(relPath.replace(/\\/g, '/'))),
          });
          continue;
        }
        if (stat.size > sourceCap) {
          // A private-key file over the cap is exactly the case worth naming.
          stats?.oversize?.push({
            path: withSlashSeparators(relPath),
            bytes: stat.size,
            capBytes: sourceCap,
          });
          continue;
        }
        const ext = path.extname(filePath).toLowerCase();

        if (ext === '.p12' || ext === '.pfx') {
          // Binary PKCS#12 keystore — presence alone is the finding.
          findings.push({
            file: relPath,
            line: 1,
            patternId: 'pkcs12-keystore',
            patternName: 'PKCS#12 Keystore',
            severity: 'high',
            preview: `${path.basename(filePath)} (binary keystore — contains a private key)`,
            fix: 'Never commit keystores. Store in a secrets manager and reference at runtime.',
            confidence: 0.95,
            confidenceTier: 'high',
            looksLikeFixture: !!(fixtureMatcher && fixtureMatcher.matches(relPath.replace(/\\/g, '/'))),
          });
          continue;
        }

        const content = fs.readFileSync(filePath, 'utf-8');
        if (!pemPattern.regex.test(content)) continue; // public cert / no private key → not a finding
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const match = findRealMatch(lines[i], pemPattern);
          if (match) {
            const finding = buildFinding(relPath, i + 1, pemPattern, match, 'high', '[PEM Private Key REDACTED]');
            if (finding) findings.push(finding);
            break;
          }
        }
      } catch {
        // Non-UTF8 is expected for .p12/.pfx and handled above, so reaching here
        // means the file could not be opened at all.
        stats?.unreadable?.push(withSlashSeparators(relPath));
      }
    }
  }

  // Sort: critical first, then by descending confidence (highest first), then by file
  // for stable ties. Surfacing high-confidence findings ahead of low-confidence
  // ones helps users prioritise on a noisy repo.
  findings.sort((a, b) => {
    if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
    if (a.confidence !== b.confidence) return b.confidence - a.confidence;
    return a.file.localeCompare(b.file);
  });

  // One credential, one finding. Following symlinks means the same underlying
  // file is reachable by more than one path — twelve packages each linking to a
  // shared config turned one leaked key into thirteen criticals, so `total`
  // counted PATHS rather than credentials and a triage queue read thirteen
  // incidents. Deduplicated on the resolved file plus its position, after the
  // sort, so the surviving path is the highest-confidence one.
  return dedupeByRealFile(findings, projectDir);
}

/** Collapse findings that resolve to the same real file, line and pattern. */
function dedupeByRealFile(findings: ScanFinding[], projectDir: string): ScanFinding[] {
  const realOf = new Map<string, string>();
  const seen = new Set<string>();
  const out: ScanFinding[] = [];
  for (const f of findings) {
    let real = realOf.get(f.file);
    if (real === undefined) {
      real = realpathOrNull(path.resolve(projectDir, f.file)) ?? f.file;
      realOf.set(f.file, real);
    }
    const key = `${real}\u0000${f.line}\u0000${f.patternId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

/**
 * Directories that contain test fixtures and should be skipped by default.
 *
 * This is the walker half of a pair; `TEST_DEFAULT_IGNORE_PATTERNS` in
 * secretlessignore.ts is the ignore-list half. Both suppress independently, so
 * `includeTests` has to open BOTH — opening only this one is what made
 * `--include-tests` a no-op for files under `test/`.
 */
export const TEST_DIRS: ReadonlySet<string> = new Set(['__tests__', '__mocks__', 'test', 'tests', 'fixtures', '__fixtures__']);

/**
 * Hidden cache and build-output directories the SOURCE walk does not enter.
 *
 * Every other dot-directory is entered, `.claude/`, `.github/` and `.vscode/`
 * among them. The source walk used to prune every name starting with `.`, so a
 * token in `.claude/agent.ts` went unreported while its byte-identical copy in
 * `src/app.ts` was a finding (#144). These names stay pruned: they hold
 * generated or downloaded files, not source a user wrote.
 *
 * Kept here rather than in `SOURCE_SKIP_DIRS`, which must equal the shared
 * pattern catalog. The key and config walks enter these directories, and
 * naming one scans it.
 */
export const HIDDEN_CACHE_DIRS: ReadonlySet<string> = new Set([
  '.netlify', '.open-next', '.turbo', '.playwright-mcp', '.yarn', '.pnpm-store',
  '.cache', '.terraform', '.parcel-cache', '.angular', '.serverless',
]);

/**
 * Directories of linked git worktrees, which the SOURCE walk does not enter.
 * A linked worktree holds a `.git` FILE, so the `.git` prune does not stop a
 * walk inside one, and each one is another checkout of a repository.
 */
export const WORKTREE_DIRS: ReadonlySet<string> = new Set(['.worktrees']);

/**
 * The names `isTestFile` matches, written as globs for `scan --help`. Kept
 * beside the function because they are two statements of one rule; a test
 * walks a file named after each glob and checks the walk skips it as a test
 * file, so an edit to one without the other fails.
 */
export const TEST_FILE_GLOBS: readonly string[] = ['*.test.*', '*.spec.*', '*.e2e.*', 'test_*', '*_test.go'];

/** File name patterns that indicate test files */
function isTestFile(name: string): boolean {
  return /\.(test|spec|e2e)\.[^.]+$/.test(name)
    || name.startsWith('test_')
    || name.endsWith('_test.go');
}

/**
 * Walk a directory tree and return source files matching SOURCE_FILE_EXTENSIONS.
 * Skips directories in SOURCE_SKIP_DIRS. Stops after maxFiles.
 * By default, skips test files and test directories.
 *
 * Also honors an `IgnoreMatcher` (from `.secretlessignore` + defaults). The
 * matcher is consulted at the directory level (cheaper, prunes whole subtrees)
 * and again at the file level (in case the user uses a file-name glob).
 */
/** Private-key file extensions scanned in addition to source/config files. */
export const KEY_FILE_EXTENSIONS: ReadonlySet<string> = new Set(['.pem', '.key', '.crt', '.p12', '.pfx', BUNDLE_EXTENSION]);

/** What a walker collected, and every reason its coverage fell short. */
interface WalkResult {
  files: string[];
  /**
   * True when a real candidate was dropped because `maxFiles` was already
   * reached, or when queued directories were left unvisited. A truncated walk
   * must never render as a clean scan — see `ScanStats.truncated`.
   */
  truncated: boolean;
  /**
   * Files that passed every filter, INCLUDING the ones dropped at the cap. The
   * walk keeps counting past the cap (reading directories, never files) so a
   * truncated scan can say how large a cap would have covered the tree.
   */
  eligible: number;
  /** True when the walk stopped on its directory budget, not the file cap. */
  budgetExceeded: boolean;
  /**
   * Directories that could not be listed and entries that could not be stat'd.
   * A `readdirSync` that throws used to `continue` with nothing recorded, so an
   * unreadable directory produced findings=0 with `truncated:false` — the scan
   * actively asserted it was complete over a subtree it never opened.
   */
  unreadable: string[];
  /**
   * Symlinks whose target resolves outside the scan root, which are not
   * followed. Reported rather than dropped: silently skipping them would be the
   * same fail-open in a new place.
   */
  outOfRoot: string[];
  /**
   * What this walk chose not to look at, with the reason it chose that.
   *
   * DISCLOSURE ONLY — see `CoverageSkips`. Populated on the walk that opts in
   * via `discloseSkips`, which is the SOURCE walk alone: the config and key
   * walks prune the same heavy directories, so counting all three would report
   * `node_modules` three times and produce a number nobody can act on.
   */
  skips: CoverageSkips;
}

/**
 * Directories not entered and files not opened, each with the reason.
 *
 * These are DECLARED BOUNDARIES, not failures of a claim the scanner made, so
 * they do not set the exit code — the same class as `outOfRoot` and the same
 * treatment. `truncated`, `unreadable` and `oversize` are the other class: we
 * said we would read something and did not.
 *
 * The reason travels with the path because the count alone is not actionable.
 * The raw count is dominated by dependency and build output, which every user
 * already expects to be skipped; an entry a user does not expect is invisible
 * inside a single total.
 */
export interface CoverageSkips {
  /** Directories not descended into: `{ path, reason }`, capped. */
  dirs: Array<{ path: string; reason: SkipReasonText }>;
  /** Files enumerated but not opened: `{ path, reason }`, capped. */
  files: Array<{ path: string; reason: SkipReasonText }>;
  /** True counts, which keep rising after the samples above stop growing. */
  dirCount: number;
  fileCount: number;
}

/**
 * Every reason the SOURCE walk gives for a directory it did not enter or a file
 * it did not open: the strings the scan prints beside each path. The flag in
 * parentheses is the one that opens it.
 *
 * `scan --help` names each of these before the run, and a test walks a tree
 * that produces every one, so the walk, this catalog and the help cannot drift
 * apart. A new reason added to the walk as a bare string would print a skip the
 * help never explained.
 *
 * A hidden cache or worktree directory has more than one, because what the
 * other walks do inside it depends on the filesystem: the key and config walks
 * read inside one they can open, and nothing inside one they cannot open or
 * that links out of the root. One reason for all three either claimed reads
 * that never happened or hid the findings that did come from inside.
 */
export const SOURCE_SKIP_REASONS = {
  unsupportedType: 'unsupported file type',
  configNotListed: 'config file not on the built-in list (--include-config)',
  testFile: 'test file (--include-tests)',
  testDir: 'test directory (--include-tests)',
  ignoreRule: 'ignore rule (--no-ignore)',
  hiddenCache: 'hidden cache or build output; config and key files inside are still read',
  worktrees: 'linked git worktrees; config and key files inside are still read',
  hiddenDirOutsideRoot: 'hidden directory linked outside the scan root; nothing inside is read',
  hiddenDirClosed: 'hidden directory this user cannot open; nothing inside is read',
  buildOutput: 'dependency or build output',
  gitMetadata: 'git metadata',
} as const;

/**
 * Why a path the scan meant to read could not be read: the strings printed
 * beside each path in `unreadable`. Each one is what `lstat`, `stat` and
 * `access` say about that path, so the cause is measured per path instead of
 * listed as a set of possibilities, one of which (a broken link) the walk
 * never reports: a link to nothing has nothing to read.
 */
export const UNREAD_REASONS = {
  fileNotReadable: 'this user cannot read the file',
  dirNotListable: 'this user cannot list the directory',
  parentNotSearchable: 'inside a directory this user cannot search',
  linkLoop: 'symbolic link in a loop, or in a chain too long to follow',
  linkTargetUnreachable: 'symbolic link to a path this user cannot reach',
  readError: 'opening it failed with an error other than permissions',
} as const;

export type SkipReason = keyof typeof SOURCE_SKIP_REASONS;
export type UnreadReason = keyof typeof UNREAD_REASONS;
/** Every reason a listed path can carry. One value each, one text per value. */
export type CoverageReason = SkipReason | UnreadReason;
export type SkipReasonText = (typeof SOURCE_SKIP_REASONS)[SkipReason];
export type UnreadReasonText = (typeof UNREAD_REASONS)[UnreadReason];

/** What the filesystem says about one path, gathered without opening it. */
export interface PathFacts {
  /** `lstat` of the path itself, or the error code it failed with. */
  lstat: fs.Stats | string;
  /** `stat`, which follows a link, or the error code it failed with. */
  stat: fs.Stats | string;
  /** `access` for reading, and for searching too when `stat` found a directory. */
  access: boolean;
  /** The real path lies inside the scan root. */
  insideRoot: boolean;
}

export function readPathFacts(absPath: string, rootReal: string): PathFacts {
  const codeOf = (err: unknown) => (err as NodeJS.ErrnoException)?.code ?? 'EIO';
  let lstat: fs.Stats | string;
  let stat: fs.Stats | string;
  try { lstat = fs.lstatSync(absPath); } catch (err) { lstat = codeOf(err); }
  try { stat = fs.statSync(absPath); } catch (err) { stat = codeOf(err); }
  let access = false;
  if (typeof stat !== 'string') {
    const mode = stat.isDirectory() ? fs.constants.R_OK | fs.constants.X_OK : fs.constants.R_OK;
    try { fs.accessSync(absPath, mode); access = true; } catch { /* access stays false */ }
  }
  const real = realpathOrNull(absPath);
  return { lstat, stat, access, insideRoot: real !== null && isWithinRoot(real, rootReal) };
}

/**
 * The reason a listed path carries. `rule` is the walk rule that skipped it,
 * or null for a path the walk meant to read and could not.
 *
 * Every reason the scan prints comes out of here, so a reason cannot say more
 * than the walk rule and the filesystem do.
 */
export function coverageReason(rule: SkipReason, facts: PathFacts): SkipReason;
export function coverageReason(rule: null, facts: PathFacts): UnreadReason;
export function coverageReason(rule: SkipReason | null, facts: PathFacts): CoverageReason {
  const { lstat, stat, access, insideRoot } = facts;
  if (rule !== null) {
    if (rule !== 'hiddenCache' && rule !== 'worktrees') return rule;
    // The key and config walks stop at a directory link out of the root before
    // they try to list it, so that answer comes first.
    if (typeof lstat !== 'string' && lstat.isSymbolicLink() && typeof stat !== 'string' && !insideRoot) {
      return 'hiddenDirOutsideRoot';
    }
    return typeof stat === 'string' || !access ? 'hiddenDirClosed' : rule;
  }
  // `lstat` itself fails only on the way TO the path: a directory above it
  // that cannot be searched, or a loop among the links above it.
  if (typeof lstat === 'string') {
    if (lstat === 'EACCES') return 'parentNotSearchable';
    return lstat === 'ELOOP' ? 'linkLoop' : 'readError';
  }
  if (typeof stat === 'string') {
    if (stat === 'ELOOP') return 'linkLoop';
    return stat === 'EACCES' ? 'linkTargetUnreachable' : 'readError';
  }
  if (!access) return stat.isDirectory() ? 'dirNotListable' : 'fileNotReadable';
  return 'readError';
}

/** The reason text for a path in `unreadable`, as listed relative to `projectDir`. */
export function unreadReason(projectDir: string, listedPath: string): UnreadReasonText {
  const rootReal = realpathOrNull(projectDir) ?? path.resolve(projectDir);
  return UNREAD_REASONS[coverageReason(null, readPathFacts(path.resolve(projectDir, listedPath), rootReal))];
}

/** Samples are for a human; the counts carry the magnitude. */
const SKIP_SAMPLE_CAP = 20;

export function emptySkips(): CoverageSkips {
  return { dirs: [], files: [], dirCount: 0, fileCount: 0 };
}

/**
 * Classify a directory entry, FOLLOWING symlinks.
 *
 * `Dirent.isDirectory()` / `isFile()` are lstat-based: a symlink is NEITHER, so
 * classifying from the Dirent alone drops every symlinked entry on the floor.
 * 0.21.0 reached config files through `existsSync`/`statSync`, which follow
 * links; making the config walk recursive in 0.21.1 silently removed symlink
 * support, so a symlinked `.claude/` — what a dotfile manager or a shared
 * monorepo config produces — reported "No hardcoded credentials found."
 *
 * Returns 'skip' for a broken link, a socket/fifo/device, or anything we cannot
 * stat, so an unresolvable link is dropped rather than throwing mid-walk.
 */
function classifyEntry(entryPath: string, entry: fs.Dirent): 'dir' | 'file' | 'skip' | 'unreadable' {
  if (entry.isDirectory()) return 'dir';
  if (entry.isFile()) return 'file';
  // Sockets, FIFOs and device files are deliberately never opened: a read on a
  // FIFO blocks forever, so this is what keeps a config-named pipe from hanging
  // the scan.
  if (!entry.isSymbolicLink()) return 'skip';
  try {
    const target = fs.statSync(entryPath); // follows the link
    if (target.isDirectory()) return 'dir';
    if (target.isFile()) return 'file';
    return 'skip';
  } catch (err) {
    // A link we cannot resolve splits two ways. ENOENT is a broken link and
    // there is nothing to scan, so it is genuinely a skip. EACCES/ELOOP/EMFILE
    // mean something IS there and we could not look at it, which must be
    // reported rather than counted as clean.
    // ENOENT is a broken link and ENOTDIR is a link through a non-directory —
    // both point at nothing, so there is no content we failed to examine.
    // EACCES/ELOOP/EMFILE mean something IS there that we could not look at.
    const code = (err as NodeJS.ErrnoException)?.code;
    return code === 'ENOENT' || code === 'ENOTDIR' ? 'skip' : 'unreadable';
  }
}

/**
 * Cycle guard for a symlink-following walk.
 *
 * Following symlinks without one trades a fail-open for a hang: no walker has a
 * depth bound, so `a/loop -> a` recurses until the file cap and a cross-linked
 * pair of directories never terminates. Keyed on the RESOLVED real path, so two
 * routes to the same directory are walked once. Returns false if already seen.
 */
/**
 * `.env` suffixes that hold placeholders by convention and are meant to be
 * committed. Everything else after `.env.` is treated as a REAL env file.
 *
 * The polarity matters: an unrecognised `.env.whatever` is scanned rather than
 * skipped, so the unknown case fails closed. The previous allowlist named only
 * `.env` and `.env.local`, which missed `.env.development`, `.env.production`,
 * `.env.staging`, `.env.test` and `.env.prod` — the exact set the CLAUDE.md
 * block Secretless itself installs tells the user it protects (#116 P2-3).
 */
export const ENV_TEMPLATE_SUFFIXES: ReadonlySet<string> = new Set(['example', 'sample', 'template', 'dist']);

/**
 * True for a real `.env` file; false for a committed template.
 *
 * Case-insensitive throughout, like the config-name matcher: on macOS and
 * Windows `.ENV.STAGING` and `.env.staging` are one file. Only the template
 * marker used to be lowered, so rejection ignored case while recognition did
 * not, and a real `.Env.Production` was never scanned (#120).
 */
export function isEnvFile(basename: string): boolean {
  const name = basename.toLowerCase();
  if (name === '.env') return true;
  if (!name.startsWith('.env.')) return false;
  // A template marker in ANY segment wins, so `.env.example.local` stays out.
  return !name
    .slice('.env.'.length)
    .split('.')
    .some(segment => ENV_TEMPLATE_SUFFIXES.has(segment));
}

interface ConfigNameMatcher {
  byBasename: Set<string>;
  bySuffix: string[];
}

/** Split the config catalogs into basename and path-suffix forms, lowercased once. */
function buildConfigNameMatcher(): ConfigNameMatcher {
  const byBasename = new Set<string>();
  const bySuffix: string[] = [];
  for (const entry of CONFIG_FILES) {
    if (entry.includes('/')) bySuffix.push(entry.toLowerCase());
    else byBasename.add(entry.toLowerCase());
  }
  return { byBasename, bySuffix };
}

/**
 * Does this entry name a project config file?
 *
 * Matched case-insensitively: on a case-insensitive filesystem (macOS, Windows)
 * `Claude.md` and `CLAUDE.md` are the SAME file to the OS but not to an
 * exact-match Set, so an exact comparison skipped a file the user can plainly
 * see. On a case-sensitive filesystem this widens the match to case variants of
 * the same config name, which is the safe direction for a scanner.
 */
function matchesConfigName(
  basename: string,
  relFromRoot: string,
  matcher: ConfigNameMatcher,
): boolean {
  if (matcher.byBasename.has(basename.toLowerCase())) return true;
  if (isEnvFile(basename)) return true;
  const lowerRel = relFromRoot.toLowerCase();
  return matcher.bySuffix.some(sfx => lowerRel === sfx || lowerRel.endsWith('/' + sfx));
}

/**
 * Upper bound on directories dequeued in one walk.
 *
 * Cycle detection is per-ancestry (see `walkTree`), which deliberately allows
 * the same real directory to be reached by two different paths — but that means
 * a fan of N links to one subtree costs N traversals. `maxFiles` alone does not
 * bound this, because a fan of directories yielding no matching files collects
 * nothing while still walking. Exhausting this budget sets `truncated`, so the
 * bound is reported rather than silently applied.
 */
const MAX_DIRS_VISITED = 50_000;

/** The MAX_DIRS_VISITED a walk uses; only {@link withDirsVisitedBudget} changes it. */
let dirsVisitedBudget = MAX_DIRS_VISITED;

/**
 * @internal Test only: run `fn` with a lower MAX_DIRS_VISITED, restored on
 * return. A tree that exceeds the real budget is fifty thousand directories,
 * so without this the stop on that budget went untested.
 */
export function withDirsVisitedBudget<T>(budget: number, fn: () => T): T {
  const saved = dirsVisitedBudget;
  dirsVisitedBudget = budget;
  try {
    return fn();
  } finally {
    dirsVisitedBudget = saved;
  }
}

/**
 * How many distinct paths to the SAME real directory one walk will follow.
 *
 * Per-ancestry cycle detection deliberately allows a directory to be reached by
 * more than one path — that is what makes `pkg/.claude -> shared/` work when
 * `shared/` is also in the tree. But the number of paths through a lattice of
 * links is exponential: a hand-built 31-directory fixture produced 2,047 walks,
 * 45s of wall clock and 289 MB of RSS. A repo is a hostile input to a scanner,
 * so the multiplicity is capped. Twelve packages each linking to a shared
 * directory is the realistic high-water mark; well past that is pathological,
 * and crossing the cap sets `truncated` rather than passing silently.
 */
const MAX_PATHS_PER_DIR = 32;

/**
 * Is `target` the root itself or inside it? Both must already be real paths.
 *
 * `path.sep` is appended for the prefix test so `/tmp/rootx` is not read as
 * inside `/tmp/root` — but a root of `/` already ends in the separator, and
 * appending a second one made every absolute path test as OUTSIDE it.
 *
 * A pure string comparison is sound here ONLY because both sides come from
 * `realpathOrNull`, which resolves `..` and every intermediate symlink first: a
 * traversal string cannot survive that, so `<root>/link -> <root>/../../etc`
 * arrives as `/etc` and is rejected on its own merits.
 */
function isWithinRoot(target: string, rootReal: string): boolean {
  const prefix = rootReal.endsWith(path.sep) ? rootReal : rootReal + path.sep;
  return target === rootReal || target.startsWith(prefix);
}

/**
 * Resolve a path to its real location, or null when it cannot be resolved.
 *
 * `realpathSync.native` rather than `realpathSync`, because it also canonicalises
 * CASE. That matters for `isWithinRoot`: on a case-insensitive volume, scanning
 * `ROOT` when the directory is `root` otherwise leaves an in-tree link resolving
 * to a differently-cased string that fails the prefix test, silently dropping
 * the subtree it reaches.
 *
 * This replaced a platform-keyed case-insensitive comparison, which was wrong in
 * the other direction: macOS can host case-SENSITIVE volumes, where `/repo` and
 * /REPO` are genuinely different directories and lowercasing would have let a
 * link escape the root. Asking the filesystem is correct on both volume types;
 * guessing from `process.platform` is correct on neither reliably.
 */
function realpathOrNull(p: string): string | null {
  try {
    return fs.realpathSync.native(p);
  } catch {
    // `.native` can fail where the portable implementation succeeds (and is
    // absent on some runtimes), so fall back rather than treating a resolvable
    // path as unreadable.
    try {
      return fs.realpathSync(p);
    } catch {
      return null;
    }
  }
}

/**
 * True only when nothing is at `p`: `stat` failed with ENOENT, or with ENOTDIR
 * (a name on the way to it is not a directory). `fs.existsSync` is false for
 * every failed lookup, EACCES and ELOOP included, where something is there
 * that this user cannot reach.
 */
function isAbsent(p: string): boolean {
  try {
    fs.statSync(p);
    return false;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    return code === 'ENOENT' || code === 'ENOTDIR';
  }
}

/**
 * Order two names by Unicode code point, which is the byte order of their UTF-8
 * form.
 *
 * Node documents no order for `readdir`. It returns byte order on macOS and
 * Linux only because its I/O layer sorts; APFS and ext4 themselves return hash
 * order. Byte order keeps those two platforms' output as it was. Not `<`, which
 * compares UTF-16 units and puts an emoji before U+FF21 (fullwidth A), and not
 * `localeCompare`, whose result moves with the locale.
 */
function compareCodePoints(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a.codePointAt(i)!;
    const y = b.codePointAt(i)!;
    if (x !== y) return x - y;
    // Equal astral code points: both strings hold the same surrogate pair.
    if (x > 0xffff) i++;
  }
  return a.length - b.length;
}

/** Per-walk behaviour: which directories to descend, which files to keep. */
interface WalkSpec {
  /**
   * The rule that skips this directory, or false to descend.
   *
   * It returns the reason rather than a boolean so the disclosure and the
   * decision come from the same expression. A separate `skipReason` predicate
   * beside a boolean `skipDir` would be two statements of one rule, free to
   * drift — and a disclosure that disagrees with the walk is worse than none.
   * The text printed for it is `coverageReason`'s.
   */
  skipDir(name: string, relFromRoot: string): SkipReason | false;
  /**
   * The rule that rejects this file, or false to keep it. Same rule.
   * `listedFromRoot` is the path as a report lists it (see `walkTree`).
   */
  rejectFile(name: string, relFromRoot: string, listedFromRoot: string): SkipReason | false;
  /**
   * True when another walk reads this file, so this one leaves it out WITHOUT
   * disclosing it: `config.json` is read by the config walk, and counting it
   * as a file the source walk "did not open" reported a scanned file as
   * skipped (#124).
   */
  coveredElsewhere?(name: string, relFromRoot: string): boolean;
  /**
   * What to push into `files` — an absolute path or a root-relative one.
   * The root-relative one is `listedFromRoot`, never `relFromRoot`: a caller
   * opens it, and `relFromRoot` names a different path for a file whose name
   * holds a backslash. The config walk collected it, so `.env.back\slash` was
   * opened as `.env.back/slash`, found absent, and neither read nor listed.
   */
  collect(entryPath: string, listedFromRoot: string): string;
  /**
   * Record what was skipped. Only the SOURCE walk sets this: all three walks
   * prune `node_modules` and friends, so disclosing every walk would treble the
   * count and bury the one entry a user needs to see.
   */
  discloseSkips?: boolean;
  /**
   * Visit every directory reached without passing through a dot-directory
   * before any directory at or under one. Only the SOURCE walk sets this.
   *
   * That walk pruned every dot-directory until #144. Once it entered them, a
   * dot-directory sorted ahead of `src/` and its files filled `maxFiles` first,
   * so a capped scan dropped a finding the previous release reported (#397).
   * With this set, the files outside dot-directories are collected in the same
   * order as before #144, and a cap stop drops files inside dot-directories
   * first. The key and config walks always entered dot-directories, so their
   * order stays as it was.
   */
  hiddenDirsLast?: boolean;
}

/**
 * One breadth-first tree walk, shared by all three walkers.
 *
 * The three used to be separate copies of the same loop, and they drifted: the
 * config copy gained recursion while losing the symlink support the others
 * never had, which is the defect this release exists to fix. Sharing the
 * traversal means a fix to link handling, cycle safety or coverage reporting
 * lands in all three by construction; only the filters differ.
 *
 * **Cycle detection is per-ancestry, not global.** A global visited-realpath set
 * terminates just as well, but it also drops a directory reachable by a SECOND
 * path once the first has been seen — and which path wins depends on readdir
 * order. That silently re-broke the headline case: with `pkg/.claude -> shared/`
 * where `shared/` is also in the tree, BFS reaches `shared/` first, marks the
 * realpath seen, then skips `pkg/.claude` — and only the `.claude` path matches
 * the `.claude/settings.json` config entry. A directory is a cycle only when it
 * appears in its OWN ancestor chain, which is what is checked here.
 */
function walkTree(dir: string, maxFiles: number, spec: WalkSpec): WalkResult {
  const files: string[] = [];
  const unreadable: string[] = [];
  const skips = emptySkips();
  const outOfRoot: string[] = [];
  let truncated = false;
  let eligible = 0;
  let budgetExceeded = false;

  const rootReal = realpathOrNull(dir) ?? path.resolve(dir);
  // Each entry carries the realpath chain of the directories above it, and
  // whether it is a dot-directory or lies under one. Under `hiddenDirsLast`
  // those wait in `deferred` until `queue` is empty.
  type QueuedDir = { dir: string; ancestors: string[]; hidden: boolean };
  const queue: QueuedDir[] = [{ dir, ancestors: [], hidden: false }];
  const deferred: QueuedDir[] = [];
  const visitsByReal = new Map<string, number>();
  let dirsVisited = 0;

  const rel = (p: string) => path.relative(dir, p).replace(/\\/g, '/');
  // What the lists of skipped, unread and unfollowed paths record. `rel` above
  // is what the filters match against, and it turns every backslash into `/`,
  // which on POSIX names a different path: a file named `n\x.txt` was listed,
  // and offered as `Scan one:`, as `n/x.txt`. A listed path changes only the
  // platform's own separator.
  const listed = (p: string) => withSlashSeparators(path.relative(dir, p));
  // The text of a disclosed skip. Only the sampled entries pay for the
  // filesystem calls, so the count can keep rising without them.
  const reasonText = (rule: SkipReason, entryPath: string): SkipReasonText =>
    SOURCE_SKIP_REASONS[coverageReason(rule, readPathFacts(entryPath, rootReal))];

  // `truncated` is a claim about FILES: a candidate that passed every filter
  // and was dropped because the cap was full. Reaching the cap with directories
  // still queued is not that — they may hold nothing — so the walk goes on
  // reading directories (never files) past the cap. A tree of exactly
  // `maxFiles` files plus an empty directory used to report "Scan incomplete"
  // and exit 1 with nothing unscanned (#120). Walking on to the end also gives
  // `eligible`, the count a `--max-files` suggestion is sized from. The extra
  // work is bounded by MAX_DIRS_VISITED, which still truncates.
  while (queue.length > 0 || deferred.length > 0) {
    if (dirsVisited >= dirsVisitedBudget) { truncated = true; budgetExceeded = true; break; }
    const { dir: current, ancestors, hidden } = (queue.length > 0 ? queue : deferred).shift()!;

    const currentReal = realpathOrNull(current);
    if (currentReal === null) { unreadable.push(listed(current)); continue; }
    // A directory inside its own ancestry is a genuine loop.
    if (ancestors.includes(currentReal)) continue;
    // Bound how many distinct routes to one directory we follow (see the
    // constant): the path count through a link lattice is exponential.
    const seenCount = visitsByReal.get(currentReal) ?? 0;
    if (seenCount >= MAX_PATHS_PER_DIR) { truncated = true; budgetExceeded = true; continue; }
    visitsByReal.set(currentReal, seenCount + 1);
    const childAncestors = [...ancestors, currentReal];
    dirsVisited += 1;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      // Was a bare `continue`: an unreadable directory vanished from the result
      // while the scan still reported itself complete.
      unreadable.push(listed(current));
      continue;
    }
    // The samples and the `Scan one:` command name the first entries the walk
    // meets, so the order is the walk's own rather than whatever `readdir`
    // returned. It also settles which files fill `maxFiles` on a truncated scan.
    entries.sort((a, b) => compareCodePoints(a.name, b.name));

    for (const entry of entries) {
      const entryPath = path.join(current, entry.name);
      const relFromRoot = rel(entryPath);
      const listedFromRoot = listed(entryPath);
      const kind = classifyEntry(entryPath, entry);

      if (kind === 'unreadable') { unreadable.push(listedFromRoot); continue; }
      if (kind === 'skip') continue;

      if (kind === 'dir') {
        // Filters run BEFORE containment, so a pruned tree never produces a
        // coverage warning. Reporting `node_modules -> /pnpm-store` as an
        // unfollowed boundary — and telling the user to go scan it — is noise
        // about a directory that was never going to be walked.
        const skipReason = spec.skipDir(entry.name, relFromRoot);
        if (skipReason) {
          if (spec.discloseSkips) {
            skips.dirCount++;
            if (skips.dirs.length < SKIP_SAMPLE_CAP) skips.dirs.push({ path: listedFromRoot, reason: reasonText(skipReason, entryPath) });
          }
          continue;
        }

        // Containment applies to DIRECTORY links only. Following one is
        // unbounded: a repo holding `link -> $HOME` would pull the whole home
        // directory into the scan.
        if (entry.isSymbolicLink()) {
          const target = realpathOrNull(entryPath);
          if (target === null) continue;
          if (!isWithinRoot(target, rootReal)) { outOfRoot.push(listedFromRoot); continue; }
        }

        const childHidden = hidden || entry.name.startsWith('.');
        (spec.hiddenDirsLast && childHidden ? deferred : queue)
          .push({ dir: entryPath, ancestors: childAncestors, hidden: childHidden });
      } else {
        if (spec.coveredElsewhere?.(entry.name, relFromRoot)) continue;
        const rejectReason = spec.rejectFile(entry.name, relFromRoot, listedFromRoot);
        if (rejectReason) {
          if (spec.discloseSkips) {
            skips.fileCount++;
            if (skips.files.length < SKIP_SAMPLE_CAP) skips.files.push({ path: listedFromRoot, reason: reasonText(rejectReason, entryPath) });
          }
          continue;
        }
        // A symlinked FILE is NOT contained, even out of the root. Reading one
        // file the repository explicitly names is bounded work, and it is the
        // shape every dotfile manager produces: `pkg/.env -> ../../shared/.env`
        // under stow/chezmoi, or a package pointing at the monorepo root env.
        // Refusing it would drop a credential the repo is asking us to treat as
        // its own — the opposite of the unbounded-traversal risk above.
        // Checked AFTER the filters, so only a real candidate trips the cap.
        eligible += 1;
        if (files.length >= maxFiles) { truncated = true; continue; }
        files.push(spec.collect(entryPath, listedFromRoot));
      }
    }
  }

  return { files, truncated, eligible, budgetExceeded, unreadable, outOfRoot, skips };
}

/**
 * Walk a directory tree and return standalone key files (`*.pem`, `*.key`, `*.p12`, ...).
 * Mirrors walkSourceFiles' directory pruning, test-skipping, and ignore semantics so a
 * key file in node_modules/ or a skipped test dir behaves the same as a source file there.
 */
function walkKeyFiles(
  dir: string,
  maxFiles: number,
  includeTests: boolean,
  ignore: IgnoreMatcher | null,
): WalkResult {
  return walkTree(dir, maxFiles, {
    // Key files commonly live in HIDDEN directories (`.ssh/`, `.certs/`, `.aws/`),
    // so this walk enters the hidden caches the source walk prunes too. We still
    // skip the heavy/irrelevant ones (node_modules, .git) and honor the ignore matcher.
    // This walk discloses nothing, so these values are never printed; they
    // come from the same set so a walk cannot return a free-form reason.
    skipDir: (name, rel) =>
      (SOURCE_SKIP_DIRS.has(name) && 'buildOutput')
      || (name === '.git' && 'gitMetadata')
      || (!includeTests && TEST_DIRS.has(name) && 'testDir')
      || (!!(ignore && ignore.matches(rel + '/.')) && 'ignoreRule'),
    rejectFile: (name, rel) =>
      (!KEY_FILE_EXTENSIONS.has(path.extname(name).toLowerCase()) && 'unsupportedType')
      || (!(includeTests || !isTestFile(name)) && 'testFile')
      || (!!(ignore && ignore.matches(rel)) && 'ignoreRule'),
    collect: (entryPath) => entryPath,
  });
}

function walkConfigFiles(
  dir: string,
  maxFiles: number,
  includeTests: boolean,
  ignore: IgnoreMatcher | null,
): WalkResult {
  const matcher = buildConfigNameMatcher();
  return walkTree(dir, maxFiles, {
    // Never printed, like the key walk's.
    skipDir: (name, rel) =>
      (SOURCE_SKIP_DIRS.has(name) && 'buildOutput')
      || (name === '.git' && 'gitMetadata')
      || (!includeTests && TEST_DIRS.has(name) && 'testDir')
      || (!!(ignore && ignore.matches(rel + '/.')) && 'ignoreRule'),
    rejectFile: (name, rel) =>
      (!matchesConfigName(name, rel, matcher) && 'unsupportedType')
      || (!!(ignore && ignore.matches(rel)) && 'ignoreRule'),
    collect: (_entryPath, listedRel) => listedRel,
  });
}

function walkSourceFiles(
  dir: string,
  maxFiles: number,
  includeTests: boolean,
  ignore: IgnoreMatcher | null,
  includeConfig = false,
  ignoreDefaults: IgnoreMatcher | null = null,
): WalkResult & { unscannedConfig: { count: number; files: string[] }; ignoreFileExcluded: number } {
  const configMatcher = buildConfigNameMatcher();
  const unscannedConfig = { count: 0, files: [] as string[] };
  // The ignore rule's reason, counted in `ignoreFileExcluded` when the
  // default-ignore list alone does not match `matched`: then the scanned
  // tree's own ignore file is what kept the path from being read (#414).
  let ignoreFileExcluded = 0;
  const byIgnoreRule = (matched: string): 'ignoreRule' => {
    if (ignoreDefaults && !ignoreDefaults.matches(matched)) ignoreFileExcluded++;
    return 'ignoreRule';
  };
  const walk = walkTree(dir, maxFiles, {
    // Prune whole-tree ignored directories. The matcher's directory patterns
    // end with `/`, so we test the dir path with a trailing segment.
    // `.git` is tested BEFORE the build-output set purely so the disclosure
    // names it accurately: it is in SOURCE_SKIP_DIRS, so without this arm it
    // reported as "dependency or build output", which it is not. The set that
    // skips is unchanged; only the reason differs. Every other dot-directory
    // is entered (#144) except the hidden caches and worktree directories,
    // which this walk alone prunes. One an ignore rule covers is entered by
    // no walk (the key and config walks apply the rule too), so it falls
    // through to the ignore rule's reason. One no ignore rule covers is
    // `hiddenCache` or `worktrees`, which `coverageReason` narrows by what the
    // filesystem says: the key and config walks read inside it, but not
    // through a link out of the root or into a directory they cannot open.
    // Dot-directories are entered after every other directory, so their files
    // reach the cap last (#397).
    hiddenDirsLast: true,
    skipDir: (name, rel) => {
      const ignored = !!(ignore && ignore.matches(rel + '/.'));
      return (name === '.git' && 'gitMetadata')
        || (SOURCE_SKIP_DIRS.has(name) && 'buildOutput')
        || (!ignored && HIDDEN_CACHE_DIRS.has(name) && 'hiddenCache')
        || (!ignored && WORKTREE_DIRS.has(name) && 'worktrees')
        || (!includeTests && TEST_DIRS.has(name) && 'testDir')
        || (ignored && byIgnoreRule(rel + '/.'));
    },
    // The config walk reads these (it applies the ignore rule itself). So does
    // the key walk, under the test-file and ignore rules this walk applies,
    // in every directory this walk enters: a `.secretless-bundle` it reported
    // as a finding was also listed as "not opened: unsupported file type",
    // with a `Scan one:` line that reported it again (#341).
    coveredElsewhere: (name, rel) => {
      if (ignore && ignore.matches(rel)) return false;
      if (matchesConfigName(name, rel, configMatcher)) return true;
      const ext = path.extname(name).toLowerCase();
      return KEY_FILE_EXTENSIONS.has(ext) && !SOURCE_FILE_EXTENSIONS.has(ext)
        && (includeTests || !isTestFile(name));
    },
    rejectFile: (name, rel, listedRel) => {
      // #124 — a config-format file off the CONFIG_FILES list was "unsupported
      // file type" to this walk and unknown to the config walk: read by
      // neither, and a clean scan said nothing. It now takes the test and
      // ignore rules like a source file, then is scanned (--include-config) or
      // reported as a boundary with its own reason.
      // Lowered like the key-file and config matchers: `Legacy.JS` is a
      // JavaScript file, and an exact match never opened it (#120).
      const ext = path.extname(name).toLowerCase();
      const supported = SOURCE_FILE_EXTENSIONS.has(ext);
      const configShaped = !supported && isConfigShaped(name);
      if (!supported && !configShaped) {
        // A key file reaches here only when the test-file or ignore rule
        // stopped the key walk too (otherwise it is covered elsewhere). That
        // rule is why no walk opened it, and its flag is the one that does:
        // "unsupported file type" named a type the key walk reads.
        if (KEY_FILE_EXTENSIONS.has(ext)) {
          if (!(includeTests || !isTestFile(name))) return 'testFile';
          if (ignore && ignore.matches(rel)) return byIgnoreRule(rel);
        }
        // Likewise a file the config walk reads by name, such as `.env`:
        // it reaches here only when the ignore rule stopped that walk, so
        // "unsupported file type" hid that a rule kept it from being read.
        if (ignore && ignore.matches(rel) && matchesConfigName(name, rel, configMatcher)) return byIgnoreRule(rel);
        return 'unsupportedType';
      }
      if (!(includeTests || !isTestFile(name))) return 'testFile';
      if (ignore && ignore.matches(rel)) return byIgnoreRule(rel);
      if (configShaped && !includeConfig) {
        unscannedConfig.count++;
        if (unscannedConfig.files.length < SKIP_SAMPLE_CAP) unscannedConfig.files.push(listedRel);
        return 'configNotListed';
      }
      return false;
    },
    collect: (entryPath) => entryPath,
    discloseSkips: true,
  });
  return { ...walk, unscannedConfig, ignoreFileExcluded };
}

/**
 * @internal What a plain `scan` of `projectDir` would count in
 * `ignoreFileExcluded` were `lines` its `.secretlessignore`: the paths the
 * source walk leaves unread for those lines and would read under the
 * default-ignore list alone. The walk and matchers `scan` builds, so the count
 * is the one `scan` reports for those lines; it reads directory listings, not
 * file contents. `ignore` asks it whether the line it wrote makes `scan` exit 1.
 */
export function countIgnoreFileExcluded(projectDir: string, lines: readonly string[]): number {
  const defaults = defaultIgnoreLines();
  return walkSourceFiles(projectDir, 5000, false, buildMatcher([...defaults, ...lines]), false, buildMatcher(defaults))
    .ignoreFileExcluded;
}
