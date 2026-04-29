/**
 * `.secretlessignore` parser — gitignore-style globs that skip paths from
 * scanning. Designed to suppress real-world false positives where intentional
 * fixture credentials live (test fixtures, demo scripts, e2e seeds).
 *
 * The user file is additive on top of a default-ignore list. Each default
 * path is justified by a real-world FP class observed during dogfooding;
 * see `handoff_secretless_ai_0_16_4_pickup.md` for the FP table.
 *
 * Negative patterns (`!pattern`) override defaults — a user can re-enable
 * scanning for a default-ignored path by adding `!docs/vhs/` to their
 * `.secretlessignore`.
 */

import * as fs from 'fs';
import * as path from 'path';

/**
 * Default-ignore list. Every entry maps to a real-world false-positive
 * class. Do NOT add speculatively.
 *
 * - `__tests__/`, `__fixtures__/`, `test/`, `tests/`, `test-server/` —
 *   fixture dirs (closes adversarial-fixture FPs from hackmyagent dogfooding)
 * - `docs/vhs/` — VHS demo scripts (sk-proj-fake + postgres://demo creds)
 * - `examples/` — by-convention example code
 * - `e2e/` — end-to-end test dirs
 * - `.golden/` — fixture golden files (HMA convention)
 * - `node_modules/`, `dist/`, `build/` — generated artifacts (defensive
 *   layer over scan.ts SOURCE_SKIP_DIRS)
 */
export const DEFAULT_IGNORE_PATTERNS: readonly string[] = Object.freeze([
  '__tests__/',
  '__fixtures__/',
  'test/',
  'tests/',
  'test-server/',
  'docs/vhs/',
  'examples/',
  'e2e/',
  '.golden/',
  'node_modules/',
  'dist/',
  'build/',
]);

/** Match function for a relative POSIX path. */
export interface IgnoreMatcher {
  /** Returns true if the relative path is ignored. */
  matches(relativePath: string): boolean;
  /** Number of patterns active (defaults + user, after negatives applied). */
  patternCount: number;
}

interface CompiledPattern {
  /** Original literal pattern (debug only). */
  source: string;
  /** Compiled regex. */
  regex: RegExp;
  /** True for `!pattern` negations — re-includes a previously ignored path. */
  negate: boolean;
  /** True if pattern ends with `/` — directory-only (matches anything under it). */
  dirOnly: boolean;
}

/**
 * Parse a single gitignore-style line into a CompiledPattern.
 * Returns null for blank lines and comments.
 *
 * Supported syntax (subset of gitignore):
 * - `#` comment lines
 * - blank lines ignored
 * - leading `!` negates
 * - trailing `/` matches directory + everything below
 * - `*` matches any character except `/`
 * - `**` matches any number of directories (including zero)
 * - `?` matches one character except `/`
 * - leading `/` anchors to repo root
 *
 * Path traversal (`..`) and absolute system paths are not allowed —
 * patterns are interpreted as repo-relative globs only.
 */
function compilePattern(rawLine: string): CompiledPattern | null {
  let line = rawLine.trim();
  if (!line) return null;
  if (line.startsWith('#')) return null;

  let negate = false;
  if (line.startsWith('!')) {
    negate = true;
    line = line.slice(1);
  }

  // Reject path traversal — security guard. A pattern like `../foo` would
  // otherwise resolve outside the repo root.
  if (line.includes('..')) return null;

  // A leading `/` anchors to repo root and is otherwise stripped. Track this
  // separately from "the pattern contains a slash internally" so that
  // `/build/` anchors to root while `build/` matches at any depth.
  let anchoredToRoot = false;
  if (line.startsWith('/')) {
    anchoredToRoot = true;
    while (line.startsWith('/')) line = line.slice(1);
  }

  const dirOnly = line.endsWith('/');
  if (dirOnly) line = line.slice(0, -1);
  if (!line) return null;

  // Convert glob to regex. Escape regex metacharacters except `*`, `?`.
  // Two passes: `**` first, then `*`, so we don't double-encode.
  let regexSrc = '';
  let i = 0;
  while (i < line.length) {
    const ch = line[i];
    if (ch === '*' && line[i + 1] === '*') {
      // `**` — match zero or more path segments. Consume optional trailing `/`.
      regexSrc += '(?:.*)';
      i += 2;
      if (line[i] === '/') i++;
    } else if (ch === '*') {
      regexSrc += '[^/]*';
      i++;
    } else if (ch === '?') {
      regexSrc += '[^/]';
      i++;
    } else if (/[.+^${}()|[\]\\]/.test(ch)) {
      regexSrc += '\\' + ch;
      i++;
    } else {
      regexSrc += ch;
      i++;
    }
  }

  // Anchoring: a pattern with an internal slash (or leading `/`) anchors to
  // root; a slash-free pattern matches at any depth (gitignore behavior).
  const hasInternalSlash = line.includes('/');
  const anchorPrefix = (anchoredToRoot || hasInternalSlash) ? '^' : '^(?:.*?/)?';
  // `dir/` matches the directory contents — we require a trailing `/something`.
  // Bare `name` (no trailing slash) matches the file itself or anything below.
  const anchorSuffix = dirOnly ? '/.*$' : '(?:/.*)?$';

  return {
    source: rawLine,
    regex: new RegExp(anchorPrefix + regexSrc + anchorSuffix),
    negate,
    dirOnly,
  };
}

function compileAll(lines: readonly string[]): CompiledPattern[] {
  const out: CompiledPattern[] = [];
  for (const line of lines) {
    const cp = compilePattern(line);
    if (cp) out.push(cp);
  }
  return out;
}

/**
 * Normalize a relative path for matching:
 * - Convert backslashes to forward slashes (Windows compatibility).
 * - Remove leading `./`.
 * - Reject any input that traverses out of root via `..`.
 *
 * Returns null if the path is not safe to match (caller should treat as
 * "do not ignore" — we never block a scan due to a malformed path).
 */
function normalize(relativePath: string): string | null {
  let p = relativePath.replace(/\\/g, '/');
  while (p.startsWith('./')) p = p.slice(2);
  if (p === '.' || p === '') return null;
  // Reject traversal — caller is using us as a safety filter, not a sandbox,
  // but we still don't want a `../foo` to match a default like `test/`.
  if (p.split('/').includes('..')) return null;
  return p;
}

export interface LoadOptions {
  /** Skip the default-ignore list (only the user file applies). */
  skipDefaults?: boolean;
}

/**
 * Build a matcher from `<rootDir>/.secretlessignore` plus the defaults.
 *
 * If the file does not exist, the defaults still apply (unless skipDefaults
 * is set). If the file is unreadable, we fall back to defaults silently —
 * scanning should never fail because of a malformed ignore file.
 */
export function loadSecretlessIgnore(rootDir: string, options?: LoadOptions): IgnoreMatcher {
  const lines: string[] = [];
  if (!options?.skipDefaults) {
    lines.push(...DEFAULT_IGNORE_PATTERNS);
  }

  const filePath = path.join(rootDir, '.secretlessignore');
  if (fs.existsSync(filePath)) {
    try {
      const stat = fs.statSync(filePath);
      // Defensive size cap — a 10MB ignore file is almost certainly broken.
      if (stat.isFile() && stat.size <= 1024 * 1024) {
        const content = fs.readFileSync(filePath, 'utf-8');
        for (const line of content.split(/\r?\n/)) {
          lines.push(line);
        }
      }
    } catch {
      // Fall through — defaults still apply.
    }
  }

  return buildMatcher(lines);
}

/**
 * Build a matcher from an explicit list of pattern strings. Useful for
 * tests and for callers that want to compose patterns programmatically
 * without touching disk.
 */
export function buildMatcher(patternLines: readonly string[]): IgnoreMatcher {
  const compiled = compileAll(patternLines);

  return {
    patternCount: compiled.length,
    matches(relativePath: string): boolean {
      const norm = normalize(relativePath);
      if (norm === null) return false;
      // Last-write-wins semantics: walk through compiled patterns in order
      // and let later negations override earlier ignores.
      let ignored = false;
      for (const cp of compiled) {
        if (cp.regex.test(norm)) {
          ignored = !cp.negate;
        }
      }
      return ignored;
    },
  };
}
