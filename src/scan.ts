/**
 * Scan project files for hardcoded credentials.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CREDENTIAL_PATTERNS, CONFIG_FILES, CREDENTIAL_PREFIX_QUICK_CHECK, SOURCE_FILE_EXTENSIONS, SOURCE_SKIP_DIRS, KNOWN_EXAMPLE_KEYS, PLACEHOLDER_INDICATORS, type CredentialPattern } from './patterns';
import { loadSecretlessIgnore, buildMatcher, DEFAULT_IGNORE_PATTERNS, type IgnoreMatcher } from './secretlessignore';
import { scoreFinding, type ConfidenceTier } from './confidence';

export interface ScanFinding {
  file: string;
  line: number;
  patternId: string;
  patternName: string;
  severity: 'critical' | 'high';
  preview: string;
  /** Actionable fix guidance for this finding */
  fix?: string;
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
}

/** Per-pattern fix guidance. Tells users exactly how to fix each finding. */
const FIX_GUIDANCE: Record<string, string> = {
  'anthropic': 'Move to env var ANTHROPIC_API_KEY. Rotate at console.anthropic.com > API Keys.',
  'openai-proj': 'Move to env var OPENAI_API_KEY. Rotate at platform.openai.com > API Keys.',
  'openai-legacy': 'Move to env var OPENAI_API_KEY. Rotate at platform.openai.com > API Keys.',
  'aws-access': 'Move to env var AWS_ACCESS_KEY_ID. Rotate in AWS IAM console.',
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

export interface ScanOptions {
  /** Scan global config files like ~/.claude/CLAUDE.md (default: true) */
  scanGlobal?: boolean;
  /** Scan source code files for hardcoded credentials (default: true) */
  scanSource?: boolean;
  /** Include test files in source scan (default: false) */
  includeTests?: boolean;
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
}

/** Optional out-param: counters the scan populates as a side channel. */
export interface ScanStats {
  /** Count of pattern matches suppressed as known examples / placeholders. */
  placeholdersSuppressed: number;
}

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

function isExampleInComment(line: string): boolean {
  const lineLC = line.toLowerCase();
  if (!lineLC.includes('example')) return false;
  if (lineLC.includes('//')) return true;
  if (lineLC.includes('#')) return true;
  if (lineLC.includes('/*')) return true;
  if (lineLC.includes('<!--')) return true;
  if (lineLC.includes('-->')) return true;
  if (lineLC.includes("'''")) return true;
  if (lineLC.includes('"""')) return true;
  // JSDoc continuation: line starts with optional whitespace then `*`.
  // Anchored so `x * y` (multiplication) does NOT match.
  if (/^\s*\*/.test(line)) return true;
  return false;
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
 * Scan project config files for hardcoded credentials.
 * Also scans global AI tool configs (e.g. ~/.claude/CLAUDE.md).
 * Returns findings sorted by severity then file.
 */
export function scan(projectDir: string, options?: ScanOptions, stats?: ScanStats): ScanFinding[] {
  // Shared per-match options for the credential-pattern call sites: reveal or count
  // placeholder-suppressed matches so the CLI can tell the user what was hidden.
  const matchOpts = {
    includeExamples: options?.showPlaceholders === true,
    onSuppressed: () => { if (stats) stats.placeholdersSuppressed += 1; },
  };
  const findings: ScanFinding[] = [];
  const scanGlobal = options?.scanGlobal !== false;

  // Resolve the ignore matcher. Default: load `<projectDir>/.secretlessignore`
  // plus the default-ignore list. `ignore: false` disables both.
  const ignore: IgnoreMatcher | null = (() => {
    if (options?.ignore === false) return null;
    if (options?.ignore && typeof options.ignore === 'object') return options.ignore;
    try {
      return loadSecretlessIgnore(projectDir);
    } catch {
      return null;
    }
  })();

  // Defaults-only matcher used to flag `--no-ignore` findings whose path is
  // in the default-ignore list. Built lazily because it's only useful when
  // `ignore === null` (otherwise the path is already filtered out).
  const fixtureMatcher: IgnoreMatcher | null = ignore === null
    ? buildMatcher(DEFAULT_IGNORE_PATTERNS as readonly string[])
    : null;

  const minConfidence = Math.max(0, Math.min(1, options?.minConfidence ?? 0));

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
    if (breakdown.score < minConfidence) return null;
    const looksLikeFixture = !!(fixtureMatcher && fixtureMatcher.matches(file.replace(/\\/g, '/')));
    return {
      file,
      line,
      patternId: pattern.id,
      patternName: pattern.name,
      severity,
      preview: masked.trim().substring(0, 80),
      fix: FIX_GUIDANCE[pattern.id],
      confidence: breakdown.score,
      confidenceTier: breakdown.tier,
      looksLikeFixture,
    };
  }

  // Scan global config files (keys in ~/.claude/CLAUDE.md are in every session's context)
  for (const global of (scanGlobal ? GLOBAL_CONFIG_FILES : [])) {
    const fullPath = path.join(global.dir, global.file);
    if (!fs.existsSync(fullPath)) continue;
    try {
      const stat = fs.statSync(fullPath);
      if (stat.size > 10 * 1024 * 1024 || !stat.isFile()) continue;
      const content = fs.readFileSync(fullPath, 'utf-8');
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 4096) continue;
        if (/\$\{[A-Z_]+\}/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) continue;
        for (const pattern of CREDENTIAL_PATTERNS) {
          const match = findRealMatch(line, pattern, matchOpts);
          if (match) {
            const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
            const masked = line.replace(globalRegex, `[${pattern.name} REDACTED]`);
            const finding = buildFinding(global.label, i + 1, pattern, match, 'critical', masked);
            if (finding) findings.push(finding);
            break;
          }
        }
      }
    } catch { /* skip */ }
  }

  // Scan project-level config files
  for (const configFile of CONFIG_FILES) {
    if (ignore && ignore.matches(configFile)) continue;
    const fullPath = path.join(projectDir, configFile);
    if (!fs.existsSync(fullPath)) continue;

    try {
      const stat = fs.statSync(fullPath);
      if (stat.size > 10 * 1024 * 1024) continue;
      if (!stat.isFile()) continue;

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
            // Mask the actual secret in the preview (replace ALL occurrences)
            const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
            const masked = line.replace(globalRegex, `[${pattern.name} REDACTED]`);

            const finding = buildFinding(configFile, i + 1, pattern, match, 'critical', masked);
            if (finding) findings.push(finding);
            break; // One finding per line
          }
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  // Scan source code files for hardcoded credentials
  if (options?.scanSource !== false) {
    const configFileSet = new Set(CONFIG_FILES);
    const maxFiles = options?.maxSourceFiles ?? 5000;
    const includeTests = options?.includeTests ?? false;
    const sourceFiles = walkSourceFiles(projectDir, maxFiles, includeTests, ignore);

    for (const filePath of sourceFiles) {
      const relPath = path.relative(projectDir, filePath);
      // Skip files already covered by config scan
      if (configFileSet.has(relPath)) continue;
      // Apply user/default ignore filter at file level too — defends
      // against entries inside an otherwise-walked directory.
      if (ignore && ignore.matches(relPath.replace(/\\/g, '/'))) continue;

      try {
        const stat = fs.statSync(filePath);
        if (stat.size > 1 * 1024 * 1024 || !stat.isFile()) continue; // 1MB limit for source

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
              const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
              const masked = line.replace(globalRegex, `[${pattern.name} REDACTED]`);

              const finding = buildFinding(relPath, i + 1, pattern, match, 'high', masked);
              if (finding) findings.push(finding);
              break;
            }
          }
        }
      } catch {
        // Skip unreadable files
      }
    }
  }

  // Scan standalone private-key files (server.key, id_rsa.pem, *.p12). These extensions
  // are in SECRET_FILE_PATTERNS (the block list) but were never fed to the scanner, so the
  // single most common private-key layout on disk reported clean. Text key files are
  // scanned for a PEM PRIVATE KEY block (public certs in .crt/.pem won't match); binary
  // PKCS#12 bundles (.p12/.pfx) are flagged by existence — they always carry a private key.
  if (options?.scanSource !== false) {
    const includeTests = options?.includeTests ?? false;
    const pemPattern = CREDENTIAL_PATTERNS.find(p => p.id === 'pem-private-key')!;
    const keyFiles = walkKeyFiles(projectDir, options?.maxSourceFiles ?? 5000, includeTests, ignore);
    for (const filePath of keyFiles) {
      const relPath = path.relative(projectDir, filePath);
      if (ignore && ignore.matches(relPath.replace(/\\/g, '/'))) continue;
      try {
        const stat = fs.statSync(filePath);
        if (!stat.isFile() || stat.size > 1 * 1024 * 1024) continue;
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
        // Skip unreadable / non-UTF8 files
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

  return findings;
}

/** Directories that contain test fixtures and should be skipped by default */
const TEST_DIRS = new Set(['__tests__', '__mocks__', 'test', 'tests', 'fixtures', '__fixtures__']);

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
const KEY_FILE_EXTENSIONS = new Set(['.pem', '.key', '.crt', '.p12', '.pfx']);

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
): string[] {
  const results: string[] = [];
  const queue: string[] = [dir];

  while (queue.length > 0 && results.length < maxFiles) {
    const current = queue.shift()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (results.length >= maxFiles) break;
      const entryPath = path.join(current, entry.name);
      const relFromRoot = path.relative(dir, entryPath).replace(/\\/g, '/');

      if (entry.isDirectory()) {
        // Unlike source files, key files commonly live in HIDDEN directories (`.ssh/`,
        // `.certs/`, `.aws/`), so we do NOT blanket-skip dot-dirs here. We still skip the
        // heavy/irrelevant ones (node_modules, .git) and honor the ignore matcher.
        if (SOURCE_SKIP_DIRS.has(entry.name) || entry.name === '.git') continue;
        if (!includeTests && TEST_DIRS.has(entry.name)) continue;
        if (ignore && ignore.matches(relFromRoot + '/.')) continue;
        queue.push(entryPath);
      } else if (entry.isFile()) {
        if (!KEY_FILE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;
        if (!includeTests && isTestFile(entry.name)) continue;
        if (ignore && ignore.matches(relFromRoot)) continue;
        results.push(entryPath);
      }
    }
  }

  return results;
}

function walkSourceFiles(
  dir: string,
  maxFiles: number,
  includeTests: boolean,
  ignore: IgnoreMatcher | null,
): string[] {
  const results: string[] = [];
  const queue: string[] = [dir];

  while (queue.length > 0 && results.length < maxFiles) {
    const current = queue.shift()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (results.length >= maxFiles) break;

      const entryPath = path.join(current, entry.name);
      const relFromRoot = path.relative(dir, entryPath).replace(/\\/g, '/');

      if (entry.isDirectory()) {
        if (SOURCE_SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        if (!includeTests && TEST_DIRS.has(entry.name)) continue;
        // Prune whole-tree ignored directories. The matcher's directory
        // patterns end with `/`, so we test the dir path with a trailing
        // segment; equivalently, append `/dummy`.
        if (ignore && ignore.matches(relFromRoot + '/.')) continue;
        queue.push(entryPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (!SOURCE_FILE_EXTENSIONS.has(ext)) continue;
        if (!includeTests && isTestFile(entry.name)) continue;
        if (ignore && ignore.matches(relFromRoot)) continue;
        results.push(entryPath);
      }
    }
  }

  return results;
}
