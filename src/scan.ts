/**
 * Scan project files for hardcoded credentials.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CREDENTIAL_PATTERNS, CONFIG_FILES, CREDENTIAL_PREFIX_QUICK_CHECK, SOURCE_FILE_EXTENSIONS, SOURCE_SKIP_DIRS, KNOWN_EXAMPLE_KEYS, PLACEHOLDER_INDICATORS } from './patterns';

export interface ScanFinding {
  file: string;
  line: number;
  patternId: string;
  patternName: string;
  severity: 'critical' | 'high';
  preview: string;
  /** Actionable fix guidance for this finding */
  fix?: string;
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
  'mongodb': 'Move to env var MONGODB_URI. Rotate the database password.',
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
}

/**
 * Check if a matched credential is a known example or placeholder.
 * Returns true if the match should be excluded from results.
 */
function isKnownExample(line: string, match: RegExpMatchArray): boolean {
  const value = match[0];
  // Check exact known example keys
  if (KNOWN_EXAMPLE_KEYS.has(value)) return true;
  // Check placeholder indicators (case-insensitive)
  const lower = value.toLowerCase();
  if (PLACEHOLDER_INDICATORS.some(p => lower.includes(p))) return true;
  // Check if the line contains a comment marking it as an example
  const lineLC = line.toLowerCase();
  if (lineLC.includes('example') && lineLC.includes('//') || lineLC.includes('#')) {
    if (lineLC.includes('example') || lineLC.includes('placeholder') || lineLC.includes('fake')) return true;
  }
  return false;
}

/** Global config files that may contain secrets (outside project dir) */
const GLOBAL_CONFIG_FILES = [
  { dir: path.join(os.homedir(), '.claude'), file: 'CLAUDE.md', label: '~/.claude/CLAUDE.md' },
  { dir: path.join(os.homedir(), '.claude'), file: 'settings.json', label: '~/.claude/settings.json' },
];

/**
 * Scan project config files for hardcoded credentials.
 * Also scans global AI tool configs (e.g. ~/.claude/CLAUDE.md).
 * Returns findings sorted by severity then file.
 */
export function scan(projectDir: string, options?: ScanOptions): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const scanGlobal = options?.scanGlobal !== false;

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
          const match = line.match(pattern.regex);
          if (match) {
            if (isKnownExample(line, match)) break;
            const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
            const masked = line.replace(globalRegex, `[${pattern.name} REDACTED]`);
            findings.push({
              file: global.label,
              line: i + 1,
              patternId: pattern.id,
              patternName: pattern.name,
              severity: 'critical',
              preview: masked.trim().substring(0, 80),
              fix: FIX_GUIDANCE[pattern.id],
            });
            break;
          }
        }
      }
    } catch { /* skip */ }
  }

  // Scan project-level config files
  for (const configFile of CONFIG_FILES) {
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
          const match = line.match(pattern.regex);
          if (match) {
            if (isKnownExample(line, match)) break;
            // Mask the actual secret in the preview (replace ALL occurrences)
            const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
            const masked = line.replace(globalRegex, `[${pattern.name} REDACTED]`);

            findings.push({
              file: configFile,
              line: i + 1,
              patternId: pattern.id,
              patternName: pattern.name,
              severity: 'critical',
              preview: masked.trim().substring(0, 80),
              fix: FIX_GUIDANCE[pattern.id],
            });
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
    const sourceFiles = walkSourceFiles(projectDir, maxFiles, includeTests);

    for (const filePath of sourceFiles) {
      const relPath = path.relative(projectDir, filePath);
      // Skip files already covered by config scan
      if (configFileSet.has(relPath)) continue;

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
            const match = line.match(pattern.regex);
            if (match) {
              if (isKnownExample(line, match)) break;
              const globalRegex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
              const masked = line.replace(globalRegex, `[${pattern.name} REDACTED]`);

              findings.push({
                file: relPath,
                line: i + 1,
                patternId: pattern.id,
                patternName: pattern.name,
                severity: 'high',
                preview: masked.trim().substring(0, 80),
                fix: FIX_GUIDANCE[pattern.id],
              });
              break;
            }
          }
        }
      } catch {
        // Skip unreadable files
      }
    }
  }

  // Sort: critical first, then by file
  findings.sort((a, b) => {
    if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
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
 */
function walkSourceFiles(dir: string, maxFiles: number, includeTests: boolean): string[] {
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

      if (entry.isDirectory()) {
        if (SOURCE_SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        if (!includeTests && TEST_DIRS.has(entry.name)) continue;
        queue.push(path.join(current, entry.name));
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (!SOURCE_FILE_EXTENSIONS.has(ext)) continue;
        if (!includeTests && isTestFile(entry.name)) continue;
        results.push(path.join(current, entry.name));
      }
    }
  }

  return results;
}
