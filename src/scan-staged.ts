/**
 * Scan staged git files for secrets — called by the pre-commit hook.
 *
 * Checks staged filenames against SECRET_FILE_PATTERNS and scans
 * staged file contents against CREDENTIAL_PATTERNS.
 */

import { execFileSync } from 'child_process';
import { CREDENTIAL_PATTERNS, SECRET_FILE_PATTERNS, CREDENTIAL_PREFIX_QUICK_CHECK } from './patterns';
import { findRealMatch } from './scan';
import { loadSecretlessIgnore, type IgnoreMatcher } from './secretlessignore';

export interface ScanStagedOptions {
  /** Repo root used to load `.secretlessignore`. Defaults to `git rev-parse --show-toplevel`. */
  rootDir?: string;
  /** Skip the default-ignore list + user `.secretlessignore`. Default: false. */
  noIgnore?: boolean;
  /** Inject a pre-built matcher (tests, callers wiring in from `runScanStaged`). */
  ignore?: IgnoreMatcher;
}

interface StagedFinding {
  file: string;
  line: number;
  patternName: string;
}

/**
 * Scan staged files for secrets. Returns findings and exit code.
 */
export function scanStagedFiles(options?: ScanStagedOptions): { findings: StagedFinding[]; blockedFiles: string[] } {
  const findings: StagedFinding[] = [];
  const blockedFiles: string[] = [];

  // Get list of staged files
  let stagedFiles: string[];
  try {
    const output = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR'], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    stagedFiles = output.trim().split('\n').filter(Boolean);
  } catch {
    // Not in a git repo or no staged files
    return { findings, blockedFiles };
  }

  if (stagedFiles.length === 0) {
    return { findings, blockedFiles };
  }

  // Resolve ignore matcher. Priority:
  //   1. options.ignore (caller-provided),
  //   2. options.noIgnore=true → null (defaults disabled, user file disabled),
  //   3. otherwise: loadSecretlessIgnore from rootDir or git toplevel.
  let ignore: IgnoreMatcher | null = null;
  if (options?.ignore) {
    ignore = options.ignore;
  } else if (!options?.noIgnore) {
    let rootDir = options?.rootDir;
    if (!rootDir) {
      try {
        rootDir = execFileSync('git', ['rev-parse', '--show-toplevel'], {
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        }).trim();
      } catch {
        // Fall through — no ignore filter applied.
      }
    }
    if (rootDir) {
      try {
        ignore = loadSecretlessIgnore(rootDir);
      } catch {
        ignore = null;
      }
    }
  }

  // Filter out ignored staged files BEFORE filename + content scan.
  if (ignore) {
    stagedFiles = stagedFiles.filter(f => !ignore!.matches(f.replace(/\\/g, '/')));
  }

  // Check filenames against secret file patterns
  for (const file of stagedFiles) {
    const basename = file.split('/').pop() ?? file;
    for (const pattern of SECRET_FILE_PATTERNS) {
      if (pattern.includes('*')) {
        // Glob pattern: *.key, *.pem, etc.
        const ext = pattern.replace('*', '');
        if (basename.endsWith(ext)) {
          blockedFiles.push(file);
          break;
        }
      } else if (pattern.endsWith('/')) {
        // Directory pattern: secrets/, credentials/
        if (file.startsWith(pattern) || file.includes('/' + pattern)) {
          blockedFiles.push(file);
          break;
        }
      } else {
        // Exact match: .env, .env.local, etc.
        if (basename === pattern || file === pattern) {
          blockedFiles.push(file);
          break;
        }
      }
    }
  }

  // Scan staged file contents for credential patterns
  for (const file of stagedFiles) {
    // Skip test files -- they intentionally contain fake credential patterns
    if (file.endsWith('.test.ts') || file.endsWith('.test.js') || file.endsWith('.spec.ts') || file.endsWith('.spec.js')) {
      continue;
    }

    // Skip binary files and very large files
    let content: string;
    try {
      content = execFileSync('git', ['show', `:${file}`], {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        maxBuffer: 5 * 1024 * 1024,
      });
    } catch {
      continue; // Skip files that can't be read (binary, deleted, etc.)
    }

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 4096) continue; // ReDoS protection

      // Skip env var references
      if (/\$\{[A-Z_]+\}/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) {
        continue;
      }

      for (const pattern of CREDENTIAL_PATTERNS) {
        const match = findRealMatch(line, pattern);
        if (!match) continue;

        findings.push({
          file,
          line: i + 1,
          patternName: pattern.name,
        });
        break; // One finding per line
      }
    }
  }

  return { findings, blockedFiles };
}
