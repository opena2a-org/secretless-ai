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

export interface UnscannedFile {
  file: string;
  reason: string;
}

export interface ScanStagedResult {
  findings: StagedFinding[];
  blockedFiles: string[];
  /** Staged files whose content could not be read, so were not scanned. */
  unscannedFiles: UnscannedFile[];
  /** Set when the staged set could not be listed: nothing was scanned. */
  error?: string;
}

/** Largest staged file read for scanning. */
const MAX_FILE_BYTES = 5 * 1024 * 1024;
/** Longest text handed to one pattern match (ReDoS bound). */
const MAX_WINDOW = 4096;
/**
 * Overlap between consecutive windows of a longer line. A credential no longer
 * than this lies wholly inside one window, so a long line (a minified bundle,
 * inline data) is scanned in pieces rather than skipped.
 */
const WINDOW_OVERLAP = 1024;

function lineWindows(line: string): string[] {
  if (line.length <= MAX_WINDOW) return [line];
  const windows: string[] = [];
  for (let start = 0; ; start += MAX_WINDOW - WINDOW_OVERLAP) {
    windows.push(line.slice(start, start + MAX_WINDOW));
    if (start + MAX_WINDOW >= line.length) break;
  }
  return windows;
}

function gitErrorDetail(err: unknown): string {
  const stderr = (err as { stderr?: unknown })?.stderr;
  const text = (typeof stderr === 'string' ? stderr : Buffer.isBuffer(stderr) ? stderr.toString('utf-8') : '')
    || (err instanceof Error ? err.message : String(err));
  return text.trim().split('\n')[0] || 'unknown error';
}

/**
 * Scan staged files for secrets.
 *
 * Fails closed: a staged set that cannot be listed comes back as `error`, and
 * a file that cannot be read comes back in `unscannedFiles`, never as a clean
 * result.
 */
export function scanStagedFiles(options?: ScanStagedOptions): ScanStagedResult {
  const findings: StagedFinding[] = [];
  const blockedFiles: string[] = [];
  const unscannedFiles: UnscannedFile[] = [];

  // Get list of staged files. -z: without it git quotes any path with a
  // non-ASCII byte ("caf\303\251.env"), and the quoted name matches no pattern
  // and cannot be read. Submodule entries are commit pointers with no content.
  let stagedFiles: string[];
  try {
    const output = execFileSync(
      'git',
      ['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR', '--ignore-submodules=all'],
      {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );
    stagedFiles = output.split('\0').filter(Boolean);
  } catch (err) {
    // Outside a repository `git diff` falls back to --no-index mode and
    // rejects --cached, which says nothing useful to the reader.
    const detail = gitErrorDetail(err);
    const notRepo = /not a git repository|unknown option `cached'/i.test(detail);
    return {
      findings,
      blockedFiles,
      unscannedFiles,
      error: `could not list the staged files: ${notRepo ? 'not a git repository' : detail}`,
    };
  }

  if (stagedFiles.length === 0) {
    return { findings, blockedFiles, unscannedFiles };
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

    let content: string;
    try {
      content = execFileSync('git', ['show', `:${file}`], {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
        maxBuffer: MAX_FILE_BYTES,
      });
    } catch (err) {
      const tooLarge = (err as NodeJS.ErrnoException)?.code === 'ENOBUFS';
      unscannedFiles.push({
        file,
        reason: tooLarge ? 'larger than 5 MB' : `could not be read: ${gitErrorDetail(err)}`,
      });
      continue;
    }

    const lines = content.split('\n');
    lineLoop: for (let i = 0; i < lines.length; i++) {
      for (const segment of lineWindows(lines[i])) {
        // Skip env var references
        if (/\$\{[A-Z_]+\}/.test(segment) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(segment)) {
          continue;
        }

        for (const pattern of CREDENTIAL_PATTERNS) {
          const match = findRealMatch(segment, pattern);
          if (!match) continue;

          findings.push({
            file,
            line: i + 1,
            patternName: pattern.name,
          });
          continue lineLoop; // One finding per line
        }
      }
    }
  }

  return { findings, blockedFiles, unscannedFiles };
}
