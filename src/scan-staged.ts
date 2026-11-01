/**
 * Scan staged git files for secrets — called by the pre-commit hook.
 *
 * Checks staged filenames against SECRET_FILE_PATTERNS and scans
 * staged file contents against CREDENTIAL_PATTERNS.
 */

import { execFileSync } from 'child_process';
import * as path from 'path';
import { CREDENTIAL_PATTERNS, SECRET_FILE_PATTERNS, CREDENTIAL_PREFIX_QUICK_CHECK } from './patterns';
import { findRealMatch } from './scan';
import { loadSecretlessIgnore, type IgnoreMatcher } from './secretlessignore';
import { BUNDLE_EXTENSION } from './bundle';
import { MCP_ENV_SECRET_NAME, envFindingsOnLine, homeMcpConfigPaths, isProjectMcpConfig, mcpEnvSecretsByLine, type LineSpan } from './mcp/env-secrets';
import { mcpConfigLocations } from './mcp/discover';

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
export interface ScanStagedResult {
  findings: StagedFinding[];
  blockedFiles: string[];
  /**
   * True when git could not list the staged files (not inside a repository,
   * or git itself failed). A THIRD state, distinct from "nothing staged":
   * both used to return the same empty result, so `scan-staged` run outside a
   * repo printed nothing and exited 0, which reads exactly like a clean
   * commit check (#125).
   */
  notARepo?: boolean;
  /**
   * Matches hidden because they looked like a known example or placeholder,
   * counted the way `scan` counts them, so the hook can say what it hid.
   */
  placeholdersSuppressed: number;
}

export function scanStagedFiles(options?: ScanStagedOptions): ScanStagedResult {
  const findings: StagedFinding[] = [];
  const blockedFiles: string[] = [];
  let placeholdersSuppressed = 0;
  const matchOpts = { onSuppressed: () => { placeholdersSuppressed += 1; } };

  // Get list of staged files
  let stagedFiles: string[];
  try {
    const output = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR'], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    stagedFiles = output.trim().split('\n').filter(Boolean);
  } catch {
    // An empty index does not throw (git prints nothing and exits 0), so a
    // failure here means git could not answer at all.
    return { findings, blockedFiles, notARepo: true, placeholdersSuppressed };
  }

  if (stagedFiles.length === 0) {
    return { findings, blockedFiles, placeholdersSuppressed };
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
    // A bundle from `export`. Not in SECRET_FILE_PATTERNS, which is kept
    // identical to the shared pattern package.
    if (basename.toLowerCase().endsWith(BUNDLE_EXTENSION)) {
      blockedFiles.push(file);
      continue;
    }
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
    // A staged project MCP config's env is read by the env rule, as `scan`
    // reads it, from the staged text.
    const env = stagedMcpConfig(file) ? mcpEnvSecretsByLine(content) : undefined;
    const fileFindings: StagedFinding[] = [];
    // The span of the match each line's pattern finding was made for.
    const reported = new Map<number, LineSpan>();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 4096) continue; // ReDoS protection

      // Skip env var references
      if (/\$\{[A-Z_]+\}/.test(line) && !CREDENTIAL_PREFIX_QUICK_CHECK.test(line)) {
        continue;
      }

      for (const pattern of CREDENTIAL_PATTERNS) {
        const match = findRealMatch(line, pattern, matchOpts);
        if (!match) continue;

        fileFindings.push({
          file,
          line: i + 1,
          patternName: pattern.name,
        });
        reported.set(i + 1, { from: match.index ?? 0, to: (match.index ?? 0) + match[0].length });
        break; // One finding per line
      }
    }
    // Every line the pass found a secret on, those skipped above too. A
    // value a pattern reported on its line is that finding.
    for (const [lineNo, secrets] of env ?? []) {
      for (const found of envFindingsOnLine(secrets, reported.get(lineNo), matchOpts)) {
        fileFindings.push({ file, line: lineNo, patternName: found.vendor?.pattern.name ?? MCP_ENV_SECRET_NAME });
      }
    }
    if (env !== undefined) fileFindings.sort((a, b) => a.line - b.line);
    findings.push(...fileFindings);
  }

  return { findings, blockedFiles, placeholdersSuppressed };
}

/**
 * The per-user MCP configs `mcp-status` reads in the home directory that a
 * staged path names when the repository is the home directory:
 * `.cursor/mcp.json`, `.vscode/mcp.json` and `.windsurf/mcp.json`.
 */
const HOME_RELATIVE_MCP_CONFIGS: ReadonlySet<string> = new Set(
  mcpConfigLocations()
    .filter((l) => l.scope === 'home' && path.basename(l.relativePath) === 'mcp.json')
    .map((l) => l.relativePath.split(path.sep).join('/')),
);

/**
 * Whether the env rule reads a staged file: one named as a project MCP
 * config, unless it is a per-user config `mcp-status` reads in the home
 * directory, as a repository kept at the home directory stages one. Only
 * for such a path is the repository's top level asked for.
 */
function stagedMcpConfig(file: string): boolean {
  const name = file.split('/').pop() ?? file;
  if (name !== '.mcp.json' && name !== 'mcp.json') return false;
  if (!HOME_RELATIVE_MCP_CONFIGS.has(file)) return true;
  let top: string;
  try {
    top = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return true;
  }
  return isProjectMcpConfig(path.join(top, file), homeMcpConfigPaths());
}
