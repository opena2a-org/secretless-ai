/**
 * Scan staged git files for secrets — called by the pre-commit hook.
 *
 * Checks staged filenames against SECRET_FILE_PATTERNS and scans
 * staged file contents against CREDENTIAL_PATTERNS.
 */

import { execFileSync } from 'child_process';
import { CREDENTIAL_PATTERNS, SECRET_FILE_PATTERNS, CREDENTIAL_PREFIX_QUICK_CHECK } from './patterns';
import { isKnownExample } from './scan';

interface StagedFinding {
  file: string;
  line: number;
  patternName: string;
}

/**
 * Scan staged files for secrets. Returns findings and exit code.
 */
export function scanStagedFiles(): { findings: StagedFinding[]; blockedFiles: string[] } {
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
        // Reset lastIndex so /g regexes don't skip matches across lines
        pattern.regex.lastIndex = 0;
        const match = line.match(pattern.regex);
        if (!match) continue;

        // Skip public example keys (e.g. AWS AKIAIOSFODNN7EXAMPLE in docs)
        // Parity with the non-staged scanner.
        if (isKnownExample(line, match)) break;

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
