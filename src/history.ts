/**
 * Shell history scanning and cleaning module.
 *
 * Scans shell history files (.bash_history, .zsh_history) for hardcoded
 * credentials and optionally redacts them. Uses the same credential
 * patterns as the main scanner plus additional command-line-specific patterns.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { CREDENTIAL_PATTERNS, type CredentialPattern } from './patterns';
import { maskCredentials } from './line-mask';

export interface HistoryFinding {
  /** Display path with ~ for home directory */
  file: string;
  /** Line number (1-based) */
  line: number;
  /** Pattern ID that matched */
  patternId: string;
  /** Human-readable pattern name */
  patternName: string;
  /** The matching line, each credential on it replaced by `[<pattern name> REDACTED]` */
  preview: string;
}

export interface HistoryScanResult {
  filesScanned: number;
  findingCount: number;
  findings: HistoryFinding[];
}

export interface HistoryCleanResult {
  filesScanned: number;
  filesModified: number;
  linesRedacted: number;
  backupPaths: string[];
}

const HISTORY_FILES = ['.bash_history', '.zsh_history'];
const MAX_LINES = 10_000;
const MAX_LINE_LENGTH = 4096;

/** Additional command-line patterns for history context. */
const COMMAND_PATTERNS: Array<{ id: string; name: string; regex: RegExp }> = [
  { id: 'cmd-bearer', name: 'Bearer token in curl', regex: /curl\s+[^\n]*-H\s*["']Authorization:\s*Bearer\s+\S{20,}/i },
  { id: 'cmd-api-key', name: 'API key in command', regex: /--api[_-]?key[=\s]+\S{20,}/i },
  { id: 'cmd-export', name: 'Secret in export', regex: /export\s+[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*\s*=\s*['"]?\S{20,}/i },
  // `secret set NAME=VALUE` (#413). The value was stored as a secret, so it
  // has no length floor. Flags before the name are passed over, `--description`
  // and `--meta` together with their argument, so `--meta app=web` is not read
  // as NAME=VALUE. A value opening with `$` or a backtick is a substitution:
  // history holds the reference, not the value. The unquoted flag argument
  // cannot open with a quote, so a quoted argument matches exactly one
  // alternative and a line of many quoted arguments is matched in one pass
  // rather than one per combination.
  {
    id: 'cmd-secret-set',
    name: 'Secret in secret set NAME=VALUE',
    regex: /(?<![\w-])secret\s+set\s+(?:--(?:description|meta)(?:=|\s+)(?:"[^"\n]*"|'[^'\n]*'|[^\s"']\S*)\s+|--(?!(?:description|meta)(?:[=\s]|$))\S+\s+)*[A-Za-z][\w-]*=(?<value>"(?![$`])[^"\n]+"|'[^'\n]+'|(?![$`"'])\S+)/,
  },
];

/**
 * Get the display path with ~ substitution for the home directory.
 */
function displayPath(filePath: string): string {
  const home = os.homedir();
  if (filePath.startsWith(home)) {
    return '~' + filePath.slice(home.length);
  }
  return filePath;
}

/**
 * Strip zsh extended history timestamp prefix.
 * Format: `: 1234567890:0;actual command`
 */
function stripZshTimestamp(line: string): string {
  const match = line.match(/^: \d+:\d+;(.*)$/);
  return match ? match[1] : line;
}

/**
 * Check a single line against all patterns.
 * Returns the first matching pattern or null.
 */
function matchLine(line: string): { id: string; name: string; regex: RegExp } | null {
  // Check credential patterns first
  for (const pattern of CREDENTIAL_PATTERNS) {
    if (pattern.regex.test(line)) {
      return { id: pattern.id, name: pattern.name, regex: pattern.regex };
    }
  }

  // Then check command patterns
  for (const pattern of COMMAND_PATTERNS) {
    if (pattern.regex.test(line)) {
      return pattern;
    }
  }

  return null;
}

/**
 * Scan shell history files for hardcoded credentials.
 *
 * Reads .bash_history and .zsh_history from the user's home directory,
 * checking the last MAX_LINES lines of each against credential patterns
 * and command-line patterns.
 */
export async function scanHistory(): Promise<HistoryScanResult> {
  const home = os.homedir();
  const findings: HistoryFinding[] = [];
  let filesScanned = 0;

  for (const fileName of HISTORY_FILES) {
    const filePath = path.join(home, fileName);

    let content: string;
    try {
      content = await fs.readFile(filePath, 'utf-8');
    } catch {
      // File does not exist or is not readable -- skip
      continue;
    }

    filesScanned++;
    const allLines = content.split('\n');

    // Only scan the last MAX_LINES lines
    const startIdx = Math.max(0, allLines.length - MAX_LINES);
    const lines = allLines.slice(startIdx);

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];

      // Skip empty lines and lines that are too long
      if (!rawLine || rawLine.length > MAX_LINE_LENGTH) {
        continue;
      }

      // Strip zsh timestamp prefix for matching
      const line = stripZshTimestamp(rawLine);

      const match = matchLine(line);
      if (match) {
        const lineNumber = startIdx + i + 1;
        // Every credential on the line, by every pattern. A pattern whose
        // `value` group is the secret (`secret set NAME=VALUE`) keeps the
        // command and the name in front of it.
        const preview = maskCredentials(line, { commandPatterns: COMMAND_PATTERNS });

        findings.push({
          file: displayPath(filePath),
          line: lineNumber,
          patternId: match.id,
          patternName: match.name,
          preview,
        });
      }
    }
  }

  return {
    filesScanned,
    findingCount: findings.length,
    findings,
  };
}

/**
 * Clean shell history files by redacting credential matches.
 *
 * Creates a backup of each modified file (.bak extension) before
 * overwriting with redacted content. In dry-run mode, reports what
 * would be changed without modifying files.
 */
export async function cleanHistory(dryRun = false): Promise<HistoryCleanResult> {
  const home = os.homedir();
  let filesScanned = 0;
  let filesModified = 0;
  let linesRedacted = 0;
  const backupPaths: string[] = [];

  for (const fileName of HISTORY_FILES) {
    const filePath = path.join(home, fileName);

    let content: string;
    try {
      content = await fs.readFile(filePath, 'utf-8');
    } catch {
      continue;
    }

    filesScanned++;
    const lines = content.split('\n');
    let modified = false;

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      if (!rawLine || rawLine.length > MAX_LINE_LENGTH) continue;

      const line = stripZshTimestamp(rawLine);
      const match = matchLine(line);

      if (match) {
        linesRedacted++;
        modified = true;

        if (!dryRun) {
          // Replace every pattern's matches on the line with a redaction
          // marker, each through the credential characters that follow it: the
          // pattern's quantifier is not the credential's length, and the line
          // `linesRedacted` counts may hold more than one credential. The same
          // masker builds the `scan-history` preview, so the two cannot drift.
          lines[i] = maskCredentials(rawLine, {
            commandPatterns: COMMAND_PATTERNS,
            label: (pattern) => `[REDACTED:${pattern.id}]`,
            preferCaptureGroup: false,
          });
        }
      }
    }

    if (modified && !dryRun) {
      // Create backup
      const backupPath = filePath + '.bak';
      await fs.writeFile(backupPath, content, 'utf-8');
      backupPaths.push(displayPath(backupPath));

      // Write redacted content
      await fs.writeFile(filePath, lines.join('\n'), 'utf-8');
      filesModified++;
    } else if (modified) {
      filesModified++;
    }
  }

  return {
    filesScanned,
    filesModified,
    linesRedacted,
    backupPaths,
  };
}
