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

/** A history file that is present and could not be read (#462). */
export interface HistoryFileNotRead {
  /** Display path with ~ for home directory */
  file: string;
  /** `could not be read (<error code>)` */
  reason: string;
}

/** A run of lines of one history file that the scan did not read for one reason (#462). */
export interface HistoryLinesNotRead {
  /** Display path with ~ for home directory */
  file: string;
  /** First line of the run (1-based) */
  firstLine: number;
  /** Last line of the run (1-based); `firstLine` for a run of one line */
  lastLine: number;
  reason: HistoryLinesNotReadReason;
}

/** Why a run of lines was not read: one of the values of `HISTORY_LINES_NOT_READ`. */
export type HistoryLinesNotReadReason = (typeof HISTORY_LINES_NOT_READ)[keyof typeof HISTORY_LINES_NOT_READ];

export interface HistoryScanResult {
  filesScanned: number;
  findingCount: number;
  findings: HistoryFinding[];
  /**
   * History files that are present and could not be read (#462). They were
   * skipped without a word, so a `.bash_history` with mode 000 printed
   * "Files scanned: 0" and "No credentials found in shell history." at exit 0,
   * the report for a home with no history file. `scanHistory()` fills it in;
   * it is optional so a result built by hand still compiles, and an absent
   * list reads as empty.
   */
  filesNotRead?: HistoryFileNotRead[];
  /**
   * The lines of the files read that were not matched (#462): the lines before
   * the last `MAX_LINES`, and each run of lines longer than `MAX_LINE_LENGTH`
   * characters. Neither was reported, so a credential on one of them left
   * "No credentials found in shell history." standing. Written and read like
   * `filesNotRead`.
   */
  linesNotRead?: HistoryLinesNotRead[];
}

export interface HistoryCleanResult {
  filesScanned: number;
  filesModified: number;
  linesRedacted: number;
  backupPaths: string[];
  /**
   * History files that are present and could not be read, so were not cleaned
   * (#466). They were skipped without a word, as the scan skipped them before
   * #462, and `clean-history` printed "No credentials found in shell history."
   * over them. `cleanHistory()` fills it in; optional as on `HistoryScanResult`.
   */
  filesNotRead?: HistoryFileNotRead[];
  /**
   * The runs of lines longer than `MAX_LINE_LENGTH` characters in the files
   * read (#466): they are not matched, so not redacted. `cleanHistory` reads
   * every line of a file, so it lists no lines before a window. Written and
   * read like `filesNotRead`.
   */
  linesNotRead?: HistoryLinesNotRead[];
}

const HISTORY_FILES = ['.bash_history', '.zsh_history'];
export const MAX_LINES = 10_000;
export const MAX_LINE_LENGTH = 4096;

/**
 * Why `scanHistory` did not read a run of lines of a file it read (#462).
 * `cleanHistory` lists runs of the second kind (#466).
 */
export const HISTORY_LINES_NOT_READ = {
  beforeWindow: `before the last ${MAX_LINES} lines`,
  tooLong: `longer than ${MAX_LINE_LENGTH} characters`,
} as const;

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
 *
 * The home directory is matched as `path.join` writes it into the path of a
 * history file: normalized, and followed by one separator. A HOME that ends in
 * a separator (`HOME=/home/user/`) was matched as given, so the separator went
 * with it and the file was shown as `~.bash_history` (#466).
 */
function displayPath(filePath: string): string {
  const home = path.normalize(os.homedir());
  const prefix = home.endsWith(path.sep) ? home : home + path.sep;
  if (filePath.startsWith(prefix)) {
    return '~' + path.sep + filePath.slice(prefix.length);
  }
  return filePath;
}

/**
 * The content of a history file, or null when there is none to read. A file
 * that is present and could not be read is added to `filesNotRead` with the
 * error code (#462); a file that is not there is no history to read.
 */
async function readHistoryFile(filePath: string, filesNotRead: HistoryFileNotRead[]): Promise<string | null> {
  try {
    return await fs.readFile(filePath, 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code ?? 'unknown error';
    if (code !== 'ENOENT' && code !== 'ENOTDIR') {
      filesNotRead.push({ file: displayPath(filePath), reason: `could not be read (${code})` });
    }
    return null;
  }
}

/**
 * List line `lineNumber` of `file` as longer than MAX_LINE_LENGTH characters,
 * joined to the run of such lines right before it when there is one.
 */
function addTooLongLine(linesNotRead: HistoryLinesNotRead[], file: string, lineNumber: number): void {
  const run = linesNotRead[linesNotRead.length - 1];
  if (run && run.file === file && run.reason === HISTORY_LINES_NOT_READ.tooLong && run.lastLine === lineNumber - 1) {
    run.lastLine = lineNumber;
  } else {
    linesNotRead.push({ file, firstLine: lineNumber, lastLine: lineNumber, reason: HISTORY_LINES_NOT_READ.tooLong });
  }
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
 * and command-line patterns. A file that is present and could not be read,
 * and the lines it did not match, are listed in the result.
 */
export async function scanHistory(): Promise<HistoryScanResult> {
  const home = os.homedir();
  const findings: HistoryFinding[] = [];
  const filesNotRead: HistoryFileNotRead[] = [];
  const linesNotRead: HistoryLinesNotRead[] = [];
  let filesScanned = 0;

  for (const fileName of HISTORY_FILES) {
    const filePath = path.join(home, fileName);
    const file = displayPath(filePath);

    const content = await readHistoryFile(filePath, filesNotRead);
    if (content === null) continue;

    filesScanned++;
    const allLines = content.split('\n');
    // The empty string after the final newline is not a line of history.
    // Counted as one, it took a place in the window, so the scan matched only
    // the last MAX_LINES - 1 lines of a longer file ending in a newline (#462).
    if (allLines[allLines.length - 1] === '') allLines.pop();

    // Only scan the last MAX_LINES lines
    const startIdx = Math.max(0, allLines.length - MAX_LINES);
    const lines = allLines.slice(startIdx);
    if (startIdx > 0) {
      linesNotRead.push({ file, firstLine: 1, lastLine: startIdx, reason: HISTORY_LINES_NOT_READ.beforeWindow });
    }

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      const lineNumber = startIdx + i + 1;

      // Skip empty lines
      if (!rawLine) {
        continue;
      }

      // A line over the length cap is not matched. It is listed, joined to the
      // run of over-length lines right before it when there is one.
      if (rawLine.length > MAX_LINE_LENGTH) {
        addTooLongLine(linesNotRead, file, lineNumber);
        continue;
      }

      // Strip zsh timestamp prefix for matching
      const line = stripZshTimestamp(rawLine);

      const match = matchLine(line);
      if (match) {
        // Every credential on the line, by every pattern. A pattern whose
        // `value` group is the secret (`secret set NAME=VALUE`) keeps the
        // command and the name in front of it.
        const preview = maskCredentials(line, { commandPatterns: COMMAND_PATTERNS });

        findings.push({
          file,
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
    filesNotRead,
    linesNotRead,
  };
}

/**
 * Clean shell history files by redacting credential matches.
 *
 * Creates a backup of each modified file (.bak extension) before
 * overwriting with redacted content. In dry-run mode, reports what
 * would be changed without modifying files. A file that is present and
 * could not be read, and the lines longer than MAX_LINE_LENGTH characters,
 * are not cleaned; both are listed in the result, as `scanHistory` lists them.
 */
export async function cleanHistory(dryRun = false): Promise<HistoryCleanResult> {
  const home = os.homedir();
  let filesScanned = 0;
  let filesModified = 0;
  let linesRedacted = 0;
  const backupPaths: string[] = [];
  const filesNotRead: HistoryFileNotRead[] = [];
  const linesNotRead: HistoryLinesNotRead[] = [];

  for (const fileName of HISTORY_FILES) {
    const filePath = path.join(home, fileName);
    const file = displayPath(filePath);

    const content = await readHistoryFile(filePath, filesNotRead);
    if (content === null) continue;

    filesScanned++;
    const lines = content.split('\n');
    let modified = false;

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      if (!rawLine) continue;
      // A line over the length cap is not matched, so a credential on it is
      // not redacted. It is listed rather than passed over (#466).
      if (rawLine.length > MAX_LINE_LENGTH) {
        addTooLongLine(linesNotRead, file, i + 1);
        continue;
      }

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
    filesNotRead,
    linesNotRead,
  };
}
