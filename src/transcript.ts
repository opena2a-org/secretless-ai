/**
 * JSONL transcript scanning and redaction engine.
 * Discovers, scans, and redacts credentials in Claude Code transcript files.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { CREDENTIAL_PATTERNS, type CredentialPattern } from './patterns';
import { BUNDLE_TOKEN } from './bundle';
import { redactMatches } from './redact';

export interface TranscriptFinding {
  file: string;
  line: number;
  jsonPath: string;
  patternId: string;
  patternName: string;
  preview: string;
}

export interface CleanResult {
  filesScanned: number;
  filesWithSecrets: number;
  totalFindings: number;
  totalRedacted: number;
  findings: TranscriptFinding[];
  /**
   * Lines longer than `MAX_LINE_SIZE` characters, per file. Such a line is left
   * unchanged without being read, so a credential on it is neither reported nor
   * redacted, and "no credentials found" says nothing about it.
   */
  linesNotRead: Array<{ file: string; path: string; lines: number[] }>;
  totalLinesNotRead: number;
}

export interface CleanOptions {
  dryRun?: boolean;
  targetPath?: string;
  lastSession?: boolean;
  /**
   * Called with each span that is redacted (or, on a dry run, would be) and
   * where it is, so a caller can tell whether a stored secret was exposed
   * (#236). The span is credential text: compare it in memory, keep it nowhere.
   */
  onRedacted?: OnRedacted;
}

/** Receives one redacted span and where it was. */
export type OnRedacted = (span: string, where: { file: string; line: number }) => void;

/** Where a string being scanned came from. */
export interface FileInfo {
  file: string;
  line: number;
  onRedacted?: OnRedacted;
}

/** Metadata keys that should never be scanned for credentials (ID/hash fields, not user content) */
const SKIP_KEYS = new Set([
  'uuid', 'sessionId', 'parentUuid', 'timestamp', 'signature',
  'cacheKey', 'hash', 'requestId', 'traceId', 'spanId', 'correlationId',
  'messageId', 'conversationId', 'cacheCreatedAt',
]);

/** Max string/line size to process (ReDoS protection — 50KB per string value) */
export const MAX_LINE_SIZE = 50 * 1024;

/**
 * A value assigned to a secret-named variable, whatever its format.
 *
 * Process listings and environment dumps print `NAME=value`, and most values
 * carry no vendor prefix (`JIRA_TOKEN=<hex>`), so the vendor patterns never see
 * them. Here the NAME is the signal: it must END in one of the words the guard
 * hook already treats as secret (init.ts SECRET_VAR_WORDS), so `TOKEN_COUNT=3`
 * and `MAX_TOKENS=4096` stay. Three of the hook's words are left out because
 * they name configuration, not a secret: VAULT (`VAULT_ADDR`), DATABASE_URL
 * and CONNECTION_STRING, whose embedded passwords the connection-string
 * patterns already catch. SECRET_KEY is added for the Django and Flask name.
 *
 * Kept out of CREDENTIAL_PATTERNS on purpose: `scan`, `doctor` and `verify`
 * read that list, and this is a transcript redaction only.
 *
 * Bounds, because `clean` rewrites the user's file:
 * - uppercase names only, starting at an identifier boundary and with `=` right
 *   after the name, the shape `env` and `ps` print;
 * - a value of at least 8 characters, stopping at whitespace or a quote;
 * - a value that is a reference rather than a secret is left alone: `$VAR`,
 *   `${VAR}`, `$(cmd)`, `<placeholder>`, `****`, an env accessor, or a marker
 *   this tool already wrote (so a second run finds nothing).
 *
 * The value is capture group 1, so redaction keeps the variable name visible.
 */
const SECRET_ASSIGNMENT_PATTERN: CredentialPattern = {
  id: 'secret-assignment',
  name: 'Secret-Named Variable',
  regex: /(?<![A-Za-z0-9_])[A-Z0-9_]{0,64}(?:SECRET(?:_?KEY)?|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|TOKEN|CREDENTIAL)=["']?(?!\[REDACTED:[a-z0-9-]+\](?![^\s"'`])|process\.env|os\.environ|os\.getenv|import\.meta\.env|Deno\.env)([^\s"'`$<*][^\s"'`]{7,511})/,
  envPrefix: '',
};

/**
 * Discover Claude Code transcript files.
 * Walks ~/.claude/projects/ recursively, finding .jsonl files.
 * Also discovers session-memory/summary.md files.
 */
export function discoverTranscripts(targetPath?: string): string[] {
  const files: Array<{ path: string; mtime: number }> = [];

  if (targetPath) {
    try {
      const stat = fs.statSync(targetPath);
      if (stat.isFile() && (targetPath.endsWith('.jsonl') || targetPath.endsWith('.md'))) {
        return [targetPath];
      }
      if (stat.isDirectory()) {
        walkDir(targetPath, files);
        return files.sort((a, b) => b.mtime - a.mtime).map(f => f.path);
      }
    } catch {
      return [];
    }
  }

  const transcriptDir = path.join(os.homedir(), '.claude', 'projects');
  if (!fs.existsSync(transcriptDir)) return [];

  walkDir(transcriptDir, files);
  return files.sort((a, b) => b.mtime - a.mtime).map(f => f.path);
}

function walkDir(dir: string, files: Array<{ path: string; mtime: number }>): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    // Skip symlinks to prevent scanning/modifying files outside the target directory
    if (entry.isSymbolicLink()) continue;

    const fullPath = path.join(dir, entry.name);

    // Skip tool-results directories
    if (entry.isDirectory() && entry.name === 'tool-results') continue;

    if (entry.isDirectory()) {
      walkDir(fullPath, files);
    } else if (entry.isFile()) {
      if (entry.name.endsWith('.jsonl') || (entry.name === 'summary.md' && dir.endsWith('session-memory'))) {
        try {
          const stat = fs.statSync(fullPath);
          files.push({ path: fullPath, mtime: stat.mtimeMs });
        } catch {
          // Skip unreadable files
        }
      }
    }
  }
}

/**
 * Recursively walk a JSON value, scanning string leaves for credentials.
 * Returns the (possibly redacted) value.
 */
export function deepScan(
  value: unknown,
  jsonPath: string,
  findings: TranscriptFinding[],
  fileInfo: FileInfo,
): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === 'string') {
    return scanString(value, jsonPath, findings, fileInfo);
  }

  if (Array.isArray(value)) {
    return value.map((item, i) => deepScan(item, `${jsonPath}[${i}]`, findings, fileInfo));
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(obj)) {
      if (SKIP_KEYS.has(key)) {
        result[key] = obj[key];
        continue;
      }
      result[key] = deepScan(obj[key], `${jsonPath}.${key}`, findings, fileInfo);
    }
    return result;
  }

  return value;
}

/**
 * What `clean` redacts: the shared credential catalog, plus a bundle written by
 * `export`, so a bundle an agent printed does not stay in its transcript, plus
 * a value assigned to a secret-named variable. The bundle pattern is added here
 * rather than to `patterns.ts`, which is kept identical to the shared pattern
 * package. Vendor patterns and the bundle come first: a vendor-shaped value or
 * a bundle is reported under its own id.
 */
const TRANSCRIPT_PATTERNS: ReadonlyArray<Pick<CredentialPattern, 'id' | 'name' | 'regex'>> = [
  ...CREDENTIAL_PATTERNS,
  { id: 'secretless-bundle', name: 'Secretless Encrypted Bundle', regex: BUNDLE_TOKEN },
  SECRET_ASSIGNMENT_PATTERN,
];

function scanString(
  value: string,
  jsonPath: string,
  findings: TranscriptFinding[],
  fileInfo: FileInfo,
): string {
  // Skip very long strings (ReDoS protection)
  if (value.length > MAX_LINE_SIZE) return value;

  let result = value;
  for (const pattern of TRANSCRIPT_PATTERNS) {
    if (pattern.regex.test(result)) {
      // redactMatches replaces ALL occurrences AND extends across the tail of a
      // value longer than the pattern's fixed quantifier. Plain String.replace
      // wrote the tail of an over-length credential back into the user's
      // transcript while reporting the line as redacted.
      const onSpan = fileInfo.onRedacted
        ? (span: string) => fileInfo.onRedacted!(span, { file: fileInfo.file, line: fileInfo.line })
        : undefined;
      const redacted = redactMatches(result, pattern.regex, `[REDACTED:${pattern.id}]`, {
        preferCaptureGroup: pattern === SECRET_ASSIGNMENT_PATTERN,
        onSpan,
      });
      const preview = redacted.substring(0, 80);
      findings.push({
        file: fileInfo.file,
        line: fileInfo.line,
        jsonPath,
        patternId: pattern.id,
        patternName: pattern.name,
        preview,
      });
      result = redacted;
    }
  }

  return result;
}

/**
 * Scan a single transcript file. Returns findings and optionally redacted lines.
 */
export function scanTranscriptFile(
  filePath: string,
  dryRun: boolean,
  onRedacted?: OnRedacted,
): { findings: TranscriptFinding[]; redactedLines: string[] | null; linesNotRead: number[] } {
  const findings: TranscriptFinding[] = [];
  let hasChanges = false;
  const redactedLines: string[] = [];
  const linesNotRead: number[] = [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return { findings, redactedLines: null, linesNotRead };
  }

  const lines = content.split('\n');
  const displayPath = filePath.replace(os.homedir(), '~');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip empty lines
    if (!line.trim()) {
      if (!dryRun) redactedLines.push(line);
      continue;
    }

    // Skip oversized lines (ReDoS protection). Skipped is not clean: the line
    // is neither scanned nor redacted, so its number goes back to the caller.
    if (line.length > MAX_LINE_SIZE) {
      linesNotRead.push(i + 1);
      if (!dryRun) redactedLines.push(line);
      continue;
    }

    // Handle .md files (non-JSONL)
    if (filePath.endsWith('.md')) {
      const lineFindingsBefore = findings.length;
      const scanned = scanString(line, 'content', findings, { file: displayPath, line: i + 1, onRedacted });
      if (scanned !== line) hasChanges = true;
      if (!dryRun) redactedLines.push(scanned);
      continue;
    }

    // Parse JSONL line
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      // Malformed JSON line — keep as-is
      if (!dryRun) redactedLines.push(line);
      continue;
    }

    const findingsBefore = findings.length;
    const redacted = deepScan(parsed, '', findings, { file: displayPath, line: i + 1, onRedacted });

    if (findings.length > findingsBefore) {
      hasChanges = true;
      if (!dryRun) redactedLines.push(JSON.stringify(redacted));
    } else {
      if (!dryRun) redactedLines.push(line);
    }
  }

  return {
    findings,
    redactedLines: !dryRun && hasChanges ? redactedLines : null,
    linesNotRead,
  };
}

/**
 * Atomic write: write to temp file then rename.
 */
export function atomicWrite(filePath: string, lines: string[]): void {
  const suffix = crypto.randomBytes(8).toString('hex');
  const tempPath = `${filePath}.tmp.${process.pid}.${suffix}`;
  try {
    // Write with restrictive permissions (owner-only read/write)
    const fd = fs.openSync(tempPath, 'w', 0o600);
    fs.writeSync(fd, lines.join('\n'));
    fs.closeSync(fd);
    fs.renameSync(tempPath, filePath);
  } catch (err) {
    // Clean up temp file on error
    try { fs.unlinkSync(tempPath); } catch { /* ignore */ }
    throw err;
  }
}

/**
 * Main orchestrator: discover, scan, and optionally redact transcripts.
 */
export function cleanTranscripts(options?: CleanOptions): CleanResult {
  const dryRun = options?.dryRun ?? false;
  const result: CleanResult = {
    filesScanned: 0,
    filesWithSecrets: 0,
    totalFindings: 0,
    totalRedacted: 0,
    findings: [],
    linesNotRead: [],
    totalLinesNotRead: 0,
  };

  let files = discoverTranscripts(options?.targetPath);

  if (options?.lastSession) {
    // Only process the newest .jsonl per project directory
    const newestPerProject = new Map<string, string>();
    for (const file of files) {
      if (!file.endsWith('.jsonl')) continue;
      const projectDir = path.dirname(file);
      if (!newestPerProject.has(projectDir)) {
        newestPerProject.set(projectDir, file);
      }
    }
    files = [...newestPerProject.values()];
  }

  for (const file of files) {
    result.filesScanned++;
    const { findings, redactedLines, linesNotRead } = scanTranscriptFile(file, dryRun, options?.onRedacted);

    if (linesNotRead.length > 0) {
      result.linesNotRead.push({ file: file.replace(os.homedir(), '~'), path: file, lines: linesNotRead });
      result.totalLinesNotRead += linesNotRead.length;
    }

    if (findings.length > 0) {
      result.filesWithSecrets++;
      result.totalFindings += findings.length;
      result.findings.push(...findings);

      if (!dryRun && redactedLines) {
        atomicWrite(file, redactedLines);
        result.totalRedacted += findings.length;
      }
    }
  }

  return result;
}
