/**
 * JSONL transcript scanning and redaction engine.
 * Discovers, scans, and redacts credentials in Claude Code transcript files.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { CREDENTIAL_PATTERNS } from './patterns';

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
}

export interface CleanOptions {
  dryRun?: boolean;
  targetPath?: string;
  lastSession?: boolean;
}

/** Metadata keys that should never be scanned for credentials (ID/hash fields, not user content) */
const SKIP_KEYS = new Set([
  'uuid', 'sessionId', 'parentUuid', 'timestamp', 'signature',
  'cacheKey', 'hash', 'requestId', 'traceId', 'spanId', 'correlationId',
  'messageId', 'conversationId', 'cacheCreatedAt',
]);

/** Max string/line size to process (ReDoS protection — 50KB per string value) */
const MAX_LINE_SIZE = 50 * 1024;

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
  fileInfo: { file: string; line: number },
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

function scanString(
  value: string,
  jsonPath: string,
  findings: TranscriptFinding[],
  fileInfo: { file: string; line: number },
): string {
  // Skip very long strings (ReDoS protection)
  if (value.length > MAX_LINE_SIZE) return value;

  let result = value;
  for (const pattern of CREDENTIAL_PATTERNS) {
    if (pattern.regex.test(result)) {
      // Use global regex to replace ALL occurrences, not just the first
      const flags = pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g';
      const globalRegex = new RegExp(pattern.regex.source, flags);
      const preview = result.replace(globalRegex, `[REDACTED:${pattern.id}]`).substring(0, 80);
      findings.push({
        file: fileInfo.file,
        line: fileInfo.line,
        jsonPath,
        patternId: pattern.id,
        patternName: pattern.name,
        preview,
      });
      result = result.replace(globalRegex, `[REDACTED:${pattern.id}]`);
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
): { findings: TranscriptFinding[]; redactedLines: string[] | null } {
  const findings: TranscriptFinding[] = [];
  let hasChanges = false;
  const redactedLines: string[] = [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return { findings, redactedLines: null };
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

    // Skip oversized lines (ReDoS protection)
    if (line.length > MAX_LINE_SIZE) {
      if (!dryRun) redactedLines.push(line);
      continue;
    }

    // Handle .md files (non-JSONL)
    if (filePath.endsWith('.md')) {
      const lineFindingsBefore = findings.length;
      const scanned = scanString(line, 'content', findings, { file: displayPath, line: i + 1 });
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
    const redacted = deepScan(parsed, '', findings, { file: displayPath, line: i + 1 });

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
    const { findings, redactedLines } = scanTranscriptFile(file, dryRun);

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
