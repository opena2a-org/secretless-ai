/**
 * File watcher daemon for real-time transcript protection.
 * Monitors ~/.claude/projects/ for new/modified .jsonl files and auto-redacts.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { scanTranscriptFile, atomicWrite } from './transcript';

const SECRETLESS_DIR = path.join(os.homedir(), '.secretless-ai');
const PID_FILE = path.join(SECRETLESS_DIR, 'watch.pid');
const LOG_FILE = path.join(SECRETLESS_DIR, 'watch.log');
const TRANSCRIPT_DIR = path.join(os.homedir(), '.claude', 'projects');
/** Canonical resolved path — cached once to prevent TOCTOU with symlinks */
let resolvedTranscriptDir: string | null = null;

/** Debounce window in milliseconds */
const DEBOUNCE_MS = 3000;

/** Plist identifier for macOS LaunchAgent */
const LAUNCH_AGENT_LABEL = 'ai.secretless.watch';

/** Escape a string for safe inclusion in XML content or attribute values. */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Start watching Claude Code transcripts for credentials.
 * Runs in the foreground, monitoring file changes and auto-redacting.
 */
export function startWatch(options?: { logFile?: string }): void {
  const logPath = options?.logFile || LOG_FILE;

  // Ensure directories exist
  fs.mkdirSync(SECRETLESS_DIR, { recursive: true });

  if (!fs.existsSync(TRANSCRIPT_DIR)) {
    log(logPath, 'Transcript directory not found: ' + TRANSCRIPT_DIR);
    log(logPath, 'Start a Claude Code session first, then re-run.');
    return;
  }

  // Resolve and cache the canonical transcript directory path
  resolvedTranscriptDir = fs.realpathSync(TRANSCRIPT_DIR);

  // Write PID file with start time for TOCTOU protection (O_EXCL prevents concurrent writers)
  const pidData = JSON.stringify({ pid: process.pid, startedAt: Date.now() });
  try {
    const fd = fs.openSync(PID_FILE, 'wx');
    fs.writeSync(fd, pidData);
    fs.closeSync(fd);
  } catch (err: any) {
    if (err.code === 'EEXIST') {
      // Another watcher may be running — check before overwriting
      if (isWatchRunning()) {
        log(logPath, 'Another watcher is already running.');
        return;
      }
      // Stale PID file — overwrite
      fs.writeFileSync(PID_FILE, pidData);
    } else {
      throw err;
    }
  }
  log(logPath, `Watcher started (PID: ${process.pid})`);
  log(logPath, `Monitoring: ${TRANSCRIPT_DIR}`);

  // Track debounce timers per file
  const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

  // Watch for changes
  const watcher = fs.watch(TRANSCRIPT_DIR, { recursive: true }, (eventType, filename) => {
    if (!filename || !filename.endsWith('.jsonl')) return;

    const fullPath = path.join(TRANSCRIPT_DIR, filename);

    // Path traversal protection: resolve and verify the path stays within TRANSCRIPT_DIR
    let realPath: string;
    try {
      realPath = fs.realpathSync(fullPath);
    } catch {
      return; // File may not exist yet
    }
    if (!resolvedTranscriptDir || !realPath.startsWith(resolvedTranscriptDir)) return;

    // Skip if in tool-results
    if (filename.includes('tool-results')) return;

    // Debounce: Claude Code writes in bursts
    const existing = debounceTimers.get(fullPath);
    if (existing) clearTimeout(existing);

    debounceTimers.set(fullPath, setTimeout(() => {
      debounceTimers.delete(fullPath);
      processFile(fullPath, logPath);
    }, DEBOUNCE_MS));
  });

  // Graceful shutdown
  const shutdown = () => {
    log(logPath, 'Watcher stopping...');
    watcher.close();
    for (const timer of debounceTimers.values()) clearTimeout(timer);
    debounceTimers.clear();
    try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
    log(logPath, 'Watcher stopped.');
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

function processFile(filePath: string, logPath: string): void {
  try {
    const { findings, redactedLines } = scanTranscriptFile(filePath, false);
    if (findings.length > 0 && redactedLines) {
      atomicWrite(filePath, redactedLines);
      const displayPath = filePath.replace(os.homedir(), '~');
      log(logPath, `Redacted ${findings.length} credential(s) in ${displayPath}`);
      for (const f of findings) {
        log(logPath, `  ${f.jsonPath} → [REDACTED:${f.patternId}]`);
      }
    }
  } catch (err) {
    log(logPath, `Error processing ${filePath}: ${err}`);
  }
}

function log(logPath: string, message: string): void {
  const timestamp = new Date().toISOString();
  const line = `[${timestamp}] ${message}\n`;
  try {
    fs.appendFileSync(logPath, line);
  } catch {
    // Fallback to stderr if log file is not writable
  }
  process.stderr.write(line);
}

/**
 * Stop the running watcher process.
 */
export function stopWatch(): boolean {
  const pidInfo = readPidFile();
  if (!pidInfo) return false;

  try {
    process.kill(pidInfo.pid, 'SIGTERM');
    try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
    return true;
  } catch {
    // Process may already be dead — clean up stale PID file
    try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
    return false;
  }
}

/**
 * Check if the watcher is currently running.
 */
export function isWatchRunning(): boolean {
  const pidInfo = readPidFile();
  if (!pidInfo) return false;

  try {
    process.kill(pidInfo.pid, 0); // Signal 0 = check if process exists
    return true;
  } catch {
    return false;
  }
}

/** Read and parse PID file. Handles both legacy (plain number) and new (JSON) formats. */
function readPidFile(): { pid: number; startedAt: number } | null {
  if (!fs.existsSync(PID_FILE)) return null;

  try {
    const raw = fs.readFileSync(PID_FILE, 'utf-8').trim();
    // Try JSON object format first
    try {
      const data = JSON.parse(raw);
      if (data && typeof data === 'object' && typeof data.pid === 'number') {
        return data;
      }
    } catch {
      // Not valid JSON — fall through to legacy handling
    }
    // Fallback: legacy plain PID format
    const pid = parseInt(raw, 10);
    if (!isNaN(pid) && pid > 0) return { pid, startedAt: 0 };
  } catch {
    // Unreadable PID file
  }
  return null;
}

/**
 * Install macOS LaunchAgent for auto-start on login.
 */
export function installLaunchAgent(): boolean {
  if (process.platform !== 'darwin') return false;

  const launchAgentsDir = path.join(os.homedir(), 'Library', 'LaunchAgents');
  fs.mkdirSync(launchAgentsDir, { recursive: true });

  const plistPath = path.join(launchAgentsDir, `${LAUNCH_AGENT_LABEL}.plist`);

  // Resolve absolute path to npx to prevent PATH hijacking
  let npxPath = '/usr/local/bin/npx';
  try {
    const { execSync } = require('child_process');
    const resolved = execSync('which npx', { encoding: 'utf-8' }).trim();
    // Validate path contains only safe characters (prevent XML injection in plist)
    if (resolved && /^[/a-zA-Z0-9._-]+$/.test(resolved)) {
      npxPath = resolved;
    }
  } catch { /* fallback to default path */ }

  const safeLabel = escapeXml(LAUNCH_AGENT_LABEL);
  const safeNpxPath = escapeXml(npxPath);
  const safeLogFile = escapeXml(LOG_FILE);

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${safeLabel}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${safeNpxPath}</string>
    <string>secretless-ai</string>
    <string>watch</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>${safeLogFile}</string>
  <key>StandardOutPath</key>
  <string>${safeLogFile}</string>
</dict>
</plist>`;

  fs.writeFileSync(plistPath, plist);
  fs.chmodSync(plistPath, 0o600);
  return true;
}

/**
 * Uninstall macOS LaunchAgent.
 */
export function uninstallLaunchAgent(): boolean {
  if (process.platform !== 'darwin') return false;

  const plistPath = path.join(os.homedir(), 'Library', 'LaunchAgents', `${LAUNCH_AGENT_LABEL}.plist`);
  if (!fs.existsSync(plistPath)) return false;

  try {
    fs.unlinkSync(plistPath);
    return true;
  } catch {
    return false;
  }
}

// Export constants for testing
export { PID_FILE, LOG_FILE, DEBOUNCE_MS };
