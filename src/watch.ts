/**
 * File watcher daemon for real-time transcript protection.
 * Monitors the Claude Code transcript directories for new or modified .jsonl
 * files and redacts credentials in them.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawn } from 'child_process';
import { scanTranscriptFile, atomicWrite, defaultTranscriptDir } from './transcript';
import type { TranscriptFinding } from './transcript';
import { SecretStore, isSettableSecretName, notSettableReason } from './secret-store';
import { markRedactedSecretsExposed } from './secret-exposure';
import type { ExposureMarks, RedactedSpan } from './secret-exposure';
import { SECRETLESS_DIR, PID_FILE, LOG_FILE, readPidFile, isWatchRunning, watchStatus } from './watch-state';
import type { WatchStatus } from './watch-state';

export { isWatchRunning, watchStatus, readPidFile };
export type { WatchStatus };

/** Debounce window in milliseconds */
const DEBOUNCE_MS = 3000;

/** Plist identifier for macOS LaunchAgent */
const LAUNCH_AGENT_LABEL = 'ai.secretless.watch';

/** How long `installWatcher` waits for the process it started to write its PID file. */
const START_WAIT_MS = 3000;

/** Escape a string for safe inclusion in XML content or attribute values. */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** Shows one desktop notification. The watcher never waits for it. */
export type Notifier = (title: string, body: string) => void;

export interface StartWatchOptions {
  logFile?: string;
  /**
   * Directories to watch besides the default transcript directory, as
   * `watch start --dir` gives them. The default is always covered (#237).
   */
  dirs?: string[];
  /** Shows a notification for each file redacted; the desktop notifier unless given. */
  notify?: Notifier;
}

/**
 * The directories a watcher covers: the default transcript directory
 * (`~/.claude/projects`, or `projects/` under `CLAUDE_CONFIG_DIR`), then each
 * extra directory given, made absolute, each listed once.
 */
export function resolveWatchDirs(extra: readonly string[] = []): string[] {
  const dirs: string[] = [];
  for (const dir of [defaultTranscriptDir(), ...extra]) {
    const absolute = path.resolve(dir);
    if (!dirs.includes(absolute)) dirs.push(absolute);
  }
  return dirs;
}

/**
 * Start watching Claude Code transcripts for credentials.
 * Runs in the foreground, monitoring file changes and auto-redacting.
 *
 * Returns true once the watcher is installed, false when it did not start
 * (the reason is written to the log). The watcher lives in this process, so a
 * caller that exits ends it. A directory that does not exist is logged and
 * left out; with none left there is nothing to watch, and the watcher does
 * not start.
 */
export function startWatch(options: StartWatchOptions = {}): boolean {
  const logPath = options.logFile || LOG_FILE;
  const notify = options.notify ?? desktopNotify;

  // Ensure directories exist
  fs.mkdirSync(SECRETLESS_DIR, { recursive: true });

  const dirs = resolveWatchDirs(options.dirs);
  const present: string[] = [];
  for (const dir of dirs) {
    if (fs.existsSync(dir)) {
      present.push(dir);
    } else {
      log(logPath, 'Transcript directory not found: ' + dir);
    }
  }
  if (present.length === 0) {
    log(logPath, 'Start a Claude Code session first, then re-run.');
    return false;
  }

  // Write PID file with start time for TOCTOU protection (O_EXCL prevents concurrent writers)
  const pidData = JSON.stringify({ pid: process.pid, startedAt: Date.now(), dirs: present });
  try {
    const fd = fs.openSync(PID_FILE, 'wx');
    fs.writeSync(fd, pidData);
    fs.closeSync(fd);
  } catch (err: any) {
    if (err.code === 'EEXIST') {
      // Another watcher may be running — check before overwriting
      if (isWatchRunning()) {
        log(logPath, 'Another watcher is already running.');
        return false;
      }
      // Stale PID file — overwrite
      fs.writeFileSync(PID_FILE, pidData);
    } else {
      throw err;
    }
  }
  log(logPath, `Watcher started (PID: ${process.pid})`);
  log(logPath, `Monitoring: ${present.join(', ')}`);

  // Track debounce timers per file
  const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();
  const watchers: fs.FSWatcher[] = [];

  for (const dir of present) {
    // Canonical resolved path, taken once, so a symlink swapped in later
    // cannot point the path check elsewhere.
    const resolvedDir = fs.realpathSync(dir);
    let watcher: fs.FSWatcher;
    try {
      watcher = fs.watch(dir, { recursive: true }, (eventType, filename) => {
        if (!filename || !filename.endsWith('.jsonl')) return;

        const fullPath = path.join(dir, filename);

        // Path traversal protection: resolve and verify the path stays within the directory
        let realPath: string;
        try {
          realPath = fs.realpathSync(fullPath);
        } catch {
          return; // File may not exist yet
        }
        if (!realPath.startsWith(resolvedDir + path.sep)) return;

        // Skip if in tool-results
        if (filename.includes('tool-results')) return;

        // Debounce: Claude Code writes in bursts
        const existing = debounceTimers.get(fullPath);
        if (existing) clearTimeout(existing);

        debounceTimers.set(fullPath, setTimeout(() => {
          debounceTimers.delete(fullPath);
          void processFile(fullPath, logPath, undefined, notify);
        }, DEBOUNCE_MS));
      });
    } catch (err) {
      log(logPath, `Cannot watch ${dir}: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    watchers.push(watcher);
  }

  if (watchers.length === 0) {
    try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
    log(logPath, 'No directory could be watched.');
    return false;
  }

  // Graceful shutdown
  const shutdown = () => {
    log(logPath, 'Watcher stopping...');
    for (const watcher of watchers) watcher.close();
    for (const timer of debounceTimers.values()) clearTimeout(timer);
    debounceTimers.clear();
    try { fs.unlinkSync(PID_FILE); } catch { /* ignore */ }
    log(logPath, 'Watcher stopped.');
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  return true;
}

/**
 * Redact one transcript, then mark exposed any stored secret whose value was
 * redacted (#236), then notify (#237). Exported for tests; `createStore` is
 * read only when something was redacted, and `notify` is called only then,
 * with pattern names and the file, never a value. Without a `notify` nothing
 * is shown: the watcher passes the desktop notifier.
 */
export async function processFile(
  filePath: string,
  logPath: string,
  createStore: () => SecretStore = () => new SecretStore(),
  notify: Notifier = () => {},
): Promise<void> {
  // Held in memory for the stored-secret comparison below, then dropped.
  const spans: RedactedSpan[] = [];
  try {
    const { findings, redactedLines, readState } = scanTranscriptFile(filePath, false, (span, where) => {
      spans.push({ span, ...where });
    });
    if (findings.length > 0 && redactedLines && readState) {
      // A file that changed after it was read is left as it is: the change
      // fires another event, which reads it again.
      atomicWrite(filePath, redactedLines, readState);
      const displayPath = filePath.replace(os.homedir(), '~');
      log(logPath, `Redacted ${findings.length} credential(s) in ${displayPath}`);
      for (const f of findings) {
        log(logPath, `  ${f.jsonPath} → [REDACTED:${f.patternId}]`);
      }
      const marks = await markRedactedSecretsExposed(spans, createStore, { foundBy: 'watch' });
      if (marks.notChecked) log(logPath, `Not checked whether a redacted value is a stored secret: ${marks.notChecked}`);
      for (const m of marks.marked) {
        // The store holds names `secret set` refuses, ones that start with a
        // digit, '_' or '-'. Such a name gets the reason in place of the
        // `secret set` command.
        const next = isSettableSecretName(m.name)
          ? `then: secretless-ai secret set ${m.name}`
          : `then store the new value the way this one was first stored. ${notSettableReason(m.name)}.`;
        log(logPath, `Stored secret ${m.name} marked exposed. Rotate it at its provider, ${next}`);
      }
      for (const m of marks.alreadyOpen) log(logPath, `Stored secret ${m.name} already marked exposed since ${m.exposedAt}`);
      for (const m of marks.failed) log(logPath, `Stored secret ${m.name} NOT marked exposed: ${m.reason}`);
      const notice = watchNotification(findings, displayPath, marks);
      try {
        notify(notice.title, notice.body);
      } catch (err) {
        log(logPath, `Notification not shown: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  } catch (err) {
    log(logPath, `Error processing ${filePath}: ${err}`);
  } finally {
    spans.length = 0;
  }
}

/**
 * The notification for one redacted transcript: how many values, which
 * patterns, which file, and which stored secrets were among them. A value is
 * never part of it; the findings carry pattern ids and names only.
 */
export function watchNotification(
  findings: readonly TranscriptFinding[],
  displayPath: string,
  marks?: ExposureMarks,
): { title: string; body: string } {
  const names = [...new Set(findings.map((f) => f.patternName))];
  const n = findings.length;
  let body = `Redacted ${n} credential${n === 1 ? '' : 's'} (${names.join(', ')}) in ${displayPath}.`;
  const exposed = marks ? [...marks.marked, ...marks.alreadyOpen].map((m) => m.name) : [];
  if (exposed.length > 0) {
    body += ` Stored secret${exposed.length === 1 ? '' : 's'} ${exposed.join(', ')} exposed: rotate at the provider, then secret set.`;
  }
  return { title: 'Secretless', body };
}

/** An AppleScript string literal: backslashes and double quotes escaped. */
function appleScriptString(text: string): string {
  return '"' + text.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

/**
 * The command that shows a desktop notification on `platform`: `osascript`
 * on macOS, `notify-send` on Linux, none elsewhere. Control characters are
 * replaced, so a file name cannot end the AppleScript statement.
 */
export function notificationCommand(
  platform: NodeJS.Platform,
  title: string,
  body: string,
): { command: string; args: string[] } | null {
  const text = (s: string) => s.replace(/[\u0000-\u001f\u007f]/g, '?');
  if (platform === 'darwin') {
    return {
      command: 'osascript',
      args: ['-e', `display notification ${appleScriptString(text(body))} with title ${appleScriptString(text(title))}`],
    };
  }
  if (platform === 'linux') {
    return { command: 'notify-send', args: ['--app-name=Secretless', text(title), text(body)] };
  }
  return null;
}

/**
 * Show a desktop notification, best effort: a machine without the notifier,
 * or one that refuses it, changes nothing for the watcher, whose log still
 * has the line.
 */
export function desktopNotify(title: string, body: string): void {
  const notice = notificationCommand(process.platform, title, body);
  if (!notice) return;
  try {
    const child = spawn(notice.command, notice.args, { stdio: 'ignore', detached: true });
    child.on('error', () => { /* no notifier on this machine */ });
    child.unref();
  } catch {
    // Same: the notification is an extra, never a reason to stop watching.
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

export interface InstallWatcherResult {
  /** A watcher runs now: the one this call started, or one that was already running. */
  running: boolean;
  alreadyRunning: boolean;
  pid: number | null;
  /** The directories the running watcher covers, or the ones it would have. */
  dirs: string[];
  /** The macOS login agent was written, so the watcher also starts at login. */
  launchAgent: boolean;
  /** Why no watcher runs, when none does. */
  reason?: string;
}

export interface InstallWatcherOptions {
  /** Extra directories, as `--dir` gives them; the default is always covered. */
  dirs?: string[];
  /** The CLI script the watcher process runs; `cli.js` beside this module unless given. */
  script?: string;
  /** The platform the login agent decision is made for; this one unless given. */
  platform?: NodeJS.Platform;
  /** The PID file read for a running watcher; the real one unless a test gives its own. */
  pidFile?: string;
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Start the watcher as a background process, and on macOS write the login
 * agent so it starts at each login (#237). `init` and `watch install` call
 * this. A watcher already running is left as it is. With no transcript
 * directory present nothing is started: the watcher would exit at once, and
 * a login agent would start it again and again.
 */
export async function installWatcher(options: InstallWatcherOptions = {}): Promise<InstallWatcherResult> {
  const dirs = resolveWatchDirs(options.dirs);
  const pidFile = options.pidFile ?? PID_FILE;
  const current = watchStatus(pidFile);
  if (current.running) {
    return { running: true, alreadyRunning: true, pid: current.pid, dirs: current.dirs.length > 0 ? current.dirs : dirs, launchAgent: false };
  }
  const notStarted = (reason: string): InstallWatcherResult => ({
    running: false, alreadyRunning: false, pid: null, dirs, launchAgent: false, reason,
  });

  if (!dirs.some((d) => fs.existsSync(d))) {
    return notStarted(`no transcript directory to watch (${dirs.join(', ')} not found)`);
  }
  const script = options.script ?? path.join(__dirname, 'cli.js');
  if (!isFile(script)) {
    return notStarted(`${script} is not a file, so no watcher process was started`);
  }

  fs.mkdirSync(SECRETLESS_DIR, { recursive: true });
  const args = [script, 'watch', 'start', ...(options.dirs ?? []).flatMap((d) => ['--dir', d])];
  try {
    const child = spawn(process.execPath, args, { detached: true, stdio: 'ignore' });
    child.on('error', () => { /* reported below: the PID file never appears */ });
    child.unref();
  } catch (err) {
    return notStarted(`the watcher process could not be started: ${err instanceof Error ? err.message : String(err)}`);
  }

  const deadline = Date.now() + START_WAIT_MS;
  while (!isWatchRunning(pidFile) && Date.now() < deadline) await sleep(50);
  const after = watchStatus(pidFile);
  if (!after.running) {
    return notStarted(`the watcher did not report itself running within ${START_WAIT_MS / 1000} seconds; see ${LOG_FILE}`);
  }

  const platform = options.platform ?? process.platform;
  const launchAgent = platform === 'darwin' ? installLaunchAgent({ dirs: options.dirs }) : false;
  return { running: true, alreadyRunning: false, pid: after.pid, dirs: after.dirs.length > 0 ? after.dirs : dirs, launchAgent };
}

export interface LaunchAgentOptions {
  /** Extra directories the agent's `watch start` is given as `--dir`. */
  dirs?: string[];
  /** Where `Library/LaunchAgents` is; the home directory unless given. */
  homeDir?: string;
  platform?: NodeJS.Platform;
}

/**
 * Install macOS LaunchAgent for auto-start on login.
 */
export function installLaunchAgent(options: LaunchAgentOptions = {}): boolean {
  if ((options.platform ?? process.platform) !== 'darwin') return false;

  const launchAgentsDir = path.join(options.homeDir ?? os.homedir(), 'Library', 'LaunchAgents');
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
  const safeLogFile = escapeXml(LOG_FILE);
  const programArguments = [npxPath, 'secretless-ai', 'watch', 'start', ...(options.dirs ?? []).flatMap((d) => ['--dir', path.resolve(d)])]
    .map((arg) => `    <string>${escapeXml(arg)}</string>`)
    .join('\n');

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${safeLabel}</string>
  <key>ProgramArguments</key>
  <array>
${programArguments}
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
export function uninstallLaunchAgent(options: { homeDir?: string; platform?: NodeJS.Platform } = {}): boolean {
  if ((options.platform ?? process.platform) !== 'darwin') return false;

  const plistPath = path.join(options.homeDir ?? os.homedir(), 'Library', 'LaunchAgents', `${LAUNCH_AGENT_LABEL}.plist`);
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
