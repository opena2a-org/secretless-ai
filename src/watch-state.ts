/**
 * What the transcript watcher leaves on disk while it runs: a PID file naming
 * the process and the directories it covers, and the log it appends to.
 *
 * Kept apart from `watch.ts` so `status` can read the covered directories
 * without loading the watcher itself.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export const SECRETLESS_DIR = path.join(os.homedir(), '.secretless-ai');
export const PID_FILE = path.join(SECRETLESS_DIR, 'watch.pid');
export const LOG_FILE = path.join(SECRETLESS_DIR, 'watch.log');

/** The PID file's content: the process, when it started, and what it watches. */
export interface WatchPidRecord {
  pid: number;
  startedAt: number;
  /** Absolute paths of the directories the watcher covers; absent in a file an older watcher wrote. */
  dirs?: string[];
}

export interface WatchStatus {
  running: boolean;
  /** The watcher's process id when it is running, else null. */
  pid: number | null;
  /** The directories the running watcher covers; empty when it is not running or its PID file does not name them. */
  dirs: string[];
}

/**
 * Read and parse the PID file. Handles both the legacy plain-number and the
 * JSON format. `pidFile` is for tests, which must not share the real one.
 */
export function readPidFile(pidFile: string = PID_FILE): WatchPidRecord | null {
  if (!fs.existsSync(pidFile)) return null;

  try {
    const raw = fs.readFileSync(pidFile, 'utf-8').trim();
    try {
      const data = JSON.parse(raw);
      if (data && typeof data === 'object' && typeof data.pid === 'number') {
        const record: WatchPidRecord = { pid: data.pid, startedAt: typeof data.startedAt === 'number' ? data.startedAt : 0 };
        if (Array.isArray(data.dirs)) {
          record.dirs = data.dirs.filter((d: unknown): d is string => typeof d === 'string');
        }
        return record;
      }
    } catch {
      // Not valid JSON: fall through to the legacy plain-number form.
    }
    const pid = parseInt(raw, 10);
    if (!isNaN(pid) && pid > 0) return { pid, startedAt: 0 };
  } catch {
    // Unreadable PID file.
  }
  return null;
}

/** True when the process the PID file names is alive. */
export function isWatchRunning(pidFile: string = PID_FILE): boolean {
  const pidInfo = readPidFile(pidFile);
  if (!pidInfo) return false;

  try {
    process.kill(pidInfo.pid, 0); // Signal 0: is the process there?
    return true;
  } catch {
    return false;
  }
}

/** Whether the watcher runs, as which process, and which directories it covers. */
export function watchStatus(pidFile: string = PID_FILE): WatchStatus {
  const pidInfo = readPidFile(pidFile);
  if (!pidInfo || !isWatchRunning(pidFile)) return { running: false, pid: null, dirs: [] };
  return { running: true, pid: pidInfo.pid, dirs: pidInfo.dirs ?? [] };
}
