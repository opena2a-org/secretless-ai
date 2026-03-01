/**
 * Audit logger — append-only JSONL audit trail for broker operations.
 *
 * Writes structured audit entries to ~/.secretless-ai/broker-audit.log in
 * JSON Lines format. Supports automatic log rotation at 50MB with 5 retained
 * files. NEVER logs credential values.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { AuditEntry } from './types';

const DEFAULT_AUDIT_LOG = path.join(os.homedir(), '.secretless-ai', 'broker-audit.log');

/** Maximum log file size before rotation (50 MB). */
const MAX_FILE_SIZE = 50 * 1024 * 1024;

/** Number of rotated log files to retain. */
const MAX_RETAINED = 5;

export class AuditLogger {
  private readonly logPath: string;
  private fd: number | null = null;

  constructor(logPath?: string) {
    this.logPath = logPath ?? DEFAULT_AUDIT_LOG;
  }

  /**
   * Write an audit entry to the log file.
   * Creates the log directory and file if they do not exist.
   */
  log(entry: AuditEntry): void {
    const dir = path.dirname(this.logPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    // Check rotation before writing
    this.rotateIfNeeded();

    const line = JSON.stringify(entry) + '\n';

    // Append-only write with restrictive permissions
    fs.appendFileSync(this.logPath, line, { mode: 0o600 });
  }

  /**
   * Create an audit entry from individual fields.
   * Convenience method that populates the timestamp automatically.
   */
  logEvent(
    eventType: string,
    agentId: string,
    credentialName: string,
    policyId: string,
    result: 'allowed' | 'denied',
    reason: string,
    latencyMs: number,
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      eventType,
      agentId,
      credentialName,
      policyId,
      result,
      reason,
      latencyMs,
    });
  }

  /**
   * Read recent audit entries (last N lines).
   * Returns entries in chronological order (oldest first).
   */
  readRecent(count: number): AuditEntry[] {
    if (!fs.existsSync(this.logPath)) return [];

    try {
      const content = fs.readFileSync(this.logPath, 'utf-8');
      const lines = content.trim().split('\n').filter(l => l.length > 0);
      const recent = lines.slice(-count);

      return recent.map(line => {
        try {
          return JSON.parse(line) as AuditEntry;
        } catch {
          return null;
        }
      }).filter((e): e is AuditEntry => e !== null);
    } catch {
      return [];
    }
  }

  /**
   * Close the audit logger and release file handles.
   */
  close(): void {
    if (this.fd !== null) {
      try {
        fs.closeSync(this.fd);
      } catch {
        // Ignore close errors
      }
      this.fd = null;
    }
  }

  /** Rotate log file if it exceeds the size limit. */
  private rotateIfNeeded(): void {
    if (!fs.existsSync(this.logPath)) return;

    try {
      const stat = fs.statSync(this.logPath);
      if (stat.size < MAX_FILE_SIZE) return;
    } catch {
      return;
    }

    // Rotate: .4 -> .5 (deleted), .3 -> .4, .2 -> .3, .1 -> .2, current -> .1
    for (let i = MAX_RETAINED; i >= 1; i--) {
      const older = `${this.logPath}.${i}`;
      const newer = i === 1 ? this.logPath : `${this.logPath}.${i - 1}`;

      if (i === MAX_RETAINED) {
        // Delete the oldest
        try { fs.unlinkSync(older); } catch { /* ignore */ }
      }

      if (fs.existsSync(newer)) {
        try {
          fs.renameSync(newer, older);
        } catch {
          // If rename fails (cross-device), copy and truncate
          try {
            fs.copyFileSync(newer, older);
            fs.writeFileSync(newer, '', { mode: 0o600 });
          } catch {
            // Give up on this rotation step
          }
        }
      }
    }
  }
}
