/**
 * Session state management — tracks Touch ID / biometric session warmth.
 *
 * The session state file at ~/.secretless-ai/session.json records when the
 * user last authenticated via biometrics. The broker and hook commands check
 * this file to determine if re-authentication is needed.
 *
 * This is a lightweight, file-based approach that avoids IPC overhead.
 * The Touch ID helper writes the session file; consumers only read it.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

const SECRETLESS_DIR = path.join(os.homedir(), '.secretless-ai');
const SESSION_FILE = path.join(SECRETLESS_DIR, 'session.json');

/** Derive an HMAC key from machine-local identity (not secret, but prevents trivial forgery). */
function getHmacKey(): string {
  return `${os.homedir()}-secretless-session-${os.userInfo().username}`;
}

/** Compute HMAC-SHA256 over the given content string. */
function computeHmac(content: string): string {
  return crypto.createHmac('sha256', getHmacKey()).update(content).digest('hex');
}

/** Default session duration: 5 minutes (300 seconds). */
const DEFAULT_SESSION_TTL_SECONDS = 300;

/** Maximum allowed session TTL: 8 hours. */
const MAX_SESSION_TTL_SECONDS = 8 * 60 * 60;

export interface SessionState {
  /** ISO 8601 timestamp of last successful biometric authentication. */
  authenticatedAt: string;
  /** Session TTL in seconds from the time of authentication. */
  ttlSeconds: number;
  /** PID of the process that created the session (informational). */
  pid: number;
  /** Hostname where the session was created (multi-machine safety). */
  hostname: string;
  /** Session version for forward compatibility. */
  version: 1;
}

export interface SessionStatus {
  /** Whether the session is currently warm (authenticated and not expired). */
  warm: boolean;
  /** Seconds remaining until session expires. 0 if expired or no session. */
  remainingSeconds: number;
  /** ISO 8601 expiry time. Empty string if no session. */
  expiresAt: string;
  /** ISO 8601 time of last authentication. Empty string if no session. */
  authenticatedAt: string;
  /** The configured TTL in seconds. */
  ttlSeconds: number;
}

/**
 * Read the current session state from disk.
 * Returns null if no session file exists or it is unreadable.
 */
export function readSessionState(): SessionState | null {
  if (!fs.existsSync(SESSION_FILE)) return null;

  try {
    const raw = fs.readFileSync(SESSION_FILE, 'utf-8');
    const parsed = JSON.parse(raw);

    if (
      parsed &&
      typeof parsed === 'object' &&
      parsed.version === 1 &&
      typeof parsed.authenticatedAt === 'string' &&
      typeof parsed.ttlSeconds === 'number'
    ) {
      // Verify HMAC integrity if present
      if (typeof parsed.hmac === 'string') {
        const storedHmac = parsed.hmac;
        // Rebuild JSON without the hmac field to compute expected HMAC
        const { hmac: _removed, ...dataWithoutHmac } = parsed;
        const content = JSON.stringify(dataWithoutHmac, null, 2);
        const expectedHmac = computeHmac(content);
        if (!crypto.timingSafeEqual(Buffer.from(storedHmac, 'hex'), Buffer.from(expectedHmac, 'hex'))) {
          // HMAC mismatch — treat as expired/tampered
          return null;
        }
      }
      // Return state without the hmac field
      const { hmac: _h, ...state } = parsed;
      return state as SessionState;
    }
  } catch {
    // Corrupted session file — treat as no session
  }

  return null;
}

/**
 * Write a new session state to disk.
 * Called after successful biometric authentication.
 */
export function writeSessionState(ttlSeconds?: number): SessionState {
  const ttl = Math.min(
    Math.max(ttlSeconds ?? DEFAULT_SESSION_TTL_SECONDS, 1),
    MAX_SESSION_TTL_SECONDS,
  );

  const state: SessionState = {
    authenticatedAt: new Date().toISOString(),
    ttlSeconds: ttl,
    pid: process.pid,
    hostname: os.hostname(),
    version: 1,
  };

  // Compute HMAC over the state JSON and include it in the persisted file
  const content = JSON.stringify(state, null, 2);
  const hmac = computeHmac(content);
  const persisted = { ...state, hmac };

  fs.mkdirSync(SECRETLESS_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(SESSION_FILE, JSON.stringify(persisted, null, 2), { mode: 0o600 });

  return state;
}

/**
 * Get the current session status (warm/expired, remaining time).
 * This is the primary read path — optimized for speed.
 */
export function getSessionStatus(ttlOverride?: number): SessionStatus {
  const state = readSessionState();

  if (!state) {
    return {
      warm: false,
      remainingSeconds: 0,
      expiresAt: '',
      authenticatedAt: '',
      ttlSeconds: ttlOverride ?? DEFAULT_SESSION_TTL_SECONDS,
    };
  }

  const authenticatedAt = new Date(state.authenticatedAt).getTime();
  const ttl = ttlOverride ?? state.ttlSeconds;
  const expiresAtMs = authenticatedAt + ttl * 1000;
  const now = Date.now();
  const remainingMs = expiresAtMs - now;

  const warm = remainingMs > 0;
  const remainingSeconds = warm ? Math.ceil(remainingMs / 1000) : 0;

  return {
    warm,
    remainingSeconds,
    expiresAt: warm ? new Date(expiresAtMs).toISOString() : '',
    authenticatedAt: state.authenticatedAt,
    ttlSeconds: ttl,
  };
}

/**
 * Check if the session is warm. Fast path: reads file + compares timestamp.
 * Returns true if authenticated within the TTL window.
 */
export function isSessionWarm(): boolean {
  return getSessionStatus().warm;
}

/**
 * Clear the session state (force re-authentication on next check).
 */
export function clearSessionState(): boolean {
  if (!fs.existsSync(SESSION_FILE)) return false;

  try {
    fs.unlinkSync(SESSION_FILE);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get the session file path (for testing/diagnostics).
 */
export function getSessionFilePath(): string {
  return SESSION_FILE;
}

export {
  DEFAULT_SESSION_TTL_SECONDS,
  MAX_SESSION_TTL_SECONDS,
};
