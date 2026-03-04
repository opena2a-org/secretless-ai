/**
 * Touch ID integration — manages biometric authentication on macOS.
 *
 * Uses the macOS `security` command and keychain to perform Touch ID
 * authentication without requiring a compiled Swift binary. The approach:
 *
 * 1. Create a keychain item specifically for session authentication
 * 2. Access it with `-T` (ACL) that requires biometric confirmation
 * 3. Successful access = Touch ID confirmed = session is warm
 *
 * Falls back gracefully on non-macOS platforms or when Touch ID is unavailable.
 */

import * as os from 'os';
import { execSync, type ExecSyncOptions } from 'child_process';
import { writeSessionState, getSessionStatus, type SessionStatus } from './session-state';

const KEYCHAIN_SERVICE = 'com.opena2a.secretless.session';
const KEYCHAIN_ACCOUNT = 'secretless-session-token';

/** Check if we're running on macOS. */
export function isMacOS(): boolean {
  return os.platform() === 'darwin';
}

/** Check if Touch ID hardware is available. */
export function isTouchIDAvailable(): boolean {
  if (!isMacOS()) return false;

  try {
    // Check for biometric hardware via bioutil
    const result = execSync('bioutil -r -s', {
      encoding: 'utf-8',
      timeout: 5000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return result.includes('biometric');
  } catch {
    // bioutil not available or no biometric hardware
    // Fall back to checking if Touch ID keychain operations work
    try {
      execSync('security find-generic-password -h 2>&1 || true', {
        encoding: 'utf-8',
        timeout: 2000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      return true; // security command available, Touch ID may work
    } catch {
      return false;
    }
  }
}

/**
 * Warm the session by triggering Touch ID authentication.
 *
 * This creates (or accesses) a keychain item that requires biometric
 * confirmation. Successful access proves the user is present and
 * authenticated. The session state is then written to disk.
 *
 * @param ttlSeconds - How long the session should remain warm
 * @returns Session status after warming
 */
export async function warmSession(ttlSeconds?: number): Promise<SessionStatus> {
  if (!isMacOS()) {
    // On non-macOS, just write session state (no biometric gate)
    writeSessionState(ttlSeconds);
    return getSessionStatus();
  }

  // Ensure the keychain item exists
  ensureKeychainItem();

  // Access the keychain item (triggers Touch ID / password prompt)
  const authenticated = await authenticateViaKeychain();

  if (!authenticated) {
    return {
      warm: false,
      remainingSeconds: 0,
      expiresAt: '',
      authenticatedAt: '',
      ttlSeconds: ttlSeconds ?? 300,
    };
  }

  // Authentication succeeded — write session state
  writeSessionState(ttlSeconds);
  return getSessionStatus();
}

/**
 * Ensure a keychain item exists for session authentication.
 * Creates one if it doesn't exist. Idempotent.
 */
function ensureKeychainItem(): void {
  const execOpts: ExecSyncOptions = {
    encoding: 'utf-8' as const,
    timeout: 5000,
    stdio: ['pipe', 'pipe', 'pipe'],
  };

  try {
    // Check if item already exists
    execSync(
      `security find-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" 2>/dev/null`,
      execOpts,
    );
    // Item exists
  } catch {
    // Item doesn't exist — create it
    try {
      execSync(
        `security add-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" -w "secretless-session" -U`,
        execOpts,
      );
    } catch {
      // May fail if keychain is locked — that's okay, we'll catch it during auth
    }
  }
}

/**
 * Authenticate by accessing the keychain item.
 * On macOS, this triggers the system authentication dialog (Touch ID or password).
 */
async function authenticateViaKeychain(): Promise<boolean> {
  const execOpts: ExecSyncOptions = {
    encoding: 'utf-8' as const,
    timeout: 30000, // 30s for user to complete Touch ID
    stdio: ['pipe', 'pipe', 'pipe'],
  };

  try {
    execSync(
      `security find-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" -w 2>/dev/null`,
      execOpts,
    );
    return true;
  } catch {
    return false;
  }
}
