/**
 * Touch ID integration — manages biometric authentication on macOS.
 *
 * Uses the macOS LocalAuthentication framework via an inline Swift script
 * to trigger real Touch ID authentication. The Swift script is compiled
 * once and cached at ~/.secretless-ai/bin/secretless-touchid.
 *
 * Falls back gracefully on non-macOS platforms or when Touch ID is unavailable.
 */

import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execSync, execFileSync, type ExecSyncOptions } from 'child_process';
import { writeSessionState, getSessionStatus, type SessionStatus } from './session-state';

const SECRETLESS_DIR = path.join(os.homedir(), '.secretless-ai');
const BIN_DIR = path.join(SECRETLESS_DIR, 'bin');
const TOUCHID_BINARY = path.join(BIN_DIR, 'secretless-touchid');
const TOUCHID_SWIFT_SRC = path.join(BIN_DIR, 'secretless-touchid.swift');

/**
 * Swift source for the Touch ID helper binary.
 * Uses LAContext from LocalAuthentication framework to trigger real biometrics.
 * Exits 0 on success, 1 on failure/cancellation.
 */
const SWIFT_SOURCE = `
import Foundation
import LocalAuthentication

let context = LAContext()

// Allow reuse of recent biometric auth within the session
if CommandLine.arguments.count > 1, let ttl = TimeInterval(CommandLine.arguments[1]) {
    context.touchIDAuthenticationAllowableReuseDuration = ttl
}

var error: NSError?
guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
    // No biometric hardware or not enrolled
    // Fall back to device passcode
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        fputs("error: No authentication method available\\n", stderr)
        exit(2)
    }
    let semaphore = DispatchSemaphore(value: 0)
    var authSuccess = false
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Secretless: Authenticate to access credentials") { success, _ in
        authSuccess = success
        semaphore.signal()
    }
    semaphore.wait()
    exit(authSuccess ? 0 : 1)
}

let semaphore = DispatchSemaphore(value: 0)
var authSuccess = false

context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Secretless: Authenticate to access credentials") { success, _ in
    authSuccess = success
    semaphore.signal()
}

semaphore.wait()
exit(authSuccess ? 0 : 1)
`.trim();

/** Hash of the Swift source to detect when recompilation is needed. */
const SWIFT_SOURCE_HASH = crypto.createHash('sha256').update(SWIFT_SOURCE).digest('hex').slice(0, 12);

/** Check if we're running on macOS. */
export function isMacOS(): boolean {
  return os.platform() === 'darwin';
}

/** Check if Touch ID hardware is available. */
export function isTouchIDAvailable(): boolean {
  if (!isMacOS()) return false;

  try {
    const result = execSync('bioutil -r -s', {
      encoding: 'utf-8',
      timeout: 5000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return result.toLowerCase().includes('biometric');
  } catch {
    return false;
  }
}

/**
 * Ensure the Touch ID helper binary is compiled and up to date.
 * Compiles from Swift source on first run or when source changes.
 * Returns the path to the binary, or null if compilation fails.
 */
export function ensureTouchIdBinary(): string | null {
  if (!isMacOS()) return null;

  fs.mkdirSync(BIN_DIR, { recursive: true, mode: 0o700 });

  // Check if binary exists and is current
  const hashFile = TOUCHID_BINARY + '.hash';
  if (fs.existsSync(TOUCHID_BINARY) && fs.existsSync(hashFile)) {
    try {
      const existingHash = fs.readFileSync(hashFile, 'utf-8').trim();
      if (existingHash === SWIFT_SOURCE_HASH) {
        return TOUCHID_BINARY;
      }
    } catch {
      // Recompile
    }
  }

  // Write Swift source
  fs.writeFileSync(TOUCHID_SWIFT_SRC, SWIFT_SOURCE, { mode: 0o600 });

  // Compile
  try {
    execSync(
      `swiftc -O -o "${TOUCHID_BINARY}" "${TOUCHID_SWIFT_SRC}" -framework LocalAuthentication 2>&1`,
      {
        encoding: 'utf-8',
        timeout: 30000,
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );
    fs.chmodSync(TOUCHID_BINARY, 0o700);
    fs.writeFileSync(hashFile, SWIFT_SOURCE_HASH, { mode: 0o600 });
    return TOUCHID_BINARY;
  } catch (err) {
    // Compilation failed — clean up
    try { fs.unlinkSync(TOUCHID_SWIFT_SRC); } catch { /* ignore */ }
    return null;
  }
}

/**
 * Warm the session by triggering Touch ID authentication.
 *
 * On macOS: compiles (once) and runs a Swift binary that calls LAContext.
 * On other platforms: just writes session state (no biometric gate).
 *
 * @param ttlSeconds - How long the session should remain warm
 * @returns Session status after warming
 */
export async function warmSession(ttlSeconds?: number): Promise<SessionStatus> {
  const ttl = ttlSeconds ?? 300;

  if (!isMacOS()) {
    // On non-macOS, just write session state (no biometric gate)
    writeSessionState(ttl);
    return getSessionStatus();
  }

  if (!isTouchIDAvailable()) {
    // No biometric hardware — write session without biometric gate
    writeSessionState(ttl);
    return getSessionStatus();
  }

  // Compile the Touch ID binary if needed
  const binary = ensureTouchIdBinary();
  if (!binary) {
    // Compilation failed — fall back to session-only (no biometric gate)
    writeSessionState(ttl);
    return getSessionStatus();
  }

  // Run the Touch ID binary (this triggers the actual biometric prompt)
  const authenticated = runTouchIdBinary(binary, ttl);

  if (!authenticated) {
    return {
      warm: false,
      remainingSeconds: 0,
      expiresAt: '',
      authenticatedAt: '',
      ttlSeconds: ttl,
      tampered: false,
    };
  }

  // Authentication succeeded — write session state
  writeSessionState(ttl);
  return getSessionStatus();
}

/**
 * Run the Touch ID binary.
 * @param binary - Path to the compiled binary
 * @param reuseDuration - LAContext reuse duration in seconds
 * @returns true if authentication succeeded
 */
function runTouchIdBinary(binary: string, reuseDuration: number): boolean {
  try {
    execFileSync(binary, [String(reuseDuration)], {
      timeout: 60000, // 60s for user to complete Touch ID
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return true;
  } catch {
    return false;
  }
}
