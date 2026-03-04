/**
 * Warm command — interactive session warmup for credential access.
 *
 * Intended to be run once before starting an AI coding session.
 * Warms the biometric session so subsequent credential access
 * doesn't trigger repeated Touch ID prompts.
 *
 * Also ensures the broker daemon is running.
 */

import { warmSession, isMacOS, isTouchIDAvailable } from './touchid';
import { getSessionStatus, type SessionStatus } from './session-state';
import { isDaemonRunning, startDaemon, getDaemonStatus } from '../broker/daemon';

export interface WarmResult {
  /** Whether the session is now warm. */
  sessionWarm: boolean;
  /** Session status after warming. */
  session: SessionStatus;
  /** Whether the broker daemon is running. */
  brokerRunning: boolean;
  /** Whether the broker was started by this command. */
  brokerStarted: boolean;
  /** Whether Touch ID was used (macOS only). */
  touchIdUsed: boolean;
  /** Error message if warming failed. */
  error?: string;
}

/**
 * Warm the session: authenticate once, start broker if needed.
 *
 * @param ttlSeconds - Session TTL in seconds (default: 300 = 5 minutes)
 * @param startBrokerIfStopped - Whether to start the broker if not running
 */
export async function warm(
  ttlSeconds?: number,
  startBrokerIfStopped = true,
): Promise<WarmResult> {
  const result: WarmResult = {
    sessionWarm: false,
    session: getSessionStatus(),
    brokerRunning: false,
    brokerStarted: false,
    touchIdUsed: false,
  };

  // Check if session is already warm
  const currentStatus = getSessionStatus(ttlSeconds);
  if (currentStatus.warm) {
    result.sessionWarm = true;
    result.session = currentStatus;
    result.brokerRunning = isDaemonRunning();
    return result;
  }

  // Warm the biometric session
  try {
    result.touchIdUsed = isMacOS() && isTouchIDAvailable();
    const session = await warmSession(ttlSeconds);
    result.session = session;
    result.sessionWarm = session.warm;
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    return result;
  }

  // Start broker if not running
  result.brokerRunning = isDaemonRunning();
  if (!result.brokerRunning && startBrokerIfStopped) {
    try {
      await startDaemon();
      result.brokerRunning = true;
      result.brokerStarted = true;
    } catch {
      // Broker start failure is non-fatal for warm
      // Session is still warm even if broker isn't running
    }
  }

  return result;
}
