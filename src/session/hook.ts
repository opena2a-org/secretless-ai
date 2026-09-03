/**
 * Hook command — idempotent session check for Claude Code PreToolUse hooks.
 *
 * Designed to run before every Bash tool call in Claude Code.
 * Must be extremely fast (<5ms) in the warm path.
 *
 * Behavior:
 *   - Session warm:    exit 0 (silent, no output)
 *   - Session expired: exit 2, PreToolUse deny JSON on stdout, reason on stderr
 *   - Session tampered (HMAC mismatch): exit 2, deny JSON on stdout, reason on stderr
 *   - Not installed:   exit 0 (don't block non-Secretless users)
 *
 * Usage in Claude Code hooks config:
 *   {
 *     "hooks": {
 *       "PreToolUse": [{
 *         "matcher": "Bash",
 *         "hooks": [{
 *           "type": "command",
 *           "command": "secretless-ai hook --check-only"
 *         }]
 *       }]
 *     }
 *   }
 */

import { getSessionStatus } from './session-state';
import { isDaemonRunning } from '../broker/daemon';

export interface HookCheckResult {
  /** Whether the check passed (allow the tool call). */
  passed: boolean;
  /** Whether the session is warm. */
  sessionWarm: boolean;
  /** Whether the broker daemon is running. */
  brokerRunning: boolean;
  /** Whether the session file failed its integrity check. */
  tampered: boolean;
  /** Human-readable deny reason (empty when the check passes). */
  reason: string;
  /** Single-line PreToolUse deny JSON for stdout (empty when the check passes). */
  denyJson: string;
}

/** Build the single-line PreToolUse deny JSON Claude Code expects on stdout. */
function buildDenyJson(reason: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  });
}

function pass(sessionWarm: boolean, brokerRunning: boolean): HookCheckResult {
  return { passed: true, sessionWarm, brokerRunning, tampered: false, reason: '', denyJson: '' };
}

function deny(brokerRunning: boolean, tampered: boolean, reason: string): HookCheckResult {
  return {
    passed: false,
    sessionWarm: false,
    brokerRunning,
    tampered,
    reason,
    denyJson: buildDenyJson(reason),
  };
}

/**
 * Check if the session is ready for credential operations.
 * This is the hot path — must be fast.
 *
 * The check is permissive only toward users who never set secretless up:
 * - No session file at all: pass (don't block other users)
 * - Expired or tampered session: deny
 */
export function hookCheck(): HookCheckResult {
  const status = getSessionStatus();

  // A session file that fails its integrity check is never trusted —
  // it must not be confused with "never installed".
  if (status.tampered) {
    return deny(
      isDaemonRunning(),
      true,
      'Secretless session file failed integrity check (tampered). Run: secretless-ai warm',
    );
  }

  // Fast path: session is warm
  if (status.warm) {
    return pass(true, isDaemonRunning());
  }

  // If there was never a session, don't block (user may not use secretless)
  if (!status.authenticatedAt) {
    return pass(false, false);
  }

  // Session existed but expired. If the broker is down, warming alone won't
  // succeed — name `broker start` before `warm`.
  const brokerRunning = isDaemonRunning();
  const reason = brokerRunning
    ? 'Secretless session expired. Run: secretless-ai warm'
    : 'Secretless session expired. Run: secretless-ai broker start, then: secretless-ai warm';
  return deny(brokerRunning, false, reason);
}

/**
 * Run the hook check and exit with the appropriate code.
 * This is the entry point for `secretless-ai hook --check-only`.
 */
export function runHookCheck(): void {
  const result = hookCheck();

  if (result.passed) {
    process.exit(0);
  }

  // stdout carries the PreToolUse deny JSON (exactly one line);
  // stderr carries the human-readable reason.
  process.stdout.write(result.denyJson + '\n');
  process.stderr.write(result.reason + '\n');
  process.exit(2);
}
