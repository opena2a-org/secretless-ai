/**
 * Hook command — idempotent session check for Claude Code PreToolUse hooks.
 *
 * Designed to run before every Bash tool call in Claude Code.
 * Must be extremely fast (<5ms) in the warm path.
 *
 * Behavior:
 *   - Session warm:   exit 0 (silent, no output)
 *   - Session expired: exit 1 with message to run `secretless-ai warm`
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

import { isSessionWarm, getSessionStatus } from './session-state';
import { isDaemonRunning } from '../broker/daemon';

export interface HookCheckResult {
  /** Whether the check passed (allow the tool call). */
  passed: boolean;
  /** Whether the session is warm. */
  sessionWarm: boolean;
  /** Whether the broker daemon is running. */
  brokerRunning: boolean;
  /** Human-readable message (only shown if check fails). */
  message: string;
}

/**
 * Check if the session is ready for credential operations.
 * This is the hot path — must be fast.
 *
 * The check is permissive by design:
 * - If secretless is not set up, pass (don't block other users)
 * - Only fail if secretless IS set up but the session has expired
 */
export function hookCheck(): HookCheckResult {
  // Fast path: session is warm
  if (isSessionWarm()) {
    return {
      passed: true,
      sessionWarm: true,
      brokerRunning: isDaemonRunning(),
      message: '',
    };
  }

  // Session is not warm — check if secretless is even set up
  const status = getSessionStatus();

  // If there was never a session, don't block (user may not use secretless)
  if (!status.authenticatedAt) {
    return {
      passed: true,
      sessionWarm: false,
      brokerRunning: false,
      message: '',
    };
  }

  // Session existed but expired
  return {
    passed: false,
    sessionWarm: false,
    brokerRunning: isDaemonRunning(),
    message: 'Secretless session expired. Run: secretless-ai warm',
  };
}

/**
 * Run the hook check and exit with the appropriate code.
 * This is the entry point for `secretless-ai hook --check-only`.
 */
export function runHookCheck(): void {
  const result = hookCheck();

  if (result.passed) {
    process.exit(0);
  } else {
    // Output to stderr so it shows as a hook failure message
    process.stderr.write(result.message + '\n');
    process.exit(1);
  }
}
