/**
 * Git pre-commit hook — blocks commits containing secrets.
 *
 * Installs a shell script hook that runs `scan-staged` through
 * commandPrefixForHooks() to check staged files for credential patterns and
 * secret file patterns.
 */

import * as fs from 'fs';
import * as path from 'path';
import { commandPrefixForHooks, missingPrefixTarget, targetCheck } from './hook-prefix';

const HOOK_MARKER = '# secretless-ai pre-commit hook';

const SUBCOMMAND = ' scan-staged';

/**
 * The line the hook runs. A prefix that names a copy by path is preceded by
 * a test that its CLI file is there; without it, a commit after that copy was
 * removed died with a Node stack trace. The hook blocks the commit then, as
 * it does when it cannot scan, and `--no-verify` stays the way past it.
 */
function hookCommand(prefix: string): string {
  return `${targetCheck(prefix, 'pre-commit scanner', 'npx secretless-ai hook install', 1)}${prefix}${SUBCOMMAND}`;
}

export function hookScript(prefix: string = commandPrefixForHooks()): string {
  return `#!/bin/sh
${HOOK_MARKER}
# Automatically scans staged files for hardcoded secrets.
# Installed by: secretless-ai hook install
# Bypass with: git commit --no-verify (use with caution)

${hookCommand(prefix)}
`;
}

/**
 * Install the pre-commit hook in the project's .git/hooks directory.
 *
 * If an existing pre-commit hook exists and was not installed by secretless,
 * it will NOT be overwritten. Returns a status message.
 */
export function installPreCommitHook(projectDir: string): {
  installed: boolean;
  message: string;
} {
  const gitDir = path.join(projectDir, '.git');
  if (!fs.existsSync(gitDir)) {
    return { installed: false, message: 'Not a git repository (no .git directory).' };
  }

  const hooksDir = path.join(gitDir, 'hooks');
  fs.mkdirSync(hooksDir, { recursive: true });

  const hookPath = path.join(hooksDir, 'pre-commit');

  // Check for existing hook
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, 'utf-8');
    if (existing.includes(HOOK_MARKER)) {
      // Already installed — update it
      fs.writeFileSync(hookPath, hookScript(), { mode: 0o755 });
      return { installed: true, message: 'Pre-commit hook updated.' };
    }
    // Foreign hook — don't overwrite
    return {
      installed: false,
      message: `A pre-commit hook already exists (not from secretless). Append this line to it: ${hookCommand(commandPrefixForHooks())}`,
    };
  }

  fs.writeFileSync(hookPath, hookScript(), { mode: 0o755 });
  return { installed: true, message: 'Pre-commit hook installed.' };
}

/**
 * Remove the pre-commit hook if it was installed by secretless.
 */
export function uninstallPreCommitHook(projectDir: string): {
  removed: boolean;
  message: string;
} {
  const hookPath = path.join(projectDir, '.git', 'hooks', 'pre-commit');

  if (!fs.existsSync(hookPath)) {
    return { removed: false, message: 'No pre-commit hook found.' };
  }

  const content = fs.readFileSync(hookPath, 'utf-8');
  if (!content.includes(HOOK_MARKER)) {
    return {
      removed: false,
      message: 'Pre-commit hook was not installed by secretless. Not removing.',
    };
  }

  fs.unlinkSync(hookPath);
  return { removed: true, message: 'Pre-commit hook removed.' };
}

/**
 * Check if the secretless pre-commit hook is installed.
 */
export function isHookInstalled(projectDir: string): boolean {
  const hookPath = path.join(projectDir, '.git', 'hooks', 'pre-commit');
  if (!fs.existsSync(hookPath)) return false;

  const content = fs.readFileSync(hookPath, 'utf-8');
  return content.includes(HOOK_MARKER);
}

/**
 * The file the secretless pre-commit hook runs and that is missing: its CLI
 * script, or else its node binary. Null when there is no such hook, when it
 * runs the npx form, and when both files exist.
 */
export function preCommitTargetMissing(projectDir: string): string | null {
  const hookPath = path.join(projectDir, '.git', 'hooks', 'pre-commit');
  let content: string;
  try {
    content = fs.readFileSync(hookPath, 'utf-8');
  } catch {
    return null;
  }
  if (!content.includes(HOOK_MARKER)) return null;
  for (const line of content.split('\n')) {
    if (!line.endsWith(SUBCOMMAND)) continue;
    const missing = missingPrefixTarget(line.slice(0, -SUBCOMMAND.length));
    if (missing !== null) return missing;
  }
  return null;
}
