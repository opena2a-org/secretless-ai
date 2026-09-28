/**
 * Git pre-commit hook — blocks commits containing secrets.
 *
 * Installs a shell script hook that calls `secretless-ai scan-staged`
 * to check staged files for credential patterns and secret file patterns.
 */

import * as fs from 'fs';
import * as path from 'path';
import { VERSION } from './commands/utils';

const HOOK_MARKER = '# secretless-ai pre-commit hook';

/**
 * The command the hook runs, pinned to one version.
 *
 * Unpinned, `npx secretless-ai` runs whatever `secretless-ai` binary npx
 * resolves first: an ancestor directory's `node_modules/.bin` or a global
 * install wins over the cache, so a planted stub answered for the hook and the
 * commit passed. The version spec makes npx accept only that exact package,
 * and `npm_config_offline=true` keeps npx on the local cache, so the hook
 * never fetches code at commit time.
 *
 * `--no-ignore`: `.secretlessignore` is a working-tree file, so a committed
 * `*` pattern would switch the hook off. The hook scans without it.
 */
export function hookCommand(version: string = VERSION): string {
  return `npm_config_offline=true npx --yes secretless-ai@${version} scan-staged --no-ignore`;
}

/**
 * The hook body. npm exits 1 on a cache miss, the same code as a blocked
 * commit, so on any failure the hook checks whether the pinned version can
 * start at all and, if not, prints the one command that caches it.
 */
export function hookScript(version: string = VERSION): string {
  const pinned = `secretless-ai@${version}`;
  return `#!/bin/sh
${HOOK_MARKER}
# Automatically scans staged files for hardcoded secrets.
# Installed by: npx secretless-ai hook install
# Bypass with: git commit --no-verify (use with caution)
# Runs ${pinned} from the npm cache only; reinstall the hook to change version.

${hookCommand(version)}
status=$?
if [ "$status" -ne 0 ] && ! OPENA2A_TELEMETRY=off npm_config_offline=true npx --yes ${pinned} --version >/dev/null 2>&1; then
  echo "  secretless: ${pinned} is not in the npm cache, so the pre-commit scan did not run." >&2
  echo "  Cache it once, then commit again: npx --yes ${pinned} --version" >&2
fi
exit "$status"
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
      message: `A pre-commit hook already exists (not from secretless). Append this line to it: ${hookCommand()}`,
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
 * The version an installed secretless hook is pinned to, or null when the hook
 * is missing, foreign, or an older unpinned one (`npx secretless-ai scan-staged`)
 * that `hook install` should replace.
 */
export function installedHookVersion(projectDir: string): string | null {
  const hookPath = path.join(projectDir, '.git', 'hooks', 'pre-commit');
  if (!fs.existsSync(hookPath)) return null;

  const content = fs.readFileSync(hookPath, 'utf-8');
  if (!content.includes(HOOK_MARKER)) return null;
  const m = content.match(/npx --yes secretless-ai@([^\s]+) scan-staged/);
  return m ? m[1] : null;
}
