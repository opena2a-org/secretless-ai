/**
 * Wrapper installation module.
 *
 * Copies the compiled mcp-wrapper.js and its dependency tree from `dist/`
 * to a stable data directory (e.g. ~/.secretless-ai/bin). MCP configs then
 * reference this stable path instead of an ephemeral npx cache location.
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WrapperCommand {
  /** Absolute path to the node binary (process.execPath) */
  command: string;
  /** Base args — [path to mcp-wrapper.js]. Server/client/-- appended by rewrite. */
  args: string[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Locate the package root by walking up from the given directory until
 * a directory containing package.json (with name "secretless-ai") is found.
 */
function findPackageRoot(startDir: string): string | null {
  let dir = path.resolve(startDir);
  const root = path.parse(dir).root;
  const MAX_DEPTH = 20;
  let depth = 0;

  while (dir !== root && depth < MAX_DEPTH) {
    depth++;
    const pkgPath = path.join(dir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        if (pkg.name === 'secretless-ai') return dir;
      } catch {
        // Ignore parse errors — keep walking up.
      }
    }
    dir = path.dirname(dir);
  }
  return null;
}

/**
 * Resolve the dist directory that contains the compiled mcp-wrapper.js.
 *
 * Works in two modes:
 * 1. Running from compiled dist/ (__dirname is inside dist/) — parent is the package root.
 * 2. Running from source src/ (vitest) — package root is two levels up, dist/ is a sibling.
 */
function resolveDistDir(): string {
  const pkgRoot = findPackageRoot(__dirname);
  if (!pkgRoot) {
    throw new Error(
      'install-wrapper: Cannot locate secretless-ai package root. ' +
      'Ensure this module is running from within the secretless-ai package.',
    );
  }

  const distDir = path.join(pkgRoot, 'dist');
  const wrapperPath = path.join(distDir, 'mcp-wrapper.js');
  if (!fs.existsSync(wrapperPath)) {
    throw new Error(
      `install-wrapper: Compiled wrapper not found at ${wrapperPath}. ` +
      'Run "npm run build" first.',
    );
  }

  return distDir;
}

/**
 * Recursively copy a directory tree.
 * Overwrites existing files at the destination.
 */
function copyRecursive(src: string, dest: string): void {
  fs.mkdirSync(dest, { recursive: true, mode: 0o700 });
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
      fs.chmodSync(destPath, 0o600);
    }
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Install the compiled wrapper and its dependency tree to a stable location.
 *
 * Copies the entire `dist/` directory to `{dataDir}/bin/` so that all
 * relative imports from mcp-wrapper.js (e.g. `./mcp/vault`) resolve correctly.
 *
 * @param dataDir - Stable data directory (e.g. ~/.secretless-ai)
 * @returns WrapperCommand with `command` (node path) and `args` (wrapper script path)
 */
export function installWrapper(dataDir: string): WrapperCommand {
  const distDir = resolveDistDir();
  const binDir = path.join(dataDir, 'bin');

  // Copy entire dist/ tree to binDir/ so that internal require() paths resolve
  copyRecursive(distDir, binDir);

  const targetPath = path.join(binDir, 'mcp-wrapper.js');
  return {
    command: process.execPath,
    args: [targetPath],
  };
}

/**
 * Get the wrapper command for an already-installed wrapper.
 *
 * Does NOT install or copy files — assumes installWrapper() was already called.
 *
 * @param dataDir - Stable data directory (same one passed to installWrapper)
 * @returns WrapperCommand with `command` (node path) and `args` (wrapper script path)
 */
export function getWrapperCommand(dataDir: string): WrapperCommand {
  const targetPath = path.join(dataDir, 'bin', 'mcp-wrapper.js');
  return {
    command: process.execPath,
    args: [targetPath],
  };
}
