/**
 * `secretless-ai diff <ref>` — show how secretless-managed files have
 * changed vs a git ref.
 *
 * Concrete change-set audit. After running `init`, a user wants to see
 * exactly what was added/modified — without inspecting each file by hand
 * or running `git diff` against a noisy diff that includes unrelated work.
 * This subcommand restricts `git diff` to the small set of paths
 * secretless owns: `.claude/settings.json`, `.secretlessignore`, and
 * `.secretless-rules.yaml` (custom rules — see src/custom-rules.ts).
 *
 * Output: a unified-diff-like report, headered by file with an INTRODUCED /
 * REMOVED / MODIFIED / UNCHANGED tag.
 *
 * Security notes (Wave 2 Phase 4.5):
 * - Refs are validated against `[A-Za-z0-9._/^@~+-]` only — no shell
 *   metacharacters slip through into `git diff`.
 * - We use `execFileSync` with an array argv (NOT a shell string), so even
 *   if a ref slipped past validation it would be treated as a positional
 *   argument by git.
 * - `git diff` failures (missing ref, not a repo) return non-zero and are
 *   surfaced to the user without leaking the underlying git stderr verbatim.
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Git repo-discovery environment variables. When `secretless diff` runs inside a
 * git hook (e.g. a pre-push hook), git sets GIT_DIR / GIT_WORK_TREE / etc. in the
 * environment, and they take precedence over cwd-based discovery — so a `git`
 * invocation scoped with `cwd` would silently operate on the HOOK's repo instead of
 * the directory the caller asked about. We strip them so `cwd` is authoritative and
 * `computeDiff(ref, cwd)` honors its documented contract regardless of ambient git env.
 */
const GIT_DISCOVERY_ENV_VARS = [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_COMMON_DIR',
  'GIT_INDEX_FILE',
  'GIT_PREFIX',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_NAMESPACE',
] as const;

/** A copy of process.env with git's repo-discovery vars removed (see above). */
export function gitDiscoveryFreeEnv(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env = { ...base };
  for (const k of GIT_DISCOVERY_ENV_VARS) delete env[k];
  return env;
}

/** Files secretless considers "managed" — only these are diffed. */
const MANAGED_PATHS: readonly string[] = Object.freeze([
  '.claude/settings.json',
  '.secretlessignore',
  '.secretless-rules.yaml',
]);

/**
 * Validate a git ref. Allows: alphanumerics, `.`, `_`, `/`, `^`, `@`, `~`,
 * `+`, `-`. Rejects everything else — including shell metacharacters and
 * whitespace. This is conservative; it rejects some legitimate refs (e.g.
 * `${tag}`) but the user can quote the ref in their shell, not inside us.
 *
 * Empty refs are rejected.
 */
export function isSafeGitRef(ref: string): boolean {
  if (!ref) return false;
  if (ref.length > 256) return false;
  // Refs cannot start with `-` (would be parsed as a flag by git).
  if (ref.startsWith('-')) return false;
  // Refs cannot contain `..` (parent traversal in a path-shaped ref) per git.
  // git itself also rejects this, but we duplicate the check defensively.
  if (ref.includes('..')) return false;
  return /^[A-Za-z0-9._/^@~+-]+$/.test(ref);
}

export interface DiffFileChange {
  /** Repo-relative POSIX path. */
  file: string;
  /** Status: A introduced, D removed, M modified, U unchanged. */
  status: 'A' | 'D' | 'M' | 'U';
  /** Unified diff body (empty when status === 'U'). */
  unified: string;
}

export interface DiffResult {
  /** 0 ok, 1 invalid args, 2 git error. */
  exitCode: number;
  /** The ref the diff was taken against. */
  ref?: string;
  /** Per-file change summary. */
  changes: DiffFileChange[];
  /** Single-line message for stderr/stdout. */
  message: string;
}

/**
 * Run `git rev-parse --show-toplevel` to anchor diff calls. Returns null
 * if not in a git repo (and the caller surfaces that as a user error).
 */
function gitToplevel(cwd: string): string | null {
  try {
    const out = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      env: gitDiscoveryFreeEnv(),
    });
    return out.trim();
  } catch {
    return null;
  }
}

/**
 * Run `git diff <ref> -- <path>` for a single managed file. Returns the
 * unified-diff body, or empty string if there are no differences. On git
 * error (e.g. unknown ref), throws — caller catches and reports.
 */
function diffOne(rootDir: string, ref: string, file: string): string {
  return execFileSync('git', ['diff', '--no-color', ref, '--', file], {
    cwd: rootDir,
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    maxBuffer: 5 * 1024 * 1024,
    env: gitDiscoveryFreeEnv(),
  });
}

/**
 * Resolve a managed-path's status at `ref` and HEAD by combining `git ls-tree`
 * with current-FS existence. Used to produce the A/D/M/U status tag.
 */
function resolveStatus(rootDir: string, ref: string, file: string): 'A' | 'D' | 'M' | 'U' | 'gone' {
  // Existed at ref?
  let inRef = false;
  try {
    execFileSync('git', ['cat-file', '-e', `${ref}:${file}`], {
      cwd: rootDir,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: gitDiscoveryFreeEnv(),
    });
    inRef = true;
  } catch {
    inRef = false;
  }
  // Exists now (working tree)?
  const onDisk = fs.existsSync(path.join(rootDir, file));

  if (!inRef && !onDisk) return 'gone';
  if (!inRef && onDisk) return 'A';
  if (inRef && !onDisk) return 'D';
  // Both: compare the diff. Empty diff → unchanged, else modified.
  try {
    const d = diffOne(rootDir, ref, file);
    return d.trim() === '' ? 'U' : 'M';
  } catch {
    return 'U';
  }
}

/**
 * Compute the secretless-managed diff vs `ref` from `cwd`.
 * Pure-ish: side effects are the `git` invocations (read-only).
 */
export function computeDiff(ref: string, cwd: string = process.cwd()): DiffResult {
  if (!isSafeGitRef(ref)) {
    return {
      exitCode: 1,
      changes: [],
      message: `Invalid git ref: "${ref}". Only [A-Za-z0-9._/^@~+-] are allowed.`,
    };
  }

  const rootDir = gitToplevel(cwd);
  if (!rootDir) {
    return {
      exitCode: 2,
      changes: [],
      message: 'Not a git repository (or any parent up to mount point).',
    };
  }

  // Probe the ref. `git rev-parse <ref>` is a cheap existence check that
  // surfaces a useful error without trying every managed file.
  try {
    execFileSync('git', ['rev-parse', '--verify', ref], {
      cwd: rootDir,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: gitDiscoveryFreeEnv(),
    });
  } catch {
    return {
      exitCode: 2,
      ref,
      changes: [],
      message: `Unknown git ref: ${ref}. Try \`git fetch\` or check the spelling.`,
    };
  }

  const changes: DiffFileChange[] = [];
  for (const file of MANAGED_PATHS) {
    const status = resolveStatus(rootDir, ref, file);
    if (status === 'gone') continue;
    let unified = '';
    if (status !== 'U') {
      try {
        unified = diffOne(rootDir, ref, file);
      } catch {
        unified = '';
      }
      // `git diff <ref> -- <path>` skips untracked files (they're not in the
      // index). For an INTRODUCED file we synthesise a unified diff from
      // the file contents directly so the user still sees what was added.
      if (status === 'A' && unified.trim() === '') {
        try {
          const fullPath = path.join(rootDir, file);
          const content = fs.readFileSync(fullPath, 'utf-8');
          const headerLines = [
            `--- /dev/null`,
            `+++ b/${file}`,
            `@@ untracked, ${content.split('\n').length} line(s) @@`,
          ];
          const body = content.split('\n').map(l => `+${l}`).join('\n');
          unified = headerLines.join('\n') + '\n' + body;
        } catch {
          // Binary or unreadable — leave unified empty; the renderer prints
          // "(binary or empty diff)".
        }
      }
    }
    changes.push({ file, status, unified });
  }

  if (changes.length === 0) {
    return {
      exitCode: 0,
      ref,
      changes,
      message: `No secretless-managed files differ from ${ref}.`,
    };
  }

  return {
    exitCode: 0,
    ref,
    changes,
    message: `Diff vs ${ref}: ${changes.filter(c => c.status !== 'U').length} file(s) changed.`,
  };
}

const STATUS_LABEL: Record<DiffFileChange['status'], string> = {
  A: 'INTRODUCED',
  D: 'REMOVED',
  M: 'MODIFIED',
  U: 'UNCHANGED',
};

/**
 * CLI entry point. Args: [ref?]. Default ref is `HEAD`.
 */
export function runDiff(args: string[]): number {
  const ref = args[0] ?? 'HEAD';
  const result = computeDiff(ref);

  if (result.exitCode !== 0) {
    console.error(`  ${result.message}`);
    return result.exitCode;
  }

  console.log(`\n  Secretless Diff vs ${result.ref}\n`);

  if (result.changes.length === 0) {
    console.log(`  ${result.message}\n`);
    return 0;
  }

  for (const change of result.changes) {
    console.log(`  ── ${STATUS_LABEL[change.status]}  ${change.file}`);
    if (change.status === 'U') {
      console.log('       (no changes)');
      continue;
    }
    if (!change.unified.trim()) {
      console.log('       (binary or empty diff)');
      continue;
    }
    // Indent each diff line by 4 spaces for readability.
    for (const line of change.unified.split('\n')) {
      console.log(`     ${line}`);
    }
  }
  console.log();
  console.log(`  ${result.message}\n`);
  return 0;
}
