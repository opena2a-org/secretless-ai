/**
 * Shell environment export — outputs stored secrets as shell export statements.
 *
 * Usage:
 *   eval "$(secretless-ai env)"          # Export all secrets to current shell
 *   eval "$(secretless-ai env --only NPM_TOKEN,GITHUB_TOKEN)"  # Specific secrets
 *
 * Designed to be added to shell profiles (~/.zshenv, ~/.bashrc) so secrets
 * stored in the vault are automatically available as env vars without manual
 * export lines.
 *
 * Security:
 *   - Output goes only to a TTY or to a shell `eval` consumer; AI tools never capture it.
 *   - Values are single-quoted to prevent shell expansion
 *   - The eval pattern means secrets never touch disk as plaintext
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SecretStore } from './secret-store';
import type { SecretStoreOptions } from './secret-store';

export interface EnvOptions extends SecretStoreOptions {
  /** Only export these specific secret names. */
  only?: string[];
}

/**
 * A POSIX shell variable name: a letter or underscore followed by letters,
 * digits, or underscores. Stored secret names are more permissive than this
 * (they also allow `-`), so a name like `vault-name` is a valid secret but an
 * invalid shell identifier. Exporting it as `export vault-name=...` makes the
 * shell reject the whole `eval`, which breaks every command in profiles that
 * run `eval "$(secretless-ai env)"`. We skip such names instead.
 */
const SHELL_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function isValidShellIdentifier(name: string): boolean {
  return SHELL_IDENTIFIER.test(name);
}

/**
 * Environment variables that a known AI coding agent sets in every subprocess
 * it spawns. Presence means `secretless-ai` is running as a child of that agent
 * — so its stdout is captured into the agent's context.
 *
 * This is the load-bearing check for `env`, which dumps every stored secret as
 * plaintext. It is deliberately independent of the command string: an agent can
 * spell the invocation any number of ways (`npx secretless-ai@latest env`,
 * `secretless-ai 'env'`, `$SL env`, a tab separator), all of which defeat a
 * deny-glob or a grep in the guard hook, but every one of them inherits these
 * markers from the agent process. Enumeration-limited by nature — it can only
 * name agents we know set a marker — so it backs, and is backed by, the Claude
 * Code deny rules and guard hook rather than replacing them.
 */
const AGENT_RUNTIME_ENV_VARS: readonly string[] = [
  'CLAUDECODE', // Claude Code
  'CLAUDE_CODE_ENTRYPOINT', // Claude Code
  'CURSOR_TRACE_ID', // Cursor
  'AIDER_MODEL', // Aider
];

/**
 * Returns the name of a detected AI-agent runtime env var, or null. Used to
 * refuse bulk secret exposure (`env`) inside an agent while leaving the same
 * command working in the user's own shell (where no marker is set).
 */
export function detectAgentRuntime(env: NodeJS.ProcessEnv = process.env): string | null {
  for (const name of AGENT_RUNTIME_ENV_VARS) {
    const v = env[name];
    if (v !== undefined && v !== '') return name;
  }
  return null;
}

/**
 * Generate shell export statements for stored secrets.
 * Returns the export script as a string.
 *
 * Secret names that are not valid shell identifiers (e.g. they contain a `-`)
 * are skipped — one such name would otherwise make the entire `eval` fail and
 * break every shell command. The skipped names are reported as a leading shell
 * comment, which is a no-op inside `eval` but visible on direct invocation, so
 * the secret stays loadable via `secretless-ai run` / `--only` and the user is
 * told how to fix it without any secret value being exposed.
 */
export async function generateEnvExports(options?: EnvOptions): Promise<string> {
  const store = new SecretStore(options);
  const secrets = await store.loadSecrets(options?.only);

  const lines: string[] = [];
  const skipped: string[] = [];
  for (const [name, value] of Object.entries(secrets)) {
    if (!isValidShellIdentifier(name)) {
      skipped.push(name);
      continue;
    }
    // Single-quote the value and escape any embedded single quotes
    // using the standard shell pattern: replace ' with '\''
    const escaped = value.replace(/'/g, "'\\''");
    lines.push(`export ${name}='${escaped}'`);
  }

  if (skipped.length > 0) {
    // A shell comment: harmless inside `eval`, visible on direct invocation.
    lines.unshift(
      `# secretless: skipped ${skipped.length} secret${skipped.length === 1 ? '' : 's'} ` +
        `with a name that is not a valid shell variable: ${skipped.join(', ')}. ` +
        `Rename to export (e.g. secretless-ai secret set NEW_NAME), or use secretless-ai run -- <cmd>.`,
    );
  }

  return lines.join('\n');
}

/** The hook line written before #333. It finds the CLI on PATH. */
const BARE_HOOK_LINE = 'eval "$(secretless-ai env 2>/dev/null)"';

/** A hook line written by getShellHookLine: two single-quoted paths, then `env`. */
const PATH_HOOK_LINE = /^eval "\$\('((?:[^']|'\\'')*)' '((?:[^']|'\\'')*)' env 2>\/dev\/null\)"$/;

export function shellQuote(word: string): string {
  return `'${word.replace(/'/g, `'\\''`)}'`;
}

function realpathOrNull(p: string): string | null {
  try {
    return fs.realpathSync(p);
  } catch {
    return null;
  }
}

/** The first executable file `name` in the directories of `pathEnv`, or null. */
export function findOnPath(name: string, pathEnv: string = process.env.PATH ?? ''): string | null {
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!path.isAbsolute(dir)) continue;
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // Not in this directory.
    }
  }
  return null;
}

/**
 * The command the shell hook runs: a node binary and this package's CLI
 * script, as absolute paths. A profile cannot count on PATH to find
 * `secretless-ai`: a copy run through npx is never on PATH, and a new macOS
 * terminal reads ~/.zshenv before Homebrew or nvm add their directories to
 * PATH (#333). `process.execPath` is the resolved binary, which under
 * Homebrew is a versioned path that an upgrade removes, so a `node` on PATH
 * that resolves to the same binary is written instead.
 */
export function shellHookCommand(
  execPath: string = process.execPath,
  pathEnv: string = process.env.PATH ?? '',
  script: string = path.join(__dirname, 'cli.js'),
): string[] {
  const node = findOnPath('node', pathEnv);
  const real = realpathOrNull(execPath);
  const sameBinary = node !== null && real !== null && realpathOrNull(node) === real;
  return [sameBinary ? node : execPath, script];
}

/**
 * Generate the shell profile hook line for auto-loading secrets.
 * Returns the eval line to add to ~/.zshenv or ~/.bashrc.
 */
export function getShellHookLine(command: readonly string[] = shellHookCommand()): string {
  return `eval "$(${command.map(shellQuote).join(' ')} env 2>/dev/null)"`;
}

/**
 * Whether a hook line this tool wrote still reaches a CLI: the bare line
 * needs `secretless-ai` on PATH, a line with paths needs both files. A line
 * in any other form is the user's own and counts as working.
 */
export function hookLineRuns(line: string, pathEnv: string = process.env.PATH ?? ''): boolean {
  if (line === BARE_HOOK_LINE) return findOnPath('secretless-ai', pathEnv) !== null;
  const m = PATH_HOOK_LINE.exec(line);
  if (m === null) return true;
  return [m[1], m[2]].every((p) => fs.existsSync(p.replace(/'\\''/g, "'")));
}

/**
 * Marker comment used to identify secretless-managed lines in shell profiles.
 */
export const SHELL_HOOK_MARKER = '# secretless-ai: auto-load secrets from vault';

export interface InstallShellHookOptions {
  home?: string;
  shell?: string;
  platform?: NodeJS.Platform;
  /** The command the hook runs; defaults to shellHookCommand(). */
  command?: string[];
  pathEnv?: string;
}

export interface ShellHookChange {
  profilePath: string;
  /** `repaired`: the hook line this tool wrote earlier no longer reached a CLI and was replaced. */
  action: 'installed' | 'repaired';
  command: string[];
  /** Whether `secretless-ai` is on PATH, so the hook does not depend on `command` alone. */
  cliOnPath: boolean;
}

/**
 * Add the hook to ~/.zshenv (macOS or zsh) or ~/.bashrc, or replace the hook
 * line this tool wrote earlier when it no longer reaches a CLI. Returns null
 * when the profile already has a working hook.
 */
export function installShellHook(options: InstallShellHookOptions = {}): ShellHookChange | null {
  const home = options.home ?? os.homedir();
  const shell = options.shell ?? process.env.SHELL ?? '';
  const platform = options.platform ?? os.platform();
  const pathEnv = options.pathEnv ?? process.env.PATH ?? '';
  const command = options.command ?? shellHookCommand(process.execPath, pathEnv);

  const profilePath = path.join(home, platform === 'darwin' || shell.endsWith('/zsh') ? '.zshenv' : '.bashrc');
  let existing = '';
  try {
    existing = fs.readFileSync(profilePath, 'utf-8');
  } catch {
    // File doesn't exist — will create it
  }

  const hookLine = getShellHookLine(command);
  const cliOnPath = findOnPath('secretless-ai', pathEnv) !== null;
  const lines = existing.split('\n');
  const at = lines.indexOf(SHELL_HOOK_MARKER);
  if (at !== -1) {
    const current = lines[at + 1] ?? '';
    if (current === hookLine || hookLineRuns(current, pathEnv)) return null;
    lines[at + 1] = hookLine;
    fs.writeFileSync(profilePath, lines.join('\n'));
    return { profilePath, action: 'repaired', command, cliOnPath };
  }
  // A marker this split did not find on a line of its own, or the user's own line.
  if (existing.includes(SHELL_HOOK_MARKER) || existing.includes('secretless-ai env')) return null;

  fs.writeFileSync(profilePath, `${existing}\n${SHELL_HOOK_MARKER}\n${hookLine}\n`);
  return { profilePath, action: 'installed', command, cliOnPath };
}
