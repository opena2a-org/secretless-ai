/**
 * MCP config file auto-discovery across 5 clients.
 *
 * Finds MCP server configurations in Claude Desktop, Cursor,
 * Claude Code, VS Code, and Windsurf config files, in the home
 * directory and in the project directory.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { listedName } from '../secret-value';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * The client a config is read as. 'unknown' is a project-level mcp.json:
 * which client writes a bare mcp.json is not established, so it is named by
 * its path alone, as `scan` names it.
 */
export type McpClient = 'claude-desktop' | 'cursor' | 'claude-code' | 'vscode' | 'windsurf' | 'unknown';

/** 'home': a per-user client config. 'project': a config in the project directory. */
export type McpConfigScope = 'home' | 'project';

export interface McpServerEntry {
  name: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  /** true if command is the secretless-mcp binary or the mcp-wrapper.js script */
  alreadyProtected: boolean;
}

/** A server entry in a parsed config with a part that could not be read, so that part was not checked for secrets. */
export interface UncheckedMcpServer {
  /** Server name as written in the config */
  name: string;
  /** The part that was not read: "entry", "env", or env values by name. Never quotes a value. */
  part: string;
  /** Why it was not read, e.g. "not a JSON object" */
  reason: string;
}

export interface McpConfigFile {
  client: McpClient;
  filePath: string;
  /** The path from the project directory, for a config found there. Absent for a config in the home directory. */
  projectPath?: string;
  /**
   * For a server map kept for one project under `projects` in ~/.claude.json:
   * the key it is under, the project's path. Absent for the server map at the
   * top level of a file, the one rewriteConfig rewrites.
   */
  projectKey?: string;
  servers: McpServerEntry[];
  /** Server entries with a part that could not be read. A caller never reports one of these as clean. */
  unchecked: UncheckedMcpServer[];
  /** Raw parsed JSON for later rewriting */
  raw: Record<string, unknown>;
}

/** A config file that exists but could not be read or parsed, so its servers are unknown. */
export interface UnparsedMcpConfig {
  client: McpClient;
  filePath: string;
  /** The path from the project directory, for a config found there. Absent for a config in the home directory. */
  projectPath?: string;
  /** For the entry of one project under `projects` in ~/.claude.json: the key it is under (see McpConfigFile). */
  projectKey?: string;
  /** What stopped the parse, e.g. "not valid JSON (line 4, column 1)". Never quotes the file's content. */
  reason: string;
}

export interface McpConfigDiscovery {
  configs: McpConfigFile[];
  unparsed: UnparsedMcpConfig[];
}

// ---------------------------------------------------------------------------
// Client config path definitions
// ---------------------------------------------------------------------------

/** A place a client config is looked for. */
export interface McpConfigLocation {
  client: McpClient;
  scope: McpConfigScope;
  /** From the home directory for scope 'home', from the project directory for scope 'project'. */
  relativePath: string;
  /**
   * The file also keeps a server map for each project, under `projects` and
   * keyed by the project's path, as ~/.claude.json does. Each one that holds a
   * server is read as a config of its own, with that key as its projectKey.
   */
  projectMaps?: boolean;
}

/** The Claude Code project-scope config: the one project-level config protect-mcp rewrites. */
const CLAUDE_CODE_PROJECT_CONFIG = '.mcp.json';

/**
 * Every place a client config is looked for, home first, in the order they
 * are read. `mcp-status` and `protect-mcp` print this list when they find no
 * config, so a path added here is a path they name.
 */
const MCP_CONFIG_LOCATIONS: readonly McpConfigLocation[] = [
  // Claude Desktop: search both macOS and Linux paths on all platforms.
  // The check is just existsSync (harmless miss), and searching both enables
  // cross-platform testing via homeOverride.
  {
    client: 'claude-desktop',
    scope: 'home',
    relativePath: path.join('Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
  },
  { client: 'claude-desktop', scope: 'home', relativePath: path.join('.config', 'Claude', 'claude_desktop_config.json') },
  { client: 'cursor', scope: 'home', relativePath: path.join('.cursor', 'mcp.json') },
  // Claude Code keeps its user-scope MCP servers at the top level of
  // ~/.claude.json and its local-scope servers under `projects`, keyed by the
  // project's path. Its two settings files are read as well.
  { client: 'claude-code', scope: 'home', relativePath: '.claude.json', projectMaps: true },
  { client: 'claude-code', scope: 'home', relativePath: path.join('.claude', 'settings.json') },
  { client: 'claude-code', scope: 'home', relativePath: path.join('.claude', 'settings.local.json') },
  { client: 'vscode', scope: 'home', relativePath: path.join('.vscode', 'mcp.json') },
  { client: 'windsurf', scope: 'home', relativePath: path.join('.windsurf', 'mcp.json') },
  // Project level: the MCP configs `scan` reads in a project. These files are
  // usually committed, so plaintext env values in them leak beyond one machine.
  { client: 'claude-code', scope: 'project', relativePath: CLAUDE_CODE_PROJECT_CONFIG },
  { client: 'cursor', scope: 'project', relativePath: path.join('.cursor', 'mcp.json') },
  { client: 'vscode', scope: 'project', relativePath: path.join('.vscode', 'mcp.json') },
  { client: 'windsurf', scope: 'project', relativePath: path.join('.windsurf', 'mcp.json') },
  { client: 'unknown', scope: 'project', relativePath: 'mcp.json' },
];

/** Every place a client config is looked for, home first, in the order they are read. */
export function mcpConfigLocations(): readonly McpConfigLocation[] {
  return MCP_CONFIG_LOCATIONS;
}

/**
 * Whether protect-mcp rewrites a config: every home config, and the project's
 * .mcp.json. protect-mcp writes this machine's wrapper path into a config it
 * rewrites, and a project-level config is usually committed, so it leaves the
 * other project-level configs as they are and names them.
 */
export function rewrittenByProtectMcp(config: { projectPath?: string }): boolean {
  return config.projectPath === undefined || config.projectPath === CLAUDE_CODE_PROJECT_CONFIG;
}

/**
 * The top-level keys a server map is read from, in this order: `mcpServers`,
 * `mcp-servers`, and `servers`, the key the VS Code workspace file
 * `.vscode/mcp.json` carries.
 */
const SERVER_MAP_KEYS = ['mcpServers', 'mcp-servers', 'servers'] as const;

/**
 * The key of the server map in a parsed config: the first of SERVER_MAP_KEYS
 * whose value is not null. protect-mcp rewrites the map under this key, the
 * one its secrets were read from.
 */
export function serverMapKey(raw: Record<string, unknown>): string | undefined {
  return SERVER_MAP_KEYS.find((key) => raw[key] !== undefined && raw[key] !== null);
}

// ---------------------------------------------------------------------------
// Server entry parsing
// ---------------------------------------------------------------------------

/**
 * Check if a server command indicates it is already wrapped by secretless-mcp.
 */
function isProtectedCommand(command: string): boolean {
  if (command === 'secretless-mcp') return true;
  if (command.endsWith('/secretless-mcp')) return true;

  // The protect-mcp command rewrites configs to use the full path to mcp-wrapper.js
  // (e.g., /Users/.../dist/mcp-wrapper.js). Detect that as protected too.
  const wrapperPath = path.resolve(__dirname, '..', 'dist', 'mcp-wrapper.js');
  if (command === wrapperPath) return true;
  if (command.endsWith('/mcp-wrapper.js') && command.includes('secretless')) return true;

  return false;
}

/**
 * True for a value that holds content where a JSON object belongs. null and
 * undefined hold nothing, so there is nothing in them left unchecked.
 */
function isNotJsonObject(value: unknown): boolean {
  return value !== null && value !== undefined && (typeof value !== 'object' || Array.isArray(value));
}

/**
 * Extract MCP server entries from a parsed JSON config.
 * Reads the server map under the key serverMapKey names.
 *
 * A part that does not have the shape of a server entry is passed over and
 * returned in `unchecked`: a secret in it was not seen.
 */
function parseServers(raw: Record<string, unknown>): { servers: McpServerEntry[]; unchecked: UncheckedMcpServer[] } | null {
  const key = serverMapKey(raw);
  const serversObj = (key === undefined ? undefined : raw[key]) as Record<string, unknown> | undefined;

  if (!serversObj || typeof serversObj !== 'object') {
    return null;
  }

  const entries: McpServerEntry[] = [];
  const unchecked: UncheckedMcpServer[] = [];

  for (const [name, value] of Object.entries(serversObj)) {
    if (isNotJsonObject(value)) {
      unchecked.push({ name, part: 'entry', reason: 'not a JSON object' });
    }
    if (!value || typeof value !== 'object') continue;

    const serverDef = value as Record<string, unknown>;
    const command = typeof serverDef['command'] === 'string' ? serverDef['command'] : '';
    const args = Array.isArray(serverDef['args'])
      ? (serverDef['args'] as unknown[]).filter((a): a is string => typeof a === 'string')
      : [];
    const env: Record<string, string> = {};

    const envValue = serverDef['env'];
    if (isNotJsonObject(envValue)) {
      unchecked.push({ name, part: 'env', reason: 'not a JSON object' });
    }
    if (envValue && typeof envValue === 'object') {
      const notStrings: string[] = [];
      for (const [k, v] of Object.entries(envValue as Record<string, unknown>)) {
        if (typeof v === 'string') {
          env[k] = v;
        } else if (v !== null) {
          notStrings.push(listedName(k));
        }
      }
      // An env written as an array is already reported whole.
      if (notStrings.length > 0 && !Array.isArray(envValue)) {
        unchecked.push(
          notStrings.length === 1
            ? { name, part: `env value ${notStrings[0]}`, reason: 'not a string' }
            : { name, part: `env values ${notStrings.join(', ')}`, reason: 'not strings' },
        );
      }
    }

    entries.push({
      name,
      command,
      args,
      env,
      alreadyProtected: isProtectedCommand(command),
    });
  }

  return { servers: entries, unchecked };
}

/**
 * Describe a JSON.parse failure by its position only. The engine's message
 * can quote the text around the error, and these files hold plaintext secrets.
 */
function describeJsonError(err: unknown, content: string): string {
  const match = /at position (\d+)/.exec(err instanceof Error ? err.message : '');
  if (!match) return 'not valid JSON';
  const linesBefore = content.slice(0, Number(match[1])).split('\n');
  const column = linesBefore[linesBefore.length - 1].length + 1;
  return `not valid JSON (line ${linesBefore.length}, column ${column})`;
}

// ---------------------------------------------------------------------------
// Main discovery function
// ---------------------------------------------------------------------------

/**
 * Discover all MCP configuration files on the developer's machine.
 *
 * Searches every location in mcpConfigLocations(): the home directory configs
 * of 5 clients (Claude Desktop, Cursor, Claude Code, VS Code, Windsurf), and
 * the project-level configs (.mcp.json, .cursor/mcp.json, .vscode/mcp.json,
 * .windsurf/mcp.json and mcp.json in the project directory). In
 * ~/.claude.json it reads the server map at the top level and the one kept
 * for each project under `projects`, each as a config of its own.
 *
 * @param homeOverride - Override home directory (for testing). Defaults to os.homedir().
 * @param projectDirOverride - Override project directory (for testing). Defaults to process.cwd().
 * @returns Array of discovered config files with parsed server entries.
 */
export function discoverMcpConfigs(homeOverride?: string, projectDirOverride?: string): McpConfigFile[] {
  return discoverMcpConfigsDetailed(homeOverride, projectDirOverride).configs;
}

/**
 * Same search as discoverMcpConfigs, but also returns the config files that
 * exist and could not be read or parsed. A caller that reports on MCP configs
 * must name these: their servers, and any secrets in them, were not checked.
 * An empty or whitespace-only file holds no servers and is not reported.
 */
export function discoverMcpConfigsDetailed(homeOverride?: string, projectDirOverride?: string): McpConfigDiscovery {
  const home = homeOverride ?? os.homedir();
  const projectDir = projectDirOverride ?? process.cwd();
  const results: McpConfigFile[] = [];
  const unparsed: UnparsedMcpConfig[] = [];
  // A project directory that is the home directory reaches some files twice.
  // Each is read once, as the home config it is listed first as.
  const filesRead = new Set<string>();

  for (const { client, scope, relativePath, projectMaps } of MCP_CONFIG_LOCATIONS) {
    const fullPath = path.join(scope === 'home' ? home : projectDir, relativePath);
    if (!fs.existsSync(fullPath)) continue;
    const file = realPathOf(fullPath);
    if (filesRead.has(file)) continue;
    filesRead.add(file);
    const where = { client, filePath: fullPath, ...(scope === 'project' ? { projectPath: relativePath } : {}) };

    let content: string;
    try {
      content = fs.readFileSync(fullPath, 'utf-8');
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      unparsed.push({ ...where, reason: code ? `could not be read (${code})` : 'could not be read' });
      continue;
    }
    if (content.trim() === '') continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch (err) {
      unparsed.push({ ...where, reason: describeJsonError(err, content) });
      continue;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      unparsed.push({ ...where, reason: 'not a JSON object' });
      continue;
    }
    const raw = parsed as Record<string, unknown>;

    const top = readServerMap(raw);
    if (top !== undefined && 'reason' in top) {
      unparsed.push({ ...where, reason: top.reason });
    } else if (top !== undefined) {
      results.push({ ...where, servers: top.servers, unchecked: top.unchecked, raw });
    }
    if (projectMaps) readProjectMaps(raw, where, results, unparsed);
  }

  return { configs: results, unparsed };
}

/**
 * The server map of one part of a config: the top level of a file, or the
 * entry of one project in ~/.claude.json. Undefined when that part holds no
 * server map, and a reason when its server map is not a JSON object.
 */
function readServerMap(
  container: Record<string, unknown>,
): { servers: McpServerEntry[]; unchecked: UncheckedMcpServer[] } | { reason: string } | undefined {
  const key = serverMapKey(container);
  const serversValue = key === undefined ? undefined : container[key];
  if (serversValue !== undefined && typeof serversValue !== 'object') {
    return { reason: 'its MCP server list is not a JSON object' };
  }
  return parseServers(container) ?? undefined;
}

/**
 * Read the server map in the entry of each project under `projects`, as a
 * config of its own with the project's key as its projectKey. A project whose
 * server map holds no entry is passed over, so a file listing many projects
 * with empty maps does not list each one. A `projects` value or a project
 * entry that is not a JSON object is returned as unparsed: a server in it was
 * not read.
 */
function readProjectMaps(
  raw: Record<string, unknown>,
  where: { client: McpClient; filePath: string; projectPath?: string },
  results: McpConfigFile[],
  unparsed: UnparsedMcpConfig[],
): void {
  const projects = raw['projects'];
  if (isNotJsonObject(projects)) {
    unparsed.push({ ...where, reason: 'its projects value is not a JSON object' });
    return;
  }
  if (!projects) return;

  for (const [projectKey, entry] of Object.entries(projects as Record<string, unknown>)) {
    const at = { ...where, projectKey };
    if (isNotJsonObject(entry)) {
      unparsed.push({ ...at, reason: 'not a JSON object' });
      continue;
    }
    if (!entry) continue;
    const map = readServerMap(entry as Record<string, unknown>);
    if (map === undefined) continue;
    if ('reason' in map) {
      unparsed.push({ ...at, reason: map.reason });
    } else if (map.servers.length > 0 || map.unchecked.length > 0) {
      results.push({ ...at, servers: map.servers, unchecked: map.unchecked, raw });
    }
  }
}

/** The file a path reaches, so a file reached by two paths is read once. */
function realPathOf(fullPath: string): string {
  try {
    return fs.realpathSync(fullPath);
  } catch {
    return path.resolve(fullPath);
  }
}

// ---------------------------------------------------------------------------
// Where a bound entry starts
// ---------------------------------------------------------------------------

/**
 * The most bytes of a project-level config read while looking in it for a
 * copy of a binding. A larger file is not read, and the entry does not start:
 * whether the file holds a copy could not be told.
 */
export const BINDING_COPY_READ_LIMIT = 1024 * 1024;

/**
 * Whether a bound entry starts in a directory, after checkLaunch has passed
 * it, and when not, why. Paths only: never the id.
 */
export type McpPlaceVerdict =
  | { refused: false }
  /** A project binding, started outside its project's directory. */
  | { refused: 'outside-project'; project: string; startDir: string }
  /** A project binding whose project directory or config file could not be resolved. */
  | { refused: 'project-unresolved'; project: string; path: string; code: string }
  /** The directory the entry was started in could not be resolved. */
  | { refused: 'start-unresolved'; code: string }
  /** A project-level config visible from the start directory, other than the bound one, holds the id. */
  | { refused: 'copy-found'; file: string }
  /** A project-level config visible from the start directory could not be read for the id. */
  | { refused: 'copy-unchecked'; file: string; why: string };

/**
 * The checks the wrapper runs after checkLaunch and before it reads a secret,
 * in this order. A project binding is honoured only where the start directory
 * is its project's directory or below it, both resolved. Then no project-level
 * config visible from the start directory, in it or in any directory above
 * it, holds the binding's id, other than the bound config and the home
 * configs: a client reads an entry from each of those places. The start
 * directory is the process's own, never one an environment variable names
 * (an entry's env can set those). `mcp-status` runs the same function, so the
 * two never disagree on whether an entry starts.
 */
export function checkLaunchPlace(
  binding: { id: string; scope: McpConfigScope; file: string },
  options: { startDir?: string; home?: string } = {},
): McpPlaceVerdict {
  let start: string;
  try {
    start = fs.realpathSync(options.startDir ?? process.cwd());
  } catch (err) {
    return { refused: 'start-unresolved', code: errorCode(err) };
  }

  let boundFile = realPathOf(binding.file);
  if (binding.scope === 'project') {
    const recorded = path.dirname(path.resolve(binding.file));
    let project: string;
    try {
      project = fs.realpathSync(recorded);
    } catch (err) {
      return { refused: 'project-unresolved', project: recorded, path: recorded, code: errorCode(err) };
    }
    // The bound config itself: a deleted one leaves the binding no entry to start.
    const file = path.join(project, path.basename(binding.file));
    try {
      boundFile = fs.realpathSync(file);
    } catch (err) {
      return { refused: 'project-unresolved', project, path: file, code: errorCode(err) };
    }
    const inside = project.endsWith(path.sep) ? project : `${project}${path.sep}`;
    if (start !== project && !start.startsWith(inside)) {
      return { refused: 'outside-project', project, startDir: start };
    }
  }

  // A home config found from a parent directory is read as the home config it
  // is, and the bound config holds the id by design.
  const home = options.home ?? os.homedir();
  const skipped = new Set<string>([boundFile]);
  for (const location of mcpConfigLocations()) {
    if (location.scope !== 'home') continue;
    try {
      skipped.add(fs.realpathSync(path.join(home, location.relativePath)));
    } catch {
      // Absent: nothing found from a parent directory can be it.
    }
  }
  const projectLocations = mcpConfigLocations().filter((location) => location.scope === 'project');
  for (let dir = start; ; dir = path.dirname(dir)) {
    for (const location of projectLocations) {
      const found = copyOfBinding(path.join(dir, location.relativePath), binding.id, skipped);
      if (found !== undefined) return found;
    }
    if (path.dirname(dir) === dir) break;
  }
  return { refused: false };
}

/**
 * Whether one project-level config holds a binding's id: undefined where it
 * does not, and where it is absent, skipped or not a regular file (no client
 * reads an entry from it). A file that exists and could not be read, or is
 * larger than the bound, could hold it, so it refuses.
 */
function copyOfBinding(candidate: string, id: string, skipped: Set<string>): McpPlaceVerdict | undefined {
  const unreadable = (err: unknown): McpPlaceVerdict => ({
    refused: 'copy-unchecked',
    file: candidate,
    why: `it could not be read (${errorCode(err)})`,
  });
  let resolved: string;
  try {
    resolved = fs.realpathSync(candidate);
    if (skipped.has(resolved) || !fs.statSync(resolved).isFile()) return undefined;
  } catch (err) {
    return isAbsent(err) ? undefined : unreadable(err);
  }
  let fd: number;
  try {
    // Not blocking: a file swapped for a FIFO after the stat above does not hang the start.
    fd = fs.openSync(resolved, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  } catch (err) {
    return isAbsent(err) ? undefined : unreadable(err);
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) return undefined;
    const tooLarge: McpPlaceVerdict = {
      refused: 'copy-unchecked',
      file: candidate,
      why: `it is larger than ${BINDING_COPY_READ_LIMIT} bytes`,
    };
    if (stat.size > BINDING_COPY_READ_LIMIT) return tooLarge;
    const bytes = readUpTo(fd, BINDING_COPY_READ_LIMIT);
    if (bytes === undefined) return tooLarge;
    return holdsId(bytes, id) ? { refused: 'copy-found', file: candidate } : undefined;
  } catch (err) {
    return unreadable(err);
  } finally {
    fs.closeSync(fd);
  }
}

/** The bytes of an open file, or undefined when it holds more than `limit`. */
function readUpTo(fd: number, limit: number): Buffer | undefined {
  const chunks: Buffer[] = [];
  const chunk = Buffer.alloc(64 * 1024);
  let total = 0;
  for (;;) {
    const read = fs.readSync(fd, chunk, 0, chunk.length, null);
    if (read === 0) return Buffer.concat(chunks, total);
    total += read;
    if (total > limit) return undefined;
    chunks.push(Buffer.from(chunk.subarray(0, read)));
  }
}

/**
 * Whether a config's bytes hold an id: in any string of the document, keys
 * included, where it parses as JSON (so an id written with escapes is found),
 * and anywhere in its bytes where it does not.
 */
function holdsId(bytes: Buffer, id: string): boolean {
  let document: unknown;
  try {
    document = JSON.parse(bytes.toString('utf-8'));
  } catch {
    return bytes.includes(id);
  }
  const pending: unknown[] = [document];
  while (pending.length > 0) {
    const value = pending.pop();
    if (typeof value === 'string') {
      if (value.includes(id)) return true;
    } else if (Array.isArray(value)) {
      for (const item of value) pending.push(item);
    } else if (value !== null && typeof value === 'object') {
      for (const [key, item] of Object.entries(value)) {
        if (key.includes(id)) return true;
        pending.push(item);
      }
    }
  }
  return false;
}

/** A path that does not exist: it, or a directory on the way to it, is absent. */
function isAbsent(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException).code;
  return code === 'ENOENT' || code === 'ENOTDIR';
}

function errorCode(err: unknown): string {
  return (err as NodeJS.ErrnoException).code ?? 'unknown error';
}
