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
