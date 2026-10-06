/**
 * MCP config file auto-discovery across 5 clients.
 *
 * Finds MCP server configurations in Claude Desktop, Cursor,
 * Claude Code, VS Code, and Windsurf config files.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type McpClient = 'claude-desktop' | 'cursor' | 'claude-code' | 'vscode' | 'windsurf';

export interface McpServerEntry {
  name: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  /** true if command is the secretless-mcp binary or the mcp-wrapper.js script */
  alreadyProtected: boolean;
}

export interface McpConfigFile {
  client: McpClient;
  filePath: string;
  servers: McpServerEntry[];
  /** Raw parsed JSON for later rewriting */
  raw: Record<string, unknown>;
}

/** A config file that exists but could not be read or parsed, so its servers are unknown. */
export interface UnparsedMcpConfig {
  client: McpClient;
  filePath: string;
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

interface ClientConfigPath {
  client: McpClient;
  /** Relative path from home directory */
  relativePath: string;
}

/**
 * Returns the list of config file paths to search, relative to the home directory.
 * Platform-aware: Claude Desktop has different paths on macOS vs Linux.
 */
function getClientConfigPaths(): ClientConfigPath[] {
  const paths: ClientConfigPath[] = [];

  // Claude Desktop: search both macOS and Linux paths on all platforms.
  // The check is just existsSync (harmless miss), and searching both enables
  // cross-platform testing via homeOverride.
  paths.push({
    client: 'claude-desktop',
    relativePath: path.join('Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
  });
  paths.push({
    client: 'claude-desktop',
    relativePath: path.join('.config', 'Claude', 'claude_desktop_config.json'),
  });

  // Cursor
  paths.push({
    client: 'cursor',
    relativePath: path.join('.cursor', 'mcp.json'),
  });

  // Claude Code: two possible settings files
  paths.push({
    client: 'claude-code',
    relativePath: path.join('.claude', 'settings.json'),
  });
  paths.push({
    client: 'claude-code',
    relativePath: path.join('.claude', 'settings.local.json'),
  });

  // VS Code
  paths.push({
    client: 'vscode',
    relativePath: path.join('.vscode', 'mcp.json'),
  });

  // Windsurf
  paths.push({
    client: 'windsurf',
    relativePath: path.join('.windsurf', 'mcp.json'),
  });

  return paths;
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
 * Extract MCP server entries from a parsed JSON config.
 * Supports both `mcpServers` and `mcp-servers` keys.
 */
function parseServers(raw: Record<string, unknown>): McpServerEntry[] | null {
  const serversObj =
    (raw['mcpServers'] as Record<string, unknown> | undefined) ??
    (raw['mcp-servers'] as Record<string, unknown> | undefined);

  if (!serversObj || typeof serversObj !== 'object') {
    return null;
  }

  const entries: McpServerEntry[] = [];

  for (const [name, value] of Object.entries(serversObj)) {
    if (!value || typeof value !== 'object') continue;

    const serverDef = value as Record<string, unknown>;
    const command = typeof serverDef['command'] === 'string' ? serverDef['command'] : '';
    const args = Array.isArray(serverDef['args'])
      ? (serverDef['args'] as unknown[]).filter((a): a is string => typeof a === 'string')
      : [];
    const env: Record<string, string> = {};

    if (serverDef['env'] && typeof serverDef['env'] === 'object') {
      for (const [k, v] of Object.entries(serverDef['env'] as Record<string, unknown>)) {
        if (typeof v === 'string') {
          env[k] = v;
        }
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

  return entries;
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
 * Searches across 5 clients: Claude Desktop, Cursor, Claude Code, VS Code, Windsurf —
 * plus the Claude Code project-scope config (.mcp.json at the project root).
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

  const candidates: Array<{ client: McpClient; fullPath: string }> = getClientConfigPaths().map(
    ({ client, relativePath }) => ({ client, fullPath: path.join(home, relativePath) }),
  );
  // Claude Code project-scope MCP config: .mcp.json at the project root is
  // committed to repos, so plaintext env values there leak beyond one machine.
  candidates.push({ client: 'claude-code', fullPath: path.join(projectDir, '.mcp.json') });

  for (const { client, fullPath } of candidates) {
    if (!fs.existsSync(fullPath)) continue;

    let content: string;
    try {
      content = fs.readFileSync(fullPath, 'utf-8');
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      unparsed.push({ client, filePath: fullPath, reason: code ? `could not be read (${code})` : 'could not be read' });
      continue;
    }
    if (content.trim() === '') continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch (err) {
      unparsed.push({ client, filePath: fullPath, reason: describeJsonError(err, content) });
      continue;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      unparsed.push({ client, filePath: fullPath, reason: 'not a JSON object' });
      continue;
    }
    const raw = parsed as Record<string, unknown>;

    const serversValue = raw['mcpServers'] ?? raw['mcp-servers'];
    if (serversValue !== undefined && serversValue !== null && typeof serversValue !== 'object') {
      unparsed.push({ client, filePath: fullPath, reason: 'its MCP server list is not a JSON object' });
      continue;
    }

    const servers = parseServers(raw);
    if (!servers) continue; // No mcpServers key

    results.push({
      client,
      filePath: fullPath,
      servers,
      raw,
    });
  }

  return { configs: results, unparsed };
}
