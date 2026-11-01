/**
 * A plaintext secret in the env of an MCP server: the one decision every
 * command makes about it, and the one pass over a config's text that finds
 * each value it is made for.
 *
 * The decision. An env entry that `classifyEnvVars` (classify.ts) calls a
 * secret holds a literal secret unless its value is
 *   - empty;
 *   - a whole-value expansion the client fills in when it starts the server:
 *     the whole value is `${NAME}`, `${NAME:-default}`, `${env:NAME}` or
 *     `${input:ID}`;
 *   - a placeholder by the value rules of `isKnownExample` (scan.ts): a known
 *     example key, a placeholder word, too few distinct characters, or a
 *     localhost demo connection string. Its comment rule reads the line a
 *     value is on, and a JSON value has no comment, so it is not applied.
 * A bare `$NAME` is a literal: no client is known to expand one.
 *
 * `mcp-status` counts a server's literals as its plaintext secrets. `scan`,
 * `scan-staged` (the pre-commit hook), `status` and `verify` report each
 * literal in a project's MCP configs as an `mcp-env-secret` finding, or under
 * the credential pattern its value matches, so one value is one finding.
 * A per-user config (the Claude Desktop config, `~/.claude.json`,
 * `~/.cursor/mcp.json` and the others `mcp-status` reads in the home
 * directory) is read by `mcp-status` alone.
 *
 * The pass. `readMcpEnv` reads the text once, front to back, and records the
 * line and the offsets of each env value's string token as it passes it, so a
 * key or a value written with escapes (`A`, `\/`) is found where it is
 * written, and each occurrence of a key written twice is read, where
 * `JSON.parse` keeps the last.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CREDENTIAL_PATTERNS, type CredentialPattern } from '../patterns';
// A cycle, read only at call time: scan.ts imports this module, and this
// module calls scan.ts's value rules, so there is one copy of them.
import { isKnownExample } from '../scan';
import { hasDisplayHazard, shellQuote, withSlashSeparators } from '../display-safe';
import { classifyEnvVars } from './classify';
import { mcpConfigLocations, serverMapKey } from './discover';

/** The pattern id of a literal secret in an MCP server's env that no credential pattern matches. */
export const MCP_ENV_SECRET_ID = 'mcp-env-secret';
/** Its pattern name, as findings and previews name it. */
export const MCP_ENV_SECRET_NAME = 'MCP Server Env Secret';

/** What a value under a secret's name in an MCP server's env is. */
export type EnvValueKind = 'empty' | 'expansion' | 'placeholder' | 'literal';

/** The kinds of value a finding can be made for: a literal, and a placeholder under `--show-placeholders`. */
export type EnvSecretKind = 'literal' | 'placeholder';

/** The whole value is one expansion and nothing else. */
const WHOLE_VALUE_EXPANSION =
  /^\$\{(?:[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?|env:[A-Za-z_][A-Za-z0-9_]*|input:[^${}]+)\}$/;

/** Whether `value` is a placeholder by `isKnownExample`'s value rules alone. */
function isPlaceholderValue(value: string): boolean {
  // An empty line holds no comment, so the comment rule cannot apply.
  const match = Object.assign([value], { index: 0, input: value }) as unknown as RegExpMatchArray;
  return isKnownExample('', match);
}

/** What an env value is, by the decision above. Says nothing about the key. */
export function envValueKind(value: string): EnvValueKind {
  if (value === '') return 'empty';
  if (WHOLE_VALUE_EXPANSION.test(value)) return 'expansion';
  if (isPlaceholderValue(value)) return 'placeholder';
  return 'literal';
}

/**
 * The kind of secret an env entry holds: undefined when `classifyEnvVars` does
 * not call it a secret, or when its value is empty or an expansion.
 */
export function envSecretKind(key: string, value: string): EnvSecretKind | undefined {
  const { secrets } = classifyEnvVars({ [key]: value });
  if (!Object.prototype.hasOwnProperty.call(secrets, key)) return undefined;
  const kind = envValueKind(value);
  return kind === 'literal' || kind === 'placeholder' ? kind : undefined;
}

/** One string value in a server's env, where the config's text holds it. */
export interface McpEnvValue {
  /** The key under `projects` in ~/.claude.json, for a server kept for one project; undefined at the top level. */
  projectKey?: string;
  /** The server's name, decoded. */
  server: string;
  /** The env key, decoded. */
  key: string;
  /** The value, decoded. */
  value: string;
  /** 1-based line of the value, as `text.split('\n')` numbers it. */
  line: number;
  /** Offset on its line of the value token's opening quote. */
  from: number;
  /** Offset on its line just past the value token's closing quote. */
  to: number;
}

/** An env value the decision calls a secret, with its kind. */
export interface McpEnvSecret extends McpEnvValue {
  kind: EnvSecretKind;
}

/** A container the pass is inside. */
interface Frame {
  array: boolean;
  /** An object whose next string is a member's key. */
  expectKey: boolean;
  /** An object's current member key, decoded while the frame is shallow enough to need it. */
  key: string | undefined;
  /** An array's current element index. */
  index: number;
}

/** The text of a string token from its opening quote to past its closing quote, decoded. */
function tokenText(text: string, start: number, end: number): string {
  const inner = text.slice(start + 1, end - 1);
  return inner.indexOf('\\') === -1 ? inner : (JSON.parse(text.slice(start, end)) as string);
}

/** The offset past the closing quote of the string token whose opening quote is at `start`. */
function stringEnd(text: string, start: number): number {
  let from = start + 1;
  for (;;) {
    const quote = text.indexOf('"', from);
    if (quote === -1) return text.length;
    let back = quote - 1;
    while (back > start && text.charCodeAt(back) === 0x5c) back--;
    // An even run of backslashes before the quote escapes none of it.
    if ((quote - 1 - back) % 2 === 0) return quote + 1;
    from = quote + 1;
  }
}

/** The offset past a number, `true`, `false` or `null` starting at `start`. */
function scalarEnd(text: string, start: number): number {
  let i = start;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === 0x2c || c === 0x5d || c === 0x7d || c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) break;
    i++;
  }
  return i;
}

/** The member a frame is at: an object's key, or an array element's index, as `Object.entries` names it. */
function memberOf(frame: Frame): string | undefined {
  return frame.array ? String(frame.index) : frame.key;
}

/** An object member of `container` by its own key, or undefined. */
function ownObject(container: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  if (!Object.prototype.hasOwnProperty.call(container, key)) return undefined;
  const value = container[key];
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

/**
 * Every string value in the env of each server in the server map `discover.ts`
 * reads (the first of `mcpServers`, `mcp-servers` and `servers` present), in
 * text order, every occurrence of a key written twice included. With
 * `projectMaps`, the server map of each project under `projects` too, as in
 * ~/.claude.json. Empty for text that is not a JSON object, which
 * `mcp-status` lists as not checked.
 */
export function readMcpEnv(text: string, options: { projectMaps?: boolean } = {}): McpEnvValue[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return [];
  const root = parsed as Record<string, unknown>;
  const topKey = serverMapKey(root);
  const projects = options.projectMaps ? ownObject(root, 'projects') : undefined;
  if (topKey === undefined && projects === undefined) return [];
  const projectMapKey = new Map<string, string | undefined>();
  const mapKeyOf = (projectKey: string): string | undefined => {
    if (!projectMapKey.has(projectKey)) {
      const entry = projects === undefined ? undefined : ownObject(projects, projectKey);
      projectMapKey.set(projectKey, entry === undefined ? undefined : serverMapKey(entry));
    }
    return projectMapKey.get(projectKey);
  };
  // Keys are decoded only as deep as an env value's path reaches.
  const maxDepth = projects === undefined ? 4 : 6;

  const values: McpEnvValue[] = [];
  const stack: Frame[] = [];
  let line = 1;
  let lineStart = 0;
  let i = 0;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === 0x0a) {
      i++;
      line++;
      lineStart = i;
    } else if (c === 0x20 || c === 0x09 || c === 0x0d || c === 0x3a) {
      i++;
    } else if (c === 0x2c) {
      const top = stack[stack.length - 1];
      if (top !== undefined) {
        if (top.array) top.index++;
        else top.expectKey = true;
      }
      i++;
    } else if (c === 0x7b || c === 0x5b) {
      stack.push({ array: c === 0x5b, expectKey: c === 0x7b, key: undefined, index: 0 });
      i++;
    } else if (c === 0x7d || c === 0x5d) {
      stack.pop();
      i++;
    } else if (c === 0x22) {
      const end = stringEnd(text, i);
      const top = stack[stack.length - 1];
      if (top !== undefined && !top.array && top.expectKey) {
        top.expectKey = false;
        top.key = stack.length <= maxDepth ? tokenText(text, i, end) : undefined;
      } else {
        const at = envPathAt(stack, topKey, projects === undefined ? undefined : mapKeyOf);
        if (at !== undefined) {
          values.push({ ...at, value: tokenText(text, i, end), line, from: i - lineStart, to: end - lineStart });
        }
      }
      i = end;
    } else {
      i = scalarEnd(text, i);
    }
  }
  return values;
}

/**
 * The server and key a string value at the top of `stack` is the env value
 * of, or undefined when it is not one: at `[serverMap, server, "env", key]`,
 * or with project maps at `["projects", project, serverMap, server, "env",
 * key]`. A server map or an env may be an array, read by index as
 * `discover.ts` reads it through `Object.entries`; a server is an object.
 */
function envPathAt(
  stack: readonly Frame[],
  topKey: string | undefined,
  mapKeyOf: ((projectKey: string) => string | undefined) | undefined,
): { projectKey?: string; server: string; key: string } | undefined {
  if (stack.length === 4) {
    const [root, map, server, env] = stack;
    if (topKey === undefined || root.key !== topKey || server.array || server.key !== 'env') return undefined;
    const name = memberOf(map);
    const key = memberOf(env);
    return name === undefined || key === undefined ? undefined : { server: name, key };
  }
  if (stack.length === 6 && mapKeyOf !== undefined) {
    const [root, projects, project, map, server, env] = stack;
    if (root.key !== 'projects' || projects.array || project.array || server.array || server.key !== 'env') return undefined;
    const projectKey = projects.key;
    if (projectKey === undefined || project.key === undefined || project.key !== mapKeyOf(projectKey)) return undefined;
    const name = memberOf(map);
    const key = memberOf(env);
    return name === undefined || key === undefined ? undefined : { projectKey, server: name, key };
  }
  return undefined;
}

/** The env values of `readMcpEnv(text, options)` the decision calls a secret: literals and placeholders. */
export function mcpEnvSecrets(text: string, options: { projectMaps?: boolean } = {}): McpEnvSecret[] {
  const secrets: McpEnvSecret[] = [];
  for (const value of readMcpEnv(text, options)) {
    const kind = envSecretKind(value.key, value.value);
    if (kind !== undefined) secrets.push({ ...value, kind });
  }
  return secrets;
}

/** The secrets of `mcpEnvSecrets(text)`, by line, in text order on each line. */
export function mcpEnvSecretsByLine(text: string): Map<number, McpEnvSecret[]> {
  const byLine = new Map<number, McpEnvSecret[]>();
  for (const secret of mcpEnvSecrets(text)) {
    const onLine = byLine.get(secret.line);
    if (onLine) onLine.push(secret);
    else byLine.set(secret.line, [secret]);
  }
  return byLine;
}

/** The longest value the credential patterns are run on, as `scan` runs them on a line of at most this length. */
const PATTERN_INPUT_MAX = 4096;

/** Each credential pattern with the global flag, built once, so no pattern is compiled per value. */
const GLOBAL_PATTERN_REGEX = new Map<CredentialPattern, RegExp>();

function globalRegexOf(pattern: CredentialPattern): RegExp {
  let regex = GLOBAL_PATTERN_REGEX.get(pattern);
  if (regex === undefined) {
    regex = pattern.regex.flags.includes('g') ? new RegExp(pattern.regex.source, pattern.regex.flags) : new RegExp(pattern.regex.source, `${pattern.regex.flags}g`);
    GLOBAL_PATTERN_REGEX.set(pattern, regex);
  }
  return regex;
}

/**
 * The first credential pattern, in list order, with a match in `value` that is
 * not a known example (any match, with `includeExamples`), and that match; or
 * undefined. A value with one is vendor-shaped and is reported under that
 * pattern's name. A value longer than a line `scan` runs the patterns on is
 * not run.
 */
export function vendorMatchOf(
  value: string,
  includeExamples = false,
): { pattern: CredentialPattern; match: RegExpExecArray } | undefined {
  if (value.length > PATTERN_INPUT_MAX) return undefined;
  for (const pattern of CREDENTIAL_PATTERNS) {
    const regex = globalRegexOf(pattern);
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(value)) !== null) {
      if (match[0] === '') {
        regex.lastIndex++;
        continue;
      }
      if (includeExamples || !isKnownExample('', match)) return { pattern, match };
    }
  }
  return undefined;
}

/** The marker a preview writes in place of a value: `[<pattern name> REDACTED]`, as `maskCredentials` writes. */
export function redactedMarker(patternName: string): string {
  return `[${patternName} REDACTED]`;
}

/** Keys in a constructed preview are cut to this many characters. */
const PREVIEW_KEY_MAX = 48;

/**
 * The preview of a finding made for an env value: `"<key>": "[<name>
 * REDACTED]"`, built from the key, never a slice of the line, so it holds no
 * character of the value however the line is written.
 */
export function envFindingPreview(key: string, patternName: string): string {
  const shown = key.length > PREVIEW_KEY_MAX ? `${key.slice(0, PREVIEW_KEY_MAX)}...` : key;
  return `"${shown}": "${redactedMarker(patternName)}"`;
}

/**
 * `line` with the string token of each secret on it replaced, between its
 * quotes, by its marker: the pattern name its value matches, or `MCP Server
 * Env Secret`. The token is replaced as written, escapes included. Run before
 * `maskCredentials`, for the preview of a finding on a line that holds env
 * secrets.
 */
export function maskEnvSecrets(line: string, secrets: readonly McpEnvValue[]): string {
  let masked = line;
  // Right to left, so each replacement leaves the offsets before it as they were.
  const ordered = [...secrets].sort((a, b) => b.from - a.from);
  for (const secret of ordered) {
    if (secret.to > line.length || secret.to - secret.from < 2) continue;
    const name = vendorMatchOf(secret.value, true)?.pattern.name ?? MCP_ENV_SECRET_NAME;
    masked = `${masked.slice(0, secret.from + 1)}${redactedMarker(name)}${masked.slice(secret.to - 1)}`;
  }
  return masked;
}

/** A finding the env rule makes on one line: the value it names, and the credential pattern it matched, if any. */
export interface EnvLineFinding {
  secret: McpEnvSecret;
  /** The credential pattern the value matched, and its match on the decoded value; undefined for `mcp-env-secret`. */
  vendor?: { pattern: CredentialPattern; match: RegExpExecArray };
}

/** Where a finding the pattern path reported on a line lies on that line. */
export interface LineSpan {
  from: number;
  to: number;
}

/**
 * The findings the env rule makes on one line: for each name, the first
 * secret in text order whose value is reported, one finding per line and
 * name as the pattern path makes one per line. A literal is reported; a
 * placeholder only with `showPlaceholders`, and otherwise passed to
 * `onSuppressed` when no credential pattern matches it (a value one matches
 * is counted where the pattern path reads it). A secret whose token the
 * pattern path's finding on the line covers (`covered`) is that finding, and
 * is not reported again.
 */
export function envFindingsOnLine(
  secrets: readonly McpEnvSecret[],
  covered: LineSpan | undefined,
  options: { showPlaceholders?: boolean; onSuppressed?: () => void } = {},
): EnvLineFinding[] {
  const byName = new Map<string, EnvLineFinding>();
  for (const secret of secrets) {
    if (secret.kind === 'placeholder' && !options.showPlaceholders) {
      if (vendorMatchOf(secret.value, true) === undefined) options.onSuppressed?.();
      continue;
    }
    if (covered !== undefined && secret.from < covered.to && covered.from < secret.to) continue;
    const vendor = vendorMatchOf(secret.value, options.showPlaceholders === true);
    const name = vendor?.pattern.id ?? MCP_ENV_SECRET_ID;
    if (!byName.has(name)) byName.set(name, vendor === undefined ? { secret } : { secret, vendor });
  }
  return [...byName.values()];
}

/** The basenames of the project-level MCP configs `mcp-status` reads: `.mcp.json` and `mcp.json`. */
const PROJECT_MCP_CONFIG_NAMES: ReadonlySet<string> = new Set(
  mcpConfigLocations().filter((l) => l.scope === 'project').map((l) => path.basename(l.relativePath)),
);

/** The client directories a project-level `mcp.json` is read in: `.cursor`, `.vscode` and `.windsurf`. */
const CLIENT_CONFIG_DIRS: ReadonlySet<string> = new Set(
  mcpConfigLocations()
    .filter((l) => l.scope === 'project' && path.dirname(l.relativePath) !== '.')
    .map((l) => path.dirname(l.relativePath)),
);

function realOrResolved(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

/** The real paths of the per-user MCP configs `mcp-status` reads in `home`. */
export function homeMcpConfigPaths(home: string = os.homedir()): ReadonlySet<string> {
  return new Set(
    mcpConfigLocations()
      .filter((l) => l.scope === 'home')
      .map((l) => realOrResolved(path.join(home, l.relativePath))),
  );
}

/**
 * Whether the file at `filePath` is read by the env rule: named as a
 * project-level MCP config (`.mcp.json`, or `mcp.json` alone or under
 * `.cursor/`, `.vscode/` or `.windsurf/`), at any depth, and not one of the
 * per-user configs `mcp-status` reads in the home directory. `homeConfigs`
 * is `homeMcpConfigPaths()`, passed in by a caller that asks for many files.
 */
export function isProjectMcpConfig(filePath: string, homeConfigs: ReadonlySet<string> = homeMcpConfigPaths()): boolean {
  if (!PROJECT_MCP_CONFIG_NAMES.has(path.basename(filePath))) return false;
  return !homeConfigs.has(realOrResolved(filePath));
}

/** The directory `mcp-status` and `protect-mcp` read a project-level MCP config from. */
function configProjectDir(configPath: string): string {
  const dir = path.dirname(path.resolve(configPath));
  return path.basename(configPath) !== '.mcp.json' && CLIENT_CONFIG_DIRS.has(path.basename(dir)) ? path.dirname(dir) : dir;
}

/** `dir` as a shell operand from `cwd`, or `<dir>` when it holds a character that would reach a terminal as a control. */
function dirOperand(dir: string, cwd: string): string {
  let shown = dir;
  const rel = path.relative(realOrResolved(cwd), realOrResolved(dir));
  if (rel && !rel.startsWith('..') && !path.isAbsolute(rel) && !rel.startsWith('-')) shown = rel;
  shown = withSlashSeparators(shown);
  return hasDisplayHazard(shown) ? '<dir>' : shellQuote(shown);
}

/**
 * The fix for a literal secret in the env of a project-level MCP config:
 * `mcp-status`'s own advice for it. For a `.mcp.json`, which `protect-mcp`
 * rewrites, run `protect-mcp`; for the others, which it leaves as they are,
 * move each value out and rotate it, then run `mcp-status` again. Both name
 * the directory to run in when it is not `cwd`.
 */
export function mcpEnvFix(configPath: string, cwd: string = process.cwd()): string {
  const dir = configProjectDir(configPath);
  const where = realOrResolved(dir) === realOrResolved(cwd) ? '' : ` in ${dirOperand(dir, cwd)}`;
  return path.basename(configPath) === '.mcp.json'
    ? `Run npx secretless-ai protect-mcp${where} to encrypt exposed secrets.`
    : `Move each value out of its file and rotate it, then run npx secretless-ai mcp-status${where} again.`;
}

/**
 * The fix of the env findings in the config at `configPath`, worked out on
 * the first call and given to every later one: `mcpEnvFix` resolves real
 * paths, once for a config however many findings it holds.
 */
export function envFixOf(configPath: string): () => string {
  let fix: string | undefined;
  return () => (fix ??= mcpEnvFix(configPath));
}
