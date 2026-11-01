import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { VERSION } from './commands/utils';
import { printedCommand } from './printed-command';
import { type Sandbox, CLI_PATH, githubToken, literalValue, makeSandbox, removeSandbox, runCli, server, write } from './mcp-env-secret.test-support';

/**
 * Three sentences say what the env rule (src/mcp/env-secrets.ts) does: the
 * CHANGELOG entry on the next step `scan` gives after such a finding, the
 * docs/scanning.md paragraph on which configs `scan` and `verify` read, and
 * the docs/use-cases/secure-mcp-configs.md sentence on what a server
 * `mcp-status` lists as exposed is in `scan`. Each is held here against the
 * commands, run from the built entry point: a change to what they do fails
 * here, and the sentence has to change with it.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const read = (relativePath: string): string => fs.readFileSync(path.join(REPO_ROOT, relativePath), 'utf-8');
/** Line breaks and runs of spaces read as one space, as Markdown renders them. */
const flat = (text: string): string => text.replace(/\s+/g, ' ');

function unreleasedSection(): string {
  const text = read('CHANGELOG.md');
  const start = text.indexOf('## [Unreleased]');
  expect(start, 'CHANGELOG.md must hold an [Unreleased] section').toBeGreaterThan(-1);
  const end = text.indexOf('\n## [', start + 1);
  return flat(text.slice(start, end === -1 ? undefined : end));
}

/** The one paragraph of `relativePath` beginning `opening`. */
function paragraph(relativePath: string, opening: string): string {
  const found = read(relativePath).split('\n').filter((l) => l.startsWith(opening));
  expect(found, `${relativePath} must hold exactly one paragraph beginning "${opening}"`).toHaveLength(1);
  return flat(found[0]);
}

let sb: Sandbox;
beforeEach(() => {
  sb = makeSandbox();
});
afterEach(() => {
  removeSandbox(sb);
});

/**
 * The command a line of `mcp-status` names: this build, in the form
 * printed-command.ts gives for the node link and the CLI script the sandbox
 * runs. `scan` names `npx secretless-ai <command>` in every fix it prints, so
 * that its JSON and SARIF output carry no path of the machine it ran on.
 */
const statusCommand = (command: string): string =>
  printedCommand(command, VERSION, { execPath: process.execPath, pathEnv: sb.env.PATH ?? '', script: CLI_PATH });
const scanCommand = (command: string): string => `npx secretless-ai ${command}`;
/** The lines of a run's output, so that a check holds a whole line and never part of one. */
const lines = (out: string): string[] => out.split('\n');

describe('the published text on a literal secret in an MCP server env', () => {
  it("CHANGELOG names mcp-status's own advice as the next step: protect-mcp for a .mcp.json, otherwise move each value out and rotate it", () => {
    const entry = unreleasedSection();
    const protect = (command: string): string => `Run ${command} to encrypt exposed secrets.`;
    const moveAndRotate = (command: string): string => `Move each value out of its file and rotate it, then run ${command} again.`;
    expect(entry).toContain('`protect-mcp` for a `.mcp.json`, the file it rewrites');
    expect(entry).toContain(`"${moveAndRotate('`npx secretless-ai mcp-status`').slice(0, -1)}"`);

    // mcp-status prints that advice for each file, naming this build; scan's
    // next step is the same advice, in the command form of its other fixes.
    write(sb.project, '.mcp.json', JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: literalValue(601) }) } }, null, 2));
    expect(lines(runCli(sb, ['mcp-status']).out)).toContain(`  ${protect(`\`${statusCommand('protect-mcp')}\``)}`);
    expect(lines(runCli(sb, ['scan', '.']).out)).toContain(`  MCP env secrets:    ${protect(scanCommand('protect-mcp'))}`);

    removeSandbox(sb);
    sb = makeSandbox();
    write(sb.project, path.join('.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: literalValue(602) }) } }, null, 2));
    expect(lines(runCli(sb, ['mcp-status']).out)).toContain(`  ${moveAndRotate(`\`${statusCommand('mcp-status')}\``)}`);
    expect(lines(runCli(sb, ['scan', '.']).out)).toContain(`  MCP env secrets:    ${moveAndRotate(scanCommand('mcp-status'))}`);
  });

  it('docs/scanning.md says scan reads these configs at any depth while verify reads the root configs', () => {
    const text = paragraph('docs/scanning.md', 'In a project-level MCP client config');
    expect(text).toContain('`scan` reads these configs at any depth, while `verify` reads the root configs only');

    const nested = literalValue(611);
    write(sb.project, path.join('sub', 'deep', '.mcp.json'), JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: nested }) } }, null, 2));
    const scanned = runCli(sb, ['scan', '.']);
    expect(scanned.code).toBe(1);
    expect(scanned.out).toContain('sub/deep/.mcp.json:');
    expect(runCli(sb, ['verify']).out).toContain('AI context: clean');

    write(sb.project, '.mcp.json', JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: literalValue(612) }) } }, null, 2));
    const verified = runCli(sb, ['verify']).out;
    expect(verified).toContain('FAIL');
    expect(verified).toContain('MCP Server Env Secret .mcp.json:');
    expect(verified).not.toContain('sub/deep/.mcp.json');
  });

  it("docs/use-cases/secure-mcp-configs.md says a server listed as exposed is reported under its value's pattern name, or as MCP Server Env Secret", () => {
    const page = flat(read('docs/use-cases/secure-mcp-configs.md'));
    const at = page.indexOf('a server listed as exposed there is');
    expect(at, 'docs/use-cases/secure-mcp-configs.md must hold the sentence on a server listed as exposed').toBeGreaterThan(-1);
    const sentence = page.slice(at, page.indexOf('. ', at) + 1);
    expect(sentence).toContain("a value with a credential format is reported under its pattern's name, such as `GitHub Token`, and any other value as `MCP Server Env Secret`.");

    const servers = { gh: server({ GITHUB_TOKEN: githubToken(621) }), svc: server({ MY_SERVICE_API_KEY: literalValue(622) }) };
    write(sb.project, '.mcp.json', JSON.stringify({ mcpServers: servers }, null, 2));
    const listed = runCli(sb, ['mcp-status']).out;
    expect(listed).toContain('gh: EXPOSED (1 plaintext secret(s))');
    expect(listed).toContain('svc: EXPOSED (1 plaintext secret(s))');
    const report = JSON.parse(runCli(sb, ['scan', '.', '--json']).stdout) as { findings: Array<{ patternName: string }> };
    expect(report.findings.map((f) => f.patternName).sort()).toEqual(['GitHub Token', 'MCP Server Env Secret']);
  });
});
