import { describe, it, expect, vi, afterEach } from 'vitest';

vi.mock('../mcp/protect', () => ({ protectMcp: vi.fn() }));

import * as path from 'path';
import { protectMcp, type ProtectResult } from '../mcp/protect';
import { mcpConfigLocations } from '../mcp/discover';
import { runProtectMcp } from './mcp';
import { findSecretValueProblem, unstorableMcpSecretError } from '../secret-value';
import { sourceCommand } from '../mcp/printed-command.test-support';

/** Any C0 control, DEL or C1 control: what must never reach the terminal raw. */
const RAW_CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/;

async function protectOutput(): Promise<string> {
  const out: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
  expect(await runProtectMcp([])).toBe(0);
  return out.join('\n');
}

describe('protect-mcp prints MCP env key names escaped (#229)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('writes a control character in an encrypted key as an escape, not raw', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      clientsScanned: 1,
      secretsFound: 3,
      serversProtected: 1,
      servers: [{ client: 'claude-code', server: 'demo', secretKeys: ['X\x1b[2J_TOKEN', 'Y\u009b2J_TOKEN', 'GITHUB_TOKEN'] }],
      alreadyProtected: 0,
      injectionWarnings: [],
      unparsed: [],
      unchecked: [],
      sharedName: [],
      refusedName: [],
      unmoved: [],
      bound: [],
      rebound: [],
      unbound: [],
      copies: [],
      copyFiles: [],
      repointed: [],
      projectLevel: [],
    });

    const output = await protectOutput();

    expect(output).not.toMatch(RAW_CONTROL);
    expect(output).toContain('      "X\\u001b[2J_TOKEN" (encrypted)');
    expect(output).toContain('      "Y\\u009b2J_TOKEN" (encrypted)');
  });

  it('CONTROL: an ordinary key is listed as it is, unquoted', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      clientsScanned: 1,
      secretsFound: 1,
      serversProtected: 1,
      servers: [{ client: 'cursor', server: 'github', secretKeys: ['GITHUB_TOKEN'] }],
      alreadyProtected: 0,
      injectionWarnings: [],
      unparsed: [],
      unchecked: [],
      sharedName: [],
      refusedName: [],
      unmoved: [],
      bound: [],
      rebound: [],
      unbound: [],
      copies: [],
      copyFiles: [],
      repointed: [],
      projectLevel: [],
    });

    expect(await protectOutput()).toContain('\n      GITHUB_TOKEN (encrypted)');
  });

  it('quotes a key holding a quote or backslash, so it cannot pass for an escaped one', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      clientsScanned: 1,
      secretsFound: 1,
      serversProtected: 1,
      servers: [{ client: 'cursor', server: 'github', secretKeys: ['"X\\u001b[2J_TOKEN"'] }],
      alreadyProtected: 0,
      injectionWarnings: [],
      unparsed: [],
      unchecked: [],
      sharedName: [],
      refusedName: [],
      unmoved: [],
      bound: [],
      rebound: [],
      unbound: [],
      copies: [],
      copyFiles: [],
      repointed: [],
      projectLevel: [],
    });

    expect(await protectOutput()).toContain('      "\\"X\\\\u001b[2J_TOKEN\\"" (encrypted)');
  });

  it('writes a control character in a key named by an injection warning as an escape', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      clientsScanned: 1,
      secretsFound: 1,
      serversProtected: 1,
      servers: [{ client: 'cursor', server: 'github', secretKeys: ['GITHUB_TOKEN'] }],
      alreadyProtected: 0,
      injectionWarnings: [{ client: 'cursor', server: 'github', key: 'NOTE\x1b[2J', injectionType: 'instruction', severity: 'high' }],
      unparsed: [],
      unchecked: [],
      sharedName: [],
      refusedName: [],
      unmoved: [],
      bound: [],
      rebound: [],
      unbound: [],
      copies: [],
      copyFiles: [],
      repointed: [],
      projectLevel: [],
    });

    const output = await protectOutput();

    expect(output).not.toMatch(RAW_CONTROL);
    expect(output).toContain('    ! cursor/github -> "NOTE\\u001b[2J"');
  });

  it('names a config it could not parse beside the secrets it encrypted', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      clientsScanned: 1,
      secretsFound: 1,
      serversProtected: 1,
      servers: [{ client: 'cursor', server: 'github', secretKeys: ['GITHUB_TOKEN'] }],
      alreadyProtected: 0,
      injectionWarnings: [],
      unparsed: [{ client: 'windsurf', filePath: '/home/u/.windsurf/mcp.json', reason: 'not valid JSON (line 2, column 1)' }],
      unchecked: [],
      sharedName: [],
      refusedName: [],
      unmoved: [],
      bound: [],
      rebound: [],
      unbound: [],
      copies: [],
      copyFiles: [],
      repointed: [],
      projectLevel: [],
    });

    const output = await protectOutput();

    expect(output).toContain('1 secret(s) encrypted across 1 server(s).');
    expect(output).toContain('  windsurf (/home/u/.windsurf/mcp.json)\n    ? not checked: not valid JSON (line 2, column 1)');
    expect(output).toContain('1 config(s) could not be parsed, so the servers in them were not checked.');
    expect(output).toContain(`Fix the file(s) above, then run \`${sourceCommand('protect-mcp')}\` again.`);
  });

  it('names the part of a server it could not read after the secrets it did encrypt', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      clientsScanned: 1,
      secretsFound: 1,
      serversProtected: 1,
      servers: [{ client: 'cursor', server: 'gh', secretKeys: ['GITHUB_TOKEN'] }],
      alreadyProtected: 0,
      injectionWarnings: [],
      unparsed: [],
      unchecked: [
        {
          client: 'cursor',
          filePath: '/home/u/.cursor/mcp.json',
          servers: [{ name: 'gh', part: 'env value API_TOKEN', reason: 'not a string' }],
        },
      ],
      sharedName: [],
      refusedName: [],
      unmoved: [],
      bound: [],
      rebound: [],
      unbound: [],
      copies: [],
      copyFiles: [],
      repointed: [],
      projectLevel: [],
    });

    const output = await protectOutput();

    expect(output).toContain('1 secret(s) encrypted across 1 server(s).');
    expect(output).toContain('  cursor (/home/u/.cursor/mcp.json)\n    ? gh: env value API_TOKEN not checked: not a string');
    expect(output).toContain('1 server(s) have a part that could not be read, so it was not checked for secrets.');
  });

  it('lists each server with a part it could not read under its config, with the name escaped', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      clientsScanned: 2,
      secretsFound: 0,
      serversProtected: 0,
      servers: [],
      alreadyProtected: 0,
      injectionWarnings: [],
      unparsed: [],
      unchecked: [
        {
          client: 'cursor',
          filePath: '/home/u/.cursor/mcp.json',
          servers: [
            { name: 'gh', part: 'env', reason: 'not a JSON object' },
            { name: 'db\x1b[2J', part: 'entry', reason: 'not a JSON object' },
          ],
        },
        {
          client: 'vscode',
          filePath: '/home/u/.vscode/mcp.json',
          servers: [{ name: 'api', part: 'env values PORT, FLAGS', reason: 'not strings' }],
        },
      ],
      sharedName: [],
      refusedName: [],
      unmoved: [],
      bound: [],
      rebound: [],
      unbound: [],
      copies: [],
      copyFiles: [],
      repointed: [],
      projectLevel: [],
    });

    const output = await protectOutput();

    expect(output).not.toMatch(RAW_CONTROL);
    expect(output).not.toContain('Already clean.');
    expect(output).toContain('No plaintext secrets found in the parts of the MCP configs that were read.');
    expect(output).toContain(
      '  cursor (/home/u/.cursor/mcp.json)\n    ? gh: env not checked: not a JSON object\n    ? "db\\u001b[2J": entry not checked: not a JSON object',
    );
    expect(output).toContain('  vscode (/home/u/.vscode/mcp.json)\n    ? api: env values PORT, FLAGS not checked: not strings');
    expect(output).toContain('3 server(s) have a part that could not be read, so it was not checked for secrets.');
    expect(output).toContain(`Fix the entries above, then run \`${sourceCommand('protect-mcp')}\` again.`);
  });

  it('writes a control character in the key of a refused value as an escape on every line', async () => {
    vi.mocked(protectMcp).mockRejectedValue(
      unstorableMcpSecretError('claude-code', 'demo', 'X\x1b[2J_TOKEN', findSecretValueProblem('\x1b')!),
    );
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });

    expect(await runProtectMcp([])).toBe(1);

    const output = out.join('\n');
    expect(output).not.toMatch(RAW_CONTROL);
    expect(output).toContain('"X\\u001b[2J_TOKEN" for MCP server claude-code/demo was not stored');
    expect(output).toContain('  Fix:     correct "X\\u001b[2J_TOKEN" in the "demo" env block of that file,');
  });
});

describe('protect-mcp names where it looked, and each project-level config it left as it is', () => {
  afterEach(() => vi.restoreAllMocks());

  const nothingFound: ProtectResult = {
    clientsScanned: 0,
    secretsFound: 0,
    serversProtected: 0,
    servers: [],
    alreadyProtected: 0,
    injectionWarnings: [],
    unparsed: [],
    unchecked: [],
    sharedName: [],
    refusedName: [],
    unmoved: [],
    bound: [],
    rebound: [],
    unbound: [],
    copies: [],
    copyFiles: [],
    repointed: [],
    projectLevel: [],
  };

  it('lists every path in the discovery list, home paths with ~, then says no config was found', async () => {
    vi.mocked(protectMcp).mockResolvedValue(nothingFound);

    const output = await protectOutput();

    const looked = mcpConfigLocations().map(
      (l) => `    ${l.scope === 'home' ? path.join('~', l.relativePath) : l.relativePath}`,
    );
    expect(looked).toContain(`    ${path.join('~', '.cursor', 'mcp.json')}`);
    expect(looked).toContain(`    ${path.join('.cursor', 'mcp.json')}`);
    expect(looked).toContain(`    ${path.join('.vscode', 'mcp.json')}`);
    expect(looked).toContain('    mcp.json');
    expect(output).toContain(['  Looked in:', ...looked, '', '  No MCP configurations found.'].join('\n'));
    expect(output.trimEnd().endsWith('  No MCP configurations found.')).toBe(true);
    expect(output).not.toContain('Looked for configs from');
  });

  it('names each project-level config it left by its path from the project, instead of "No MCP configurations found."', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      ...nothingFound,
      bound: [],
      rebound: [],
      unbound: [],
      copies: [],
      copyFiles: [],
      repointed: [],
      projectLevel: [
        { client: 'cursor', filePath: '/home/u/proj/.cursor/mcp.json', projectPath: '.cursor/mcp.json' },
        { client: 'unknown', filePath: '/home/u/proj/mcp.json', projectPath: 'mcp.json' },
      ],
    });

    const output = await protectOutput();

    expect(output).not.toContain('No MCP configurations found.');
    expect(output).toContain('  cursor (.cursor/mcp.json)\n    ? not checked: project-level config: see mcp-status');
    expect(output).toContain('\n  mcp.json\n    ? not checked: project-level config: see mcp-status');
    expect(output).toContain('2 project-level config(s) were not checked, so no secret in them was encrypted.');
    expect(output).toContain("protect-mcp would write this machine's wrapper path into them, and these files are usually committed.");
    expect(output).toContain(`Run \`${sourceCommand('mcp-status')}\` to list their servers.`);
    expect(output).not.toContain('/home/u/proj');
  });

  it('does not call the configs clean when it left a project-level config', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      ...nothingFound,
      clientsScanned: 1,
      bound: [],
      rebound: [],
      unbound: [],
      copies: [],
      copyFiles: [],
      repointed: [],
      projectLevel: [{ client: 'vscode', filePath: '/home/u/proj/.vscode/mcp.json', projectPath: '.vscode/mcp.json' }],
    });

    const output = await protectOutput();

    expect(output).toContain('Scanned 1 client(s)');
    expect(output).not.toContain('Already clean.');
    expect(output).toContain('No plaintext secrets found in the MCP configs that were checked.');
    expect(output).toContain('  vscode (.vscode/mcp.json)\n    ? not checked: project-level config: see mcp-status');
  });

  it('names a project-level config it left after the secrets it encrypted', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      ...nothingFound,
      clientsScanned: 1,
      secretsFound: 1,
      serversProtected: 1,
      servers: [{ client: 'claude-code', server: 'slack', secretKeys: ['SLACK_BOT_TOKEN'] }],
      bound: [],
      rebound: [],
      unbound: [],
      copies: [],
      copyFiles: [],
      repointed: [],
      projectLevel: [{ client: 'cursor', filePath: '/home/u/proj/.cursor/mcp.json', projectPath: '.cursor/mcp.json' }],
    });

    const output = await protectOutput();

    expect(output).toContain('1 secret(s) encrypted across 1 server(s).');
    expect(output).toContain('  cursor (.cursor/mcp.json)\n    ? not checked: project-level config: see mcp-status');
    expect(output).toContain('1 project-level config(s) were not checked, so no secret in them was encrypted.');
  });
});

describe('protect-mcp over the server maps of ~/.claude.json (#470)', () => {
  afterEach(() => vi.restoreAllMocks());

  const base: ProtectResult = {
    clientsScanned: 2,
    secretsFound: 0,
    serversProtected: 0,
    servers: [],
    alreadyProtected: 0,
    injectionWarnings: [],
    unparsed: [],
    unchecked: [],
    sharedName: [],
    refusedName: [],
    unmoved: [],
    bound: [],
    rebound: [],
    unbound: [],
    copies: [],
    copyFiles: [],
    repointed: [],
    projectLevel: [],
  };
  const claudeJson = '/home/u/.claude.json';

  it('names each server it left because its name is taken, under its config, with the config of the protected server', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      ...base,
      secretsFound: 1,
      serversProtected: 1,
      servers: [{ client: 'claude-code', server: 'github', secretKeys: ['GITHUB_TOKEN'] }],
      sharedName: [
        { client: 'claude-code', filePath: claudeJson, projectKey: '/work/app', server: 'github', protectedIn: { filePath: claudeJson } },
        { client: 'claude-code', filePath: '/home/u/proj/.mcp.json', projectPath: '.mcp.json', server: 'github', protectedIn: { filePath: claudeJson } },
      ],
    });

    const output = await protectOutput();

    expect(output).toContain('1 secret(s) encrypted across 1 server(s).');
    expect(output).toContain([
      '  claude-code (/home/u/.claude.json, project /work/app)',
      '    ? github: not protected: its name is taken by a protected server in claude-code (/home/u/.claude.json)',
      '',
      '  claude-code (.mcp.json)',
      '    ? github: not protected: its name is taken by a protected server in claude-code (/home/u/.claude.json)',
      '',
      '  2 server(s) were not protected, so their secrets are still in plaintext.',
      '  Secrets are stored under the client and server name, and a protected server reads its secrets by that name.',
      `  Rename each server listed above, then run \`${sourceCommand('protect-mcp')}\` again.`,
    ].join('\n'));
  });

  it('does not call the configs clean when the only server with secrets was left because its name is taken', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      ...base,
      alreadyProtected: 1,
      sharedName: [
        { client: 'claude-code', filePath: claudeJson, projectKey: '/work/app', server: 'github', protectedIn: { filePath: claudeJson } },
      ],
    });

    const output = await protectOutput();

    expect(output).toContain('  Scanned 2 client(s)\n');
    expect(output).toContain('  No plaintext secrets were encrypted.\n');
    expect(output).not.toContain('No plaintext secrets found');
    expect(output).not.toContain('Already clean.');
    expect(output).toContain('  1 server(s) were not protected, so their secrets are still in plaintext.');
  });

  it('names the project of a server map it could not read in full, with a control character in its path escaped', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      ...base,
      unchecked: [{
        client: 'claude-code',
        filePath: claudeJson,
        projectKey: '/work/a\x1b[2Jpp',
        servers: [{ name: 'slack', part: 'entry', reason: 'not a JSON object' }],
      }],
    });

    const output = await protectOutput();

    expect(output).not.toMatch(RAW_CONTROL);
    expect(output).toContain('  claude-code (/home/u/.claude.json, project "/work/a\\u001b[2Jpp")\n    ? slack: entry not checked: not a JSON object');
  });
});

describe('protect-mcp names each server that runs through the wrapper with secrets it left in its env (#508)', () => {
  afterEach(() => vi.restoreAllMocks());

  const base: ProtectResult = {
    clientsScanned: 1,
    secretsFound: 0,
    serversProtected: 0,
    servers: [],
    alreadyProtected: 0,
    injectionWarnings: [],
    unparsed: [],
    unchecked: [],
    sharedName: [],
    refusedName: [],
    unmoved: [],
    bound: [],
    rebound: [],
    unbound: [],
    copies: [],
    copyFiles: [],
    repointed: [],
    projectLevel: [],
  };
  const cursorJson = '/home/u/.cursor/mcp.json';

  it('lists each one under its config with why, then what to do, and does not call the configs clean', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      ...base,
      unmoved: [
        { client: 'cursor', filePath: cursorJson, server: 'github', reason: 'its --backend argument is "1password", and this run stores in local' },
        { client: 'cursor', filePath: cursorJson, server: 'gh\x1b[2J', reason: 'another protected server reads its secrets by the same name, cursor/github' },
      ],
    });

    const output = await protectOutput();

    expect(output).not.toMatch(RAW_CONTROL);
    expect(output).toContain('  No plaintext secrets were encrypted.\n');
    expect(output).not.toContain('No plaintext secrets found');
    expect(output).not.toContain('Already clean.');
    expect(output).toContain([
      '  cursor (/home/u/.cursor/mcp.json)',
      '    ? github: secrets not moved: its --backend argument is "1password", and this run stores in local',
      '    ? "gh\\u001b[2J": secrets not moved: another protected server reads its secrets by the same name, cursor/github',
      '',
      '  2 server(s) have secrets in plaintext in their env that were not encrypted.',
      `  Move each value out of its file and rotate it, then run \`${sourceCommand('mcp-status')}\` again.`,
    ].join('\n'));
  });

  it('names them after the secrets it did encrypt', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      ...base,
      secretsFound: 1,
      serversProtected: 1,
      servers: [{ client: 'cursor', server: 'slack', secretKeys: ['SLACK_BOT_TOKEN'] }],
      unmoved: [{ client: 'cursor', filePath: cursorJson, server: 'github', reason: 'its --backend argument is "1password", and this run stores in local' }],
    });

    const output = await protectOutput();

    expect(output).toContain('1 secret(s) encrypted across 1 server(s).');
    expect(output).toContain('  cursor (/home/u/.cursor/mcp.json)\n    ? github: secrets not moved: its --backend argument is "1password", and this run stores in local');
    expect(output).toContain('  1 server(s) have secrets in plaintext in their env that were not encrypted.');
  });

  it('lists a server not yet wrapped, left because its name holds stored secrets, without saying it runs through the wrapper', async () => {
    vi.mocked(protectMcp).mockResolvedValue({
      ...base,
      unmoved: [{ client: 'cursor', filePath: cursorJson, server: 'github', reason: 'OTHER_API_KEY is stored under cursor/github and is not in its env' }],
    });

    const output = await protectOutput();

    expect(output).toContain('  No plaintext secrets were encrypted.\n');
    expect(output).not.toContain('Already clean.');
    expect(output).toContain([
      '  cursor (/home/u/.cursor/mcp.json)',
      '    ? github: secrets not moved: OTHER_API_KEY is stored under cursor/github and is not in its env',
      '',
      '  1 server(s) have secrets in plaintext in their env that were not encrypted.',
    ].join('\n'));
    expect(output).not.toContain('run through the wrapper');
  });
});
