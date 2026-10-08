import { describe, it, expect, vi, afterEach } from 'vitest';

vi.mock('../mcp/protect', () => ({ protectMcp: vi.fn() }));

import { protectMcp } from '../mcp/protect';
import { runProtectMcp } from './mcp';
import { findSecretValueProblem, unstorableMcpSecretError } from '../secret-value';

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
    });

    const output = await protectOutput();

    expect(output).toContain('1 secret(s) encrypted across 1 server(s).');
    expect(output).toContain('  windsurf (/home/u/.windsurf/mcp.json)\n    ? not checked: not valid JSON (line 2, column 1)');
    expect(output).toContain('1 config(s) could not be parsed, so the servers in them were not checked.');
    expect(output).toContain('Fix the file(s) above, then run `npx secretless-ai protect-mcp` again.');
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
