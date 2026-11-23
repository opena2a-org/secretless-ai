import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { protectMcp } from './protect';
import { McpVault } from './vault';
import { envSecretKind } from './env-secrets';

/**
 * protect-mcp moves what mcp-status counts: the literal secrets in a server's
 * env, by the shared decision (env-secrets.ts). An empty value, a whole-value
 * expansion and a placeholder stay in the env, so a server mcp-status lists
 * as clean is left as it is and nothing is stored for it.
 */
describe('protectMcp moves only the env values the shared decision calls literals', () => {
  let homeDir: string;
  let dataDir: string;
  let projectDir: string;
  const wrapperPath = '/usr/local/bin/secretless-mcp';

  beforeEach(() => {
    homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-env-kind-home-'));
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-env-kind-data-'));
    projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-env-kind-project-'));
  });
  afterEach(() => {
    for (const dir of [homeDir, dataDir, projectDir]) fs.rmSync(dir, { recursive: true, force: true });
  });

  const protect = () => protectMcp({ homeDir, dataDir, projectDir, wrapperPath, backendType: 'local' });
  const mcpJson = () => path.join(projectDir, '.mcp.json');
  const write = (content: unknown): string => {
    const text = `${JSON.stringify(content, null, 2)}\n`;
    fs.writeFileSync(mcpJson(), text);
    return text;
  };
  const stored = async (server: string) =>
    new McpVault({
      storeDir: path.join(dataDir, 'mcp-vault'),
      key: `${homeDir}-secretless-mcp-${process.env.USER ?? 'default'}`,
      backendType: 'local',
    }).getServerSecrets('claude-code', server);

  // Values under names classify.ts calls secrets, built at runtime.
  const cleanEnv: Record<string, string> = {
    GITHUB_TOKEN: '',
    OPENAI_API_KEY: ['${', 'OPENAI_API_KEY', '}'].join(''),
    ANTHROPIC_API_KEY: ['${', 'ANTHROPIC_API_KEY:-', '}'].join(''),
    SLACK_BOT_TOKEN: ['${', 'env:SLACK_BOT_TOKEN', '}'].join(''),
    STRIPE_SECRET_KEY: ['${', 'input:stripe-key', '}'].join(''),
    DATABASE_PASSWORD: ['your', '_password_', 'here'].join(''),
  };
  // A literal no credential pattern or placeholder rule reads as an example.
  const literal = ['q7Vm', 'X2pL', '9rTz', 'Kd4W', 'n8Hs', 'B3yF'].join('');

  it('the values of the clean env are not literals by the shared decision', () => {
    for (const [key, value] of Object.entries(cleanEnv)) expect(envSecretKind(key, value), key).not.toBe('literal');
    expect(envSecretKind('API_KEY', literal)).toBe('literal');
  });

  it('a server whose env holds only empty, expansion and placeholder values leaves .mcp.json unchanged and stores nothing', async () => {
    const before = write({ mcpServers: { svc: { command: 'npx', args: ['some-mcp'], env: cleanEnv } } });

    const result = await protect();

    expect(fs.readFileSync(mcpJson(), 'utf-8')).toBe(before);
    expect(result.secretsFound).toBe(0);
    expect(result.serversProtected).toBe(0);
    expect(result.servers).toEqual([]);
    expect(await stored('svc')).toEqual({});
  });

  it('CONTROL: a literal beside them is moved, and the others stay in the env', async () => {
    write({ mcpServers: { svc: { command: 'npx', args: ['some-mcp'], env: { ...cleanEnv, API_KEY: literal } } } });

    const result = await protect();

    expect(result.secretsFound).toBe(1);
    expect(result.servers).toEqual([{ client: 'claude-code', server: 'svc', secretKeys: ['API_KEY'] }]);
    const config = JSON.parse(fs.readFileSync(mcpJson(), 'utf-8'));
    expect(config.mcpServers.svc.command).toBe(wrapperPath);
    expect(config.mcpServers.svc.env).toEqual(cleanEnv);
    expect(await stored('svc')).toEqual({ API_KEY: literal });
  });
});
