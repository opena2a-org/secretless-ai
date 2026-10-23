import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { protectMcp, type ProtectResult } from './protect';
import { McpVault } from './vault';

// protect-mcp stores a server's secrets under a client/server name, and the
// wrapper gives a server every secret stored under the name it reads by. These
// tests pin which names a server's secrets are stored under: one no other
// protected server reads, in any config protect-mcp reads; never one where a
// stored value would be replaced; for a server that does not yet run through
// the wrapper, one that holds no stored secret or only its own; and for a
// value from a project-level config, the project's .mcp.json included, one
// that holds no stored secret. A server left is listed with a reason that
// names the client/server name and the stored env names, never a value.

const wrapperPath = '/usr/local/bin/secretless-mcp';

// Values are assembled when the test runs, so the file holds no credential-shaped literal.
const value = (label: string): string => ['FAKE', 'pair', 'source', label].join('-');

const projectRule = 'a value from a project-level config is stored only under a name that holds no stored secret';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-pair-sources-'));
}

describe('protectMcp stores a server\'s secrets only under a name no other server reads and never into another config\'s stored name', () => {
  let homeDir: string;
  let dataDir: string;
  let projectDir: string;
  let savedHome: string | undefined;

  beforeEach(() => {
    homeDir = tmpDir();
    dataDir = tmpDir();
    projectDir = tmpDir();
    // The configured backend is read from HOME: this home configures none.
    savedHome = process.env.HOME;
    process.env.HOME = homeDir;
  });
  afterEach(() => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    for (const dir of [homeDir, dataDir, projectDir]) fs.rmSync(dir, { recursive: true, force: true });
  });

  const protect = (): Promise<ProtectResult> => protectMcp({ homeDir, dataDir, projectDir, wrapperPath, backendType: 'local' });
  // The store protectMcp builds for a run given homeDir: the encrypted file under dataDir, keyed by homeDir.
  const vault = (): McpVault => new McpVault({
    storeDir: path.join(dataDir, 'mcp-vault'),
    key: `${homeDir}-secretless-mcp-${process.env.USER ?? 'default'}`,
    backendType: 'local',
  });
  const plain = (env: Record<string, string>) => ({ command: 'npx', args: ['some-mcp'], env });
  const wrapped = (client: string, server: string, env: Record<string, string>) => ({
    command: wrapperPath,
    args: ['--server', server, '--client', client, '--', 'npx', 'some-mcp'],
    env,
  });
  /** Writes a config under `base`, and returns its path and the content written. */
  const write = (base: string, relativePath: string, servers: Record<string, unknown>, mapKey = 'mcpServers') => {
    const filePath = path.join(base, relativePath);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const content = JSON.stringify({ [mapKey]: servers });
    fs.writeFileSync(filePath, content);
    return { filePath, content };
  };
  const read = (filePath: string): string => fs.readFileSync(filePath, 'utf-8');
  const homeCursor = path.join('.cursor', 'mcp.json');
  /** What protectMcp returns names env names and client/server names, never a value. */
  const expectNoValue = (result: ProtectResult, values: string[]): void => {
    const returned = JSON.stringify(result);
    for (const v of values) expect(returned).not.toContain(v);
  };

  describe('a protected server in a project-level config that protect-mcp does not rewrite reads the name', () => {
    it.each([
      [path.join('.cursor', 'mcp.json'), 'mcpServers'],
      [path.join('.vscode', 'mcp.json'), 'servers'],
      ['mcp.json', 'mcpServers'],
    ])('leaves a home server not yet wrapped as it is, names %s as where the name is read, and stores nothing under it', async (projectPath, mapKey) => {
      const home = write(homeDir, homeCursor, { github: plain({ GITHUB_TOKEN: value('home') }) });
      const project = write(projectDir, projectPath, { repoTool: wrapped('cursor', 'github', {}) }, mapKey);

      const result = await protect();

      expect(result.servers).toEqual([]);
      expect(result.secretsFound).toBe(0);
      expect(result.sharedName).toEqual([{
        client: 'cursor',
        filePath: home.filePath,
        server: 'github',
        protectedIn: { filePath: project.filePath, projectPath },
      }]);
      expect(result.unmoved).toEqual([]);
      expect(read(home.filePath)).toBe(home.content);
      expect(read(project.filePath)).toBe(project.content);
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({});
      expectNoValue(result, [value('home')]);
    });

    it('CONTROL: stores the home server when the project-level server reads another name', async () => {
      const home = write(homeDir, homeCursor, { github: plain({ GITHUB_TOKEN: value('home') }) });
      write(projectDir, path.join('.cursor', 'mcp.json'), { repoTool: wrapped('cursor', 'gitlab', {}) });

      const result = await protect();

      expect(result.servers).toEqual([{ client: 'cursor', server: 'github', secretKeys: ['GITHUB_TOKEN'] }]);
      expect(result.sharedName).toEqual([]);
      expect(result.unmoved).toEqual([]);
      expect(JSON.parse(read(home.filePath)).mcpServers.github.env).not.toHaveProperty('GITHUB_TOKEN');
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: value('home') });
    });
  });

  describe('a home server not yet wrapped, whose name holds stored secrets', () => {
    it('leaves it, and the store as it is, when an env name of its own is stored there with another value', async () => {
      await vault().storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: value('stored') });
      const home = write(homeDir, homeCursor, { github: plain({ GITHUB_TOKEN: value('home') }) });

      const result = await protect();

      expect(result.servers).toEqual([]);
      expect(result.secretsFound).toBe(0);
      expect(result.sharedName).toEqual([]);
      expect(result.unmoved).toEqual([{
        client: 'cursor',
        filePath: home.filePath,
        server: 'github',
        reason: 'GITHUB_TOKEN is stored under cursor/github with another value',
      }]);
      expect(read(home.filePath)).toBe(home.content);
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: value('stored') });
      expectNoValue(result, [value('stored'), value('home')]);
    });

    it('leaves it, and the store as it is, when an env name it does not have is stored there', async () => {
      await vault().storeServerSecrets('cursor', 'github', { OTHER_API_KEY: value('stored') });
      const home = write(homeDir, homeCursor, { github: plain({ GITHUB_TOKEN: value('home') }) });

      const result = await protect();

      expect(result.servers).toEqual([]);
      expect(result.secretsFound).toBe(0);
      expect(result.unmoved).toEqual([{
        client: 'cursor',
        filePath: home.filePath,
        server: 'github',
        reason: 'OTHER_API_KEY is stored under cursor/github and is not in its env',
      }]);
      expect(read(home.filePath)).toBe(home.content);
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ OTHER_API_KEY: value('stored') });
      expectNoValue(result, [value('stored'), value('home')]);
    });

    it('names every stored env name that is not its own, and none that is', async () => {
      await vault().storeServerSecrets('cursor', 'github', {
        GITHUB_TOKEN: value('home'),
        MY_SERVICE_API_KEY: value('stored-1'),
        OTHER_API_KEY: value('stored-2'),
        THIRD_API_KEY: value('stored-3'),
      });
      const home = write(homeDir, homeCursor, {
        github: plain({ GITHUB_TOKEN: value('home'), MY_SERVICE_API_KEY: value('home-1') }),
      });

      const result = await protect();

      expect(result.unmoved.map((server) => server.reason)).toEqual([
        'MY_SERVICE_API_KEY is stored under cursor/github with another value, and OTHER_API_KEY, THIRD_API_KEY are stored there and are not in its env',
      ]);
      expect(read(home.filePath)).toBe(home.content);
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({
        GITHUB_TOKEN: value('home'),
        MY_SERVICE_API_KEY: value('stored-1'),
        OTHER_API_KEY: value('stored-2'),
        THIRD_API_KEY: value('stored-3'),
      });
      expectNoValue(result, [value('home'), value('home-1'), value('stored-1'), value('stored-2'), value('stored-3')]);
    });
  });

  describe('a server in the project\'s .mcp.json, whose name holds a stored secret', () => {
    it('leaves a wrapped one with a new env name, and the store as it is', async () => {
      await vault().storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: value('stored') });
      const project = write(projectDir, '.mcp.json', { github: wrapped('cursor', 'github', { NEW_API_KEY: value('project') }) });

      const result = await protect();

      expect(result.servers).toEqual([]);
      expect(result.secretsFound).toBe(0);
      expect(result.unmoved).toEqual([{
        client: 'claude-code',
        filePath: project.filePath,
        projectPath: '.mcp.json',
        server: 'github',
        reason: `GITHUB_TOKEN is stored under cursor/github, and ${projectRule}`,
      }]);
      expect(read(project.filePath)).toBe(project.content);
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: value('stored') });
      expectNoValue(result, [value('stored'), value('project')]);
    });

    it('leaves a wrapped one whose env holds the stored env name with the stored value', async () => {
      await vault().storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: value('stored') });
      const project = write(projectDir, '.mcp.json', { github: wrapped('cursor', 'github', { GITHUB_TOKEN: value('stored') }) });

      const result = await protect();

      expect(result.servers).toEqual([]);
      expect(result.unmoved.map((server) => server.reason)).toEqual([`GITHUB_TOKEN is stored under cursor/github, and ${projectRule}`]);
      expect(read(project.filePath)).toBe(project.content);
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: value('stored') });
    });

    it.each([
      ['its stored env name with another value', { GITHUB_TOKEN: value('project') }],
      ['an env name not stored there', { OTHER_API_KEY: value('project') }],
      ['its stored env name with the stored value', { GITHUB_TOKEN: value('stored') }],
    ])('leaves one not yet wrapped that holds %s, and the store as it is', async (_holds, env) => {
      await vault().storeServerSecrets('claude-code', 'github', { GITHUB_TOKEN: value('stored') });
      const project = write(projectDir, '.mcp.json', { github: plain(env) });

      const result = await protect();

      expect(result.servers).toEqual([]);
      expect(result.secretsFound).toBe(0);
      expect(result.sharedName).toEqual([]);
      expect(result.unmoved).toEqual([{
        client: 'claude-code',
        filePath: project.filePath,
        projectPath: '.mcp.json',
        server: 'github',
        reason: `GITHUB_TOKEN is stored under claude-code/github, and ${projectRule}`,
      }]);
      expect(read(project.filePath)).toBe(project.content);
      expect(await vault().getServerSecrets('claude-code', 'github')).toEqual({ GITHUB_TOKEN: value('stored') });
      expectNoValue(result, [value('stored'), value('project')]);
    });

    it('CONTROL: stores one not yet wrapped when its name holds no stored secret, and rewrites the file', async () => {
      const project = write(projectDir, '.mcp.json', { github: plain({ GITHUB_TOKEN: value('project') }) });

      const result = await protect();

      expect(result.servers).toEqual([{ client: 'claude-code', server: 'github', secretKeys: ['GITHUB_TOKEN'] }]);
      expect(result.unmoved).toEqual([]);
      expect(JSON.parse(read(project.filePath)).mcpServers.github.env).not.toHaveProperty('GITHUB_TOKEN');
      expect(await vault().getServerSecrets('claude-code', 'github')).toEqual({ GITHUB_TOKEN: value('project') });
    });

    it('CONTROL: stores a wrapped one when its name holds no stored secret', async () => {
      const project = write(projectDir, '.mcp.json', { github: wrapped('claude-code', 'github', { NEW_API_KEY: value('project') }) });

      const result = await protect();

      expect(result.servers).toEqual([{ client: 'claude-code', server: 'github', secretKeys: ['NEW_API_KEY'] }]);
      expect(result.unmoved).toEqual([]);
      expect(JSON.parse(read(project.filePath)).mcpServers.github.env).toEqual({});
      expect(await vault().getServerSecrets('claude-code', 'github')).toEqual({ NEW_API_KEY: value('project') });
    });
  });

  describe('CONTROL: what protect-mcp stores as before', () => {
    it('stores a home server not yet wrapped under a name that holds no stored secret', async () => {
      const home = write(homeDir, homeCursor, { github: plain({ GITHUB_TOKEN: value('home'), LOG_LEVEL: 'debug' }) });

      const result = await protect();

      expect(result.servers).toEqual([{ client: 'cursor', server: 'github', secretKeys: ['GITHUB_TOKEN'] }]);
      expect(result.sharedName).toEqual([]);
      expect(result.unmoved).toEqual([]);
      const config = JSON.parse(read(home.filePath));
      expect(config.mcpServers.github.command).toBe(wrapperPath);
      expect(config.mcpServers.github.env).toEqual({ LOG_LEVEL: 'debug' });
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: value('home') });
    });

    it('stores a new env name of a home wrapped server beside the secrets stored under its own name', async () => {
      await vault().storeServerSecrets('cursor', 'github', { GITHUB_TOKEN: value('stored') });
      const home = write(homeDir, homeCursor, { github: wrapped('cursor', 'github', { MY_SERVICE_API_KEY: value('home') }) });

      const result = await protect();

      expect(result.servers).toEqual([{ client: 'cursor', server: 'github', secretKeys: ['MY_SERVICE_API_KEY'] }]);
      expect(result.unmoved).toEqual([]);
      expect(JSON.parse(read(home.filePath)).mcpServers.github.env).toEqual({});
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({
        GITHUB_TOKEN: value('stored'),
        MY_SERVICE_API_KEY: value('home'),
      });
    });

    it('stores a new env name of a wrapped server in a project map of ~/.claude.json beside the secrets stored under its name', async () => {
      await vault().storeServerSecrets('claude-code', 'github', { GITHUB_TOKEN: value('stored') });
      const configPath = path.join(homeDir, '.claude.json');
      fs.writeFileSync(configPath, JSON.stringify({
        projects: { '/work/app': { mcpServers: { github: wrapped('claude-code', 'github', { MY_SERVICE_API_KEY: value('home') }) } } },
      }));

      const result = await protect();

      expect(result.servers).toEqual([{ client: 'claude-code', server: 'github', secretKeys: ['MY_SERVICE_API_KEY'] }]);
      expect(result.unmoved).toEqual([]);
      expect(await vault().getServerSecrets('claude-code', 'github')).toEqual({
        GITHUB_TOKEN: value('stored'),
        MY_SERVICE_API_KEY: value('home'),
      });
    });

    it('changes nothing and leaves no server on a re-run, and stores no other value when the values in the env are the ones stored', async () => {
      const home = write(homeDir, homeCursor, { github: plain({ GITHUB_TOKEN: value('home') }) });
      await protect();
      const rewritten = read(home.filePath);
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: value('home') });

      // The second run finds the server wrapped, with no secret in its env.
      const second = await protect();

      expect(second.alreadyProtected).toBe(1);
      expect(second.secretsFound).toBe(0);
      expect(second.sharedName).toEqual([]);
      expect(second.unmoved).toEqual([]);
      expect(read(home.filePath)).toBe(rewritten);
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: value('home') });

      // The file as it was before the first run: its env holds the stored values.
      fs.writeFileSync(home.filePath, home.content);
      const third = await protect();

      expect(third.servers).toEqual([{ client: 'cursor', server: 'github', secretKeys: ['GITHUB_TOKEN'] }]);
      expect(third.sharedName).toEqual([]);
      expect(third.unmoved).toEqual([]);
      expect(await vault().getServerSecrets('cursor', 'github')).toEqual({ GITHUB_TOKEN: value('home') });
    });
  });
});
