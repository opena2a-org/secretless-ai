import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { discoverMcpConfigsDetailed, runsThroughSecretlessWrapper, thisBuildWrapperPath } from './discover';
import { rewriteConfig } from './rewrite';

/**
 * Which entries run through a secretless wrapper, decided by one function
 * that discovery and protect-mcp's rewrite both call.
 *
 * Values are assembled at run time and are not credentials.
 */

const NAME = ['MY', 'SERVICE', 'API', 'KEY'].join('_');
const VALUE = ['stand', 'in', 'value', String(process.pid)].join('-');

let home: string;
let project: string;
let bin: string;
let saved: Record<'HOME' | 'USER' | 'PATH', string | undefined>;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-repoint-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-repoint-proj-'));
  bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-repoint-bin-'));
  // Never run: a keychain backend is not built where `local` is configured.
  fs.writeFileSync(path.join(bin, 'secret-tool'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  // The local store's key is made from HOME and USER: this process and the
  // commands it starts get the same ones.
  saved = { HOME: process.env.HOME, USER: process.env.USER, PATH: process.env.PATH };
  process.env.HOME = home;
  delete process.env.USER;
  process.env.PATH = `${bin}${path.delimiter}${saved.PATH ?? ''}`;
  write(path.join(home, '.secretless-ai', 'config.json'), { backend: 'local' });
});

afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const d of [home, project, bin]) fs.rmSync(d, { recursive: true, force: true });
});

function write(fullPath: string, content: unknown): string {
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
  return fullPath;
}

/** This build's wrapper as a module in src/mcp or dist/mcp names it. */
const THIS_BUILD = path.resolve(__dirname, '..', 'mcp-wrapper.js');

/** Each command form, by server name, and whether it runs through a secretless wrapper. */
const FORMS: Array<{ server: string; command: string; wrapped: boolean }> = [
  { server: 'bare', command: 'secretless-mcp', wrapped: true },
  { server: 'binPath', command: '/usr/local/bin/secretless-mcp', wrapped: true },
  { server: 'otherBuild', command: '/opt/secretless-ai-old/dist/mcp-wrapper.js', wrapped: true },
  { server: 'installedCopy', command: '/home/someone/.secretless-ai/bin/mcp-wrapper.js', wrapped: true },
  { server: 'thisBuild', command: THIS_BUILD, wrapped: true },
  { server: 'node', command: process.execPath, wrapped: false },
  { server: 'npx', command: 'npx', wrapped: false },
  { server: 'otherWrapper', command: '/opt/tools/mcp-wrapper.js', wrapped: false },
  { server: 'otherScript', command: '/opt/secretless-tools/server.js', wrapped: false },
  { server: 'empty', command: '', wrapped: false },
];

describe('one function decides that an entry runs through a secretless wrapper', () => {
  it('p1: it accepts the bare name, a path ending /secretless-mcp, this build\'s wrapper and any secretless mcp-wrapper.js', () => {
    expect(thisBuildWrapperPath()).toBe(THIS_BUILD);
    for (const form of FORMS) {
      expect(runsThroughSecretlessWrapper(form.command), form.server).toBe(form.wrapped);
    }
    // The wrapper a rewrite writes counts as well, wherever it is.
    expect(runsThroughSecretlessWrapper('/opt/tools/mcp-wrapper.js', '/opt/tools/mcp-wrapper.js')).toBe(true);
    expect(runsThroughSecretlessWrapper('', '')).toBe(false);
  });

  it('p2: discovery counts an entry as wrapped exactly when protect-mcp\'s rewrite leaves its command alone', () => {
    const file = write(path.join(home, '.cursor', 'mcp.json'), {
      mcpServers: Object.fromEntries(
        FORMS.map((form) => [form.server, { command: form.command, args: ['-y', 'some-mcp'], env: { [NAME]: VALUE } }]),
      ),
    });
    const before = discoverMcpConfigsDetailed(home, project).configs.find((config) => config.filePath === file);
    expect(before).toBeDefined();
    const protectedByDiscovery = Object.fromEntries(before!.servers.map((server) => [server.name, server.alreadyProtected]));

    // Every entry is handed to the rewrite with its secret, as a direct
    // caller of rewriteConfig may hand it.
    rewriteConfig(
      file,
      'cursor',
      Object.fromEntries(FORMS.map((form) => [form.server, { [NAME]: VALUE }])),
      THIS_BUILD,
      path.join(home, '.secretless-ai', 'mcp-backups'),
    );
    const after = JSON.parse(fs.readFileSync(file, 'utf-8')).mcpServers;
    for (const form of FORMS) {
      const rewritten = after[form.server].command === THIS_BUILD && after[form.server].args[0] === '--server';
      expect(protectedByDiscovery[form.server], `discovery: ${form.server}`).toBe(form.wrapped);
      expect(rewritten, `rewrite: ${form.server}`).toBe(!form.wrapped);
    }
  });
});
