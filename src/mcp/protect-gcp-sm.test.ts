/**
 * protect-mcp on the gcp-sm backend, over an in-memory Secret Manager project
 * that holds secrets of its own: a server's secrets are stored under a name
 * derived from its client, server and env name, and the project's other
 * secrets are neither read nor written.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { protectMcp } from './protect';
import { createBackend } from '../backends/factory';
import { GCPSecretManagerBackend } from '../backends/gcp-sm';
import { fakeSecretManager, type FakeSecretManager } from '../backends/gcp-sm-fake.test-support';

// protectMcp builds its store with createBackend. For `gcp-sm` the test hands
// it a backend for the in-memory project, with a token already in place, so no
// credential file is read and no token is requested. Every other type reaches
// the real function.
vi.mock('../backends/factory', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../backends/factory')>();
  return { ...actual, createBackend: vi.fn(actual.createBackend) };
});

const PROJECT = 'acme-mcp-census';
const WRAPPER = '/usr/local/bin/secretless-mcp';

/** A value built at run time, shaped like no provider's token. */
function placeholder(label: string): string {
  return [label, 'placeholder', crypto.randomBytes(6).toString('hex')].join('-');
}

function gcpBackendFor(project: FakeSecretManager): GCPSecretManagerBackend {
  const backend = new GCPSecretManagerBackend({ projectId: project.projectId });
  (backend as unknown as { accessToken: string }).accessToken = 'unit-test-access';
  (backend as unknown as { tokenExpiry: number }).tokenExpiry = Date.now() + 3600_000;
  return backend;
}

describe('protectMcp on the gcp-sm backend', () => {
  let homeDir: string;
  let dataDir: string;
  let project: FakeSecretManager;
  let dbPassword: string;
  let stripeKey: string;

  beforeEach(async () => {
    homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-gcp-home-'));
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-mcp-gcp-data-'));
    project = fakeSecretManager(PROJECT);
    dbPassword = placeholder('db');
    stripeKey = placeholder('stripe');
    project.put('DB_PASSWORD', dbPassword);
    project.put('STRIPE_KEY', stripeKey);
    vi.stubGlobal('fetch', vi.fn(project.fetch));
    const actual = await vi.importActual<typeof import('../backends/factory')>('../backends/factory');
    vi.mocked(createBackend).mockImplementation((type, config, strict, options) =>
      type === 'gcp-sm' ? gcpBackendFor(project) : actual.createBackend(type, config, strict, options));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.mocked(createBackend).mockReset();
    fs.rmSync(homeDir, { recursive: true, force: true });
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  it('stores the secret of a server the project holds nothing for and rewrites the server, reading no other secret', async () => {
    const token = placeholder('github');
    const configPath = path.join(homeDir, '.cursor', 'mcp.json');
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        github: { command: 'npx', args: ['@github/mcp-server'], env: { GITHUB_TOKEN: token } },
      },
    }));

    const result = await protectMcp({ homeDir, dataDir, wrapperPath: WRAPPER, backendType: 'gcp-sm' });

    expect(result.unmoved).toEqual([]);
    expect(result.servers).toEqual([{ client: 'cursor', server: 'github', secretKeys: ['GITHUB_TOKEN'] }]);
    expect(result.serversProtected).toBe(1);

    // One new secret, named after the whole key and labelled as written by
    // this tool; the project's own secrets keep the one version they had.
    expect([...project.secrets.keys()].sort()).toEqual(['DB_PASSWORD', 'STRIPE_KEY', 'mcp--cursor--github--GITHUB__TOKEN']);
    expect(project.secrets.get('mcp--cursor--github--GITHUB__TOKEN')).toEqual({
      labels: { 'secretless-ai': 'store-key' },
      versions: [token],
    });
    expect(project.secrets.get('DB_PASSWORD')!.versions).toEqual([dbPassword]);
    expect(project.secrets.get('STRIPE_KEY')!.versions).toEqual([stripeKey]);
    expect(project.valueReads).toEqual([]);

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.mcpServers.github.command).toBe(WRAPPER);
    expect(config.mcpServers.github.args).toEqual([
      '--server', 'github', '--client', 'cursor', '--backend', 'gcp-sm', '--', 'npx', '@github/mcp-server',
    ]);
    expect(config.mcpServers.github.env ?? {}).not.toHaveProperty('GITHUB_TOKEN');
  });
});
