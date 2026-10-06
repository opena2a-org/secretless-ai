import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as http from 'http';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BrokerServer } from './server';
import type { CredentialResolver } from './resolver';

/**
 * POST /resolve refuses a body that repeats a member name, the same as /grant
 * and the policy file. Before this, the body went straight to JSON.parse, which
 * keeps the last copy of a repeated member, so the broker acted on one half of
 * the request without anything saying there had been two.
 */

const FAKE_VALUE = 'FAKE-resolve-test-value';

function post(
  socketPath: string,
  token: string,
  body: string,
): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    // Sent verbatim: JSON.stringify would collapse the duplicate under test.
    const req = http.request(
      {
        socketPath,
        path: '/resolve',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          Authorization: `Bearer ${token}`,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf-8');
          let json: unknown;
          try { json = JSON.parse(text); } catch { json = undefined; }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function fakeResolver(): CredentialResolver {
  return { resolve: async () => FAKE_VALUE } as unknown as CredentialResolver;
}

describe('POST /resolve refuses a duplicated member name', () => {
  let tmpDir: string;
  let socketPath: string;
  let tokenPath: string;
  let server: BrokerServer;
  let token: string;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'resolve-dup-'));
    socketPath = path.join(tmpDir, 'broker.sock');
    tokenPath = path.join(tmpDir, 'broker.token');
    const policyFile = path.join(tmpDir, 'broker-policies.json');
    fs.writeFileSync(policyFile, JSON.stringify({
      rules: [{
        id: 'allow-test-key',
        agentSelector: 'agent-a',
        credentialSelector: 'TEST_KEY',
        constraints: {},
        effect: 'allow',
      }],
    }));
    server = new BrokerServer(
      { socketPath, httpPort: 0, auditLog: path.join(tmpDir, 'audit.log'), tokenFile: tokenPath, policyFile },
      { aimClient: null, resolver: fakeResolver() },
    );
    await server.start();
    token = fs.readFileSync(tokenPath, 'utf-8');
  });

  afterEach(async () => {
    await server.stop();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('serves the credential for a clean body (control)', async () => {
    const res = await post(socketPath, token, '{"agentId":"agent-a","credentialName":"TEST_KEY"}');
    expect(res.status).toBe(200);
    expect(res.json.value).toBe(FAKE_VALUE);
  });

  it('refuses an exact repeat of credentialName instead of serving the last copy', async () => {
    const res = await post(
      socketPath,
      token,
      '{"agentId":"agent-a","credentialName":"OTHER_KEY","credentialName":"TEST_KEY"}',
    );
    expect(res.status).toBe(400);
    expect(res.json.error).toContain('Duplicate member "credentialName"');
    expect(res.json.value).toBeUndefined();
  });

  it('refuses a case variant of a member name', async () => {
    const res = await post(
      socketPath,
      token,
      '{"AGENTID":"someone-else","agentId":"agent-a","credentialName":"TEST_KEY"}',
    );
    expect(res.status).toBe(400);
    expect(res.json.error).toContain('Duplicate member "agentId"');
  });

  it('still answers malformed JSON with Invalid JSON', async () => {
    const res = await post(socketPath, token, '{"agentId":"agent-a",');
    expect(res.status).toBe(400);
    expect(res.json.error).toBe('Invalid JSON');
  });
});

/**
 * A scanner that will not load must withhold, not wave the body through to a
 * bare JSON.parse. No policy file here, so the broker starts without loading
 * the scanner and the refusal can only come from /resolve itself.
 */
describe('POST /resolve withholds when the duplicate-member scanner will not load', () => {
  let tmpDir: string;

  afterEach(() => {
    vi.resetModules();
    vi.doUnmock('@opena2a/atx-verify');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('answers 503 and records the cause in the audit log', async () => {
    vi.resetModules();
    vi.doMock('@opena2a/atx-verify', () => {
      throw new Error("Cannot find module '@opena2a/atx-verify'");
    });
    const { BrokerServer: FreshServer } = await import('./server');

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'resolve-noscan-'));
    const socketPath = path.join(tmpDir, 'broker.sock');
    const tokenPath = path.join(tmpDir, 'broker.token');
    const auditLog = path.join(tmpDir, 'audit.log');
    const server = new FreshServer(
      {
        socketPath,
        httpPort: 0,
        auditLog,
        tokenFile: tokenPath,
        policyFile: path.join(tmpDir, 'absent-policies.json'),
      },
      { aimClient: null, resolver: fakeResolver() },
    );
    await server.start();
    try {
      const token = fs.readFileSync(tokenPath, 'utf-8');
      const res = await post(socketPath, token, '{"agentId":"agent-a","credentialName":"TEST_KEY"}');
      expect(res.status).toBe(503);
      expect(res.json.value).toBeUndefined();
      expect(fs.readFileSync(auditLog, 'utf-8')).toMatch(/failed to load/);
    } finally {
      await server.stop();
    }
  });
});
