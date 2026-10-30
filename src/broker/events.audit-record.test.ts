import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { AuditLogger } from './audit';
import { CredentialEventEmitter } from './events';
import type { AuditEntry } from './types';
import { armChannelSpies, type ChannelSpies } from './audit-record.test-support';

/**
 * The credential event emitter writes, for each event, the code of its type and never the
 * caller's reason, leak context or trigger. It writes the agent id as sent only as a DID or an
 * agent name of at most 128 bytes, and the secret reference and the policy rule id as sent only
 * when the emitter's anchor names them; any other value is written as `unparsed:<length>`. What
 * it forwards to AIM is the record it wrote, and nothing else.
 *
 * Every listener here binds 127.0.0.1.
 */

const PLANTED_AGENT = 'Planted Payee Odalys Brennecke';
const PLANTED_TEXT = 'seen in a transcript beside Kestrelmoor';
const PLANTED_CAPABILITY = 'capability Kestrelmoor';
const PLANTED_BACKEND = 'backend Kestrelmoor';

let tmpDir: string;
let logPath: string;
let logger: AuditLogger;
let spies: ChannelSpies;
/** Text the emitter must write to neither the log file nor any other channel. */
let planted: string[];

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'events-audit-record-'));
  logPath = path.join(tmpDir, 'broker-audit.log');
  logger = new AuditLogger(logPath);
  spies = armChannelSpies();
  planted = ['Odalys', 'Brennecke', 'Kestrelmoor'];
});

afterEach(() => {
  try {
    expectNoPlantedText();
  } finally {
    spies.restore();
    logger.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

/** The planted text is in neither the log file nor stdout, stderr or the console. */
function expectNoPlantedText(): void {
  const file = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf-8') : '';
  const elsewhere = spies.text();
  for (const word of planted) {
    expect(file.includes(word), 'the audit log carries planted text').toBe(false);
    expect(elsewhere.includes(word), 'planted text reached stdout, stderr or the console').toBe(false);
  }
}

function last(): AuditEntry {
  return logger.readRecent(1)[0];
}

/** The six emit methods that take an agent id, each called with planted caller text. */
function agentEmits(
  emitter: CredentialEventEmitter,
): Array<(agentId: string, secretRef: string, policyRuleId?: string) => void> {
  return [
    (agentId, secretRef) => emitter.emitRequested(agentId, secretRef, PLANTED_CAPABILITY),
    (agentId, secretRef, policyRuleId) =>
      emitter.emitGranted(agentId, secretRef, { trustScore: 0.9, ttlSeconds: 60, policyRuleId, backend: PLANTED_BACKEND }),
    (agentId, secretRef, policyRuleId) => emitter.emitDenied(agentId, secretRef, PLANTED_TEXT, { trustScore: 0.1, policyRuleId }),
    (agentId, secretRef) => emitter.emitExpired(agentId, secretRef, true),
    (agentId, secretRef) => emitter.emitRevoked(agentId, secretRef, PLANTED_TEXT),
    (agentId, secretRef) => emitter.emitLeakDetected(agentId, secretRef, PLANTED_TEXT),
  ];
}

/** All seven emit methods, by the secret reference they are called with. */
function refEmits(emitter: CredentialEventEmitter): Array<(secretRef: string) => void> {
  return [
    ...agentEmits(emitter).map((emit) => (secretRef: string) => emit('scan-01', secretRef)),
    (secretRef) => emitter.emitRotated(secretRef, PLANTED_TEXT),
  ];
}

describe('T10: a credential event is recorded by the code of its type', () => {
  it('T10: each emit method, both expired branches included, writes its code and no caller text', () => {
    const emitter = new CredentialEventEmitter(logger);
    emitter.emitRequested('agent-001', 'db-password', PLANTED_CAPABILITY);
    emitter.emitGranted('agent-001', 'db-password', { trustScore: 0.85, ttlSeconds: 300, backend: PLANTED_BACKEND });
    emitter.emitDenied('agent-001', 'db-password', `denied: ${PLANTED_TEXT}`);
    emitter.emitExpired('agent-001', 'db-password', true);
    emitter.emitExpired('agent-001', 'db-password', false);
    emitter.emitRevoked('agent-001', 'db-password', `revoked: ${PLANTED_TEXT}`);
    emitter.emitLeakDetected('agent-001', 'db-password', `leak: ${PLANTED_TEXT}`);
    emitter.emitRotated('db-password', `rotated: ${PLANTED_TEXT}`);

    expect(logger.readRecent(8).map((e) => [e.eventType, e.result, e.reason])).toEqual([
      ['credential.requested', 'allowed', 'credential-requested'],
      ['credential.granted', 'allowed', 'credential-granted'],
      ['credential.denied', 'denied', 'credential-denied'],
      ['credential.expired', 'allowed', 'credential-expired-after-use'],
      ['credential.expired', 'allowed', 'credential-expired-unused'],
      ['credential.revoked', 'denied', 'credential-revoked'],
      ['credential.leak_detected', 'denied', 'credential-leak-detected'],
      ['credential.rotated', 'allowed', 'credential-rotated'],
    ]);
    planted.push('TTL expired', 'denied:', 'revoked:', 'leak:', 'rotated:');
    expect(logger.verify()).toEqual({ valid: true, records: 8 });
  });
});

describe('T14: the emitter writes its members parsed or marked', () => {
  it('T14: agentId is written as sent only as a DID or an agent name of at most 128 bytes', () => {
    const emitter = new CredentialEventEmitter(logger);
    const name129 = 'n'.repeat(129);
    planted.push(name129);
    const cases: Array<[string, string]> = [
      ['scan-01', 'scan-01'],
      ['did:web:example.com', 'did:web:example.com'],
      ['m'.repeat(128), 'm'.repeat(128)],
      [name129, 'unparsed:129'],
      [PLANTED_AGENT, 'unparsed:30'],
    ];
    for (const [sent, written] of cases) {
      for (const emit of agentEmits(emitter)) {
        emit(sent, 'db-password');
        expect(last().agentId).toBe(written);
        expectNoPlantedText();
      }
    }
    emitter.emitRotated('db-password', PLANTED_TEXT);
    expect(last().agentId).toBe('system');
    expectNoPlantedText();
  });

  it('T14: the secret reference is written as sent only when the anchor names it', () => {
    const emitter = new CredentialEventEmitter(logger, undefined, { credentialNames: ['PLANTED_DB_PASSWORD'] });
    // Provider-token-shaped, built from fragments at run time: never a literal in this file.
    const tokenShaped = ['g', 'h', 'p', '_'].join('') + crypto.randomBytes(18).toString('hex');
    planted.push('PLANTED_OTHER', tokenShaped);
    const cases: Array<[string, string]> = [
      ['PLANTED_DB_PASSWORD', 'PLANTED_DB_PASSWORD'],
      ['PLANTED_OTHER', 'unparsed:13'],
      [tokenShaped, 'unparsed:40'],
    ];
    for (const [sent, written] of cases) {
      for (const emit of refEmits(emitter)) {
        emit(sent);
        expect(last().credentialName).toBe(written);
        expectNoPlantedText();
      }
    }
  });

  it('T14: with no anchor, every secret reference is a marker', () => {
    const emitter = new CredentialEventEmitter(logger);
    planted.push('PLANTED_DB_PASSWORD');
    for (const emit of refEmits(emitter)) {
      emit('PLANTED_DB_PASSWORD');
      expect(last().credentialName).toBe('unparsed:19');
      expectNoPlantedText();
    }
  });

  it('T14: the policy rule id is written as sent only when the anchor names it, and an absent one as empty', () => {
    const emitter = new CredentialEventEmitter(logger, undefined, { policyRuleIds: ['rule-1'] });
    planted.push('rule-9');
    const cases: Array<[string | undefined, string]> = [
      ['rule-1', 'rule-1'],
      ['rule-9', 'unparsed:6'],
      [undefined, ''],
    ];
    const [, granted, denied] = agentEmits(emitter);
    for (const [sent, written] of cases) {
      for (const emit of [granted, denied]) {
        emit('scan-01', 'db-password', sent);
        expect(last().policyId).toBe(written);
        expectNoPlantedText();
      }
    }
  });
});

describe('T15: the forward to AIM is the written record', () => {
  it('T15: every body AIM receives is the record the chain wrote for the same call, and nothing else', async () => {
    // Removed in this process only, and never read: the forward then carries no authorization.
    delete process.env.AIM_API_KEY;
    const received: Array<{ headers: http.IncomingHttpHeaders; body: string }> = [];
    let arrived: (() => void) | null = null;
    const aim = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        received.push({ headers: req.headers, body: Buffer.concat(chunks).toString('utf-8') });
        res.writeHead(204);
        res.end();
        arrived?.();
      });
    });
    await new Promise<void>((resolve) => aim.listen(0, '127.0.0.1', resolve));
    try {
      const port = (aim.address() as net.AddressInfo).port;
      const emitter = new CredentialEventEmitter(logger, `http://127.0.0.1:${port}/api/v1/audit`, {
        credentialNames: ['PLANTED_DB_PASSWORD'],
        policyRuleIds: ['rule-1'],
      });
      const tokenShaped = ['g', 'h', 'p', '_'].join('') + crypto.randomBytes(18).toString('hex');
      planted.push('PLANTED_OTHER', 'rule-9', tokenShaped);
      const calls: Array<() => void> = [
        () => emitter.emitRequested(PLANTED_AGENT, 'PLANTED_OTHER', PLANTED_CAPABILITY),
        () =>
          emitter.emitGranted('scan-01', 'PLANTED_DB_PASSWORD', {
            trustScore: 0.9,
            ttlSeconds: 60,
            policyRuleId: 'rule-9',
            backend: PLANTED_BACKEND,
          }),
        () => emitter.emitDenied(PLANTED_AGENT, 'PLANTED_OTHER', PLANTED_TEXT, { trustScore: 0.1, policyRuleId: 'rule-1' }),
        () => emitter.emitExpired('scan-01', 'PLANTED_OTHER', true),
        () => emitter.emitExpired('scan-01', 'PLANTED_OTHER', false),
        () => emitter.emitRevoked(PLANTED_AGENT, 'PLANTED_DB_PASSWORD', PLANTED_TEXT),
        () => emitter.emitLeakDetected(PLANTED_AGENT, tokenShaped, PLANTED_TEXT),
        () => emitter.emitRotated('PLANTED_OTHER', PLANTED_TEXT),
      ];
      for (const call of calls) {
        const delivered = new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('no forward arrived')), 3000);
          arrived = () => {
            clearTimeout(timer);
            resolve();
          };
        });
        call();
        await delivered;

        const { headers, body } = received[received.length - 1];
        const forwarded = JSON.parse(body) as Record<string, unknown>;
        expect(forwarded).toEqual(last());
        expect(Object.keys(forwarded)).toEqual([
          'timestamp',
          'eventType',
          'agentId',
          'credentialName',
          'policyId',
          'result',
          'reason',
          'latencyMs',
        ]);
        expect('capability' in forwarded || 'backend' in forwarded).toBe(false);
        expect(headers.authorization).toBeUndefined();
        for (const word of planted) expect(body.includes(word), 'the forward carries planted text').toBe(false);
      }
      expect(received).toHaveLength(calls.length);
    } finally {
      await new Promise<void>((resolve) => aim.close(() => resolve()));
    }
  });
});
