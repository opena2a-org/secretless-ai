/**
 * The grant record: what the broker writes to its signed audit log for each grant resolution.
 *
 * For an operation it forwards through a downstream caller that delivers salts, the broker draws a
 * fresh 32-byte salt, hands it to the caller with the operation, and writes only
 * SHA-256(salt || JCS(operation)) to the record. The resource keeps the salt beside the operation in
 * its own record, so whoever holds both can open the commitment, and a reader of the broker log
 * alone cannot. The record also carries the `jti` of the CGT minted for the resolution, a reason
 * code from a closed set, and unverified inputs only in parsed form or as a marker with their
 * length.
 *
 * Every value here is fictional. Tokens and salts are drawn at run time and never printed: a search
 * reports where it found a value, never the value.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  Atx,
  AtxVerifier,
  ResolutionContext,
} from '@opena2a/atx-verify' with { 'resolution-mode': 'import' };
import { AuditLogger, verifyAuditLog } from './audit';
import { generateBrokerSigningKey } from './cpi/assertion';
import { ExchangeProvider, type TokenExchangeTransport } from './cpi/exchange';
import { MapProviderRegistry } from './cpi/registry';
import type { CredentialProvider, ScopedCredential } from './cpi/types';
import { GrantPolicy } from './grant-policy';
import { GrantResolver, type GrantResolveOutcome } from './grant-resolver';
import {
  EphemeralWorker,
  HttpsDownstreamCaller,
  type AgentOperation,
  type DownstreamCaller,
} from './worker';

const AGENT_DID = 'did:opena2a:agent:acme/payments-agent';

const CTX: ResolutionContext = {
  agentId: 'aim_payments_agent',
  agentDid: AGENT_DID,
  issuerDid: 'did:opena2a:authority:opena2a.org',
  issuerChain: ['did:opena2a:authority:opena2a.org'],
  trustLevel: 4,
  trustScore: 0.95,
  capabilities: ['payments:write'],
  oasbLevel: 'L2',
  signedCapabilities: true,
};

const VERIFIES: AtxVerifier = { verify: () => ({ valid: true, context: CTX }) };
const REJECTS: AtxVerifier = {
  verify: () => ({ valid: false, rejectCategory: 'SIGNATURE_INVALID' }),
};

const GRANT = 'grant://payments';

function bindingDoc(mode: 'exchange' | 'retrieve' = 'exchange'): Record<string, unknown> {
  return {
    grant: GRANT,
    match: { trustClass: 'payments:write' },
    resolve: {
      mode,
      providerId: 'payments-idp',
      scope: 'payments.write',
      audience: 'https://bank.example',
      ttlSeconds: 300,
    },
  };
}

/** A fictional payment, and its RFC 8785 form written out by hand. */
const PAYMENT: AgentOperation = {
  method: 'POST',
  path: '/payments',
  body: { payee: 'Fictional Payee Ltd', amount: '120.00', currency: 'EUR' },
};
const PAYMENT_JCS =
  '{"body":{"amount":"120.00","currency":"EUR","payee":"Fictional Payee Ltd"},' +
  '"method":"POST","path":"/payments"}';

/** A fictional listing with a query, and its RFC 8785 form written out by hand. */
const LISTING: AgentOperation = {
  method: 'GET',
  path: '/payments',
  query: { status: 'pending', from: '2026-10-01' },
};
const LISTING_JCS =
  '{"method":"GET","path":"/payments","query":{"from":"2026-10-01","status":"pending"}}';

/** The resource's own record of an operation it received: the operation, and the salt beside it. */
interface ResourceRow {
  operation: AgentOperation;
  /** Lowercase hex, as the resource stored it. Absent when no salt came with the operation. */
  salt?: string;
}

/**
 * The bank's side of the call, in process. A caller that delivers salts hands the resource the salt
 * with the operation; the resource writes both into its row and answers without the salt.
 */
function bank(
  rows: ResourceRow[],
  delivers: boolean,
  fail?: (op: AgentOperation) => Error,
): DownstreamCaller {
  return {
    deliversSalt: delivers,
    async call(_audience: string, op: AgentOperation, _cred: ScopedCredential, salt?: Uint8Array) {
      rows.push({
        operation: JSON.parse(JSON.stringify(op)) as AgentOperation,
        ...(salt === undefined ? {} : { salt: Buffer.from(salt).toString('hex') }),
      });
      if (fail) throw fail(op);
      return { status: 201, body: { paymentId: `pay-${rows.length}` } };
    },
  } as DownstreamCaller;
}

/** A token service in process: it keeps every CGT presented to it and every token it issues. */
interface TokenService {
  transport: TokenExchangeTransport;
  cgts: string[];
  issued: string[];
}

function tokenService(): TokenService {
  const cgts: string[] = [];
  const issued: string[] = [];
  return {
    cgts,
    issued,
    transport: {
      async exchange(req) {
        cgts.push(req.params.subject_token);
        const token = crypto.randomBytes(24).toString('base64url');
        issued.push(token);
        return { access_token: token, token_type: 'Bearer', expires_in: 300 };
      },
    },
  };
}

const SIGNING_KEY = generateBrokerSigningKey('https://broker.bank.example', 'broker-key-1');

let dir: string;
let logPath: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grant-record-'));
  logPath = path.join(dir, 'audit.log');
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
});

interface Broker {
  resolver: GrantResolver;
  rows: ResourceRow[];
  tokens: TokenService;
}

function broker(
  opts: {
    delivers?: boolean;
    verifier?: AtxVerifier;
    provider?: CredentialProvider;
    mode?: 'exchange' | 'retrieve';
    fail?: (op: AgentOperation) => Error;
  } = {},
): Broker {
  const rows: ResourceRow[] = [];
  const tokens = tokenService();
  const provider =
    opts.provider ??
    new ExchangeProvider(
      { tokenEndpoint: 'https://idp.bank.example/token' },
      SIGNING_KEY,
      tokens.transport,
    );
  const resolver = new GrantResolver({
    verifier: opts.verifier ?? VERIFIES,
    policy: new GrantPolicy([bindingDoc(opts.mode)]),
    providers: new MapProviderRegistry().register('payments-idp', provider),
    worker: new EphemeralWorker(bank(rows, opts.delivers ?? true, opts.fail)),
    audit: new AuditLogger(logPath),
  });
  return { resolver, rows, tokens };
}

function grant(
  b: Broker,
  operation: AgentOperation,
  input: { agentId?: string; grant?: string } = {},
): Promise<GrantResolveOutcome> {
  return b.resolver.resolve({
    agentId: input.agentId ?? AGENT_DID,
    atx: {} as Atx,
    grant: input.grant ?? GRANT,
    operation,
  });
}

function logLines(): Array<Record<string, unknown>> {
  return fs
    .readFileSync(logPath, 'utf-8')
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

/** The grant records in the broker log, oldest first. */
function grantRecords(): Array<Record<string, unknown>> {
  return logLines().filter((record) => record.eventType === 'grant');
}

/** The forms a salt could be written in: hex in either case, base64url, base64. */
function saltForms(hex: string): Array<[string, string]> {
  const bytes = Buffer.from(hex, 'hex');
  return [
    ['hex', hex],
    ['upper-case hex', hex.toUpperCase()],
    ['base64url', bytes.toString('base64url')],
    ['base64', bytes.toString('base64').replace(/=+$/, '')],
  ];
}

/** Where, among `places`, a form of the salt appears: the place and the form, never the value. */
function whereFound(hex: string, places: Array<[string, string]>): string[] {
  return places.flatMap(([where, text]) =>
    saltForms(hex)
      .filter(([, form]) => text.includes(form))
      .map(([name]) => `${where} (${name})`),
  );
}

function isSaltHex(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

/** The header and claims of a compact JWS, decoded. */
function decodedParts(token: string): string {
  return token
    .split('.')
    .slice(0, 2)
    .map((part) => Buffer.from(part, 'base64url').toString('utf-8'))
    .join('\n');
}

describe('grant record: a salted commitment to the operation', () => {
  it('T1: the same fictional operation committed twice gives two different commitments', async () => {
    const b = broker();
    await grant(b, PAYMENT);
    await grant(b, PAYMENT);

    const [first, second] = grantRecords();
    expect(first.operationCommitment).toMatch(/^[0-9a-f]{64}$/);
    expect(second.operationCommitment).toMatch(/^[0-9a-f]{64}$/);
    expect(first.operationCommitment === second.operationCommitment).toBe(false);
    // The resource received the same operation twice, each time with a salt of its own.
    expect(b.rows.map((row) => row.operation)).toEqual([PAYMENT, PAYMENT]);
    expect(b.rows.every((row) => isSaltHex(row.salt))).toBe(true);
    expect(b.rows[0].salt === b.rows[1].salt).toBe(false);
  });

  it("T2: SHA-256(salt || JCS(op)) recomputed from the resource row's salt and operation equals the record", async () => {
    const b = broker();
    await grant(b, PAYMENT);
    await grant(b, LISTING);

    const records = grantRecords();
    const canonical = [PAYMENT_JCS, LISTING_JCS];
    expect(b.rows.map((row) => row.operation)).toEqual([PAYMENT, LISTING]);
    expect(b.rows.every((row) => isSaltHex(row.salt))).toBe(true);
    b.rows.forEach((row, i) => {
      const recomputed = crypto
        .createHash('sha256')
        .update(Buffer.from(row.salt as string, 'hex'))
        .update(Buffer.from(canonical[i], 'utf-8'))
        .digest('hex');
      expect(records[i].operationCommitment).toBe(recomputed);
    });
  });

  it('T3: the salt is in no broker log, CGT, issued token or agent response, and it is in the resource row', async () => {
    const consoleText: string[] = [];
    for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        consoleText.push(args.map((arg) => String(arg)).join(' '));
      });
    }
    const b = broker();
    const responses = [await grant(b, PAYMENT), await grant(b, LISTING)];

    expect(b.rows).toHaveLength(2);
    expect(b.tokens.cgts).toHaveLength(2);
    expect(b.tokens.issued).toHaveLength(2);
    expect(b.rows.every((row) => isSaltHex(row.salt))).toBe(true);
    for (const row of b.rows) {
      const salt = row.salt as string;
      const places: Array<[string, string]> = [
        ['broker log', fs.readFileSync(logPath, 'utf-8')],
        ...b.tokens.cgts.flatMap((cgt, i): Array<[string, string]> => [
          [`CGT ${i + 1}`, cgt],
          [`CGT ${i + 1} decoded`, decodedParts(cgt)],
        ]),
        ...b.tokens.issued.map((token, i): [string, string] => [`issued token ${i + 1}`, token]),
        ...responses.map((r, i): [string, string] => [`agent response ${i + 1}`, JSON.stringify(r)]),
        ['console', consoleText.join('\n')],
      ];
      expect(whereFound(salt, places)).toEqual([]);
      expect(whereFound(salt, [['resource row', JSON.stringify(row)]])).toEqual([
        'resource row (hex)',
      ]);
    }
  });

  it('T4: with a caller that does not deliver salts, the record carries no operationCommitment', async () => {
    // The HTTPS caller has no wire carrier for a salt, so it declares that it delivers none.
    expect(new HttpsDownstreamCaller().deliversSalt).toBe(false);

    const delivering = broker({ delivers: true });
    await grant(delivering, PAYMENT);
    const silent = broker({ delivers: false });
    await grant(silent, PAYMENT);

    const [committed, uncommitted] = grantRecords();
    expect(committed.operationCommitment).toMatch(/^[0-9a-f]{64}$/);
    expect(uncommitted.result).toBe('allowed');
    expect('operationCommitment' in uncommitted).toBe(false);
    // No salt went with the operation: nobody would hold the salt that opens a commitment.
    expect(silent.rows).toHaveLength(1);
    expect('salt' in silent.rows[0]).toBe(false);
  });

  it('T5: verifyAuditLog passes over one file holding records written before and after the change', async () => {
    const logger = new AuditLogger(logPath);
    // Records in the shape earlier versions wrote, through the logger's own entry points. The
    // logger takes codes only now; records whose reasons are free text are verified in
    // audit.reason-closure.test.ts.
    logger.logEvent('startup', 'broker', '', '', 'allowed', 'broker-started', 0);
    logger.log({
      timestamp: new Date().toISOString(),
      eventType: 'grant',
      agentId: 'aim_payments_agent',
      credentialName: GRANT,
      policyId: GRANT,
      result: 'allowed',
      reason: 'resolved-exchange',
      latencyMs: 4,
    });
    // A record written now, after them in the same file.
    await grant(broker(), PAYMENT);

    const earlier = [
      'timestamp',
      'eventType',
      'agentId',
      'credentialName',
      'policyId',
      'result',
      'reason',
      'latencyMs',
    ];
    expect(logLines().map((record) => Object.keys(record))).toEqual([
      [...earlier, 'prevHash', 'sig'],
      [...earlier, 'prevHash', 'sig'],
      [...earlier, 'cgtJti', 'operationCommitment', 'prevHash', 'sig'],
    ]);
    expect(verifyAuditLog(logPath, logger.publicKeyPem())).toEqual({ valid: true, records: 3 });
  });
});

describe('grant record: no text from the operation, a provider or the downstream', () => {
  const PLANTED = 'Planted Payee Odalys Brennecke';
  const planted: AgentOperation = {
    method: 'POST',
    path: '/payments',
    body: { payee: PLANTED, amount: '75.00', reference: `invoice for ${PLANTED}` },
  };

  it('T6: forced provider and downstream failures on an operation naming a planted payee leave no planted value in the broker log', async () => {
    // The provider fails with text naming the payee, as a provider that echoes its input could.
    const failing: CredentialProvider = {
      modes: ['exchange'],
      resolve: async () => {
        throw new Error(`no mandate on file for payee ${PLANTED}`);
      },
    };
    await grant(broker({ provider: failing }), planted);
    // The downstream fails with text naming the payee it was asked to pay.
    await grant(
      broker({
        fail: (op) => new Error(`payee ${(op.body as { payee: string }).payee} was rejected`),
      }),
      planted,
    );

    expect(grantRecords().map((record) => record.result)).toEqual(['denied', 'denied']);
    const log = fs.readFileSync(logPath, 'utf-8');
    expect(
      [PLANTED, 'Odalys', 'Brennecke', 'invoice', 'mandate', 'rejected'].filter((word) =>
        log.includes(word),
      ),
    ).toEqual([]);
  });

  it('T7: an agent id that is not a DID and a grant string that names no configured grant are recorded as unparsed:<length>', async () => {
    // The ATX does not verify, so the record is written from what the agent sent.
    const b = broker({ verifier: REJECTS });
    const inputs = [
      { agentId: 'payments agent, not yet verified', grant: 'grant://not-configured' },
      { agentId: 'zahlungs-agent-ü', grant: 'secret://vault/payments' },
      { agentId: 'did:Example:upper-case-method', grant: `${GRANT} ` },
      { agentId: '', grant: '' },
    ];
    for (const input of inputs) await grant(b, PAYMENT, input);

    expect(grantRecords().map((record) => [record.agentId, record.credentialName])).toEqual(
      inputs.map(({ agentId, grant: g }) => [
        `unparsed:${Buffer.byteLength(agentId, 'utf-8')}`,
        `unparsed:${Buffer.byteLength(g, 'utf-8')}`,
      ]),
    );
  });

  it('records an agent id that parses as a DID, and a grant string that names a configured grant, as given', async () => {
    const b = broker({ verifier: REJECTS });
    await grant(b, PAYMENT, { agentId: 'did:example:payments-agent-7', grant: GRANT });
    await grant(b, PAYMENT, { agentId: 'did:web:bank.example:agents:pay%2D7', grant: GRANT });

    expect(grantRecords().map((record) => [record.agentId, record.credentialName])).toEqual([
      ['did:example:payments-agent-7', GRANT],
      ['did:web:bank.example:agents:pay%2D7', GRANT],
    ]);
  });

  it('records an unverified agent id carrying a DID URL path as a marker: a DID URL is not a DID', async () => {
    const b = broker({ verifier: REJECTS });
    await grant(b, PAYMENT, { agentId: AGENT_DID });

    expect(grantRecords()[0].agentId).toBe(`unparsed:${Buffer.byteLength(AGENT_DID, 'utf-8')}`);
  });

  it('records the verified ATX DID once the ATX verifies, whatever id the agent sent', async () => {
    const b = broker();
    await grant(b, PAYMENT, { agentId: 'aim_payments_agent' });
    await grant(b, PAYMENT, { agentId: 'did:example:someone-else' });

    expect(grantRecords().map((record) => record.agentId)).toEqual([AGENT_DID, AGENT_DID]);
  });
});

describe('grant record: the CGT jti', () => {
  it('carries the jti of the CGT the token service received', async () => {
    const b = broker();
    await grant(b, PAYMENT);
    await grant(b, LISTING);

    const presented = b.tokens.cgts.map(
      (cgt) => (JSON.parse(Buffer.from(cgt.split('.')[1], 'base64url').toString('utf-8')) as {
        jti: string;
      }).jti,
    );
    expect(presented.every((jti) => /^[0-9a-f]{32}$/.test(jti))).toBe(true);
    expect(grantRecords().map((record) => record.cgtJti)).toEqual(presented);
  });

  it('carries no jti when no CGT was minted: Retrieve mode, or a denial before minting', async () => {
    const retrieve: CredentialProvider = {
      modes: ['retrieve'],
      resolve: async () => ({
        token: crypto.randomBytes(16).toString('hex'),
        tokenType: 'Bearer',
        expiresInSeconds: 300,
      }),
    };
    await grant(broker({ provider: retrieve, mode: 'retrieve' }), PAYMENT);
    await grant(broker({ verifier: REJECTS }), PAYMENT);

    const records = grantRecords();
    expect(records.map((record) => record.result)).toEqual(['allowed', 'denied']);
    expect(records.map((record) => 'cgtJti' in record)).toEqual([false, false]);
  });

  it('writes a jti a provider reports in any other form as unparsed:<length>', async () => {
    const reported = 'jti from a provider, not 32 hex';
    const odd: CredentialProvider = {
      modes: ['exchange'],
      resolve: async () =>
        ({
          token: crypto.randomBytes(16).toString('hex'),
          tokenType: 'Bearer',
          expiresInSeconds: 300,
          cgtJti: reported,
        }) as ScopedCredential,
    };
    await grant(broker({ provider: odd }), PAYMENT);

    expect(grantRecords()[0].cgtJti).toBe(`unparsed:${Buffer.byteLength(reported, 'utf-8')}`);
  });
});
