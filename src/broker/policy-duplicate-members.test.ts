import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PolicyEngine } from './policy';

/**
 * A duplicated member name in the policy file (#140).
 *
 * `JSON.parse` resolves a repeated name before the loader is given anything to
 * inspect: the surviving object holds ONE entry, and it is the LAST one written.
 * So a rule whose text reads `"effect": "deny"` then `"effect": "allow"` reaches
 * `validateRule` as a well-formed allow, and every surface — the rule count,
 * `getRules()`, `/health` — reports the operator's rule loaded. The restrictive
 * half is gone and nothing says so.
 *
 * WHY THE FILED DIRECTION DOES NOT WORK. Issue #140 proposed a
 * duplicate-key-detecting reviver. Measured on `{"a":1,"a":2,"b":{"a":3}}`: the
 * reviver is invoked four times, and NO call ever carries `value: 1`. The first
 * member does not produce a call at all, because the reviver walks the
 * already-collapsed result. A reviver cannot see a duplicate; a control built on
 * one would never fire. The scan therefore has to run on the RAW TEXT, before
 * `JSON.parse`, which is what `firstDuplicateMember` does.
 *
 * WHY IT IS WORSE THAN "A DENY BECOMES AN ALLOW". Duplicating a KNOWN name also
 * defeats the 0.22.1 refusals, because the instance that would have been refused
 * is the instance that disappears. Measured on published 0.22.1: a duplicated
 * `constraints` hides an unknown-constraint refusal, a duplicated `rateLimit`
 * hides the sub-key refusal, a duplicated `requireCapability` hides the
 * empty-capability refusal, and a duplicated `effect` hides effect validation.
 * Those are covered below, because closing only the deny-becomes-allow shape
 * would leave every one of them live.
 */

function policyFile(text: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-dup-'));
  const file = path.join(dir, 'broker-policies.json');
  fs.writeFileSync(file, text);
  return file;
}

/** Always an explicit policyFile — never the developer's real one. */
function engineFor(text: string): PolicyEngine {
  return new PolicyEngine({ policyFile: policyFile(text) });
}

const RULE = '"id":"r1","agentSelector":"*","credentialSelector":"*"';

describe('a duplicated member is refused, at every level of the file', () => {
  /**
   * The controls come first and they must come out DIFFERENT from every row
   * below. A matrix whose refusals all pass would look identical if the loader
   * simply refused everything, so an honest file that LOADS is what makes the
   * refusals mean something.
   */
  it('CONTROL: an honest file loads, and its deny rule denies', async () => {
    const engine = engineFor(`{"version":1,"rules":[{${RULE},"effect":"deny"}]}`);
    expect(await engine.loadPolicies()).toBe(1);
    expect(engine.getRules()[0].effect).toBe('deny');
    expect(engine.evaluate('any-agent', 'PROD_DB_PASSWORD').allowed).toBe(false);
  });

  it('CONTROL: an honest file whose rule ALLOWS still allows', async () => {
    const engine = engineFor(`{"rules":[{${RULE},"effect":"allow"}]}`);
    expect(await engine.loadPolicies()).toBe(1);
    expect(engine.evaluate('any-agent', 'ANY_CRED').allowed).toBe(true);
  });

  it.each([
    [
      'the envelope — two `rules` arrays, so the deny set is never in the engine',
      `{"rules":[{"id":"deny-all","agentSelector":"*","credentialSelector":"*","effect":"deny"}],` +
      `"rules":[{"id":"allow-all","agentSelector":"*","credentialSelector":"*","effect":"allow"}]}`,
      'rules',
    ],
    [
      'the rule — `effect` twice, deny then allow',
      `{"rules":[{${RULE},"effect":"deny","effect":"allow"}]}`,
      'effect',
    ],
    [
      'the rule — `agentSelector` twice, `*` then a narrower one',
      `{"rules":[{"id":"r1","agentSelector":"*","agentSelector":"other","credentialSelector":"*","effect":"deny"}]}`,
      'agentSelector',
    ],
    [
      'the constraints container — `timeWindow` twice, closed then open',
      `{"rules":[{${RULE},"effect":"allow","constraints":{"timeWindow":{"start":"00:00","end":"00:01"},` +
      `"timeWindow":{"start":"00:00","end":"23:59"}}}]}`,
      'timeWindow',
    ],
    [
      'the constraint sub-object — `end` twice, the deepest level in the schema',
      `{"rules":[{${RULE},"effect":"allow","constraints":{"timeWindow":{"start":"00:00","end":"00:01","end":"23:59"}}}]}`,
      'end',
    ],
    [
      'the constraint sub-object — `maxPerMinute` twice, 1 then 3600',
      `{"rules":[{${RULE},"effect":"allow","constraints":{"rateLimit":{"maxPerMinute":1,"maxPerMinute":3600}}}]}`,
      'maxPerMinute',
    ],
    [
      'the bare-array file form, which has no envelope to check',
      `[{${RULE},"effect":"deny","effect":"allow"}]`,
      'effect',
    ],
  ])('refuses %s', async (_label, text, member) => {
    const engine = engineFor(text);
    await expect(engine.loadPolicies()).rejects.toThrow(new RegExp(`duplicate member "${member}"`));
  });

  /**
   * The property, asserted on the rule SET rather than on a message: a refusal
   * that threw but left rules loaded would still satisfy `.rejects.toThrow()`.
   */
  it('nothing is loaded when a duplicate is refused', async () => {
    const engine = engineFor(`{"rules":[{${RULE},"effect":"deny","effect":"allow"}]}`);
    await expect(engine.loadPolicies()).rejects.toThrow();
    expect(engine.getRules()).toEqual([]);
    expect(engine.ruleCount).toBe(0);
    expect(engine.evaluate('any-agent', 'ANY_CRED').allowed).toBe(false);
  });
});

/**
 * Duplicating a KNOWN name defeats the refusals 0.22.1 added, because the
 * instance that would have been refused is the instance `JSON.parse` drops.
 * Each row below LOADS on 0.22.1 with `allowed: true`.
 */
describe('a duplicate cannot be used to smuggle a rule past a 0.22.1 refusal', () => {
  it.each([
    [
      'an unknown constraint, hidden behind a duplicated `constraints`',
      `{"rules":[{${RULE},"effect":"allow","constraints":{"maxPerHour":1},"constraints":{}}]}`,
    ],
    [
      'the refused `scopeCheck` key, hidden behind a duplicated `constraints`',
      `{"rules":[{${RULE},"effect":"allow","constraints":{"scopeCheck":true},"constraints":{}}]}`,
    ],
    [
      'an empty requireCapability, hidden by a second spelling that is valid',
      `{"rules":[{${RULE},"effect":"allow","constraints":{"requireCapability":"","requireCapability":"read"}}]}`,
    ],
    [
      'an invalid effect, hidden by a second spelling that is valid',
      `{"rules":[{${RULE},"effect":"DENY","effect":"allow"}]}`,
    ],
    [
      'an empty agentSelector, which matches nothing, hidden by a valid second',
      `{"rules":[{"id":"r1","agentSelector":"","agentSelector":"*","credentialSelector":"*","effect":"allow"}]}`,
    ],
  ])('refuses %s', async (_label, text) => {
    const engine = engineFor(text);
    await expect(engine.loadPolicies()).rejects.toThrow(/duplicate member/);
    expect(engine.getRules()).toEqual([]);
  });
});

/**
 * The collision is judged after JSON escape decoding and after case folding, so
 * the colliding member can be spelled differently in the file than it reads in
 * the error. A byte-comparing scanner would return clean on the first case and
 * ship the bypass in the same direction as the defect.
 */
describe('a collision the file does not spell literally', () => {
  it('refuses an escaped spelling of a name already present', async () => {
    // `effect` is `effect`. JSON.parse collapses the pair and keeps "allow".
    const engine = engineFor(`{"rules":[{${RULE},"effect":"deny","\\u0065ffect":"allow"}]}`);
    await expect(engine.loadPolicies()).rejects.toThrow(/duplicate member "effect"/);
    expect(engine.getRules()).toEqual([]);
  });

  it('the refusal says the spelling may differ, so nobody hunts for a literal', async () => {
    const engine = engineFor(`{"rules":[{${RULE},"effect":"deny","\\u0065ffect":"allow"}]}`);
    let message = '';
    try { await engine.loadPolicies(); } catch (err) { message = (err as Error).message; }
    expect(message).toMatch(/escape decoding/);
    expect(message).toMatch(/case folding/);
  });

  /**
   * A case variant is ALREADY refused by the key allowlists, as an unknown
   * field. It is here to pin that the outcome does not regress to a load — the
   * message changes owner, the verdict does not.
   */
  it('CONTROL: a case variant is refused either way, never loaded', async () => {
    const engine = engineFor(`{"rules":[{${RULE},"effect":"deny","EFFECT":"allow"}]}`);
    await expect(engine.loadPolicies()).rejects.toThrow();
    expect(engine.getRules()).toEqual([]);
  });
});

/**
 * R1 — the check must not be bypassable by its own failure.
 *
 * The likeliest way this fix is broken later is a copy of the `/grant` path's
 * `try { import; scan } catch { ... }` shape with a catch that CONTINUES. That
 * would load a policy file with the check silently absent, on any machine where
 * the module does not resolve — the defect reintroduced by its own fix, and a
 * green suite would not see it. This test is the thing that sees it.
 */
describe('the duplicate-member check cannot be bypassed by failing to load', () => {
  afterEach(() => {
    vi.resetModules();
    vi.doUnmock('@opena2a/atx-verify');
  });

  it('refuses to load anything when the scanner module will not resolve', async () => {
    vi.resetModules();
    vi.doMock('@opena2a/atx-verify', () => {
      throw new Error("Cannot find module '@opena2a/atx-verify'");
    });
    const { PolicyEngine: FreshEngine } = await import('./policy');

    // An HONEST file: there is nothing wrong with it. The refusal must come
    // from the check being unavailable, not from the file's content — which is
    // what makes this a withhold rather than a refusal.
    const engine = new FreshEngine({ policyFile: policyFile(`{"rules":[{${RULE},"effect":"deny"}]}`) });

    await expect(engine.loadPolicies()).rejects.toThrow(/could not be loaded/);
    expect(engine.getRules()).toEqual([]);
    expect(engine.ruleCount).toBe(0);
    expect(engine.evaluate('any-agent', 'ANY_CRED').allowed).toBe(false);
  });

  it('says it is an installation fault, and does not tell the operator to edit the policy', async () => {
    vi.resetModules();
    vi.doMock('@opena2a/atx-verify', () => {
      throw new Error("Cannot find module '@opena2a/atx-verify'");
    });
    const { PolicyEngine: FreshEngine } = await import('./policy');
    const engine = new FreshEngine({ policyFile: policyFile(`{"rules":[{${RULE},"effect":"deny"}]}`) });

    let message = '';
    try { await engine.loadPolicies(); } catch (err) { message = (err as Error).message; }

    expect(message).toMatch(/installation fault/);
    expect(message).toMatch(/no credential will be served/);
    // A remedy that says "delete the policy file" is a fail-open by hand.
    expect(message).not.toMatch(/delete .*polic/i);
  });
});

/**
 * The scanner is strict about structure where `JSON.parse` is not. Refusing
 * here keeps the accept-set of the FILE and the accept-set of the CHECK
 * identical — a file the check cannot vouch for must not be loaded by a parser
 * that would have accepted it.
 */
describe('text the scanner cannot vouch for is refused, not parsed anyway', () => {
  it('refuses trailing content after the closing brace', async () => {
    const engine = engineFor(`{"rules":[{${RULE},"effect":"deny"}]} trailing`);
    await expect(engine.loadPolicies()).rejects.toThrow(/well-formed JSON value/);
    expect(engine.getRules()).toEqual([]);
  });

  it('CONTROL: a trailing newline is not trailing content', async () => {
    const engine = engineFor(`{"rules":[{${RULE},"effect":"deny"}]}\n`);
    expect(await engine.loadPolicies()).toBe(1);
  });
});
