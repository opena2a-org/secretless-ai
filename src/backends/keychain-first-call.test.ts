import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  BACKEND_CHILD_TIMEOUT_MS,
  KeychainChildren,
  KeychainNoAnswerError,
  UNATTENDED_FIRST_CALL_TIMEOUT_MS,
} from './bounded-child';

/**
 * The first child of an OS keychain backend in a run (KeychainChildren). The
 * children are /bin/sh scripts that append a line to a file when they start,
 * then either answer at once or wait: no keychain program is run.
 */

let dir: string;
let starts: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-first-call-'));
  starts = path.join(dir, 'starts');
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

/** argv for /bin/sh: record the start, then wait `seconds` and exit 0. */
const waits = (seconds: number): string[] => ['-c', `echo started >> "$0"; exec /bin/sleep ${seconds}`, starts];
/** argv for /bin/sh: record the start and answer at once. */
const answers = (): string[] => ['-c', 'echo started >> "$0"; echo answer', starts];
const started = (): number => (fs.existsSync(starts) ? fs.readFileSync(starts, 'utf-8').split('\n').filter((l) => l.length > 0).length : 0);

describe('KeychainChildren', () => {
  it('bounds the first child of an unattended run at the unattended bound and refuses that call', async () => {
    const children = new KeychainChildren('Test Keychain', '/bin/sh', BACKEND_CHILD_TIMEOUT_MS, { unattended: true });
    const at = performance.now();
    const err = await children.run(waits(30)).then(() => undefined, (e: unknown) => e);
    const ms = performance.now() - at;

    expect(err).toBeInstanceOf(KeychainNoAnswerError);
    expect((err as KeychainNoAnswerError).timeoutMs).toBe(UNATTENDED_FIRST_CALL_TIMEOUT_MS);
    expect((err as KeychainNoAnswerError).store).toBe('Test Keychain');
    expect((err as Error).message).toContain('Test Keychain did not answer within 0.5s');
    expect(ms).toBeGreaterThanOrEqual(UNATTENDED_FIRST_CALL_TIMEOUT_MS - 50);
    expect(ms).toBeLessThan(1000);
  }, 10_000);

  it('refuses every later call with the same error at once, starting no child', async () => {
    const children = new KeychainChildren('Test Keychain', '/bin/sh', BACKEND_CHILD_TIMEOUT_MS, { unattended: true });
    const first = await children.run(waits(30)).then(() => undefined, (e: unknown) => e);
    expect(started()).toBe(1);

    const at = performance.now();
    const second = await children.run(answers()).then(() => undefined, (e: unknown) => e);
    expect(second).toBe(first);
    expect(performance.now() - at).toBeLessThan(100);
    expect(started()).toBe(1);
  }, 10_000);

  it('never gives the first child a longer bound than the backend has', async () => {
    const children = new KeychainChildren('Test Keychain', '/bin/sh', 150, { unattended: true });
    const err = await children.run(waits(30)).then(() => undefined, (e: unknown) => e);

    expect(err).toBeInstanceOf(KeychainNoAnswerError);
    expect((err as KeychainNoAnswerError).timeoutMs).toBe(150);
  }, 10_000);

  it('gives later calls the backend bound once the first was answered', async () => {
    const children = new KeychainChildren('Test Keychain', '/bin/sh', 5_000, { unattended: true });
    expect((await children.run(answers())).status).toBe(0);

    // Longer than the unattended bound, shorter than the backend's.
    const later = await children.run(waits(0.8));
    expect(later.timedOut).toBe(false);
    expect(later.status).toBe(0);
    expect(started()).toBe(2);
  }, 10_000);

  it('with a terminal, bounds the first child as every other and returns its result', async () => {
    const children = new KeychainChildren('Test Keychain', '/bin/sh', 200, { unattended: false });
    const res = await children.run(waits(30));

    expect(res.timedOut).toBe(true);
    expect(started()).toBe(1);
    // Not refused: the next call starts a child.
    expect((await children.run(answers())).status).toBe(0);
    expect(started()).toBe(2);
  }, 10_000);

  it('tells the run once, before the first child starts, with the store name', async () => {
    const told: Array<{ store: string; startedBefore: number }> = [];
    const children = new KeychainChildren('Test Keychain', '/bin/sh', BACKEND_CHILD_TIMEOUT_MS, {
      before: (store) => told.push({ store, startedBefore: started() }),
    });
    await children.run(answers());
    await children.run(answers());

    expect(told).toEqual([{ store: 'Test Keychain', startedBefore: 0 }]);
    expect(started()).toBe(2);
  }, 10_000);

  it('starts every child with the backend bound when the run asks nothing', async () => {
    const children = new KeychainChildren('Test Keychain', '/bin/sh', 200);
    const res = await children.run(waits(30));

    expect(res.timedOut).toBe(true);
    expect((await children.run(answers())).status).toBe(0);
  }, 10_000);
});
