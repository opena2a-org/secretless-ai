import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { resolveRef, RefResolutionError } from './resolver';
import { writeBackendConfig } from '../backends/config';
import { createBackend } from '../backends/factory';

/**
 * #372: a `secret://` reference whose named backend could not be built was
 * answered by the configured backend, and the result still reported the named
 * one. With `local` configured and VAULT_ADDR unset, `secret://vault/STRIPE_KEY`
 * resolved to the encrypted file's STRIPE_KEY as `backend: 'vault'`.
 *
 * The real factory and the encrypted file, under a home of their own. No OS
 * keychain is asked for anything: the configured backend is `local`.
 */
describe('resolveRef: a reference whose named backend is unreachable (#372)', () => {
  const saved = {
    HOME: process.env.HOME,
    VAULT_ADDR: process.env.VAULT_ADDR,
    VAULT_TOKEN: process.env.VAULT_TOKEN,
  };
  let root: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-resolver-unreachable-test-'));
    fs.mkdirSync(path.join(root, 'home'));
    process.env.HOME = path.join(root, 'home');
    delete process.env.VAULT_ADDR;
    delete process.env.VAULT_TOKEN;
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('is not answered by the configured backend in its place', async () => {
    writeBackendConfig('local');
    await createBackend('local').store('secret/STRIPE_KEY', 'held-by-the-configured-backend');
    const uri = 'secret://vault/STRIPE_KEY';

    const outcome = await resolveRef(uri).then(
      (r) => r,
      (e: Error) => e,
    );

    // Before the fix: { value: 'held-by-the-configured-backend', backend: 'vault' }.
    expect(outcome).toBeInstanceOf(RefResolutionError);
    const refusal = outcome as RefResolutionError;
    expect(refusal.message).toBe(
      `Backend "vault" named by ${uri} is not reachable: VAULT_ADDR and VAULT_TOKEN must be set. No other store was read in its place.`,
    );
    expect(refusal.ref).toBe(uri);
    expect(refusal.backend).toBe('vault');
  });

  it('CONTROL: the configured backend holds the value, so the test above can fail', async () => {
    writeBackendConfig('local');
    await createBackend('local').store('secret/STRIPE_KEY', 'held-by-the-configured-backend');

    expect(await createBackend('local').resolve('secret/STRIPE_KEY')).toEqual({
      'secret/STRIPE_KEY': 'held-by-the-configured-backend',
    });
  });
});
