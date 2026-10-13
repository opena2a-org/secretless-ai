import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { resolveRef, resolveEnvRefs, RefResolutionError } from './resolver';
import { writeBackendConfig } from '../backends/config';
import { createBackend, hasKeychainImplementation } from '../backends/factory';
import { MacOSKeychainBackend } from '../backends/keychain-macos';
import { LinuxKeychainBackend } from '../backends/keychain-linux';
import { withPlatform } from '../backends/child-recorder.test-support';

/**
 * #376: on a platform with no OS keychain implementation the factory builds
 * the local encrypted file for `keychain`, and the resolver read that file as
 * the keychain. With `process.platform` reported as `win32` and `local`
 * configured, `secret://keychain/STRIPE_KEY` resolved to the encrypted file's
 * STRIPE_KEY as `backend: 'keychain'`, with the factory's fallback line as the
 * one line on stderr.
 *
 * The real factory and the encrypted file, under a home of their own, with
 * `process.platform` reporting the platform under test. The suite runs with
 * SECRETLESS_OS_KEYCHAIN=off (vitest.config.ts), so no OS keychain is asked
 * for anything.
 */
const HELD = 'held-by-the-encrypted-file';
const URI = 'secret://keychain/STRIPE_KEY';
const FALLBACK_LINE = 'Falling back to local encrypted backend';

describe('resolveRef: a reference naming the keychain (#376)', () => {
  const saved = {
    HOME: process.env.HOME,
    VAULT_ADDR: process.env.VAULT_ADDR,
    VAULT_TOKEN: process.env.VAULT_TOKEN,
  };
  let root: string;
  let stderr: ReturnType<typeof vi.spyOn>;

  /** Everything written to stderr through console.error so far, as one string. */
  const stderrText = (): string => stderr.mock.calls.map((call: unknown[]) => call.join(' ')).join('\n');

  /** Store STRIPE_KEY in the encrypted file, as `secret set` does on `platform`. */
  async function storeInEncryptedFile(configured: 'local' | undefined): Promise<void> {
    if (configured !== undefined) writeBackendConfig(configured);
    const file = createBackend('local');
    expect(file.name).toBe('local');
    await file.store('secret/STRIPE_KEY', HELD);
  }

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-resolver-no-keychain-test-'));
    fs.mkdirSync(path.join(root, 'home'));
    process.env.HOME = path.join(root, 'home');
    delete process.env.VAULT_ADDR;
    delete process.env.VAULT_TOKEN;
    stderr = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  describe.each(['win32', 'freebsd'] as const)('on %s, which has no keychain implementation', (platform) => {
    const refusal = `Backend "keychain" named by ${URI} is not reachable: OS keychain is not supported on ${platform}. No other store was read in its place.`;

    it.each([
      ['`local` configured', 'local'],
      ['no backend configured', undefined],
    ] as const)('with %s, is not answered by the encrypted file in its place', async (_label, configured) => {
      const outcome = await withPlatform(platform, async () => {
        await storeInEncryptedFile(configured);
        return resolveRef(URI).then(
          (r) => r,
          (e: Error) => e,
        );
      });

      // Before the fix: { value: 'held-by-the-encrypted-file', backend: 'keychain' }.
      expect(outcome).toBeInstanceOf(RefResolutionError);
      const error = outcome as RefResolutionError;
      expect(error.message).toBe(refusal);
      expect(error.ref).toBe(URI);
      expect(error.backend).toBe('keychain');
      // The factory was not asked to build a keychain, so it announced no fallback.
      expect(stderrText()).not.toContain(FALLBACK_LINE);
    });

    it('resolveEnvRefs reports the reference and leaves it in the environment as written', async () => {
      const { resolved, errors } = await withPlatform(platform, async () => {
        await storeInEncryptedFile('local');
        return resolveEnvRefs({ STRIPE_KEY: URI, PLAIN: 'not-a-reference' });
      });

      // Before the fix: resolved.STRIPE_KEY was the encrypted file's value, with no error.
      expect(resolved).toEqual({ STRIPE_KEY: URI, PLAIN: 'not-a-reference' });
      expect(errors).toEqual([{ message: refusal, ref: URI, backend: 'keychain' }]);
    });

    it('CONTROL: the encrypted file holds the value and the factory builds it for `keychain`, so the tests above can fail', async () => {
      await withPlatform(platform, async () => {
        await storeInEncryptedFile('local');

        expect(hasKeychainImplementation()).toBe(false);
        const built = createBackend('keychain', undefined, true, { role: 'named' });
        expect(built.name).toBe('local');
        expect(await built.resolve('secret/STRIPE_KEY')).toEqual({ 'secret/STRIPE_KEY': HELD });
        expect(stderrText()).toContain(FALLBACK_LINE);

        // The file answers a reference that names it.
        const byName = await resolveRef('secret://local/STRIPE_KEY');
        expect(byName.value).toBe(HELD);
        expect(byName.backend).toBe('local');
      });
    });
  });

  describe.each([
    ['darwin', MacOSKeychainBackend, 'keychain-macos'],
    ['linux', LinuxKeychainBackend, 'keychain-linux'],
  ] as const)('on %s, which has a keychain implementation', (platform, Keychain, name) => {
    it('is put to the keychain backend, not refused as unsupported', async () => {
      // The switch refuses the keychain's own program before it starts, so the
      // read below finds nothing and no OS keychain is asked.
      expect(process.env.SECRETLESS_OS_KEYCHAIN, 'vitest.config.ts sets the switch').toBe('off');
      const asked = vi.spyOn(Keychain.prototype, 'resolve');

      const outcome = await withPlatform(platform, async () => {
        writeBackendConfig('local');
        await createBackend('local').store('secret/STRIPE_KEY', HELD);

        expect(hasKeychainImplementation()).toBe(true);
        expect(createBackend('keychain', undefined, true, { role: 'named' }).name).toBe(name);
        return resolveRef(URI).then(
          (r) => r,
          (e: Error) => e,
        );
      });

      expect(asked.mock.calls).toEqual([['secret/STRIPE_KEY']]);
      expect(outcome).toBeInstanceOf(RefResolutionError);
      expect((outcome as RefResolutionError).message).toBe(`Secret not found: ${URI}`);
      expect(stderrText()).not.toContain(FALLBACK_LINE);
    });
  });
});
