/**
 * Issue #111: `backend` reported the CONFIGURED value while `secret list`
 * reported the CONSTRUCTED one, so on a default machine the two commands
 * disagreed about where secrets physically go.
 *
 * The property that matters is agreement between what `backend` prints and what
 * SecretStore actually built — asserted here against the real factory, not a
 * restated platform mapping.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import { effectiveBackendName, createBackend } from './factory';
import { SecretStore } from '../secret-store';

const unwrap = (n: string) => n.replace(/^cached\((.*)\)$/, '$1');

describe('effectiveBackendName agrees with the constructed backend', () => {
  it('matches what createBackend builds for local', () => {
    // The reported case: `backend` said local, `secret list` said keychain-macos.
    expect(effectiveBackendName('local')).toBe(unwrap(createBackend('local').name));
  });

  it('matches what SecretStore reports for the default config', () => {
    // SecretStore.backendName is the value `secret list` prints.
    const store = new SecretStore({ backendType: 'local' });
    expect(effectiveBackendName('local')).toBe(store.backendName);
  });

  it('names a keychain on a platform that has one', () => {
    // Guards the DIRECTION of the fix: where a keychain exists, "local" must
    // not be reported as the effective backend.
    //
    // This assertion used to be `toMatch(/^(keychain-(macos|linux)|local)$/)`,
    // which ACCEPTS the unfixed value `local` — so it passed whether or not the
    // fix was present and could not fail in the direction its own comment
    // claimed to guard. Availability is probed here independently (`security`
    // / `secret-tool` on PATH) rather than by calling the implementation's own
    // `isKeychainLikely`, which would only restate it.
    const name = effectiveBackendName('local');

    if (process.platform === 'darwin') {
      // The macOS keychain CLI ships with the OS, so there is no conditional:
      // this must resolve to the keychain, and `local` is a failure.
      expect(name).toBe('keychain-macos');
      return;
    }

    if (process.platform === 'linux') {
      const hasSecretTool = (() => {
        try {
          execFileSync('which', ['secret-tool'], { stdio: 'pipe' });
          return true;
        } catch {
          return false;
        }
      })();
      expect(name).toBe(hasSecretTool ? 'keychain-linux' : 'local');
      return;
    }

    expect(name).toBe('local');
  });

  it('leaves every non-local type alone', () => {
    // createBackend only remaps `local`; anything else must pass through
    // untouched, and must not be probed for this display.
    for (const t of ['keychain', '1password', 'vault', 'gcp-sm'] as const) {
      expect(effectiveBackendName(t)).toBe(t);
    }
  });
});
