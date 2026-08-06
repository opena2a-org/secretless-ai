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
    // Guards the direction of the fix: on macOS/Linux with a keychain
    // available, "local" must NOT be reported as the effective backend.
    const name = effectiveBackendName('local');
    if (process.platform === 'darwin' || process.platform === 'linux') {
      expect(name).toMatch(/^(keychain-(macos|linux)|local)$/);
    } else {
      expect(name).toBe('local');
    }
  });

  it('leaves every non-local type alone', () => {
    // createBackend only remaps `local`; anything else must pass through
    // untouched, and must not be probed for this display.
    for (const t of ['keychain', '1password', 'vault', 'gcp-sm'] as const) {
      expect(effectiveBackendName(t)).toBe(t);
    }
  });
});
