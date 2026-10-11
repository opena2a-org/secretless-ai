/**
 * Issue #111: `backend` reported the CONFIGURED value while `secret list`
 * reported the CONSTRUCTED one, so on a default machine the two commands
 * disagreed about where secrets physically go.
 *
 * The property that matters is agreement between what `backend` prints and what
 * SecretStore actually built — asserted here against the real factory, not a
 * restated platform mapping.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { effectiveBackendName, createBackend } from './factory';
import { writeBackendConfig } from './config';
import { SecretStore } from '../secret-store';

const unwrap = (n: string) => n.replace(/^cached\((.*)\)$/, '$1');

describe('effectiveBackendName agrees with the constructed backend', () => {
  let home: string;
  let originalHome: string | undefined;

  // Only the unconfigured default upgrades `local` to a keychain (#327), so
  // every test starts from an empty home of its own: the result must not depend
  // on whether the person running the suite has run `backend set`.
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-effective-name-'));
    originalHome = process.env.HOME;
    process.env.HOME = home;
  });

  afterEach(() => {
    if (originalHome !== undefined) {
      process.env.HOME = originalHome;
    } else {
      delete process.env.HOME;
    }
    fs.rmSync(home, { recursive: true, force: true });
  });

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

  it('names the encrypted file once a backend is configured', () => {
    // After `backend set local`, `local` is the encrypted file on every
    // platform, and `backend` must say so as `secret list` does (#327).
    writeBackendConfig('local');
    expect(effectiveBackendName('local')).toBe('local');
    expect(unwrap(createBackend('local').name)).toBe('local');
  });

  it('leaves every non-local type alone', () => {
    // createBackend only remaps `local`; anything else must pass through
    // untouched, and must not be probed for this display.
    for (const t of ['keychain', '1password', 'vault', 'gcp-sm'] as const) {
      expect(effectiveBackendName(t)).toBe(t);
    }
  });
});
