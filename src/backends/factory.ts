/**
 * Backend factory — creates the appropriate WritableSecretBackend based on type.
 *
 * Dispatches 'keychain' to the platform-specific implementation (macOS or Linux).
 * Dispatches '1password' to the OnePasswordBackend (requires `op` CLI).
 * Falls back to 'local' on unsupported platforms with a console message.
 */

import { LocalBackend } from './local';
import { MacOSKeychainBackend } from './keychain-macos';
import { LinuxKeychainBackend } from './keychain-linux';
import { OnePasswordBackend } from './onepassword';
import { VaultBackend } from './vault';
import { CachedBackend } from './cache';
import { readCacheTtl } from './config';
import type { WritableSecretBackend } from './types';
import type { SelectableBackendType } from './config';

/**
 * Create a WritableSecretBackend instance for the given type.
 *
 * @param type   - 'local', 'keychain', or '1password'
 * @param config - Backend-specific configuration (e.g. storeDir, key, vault)
 */
export function createBackend(
  type: SelectableBackendType,
  config?: Record<string, unknown>,
): WritableSecretBackend {
  let backend: WritableSecretBackend;

  switch (type) {
    case 'keychain':
      backend = createKeychainBackend(config);
      break;

    case '1password':
      backend = new OnePasswordBackend(config);
      break;

    case 'vault':
      backend = new VaultBackend(config);
      break;

    case 'local':
    default:
      // Local backend uses file-based encryption — no OS prompts, no cache needed
      return new LocalBackend(config);
  }

  // Wrap keychain and 1password backends with a TTL cache to reduce OS auth prompts
  const ttlSeconds = readCacheTtl();
  if (ttlSeconds > 0) {
    return new CachedBackend(backend, { ttlMs: ttlSeconds * 1000 });
  }
  return backend;
}

/**
 * Check if the OS keychain is available on the current platform.
 * Returns a description of the keychain status.
 */
export function isKeychainAvailable(): { available: boolean; platform: string; message: string } {
  const platform = process.platform;

  if (platform === 'darwin') {
    try {
      const { execFileSync } = require('child_process');
      execFileSync('security', ['default-keychain'], { stdio: 'pipe' });
      return { available: true, platform: 'macOS', message: 'macOS Keychain is available' };
    } catch {
      return { available: false, platform: 'macOS', message: 'macOS Keychain is not accessible' };
    }
  }

  if (platform === 'linux') {
    try {
      const { execFileSync } = require('child_process');
      execFileSync('which', ['secret-tool'], { stdio: 'pipe' });
      return { available: true, platform: 'Linux', message: 'secret-tool is available (Linux Secret Service)' };
    } catch {
      return {
        available: false,
        platform: 'Linux',
        message: 'secret-tool not found. Install libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/RHEL).',
      };
    }
  }

  return {
    available: false,
    platform: platform,
    message: `OS keychain is not supported on ${platform}. Using local encrypted backend.`,
  };
}

/**
 * Check if the 1Password CLI (`op`) is available and authenticated.
 * Returns availability status and an actionable message.
 */
export function isOnePasswordAvailable(): { available: boolean; message: string } {
  try {
    const { execFileSync } = require('child_process');
    execFileSync('op', ['--version'], { stdio: 'pipe' });
  } catch {
    return {
      available: false,
      message: '1Password CLI (op) not found. Install from https://developer.1password.com/docs/cli',
    };
  }

  try {
    const { execFileSync } = require('child_process');
    execFileSync('op', ['account', 'get', '--format', 'json'], { stdio: 'pipe' });
    return {
      available: true,
      message: '1Password CLI installed and authenticated',
    };
  } catch {
    return {
      available: false,
      message: '1Password CLI installed but not signed in. Run `op signin` or set OP_SERVICE_ACCOUNT_TOKEN.',
    };
  }
}

function createKeychainBackend(config?: Record<string, unknown>): WritableSecretBackend {
  const platform = process.platform;

  if (platform === 'darwin') {
    return new MacOSKeychainBackend(config);
  }

  if (platform === 'linux') {
    return new LinuxKeychainBackend(config);
  }

  // Unsupported platform — fall back to local with a message
  console.error(
    `secretless: OS keychain not supported on ${platform}. Falling back to local encrypted backend.`,
  );
  return new LocalBackend(config);
}
