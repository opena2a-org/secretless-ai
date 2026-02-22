/**
 * Backend factory — creates the appropriate WritableSecretBackend based on type.
 *
 * Dispatches 'keychain' to the platform-specific implementation (macOS or Linux).
 * Falls back to 'local' on unsupported platforms with a console message.
 */

import { LocalBackend } from './local';
import { MacOSKeychainBackend } from './keychain-macos';
import { LinuxKeychainBackend } from './keychain-linux';
import type { WritableSecretBackend } from './types';
import type { SelectableBackendType } from './config';

/**
 * Create a WritableSecretBackend instance for the given type.
 *
 * @param type   - 'local' or 'keychain'
 * @param config - Backend-specific configuration (e.g. storeDir, key)
 */
export function createBackend(
  type: SelectableBackendType,
  config?: Record<string, unknown>,
): WritableSecretBackend {
  switch (type) {
    case 'keychain':
      return createKeychainBackend(config);

    case 'local':
    default:
      return new LocalBackend(config);
  }
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
