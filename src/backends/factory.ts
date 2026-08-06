/**
 * Backend factory — creates the appropriate WritableSecretBackend based on type.
 *
 * Dispatches 'keychain' to the platform-specific implementation (macOS or Linux).
 * Dispatches '1password' to the OnePasswordBackend (requires `op` CLI).
 * Falls back to 'local' on unsupported platforms with a console message.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { LocalBackend } from './local';
import { MacOSKeychainBackend } from './keychain-macos';
import { LinuxKeychainBackend } from './keychain-linux';
import { OnePasswordBackend } from './onepassword';
import { VaultBackend } from './vault';
import { GCPSecretManagerBackend, isGCPAvailable } from './gcp-sm';
import { CachedBackend } from './cache';
import { readCacheTtl } from './config';
import type { WritableSecretBackend } from './types';
import type { SelectableBackendType } from './config';

/**
 * Create a WritableSecretBackend instance for the given type.
 *
 * When type is 'local', attempts to upgrade to 'keychain' if the OS keychain
 * is available (macOS Keychain, Linux Secret Service, or Windows Credential
 * Manager). Falls back to 'local' only when keychain initialization fails.
 *
 * When the caller explicitly configured a non-local backend and that backend is
 * unavailable, this THROWS rather than substituting a different store.
 * Substituting is never a safe degradation for a credential manager: a write
 * lands in a store the user did not choose while reporting success, and a read
 * reports "no secrets" from an empty store the user never populated. Both look
 * like success. See `unavailableBackendError` for the recovery message.
 *
 * @param type   - 'local', 'keychain', '1password', 'vault', or 'gcp-sm'
 * @param config - Backend-specific configuration (e.g. storeDir, key, vault)
 * @param strict - Default TRUE. Pass false ONLY for read-only diagnostics that
 *                 must render something even when the backend is down, and that
 *                 disclose which backend actually answered.
 */
export function createBackend(
  type: SelectableBackendType,
  config?: Record<string, unknown>,
  strict: boolean = true,
): WritableSecretBackend {
  let backend: WritableSecretBackend;

  // When callers request 'local', prefer keychain if the platform supports it.
  // Use the prompt-free Likely check here — this path runs from MCP wrappers,
  // brokers, and resolvers that must not trigger Touch ID. Real auth happens
  // lazily on the first secret read/write.
  if (type === 'local' && !config?.key) {
    const keychainStatus = isKeychainLikely();
    if (keychainStatus.available) {
      try {
        backend = createKeychainBackend(config);
        const ttlSeconds = readCacheTtl();
        if (ttlSeconds > 0) {
          return new CachedBackend(backend, { ttlMs: ttlSeconds * 1000 });
        }
        return backend;
      } catch {
        // Keychain initialization failed — fall through to local
      }
    }
  }

  switch (type) {
    case 'keychain':
      backend = createKeychainBackend(config);
      break;

    case '1password': {
      const op = isOnePasswordAvailable();
      if (!op.available) {
        if (strict) {
          throw unavailableBackendError('1password', op.message, [
            'brew install 1password-cli && op signin',
            'Enable "Integrate with 1Password CLI" in the 1Password app under Settings > Developer',
          ], 'op account get');
        }
        return degradedFallback('1password', op.message, config);
      }
      backend = new OnePasswordBackend(config);
      break;
    }

    case 'vault': {
      if (!process.env.VAULT_ADDR || !process.env.VAULT_TOKEN) {
        const why = 'VAULT_ADDR and VAULT_TOKEN must be set';
        if (strict) {
          throw unavailableBackendError('vault', why, [
            'export VAULT_ADDR=https://vault.example.com VAULT_TOKEN=<token>',
          ], 'vault token lookup');
        }
        return degradedFallback('vault', why, config);
      }
      backend = new VaultBackend(config);
      break;
    }

    case 'gcp-sm': {
      const gcp = isGCPAvailable();
      if (!gcp.available) {
        if (strict) {
          throw unavailableBackendError('gcp-sm', gcp.message, [
            'gcloud auth application-default login',
          ], 'gcloud auth application-default print-access-token');
        }
        return degradedFallback('gcp-sm', gcp.message, config);
      }
      backend = new GCPSecretManagerBackend(config);
      break;
    }

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
 * Build the error raised when a user-configured backend cannot be reached.
 *
 * The message has to do four things, because this is the moment a user decides
 * whether the tool is trustworthy or broken:
 *   - name the backend THEY chose, so it reads as a connection problem
 *   - state that nothing was lost and nothing was written elsewhere
 *   - give a command that VERIFIES the diagnosis independently
 *   - give the command that FIXES it, and the explicit opt-out
 * No dead ends: every line the user reads ends in something they can run.
 */
export function unavailableBackendError(
  type: SelectableBackendType,
  why: string,
  fixes: string[],
  verifyCmd: string,
): Error {
  // `why` is the `.message` of a caught error and can carry newlines. Left as
  // is, it breaks the block apart and the Verify/Fix lines stop reading as a
  // list — the recovery instructions are the whole point of this message.
  const reason = why.replace(/\s+/g, ' ').trim();

  const lines = [
    `Configured backend "${type}" is not reachable: ${reason}`,
    '',
    `  Your secrets are safe. Nothing was read from or written to another store.`,
    '',
    `  Verify:  ${verifyCmd}`,
  ];
  for (const fix of fixes) {
    lines.push(`  Fix:     ${fix}`);
  }
  lines.push(
    '',
    `  Secretless will not silently use a different store, because a secret`,
    `  written to the wrong one looks like success and is found by nothing.`,
    `  To move to a different backend deliberately:`,
    `    secretless-ai backend migrate --from ${type} --to local`,
  );
  return new Error(lines.join('\n'));
}

/**
 * Non-strict path: return the local store, but say plainly that the answer
 * comes from a DIFFERENT store than the one configured, so a caller rendering
 * "no entries" cannot be misread as "the configured backend is empty".
 *
 * Only read-only diagnostics should reach this.
 */
function degradedFallback(
  type: SelectableBackendType,
  why: string,
  config?: Record<string, unknown>,
): WritableSecretBackend {
  console.error(`secretless: backend "${type}" unreachable (${why}).`);
  console.error(`  Showing the local store instead. Entries in "${type}" are NOT listed below.\n`);
  return new LocalBackend(config);
}

/**
 * Cheap, prompt-free signal that the OS keychain is likely usable.
 *
 * Safe for read-only commands (`backend` with no subcommand, `status`,
 * `--version`) and for the local-to-keychain upgrade in `createBackend`.
 * NEVER shells out to a binary that could prompt for biometrics — on macOS
 * even `security default-keychain` can trigger Touch ID under certain configs.
 */
export function isKeychainLikely(): { available: boolean; platform: string; message: string } {
  const platform = process.platform;

  if (platform === 'darwin') {
    return { available: true, platform: 'macOS', message: 'macOS Keychain assumed available (not probed)' };
  }

  if (platform === 'linux') {
    if (binaryOnPath('secret-tool')) {
      return { available: true, platform: 'Linux', message: 'secret-tool found on PATH (not probed)' };
    }
    return {
      available: false,
      platform: 'Linux',
      message: 'secret-tool not found. Install libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/RHEL).',
    };
  }

  return {
    available: false,
    platform: platform,
    message: `OS keychain is not supported on ${platform}. Using local encrypted backend.`,
  };
}

/**
 * Cheap, prompt-free signal that the 1Password CLI is likely usable.
 *
 * Checks PATH for the `op` binary without invoking it. Safe for read-only
 * commands. The active probe (`op account get`) triggers the
 * "1Password Access Requested" dialog on Macs with the desktop app — only
 * call `isOnePasswordAvailable()` from genuine pre-flight paths.
 */
export function isOnePasswordLikely(): { available: boolean; message: string } {
  if (binaryOnPath('op')) {
    return { available: true, message: '1Password CLI (op) found on PATH (auth not probed)' };
  }
  return {
    available: false,
    message: '1Password CLI (op) not found. Install from https://developer.1password.com/docs/cli',
  };
}

function binaryOnPath(name: string): boolean {
  const PATH = process.env.PATH || '';
  const sep = process.platform === 'win32' ? ';' : ':';
  const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE').split(';') : [''];
  for (const dir of PATH.split(sep)) {
    if (!dir) continue;
    for (const ext of exts) {
      try {
        const candidate = path.join(dir, name + ext);
        fs.accessSync(candidate, fs.constants.X_OK);
        return true;
      } catch {
        // not here, keep looking
      }
    }
  }
  return false;
}

/**
 * Check if the OS keychain is available on the current platform.
 * Returns a description of the keychain status.
 *
 * Note: on macOS this shells out to `security default-keychain`, which can
 * trigger Touch ID under some configurations. Prefer `isKeychainLikely()`
 * for read-only display paths; reserve this for genuine pre-flight checks
 * (e.g. `backend set keychain`).
 */
export function isKeychainAvailable(): { available: boolean; platform: string; message: string } {
  const platform = process.platform;

  if (platform === 'darwin') {
    try {
      execFileSync('security', ['default-keychain'], { stdio: 'pipe' });
      return { available: true, platform: 'macOS', message: 'macOS Keychain is available' };
    } catch {
      return { available: false, platform: 'macOS', message: 'macOS Keychain is not accessible' };
    }
  }

  if (platform === 'linux') {
    try {
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
 *
 * Note: this calls `op account get`, which triggers a "1Password Access
 * Requested" dialog on Macs with the 1Password desktop app integration
 * enabled. Reserve for genuine pre-flight checks (e.g. `backend set
 * 1password`); use `isOnePasswordLikely()` for read-only display paths.
 */
export function isOnePasswordAvailable(): { available: boolean; message: string } {
  try {
    execFileSync('op', ['--version'], { stdio: 'pipe' });
  } catch {
    return {
      available: false,
      message: '1Password CLI (op) not found. Install from https://developer.1password.com/docs/cli',
    };
  }

  try {
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

/**
 * Name of the backend `createBackend` would actually construct for `type`.
 *
 * `local` is the only type that gets remapped: it upgrades to the platform
 * keychain when one is available (#34). `backend` reported the CONFIGURED value
 * while `secret list` reported the CONSTRUCTED one, so on a default machine the
 * two commands disagreed about where secrets physically go (#111).
 *
 * Reuses `createKeychainBackend` rather than restating the platform-to-name
 * mapping, so this cannot drift out of agreement with the thing it describes.
 * Prompt-free: `isKeychainLikely()` does not probe, and the keychain
 * constructors only prepare a directory — real auth is lazy, on first read or
 * write.
 */
export function effectiveBackendName(type: SelectableBackendType): string {
  if (type !== 'local') return type;
  if (process.platform !== 'darwin' && process.platform !== 'linux') return 'local';
  if (!isKeychainLikely().available) return 'local';
  try {
    return createKeychainBackend().name;
  } catch {
    // Same fall-through createBackend takes when keychain init fails.
    return 'local';
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
