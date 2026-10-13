/**
 * Backend factory — creates the appropriate WritableSecretBackend based on type.
 *
 * Dispatches 'keychain' to the platform-specific implementation (macOS or Linux).
 * Dispatches '1password' to the OnePasswordBackend (requires `op` CLI).
 * Falls back to 'local' on unsupported platforms with a console message.
 */

import * as fs from 'fs';
import * as path from 'path';
import { LocalBackend } from './local';
import { MacOSKeychainBackend, SECURITY_PROGRAM } from './keychain-macos';
import { BACKEND_CHILD_TIMEOUT_MS, OsKeychainRefusedError, execFileSyncBounded } from './bounded-child';
import { LinuxKeychainBackend } from './keychain-linux';
import { OnePasswordBackend } from './onepassword';
import { VaultBackend } from './vault';
import { GCPSecretManagerBackend, isGCPAvailable } from './gcp-sm';
import { CachedBackend } from './cache';
import { readBackendConfig, readCacheTtl } from './config';
import type { WritableSecretBackend } from './types';
import type { SelectableBackendType } from './config';

/**
 * Create a WritableSecretBackend instance for the given type.
 *
 * When type is 'local' and no backend has been configured, attempts to upgrade
 * to 'keychain' if the OS keychain is available (macOS Keychain, Linux Secret
 * Service, or Windows Credential Manager). Falls back to 'local' only when
 * keychain initialization fails. A configured backend is never upgraded: after
 * `backend set local`, 'local' is the encrypted file (#327). Neither is one
 * named for a run: `setup --backend local` is the encrypted file (#365).
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
 * @param options.role - Default 'configured'. 'source' is a backend read
 *                 ALONGSIDE the configured one, such as the source of `secret
 *                 sync`. It is built without the cache layer: the cache file is
 *                 shared and keyed by entry name alone, so a value read from a
 *                 second backend through it is later served as the configured
 *                 backend's value for the same name. An unreachable-backend
 *                 error names it as the source and offers no migration.
 *                 'named' is a backend named for one run IN PLACE of the
 *                 configured one (`setup --backend`): `local` is the encrypted
 *                 file, never the keychain upgrade, and an unreachable-backend
 *                 error says it was named for this run and offers no migration.
 *                 It is built without the cache layer for the same reason a
 *                 source is, unless it names the store this machine uses
 *                 anyway (see `isConfiguredStore`): that store's values are
 *                 the ones the cache holds, and a write that went round the
 *                 cache would leave the value from before it being served.
 *                 A `secret://` reference names its backend for one read in
 *                 the same way and is built with this role (#369); its
 *                 resolver reports an unreachable backend against the
 *                 reference and never shows the `--backend` wording.
 */
export function createBackend(
  type: SelectableBackendType,
  config?: Record<string, unknown>,
  strict: boolean = true,
  options?: { role?: BackendRole },
): WritableSecretBackend {
  let backend: WritableSecretBackend;
  const role: BackendRole = options?.role ?? 'configured';
  const uncached = role === 'source' || (role === 'named' && !isConfiguredStore(type));
  const cacheTtl = (): number => (uncached ? 0 : readCacheTtl());

  // When callers request the default 'local', prefer keychain if the platform
  // supports it. Use the prompt-free Likely check here — this path runs from
  // MCP wrappers, brokers, and resolvers that must not trigger Touch ID. Real
  // auth happens lazily on the first secret read/write.
  if (role !== 'named' && upgradesToKeychain(type, config)) {
    const keychainStatus = isKeychainLikely();
    if (keychainStatus.available) {
      try {
        backend = createKeychainBackend(config);
        const ttlSeconds = cacheTtl();
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
          ], 'op account get', role);
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
          ], 'vault token lookup', role);
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
          ], 'gcloud auth application-default print-access-token', role);
        }
        return degradedFallback('gcp-sm', gcp.message, config);
      }
      const gcpBackend = new GCPSecretManagerBackend(config);
      // The value cache is one file keyed by secret name alone. A project named
      // by a repository's .secretless is one of several on this machine, so a
      // cached value would be served to the next repository that asks for the
      // same name from a different project (#177).
      if (gcpBackend.describeProject().source === 'manifest') {
        return gcpBackend;
      }
      backend = gcpBackend;
      break;
    }

    case 'local':
    default:
      // Local backend uses file-based encryption — no OS prompts, no cache needed
      return new LocalBackend(config);
  }

  // Wrap keychain and 1password backends with a TTL cache to reduce OS auth prompts
  const ttlSeconds = cacheTtl();
  if (ttlSeconds > 0) {
    return new CachedBackend(backend, { ttlMs: ttlSeconds * 1000 });
  }
  return backend;
}

/**
 * Whether a backend is this machine's configured store, one read alongside it,
 * or one named for a single run in its place.
 */
export type BackendRole = 'configured' | 'source' | 'named';

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
  role: BackendRole = 'configured',
): Error {
  // `why` is the `.message` of a caught error and can carry newlines. Left as
  // is, it breaks the block apart and the Verify/Fix lines stop reading as a
  // list — the recovery instructions are the whole point of this message.
  const reason = why.replace(/\s+/g, ' ').trim();

  const heading = {
    source: `Source backend "${type}" is not reachable: ${reason}`,
    named: `Backend "${type}", named with --backend, is not reachable: ${reason}`,
    configured: `Configured backend "${type}" is not reachable: ${reason}`,
  }[role];
  const assurance = role === 'source'
    ? '  Nothing was read from it, and nothing on this machine was changed.'
    : '  Your secrets are safe. Nothing was read from or written to another store.';
  const lines = [heading, '', assurance, '', `  Verify:  ${verifyCmd}`];
  for (const fix of fixes) {
    lines.push(`  Fix:     ${fix}`);
  }
  // A source is not the store secrets are written to, so there is nothing to
  // migrate away from.
  if (role === 'source') return new Error(lines.join('\n'));
  // Neither is a store named for one run: the configured one is unchanged.
  if (role === 'named') {
    lines.push(
      '',
      `  --backend chose "${type}" for this run only; the configured backend is`,
      `  unchanged. To use it, run the command again without --backend.`,
    );
    return new Error(lines.join('\n'));
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
 * Internal seam for the probes below, for tests only. Nothing outside a test
 * passes it, and nothing reads it from the environment, config or a flag.
 */
export interface ProbeInternals {
  /** Per-child bound. The default is the one named source in bounded-child.ts. */
  childTimeoutMs?: number;
}

/**
 * Every child the factory starts goes through here: the program as given
 * (absolute for `security`), the argv as given, and the bound from its one
 * source. A probe of a locked or wedged tool then returns "not available"
 * instead of never returning.
 */
function probe(program: string, args: string[], internals?: ProbeInternals): void {
  execFileSyncBounded(program, args, internals?.childTimeoutMs ?? BACKEND_CHILD_TIMEOUT_MS);
}

/**
 * Check if the OS keychain is available on the current platform.
 * Returns a description of the keychain status.
 *
 * Note: on macOS this shells out to `/usr/bin/security default-keychain`,
 * which can trigger Touch ID under some configurations. Prefer
 * `isKeychainLikely()` for read-only display paths; reserve this for genuine
 * pre-flight checks (e.g. `backend set keychain`). `security` is run by its
 * absolute path: a program of that name earlier on PATH never runs.
 *
 * Under `SECRETLESS_OS_KEYCHAIN=off` the probe is refused before it starts;
 * the answer is then "not available" with the refusal's own text, Verify and
 * Fix lines included, as the message, not a generic "not accessible".
 */
export function isKeychainAvailable(
  internals?: ProbeInternals,
): { available: boolean; platform: string; message: string } {
  const platform = process.platform;

  if (platform === 'darwin') {
    try {
      probe(SECURITY_PROGRAM, ['default-keychain'], internals);
      return { available: true, platform: 'macOS', message: 'macOS Keychain is available' };
    } catch (err) {
      if (err instanceof OsKeychainRefusedError) return { available: false, platform: 'macOS', message: err.message };
      return { available: false, platform: 'macOS', message: 'macOS Keychain is not accessible' };
    }
  }

  if (platform === 'linux') {
    try {
      probe('which', ['secret-tool'], internals);
      return { available: true, platform: 'Linux', message: 'secret-tool is available (Linux Secret Service)' };
    } catch (err) {
      if (err instanceof OsKeychainRefusedError) return { available: false, platform: 'Linux', message: err.message };
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
export function isOnePasswordAvailable(
  internals?: ProbeInternals,
): { available: boolean; message: string } {
  try {
    probe('op', ['--version'], internals);
  } catch {
    return {
      available: false,
      message: '1Password CLI (op) not found. Install from https://developer.1password.com/docs/cli',
    };
  }

  try {
    probe('op', ['account', 'get', '--format', 'json'], internals);
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
 * Whether a request for `local` is the unconfigured default, the one case that
 * upgrades to the platform keychain (#34).
 *
 * A config file that names any backend is a choice the user made. Upgrading an
 * explicit `backend set local` sent every secret to the keychain while the docs
 * and `backend set` both described `local` as the AES-256-GCM encrypted file,
 * and left no way to select that file on macOS (#327). With a backend
 * configured, `local` therefore means the file: whether it is the configured
 * backend, or the source of `migrate --from local` beside another one. A
 * `--backend local` given for one run is a choice as well, and `createBackend`
 * builds the file for it without asking this (#365).
 */
function upgradesToKeychain(type: SelectableBackendType, config?: Record<string, unknown>): boolean {
  return type === 'local' && !config?.key && readBackendConfig() === undefined;
}

/**
 * Whether `type`, named for one run, is the store this machine uses without
 * the flag: the configured backend, or the platform keychain the unconfigured
 * default upgrades to. Prompt-free, as `isKeychainLikely` is.
 *
 * Any other named backend is a second store beside the configured one, and
 * the shared cache must hold nothing of it: `setup --check --backend vault`
 * cached what Vault held, and `setup --check` then reported those names as
 * satisfied by a keychain that held none of them (#367). A `secret://`
 * reference naming a second store did the same on each read (#369).
 */
function isConfiguredStore(type: SelectableBackendType): boolean {
  const configured = readBackendConfig();
  if (configured !== undefined) return type === configured;
  return type === 'keychain' && isKeychainLikely().available;
}

/**
 * Name of the backend `createBackend` would actually construct for `type`.
 *
 * `local` is the only type that gets remapped: while no backend is configured,
 * it upgrades to the platform keychain when one is available (#34, #327).
 * `backend` reported the CONFIGURED value while `secret list` reported the
 * CONSTRUCTED one, so on a default machine the two commands disagreed about
 * where secrets physically go (#111).
 *
 * Reuses `createKeychainBackend` rather than restating the platform-to-name
 * mapping, so this cannot drift out of agreement with the thing it describes.
 * Prompt-free: `isKeychainLikely()` does not probe, and the keychain
 * constructors only prepare a directory — real auth is lazy, on first read or
 * write.
 */
export function effectiveBackendName(type: SelectableBackendType): string {
  if (!upgradesToKeychain(type)) return type;
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
