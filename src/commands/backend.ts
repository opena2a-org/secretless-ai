import * as path from 'path';
import { isKeychainAvailable, isKeychainLikely, isOnePasswordAvailable, isOnePasswordLikely, createBackend, effectiveBackendName } from '../backends/factory';
import { isGCPAvailable } from '../backends/gcp-sm';
import { readBackendConfig, writeBackendConfig, resolveBackendType, readCacheTtl, writeCacheTtl, parseDuration, formatTtl } from '../backends/config';
import { clearCacheFile } from '../backends/cache';
import { migrateSecrets } from '../backends/migrate';
import type { SelectableBackendType } from '../backends/config';

export async function runBackend(args: string[]): Promise<number> {
  const subcommand = args[0];

  if (subcommand === 'list') {
    const backendType = resolveBackendType();
    const backend = createBackend(backendType);

    try {
      const [mcpEntries, secretEntries] = await Promise.all([
        backend.resolve('mcp'),
        backend.resolve('secret'),
      ]);
      const mcpKeys = Object.keys(mcpEntries).sort();
      const secretKeys = Object.keys(secretEntries).sort();
      const total = mcpKeys.length + secretKeys.length;

      console.log('\n  Secretless Backend Entries\n');

      if (total === 0) {
        console.log('  No entries found.\n');
        return 0;
      }

      if (mcpKeys.length > 0) {
        console.log(`  mcp/ (${mcpKeys.length} ${mcpKeys.length === 1 ? 'entry' : 'entries'}):`);
        for (const key of mcpKeys) {
          console.log(`    ${key}`);
        }
        console.log();
      }

      if (secretKeys.length > 0) {
        console.log(`  secret/ (${secretKeys.length} ${secretKeys.length === 1 ? 'entry' : 'entries'}):`);
        for (const key of secretKeys) {
          console.log(`    ${key}`);
        }
        console.log();
      }

      console.log(`  Total: ${total} ${total === 1 ? 'entry' : 'entries'}\n`);
      return 0;
    } catch (err) {
      console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
      return 1;
    }
  }

  if (subcommand === 'purge') {
    const hasYes = args.includes('--yes');
    let prefixFilter: string | undefined;
    const prefixIdx = args.indexOf('--prefix');
    if (prefixIdx !== -1 && args[prefixIdx + 1]) {
      const val = args[prefixIdx + 1];
      if (val !== 'mcp' && val !== 'secret') {
        console.error(`\n  Unknown prefix: ${val}. Use 'mcp' or 'secret'.\n`);
        return 1;
      }
      prefixFilter = val;
    }

    const backendType = resolveBackendType();
    const backend = createBackend(backendType);
    const prefixes = prefixFilter ? [prefixFilter] : ['mcp', 'secret'];

    try {
      const results = await Promise.all(prefixes.map(p => backend.resolve(p)));
      const keysByPrefix: Record<string, string[]> = {};
      for (let i = 0; i < prefixes.length; i++) {
        const keys = Object.keys(results[i]);
        if (keys.length > 0) {
          keysByPrefix[prefixes[i]] = keys;
        }
      }

      const allKeys = Object.values(keysByPrefix).flat();
      if (allKeys.length === 0) {
        console.log('\n  No entries to purge.\n');
        return 0;
      }

      if (!hasYes) {
        console.log(`\n  This will delete ${allKeys.length} ${allKeys.length === 1 ? 'entry' : 'entries'} from the ${backendType} backend.\n`);
        for (const [prefix, keys] of Object.entries(keysByPrefix)) {
          console.log(`  ${prefix}/:  ${keys.length}`);
        }
        console.log(`\n  To confirm, run: secretless-ai backend purge${prefixFilter ? ` --prefix ${prefixFilter}` : ''} --yes\n`);
        return 0;
      }

      let deleted = 0;
      let failed = 0;
      for (const key of allKeys) {
        const ok = await backend.delete(key);
        if (ok) {
          deleted++;
        } else {
          failed++;
        }
      }

      if (prefixFilter) {
        console.log(`\n  Deleted ${deleted} ${prefixFilter}/ ${deleted === 1 ? 'entry' : 'entries'} from ${backendType}.`);
      } else {
        console.log(`\n  Deleted ${deleted} ${deleted === 1 ? 'entry' : 'entries'} from ${backendType}.`);
      }
      if (failed > 0) {
        console.log(`  Failed: ${failed}`);
      }
      console.log('  Re-import secrets: npx secretless-ai import .env');
      console.log();
      return 0;
    } catch (err) {
      console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
      return 1;
    }
  }

  if (subcommand === 'set') {
    const type = args[1];
    if (type !== 'local' && type !== 'keychain' && type !== '1password' && type !== 'vault' && type !== 'gcp-sm') {
      console.error(`\n  Unknown backend type: ${type ?? '(none)'}. Use 'local', 'keychain', '1password', 'vault', or 'gcp-sm'.\n`);
      return 1;
    }

    if (type === 'keychain') {
      const kc = isKeychainAvailable();
      if (!kc.available) {
        console.error(`\n  Cannot use keychain backend: ${kc.message}\n`);
        return 1;
      }
    }

    if (type === '1password') {
      const op = isOnePasswordAvailable();
      if (!op.available) {
        console.error(`\n  Cannot use 1Password backend: ${op.message}\n`);
        return 1;
      }
    }

    if (type === 'vault') {
      if (!process.env.VAULT_ADDR || !process.env.VAULT_TOKEN) {
        console.error('\n  Cannot use Vault backend: VAULT_ADDR and VAULT_TOKEN must be set.\n');
        console.error('  Set them in your shell profile:');
        console.error('    export VAULT_ADDR=http://127.0.0.1:8200');
        console.error('    export VAULT_TOKEN=<your-token>\n');
        return 1;
      }
    }

    if (type === 'gcp-sm') {
      const gcp = isGCPAvailable();
      if (!gcp.available) {
        console.error(`\n  Cannot use GCP Secret Manager backend: ${gcp.message}\n`);
        return 1;
      }
    }

    writeBackendConfig(type);
    console.log(`\n  Backend set to: ${type}\n`);
    console.log('  Run `npx secretless-ai protect-mcp` to re-protect MCP servers with the new backend.');
    console.log('  Or use `npx secretless-ai migrate` to migrate existing secrets.\n');
    return 0;
  }

  // Default: show current backend status.
  // Use the prompt-free *Likely() probes so listing the available backends
  // never triggers Touch ID or a "1Password Access Requested" dialog. Run
  // `npx secretless-ai backend set <type>` to invoke the active probe when
  // the user actually wants to switch.
  const current = resolveBackendType();
  const configFile = readBackendConfig();
  const kc = isKeychainLikely();
  const op = isOnePasswordLikely();

  // Report the backend that will actually be CONSTRUCTED, not just the
  // configured value. `local` upgrades to the platform keychain where one
  // exists, and those two stores differ in ways a user acts on: the keychain is
  // shared across every project on the machine and can prompt for
  // authorization, the local encrypted file does neither (#111).
  const effective = effectiveBackendName(current);

  console.log('\n  Secretless Backend\n');
  if (effective !== current) {
    console.log(`  Current:      ${effective}  (configured: ${current}, upgraded because a platform keychain is available)`);
  } else {
    console.log(`  Current:      ${effective}${configFile ? '' : ' (default)'}`);
  }
  console.log(`  Config file:  ${configFile ?? '(not set)'}`);
  console.log(`  Keychain:     ${kc.available ? 'likely available' : 'unavailable'} (${kc.message})`);
  console.log(`  1Password:    ${op.available ? 'likely available' : 'unavailable'} (${op.message})`);
  const vaultAddr = process.env.VAULT_ADDR;
  const vaultConfigured = !!(vaultAddr && process.env.VAULT_TOKEN);
  console.log(`  Vault:        ${vaultConfigured ? 'configured' : 'not configured'} (${vaultConfigured ? vaultAddr : 'set VAULT_ADDR + VAULT_TOKEN'})`);
  const gcp = isGCPAvailable();
  console.log(`  GCP SM:       ${gcp.available ? 'available' : 'unavailable'} (${gcp.message})`);
  console.log(`  Platform:     ${kc.platform}`);
  console.log();
  console.log('  Commands:');
  console.log('    npx secretless-ai backend set local       Use local encrypted file');
  console.log('    npx secretless-ai backend set keychain     Use OS keychain');
  console.log('    npx secretless-ai backend set 1password    Use 1Password vault');
  console.log('    npx secretless-ai backend set vault        Use HashiCorp Vault');
  console.log('    npx secretless-ai backend set gcp-sm       Use GCP Secret Manager');
  console.log('    npx secretless-ai backend list             List all stored entries');
  console.log('    npx secretless-ai backend purge            Delete all entries (--yes to confirm)');
  console.log();
  return 0;
}

export async function runMigrate(args: string[]): Promise<number> {
  let fromType: SelectableBackendType | undefined;
  let toType: SelectableBackendType | undefined;

  const validBackends = ['local', 'keychain', '1password', 'vault', 'gcp-sm'];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--from' && args[i + 1]) {
      const val = args[++i];
      if (validBackends.includes(val)) {
        fromType = val as SelectableBackendType;
      } else {
        console.error(`\n  Unknown backend type: ${val}. Valid: ${validBackends.join(', ')}\n`);
        return 1;
      }
    }
    if (args[i] === '--to' && args[i + 1]) {
      const val = args[++i];
      if (validBackends.includes(val)) {
        toType = val as SelectableBackendType;
      } else {
        console.error(`\n  Unknown backend type: ${val}. Valid: ${validBackends.join(', ')}\n`);
        return 1;
      }
    }
  }

  if (!fromType || !toType) {
    console.error('\n  Usage: npx secretless-ai migrate --from <local|keychain|1password|vault|gcp-sm> --to <local|keychain|1password|vault|gcp-sm>\n');
    return 1;
  }

  if (fromType === toType) {
    console.error(`\n  Source and destination backends are the same: ${fromType}\n`);
    return 1;
  }

  // Validate vault env vars before attempting migration
  const vaultBackends = [fromType, toType].filter(t => t === 'vault');
  if (vaultBackends.length > 0 && (!process.env.VAULT_ADDR || !process.env.VAULT_TOKEN)) {
    console.error('\n  Vault backend requires VAULT_ADDR and VAULT_TOKEN environment variables.\n');
    console.error('  Set them in your shell:');
    console.error('    export VAULT_ADDR=http://127.0.0.1:8200');
    console.error('    export VAULT_TOKEN=<your-token>\n');
    return 1;
  }

  // Validate GCP credentials before attempting migration
  const gcpBackends = [fromType, toType].filter(t => t === 'gcp-sm');
  if (gcpBackends.length > 0) {
    const gcp = isGCPAvailable();
    if (!gcp.available) {
      console.error(`\n  GCP Secret Manager backend requires credentials: ${gcp.message}\n`);
      return 1;
    }
  }

  console.log('\n  Secretless Migration\n');
  console.log(`  From: ${fromType}`);
  console.log(`  To:   ${toType}\n`);

  const source = createBackend(fromType, undefined, true);
  const destination = createBackend(toType, undefined, true);

  // Migrate all known prefixes. Some backends (keychain, 1password) return nothing
  // for empty prefix -- we need to resolve each prefix explicitly.
  const PREFIXES = ['secret', 'mcp'];

  try {
    const perPrefix = await Promise.all(
      PREFIXES.map(p => migrateSecrets(source, destination, { deleteFromSource: false, prefix: p }))
    );
    const result = perPrefix.reduce(
      (acc, r) => ({
        migrated: acc.migrated + r.migrated,
        failed: acc.failed + r.failed,
        errors: [...acc.errors, ...r.errors],
      }),
      { migrated: 0, failed: 0, errors: [] as Array<{ key: string; message: string }> },
    );

    if (result.migrated === 0 && result.failed === 0) {
      console.log('  No secrets found to migrate.\n');
      return 0;
    }

    console.log(`  Migrated: ${result.migrated} secret(s)`);
    if (result.failed > 0) {
      console.log(`  Failed:   ${result.failed} secret(s)`);
      for (const err of result.errors) {
        console.log(`    - ${err.key}: ${err.message}`);
      }
    }
    console.log();

    // Update config to use the new backend
    writeBackendConfig(toType!);
    console.log(`  Backend config updated to: ${toType}`);
    console.log('  Run `npx secretless-ai protect-mcp` to update MCP wrapper configs.\n');
    return result.failed > 0 ? 1 : 0;
  } catch (err) {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

export function runCache(args: string[]): number {
  const subcommand = args[0];

  if (subcommand === 'clear') {
    const removed = clearCacheFile();
    if (removed) {
      console.log('\n  Cache cleared.\n');
    } else {
      console.log('\n  No cache file found.\n');
    }
    return 0;
  }

  if (subcommand === 'ttl') {
    const value = args[1];

    if (!value) {
      // Show current TTL
      const current = readCacheTtl();
      console.log(`\n  Cache TTL: ${formatTtl(current)}${current <= 0 ? ' (disabled)' : ''}\n`);
      return 0;
    }

    const seconds = parseDuration(value);
    if (seconds < 0) {
      console.error(`\n  Invalid duration: "${value}". Use: 5m, 1h, 1d, 300, or off\n`);
      return 1;
    }

    writeCacheTtl(seconds);
    if (seconds <= 0) {
      // Also clear existing cache when disabling
      clearCacheFile();
      console.log('\n  Cache disabled. Existing cache cleared.\n');
    } else {
      console.log(`\n  Cache TTL set to ${formatTtl(seconds)}.\n`);
    }
    return 0;
  }

  // Default: show cache status
  const ttl = readCacheTtl();
  // The EFFECTIVE backend, not the configured one: `local` upgrades to the
  // platform keychain, which DOES prompt. Keying this off the configured value
  // printed "Not needed (local backend has no auth prompts)" on a machine whose
  // secrets were going to the keychain — advice that was exactly backwards.
  const backendType = effectiveBackendName(resolveBackendType());
  const needsCache = backendType.startsWith('keychain') || backendType === '1password';

  console.log('\n  Secret Cache\n');
  console.log(`  Backend:  ${backendType}`);
  console.log(`  TTL:      ${formatTtl(ttl)}${ttl <= 0 ? ' (disabled)' : ''}`);

  if (!needsCache) {
    console.log(`  Status:   Not needed (${backendType} backend has no auth prompts)`);
  } else if (ttl <= 0) {
    console.log('  Status:   Disabled');
  } else {
    console.log('  Status:   Active');
  }

  console.log('\n  Commands:');
  console.log('    secretless-ai cache ttl <duration>  Set cache TTL (5m, 1h, 1d, off)');
  console.log('    secretless-ai cache clear           Clear cached secrets');
  console.log();
  return 0;
}
