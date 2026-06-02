import { SecretStore } from '../secret-store';
import { resolveBackendType } from '../backends/config';
import { discoverScope, listBaselines, resetBaseline, loadBaseline, detectProvider } from '../scope';

export async function runScope(args: string[]): Promise<number> {
  const subcommand = args[0];

  switch (subcommand) {
    case 'discover': {
      const credentialName = args[1];
      if (!credentialName) {
        console.error('\n  Usage: secretless-ai scope discover <credential-name>\n');
        console.log('  Reads the credential value from the secret store and discovers its scope.\n');
        return 1;
      }

      const store = new SecretStore({ backendType: resolveBackendType() });
      let value: string | undefined;
      try {
        value = await store.getSecret(credentialName);
      } catch (err) {
        console.error(`\n  Error reading credential: ${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
      if (!value) {
        console.error(`\n  Credential "${credentialName}" not found in secret store.\n`);
        return 1;
      }

      console.log(`\n  Scope Discovery: ${credentialName}\n`);

      const provider = detectProvider(value);
      if (!provider) {
        console.error('  Unable to detect credential provider.');
        console.log('  Supported: GCP service account key (JSON), Vault token (hvs./s. prefix), AWS access key (AKIA/ASIA prefix)\n');
        return 1;
      }

      console.log(`  Provider: ${provider.toUpperCase()}`);
      console.log('  Discovering permissions...\n');

      try {
        const result = await discoverScope(credentialName, value, { saveAsBaseline: true });

        console.log(`  Permissions found: ${result.currentPermissions.length}`);
        if (result.currentPermissions.length > 0) {
          for (const p of result.currentPermissions) {
            console.log(`    - ${p}`);
          }
        }

        if (result.baselinePermissions.length > 0) {
          console.log(`\n  Baseline comparison:`);
          console.log(`    Previous: ${result.baselinePermissions.length} permissions`);
          console.log(`    Current:  ${result.currentPermissions.length} permissions`);

          if (result.added.length > 0) {
            console.log(`\n  EXPANDED: +${result.added.length} new permissions`);
            for (const p of result.added) {
              console.log(`    + ${p}`);
            }
          }
          if (result.removed.length > 0) {
            console.log(`\n  Contracted: -${result.removed.length} removed permissions`);
            for (const p of result.removed) {
              console.log(`    - ${p}`);
            }
          }
          if (result.added.length === 0 && result.removed.length === 0) {
            console.log('    No changes since last baseline.');
          }
        } else {
          console.log('\n  First baseline saved. Future checks will compare against this.');
        }

        console.log(`\n  Baseline saved at: ${result.checkedAt}\n`);
        return 0;
      } catch (err) {
        console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
    }

    case 'check': {
      const credentialName = args[1];
      if (!credentialName) {
        console.error('\n  Usage: secretless-ai scope check <credential-name>\n');
        console.log('  Re-checks scope and compares to stored baseline.\n');
        return 1;
      }

      const baseline = loadBaseline(credentialName);
      if (!baseline) {
        console.error(`\n  No baseline found for "${credentialName}".`);
        console.log('  Run "secretless-ai scope discover" first to create a baseline.\n');
        return 1;
      }

      const store = new SecretStore({ backendType: resolveBackendType() });
      let value: string | undefined;
      try {
        value = await store.getSecret(credentialName);
      } catch (err) {
        console.error(`\n  Error reading credential: ${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
      if (!value) {
        console.error(`\n  Credential "${credentialName}" not found in secret store.\n`);
        return 1;
      }

      try {
        const result = await discoverScope(credentialName, value, { saveAsBaseline: false });

        console.log(`\n  Scope Check: ${credentialName}`);
        console.log(`  Provider: ${result.provider.toUpperCase()}`);
        console.log(`  Last baseline: ${baseline.checkedAt}`);
        console.log(`  Current permissions: ${result.currentPermissions.length}`);
        console.log(`  Baseline permissions: ${result.baselinePermissions.length}`);

        if (result.hasExpanded) {
          console.log(`  EXPANDED: +${result.added.length} new permissions detected`);
          for (const p of result.added) {
            console.log(`    + ${p}`);
          }
          console.log(`\n  WARNING: Credential scope has expanded since baseline.`);
          console.log(`  Run 'secretless-ai scope discover ${credentialName}' to update baseline.\n`);
        } else if (result.removed.length > 0) {
          console.log(`  Contracted: -${result.removed.length} removed permissions`);
          for (const p of result.removed) {
            console.log(`    - ${p}`);
          }
          console.log();
        } else {
          console.log('  No changes since baseline.\n');
        }
        return 0;
      } catch (err) {
        console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
    }

    case 'list': {
      const baselines = listBaselines();
      if (baselines.length === 0) {
        console.log('\n  No scope baselines stored.\n');
        console.log('  Run "secretless-ai scope discover <credential-name>" to create one.\n');
        return 0;
      }

      console.log('\n  Scope Baselines\n');
      for (const b of baselines) {
        console.log(`  ${b.credentialName}`);
        console.log(`    Provider:    ${b.provider.toUpperCase()}`);
        console.log(`    Permissions: ${b.permissions.length}`);
        console.log(`    Last check:  ${b.checkedAt}`);
        console.log();
      }
      return 0;
    }

    case 'reset': {
      const credentialName = args[1];
      if (!credentialName) {
        console.error('\n  Usage: secretless-ai scope reset <credential-name>\n');
        return 1;
      }

      const cleared = resetBaseline(credentialName);
      if (cleared) {
        console.log(`\n  Baseline for "${credentialName}" cleared.`);
        console.log('  Next discover will create a fresh baseline.\n');
      } else {
        console.log(`\n  No baseline found for "${credentialName}".\n`);
      }
      return 0;
    }

    default: {
      // No subcommand is an exploration, not an error — show usage cleanly and succeed
      // (mirrors the `secret` fix in #80). Reserve the error for a real unrecognized token.
      const usage = () => {
        console.log('  Usage: secretless-ai scope <discover|check|list|reset>\n');
        console.log('  Commands:');
        console.log('    discover <name>   Discover permissions and save baseline');
        console.log('    check <name>      Re-check and compare to baseline');
        console.log('    list              Show all stored baselines');
        console.log('    reset <name>      Clear baseline for re-baseline\n');
      };
      if (subcommand === undefined) {
        console.log('');
        usage();
        return 0;
      }
      console.error(`\n  Unknown scope command: ${subcommand}`);
      usage();
      return 1;
    }
  }
}
