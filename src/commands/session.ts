import { parseDuration } from '../backends/config';
import { warm } from '../session/warm';
import { getSessionStatus } from '../session/session-state';
import { installDaemon, uninstallDaemon, isDaemonInstalled } from '../session/install';
import { formatRemainingTime } from './utils';

export async function runWarm(args: string[]): Promise<number> {
  // Parse --ttl flag (accepts seconds or duration strings like 5m, 1h, 1d)
  let ttlSeconds: number | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--ttl' && args[i + 1]) {
      const raw = args[++i];
      const parsed = parseDuration(raw);
      if (parsed > 0) {
        ttlSeconds = parsed;
      } else {
        console.error(`\n  Invalid TTL: ${raw}. Examples: 300, 5m, 1h, 1d\n`);
        return 1;
      }
    }
  }

  const noBroker = args.includes('--no-broker');

  console.log('\n  Secretless Session\n');

  // Check if already warm
  const current = getSessionStatus(ttlSeconds);
  if (current.warm) {
    console.log('  Session is already warm.');
    console.log(`  Expires in:   ${formatRemainingTime(current.remainingSeconds)}`);
    console.log(`  Expires at:   ${current.expiresAt}`);
    console.log();
    return 0;
  }

  console.log('  Warming session...');

  try {
    const result = await warm(ttlSeconds, !noBroker);
    if (!result.sessionWarm) {
      console.error(`  Session warming failed.${result.error ? ` ${result.error}` : ''}`);
      console.log('  Try again or check system authentication settings.\n');
      return 1;
    }

    console.log('  Session is warm.\n');
    console.log(`  TTL:          ${result.session.ttlSeconds}s (${formatRemainingTime(result.session.ttlSeconds)})`);
    console.log(`  Expires at:   ${result.session.expiresAt}`);
    console.log(`  Touch ID:     ${result.touchIdUsed ? 'used' : 'not required'}`);

    if (result.cachePreloaded > 0) {
      console.log(`  Cache:        ${result.cachePreloaded} secret${result.cachePreloaded === 1 ? '' : 's'} preloaded`);
    } else {
      console.log('  Cache:        no secrets to preload');
    }

    if (result.brokerStarted) {
      console.log('  Broker:       started (was not running)');
    } else if (result.brokerRunning) {
      console.log('  Broker:       running');
    } else {
      console.log('  Broker:       not running (start with: secretless-ai broker start)');
    }

    console.log('\n  You can now use AI tools without repeated auth prompts.\n');
    return 0;
  } catch (err) {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

export function runInstall(args: string[]): number {
  const subcommand = args[0];

  if (subcommand === 'uninstall' || subcommand === 'remove') {
    const result = uninstallDaemon();
    console.log(`\n  ${result.message}\n`);
    return result.removed ? 0 : 1;
  }

  if (subcommand === 'status' || subcommand === 'check') {
    const installed = isDaemonInstalled();
    console.log(`\n  LaunchAgent: ${installed ? 'installed' : 'not installed'}`);
    if (!installed) {
      console.log('  Install: npx secretless-ai install');
    }
    console.log();
    return 0;
  }

  // Reject unknown subcommands
  if (subcommand && subcommand !== 'install') {
    console.error(`\n  Unknown install command: ${subcommand}`);
    console.log('  Usage:');
    console.log('    secretless-ai install              Install broker as login daemon');
    console.log('    secretless-ai install uninstall     Remove login daemon');
    console.log('    secretless-ai install status        Check installation status\n');
    return 1;
  }

  // Default: install
  console.log('\n  Secretless Installer\n');

  const result = installDaemon();

  if (result.installed) {
    console.log(`  Platform:     ${result.platform}`);
    console.log(`  Plist:        ${result.plistPath}`);
    console.log(`  Daemon:       ${result.loaded ? 'loaded and running' : 'installed (not loaded)'}`);
    console.log();

    if (result.loaded) {
      console.log('  Broker daemon will start automatically on login.');
      console.log('  Warm your session: npx secretless-ai warm\n');
    }
    return 0;
  }
  console.log(`  ${result.message}\n`);
  return 1;
}
