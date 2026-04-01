import * as path from 'path';
import { startDaemon, stopDaemon, getDaemonStatus } from '../broker/daemon';
import { formatUptime } from './utils';

export function runBroker(args: string[]): void {
  const subcommand = args[0];

  switch (subcommand) {
    case 'start': {
      // Parse optional flags
      let aimUrl: string | undefined;
      let port: number | undefined;
      let policyFile: string | undefined;

      for (let i = 1; i < args.length; i++) {
        if (args[i] === '--aim-url' && args[i + 1]) {
          aimUrl = args[++i];
        } else if (args[i] === '--port' && args[i + 1]) {
          const parsed = parseInt(args[++i], 10);
          if (!isNaN(parsed) && parsed > 0 && parsed <= 65535) {
            port = parsed;
          } else {
            console.error(`\n  Invalid port: ${args[i]}. Must be 1-65535.\n`);
            process.exit(1);
          }
        } else if (args[i] === '--policy-file' && args[i + 1]) {
          policyFile = path.resolve(args[++i]);
        }
      }

      console.log('\n  Secretless Broker\n');
      console.log('  Starting credential broker daemon...');

      startDaemon({ aimUrl, httpPort: port, policyFile }).then((server) => {
        const info = server.getStatus();
        console.log('  Broker is running.\n');
        console.log(`  PID:          ${info.pid}`);
        console.log(`  HTTP port:    ${info.httpPort}`);
        console.log(`  Socket:       ${info.socketPath}`);
        console.log(`  AIM:          ${aimUrl ?? 'not configured'}`);
        console.log(`  Policy file:  ${policyFile ?? '(default)'}`);
        console.log('\n  Press Ctrl+C to stop.\n');
      }).catch((err) => {
        console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
        process.exit(1);
      });
      break;
    }

    case 'stop': {
      const stopped = stopDaemon();
      if (stopped) {
        console.log('\n  Broker daemon stopped.\n');
      } else {
        console.log('\n  Broker daemon is not running.\n');
      }
      break;
    }

    case 'status': {
      const brokerStatus = getDaemonStatus();
      if (!brokerStatus) {
        console.log('\n  Broker daemon is not running.\n');
        break;
      }

      const uptime = formatUptime(brokerStatus.uptimeSeconds);

      console.log('\n  Secretless Broker Status\n');
      console.log(`  Status:       running`);
      console.log(`  PID:          ${brokerStatus.pid}`);
      console.log(`  Uptime:       ${uptime}`);
      console.log(`  Started at:   ${brokerStatus.startedAt}`);
      console.log(`  HTTP port:    ${brokerStatus.httpPort}`);
      console.log(`  Socket:       ${brokerStatus.socketPath}`);
      console.log(`  AIM:          ${brokerStatus.aimConnected ? 'connected' : 'not connected'}`);
      console.log(`  Policies:     ${brokerStatus.policyCount}`);
      console.log(`  Requests:     ${brokerStatus.requestCount}`);
      console.log();
      break;
    }

    case '--help':
    case '-h':
    default: {
      const isUnknown = subcommand && subcommand !== '--help' && subcommand !== '-h';
      if (isUnknown) {
        console.error(`\n  Unknown broker command: ${subcommand}`);
      }
      console.log('\n  Usage: secretless-ai broker <start|stop|status>\n');
      console.log('  Commands:');
      console.log('    start    Start the credential broker daemon (foreground)');
      console.log('    stop     Stop the running broker daemon');
      console.log('    status   Show broker daemon status\n');
      console.log('  Start options:');
      console.log('    --aim-url <url>        AIM server URL for identity verification');
      console.log('    --port <port>          HTTP port (default: 19421)');
      console.log('    --policy-file <path>   Policy file path\n');
      if (isUnknown) process.exit(1);
      break;
    }
  }
}
