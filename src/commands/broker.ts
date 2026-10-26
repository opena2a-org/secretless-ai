import * as path from 'path';
import { startDaemon, stopDaemon, getLiveDaemonStatus } from '../broker/daemon';
import { TOKEN_FILE } from '../broker/server';
import type { BrokerRoutes } from '../broker/types';
import { formatUptime } from './utils';
import { escapeForDisplay } from '../display-safe';
import { EXIT_USAGE } from '../argv';

/** The rule the usage states under the start options, wrapped to the terminal when printed. */
const ROUTE_RULE =
  'POST /grant and POST /resolve are on only when their files load. With no path given, the ' +
  'broker loads ~/.secretless-ai/broker-grants.json and ~/.secretless-ai/broker-policies.json ' +
  'when they exist. A path named on the command line must exist.';

export async function runBroker(args: string[]): Promise<number> {
  const subcommand = args[0];

  switch (subcommand) {
    case 'start': {
      // Parse optional flags
      let aimUrl: string | undefined;
      let aimToken: string | undefined;
      let port: number | undefined;
      let policyFile: string | undefined;
      let grantFile: string | undefined;
      let noResolve = false;

      for (let i = 1; i < args.length; i++) {
        if (args[i] === '--aim-url' && args[i + 1]) {
          aimUrl = args[++i];
        } else if (args[i] === '--aim-token' && args[i + 1]) {
          aimToken = args[++i];
        } else if (args[i] === '--port' && args[i + 1]) {
          const parsed = parseInt(args[++i], 10);
          if (!isNaN(parsed) && parsed > 0 && parsed <= 65535) {
            port = parsed;
          } else {
            // Refused before the broker starts, so EXIT_USAGE; exit 1 is
            // left to a broker that could not start (#471).
            console.error(`\n  Invalid port: ${escapeForDisplay(args[i])}. Must be 1-65535.\n`);
            return EXIT_USAGE;
          }
        } else if (args[i] === '--policy-file' && args[i + 1]) {
          policyFile = path.resolve(args[++i]);
        } else if (args[i] === '--grant-file' && args[i + 1]) {
          grantFile = path.resolve(args[++i]);
        } else if (args[i] === '--no-resolve') {
          noResolve = true;
        }
      }

      // A named policy file turns /resolve on and --no-resolve keeps it off. Refused before
      // the broker starts, so EXIT_USAGE (#471).
      if (noResolve && policyFile !== undefined) {
        console.error(
          '\n  --no-resolve together with --policy-file is refused: --policy-file turns on ' +
          'POST /resolve, and --no-resolve keeps it off. Pass one of them.\n',
        );
        return EXIT_USAGE;
      }

      console.log('\n  Secretless Broker\n');
      console.log('  Starting credential broker daemon...');

      try {
        const server = await startDaemon({ aimUrl, aimToken, httpPort: port, policyFile, grantFile, noResolve });
        const info = server.getStatus();
        console.log('  Broker is running.\n');
        console.log(`  PID:          ${info.pid}`);
        console.log(`  HTTP port:    ${info.httpPort}`);
        console.log(`  Socket:       ${info.socketPath}`);
        // startDaemon is given no tokenFile, so the token is at the default path, which
        // `broker status` and `broker stop` read.
        console.log(`  Token file:   ${escapeForDisplay(TOKEN_FILE)}`);
        console.log(`  AIM:          ${formatAimStatus(info.aimConfigured, info.aimReachable)}${aimUrl ? ` — ${aimUrl}` : ''}`);
        for (const row of routeRows(info.routes, info.policyCount, { policyFileNamed: policyFile !== undefined })) {
          console.log(row);
        }
        console.log('\n  Press Ctrl+C to stop.\n');
        // The broker runs in this process, in the foreground. Returning here
        // would hand an exit code to the dispatcher, whose process.exit() ends
        // the broker that was just reported running. The process ends in the
        // SIGTERM/SIGINT handler startDaemon installs, which closes the server
        // and removes the PID file first.
        return await new Promise<number>(() => {});
      } catch (err) {
        console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
        return 1;
      }
    }

    case 'stop': {
      const stopped = stopDaemon();
      if (stopped) {
        console.log('\n  Broker daemon stopped.\n');
      } else {
        console.log('\n  Broker daemon is not running.\n');
      }
      return 0;
    }

    case 'status': {
      const brokerStatus = await getLiveDaemonStatus();
      if (!brokerStatus) {
        console.log('\n  Broker daemon is not running.\n');
        return 0;
      }

      const uptime = formatUptime(brokerStatus.uptimeSeconds);

      console.log('\n  Secretless Broker Status\n');
      console.log(`  Status:       running`);
      console.log(`  PID:          ${brokerStatus.pid}`);
      console.log(`  Uptime:       ${uptime}`);
      console.log(`  Started at:   ${brokerStatus.startedAt}`);
      console.log(`  HTTP port:    ${brokerStatus.httpPort}`);
      console.log(`  Socket:       ${brokerStatus.socketPath}`);
      console.log(`  AIM:          ${formatAimStatus(brokerStatus.aimConfigured, brokerStatus.aimReachable)}`);
      // Only from a live reply that carried the routes: the PID file does not say which routes
      // the broker serves, and a row the broker did not report would be a claim.
      if ('routes' in brokerStatus) {
        for (const row of routeRows(brokerStatus.routes, brokerStatus.policyCount)) console.log(row);
      }
      console.log(`  Policies:     ${brokerStatus.policyCount}`);
      console.log(`  Requests:     ${brokerStatus.requestCount}`);
      console.log();
      return 0;
    }

    case '--help':
    case '-h':
    default: {
      const isUnknown = subcommand && subcommand !== '--help' && subcommand !== '-h';
      if (isUnknown) {
        console.error(`\n  Unknown broker command: ${escapeForDisplay(subcommand)}`);
      }
      console.log('\n  Usage: secretless-ai broker <start|stop|status>\n');
      console.log('  Commands:');
      console.log('    start    Start the credential broker daemon (foreground)');
      console.log('    stop     Stop the running broker daemon');
      console.log('    status   Show broker daemon status\n');
      console.log('  Start options:');
      console.log('    --aim-url <url>        AIM server URL for identity verification');
      console.log('    --aim-token <token>    Bearer token for AIM auth (or env SECRETLESS_AIM_TOKEN)');
      console.log('    --port <port>          HTTP port (default: 19421)');
      console.log('    --grant-file <path>    Grant file path (turns on POST /grant)');
      console.log('    --policy-file <path>   Policy file path (turns on POST /resolve)');
      console.log('    --no-resolve           Keep POST /resolve off (default policy file not read)\n');
      console.log(`${wrapWords(ROUTE_RULE, '  ', 80).join('\n')}\n`);
      console.log('  Serve grants only:');
      console.log('    secretless-ai broker start --grant-file <path> --no-resolve\n');
      // Asked for, the usage is the answer. With no subcommand nothing ran,
      // so that exits EXIT_USAGE as an unknown one does (#127).
      return subcommand === '--help' || subcommand === '-h' ? 0 : EXIT_USAGE;
    }
  }
}

export function formatAimStatus(configured: boolean, reachable: boolean): string {
  if (!configured) return 'not configured';
  if (reachable) return 'configured (reachable)';
  return 'configured (unreachable)';
}

/**
 * The `Grants:` and `Resolve:` rows for a broker's routes. `broker start` and `broker status`
 * both print them from here, so the same state reads byte for byte alike on both screens.
 *
 * A row names no file and no count the routes did not carry: the routes `broker status` prints
 * come from the running daemon's reply, which another build may have written. A reason this
 * build does not know prints `off` alone, never the reply's string.
 *
 * `start` adds the lines only the start screen carries: the `Public key:` row under a served
 * `Grants:`, with a note when this start created the key, and, when the default policy file
 * turned `/resolve` on beside served grants, a note that names `--no-resolve`. A policy file
 * named on the command line states its intent and gets no note.
 */
export function routeRows(
  routes: BrokerRoutes,
  policyCount: number,
  start?: { policyFileNamed: boolean },
): string[] {
  const rows: string[] = [];

  const grant = routes.grant;
  const source = grant.served && grant.source !== null && typeof grant.source === 'object' ? grant.source : null;
  let grants = 'off, no grant file';
  if (grant.served) {
    grants = 'on';
    if (typeof source?.file === 'string') {
      grants += `, grant file ${escapeForDisplay(source.file)}`;
      if (typeof source.bindingCount === 'number' && typeof source.providerCount === 'number') {
        grants += ` (${countOf(source.bindingCount, 'binding')}, ${countOf(source.providerCount, 'provider')})`;
      }
    }
  }
  rows.push(`  Grants:       ${grants}`);
  if (start && typeof source?.assertionPublicKeyFile === 'string') {
    rows.push(`  Public key:   ${escapeForDisplay(source.assertionPublicKeyFile)}`);
    if (source.assertionKeyCreated === true) {
      rows.push('                Register this new key with each provider in the grant file.');
    }
  }

  const resolve = routes.resolve;
  let resolveValue: string;
  if (resolve.served) {
    const rules = countOf(policyCount, 'rule');
    resolveValue = typeof resolve.policyFile === 'string'
      ? `on, policy file ${escapeForDisplay(resolve.policyFile)} (${rules})`
      : `on (${rules})`;
  } else if (resolve.reason === 'noPolicyFile') {
    resolveValue = 'off, no policy file';
  } else if (resolve.reason === 'disabled') {
    resolveValue = 'off, --no-resolve';
  } else {
    resolveValue = 'off';
  }
  rows.push(`  Resolve:      ${resolveValue}`);
  if (start && !start.policyFileNamed && grant.served && resolve.served) {
    rows.push('                Pass --no-resolve to serve grants only.');
  }

  return rows;
}

function countOf(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

/** `text` in lines of at most `width` columns, each led by `indent`, broken between words. */
function wrapWords(text: string, indent: string, width: number): string[] {
  const lines: string[] = [];
  let line = '';
  for (const word of text.split(' ')) {
    if (line && indent.length + line.length + 1 + word.length > width) {
      lines.push(indent + line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(indent + line);
  return lines;
}
