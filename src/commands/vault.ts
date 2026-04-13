/**
 * CLI handlers for the vault command.
 * Dispatches to vault-core.ts functions.
 * Follows the runBroker() pattern from commands/broker.ts.
 */

import {
  vaultInit,
  vaultRegister,
  vaultList,
  vaultRotate,
  vaultRevoke,
  vaultAudit,
  vaultScan,
  vaultExec,
  vaultTest,
  vaultMigrate,
} from '../vault-core';

export function runVault(args: string[]): void {
  const subcommand = args[0];

  switch (subcommand) {
    case 'init':
      handleInit(args.slice(1));
      break;
    case 'register':
      handleRegister(args.slice(1));
      break;
    case 'list':
    case 'ls':
      handleList();
      break;
    case 'rotate':
      handleRotate(args.slice(1));
      break;
    case 'revoke':
      handleRevoke(args.slice(1));
      break;
    case 'audit':
      handleAudit(args.slice(1));
      break;
    case 'scan':
      handleScan(args.slice(1));
      break;
    case 'exec':
      handleExec(args.slice(1));
      break;
    case 'test':
      handleTest();
      break;
    case 'migrate':
      handleMigrate(args.slice(1));
      break;
    case '--help':
    case '-h':
      printVaultHelp();
      break;
    default: {
      const isUnknown = subcommand && subcommand !== '--help' && subcommand !== '-h';
      if (isUnknown) {
        console.error(`\n  Unknown vault command: ${subcommand}`);
      }
      printVaultHelp();
      if (isUnknown) process.exit(1);
      break;
    }
  }
}

// ── Subcommand handlers ────────────────────────────────────────────

function handleInit(args: string[]): void {
  const agentName = parseFlag(args, '--name');
  vaultInit(agentName ?? undefined).catch(handleError);
}

function handleRegister(args: string[]): void {
  const namespace = args[0];
  if (!namespace || namespace.startsWith('-')) {
    console.error('\n  Usage: secretless-ai vault register <namespace> [options]\n');
    console.error('  Options:');
    console.error('    --value <value>       Credential value (or pipe via stdin)');
    console.error('    --env <VAR>           Read value from environment variable');
    console.error('    --description <desc>  Namespace description');
    console.error('    --operations <ops>    Comma-separated: read,write,delete,admin');
    console.error('    --url-patterns <pats> Comma-separated URL patterns\n');
    process.exit(1);
    return;
  }

  const value = parseFlag(args, '--value');
  const envVar = parseFlag(args, '--env');
  const description = parseFlag(args, '--description');
  const opsStr = parseFlag(args, '--operations');
  const urlStr = parseFlag(args, '--url-patterns');

  const operations = opsStr
    ? opsStr.split(',').map(o => o.trim()) as Array<'read' | 'write' | 'delete' | 'admin'>
    : undefined;
  const urlPatterns = urlStr ? urlStr.split(',').map(u => u.trim()) : undefined;

  vaultRegister(namespace, {
    value: value ?? undefined,
    envVar: envVar ?? undefined,
    description: description ?? undefined,
    operations,
    urlPatterns,
  }).catch(handleError);
}

function handleList(): void {
  vaultList().catch(handleError);
}

function handleRotate(args: string[]): void {
  const namespace = args[0];
  if (!namespace || namespace.startsWith('-')) {
    console.error('\n  Usage: secretless-ai vault rotate <namespace> [--value <value>] [--env <VAR>]\n');
    process.exit(1);
    return;
  }

  const value = parseFlag(args, '--value');
  const envVar = parseFlag(args, '--env');

  vaultRotate(namespace, {
    value: value ?? undefined,
    envVar: envVar ?? undefined,
  }).catch(handleError);
}

function handleRevoke(args: string[]): void {
  const namespace = args[0];
  if (!namespace || namespace.startsWith('-')) {
    console.error('\n  Usage: secretless-ai vault revoke <namespace>\n');
    process.exit(1);
    return;
  }

  vaultRevoke(namespace).catch(handleError);
}

function handleAudit(args: string[]): void {
  const limitStr = parseFlag(args, '--limit');
  const since = parseFlag(args, '--since');
  const namespace = parseFlag(args, '--namespace');

  vaultAudit({
    limit: limitStr ? parseInt(limitStr, 10) : undefined,
    since: since ?? undefined,
    namespace: namespace ?? undefined,
  }).catch(handleError);
}

function handleScan(args: string[]): void {
  const dir = args.find(a => !a.startsWith('-'));
  vaultScan(dir).catch(handleError);
}

function handleExec(args: string[]): void {
  // Parse: vault exec <namespace> [--env-name VAR] -- <command...>
  const dashDashIdx = args.indexOf('--');
  if (dashDashIdx === -1) {
    console.error('\n  Usage: secretless-ai vault exec <namespace> -- <command> [args...]\n');
    console.error('  Example:');
    console.error('    secretless-ai vault exec github -- curl https://api.github.com/user');
    console.error('    secretless-ai vault exec aws-prod --env-name AWS_SECRET_ACCESS_KEY -- aws s3 ls\n');
    process.exit(1);
    return;
  }

  const preArgs = args.slice(0, dashDashIdx);
  const command = args.slice(dashDashIdx + 1);

  const namespace = preArgs[0];
  if (!namespace || namespace.startsWith('-')) {
    console.error('\n  Error: namespace is required before --\n');
    process.exit(1);
    return;
  }

  const envName = parseFlag(preArgs, '--env-name');

  vaultExec(namespace, command, {
    envName: envName ?? undefined,
  }).then((code) => {
    process.exit(code);
  }).catch(handleError);
}

function handleTest(): void {
  vaultTest().catch(handleError);
}

function handleMigrate(args: string[]): void {
  const dryRun = args.includes('--dry-run');
  const envFile = parseFlag(args, '--env-file');

  vaultMigrate({
    dryRun,
    envFile: envFile ?? undefined,
  }).catch(handleError);
}

// ── Help ───────────────────────────────────────────────────────────

function printVaultHelp(): void {
  console.log(`
  Usage: secretless-ai vault <command> [options]

  Identity Vault — encrypted, identity-bound credential storage.
  Credentials never enter the agent's process memory (CR-001).

  Commands:
    init                     Initialize vault with agent identity
    register <ns> [opts]     Register a credential in a namespace
    list                     List stored credentials (metadata only)
    rotate <ns> [opts]       Rotate a credential to a new value
    revoke <ns>              Revoke a namespace (delete credential)
    audit                    Show vault audit log
    scan [dir]               Scan for credentials to migrate
    exec <ns> -- <cmd>       Execute command with vault credential
    test                     Run vault self-test
    migrate [opts]           Migrate from SecretStore or .env file

  Register options:
    --value <value>          Credential value (or pipe via stdin)
    --env <VAR>              Read value from environment variable
    --description <desc>     Namespace description
    --operations <ops>       Comma-separated: read,write,delete,admin
    --url-patterns <pats>    Comma-separated URL patterns

  Exec options:
    --env-name <VAR>         Env var name for the credential (default: NAMESPACE)

  Migrate options:
    --env-file <path>        Migrate from a .env file
    --dry-run                Preview without migrating

  Audit options:
    --limit <n>              Max events to show (default: 50)
    --since <ISO-date>       Events after this timestamp
    --namespace <ns>         Filter by namespace

  Examples:
    secretless-ai vault init
    secretless-ai vault register github --value ghp_abc123
    secretless-ai vault register aws --env AWS_SECRET_ACCESS_KEY
    secretless-ai vault exec github -- curl https://api.github.com/user
    secretless-ai vault migrate --env-file .env --dry-run
    secretless-ai vault audit --limit 10
`);
}

// ── Utilities ──────────────────────────────────────────────────────

/** Parse a --flag value pair from args */
function parseFlag(args: string[], flag: string): string | null {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return null;
  return args[idx + 1];
}

function handleError(err: unknown): void {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`\n  Error: ${message}\n`);
  process.exit(1);
}
