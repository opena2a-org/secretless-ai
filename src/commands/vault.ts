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

export async function runVault(args: string[]): Promise<number> {
  const subcommand = args[0];

  switch (subcommand) {
    case 'init':
      return handleInit(args.slice(1));
    case 'register':
      return handleRegister(args.slice(1));
    case 'list':
    case 'ls':
      return handleList();
    case 'rotate':
      return handleRotate(args.slice(1));
    case 'revoke':
      return handleRevoke(args.slice(1));
    case 'audit':
      return handleAudit(args.slice(1));
    case 'scan':
      return handleScan(args.slice(1));
    case 'exec':
      return handleExec(args.slice(1));
    case 'test':
      return handleTest();
    case 'migrate':
      return handleMigrate(args.slice(1));
    case '--help':
    case '-h':
      printVaultHelp();
      return 0;
    default: {
      const isUnknown = subcommand && subcommand !== '--help' && subcommand !== '-h';
      if (isUnknown) {
        console.error(`\n  Unknown vault command: ${subcommand}`);
      }
      printVaultHelp();
      return isUnknown ? 1 : 0;
    }
  }
}

// ── Subcommand handlers ────────────────────────────────────────────

async function handleInit(args: string[]): Promise<number> {
  const agentName = parseFlag(args, '--name');
  try {
    await vaultInit(agentName ?? undefined);
    return 0;
  } catch (err) {
    return handleError(err);
  }
}

async function handleRegister(args: string[]): Promise<number> {
  const namespace = args[0];
  if (!namespace || namespace.startsWith('-')) {
    console.error('\n  Usage: secretless-ai vault register <namespace> [options]\n');
    console.error('  Options:');
    console.error('    --value <value>       Credential value (or pipe via stdin)');
    console.error('    --env <VAR>           Read value from environment variable');
    console.error('    --description <desc>  Namespace description');
    console.error('    --operations <ops>    Comma-separated: read,write,delete,admin');
    console.error('    --url-patterns <pats> Comma-separated URL patterns\n');
    return 1;
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

  try {
    await vaultRegister(namespace, {
      value: value ?? undefined,
      envVar: envVar ?? undefined,
      description: description ?? undefined,
      operations,
      urlPatterns,
    });
    return 0;
  } catch (err) {
    return handleError(err);
  }
}

async function handleList(): Promise<number> {
  try {
    await vaultList();
    return 0;
  } catch (err) {
    return handleError(err);
  }
}

async function handleRotate(args: string[]): Promise<number> {
  const namespace = args[0];
  if (!namespace || namespace.startsWith('-')) {
    console.error('\n  Usage: secretless-ai vault rotate <namespace> [--value <value>] [--env <VAR>]\n');
    return 1;
  }

  const value = parseFlag(args, '--value');
  const envVar = parseFlag(args, '--env');

  try {
    await vaultRotate(namespace, {
      value: value ?? undefined,
      envVar: envVar ?? undefined,
    });
    return 0;
  } catch (err) {
    return handleError(err);
  }
}

async function handleRevoke(args: string[]): Promise<number> {
  const namespace = args[0];
  if (!namespace || namespace.startsWith('-')) {
    console.error('\n  Usage: secretless-ai vault revoke <namespace>\n');
    return 1;
  }

  try {
    await vaultRevoke(namespace);
    return 0;
  } catch (err) {
    return handleError(err);
  }
}

async function handleAudit(args: string[]): Promise<number> {
  const limitStr = parseFlag(args, '--limit');
  const since = parseFlag(args, '--since');
  const namespace = parseFlag(args, '--namespace');

  try {
    await vaultAudit({
      limit: limitStr ? parseInt(limitStr, 10) : undefined,
      since: since ?? undefined,
      namespace: namespace ?? undefined,
    });
    return 0;
  } catch (err) {
    return handleError(err);
  }
}

async function handleScan(args: string[]): Promise<number> {
  const dir = args.find(a => !a.startsWith('-'));
  try {
    await vaultScan(dir);
    return 0;
  } catch (err) {
    return handleError(err);
  }
}

async function handleExec(args: string[]): Promise<number> {
  // Parse: vault exec <namespace> [--env-name VAR] -- <command...>
  const dashDashIdx = args.indexOf('--');
  if (dashDashIdx === -1) {
    console.error('\n  Usage: secretless-ai vault exec <namespace> -- <command> [args...]\n');
    console.error('  Example:');
    console.error('    secretless-ai vault exec github -- curl https://api.github.com/user');
    console.error('    secretless-ai vault exec aws-prod --env-name AWS_SECRET_ACCESS_KEY -- aws s3 ls\n');
    return 1;
  }

  const preArgs = args.slice(0, dashDashIdx);
  const command = args.slice(dashDashIdx + 1);

  const namespace = preArgs[0];
  if (!namespace || namespace.startsWith('-')) {
    console.error('\n  Error: namespace is required before --\n');
    return 1;
  }

  const envName = parseFlag(preArgs, '--env-name');

  try {
    return await vaultExec(namespace, command, {
      envName: envName ?? undefined,
    });
  } catch (err) {
    return handleError(err);
  }
}

async function handleTest(): Promise<number> {
  try {
    await vaultTest();
    return 0;
  } catch (err) {
    return handleError(err);
  }
}

async function handleMigrate(args: string[]): Promise<number> {
  const dryRun = args.includes('--dry-run');
  const envFile = parseFlag(args, '--env-file');

  try {
    await vaultMigrate({
      dryRun,
      envFile: envFile ?? undefined,
    });
    return 0;
  } catch (err) {
    return handleError(err);
  }
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

function handleError(err: unknown): number {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`\n  Error: ${message}\n`);
  return 1;
}
