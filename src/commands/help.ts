import { VERSION, CLI, IS_EMBEDDED } from './utils';

/**
 * Subcommands whose runner handles `--help` itself, as its first statement and
 * before any side effect. Everything else falls through to top-level help,
 * because those runners would otherwise perform the action rather than
 * describe it (`init --help` once created a literal `--help/` directory).
 *
 * Lives here rather than in cli.ts because cli.ts runs `main()` on import,
 * so a test importing it would exit the process.
 */
export const OWN_HELP = new Set<string>(['setup', 'env']);


export function printHelp(): void {
  // When embedded under a host CLI (SECRETLESS_CLI_PREFIX set), suppress the
  // standalone `Secretless v<version>` brand+version line — it shows
  // secretless's own version, which is misleading under the host's umbrella.
  // The tagline stays. Standalone keeps the banner exactly as before.
  const banner = IS_EMBEDDED ? '' : `  Secretless v${VERSION}\n`;
  console.log(`
${banner}  Keep secrets out of AI context.

  Quick start:
    ${CLI} scan       Find hardcoded credentials
    ${CLI} init       Set up AI tool protections
    ${CLI} verify     Confirm secrets are hidden from AI

  Usage:
    ${CLI} init      Set up protections for your AI tools
    ${CLI} scan      Scan config and source files for hardcoded secrets (--json for CI)
    ${CLI} status    Show protection status (--json for CI)
    ${CLI} verify    Verify keys are usable but hidden from AI (--all for full list)
    ${CLI} doctor    Diagnose shell profile issues (--fix to auto-fix)
    ${CLI} clean     Scan and redact credentials in transcripts
    ${CLI} watch     Monitor transcripts in real-time
    ${CLI} warm      Warm biometric session (Touch ID on macOS)
    ${CLI} install   Install broker as login daemon (macOS)

  Secret Management:
    ${CLI} secret set <NAME[=VALUE]>  Store a secret
    ${CLI} secret list                List stored secret names
    ${CLI} secret get <NAME>          Retrieve a secret value
    ${CLI} secret get --force <NAME>  Retrieve in non-interactive contexts
    ${CLI} secret rm <NAME>           Remove a secret
    ${CLI} import <file>              Import secrets from .env file
    ${CLI} import --detect            Auto-find and import .env files
    ${CLI} run [--only K1,K2] -- <cmd>  Run with secrets injected
    ${CLI} env [--only K1,K2]         Output export statements for shell

  Project Setup:
    ${CLI} setup              Set up secrets from .secretless manifest
    ${CLI} setup --check      Check for missing required secrets (CI)

  Custom Rules:
    ${CLI} rules              List custom deny rules
    ${CLI} rules init         Create .secretless-rules.yaml template
    ${CLI} rules test <pat>   Test a pattern (see generated deny rules)

  Git Protection:
    ${CLI} hook install       Install pre-commit secret scanner
    ${CLI} hook uninstall     Remove pre-commit hook
    ${CLI} hook status        Check hook installation status

  MCP Protection:
    ${CLI} protect-mcp [--backend TYPE]  Encrypt MCP server secrets
    ${CLI} mcp-status     Show MCP protection status
    ${CLI} mcp-unprotect  Restore original MCP configs

  Backend Management:
    ${CLI} backend             Show current backend status
    ${CLI} backend set <type>  Set backend (local, keychain, 1password, vault, or gcp-sm)
    ${CLI} backend list        List all entries in current backend
    ${CLI} backend purge       Delete all entries (--prefix mcp|secret, --yes)
    ${CLI} migrate             Migrate secrets between backends

  Scope Discovery:
    ${CLI} scope discover <name>  Discover permissions and save baseline
    ${CLI} scope check <name>     Re-check and compare to baseline
    ${CLI} scope list             Show all stored baselines
    ${CLI} scope reset <name>     Clear baseline for re-baseline

  Scan Coverage (raise a cap the scan reports it hit):
    ${CLI} scan --max-files <n>          Raise the file-count cap (default 5000)
    ${CLI} scan --max-file-size <size>   Raise the per-file size cap (e.g. 20mb)
    ${CLI} scan --min-confidence <0-1>   Drop findings below a confidence score
    ${CLI} scan --show-placeholders      Show values hidden as placeholders
    ${CLI} scan --no-ignore              Ignore .secretlessignore and defaults
    ${CLI} scan --include-tests          Include test files in the source scan

  Shell History:
    ${CLI} scan --history         Scan shell history for credentials
    ${CLI} scan-history           Scan shell history for credentials
    ${CLI} clean-history          Redact credentials in shell history
    ${CLI} clean-history --dry-run  Preview without modifying

  Identity Vault (requires @opena2a/aim-core):
    ${CLI} vault init                    Initialize vault with agent identity
    ${CLI} vault register <ns> [opts]    Register a credential in a namespace
    ${CLI} vault list                    List stored credentials (metadata only)
    ${CLI} vault rotate <ns> [opts]      Rotate a credential to a new value
    ${CLI} vault revoke <ns>             Revoke a namespace and delete credential
    ${CLI} vault exec <ns> -- <cmd>      Run command with vault credential injected
    ${CLI} vault audit                   Show vault audit log
    ${CLI} vault scan [dir]              Scan for credentials to migrate
    ${CLI} vault test                    Run vault self-test
    ${CLI} vault migrate [opts]          Migrate from SecretStore or .env file

  Credential Broker:
    ${CLI} broker start        Start the credential broker daemon
    ${CLI} broker stop         Stop the running broker daemon
    ${CLI} broker status       Show broker daemon status

  Session Management:
    ${CLI} warm                Warm biometric session (Touch ID)
    ${CLI} warm --ttl 10m      Set session TTL (300, 5m, 1h, 1d)
    ${CLI} warm --no-broker    Skip auto-starting the broker daemon
    ${CLI} install             Install broker as macOS login daemon
    ${CLI} install uninstall   Remove login daemon
    ${CLI} install status      Check daemon installation status

  Claude Code Integration:
    ${CLI} hook --check-only   Session check (for PreToolUse hooks)

  Cache (reduces OS auth prompts for keychain/1password):
    ${CLI} cache               Show cache status
    ${CLI} cache ttl <dur>     Set TTL (5m, 1h, 1d, off)
    ${CLI} cache clear         Clear cached secrets

  Clean options:
    --dry-run     Report findings without redacting
    --path <p>    Scan specific file or directory
    --last        Only clean the most recent session per project

  Watch actions:
    start         Start watching (foreground)
    stop          Stop the watcher
    status        Check if watcher is running
    install       Install as macOS LaunchAgent (auto-start on login)
    uninstall     Remove LaunchAgent

  Other:
    ${CLI} feedback        Star, file an issue, or join the discussion
    ${CLI} ignore <path>   Append a path or glob to .secretlessignore
    ${CLI} ignore --pattern '*.golden.txt'
    ${CLI} diff [<ref>]    Show how secretless-managed files have changed
                                       vs a git ref (default HEAD)
    .secretlessignore                  gitignore-style file at repo root; default-ignore
                                       covers test/, __tests__/, examples/, e2e/, etc.

  Scan options:
    --include-tests          Include test files in source code scan
    --explain                Detailed per-finding view with remediation
    --no-ignore              Disable .secretlessignore + default-ignore
    --min-confidence <n>     Drop findings with composite confidence below n (0-1)

  Options:
    -v, --version    Show version
    -h, --help       Show this help

  Supports: Claude Code, Cursor, GitHub Copilot, Windsurf, Cline, Aider

  https://opena2a.org/secretless-ai
`);
}
