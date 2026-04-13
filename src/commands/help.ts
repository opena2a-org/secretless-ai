import { VERSION } from './utils';

export function printHelp(): void {
  console.log(`
  Secretless v${VERSION}
  Keep secrets out of AI context.

  Quick start:
    npx secretless-ai scan       Find hardcoded credentials
    npx secretless-ai init       Set up AI tool protections
    npx secretless-ai verify     Confirm secrets are hidden from AI

  Usage:
    npx secretless-ai init      Set up protections for your AI tools
    npx secretless-ai scan      Scan config and source files for hardcoded secrets
    npx secretless-ai status    Show protection status
    npx secretless-ai verify    Verify keys are usable but hidden from AI (--all for full list)
    npx secretless-ai doctor    Diagnose shell profile issues (--fix to auto-fix)
    npx secretless-ai clean     Scan and redact credentials in transcripts
    npx secretless-ai watch     Monitor transcripts in real-time
    npx secretless-ai warm      Warm biometric session (Touch ID on macOS)
    npx secretless-ai install   Install broker as login daemon (macOS)

  Secret Management:
    npx secretless-ai secret set <NAME[=VALUE]>  Store a secret
    npx secretless-ai secret list                List stored secret names
    npx secretless-ai secret get <NAME>          Retrieve a secret value
    npx secretless-ai secret get --force <NAME>  Retrieve in non-interactive contexts
    npx secretless-ai secret rm <NAME>           Remove a secret
    npx secretless-ai import <file>              Import secrets from .env file
    npx secretless-ai import --detect            Auto-find and import .env files
    npx secretless-ai run [--only K1,K2] -- <cmd>  Run with secrets injected
    npx secretless-ai env [--only K1,K2]         Output export statements for shell

  Project Setup:
    npx secretless-ai setup              Set up secrets from .secretless manifest
    npx secretless-ai setup --check      Check for missing required secrets (CI)

  Custom Rules:
    npx secretless-ai rules              List custom deny rules
    npx secretless-ai rules init         Create .secretless-rules.yaml template
    npx secretless-ai rules test <pat>   Test a pattern (see generated deny rules)

  Git Protection:
    npx secretless-ai hook install       Install pre-commit secret scanner
    npx secretless-ai hook uninstall     Remove pre-commit hook
    npx secretless-ai hook status        Check hook installation status

  MCP Protection:
    npx secretless-ai protect-mcp [--backend TYPE]  Encrypt MCP server secrets
    npx secretless-ai mcp-status     Show MCP protection status
    npx secretless-ai mcp-unprotect  Restore original MCP configs

  Backend Management:
    npx secretless-ai backend             Show current backend status
    npx secretless-ai backend set <type>  Set backend (local, keychain, 1password, vault, or gcp-sm)
    npx secretless-ai backend list        List all entries in current backend
    npx secretless-ai backend purge       Delete all entries (--prefix mcp|secret, --yes)
    npx secretless-ai migrate             Migrate secrets between backends

  Scope Discovery:
    npx secretless-ai scope discover <name>  Discover permissions and save baseline
    npx secretless-ai scope check <name>     Re-check and compare to baseline
    npx secretless-ai scope list             Show all stored baselines
    npx secretless-ai scope reset <name>     Clear baseline for re-baseline

  Shell History:
    npx secretless-ai scan --history         Scan shell history for credentials
    npx secretless-ai scan-history           Scan shell history for credentials
    npx secretless-ai clean-history          Redact credentials in shell history
    npx secretless-ai clean-history --dry-run  Preview without modifying

  Identity Vault (requires @opena2a/aim-core):
    npx secretless-ai vault init                    Initialize vault with agent identity
    npx secretless-ai vault register <ns> [opts]    Register a credential in a namespace
    npx secretless-ai vault list                    List stored credentials (metadata only)
    npx secretless-ai vault rotate <ns> [opts]      Rotate a credential to a new value
    npx secretless-ai vault revoke <ns>             Revoke a namespace and delete credential
    npx secretless-ai vault exec <ns> -- <cmd>      Run command with vault credential injected
    npx secretless-ai vault audit                   Show vault audit log
    npx secretless-ai vault scan [dir]              Scan for credentials to migrate
    npx secretless-ai vault test                    Run vault self-test
    npx secretless-ai vault migrate [opts]          Migrate from SecretStore or .env file

  Credential Broker:
    npx secretless-ai broker start        Start the credential broker daemon
    npx secretless-ai broker stop         Stop the running broker daemon
    npx secretless-ai broker status       Show broker daemon status

  Session Management:
    npx secretless-ai warm                Warm biometric session (Touch ID)
    npx secretless-ai warm --ttl 10m      Set session TTL (300, 5m, 1h, 1d)
    npx secretless-ai warm --no-broker    Skip auto-starting the broker daemon
    npx secretless-ai install             Install broker as macOS login daemon
    npx secretless-ai install uninstall   Remove login daemon
    npx secretless-ai install status      Check daemon installation status

  Claude Code Integration:
    npx secretless-ai hook --check-only   Session check (for PreToolUse hooks)

  Cache (reduces OS auth prompts for keychain/1password):
    npx secretless-ai cache               Show cache status
    npx secretless-ai cache ttl <dur>     Set TTL (5m, 1h, 1d, off)
    npx secretless-ai cache clear         Clear cached secrets

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

  Scan options:
    --include-tests  Include test files in source code scan
    --explain        Use NanoMind for rich context explanations (requires @nanomind/engine)

  Options:
    -v, --version    Show version
    -h, --help       Show this help

  Supports: Claude Code, Cursor, GitHub Copilot, Windsurf, Cline, Aider

  https://opena2a.org/secretless-ai
`);
}
