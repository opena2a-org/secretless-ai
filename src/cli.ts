#!/usr/bin/env node

/**
 * Secretless CLI
 *
 * Usage:
 *   npx secretless-ai init     — Set up protections for detected AI tools
 *   npx secretless-ai scan     — Scan for hardcoded secrets
 *   npx secretless-ai status   — Show current protection status
 *   npx secretless-ai verify   — Verify keys are usable but hidden from AI
 *   npx secretless-ai doctor   — Diagnose shell profile issues
 *   npx secretless-ai clean    — Scan and redact credentials in transcripts
 *   npx secretless-ai watch    — Monitor transcripts in real-time
 *   npx secretless-ai secret   — Manage secrets (set, list, get, rm)
 *   npx secretless-ai run      — Run command with secrets injected
 *   npx secretless-ai import   — Import secrets from .env files
 *   npx secretless-ai setup    — Set up secrets from .secretless manifest
 *   npx secretless-ai hook     — Manage pre-commit hook
 */

import * as path from 'path';
import { init } from './init';
import { scan } from './scan';
import { status } from './status';
import { verify } from './verify';
import { toolDisplayName } from './detect';
import { cleanTranscripts } from './transcript';
import { startWatch, stopWatch, isWatchRunning, installLaunchAgent, uninstallLaunchAgent } from './watch';
import { doctor, quickDiagnosis, fixProfiles } from './doctor';
import { protectMcp } from './mcp/protect';
import { discoverMcpConfigs } from './mcp/discover';
import { classifyEnvVars } from './mcp/classify';
import { restoreConfig } from './mcp/rewrite';
import { isKeychainAvailable, createBackend } from './backends/factory';
import { readBackendConfig, writeBackendConfig, resolveBackendType } from './backends/config';
import { migrateSecrets } from './backends/migrate';
import { SecretStore } from './secret-store';
import { runWithSecrets } from './run';
import { importEnvFile, detectEnvFiles } from './env-import';
import { runSetup } from './setup';
import { installPreCommitHook, uninstallPreCommitHook, isHookInstalled } from './git-hook';
import { scanStagedFiles } from './scan-staged';
import type { SelectableBackendType } from './backends/config';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { version: VERSION } = require('../package.json');

function main(): void {
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case 'init': {
      const dirArg = args[1];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      runInit(projectDir);
      break;
    }
    case 'scan': {
      const dirArg = args[1];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      runScan(projectDir);
      break;
    }
    case 'status': {
      const dirArg = args[1];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      runStatus(projectDir);
      break;
    }
    case 'verify': {
      const dirArg = args[1];
      const projectDir = dirArg ? path.resolve(dirArg) : process.cwd();
      runVerify(projectDir);
      break;
    }
    case 'doctor':
      runDoctor(args.includes('--fix'));
      break;
    case 'clean':
      runClean(args.slice(1));
      break;
    case 'watch':
      runWatch(args.slice(1));
      break;
    case 'protect-mcp':
      runProtectMcp(args.slice(1));
      break;
    case 'mcp-status':
      runMcpStatus();
      break;
    case 'mcp-unprotect':
      runMcpUnprotect();
      break;
    case 'backend':
      runBackend(args.slice(1));
      break;
    case 'migrate':
      runMigrate(args.slice(1));
      break;
    case 'secret':
      runSecret(args.slice(1));
      break;
    case 'run':
      runRun(args.slice(1));
      break;
    case 'import':
      runImport(args.slice(1));
      break;
    case 'setup':
      runSetupCommand(args.slice(1));
      break;
    case 'hook':
      runHook(args.slice(1));
      break;
    case 'scan-staged':
      runScanStaged();
      break;
    case '--version':
    case '-v':
      console.log(`secretless v${VERSION}`);
      break;
    case '--help':
    case '-h':
    case undefined:
      printHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

function runInit(projectDir: string): void {
  console.log('\n  Secretless v' + VERSION);
  console.log('  Keeping secrets out of AI\n');

  const result = init(projectDir);

  // Report detected tools
  if (result.toolsDetected.length > 0) {
    console.log('  Detected:');
    for (const tool of result.toolsDetected) {
      console.log(`    + ${toolDisplayName(tool)}`);
    }
  } else {
    console.log('  No AI tools detected, defaulting to Claude Code');
  }
  console.log();

  // Report configured tools
  console.log('  Configured:');
  for (const tool of result.toolsConfigured) {
    console.log(`    * ${toolDisplayName(tool)}`);
  }
  console.log();

  // Report files
  if (result.filesCreated.length > 0) {
    console.log('  Created:');
    for (const f of result.filesCreated) {
      console.log(`    + ${f}`);
    }
    console.log();
  }

  if (result.filesModified.length > 0) {
    console.log('  Modified:');
    for (const f of result.filesModified) {
      console.log(`    ~ ${f}`);
    }
    console.log();
  }

  // Report secrets found
  if (result.secretsFound > 0) {
    console.log(`  Warning: found ${result.secretsFound} hardcoded credential(s)`);
    console.log('  Run `npx secretless-ai scan` to see details\n');
  }

  // Auto-fix shell profile issues
  const fix = fixProfiles();
  if (fix) {
    console.log('  Shell profile fix:');
    console.log(`    Copied ${fix.fixed.length} export(s) from ~/${fix.sourceProfile} to ~/${fix.targetProfile}`);
    for (const v of fix.fixed) {
      console.log(`      + ${v}`);
    }
    if (fix.created) {
      console.log(`    Created ~/${fix.targetProfile}`);
    }
    console.log('    Restart your terminal for changes to take effect.\n');
  }

  console.log('  Done. Secrets are now blocked from AI context.\n');
}

function runScan(projectDir: string): void {
  console.log('\n  Secretless Scanner\n');

  const findings = scan(projectDir);

  if (findings.length === 0) {
    console.log('  No hardcoded credentials found.\n');
    return;
  }

  console.log(`  Found ${findings.length} credential(s):\n`);
  for (const finding of findings) {
    const severity = finding.severity === 'critical' ? 'CRIT' : 'HIGH';
    console.log(`  [${severity}] ${finding.patternName}`);
    console.log(`         ${finding.file}:${finding.line}`);
    console.log(`         ${finding.preview}`);
    console.log();
  }

  console.log(`  Run \`npx secretless-ai init\` to add protections.\n`);
  process.exit(findings.length > 0 ? 1 : 0);
}

function runStatus(projectDir: string): void {
  console.log('\n  Secretless Status\n');

  const s = status(projectDir);

  console.log(`  Protected:  ${s.isProtected ? 'Yes' : 'No'}`);
  console.log(`  Tools:      ${s.configuredTools.map(toolDisplayName).join(', ') || 'None'}`);
  console.log(`  Hook:       ${s.hookInstalled ? 'Installed' : 'Not installed'}`);
  console.log(`  Deny rules: ${s.denyRuleCount}`);
  console.log(`  Secrets:    ${s.secretsFound} found in config files`);

  // Transcript protection status
  if (s.transcriptProtection) {
    console.log();
    console.log('  Transcript Protection:');
    console.log(`    Stop hook: ${s.transcriptProtection.stopHookInstalled ? 'Installed' : 'Not installed'}`);
    console.log(`    Watcher:   ${s.transcriptProtection.watcherRunning ? 'Running' : 'Not running'}`);
    console.log(`    Files:     ${s.transcriptProtection.transcriptFiles} transcript files`);
    if (s.transcriptProtection.transcriptSecretsFound > 0) {
      console.log(`    Secrets:   ${s.transcriptProtection.transcriptSecretsFound} found in recent transcripts`);
    } else {
      console.log(`    Secrets:   Clean`);
    }
  }

  console.log();
}

function runVerify(projectDir: string): void {
  console.log('\n  Secretless Verify\n');

  const result = verify(projectDir);

  // Show env var availability
  const setVars = Object.entries(result.envVars).filter(([, v]) => v);
  const unsetVars = Object.entries(result.envVars).filter(([, v]) => !v);

  if (setVars.length > 0) {
    console.log('  Env vars available (usable by tools):');
    for (const [name] of setVars) {
      console.log(`    + ${name}`);
    }
  }

  if (unsetVars.length > 0) {
    console.log('  Env vars not set:');
    for (const [name] of unsetVars) {
      console.log(`    - ${name}`);
    }
  }
  console.log();

  // Show context exposure
  if (result.exposedInContext.length > 0) {
    console.log('  EXPOSED in AI context (secrets the AI can see):');
    for (const exp of result.exposedInContext) {
      console.log(`    ! ${exp.patternName} in ${exp.file}:${exp.line}`);
    }
    console.log();
  } else {
    console.log('  AI context files: clean (no credentials found)\n');
  }

  // Show transcript exposure
  if (result.exposedInTranscripts.length > 0) {
    console.log('  EXPOSED in transcripts (credentials in conversation history):');
    for (const exp of result.exposedInTranscripts) {
      console.log(`    ! ${exp.patternName} in ${exp.file}:${exp.line}`);
    }
    console.log('  Run `npx secretless-ai clean` to redact.\n');
  }

  // Verdict
  if (result.passed) {
    console.log('  PASS: Secrets are accessible via env vars but hidden from AI context.\n');
  } else if (result.exposedInContext.length > 0 || result.exposedInTranscripts.length > 0) {
    console.log('  FAIL: Credentials found in AI context or transcript files.');
    console.log('  Run `npx secretless-ai init` to protect context files.');
    console.log('  Run `npx secretless-ai clean` to redact transcripts.\n');
    process.exit(1);
  } else {
    console.log('  WARN: No API keys found in env vars.');

    // Quick diagnosis to give targeted advice
    const diag = quickDiagnosis();
    if (diag.wrongProfile.length > 0) {
      console.log(`  Found ${diag.wrongProfile.length} key(s) in an interactive-only shell profile:`);
      for (const v of diag.wrongProfile) {
        console.log(`    - ${v}`);
      }
      console.log('  These work in your terminal but fail in subprocesses (CI, Docker, Claude Code).');
      console.log('  Run `npx secretless-ai doctor` for fix instructions.\n');
    } else {
      console.log('  Set keys in ~/.zshenv (macOS) or ~/.bashrc (Linux), then restart your terminal.');
      console.log('  Run `npx secretless-ai doctor` to diagnose shell profile issues.\n');
    }
    process.exit(1);
  }
}

function runDoctor(autoFix: boolean): void {
  console.log('\n  Secretless Doctor\n');

  const result = doctor();

  // Platform & shell
  console.log(`  Platform: ${result.platform}`);
  console.log(`  Shell:    ${result.shell}`);
  console.log();

  // Profiles
  console.log('  Shell profiles:');
  for (const profile of result.profiles) {
    const tag = profile.recommendation === 'recommended'
      ? ' (RECOMMENDED)'
      : profile.recommendation === 'interactive-only'
        ? ' (interactive-only)'
        : profile.recommendation === 'login-only'
          ? ' (login-only)'
          : '';
    const status = profile.exists
      ? (profile.exportedVars.length > 0
          ? `${profile.exportedVars.length} key(s)`
          : 'no keys')
      : 'not found';
    console.log(`    ${profile.exists ? '+' : '-'} ~/${require('path').basename(profile.path)}${tag}: ${status}`);
  }
  console.log();

  // Findings
  if (result.findings.length > 0) {
    console.log('  Findings:');
    for (const finding of result.findings) {
      const label = finding.severity.toUpperCase();
      console.log(`    [${label}] ${finding.message}`);
      if (finding.fix) {
        console.log(`           Fix: ${finding.fix}`);
      }
    }
    console.log();
  }

  // Auto-fix if requested or if there are fixable issues
  if (autoFix && result.health !== 'healthy') {
    const fix = fixProfiles();
    if (fix) {
      console.log('  Auto-fix applied:');
      console.log(`    Copied ${fix.fixed.length} export(s) from ~/${fix.sourceProfile} to ~/${fix.targetProfile}`);
      for (const v of fix.fixed) {
        console.log(`      + ${v}`);
      }
      if (fix.created) {
        console.log(`    Created ~/${fix.targetProfile}`);
      }
      console.log('    Restart your terminal for changes to take effect.\n');
      return;
    }
  }

  // Health verdict
  const verdictMap = {
    healthy: 'HEALTHY: All keys correctly configured for subprocess access.',
    degraded: 'DEGRADED: Keys work in your terminal but may fail in subprocesses.',
    broken: 'BROKEN: Keys are not available to subprocesses.',
  };
  console.log(`  ${verdictMap[result.health]}\n`);

  if (result.health !== 'healthy') {
    console.log('  Run `npx secretless-ai doctor --fix` to auto-fix.\n');
    process.exit(1);
  }
}

function runClean(args: string[]): void {
  const dryRun = args.includes('--dry-run');
  const lastSession = args.includes('--last');
  let targetPath: string | undefined;

  const pathIdx = args.indexOf('--path');
  if (pathIdx !== -1 && args[pathIdx + 1]) {
    targetPath = path.resolve(args[pathIdx + 1]);
  }

  // Warn when scanning outside the default transcript directory
  if (targetPath) {
    const os = require('os');
    const claudeDir = path.join(os.homedir(), '.claude');
    if (!targetPath.startsWith(claudeDir)) {
      console.log(`  Note: scanning outside ~/.claude/ — target: ${targetPath}\n`);
    }
  }

  console.log('\n  Scanning Claude Code transcripts...\n');

  const result = cleanTranscripts({ dryRun, targetPath, lastSession });

  if (result.totalFindings === 0) {
    console.log(`  Scanned: ${result.filesScanned} files`);
    console.log('  No credentials found. Transcripts are clean.\n');
    return;
  }

  // Group findings by file
  const byFile = new Map<string, typeof result.findings>();
  for (const f of result.findings) {
    const existing = byFile.get(f.file) || [];
    existing.push(f);
    byFile.set(f.file, existing);
  }

  for (const [file, findings] of byFile) {
    console.log(`  ${file}`);
    for (const f of findings) {
      console.log(`    Line ${f.line}:  ${f.jsonPath} → [REDACTED:${f.patternId}]`);
    }
    console.log();
  }

  console.log(`  Scanned:  ${result.filesScanned} files`);
  console.log(`  Found:    ${result.totalFindings} credential(s) in ${result.filesWithSecrets} file(s)`);
  if (dryRun) {
    console.log('  Mode:     dry-run (no changes made)');
    console.log('  Run without --dry-run to redact.\n');
  } else {
    console.log(`  Redacted: ${result.totalRedacted}\n`);
  }
}

function runWatch(args: string[]): void {
  const action = args[0] || 'start';

  switch (action) {
    case 'start':
      if (isWatchRunning()) {
        console.log('\n  Watcher is already running.\n');
        return;
      }
      console.log('\n  Starting Secretless transcript watcher...');
      console.log('  Press Ctrl+C to stop.\n');
      startWatch();
      break;

    case 'stop':
      if (stopWatch()) {
        console.log('\n  Watcher stopped.\n');
      } else {
        console.log('\n  No watcher is running.\n');
      }
      break;

    case 'status':
      if (isWatchRunning()) {
        console.log('\n  Watcher: running\n');
      } else {
        console.log('\n  Watcher: not running\n');
      }
      break;

    case 'install':
      if (installLaunchAgent()) {
        console.log('\n  LaunchAgent installed.');
        console.log('  Watcher will auto-start on login.');
        console.log('  Run `launchctl load ~/Library/LaunchAgents/ai.secretless.watch.plist` to start now.\n');
      } else {
        console.log('\n  LaunchAgent installation is only supported on macOS.\n');
      }
      break;

    case 'uninstall':
      if (uninstallLaunchAgent()) {
        stopWatch();
        console.log('\n  LaunchAgent removed. Watcher will no longer auto-start.\n');
      } else {
        console.log('\n  No LaunchAgent found to remove.\n');
      }
      break;

    default:
      console.error(`\n  Unknown watch action: ${action}`);
      console.log('  Usage: secretless-ai watch [start|stop|status|install|uninstall]\n');
      process.exit(1);
  }
}

function runProtectMcp(args: string[]): void {
  console.log('\n  Secretless MCP Protection\n');

  const wrapperPath = getWrapperPath();

  // Parse --backend flag
  let backendType: SelectableBackendType | undefined;
  const backendIdx = args.indexOf('--backend');
  if (backendIdx !== -1 && args[backendIdx + 1]) {
    const val = args[backendIdx + 1];
    if (val === 'local' || val === 'keychain') {
      backendType = val;
    } else {
      console.error(`  Unknown backend type: ${val}. Use 'local' or 'keychain'.\n`);
      process.exit(1);
    }
  }

  protectMcp({ wrapperPath, backendType }).then((result) => {
    if (result.clientsScanned === 0) {
      console.log('  No MCP configurations found.\n');
      console.log('  Looked for configs from: Claude Desktop, Cursor, Claude Code, VS Code, Windsurf');
      console.log('  If your configs are in a non-standard location, please open an issue.\n');
      return;
    }

    console.log(`  Scanned ${result.clientsScanned} client(s)\n`);

    if (result.secretsFound === 0) {
      console.log('  No plaintext secrets found in MCP configs. Already clean.\n');
      return;
    }

    for (const server of result.servers) {
      console.log(`  + ${server.client}/${server.server}`);
      for (const key of server.secretKeys) {
        console.log(`      ${key} (encrypted)`);
      }
    }
    console.log();

    console.log(`  ${result.secretsFound} secret(s) encrypted across ${result.serversProtected} server(s).`);
    if (result.alreadyProtected > 0) {
      console.log(`  ${result.alreadyProtected} server(s) already protected.`);
    }
    console.log();
    console.log('  MCP servers will start normally — no workflow changes needed.');
    console.log('  Run `npx secretless-ai mcp-status` to check status anytime.');
    console.log('  Run `npx secretless-ai mcp-unprotect` to restore originals.\n');
  }).catch((err) => {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}

function getWrapperPath(): string {
  return path.resolve(__dirname, 'mcp-wrapper.js');
}

function runMcpStatus(): void {
  console.log('\n  Secretless MCP Status\n');

  const configs = discoverMcpConfigs();

  if (configs.length === 0) {
    console.log('  No MCP configurations found.\n');
    return;
  }

  for (const config of configs) {
    console.log(`  ${config.client} (${config.filePath})`);
    for (const server of config.servers) {
      if (server.alreadyProtected) {
        console.log(`    + ${server.name}: protected`);
      } else {
        const secretCount = Object.keys(classifyEnvVars(server.env).secrets).length;
        if (secretCount > 0) {
          console.log(`    ! ${server.name}: EXPOSED (${secretCount} plaintext secret(s))`);
        } else {
          console.log(`    * ${server.name}: clean (no secrets in env)`);
        }
      }
    }
    console.log();
  }

  console.log('  Run `npx secretless-ai protect-mcp` to encrypt exposed secrets.\n');
}

function runMcpUnprotect(): void {
  console.log('\n  Secretless MCP Unprotect\n');

  const os = require('os');
  const home = os.homedir();
  const backupDir = path.join(home, '.secretless-ai', 'mcp-backups');

  const configs = discoverMcpConfigs();
  let restored = 0;

  for (const config of configs) {
    if (restoreConfig(config.filePath, backupDir)) {
      console.log(`  + Restored: ${config.filePath}`);
      restored++;
    }
  }

  if (restored === 0) {
    console.log('  No backups found to restore.\n');
  } else {
    console.log(`\n  Restored ${restored} config(s) to original state.\n`);
  }
}

function runBackend(args: string[]): void {
  const subcommand = args[0];

  if (subcommand === 'list') {
    const backendType = resolveBackendType();
    const backend = createBackend(backendType);

    Promise.all([
      backend.resolve('mcp'),
      backend.resolve('secret'),
    ]).then(([mcpEntries, secretEntries]) => {
      const mcpKeys = Object.keys(mcpEntries).sort();
      const secretKeys = Object.keys(secretEntries).sort();
      const total = mcpKeys.length + secretKeys.length;

      console.log('\n  Secretless Backend Entries\n');

      if (total === 0) {
        console.log('  No entries found.\n');
        return;
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
    }).catch((err) => {
      console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    });
    return;
  }

  if (subcommand === 'purge') {
    const hasYes = args.includes('--yes');
    let prefixFilter: string | undefined;
    const prefixIdx = args.indexOf('--prefix');
    if (prefixIdx !== -1 && args[prefixIdx + 1]) {
      const val = args[prefixIdx + 1];
      if (val !== 'mcp' && val !== 'secret') {
        console.error(`\n  Unknown prefix: ${val}. Use 'mcp' or 'secret'.\n`);
        process.exit(1);
      }
      prefixFilter = val;
    }

    const backendType = resolveBackendType();
    const backend = createBackend(backendType);
    const prefixes = prefixFilter ? [prefixFilter] : ['mcp', 'secret'];

    Promise.all(prefixes.map(p => backend.resolve(p))).then(async (results) => {
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
        return;
      }

      if (!hasYes) {
        console.log(`\n  This will delete ${allKeys.length} ${allKeys.length === 1 ? 'entry' : 'entries'} from the ${backendType} backend.\n`);
        for (const [prefix, keys] of Object.entries(keysByPrefix)) {
          console.log(`  ${prefix}/:  ${keys.length}`);
        }
        console.log(`\n  To confirm, run: secretless-ai backend purge${prefixFilter ? ` --prefix ${prefixFilter}` : ''} --yes\n`);
        return;
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
      console.log();
    }).catch((err) => {
      console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(1);
    });
    return;
  }

  if (subcommand === 'set') {
    const type = args[1];
    if (type !== 'local' && type !== 'keychain') {
      console.error(`\n  Unknown backend type: ${type ?? '(none)'}. Use 'local' or 'keychain'.\n`);
      process.exit(1);
    }

    if (type === 'keychain') {
      const kc = isKeychainAvailable();
      if (!kc.available) {
        console.error(`\n  Cannot use keychain backend: ${kc.message}\n`);
        process.exit(1);
      }
    }

    writeBackendConfig(type);
    console.log(`\n  Backend set to: ${type}\n`);
    console.log('  Run `npx secretless-ai protect-mcp` to re-protect MCP servers with the new backend.');
    console.log('  Or use `npx secretless-ai migrate --from local --to keychain` to migrate existing secrets.\n');
    return;
  }

  // Default: show current backend status
  const current = resolveBackendType();
  const configFile = readBackendConfig();
  const kc = isKeychainAvailable();

  console.log('\n  Secretless Backend\n');
  console.log(`  Current:      ${current}${configFile ? '' : ' (default)'}`);
  console.log(`  Config file:  ${configFile ?? '(not set)'}`);
  console.log(`  Keychain:     ${kc.available ? 'available' : 'unavailable'} (${kc.message})`);
  console.log(`  Platform:     ${kc.platform}`);
  console.log();
  console.log('  Commands:');
  console.log('    npx secretless-ai backend set local      Use local encrypted file');
  console.log('    npx secretless-ai backend set keychain    Use OS keychain');
  console.log('    npx secretless-ai backend list            List all stored entries');
  console.log('    npx secretless-ai backend purge           Delete all entries (--yes to confirm)');
  console.log();
}

function runMigrate(args: string[]): void {
  let fromType: SelectableBackendType | undefined;
  let toType: SelectableBackendType | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--from' && args[i + 1]) {
      const val = args[++i];
      if (val === 'local' || val === 'keychain') fromType = val;
    }
    if (args[i] === '--to' && args[i + 1]) {
      const val = args[++i];
      if (val === 'local' || val === 'keychain') toType = val;
    }
  }

  if (!fromType || !toType) {
    console.error('\n  Usage: npx secretless-ai migrate --from <local|keychain> --to <local|keychain>\n');
    process.exit(1);
  }

  if (fromType === toType) {
    console.error(`\n  Source and destination backends are the same: ${fromType}\n`);
    process.exit(1);
  }

  console.log('\n  Secretless Migration\n');
  console.log(`  From: ${fromType}`);
  console.log(`  To:   ${toType}\n`);

  const source = createBackend(fromType);
  const destination = createBackend(toType);

  migrateSecrets(source, destination, { deleteFromSource: false }).then((result) => {
    if (result.migrated === 0 && result.failed === 0) {
      console.log('  No secrets found to migrate.\n');
      return;
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
  }).catch((err) => {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}

function runSecret(args: string[]): void {
  const subcommand = args[0];

  switch (subcommand) {
    case 'set': {
      const nameArg = args[1];
      if (!nameArg) {
        console.error('\n  Usage: secretless-ai secret set <NAME[=VALUE]>\n');
        process.exit(1);
      }

      // Check for inline value: NAME=VALUE
      const eqIdx = nameArg.indexOf('=');
      if (eqIdx !== -1) {
        const name = nameArg.slice(0, eqIdx);
        const value = nameArg.slice(eqIdx + 1);
        const store = new SecretStore();
        store.setSecret(name, value).then(() => {
          console.log(`  Stored: ${name}`);
        }).catch((err) => {
          console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
          process.exit(1);
        });
        return;
      }

      // Read value from stdin
      const name = nameArg;
      let input = '';
      process.stdin.setEncoding('utf-8');

      if (process.stdin.isTTY) {
        process.stderr.write(`  Enter value for ${name}: `);
      }

      process.stdin.on('data', (chunk) => { input += chunk; });
      process.stdin.on('end', () => {
        const value = input.trim();
        if (!value) {
          console.error('  Error: empty value');
          process.exit(1);
        }
        const store = new SecretStore();
        store.setSecret(name, value).then(() => {
          console.log(`  Stored: ${name}`);
        }).catch((err) => {
          console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
          process.exit(1);
        });
      });
      break;
    }

    case 'list': {
      const store = new SecretStore();
      store.listSecrets().then((names) => {
        if (names.length === 0) {
          console.log('\n  No secrets stored.\n');
          return;
        }
        console.log(`\n  ${names.length} secret(s):\n`);
        for (const name of names) {
          console.log(`    ${name}`);
        }
        console.log();
      }).catch((err) => {
        console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      });
      break;
    }

    case 'get': {
      const name = args[1];
      if (!name) {
        console.error('\n  Usage: secretless-ai secret get <NAME>\n');
        process.exit(1);
      }
      const store = new SecretStore();
      store.getSecret(name).then((value) => {
        if (value === undefined) {
          console.error(`  Secret not found: ${name}`);
          process.exit(1);
        }
        process.stdout.write(value);
        // Add newline if stdout is a terminal
        if (process.stdout.isTTY) {
          process.stdout.write('\n');
        }
      }).catch((err) => {
        console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      });
      break;
    }

    case 'rm':
    case 'remove':
    case 'delete': {
      const name = args[1];
      if (!name) {
        console.error('\n  Usage: secretless-ai secret rm <NAME>\n');
        process.exit(1);
      }
      const store = new SecretStore();
      store.removeSecret(name).then((removed) => {
        if (removed) {
          console.log(`  Removed: ${name}`);
        } else {
          console.error(`  Secret not found: ${name}`);
          process.exit(1);
        }
      }).catch((err) => {
        console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      });
      break;
    }

    default:
      console.error(`\n  Unknown secret command: ${subcommand ?? '(none)'}`);
      console.log('  Usage: secretless-ai secret <set|list|get|rm> [args]\n');
      process.exit(1);
  }
}

function runRun(args: string[]): void {
  // Parse --only flag before --
  let only: string[] | undefined;
  const separatorIdx = args.indexOf('--');

  // Check for --only before the separator
  const searchEnd = separatorIdx !== -1 ? separatorIdx : args.length;
  for (let i = 0; i < searchEnd; i++) {
    if (args[i] === '--only' && args[i + 1]) {
      only = args[i + 1].split(',').map(s => s.trim()).filter(Boolean);
      break;
    }
  }

  // Everything after -- is the child command
  if (separatorIdx === -1 || separatorIdx >= args.length - 1) {
    console.error('\n  Usage: secretless-ai run [--only KEY1,KEY2] -- <command> [args...]\n');
    process.exit(1);
  }

  const childCommand = args[separatorIdx + 1];
  const childArgs = args.slice(separatorIdx + 2);

  runWithSecrets(childCommand, childArgs, { only }).then((code) => {
    process.exit(code);
  }).catch((err) => {
    console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}

function runImport(args: string[]): void {
  console.log('\n  Secretless Import\n');

  if (args.includes('--detect')) {
    const dir = process.cwd();
    const files = detectEnvFiles(dir);
    if (files.length === 0) {
      console.log('  No .env files found in current directory.\n');
      return;
    }

    let totalImported = 0;
    const importNext = (idx: number): void => {
      if (idx >= files.length) {
        console.log(`\n  Total: ${totalImported} secret(s) imported.\n`);
        return;
      }
      const file = files[idx];
      importEnvFile(file).then((result) => {
        console.log(`  ${path.basename(file)}: ${result.imported} imported`);
        if (result.skipped > 0) {
          console.log(`    (${result.skipped} skipped — invalid names)`);
        }
        totalImported += result.imported;
        importNext(idx + 1);
      }).catch((err) => {
        console.error(`  Error importing ${file}: ${err instanceof Error ? err.message : String(err)}`);
        importNext(idx + 1);
      });
    };
    importNext(0);
    return;
  }

  const filePath = args[0];
  if (!filePath) {
    console.error('  Usage: secretless-ai import <file> or secretless-ai import --detect\n');
    process.exit(1);
  }

  const resolvedPath = path.resolve(filePath);
  importEnvFile(resolvedPath).then((result) => {
    if (result.imported === 0) {
      console.log('  No secrets found in file.\n');
      return;
    }

    console.log(`  Imported ${result.imported} secret(s) from ${path.basename(resolvedPath)}:\n`);
    for (const name of result.entries) {
      console.log(`    + ${name}`);
    }
    if (result.skipped > 0) {
      console.log(`\n  Skipped: ${result.skipped} (invalid names)`);
    }
    console.log();
  }).catch((err) => {
    console.error(`  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}

function runSetupCommand(args: string[]): void {
  const checkOnly = args.includes('--check');
  const dir = process.cwd();

  console.log('\n  Secretless Setup\n');

  runSetup(dir, { check: checkOnly }).then((result) => {
    if (checkOnly) {
      console.log(`  Satisfied: ${result.existing} secret(s)`);
      console.log(`  Missing:   ${result.missing} required`);
      console.log(`  Optional:  ${result.skipped} not set\n`);

      if (!result.complete) {
        console.log('  Missing secrets:');
        for (const name of result.missingNames) {
          console.log(`    - ${name}`);
        }
        console.log();
        console.log('  FAIL: Run `secretless-ai setup` to configure missing secrets.\n');
        process.exit(1);
      } else {
        console.log('  PASS: All required secrets are configured.\n');
      }
      return;
    }

    if (result.set > 0 || result.existing > 0) {
      console.log(`\n  Set:      ${result.set} secret(s)`);
      console.log(`  Existing: ${result.existing}`);
      console.log(`  Skipped:  ${result.skipped} (optional)\n`);
    }
  }).catch((err) => {
    console.error(`  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}

function runHook(args: string[]): void {
  const subcommand = args[0];
  const projectDir = process.cwd();

  switch (subcommand) {
    case 'install': {
      const result = installPreCommitHook(projectDir);
      console.log(`\n  ${result.message}\n`);
      if (!result.installed) {
        process.exit(1);
      }
      break;
    }

    case 'uninstall': {
      const result = uninstallPreCommitHook(projectDir);
      console.log(`\n  ${result.message}\n`);
      if (!result.removed) {
        process.exit(1);
      }
      break;
    }

    case 'status': {
      const installed = isHookInstalled(projectDir);
      console.log(`\n  Pre-commit hook: ${installed ? 'installed' : 'not installed'}\n`);
      break;
    }

    default:
      console.error(`\n  Unknown hook command: ${subcommand ?? '(none)'}`);
      console.log('  Usage: secretless-ai hook <install|uninstall|status>\n');
      process.exit(1);
  }
}

function runScanStaged(): void {
  const { findings, blockedFiles } = scanStagedFiles();
  const total = findings.length + blockedFiles.length;

  if (total === 0) {
    // Clean — allow commit
    process.exit(0);
  }

  console.error('\n  secretless: Blocked commit — secrets detected\n');

  if (blockedFiles.length > 0) {
    console.error('  Secret files staged for commit:');
    for (const file of blockedFiles) {
      console.error(`    ! ${file}`);
    }
    console.error();
  }

  if (findings.length > 0) {
    console.error('  Credentials found in staged files:');
    for (const f of findings) {
      console.error(`    ! ${f.patternName} in ${f.file}:${f.line}`);
    }
    console.error();
  }

  console.error('  Remove the secrets and try again.');
  console.error('  To bypass: git commit --no-verify\n');
  process.exit(1);
}

function printHelp(): void {
  console.log(`
  Secretless v${VERSION}
  Keep secrets out of AI context.

  Usage:
    npx secretless-ai init      Set up protections for your AI tools
    npx secretless-ai scan      Scan for hardcoded secrets
    npx secretless-ai status    Show protection status
    npx secretless-ai verify    Verify keys are usable but hidden from AI
    npx secretless-ai doctor    Diagnose shell profile issues (--fix to auto-fix)
    npx secretless-ai clean     Scan and redact credentials in transcripts
    npx secretless-ai watch     Monitor transcripts in real-time

  Secret Management:
    npx secretless-ai secret set <NAME[=VALUE]>  Store a secret
    npx secretless-ai secret list                List stored secret names
    npx secretless-ai secret get <NAME>          Retrieve a secret value
    npx secretless-ai secret rm <NAME>           Remove a secret
    npx secretless-ai import <file>              Import secrets from .env file
    npx secretless-ai import --detect            Auto-find and import .env files
    npx secretless-ai run -- <command>           Run command with secrets injected

  Project Setup:
    npx secretless-ai setup              Set up secrets from .secretless manifest
    npx secretless-ai setup --check      Check for missing required secrets (CI)

  Git Protection:
    npx secretless-ai hook install       Install pre-commit secret scanner
    npx secretless-ai hook uninstall     Remove pre-commit hook
    npx secretless-ai hook status        Check hook installation status

  MCP Protection:
    npx secretless-ai protect-mcp    Encrypt MCP server secrets
    npx secretless-ai mcp-status     Show MCP protection status
    npx secretless-ai mcp-unprotect  Restore original MCP configs

  Backend Management:
    npx secretless-ai backend             Show current backend and keychain status
    npx secretless-ai backend set <type>  Set backend (local or keychain)
    npx secretless-ai backend list        List all entries in current backend
    npx secretless-ai backend purge       Delete all entries (--prefix mcp|secret, --yes)
    npx secretless-ai migrate             Migrate secrets between backends

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

  Options:
    -v, --version    Show version
    -h, --help       Show this help

  Supports: Claude Code, Cursor, GitHub Copilot, Windsurf, Cline, Aider

  https://opena2a.org/secretless-ai
`);
}

main();
