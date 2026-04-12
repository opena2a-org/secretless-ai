import * as path from 'path';
import { init } from '../init';
import { scan } from '../scan';
import { status } from '../status';
import { verify } from '../verify';
import { toolDisplayName } from '../detect';
import { doctor, quickDiagnosis, fixProfiles } from '../doctor';
import { readBackendConfig } from '../backends/config';
import { getDaemonStatus } from '../broker/daemon';
import { getSessionStatus } from '../session/session-state';
import { isDaemonInstalled } from '../session/install';
import { VERSION, formatUptime, formatRemainingTime } from './utils';
import { explainFinding, isEngineAvailable } from '../nanomind';
import { c, divider } from './colors';

export function runInit(projectDir: string): void {
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

  // Suggest warm for backends that trigger OS auth prompts
  const configuredBackend = readBackendConfig();
  if (configuredBackend === '1password' || configuredBackend === 'keychain') {
    console.log(`  Tip: Run 'npx secretless-ai warm' before starting an AI session`);
    console.log(`  to avoid repeated ${configuredBackend === '1password' ? '1Password' : 'keychain'} auth prompts.\n`);
  }

  // Star prompt (interactive TTY only)
  if (process.stdout.isTTY) {
    console.log('  Helpful? Star the project: https://github.com/opena2a-org/secretless-ai\n');
  }
}

export function runScan(projectDir: string, options?: { includeTests?: boolean; explain?: boolean }): void {
  console.log('\n  Secretless Scanner\n');

  const nodeFs = require('fs') as typeof import('fs');
  if (!nodeFs.existsSync(projectDir)) {
    console.error(`  Directory not found: ${projectDir}`);
    console.error('  Check the path and try again.\n');
    process.exit(1);
  }

  const findings = scan(projectDir, { includeTests: options?.includeTests });

  if (findings.length === 0) {
    console.log('  No hardcoded credentials found.');
    console.log('  Verify keys are working: npx secretless-ai verify\n');
    return;
  }

  // If --explain requested, use NanoMind engine for rich context
  if (options?.explain) {
    runScanWithExplanations(findings).then((code) => process.exit(code));
    return;
  }

  printFindings(findings);
  process.exit(findings.length > 0 ? 1 : 0);
}

function printFindings(findings: ReturnType<typeof scan>): void {
  const critCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.length - critCount;

  if (critCount > 0) {
    console.log(`  ${c.boldRed(`${critCount} critical credential${critCount > 1 ? 's' : ''} exposed`)}`);
  } else {
    console.log(`  ${c.boldYellow(`${findings.length} credential${findings.length > 1 ? 's' : ''} found`)}`);
  }

  console.log(divider('Findings'));

  const summaryParts: string[] = [];
  if (critCount > 0) summaryParts.push(c.brightRed(`${critCount} critical`));
  if (highCount > 0) summaryParts.push(c.yellow(`${highCount} high`));
  console.log(`  ${summaryParts.join('  ')}`);

  for (const finding of findings) {
    const sevColor = finding.severity === 'critical' ? c.brightRed : c.yellow;
    const sevLabel = finding.severity === 'critical' ? 'CRITICAL' : 'HIGH';
    console.log();
    console.log(`  ${sevColor('\u2502')} ${c.bold(sevLabel)}  ${c.boldWhite(finding.patternName)}`);
    console.log(`  ${sevColor('\u2502')} ${c.dim(`${finding.file}:${finding.line}`)}`);
    console.log(`  ${sevColor('\u2502')} ${finding.preview}`);
    if (finding.fix) {
      console.log(`  ${sevColor('\u2502')} ${c.cyan('Fix:')} ${finding.fix}`);
    }
  }

  console.log(divider('Next Steps'));
  console.log(`  ${c.cyan('Protect now:')}        npx secretless-ai init`);
  console.log(`  ${c.cyan('Full security scan:')} npx hackmyagent secure`);
  console.log();
}

async function runScanWithExplanations(findings: ReturnType<typeof scan>): Promise<number> {
  const engineReady = await isEngineAvailable();

  if (!engineReady) {
    console.log('  NanoMind engine not available. Install @nanomind/engine for rich explanations.');
    console.log('  Falling back to standard output.\n');
    printFindings(findings);
    return findings.length > 0 ? 1 : 0;
  }

  console.log(`  Found ${findings.length} credential(s):\n`);
  console.log('  AI coding tools (Claude Code, Cursor, Copilot) can read .env files in their');
  console.log('  context window, exposing credentials to the LLM provider.\n');

  for (const finding of findings) {
    const severity = finding.severity === 'critical' ? 'CRIT' : 'HIGH';
    console.log(`  [${severity}] ${finding.patternName}`);
    console.log(`         ${finding.file}:${finding.line}`);
    console.log(`         ${finding.preview}`);

    // Try NanoMind explanation, fall back to static fix
    const explanation = await explainFinding(finding.patternName, finding.patternId, finding.file);
    if (explanation) {
      console.log(`         ${explanation}`);
    } else if (finding.fix) {
      console.log(`         Fix: ${finding.fix}`);
    }
    console.log();
  }

  console.log(`  Run \`npx secretless-ai init\` to add protections.`);
  console.log('  For a full security scan (147+ checks): npx hackmyagent secure\n');
  return findings.length > 0 ? 1 : 0;
}

export function runStatus(projectDir: string): void {
  console.log('\n  Secretless Status\n');

  const s = status(projectDir);

  console.log(`  Protected:  ${s.isProtected ? 'Yes' : 'No'}`);
  console.log(`  Tools:      ${s.configuredTools.map(toolDisplayName).join(', ') || 'None'}`);
  console.log(`  Hook:       ${s.hookInstalled ? 'Installed' : 'Not installed'}`);
  console.log(`  Deny rules: ${s.denyRuleCount}`);
  console.log(`  Secrets:    ${s.secretsFound} found in config files`);

  // Session status
  const session = getSessionStatus();
  console.log();
  console.log('  Session:');
  if (session.warm) {
    console.log(`    Status:    warm`);
    console.log(`    Expires:   ${formatRemainingTime(session.remainingSeconds)} (${session.expiresAt})`);
  } else if (session.authenticatedAt) {
    console.log(`    Status:    expired`);
    console.log(`    Last auth: ${session.authenticatedAt}`);
    console.log('    Warm it:   npx secretless-ai warm');
  } else {
    console.log(`    Status:    not initialized`);
    console.log('    Set up:    npx secretless-ai warm');
  }

  // Broker status
  const brokerStatus = getDaemonStatus();
  console.log();
  console.log('  Broker:');
  if (brokerStatus) {
    console.log(`    Status:    running (PID ${brokerStatus.pid})`);
    console.log(`    Uptime:    ${formatUptime(brokerStatus.uptimeSeconds)}`);
    console.log(`    Socket:    ${brokerStatus.socketPath}`);
    console.log(`    Policies:  ${brokerStatus.policyCount}`);
  } else {
    console.log(`    Status:    not running`);
    const installed = isDaemonInstalled();
    if (!installed) {
      console.log('    Install:   npx secretless-ai install');
    } else {
      console.log('    Start:     npx secretless-ai broker start');
    }
  }

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

export function runVerify(projectDir: string, showAll = false): void {
  console.log(`\n  ${c.boldWhite('Secretless Verify')}\n`);

  const result = verify(projectDir);

  // Show env var availability
  const setVars = Object.entries(result.envVars).filter(([, v]) => v);
  const unsetVars = Object.entries(result.envVars).filter(([, v]) => !v);

  if (setVars.length > 0) {
    for (const [name] of setVars) {
      console.log(`  ${c.green('\u2502')} ${c.green('+')} ${name}`);
    }
  }

  if (showAll && unsetVars.length > 0) {
    for (const [name] of unsetVars) {
      console.log(`  ${c.dim('\u2502')} ${c.dim('-')} ${name}`);
    }
  } else if (unsetVars.length > 0) {
    console.log(`  ${c.dim(`  ${unsetVars.length} known env vars not set (use --all to list)`)}`);
  }

  // Show context exposure
  if (result.exposedInContext.length > 0) {
    console.log(divider('Exposed in AI Context'));
    for (const exp of result.exposedInContext) {
      console.log(`  ${c.brightRed('\u2502')} ${c.brightRed('!')} ${c.bold(exp.patternName)} ${c.dim(`${exp.file}:${exp.line}`)}`);
    }
  } else {
    console.log(`\n  ${c.green('AI context: clean')} ${c.dim('(no credentials found)')}`);
  }

  // Show transcript exposure (collapsed by pattern name)
  if (result.exposedInTranscripts.length > 0) {
    console.log(divider('Exposed in Transcripts'));
    const grouped = new Map<string, number>();
    for (const exp of result.exposedInTranscripts) {
      grouped.set(exp.patternName, (grouped.get(exp.patternName) ?? 0) + 1);
    }
    for (const [patternName, count] of grouped) {
      if (count === 1) {
        const single = result.exposedInTranscripts.find(e => e.patternName === patternName)!;
        console.log(`  ${c.yellow('\u2502')} ${c.yellow('!')} ${c.bold(patternName)} ${c.dim(`${single.file}:${single.line}`)}`);
      } else {
        console.log(`  ${c.yellow('\u2502')} ${c.yellow('!')} ${c.bold(patternName)} ${c.dim(`in ${count} transcript files`)}`);
      }
    }
  }

  // Verdict
  console.log();
  if (result.passed) {
    console.log(`  ${c.boldGreen('PASS')} ${c.green('Secrets accessible via env vars, hidden from AI context.')}`);
  } else if (result.exposedInContext.length > 0 || result.exposedInTranscripts.length > 0) {
    console.log(`  ${c.boldRed('FAIL')} ${c.red('Credentials found in AI context or transcripts.')}`);
    console.log(divider('Next Steps'));
    if (result.exposedInContext.length > 0) {
      console.log(`  ${c.cyan('Protect context:')}    npx secretless-ai init`);
    }
    if (result.exposedInTranscripts.length > 0) {
      console.log(`  ${c.cyan('Redact transcripts:')} npx secretless-ai clean`);
    }
    console.log();
    process.exit(1);
  } else {
    console.log(`  ${c.boldYellow('WARN')} ${c.yellow('No API keys found in env vars.')}`);

    const diag = quickDiagnosis();
    if (diag.wrongProfile.length > 0) {
      console.log(`  Found ${diag.wrongProfile.length} key(s) in interactive-only shell profile:`);
      for (const v of diag.wrongProfile) {
        console.log(`  ${c.yellow('\u2502')} ${c.dim('-')} ${v}`);
      }
    }
    console.log(divider('Next Steps'));
    console.log(`  ${c.cyan('Diagnose:')} npx secretless-ai doctor`);
    console.log();
    process.exit(1);
  }
  console.log();
}

export function runDoctor(autoFix: boolean): void {
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
    const profileStatus = profile.exists
      ? (profile.exportedVars.length > 0
          ? `${profile.exportedVars.length} key(s)`
          : 'no keys')
      : 'not found';
    console.log(`    ${profile.exists ? '+' : '-'} ~/${require('path').basename(profile.path)}${tag}: ${profileStatus}`);
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
