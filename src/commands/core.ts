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
import { VERSION, IS_EMBEDDED, formatUptime, formatRemainingTime } from './utils';
import { explainFinding, isEngineAvailable } from '../nanomind';
import { c, divider } from './colors';

export function runInit(projectDir: string): number {
  // Suppress the standalone brand+version banner when embedded under a host CLI
  // (SECRETLESS_CLI_PREFIX set) — it shows secretless's own version, which is
  // misleading under the host's umbrella. Keep the tagline.
  if (!IS_EMBEDDED) {
    console.log('\n  Secretless v' + VERSION);
  }
  console.log('  Keeping secrets out of AI\n');

  const result = init(projectDir);

  // Configured line: collapse Detected + Configured into one row that tells
  // the user what's now active and how it compares to what we found.
  const configuredCount = result.toolsConfigured.length;
  const detectedCount = result.toolsDetected.length;
  if (configuredCount > 0) {
    const names = result.toolsConfigured.map(toolDisplayName).join(', ');
    if (detectedCount === 0) {
      console.log(`  Configured: ${names} (no AI tools detected — defaulted to Claude Code)`);
    } else {
      console.log(`  Configured: ${names} (${configuredCount} of ${detectedCount} detected)`);
    }
  } else {
    console.log('  Configured: none');
  }

  // Files: keep the breakdown but with a specific deny-rule count when
  // settings.json was modified. The count is the load-bearing fact (not just
  // "modified") — users want to know what changed, not that it changed.
  const settingsModified = result.filesModified.includes('.claude/settings.json');
  const otherModified = result.filesModified.filter(f => f !== '.claude/settings.json');

  if (result.filesCreated.length > 0) {
    console.log();
    console.log('  Created:');
    for (const f of result.filesCreated) {
      console.log(`    + ${f}`);
    }
  }

  if (settingsModified || otherModified.length > 0) {
    console.log();
    console.log('  Modified:');
    if (settingsModified) {
      const changes: string[] = [];
      if (result.denyRulesAdded > 0) {
        changes.push(`added ${result.denyRulesAdded} deny pattern${result.denyRulesAdded === 1 ? '' : 's'}`);
      }
      if (result.denyRulesRemoved > 0) {
        changes.push(`removed ${result.denyRulesRemoved} deprecated pattern${result.denyRulesRemoved === 1 ? '' : 's'}`);
      }
      if (changes.length > 0) {
        console.log(`    ~ .claude/settings.json (${changes.join(', ')})`);
      } else {
        console.log(`    ~ .claude/settings.json`);
      }
    }
    for (const f of otherModified) {
      const suffix = (f === '.claude/hooks/secretless-guard.sh' && result.hookRefreshed) ? ' (refreshed to current version)' : '';
      console.log(`    ~ ${f}${suffix}`);
    }
  }

  // No-op case: nothing created, nothing modified — already up to date.
  if (result.filesCreated.length === 0 && !settingsModified && otherModified.length === 0) {
    console.log();
    console.log('  Already up to date. No files changed.');
  }

  // Surface inline observations: secrets found + shell profile fix. Each
  // observation ends in a runnable verb (no dead ends).
  if (result.secretsFound > 0) {
    console.log();
    console.log(`  Warning: ${result.secretsFound} hardcoded credential${result.secretsFound === 1 ? '' : 's'} in config files  → secretless-ai scan`);
  }

  const fix = fixProfiles();
  if (fix) {
    console.log();
    console.log(`  Shell profile fix: copied ${fix.fixed.length} export${fix.fixed.length === 1 ? '' : 's'} from ~/${fix.sourceProfile} to ~/${fix.targetProfile}`);
    for (const v of fix.fixed) {
      console.log(`    + ${v}`);
    }
    if (fix.created) {
      console.log(`    Created ~/${fix.targetProfile}`);
    }
    console.log('    Restart your terminal for changes to take effect.');
  }

  // Suggest warm for backends that trigger OS auth prompts.
  const configuredBackend = readBackendConfig();
  if (configuredBackend === '1password' || configuredBackend === 'keychain') {
    const backendName = configuredBackend === '1password' ? '1Password' : 'keychain';
    console.log();
    console.log(`  Tip: Run \`secretless-ai warm\` before starting an AI session to avoid`);
    console.log(`  repeated ${backendName} auth prompts.`);
  }

  // Next steps block — every action ends in a runnable verb.
  console.log();
  console.log('  Next steps:');
  console.log('    Verify: secretless-ai verify');
  console.log('    Scan:   secretless-ai scan');
  console.log('    Status: secretless-ai status');
  console.log();

  return 0;
}

export async function runScan(projectDir: string, options?: { includeTests?: boolean; explain?: boolean; noIgnore?: boolean; minConfidence?: number; json?: boolean; showPlaceholders?: boolean }): Promise<number> {
  const nodeFs = require('fs') as typeof import('fs');
  const scanOpts = {
    includeTests: options?.includeTests,
    // `noIgnore` disables BOTH the user `.secretlessignore` and the
    // default-ignore list. Used when a user wants to see every finding,
    // including known-fixture noise.
    ignore: options?.noIgnore ? false : undefined,
    minConfidence: options?.minConfidence,
    showPlaceholders: options?.showPlaceholders,
  };

  // --json: emit a single valid JSON document to stdout and nothing else, so the
  // output is machine-parseable (issue #63 — the flag previously printed the human
  // report). Errors go to stderr; exit code still signals findings for CI gating.
  if (options?.json) {
    if (!nodeFs.existsSync(projectDir)) {
      console.error(`Directory not found: ${projectDir}`);
      return 1;
    }
    const stats = { placeholdersSuppressed: 0 };
    const findings = scan(projectDir, scanOpts, stats);
    const critical = findings.filter(f => f.severity === 'critical').length;
    console.log(JSON.stringify({
      tool: 'secretless-ai',
      version: require('../../package.json').version,
      findings,
      summary: {
        total: findings.length,
        critical,
        high: findings.length - critical,
        placeholdersSuppressed: stats.placeholdersSuppressed,
      },
    }, null, 2));
    return findings.length > 0 ? 1 : 0;
  }

  console.log('\n  Secretless Scanner\n');

  if (!nodeFs.existsSync(projectDir)) {
    console.error(`  Directory not found: ${projectDir}`);
    console.error('  Check the path and try again.\n');
    return 1;
  }

  const stats = { placeholdersSuppressed: 0 };
  const findings = scan(projectDir, scanOpts, stats);

  // When everything (or a real subset) was hidden as a placeholder, say so and
  // point at the flag that reveals them. A silent "No credentials found" makes a
  // user who tested with obvious placeholder values think the scanner is broken,
  // and silently dropping a real-looking value whose host is `example.com` is the
  // over-suppression the audit flagged. The hint is suppressed once the user is
  // already showing placeholders.
  const placeholderHint = () => {
    if (stats.placeholdersSuppressed > 0 && !options?.showPlaceholders) {
      const n = stats.placeholdersSuppressed;
      console.log(`  ${c.dim(`${n} value${n > 1 ? 's' : ''} looked like a placeholder and ${n > 1 ? 'were' : 'was'} hidden.`)}`);
      console.log(`  ${c.dim('See them: npx secretless-ai scan --show-placeholders')}\n`);
    }
  };

  if (findings.length === 0) {
    console.log('  No hardcoded credentials found.');
    placeholderHint();
    console.log('  Verify keys are working: npx secretless-ai verify\n');
    return 0;
  }

  // If --explain requested, use NanoMind engine for rich context
  if (options?.explain) {
    return runScanWithExplanations(findings);
  }

  printFindings(findings);
  placeholderHint();
  return findings.length > 0 ? 1 : 0;
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
    // Confidence rendering: `confidence: high (0.92)`. Tier colour mirrors the
    // severity colour ramp \u2014 high green, medium yellow, low dim \u2014 so a low-
    // confidence high-severity finding still looks lower than a high-
    // confidence one without the user squinting at the number.
    const tierColor = finding.confidenceTier === 'high'
      ? c.green
      : finding.confidenceTier === 'medium'
        ? c.yellow
        : c.dim;
    const fixtureSuffix = finding.looksLikeFixture
      ? c.dim(' (looks like a test fixture)')
      : '';
    console.log();
    console.log(`  ${sevColor('\u2502')} ${c.bold(sevLabel)}  ${c.boldWhite(finding.patternName)}`);
    console.log(`  ${sevColor('\u2502')} ${c.dim(`${finding.file}:${finding.line}`)}${fixtureSuffix}`);
    console.log(`  ${sevColor('\u2502')} ${finding.preview}`);
    console.log(`  ${sevColor('\u2502')} ${c.cyan('Confidence:')} ${tierColor(`${finding.confidenceTier} (${finding.confidence.toFixed(2)})`)}`);
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

export function runStatus(projectDir: string): number {
  console.log('\n  Secretless Status\n');

  const s = status(projectDir);
  const session = getSessionStatus();
  const brokerStatus = getDaemonStatus();
  const brokerInstalled = isDaemonInstalled();
  const tp = s.transcriptProtection;
  const configuredBackend = readBackendConfig();

  // Build observation rows. Each row: glyph + label + optional → command.
  // Satisfied observations use ✓; needs-action use ⚠. Every ⚠ ends in a
  // runnable verb so the user has no dead end (CISO Rule 11).
  type Row = { glyph: '✓' | '⚠'; label: string; action?: string };
  const rows: Row[] = [];
  const addRow = (row: Row): void => { rows[rows.length] = row; };

  // Protection / hook.
  if (s.hookInstalled) {
    const denyText = s.denyRuleCount > 0 ? ` — ${s.denyRuleCount} deny pattern${s.denyRuleCount === 1 ? '' : 's'}` : '';
    addRow({ glyph: '✓', label: `Claude Code hook installed (.claude/settings.json${denyText})` });
  } else {
    addRow({ glyph: '⚠', label: 'Claude Code hook not installed', action: 'secretless-ai init' });
  }

  // Stop hook (transcript redaction).
  if (tp.stopHookInstalled) {
    addRow({ glyph: '✓', label: 'Stop hook installed (transcript redaction)' });
  } else {
    addRow({ glyph: '⚠', label: 'Stop hook not installed (transcripts unredacted)', action: 'secretless-ai init' });
  }

  // Configured tools (instructions present in tool config files).
  if (s.configuredTools.length > 0) {
    addRow({ glyph: '✓', label: `Tool instructions: ${s.configuredTools.map(toolDisplayName).join(', ')}` });
  }

  // Secrets in config files.
  if (s.secretsFound > 0) {
    addRow({ glyph: '⚠', label: `${s.secretsFound} credential${s.secretsFound === 1 ? '' : 's'} detected in config files`, action: 'secretless-ai scan' });
  } else {
    addRow({ glyph: '✓', label: 'No credentials in config files' });
  }

  // Session warmth (only relevant when a backend that prompts is configured).
  const sessionRelevant = configuredBackend === '1password' || configuredBackend === 'keychain';
  if (sessionRelevant) {
    if (session.warm) {
      addRow({ glyph: '✓', label: `Biometric session warm (expires ${formatRemainingTime(session.remainingSeconds)})` });
    } else if (session.authenticatedAt) {
      addRow({ glyph: '⚠', label: `Biometric session expired (last auth ${session.authenticatedAt})`, action: 'secretless-ai warm' });
    } else {
      addRow({ glyph: '⚠', label: 'Biometric session not initialized', action: 'secretless-ai warm' });
    }
  }

  // Watcher running (transcript file monitoring).
  if (tp.watcherRunning) {
    addRow({ glyph: '✓', label: 'Transcript watcher running' });
  } else {
    addRow({ glyph: '⚠', label: 'Transcript watcher not running', action: 'secretless-ai watch' });
  }

  // Transcript files + secrets within them.
  if (tp.transcriptSecretsFound > 0) {
    addRow({ glyph: '⚠', label: `${tp.transcriptSecretsFound} credential${tp.transcriptSecretsFound === 1 ? '' : 's'} in recent transcripts`, action: 'secretless-ai clean' });
  } else if (tp.transcriptFiles > 0) {
    addRow({ glyph: '✓', label: `Transcripts clean (${tp.transcriptFiles} file${tp.transcriptFiles === 1 ? '' : 's'} scanned)` });
  }

  // Broker daemon.
  if (brokerStatus) {
    addRow({ glyph: '✓', label: `Broker running (PID ${brokerStatus.pid}, ${formatUptime(brokerStatus.uptimeSeconds)})` });
  } else if (brokerInstalled) {
    addRow({ glyph: '⚠', label: 'Broker daemon not running', action: 'secretless-ai broker start' });
  } else {
    addRow({ glyph: '⚠', label: 'Broker daemon not installed', action: 'secretless-ai install' });
  }

  // Render the Observations block. We measure the visible width (glyph +
  // label) so the `→ command` column lines up tidily across rows.
  const headerLine = '──────────────────────────────────────────────────────────';
  console.log(`  ── Observations ${headerLine.slice(0, Math.max(0, 44))}`);
  let leftWidth = 0;
  for (const row of rows) {
    const visible = row.glyph + ' ' + row.label;
    if (visible.length > leftWidth) leftWidth = visible.length;
  }
  for (const row of rows) {
    const left = `${row.glyph} ${row.label}`;
    if (row.action) {
      const padded = left.padEnd(leftWidth, ' ');
      console.log(`  ${padded}  → ${row.action}`);
    } else {
      console.log(`  ${left}`);
    }
  }

  // Verdict — reflects warnings (count of ⚠ rows). "Protected" requires
  // the hook installed; "Clean" requires zero warnings.
  console.log();
  console.log(`  ── Verdict ${headerLine.slice(0, Math.max(0, 49))}`);
  const warningCount = rows.filter(r => r.glyph === '⚠').length;
  if (!s.isProtected) {
    console.log('  Not protected. Run `secretless-ai init` to install hooks.');
  } else if (warningCount === 0) {
    console.log('  Protected — Clean');
  } else {
    const credSuffix = s.secretsFound > 0
      ? ` (${s.secretsFound} unblocked credential${s.secretsFound === 1 ? '' : 's'} need review)`
      : ` (${warningCount} observation${warningCount === 1 ? '' : 's'} need attention)`;
    console.log(`  Protected${credSuffix}`);
  }

  console.log();
  return 0;
}

export function runVerify(projectDir: string, showAll = false): number {
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

  // Surface suppressed placeholders BEFORE the verdict, so a green pass is never silent
  // over a value verify chose to hide (a real key whose body contains a token like
  // `sample`/`xxx`, or a real key on a `# example` line, is suppressed by the shared
  // detection path — the user must be told to confirm it, not shown a bare PASS).
  if (result.placeholdersSuppressed > 0) {
    const n = result.placeholdersSuppressed;
    console.log();
    console.log(`  ${c.dim(`${n} value${n > 1 ? 's' : ''} in AI context looked like a placeholder and ${n > 1 ? 'were' : 'was'} not counted.`)}`);
    console.log(`  ${c.dim('Confirm none are real: npx secretless-ai scan --show-placeholders')}`);
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
    return 1;
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
    return 1;
  }
  console.log();
  return 0;
}

export function runDoctor(autoFix: boolean): number {
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
      return 0;
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
    return 1;
  }
  return 0;
}
