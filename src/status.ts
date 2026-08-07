/**
 * Check Secretless AI protection status for a project.
 */

import * as fs from 'fs';
import * as path from 'path';
import { detectAITools, type AITool } from './detect';
import { scan } from './scan';
import { discoverTranscripts, scanTranscriptFile } from './transcript';
import { isWatchRunning } from './watch';

export interface StatusResult {
  isProtected: boolean;
  configuredTools: AITool[];
  hookInstalled: boolean;
  denyRuleCount: number;
  secretsFound: number;
  /**
   * True when the scan behind `secretsFound` could not cover the whole tree, so
   * the count is a lower bound rather than a verdict. `scan()` discards this
   * when no stats object is passed, which is how `status --json` reported
   * `secretsFound: 0` over a subtree it never opened.
   */
  scanIncomplete: boolean;
  transcriptProtection: {
    stopHookInstalled: boolean;
    watcherRunning: boolean;
    transcriptFiles: number;
    transcriptSecretsFound: number;
  };
}

/**
 * Check the current protection status of the project.
 */
export function status(projectDir: string): StatusResult {
  const result: StatusResult = {
    isProtected: false,
    configuredTools: [],
    hookInstalled: false,
    denyRuleCount: 0,
    secretsFound: 0,
    scanIncomplete: false,
    transcriptProtection: {
      stopHookInstalled: false,
      watcherRunning: false,
      transcriptFiles: 0,
      transcriptSecretsFound: 0,
    },
  };

  // Check Claude Code hook
  const hookPath = path.join(projectDir, '.claude', 'hooks', 'secretless-guard.sh');
  result.hookInstalled = fs.existsSync(hookPath);

  // Check Claude Code deny rules and Stop hook
  const settingsPath = path.join(projectDir, '.claude', 'settings.json');
  if (fs.existsSync(settingsPath)) {
    try {
      const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      result.denyRuleCount = settings?.permissions?.deny?.length || 0;

      // Check for Stop hook
      const stopHooks = settings?.hooks?.Stop || [];
      result.transcriptProtection.stopHookInstalled = stopHooks.some(
        (h: any) => h.hooks?.some((hh: any) => hh.command?.includes('secretless-ai'))
      );
    } catch {
      // Invalid JSON
    }
  }

  // Check which tools have Secretless AI instructions
  const detected = detectAITools(projectDir);
  for (const tool of detected) {
    const filePath = path.join(projectDir, tool.settingsFile);
    if (fs.existsSync(filePath)) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        if (content.includes('secretless:managed') || content.includes('Secretless AI')) {
          result.configuredTools.push(tool.tool);
        }
      } catch {
        // Skip
      }
    }
  }

  // Also check CLAUDE.md directly
  const claudeMd = path.join(projectDir, 'CLAUDE.md');
  if (fs.existsSync(claudeMd)) {
    try {
      const content = fs.readFileSync(claudeMd, 'utf-8');
      if (content.includes('secretless:managed') && !result.configuredTools.includes('claude-code')) {
        result.configuredTools.push('claude-code');
      }
    } catch {
      // Skip
    }
  }

  // Scan for secrets (project-level only for status report)
  const scanStats = { placeholdersSuppressed: 0, truncated: false, unreadable: [] as string[] };
  const findings = scan(projectDir, { scanGlobal: false }, scanStats);
  result.secretsFound = findings.length;
  result.scanIncomplete = scanStats.truncated || scanStats.unreadable.length > 0;

  // Transcript protection metrics
  try {
    const transcripts = discoverTranscripts();
    const jsonlFiles = transcripts.filter(f => f.endsWith('.jsonl'));
    result.transcriptProtection.transcriptFiles = jsonlFiles.length;
    result.transcriptProtection.watcherRunning = isWatchRunning();

    // Quick scan of 3 most recent transcripts
    const recentFiles = jsonlFiles.slice(0, 3);
    for (const file of recentFiles) {
      const { findings: transcriptFindings } = scanTranscriptFile(file, true);
      result.transcriptProtection.transcriptSecretsFound += transcriptFindings.length;
    }
  } catch {
    // Transcript scanning is best-effort
  }

  // Protected if hook is installed OR instructions are present in at least one tool
  result.isProtected = result.hookInstalled || result.configuredTools.length > 0;

  return result;
}
