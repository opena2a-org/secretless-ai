/**
 * Check Secretless AI protection status for a project.
 */

import * as fs from 'fs';
import * as path from 'path';
import { detectAITools, type AITool } from './detect';
import { scan } from './scan';
import { discoverTranscripts, scanTranscriptFile } from './transcript';
import { isWatchRunning } from './watch';

/**
 * How many of the most recent transcripts `status` reads. A full pass is a
 * `clean --dry-run` job (tens of seconds over thousands of files); `status` is
 * expected to answer immediately. Exported so the renderer and the tests state
 * the same number rather than each hardcoding their own.
 */
export const TRANSCRIPT_SAMPLE_SIZE = 3;

export interface StatusResult {
  isProtected: boolean;
  configuredTools: AITool[];
  hookInstalled: boolean;
  /**
   * Deny patterns in effect, or NULL when the count was not measured.
   *
   * Null in BOTH unknown states — a settings file that would not parse, and one
   * whose keys collide. A number implies a measurement, and `0` over a file we
   * could not read is a parse artifact, not a count. Two different spellings of
   * unknown in one contract is the defect class this release exists to close.
   */
  denyRuleCount: number | null;
  secretsFound: number;
  /**
   * True when the scan behind `secretsFound` could not cover the whole tree, so
   * the count is a lower bound rather than a verdict. `scan()` discards this
   * when no stats object is passed, which is how `status --json` reported
   * `secretsFound: 0` over a subtree it never opened.
   */
  scanIncomplete: boolean;
  /**
   * Set when `.claude/settings.json` exists but does not parse as a JSON
   * object, so `denyRuleCount` and `stopHookInstalled` describe nothing that
   * was read. Without it, an unparseable settings file is indistinguishable
   * from an unconfigured project — both render as "0 deny patterns" — which
   * is the same "an answer we never got is not a good answer" gap that
   * `truncated` closes for scan coverage.
   */
  settingsUnreadable?: { path: string; reason: string };
  /**
   * Present when the settings file PARSES but carries a colliding member name,
   * so what it configures cannot be read as written.
   *
   * Distinct from `settingsUnreadable`: the file is valid JSON and throws
   * nothing. `JSON.parse` keeps the last copy of a repeated key, so a file
   * whose `permissions` block appears twice loses every deny pattern in the
   * first copy — silently, in Claude Code, which is what enforces them. This
   * tool's defect was reporting `0` for that, indistinguishable from a project
   * that configured none.
   *
   * Also carries the case where the duplicate scanner itself could not load.
   * `status` is a reporting command: it does not throw on an installation
   * fault the way the policy loader does, and it does not continue as though
   * the check had passed. It reports that it could not tell.
   */
  settingsAmbiguous?: { path: string; reason: string };
  transcriptProtection: {
    stopHookInstalled: boolean;
    watcherRunning: boolean;
    transcriptFiles: number;
    /**
     * How many of `transcriptFiles` were actually read. `status` samples the
     * most recent few so it stays sub-second; `transcriptFiles` is a discovery
     * count and was being rendered as "N files scanned", which turned a
     * three-file sample into a clean verdict over everything. Measured on a real
     * machine: `status` reported 0 secrets in "8850 files scanned" while
     * `clean --dry-run` found 882 credentials in 168 of those same files.
     *
     * Same "an answer we never got is not a good answer" gap as
     * `settingsUnreadable` above and as `truncated` for scan coverage.
     */
    transcriptFilesScanned: number;
    transcriptSecretsFound: number;
  };
}

/**
 * Check the current protection status of the project.
 */
export async function status(projectDir: string): Promise<StatusResult> {
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
      transcriptFilesScanned: 0,
      transcriptSecretsFound: 0,
    },
  };

  // Check Claude Code hook
  const hookPath = path.join(projectDir, '.claude', 'hooks', 'secretless-guard.sh');
  result.hookInstalled = fs.existsSync(hookPath);

  // Check Claude Code deny rules and Stop hook
  const settingsPath = path.join(projectDir, '.claude', 'settings.json');
  if (fs.existsSync(settingsPath)) {
    // A settings file we cannot read is not a settings file with no rules in
    // it. Both used to render as "0 deny patterns", so a project whose
    // protection had never been wired up looked exactly like a healthy one.
    let settings: any;
    // Hoisted so the duplicate scan below reads the SAME bytes the parser
    // consumed. Re-reading the file there would let the two judge different
    // content, which is the defect one level over.
    let rawSettings = '';
    try {
      rawSettings = fs.readFileSync(settingsPath, 'utf-8');

      const parsed = JSON.parse(rawSettings);
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        result.settingsUnreadable = {
          path: '.claude/settings.json',
          reason: 'its top level is not a JSON object',
        };
      } else {
        settings = parsed;
      }
    } catch (err) {
      result.settingsUnreadable = {
        path: '.claude/settings.json',
        reason: (err as Error).message,
      };
    }

    if (!settings) {
      // Could not read it at all: the initial 0 would read as a measurement.
      result.denyRuleCount = null;
    }

    // Scanned on the RAW TEXT — the same bytes JSON.parse consumed, never the
    // parsed object, because the parser resolves a repeated member before any
    // consumer can see it.
    //
    // Ordered AFTER the parse has classified the file, not because the scan
    // needs the result but because the two failures are DIFFERENT states: text
    // that does not parse is `settingsUnreadable`, and running the scan on it
    // first set both flags and collapsed the distinction the fix exists to
    // create. A file only reaches here if it parsed.
    if (settings) {
      try {
        const { firstDuplicateMember } = await import('@opena2a/atx-verify');
        const dup = firstDuplicateMember(rawSettings);
        if (dup !== null) {
          result.settingsAmbiguous = {
            path: '.claude/settings.json',
            reason: `repeats "${dup}", so only the last copy is in effect`,
          };
        }
      } catch (err) {
        // The scan could not run over text that DID parse: an installation
        // fault, or input the parser accepted and the scanner will not vouch
        // for. Reported, not thrown — this is a reporting command and an
        // installation fault is not a broken project — and not swallowed,
        // which would restore the green this exists to remove.
        result.settingsAmbiguous = {
          path: '.claude/settings.json',
          reason: `keys could not be checked for collisions: ${(err as Error).message}`,
        };
      }
    }

    if (settings) {
      // Left null when a collision means the file does not say what it reads as.
      result.denyRuleCount = result.settingsAmbiguous
        ? null
        : settings?.permissions?.deny?.length || 0;

      // Check for Stop hook
      const stopHooks = settings?.hooks?.Stop || [];
      result.transcriptProtection.stopHookInstalled = stopHooks.some(
        (h: any) => h.hooks?.some((hh: any) => hh.command?.includes('secretless-ai'))
      );
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

    // Sample the most recent transcripts so `status` stays sub-second — a full
    // pass over every transcript takes tens of seconds and belongs in `clean`.
    // `discoverTranscripts` sorts by mtime descending, so these really are the
    // most recent. The count of what was read is recorded and reported: a zero
    // over three files is not a statement about the other 8847.
    const recentFiles = jsonlFiles.slice(0, TRANSCRIPT_SAMPLE_SIZE);
    for (const file of recentFiles) {
      const { findings: transcriptFindings } = scanTranscriptFile(file, true);
      result.transcriptProtection.transcriptSecretsFound += transcriptFindings.length;
      result.transcriptProtection.transcriptFilesScanned += 1;
    }
  } catch {
    // Transcript scanning is best-effort
  }

  // Protected if hook is installed OR instructions are present in at least one tool
  // An unreadable `.claude/settings.json` means the deny rules and the
  // PreToolUse wiring could not be read at all. The guard script existing on
  // disk is not protection on its own, so claiming `isProtected` here would be
  // asserting something we never verified — fail closed instead.
  result.isProtected = !result.settingsUnreadable
    && (result.hookInstalled || result.configuredTools.length > 0);

  return result;
}
