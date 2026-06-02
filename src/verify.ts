/**
 * Verify that secrets are accessible via env vars but NOT in AI context files.
 * This is the core dogfooding test: can the agent USE keys without SEEING them.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CREDENTIAL_PATTERNS, CONFIG_FILES } from './patterns';
import { findRealMatch } from './scan';
import { discoverTranscripts, scanTranscriptFile } from './transcript';

export interface VerifyResult {
  /** Env var name → whether it's set */
  envVars: Record<string, boolean>;
  /** Credentials found in AI context files (should be empty) */
  exposedInContext: Array<{
    envVar: string;
    patternName: string;
    file: string;
    line: number;
  }>;
  /** Credentials found in transcript files */
  exposedInTranscripts: Array<{
    file: string;
    line: number;
    jsonPath: string;
    patternName: string;
  }>;
  /**
   * Count of values in AI-context files suppressed as known examples / placeholders
   * (same suppression `scan` applies). Surfaced so verify never reports a silent green
   * pass while having hidden a value — a real key whose random body contains a token
   * like `sample`/`xxx`, or a real key on a `# example` line, would otherwise vanish.
   */
  placeholdersSuppressed: number;
  /** Overall pass/fail */
  passed: boolean;
}

/** Files that are loaded into the AI context window */
const AI_CONTEXT_FILES = [
  // Global
  path.join(os.homedir(), '.claude', 'CLAUDE.md'),
  path.join(os.homedir(), '.claude', 'settings.json'),
];

/** Project-level files that end up in AI context */
const PROJECT_CONTEXT_FILES = [
  'CLAUDE.md',
  '.cursorrules',
  '.windsurfrules',
  '.clinerules',
  '.github/copilot-instructions.md',
  '.claude/settings.json',
  '.cursor/mcp.json',
  '.vscode/mcp.json',
  'mcp.json',
  '.env',
  '.env.local',
  'config.json',
];

/**
 * Verify secrets are properly managed: accessible via env vars, absent from context.
 */
export function verify(projectDir: string): VerifyResult {
  const envVars: Record<string, boolean> = {};
  const exposedInContext: VerifyResult['exposedInContext'] = [];
  const exposedInTranscripts: VerifyResult['exposedInTranscripts'] = [];
  let placeholdersSuppressed = 0;

  // Deduplicate env var names across patterns
  const uniqueEnvVars = [...new Set(CREDENTIAL_PATTERNS.map((p) => p.envPrefix))];

  // Check which env vars are set
  for (const envVar of uniqueEnvVars) {
    envVars[envVar] = !!process.env[envVar] && process.env[envVar]!.length > 0;
  }

  // Build list of all files to check
  const filesToCheck: Array<{ absPath: string; label: string }> = [];

  for (const global of AI_CONTEXT_FILES) {
    filesToCheck.push({ absPath: global, label: global.replace(os.homedir(), '~') });
  }

  for (const rel of PROJECT_CONTEXT_FILES) {
    filesToCheck.push({ absPath: path.join(projectDir, rel), label: rel });
  }

  // Scan each file for credential patterns
  for (const { absPath, label } of filesToCheck) {
    if (!fs.existsSync(absPath)) continue;
    try {
      const stat = fs.statSync(absPath);
      if (!stat.isFile() || stat.size > 10 * 1024 * 1024) continue;

      const content = fs.readFileSync(absPath, 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 4096) continue;

        for (const pattern of CREDENTIAL_PATTERNS) {
          // Use the SAME detection path as `scan` (findRealMatch applies the known-example
          // / placeholder suppression in isKnownExample). Previously verify used a raw
          // `pattern.regex.test(line)`, so a placeholder like `sk-ant-api03-FAKE…` was
          // flagged here but suppressed by scan — the two commands disagreed on the same
          // file (#64). We count suppressed values so verify can SURFACE them: silently
          // hiding a value here is dangerous because verify answers "is a real key exposed
          // right now?" and a real key whose body contains a token like `sample`/`xxx`
          // would otherwise vanish into a green pass.
          if (findRealMatch(line, pattern, { onSuppressed: () => { placeholdersSuppressed += 1; } })) {
            exposedInContext.push({
              envVar: pattern.envPrefix,
              patternName: pattern.name,
              file: label,
              line: i + 1,
            });
            break;
          }
        }
      }
    } catch {
      // Skip unreadable
    }
  }

  // Scan recent transcript files (5 most recent for speed). NOTE: the transcript path
  // (scanTranscriptFile) intentionally does NOT apply placeholder suppression — a
  // transcript is historical leak data, so we flag everything that matches rather than
  // risk hiding a real value that was already sent to a provider. This asymmetry with the
  // file-scan path above is deliberate: suppress-but-surface for current config files,
  // flag-everything for what already leaked.
  try {
    const transcripts = discoverTranscripts();
    const recentTranscripts = transcripts.filter(f => f.endsWith('.jsonl')).slice(0, 5);
    for (const file of recentTranscripts) {
      const { findings } = scanTranscriptFile(file, true);
      for (const f of findings) {
        exposedInTranscripts.push({
          file: f.file,
          line: f.line,
          jsonPath: f.jsonPath,
          patternName: f.patternName,
        });
      }
    }
  } catch {
    // Transcript scanning is best-effort
  }

  // Pass = at least one env var is set AND zero credentials exposed
  const anyEnvSet = Object.values(envVars).some((v) => v);
  const passed = anyEnvSet && exposedInContext.length === 0 && exposedInTranscripts.length === 0;

  return { envVars, exposedInContext, exposedInTranscripts, placeholdersSuppressed, passed };
}
