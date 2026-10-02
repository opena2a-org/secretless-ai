/**
 * Auto-detect which AI tools are present in a project.
 */

import * as fs from 'fs';
import * as path from 'path';

export type AITool = 'claude-code' | 'cursor' | 'copilot' | 'windsurf' | 'cline' | 'aider';

interface DetectionResult {
  tool: AITool;
  configDir: string;
  settingsFile: string;
  /**
   * Project-relative paths, any one of which `init` may write the Secretless
   * instruction block into for this tool. `status` lists the tool as
   * configured when one of them is a regular file carrying the block. Listed
   * here, next to the markers, so detection and the configured check cannot
   * drift apart again: `status` used to read `settingsFile`, which for Cursor
   * was a settings path `init` never wrote, so Cursor was never listed.
   */
  instructionFiles: string[];
  hooksSupported: boolean;
}

const DETECTORS: Array<{
  tool: AITool;
  markers: string[];
  configDir: string;
  settingsFile: string;
  instructionFiles: string[];
  hooksSupported: boolean;
}> = [
  {
    tool: 'claude-code',
    markers: ['.claude', 'CLAUDE.md', '.claude/settings.json'],
    configDir: '.claude',
    settingsFile: '.claude/settings.json',
    instructionFiles: ['CLAUDE.md'],
    hooksSupported: true,
  },
  {
    tool: 'cursor',
    markers: ['.cursor', '.cursorrules', '.cursor/rules'],
    configDir: '.cursor',
    settingsFile: '.cursor/settings.json',
    // The documented rule file first; the legacy single file is appended to
    // only when the user already has one.
    instructionFiles: ['.cursor/rules/secretless.mdc', '.cursorrules'],
    hooksSupported: false,
  },
  {
    tool: 'copilot',
    markers: ['.github/copilot-instructions.md', '.copilot'],
    configDir: '.github',
    settingsFile: '.github/copilot-instructions.md',
    instructionFiles: ['.github/copilot-instructions.md'],
    hooksSupported: false,
  },
  {
    tool: 'windsurf',
    markers: ['.windsurfrules', '.windsurf'],
    configDir: '.windsurf',
    settingsFile: '.windsurfrules',
    instructionFiles: ['.windsurfrules'],
    hooksSupported: false,
  },
  {
    tool: 'cline',
    markers: ['.clinerules', '.cline'],
    configDir: '.cline',
    settingsFile: '.clinerules',
    // `.clinerules` as a regular file (legacy, appended to when present), or
    // the Secretless-owned file inside either documented rules directory.
    instructionFiles: ['.clinerules', '.clinerules/secretless.md', '.cline/rules/secretless.md'],
    hooksSupported: false,
  },
  {
    tool: 'aider',
    markers: ['.aider.conf.yml', '.aiderignore'],
    configDir: '.',
    settingsFile: '.aider.conf.yml',
    // `init` configures Aider through `.aiderignore`, which carries no
    // instruction block; this keeps the previous `status` read unchanged.
    instructionFiles: ['.aider.conf.yml'],
    hooksSupported: false,
  },
];

/**
 * Detect AI tools present in the project directory.
 * Returns all detected tools sorted by priority (hooks-capable first).
 */
export function detectAITools(projectDir: string): DetectionResult[] {
  const results: DetectionResult[] = [];

  for (const detector of DETECTORS) {
    const found = detector.markers.some(marker => {
      const fullPath = path.join(projectDir, marker);
      return fs.existsSync(fullPath);
    });

    if (found) {
      results.push({
        tool: detector.tool,
        configDir: detector.configDir,
        settingsFile: detector.settingsFile,
        instructionFiles: detector.instructionFiles,
        hooksSupported: detector.hooksSupported,
      });
    }
  }

  // Sort: hooks-capable tools first
  results.sort((a, b) => {
    if (a.hooksSupported && !b.hooksSupported) return -1;
    if (!a.hooksSupported && b.hooksSupported) return 1;
    return 0;
  });

  return results;
}

/** Get display name for a tool */
export function toolDisplayName(tool: AITool): string {
  const names: Record<AITool, string> = {
    'claude-code': 'Claude Code',
    'cursor': 'Cursor',
    'copilot': 'GitHub Copilot',
    'windsurf': 'Windsurf',
    'cline': 'Cline',
    'aider': 'Aider',
  };
  return names[tool];
}
