/**
 * Shell Profile Doctor
 *
 * Diagnoses why API keys set in shell profiles aren't available in
 * non-interactive subprocesses like Claude Code's Bash tool, CI/CD, or Docker.
 *
 * Cross-platform:
 *   macOS/zsh:  .zshenv (all shells) vs .zshrc (interactive-only)
 *   Linux/bash: .bashrc (before interactive guard) vs .bash_profile (login-only)
 *   Windows:    System env vars (setx) vs PowerShell $PROFILE (session-only)
 *
 * Security: Only reads shell profiles to detect and relocate export lines.
 * Never stores key values in its own files or state.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { CREDENTIAL_PATTERNS } from './patterns';

// ── Types ────────────────────────────────────────────────────────────────────

export interface DoctorOptions {
  homeDir?: string;
  shell?: string;
  platform?: string;
  envOverride?: Record<string, string | undefined>;
  /** If true, don't execute system commands (setx on Windows). For testing. */
  dryRun?: boolean;
}

export type Severity = 'error' | 'warn' | 'info';
export type HealthStatus = 'healthy' | 'degraded' | 'broken';

export interface DoctorFinding {
  severity: Severity;
  message: string;
  fix?: string;
}

export interface ProfileInfo {
  path: string;
  exists: boolean;
  /** Which env var names have export lines (not commented out) */
  exportedVars: string[];
  /** Whether this profile is sourced by non-interactive shells */
  nonInteractive: boolean;
  /** Recommendation label for this profile */
  recommendation: 'recommended' | 'interactive-only' | 'login-only' | 'none';
}

export interface DoctorResult {
  platform: string;
  shell: string;
  profiles: ProfileInfo[];
  findings: DoctorFinding[];
  health: HealthStatus;
}

export interface QuickDiagnosisResult {
  /** Env var names found in interactive-only profiles but missing from process.env */
  wrongProfile: string[];
  /** Env var names not found in any profile */
  missingEverywhere: string[];
}

export interface FixResult {
  /** Env var names that were fixed */
  fixed: string[];
  /** Source profile the values were found in */
  sourceProfile: string;
  /** Destination profile or mechanism used for the fix */
  targetProfile: string;
  /** Whether the target profile was created (vs appended to) */
  created: boolean;
  /** For Windows: setx commands that were executed */
  commands?: string[];
}

// ── Shell profile knowledge ──────────────────────────────────────────────────

interface ProfileSpec {
  /** Relative to home directory */
  file: string;
  nonInteractive: boolean;
  recommendation: 'recommended' | 'interactive-only' | 'login-only' | 'none';
  /** Profile syntax: bash/zsh use `export VAR=`, PowerShell uses `$env:VAR =` */
  syntax?: 'posix' | 'powershell';
}

const ZSH_PROFILES: ProfileSpec[] = [
  { file: '.zshenv', nonInteractive: true, recommendation: 'recommended' },
  { file: '.zshrc', nonInteractive: false, recommendation: 'interactive-only' },
  { file: '.zprofile', nonInteractive: false, recommendation: 'login-only' },
];

const BASH_PROFILES: ProfileSpec[] = [
  { file: '.bashrc', nonInteractive: false, recommendation: 'recommended' },
  { file: '.bash_profile', nonInteractive: false, recommendation: 'login-only' },
  { file: '.profile', nonInteractive: false, recommendation: 'login-only' },
];

const POWERSHELL_PROFILES: ProfileSpec[] = [
  { file: 'Documents/PowerShell/Microsoft.PowerShell_profile.ps1', nonInteractive: false, recommendation: 'interactive-only', syntax: 'powershell' },
  { file: 'Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1', nonInteractive: false, recommendation: 'interactive-only', syntax: 'powershell' },
];

// ── Known env var names to look for ──────────────────────────────────────────

function getKnownEnvVarNames(): string[] {
  const names = new Set<string>();
  for (const p of CREDENTIAL_PATTERNS) {
    names.add(p.envPrefix);
  }
  return [...names];
}

// ── Profile scanning ─────────────────────────────────────────────────────────

// POSIX (bash/zsh): export VAR_NAME="value"
const EXPORT_LINE_RE = /^\s*export\s+([A-Z_][A-Z0-9_]*)=/;
const COMMENT_RE = /^\s*#/;

// PowerShell: $env:VAR_NAME = "value"
const PS_ENV_LINE_RE = /^\s*\$env:([A-Z_][A-Z0-9_]*)\s*=/;

function scanProfile(filePath: string, knownVars: string[], syntax: 'posix' | 'powershell' = 'posix'): string[] {
  if (!fs.existsSync(filePath)) return [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const lineRe = syntax === 'powershell' ? PS_ENV_LINE_RE : EXPORT_LINE_RE;
  const found: string[] = [];
  for (const line of content.split('\n')) {
    if (COMMENT_RE.test(line)) continue;
    const match = lineRe.exec(line);
    if (match && knownVars.includes(match[1])) {
      found.push(match[1]);
    }
  }
  return found;
}

/** Extract full export lines (verbatim) for specific var names from a profile */
function extractExportLines(filePath: string, varNames: string[], syntax: 'posix' | 'powershell' = 'posix'): Map<string, string> {
  const result = new Map<string, string>();
  if (!fs.existsSync(filePath)) return result;

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return result;
  }

  const lineRe = syntax === 'powershell' ? PS_ENV_LINE_RE : EXPORT_LINE_RE;
  for (const line of content.split('\n')) {
    if (COMMENT_RE.test(line)) continue;
    const match = lineRe.exec(line);
    if (match && varNames.includes(match[1])) {
      result.set(match[1], line);
    }
  }
  return result;
}

/**
 * Extract the value from a PowerShell `$env:VAR = "value"` line.
 * Handles double-quoted, single-quoted, and unquoted values.
 */
function extractPsValue(line: string): string | null {
  // Match: $env:VAR = "value" or $env:VAR = 'value' or $env:VAR = value
  const match = line.match(/^\s*\$env:[A-Z_][A-Z0-9_]*\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))/);
  if (!match) return null;
  return match[1] ?? match[2] ?? match[3] ?? null;
}

/** Resolve which profile specs to use for the given shell/platform */
function resolveProfileSpecs(shell: string, platform: string): ProfileSpec[] {
  if (platform === 'win32') {
    return POWERSHELL_PROFILES;
  }
  const shellName = path.basename(shell);
  if (shellName === 'zsh' || shell.endsWith('/zsh')) {
    return ZSH_PROFILES;
  } else if (shellName === 'bash' || shell.endsWith('/bash')) {
    return BASH_PROFILES;
  }
  return platform === 'darwin' ? ZSH_PROFILES : BASH_PROFILES;
}

// ── Bash interactive guard detection ─────────────────────────────────────────

/**
 * On most Linux distros, .bashrc starts with an interactive guard:
 *   case $- in *i*) ;; *) return;; esac
 * or:
 *   [ -z "$PS1" ] && return
 *
 * Exports placed AFTER this guard won't be set in non-interactive shells.
 * This function finds the line number of the guard so we can insert before it.
 */
function findBashInteractiveGuard(content: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    // case $- in pattern (Debian/Ubuntu)
    if (/^case\s+\$-\s+in/.test(line)) return i;
    // [ -z "$PS1" ] && return (some distros)
    if (/\[\s*-z\s+"\$PS1"\s*\]/.test(line)) return i;
    // [[ $- != *i* ]] && return (another variant)
    if (/\[\[\s*\$-\s*!=\s*\*i\*\s*\]\]/.test(line)) return i;
  }
  return -1; // No guard found
}

// ── Main doctor function ─────────────────────────────────────────────────────

export function doctor(options?: DoctorOptions): DoctorResult {
  const home = options?.homeDir ?? os.homedir();
  const shell = options?.shell ?? process.env.SHELL ?? '';
  const platform = options?.platform ?? os.platform();
  const env = options?.envOverride ?? process.env;
  const knownVars = getKnownEnvVarNames();

  // Pick profile specs based on shell/platform
  const shellName = platform === 'win32' ? 'powershell' : path.basename(shell);
  const specs = resolveProfileSpecs(shell, platform);

  // Scan each profile
  const profiles: ProfileInfo[] = specs.map((spec) => {
    const fullPath = path.join(home, spec.file);
    const exists = fs.existsSync(fullPath);
    const syntax = spec.syntax ?? 'posix';
    const exportedVars = exists ? scanProfile(fullPath, knownVars, syntax) : [];
    return {
      path: fullPath,
      exists,
      exportedVars,
      nonInteractive: spec.nonInteractive,
      recommendation: spec.recommendation,
    };
  });

  // Build findings
  const findings: DoctorFinding[] = [];

  // Check each known env var
  const varsInEnv = knownVars.filter((v) => !!env[v]);

  // Vars in a non-recommended profile but not in env
  const allExportedVars = new Set<string>();
  const varsInNonInteractiveProfile = new Set<string>();
  const varsInInteractiveOnlyProfile = new Set<string>();

  for (const profile of profiles) {
    for (const v of profile.exportedVars) {
      allExportedVars.add(v);
      if (profile.nonInteractive) {
        varsInNonInteractiveProfile.add(v);
      } else {
        varsInInteractiveOnlyProfile.add(v);
      }
    }
  }

  // Windows: keys in PS profile but not in system env
  if (platform === 'win32') {
    for (const v of varsInInteractiveOnlyProfile) {
      if (!env[v]) {
        findings.push({
          severity: 'error',
          message: `${v} is in PowerShell $PROFILE (session-only) but not set as a system environment variable`,
          fix: `Run: setx ${v} "<value>" (sets persistent user env var)`,
        });
      }
    }
    for (const v of varsInEnv) {
      if (varsInInteractiveOnlyProfile.has(v)) {
        findings.push({
          severity: 'info',
          message: `${v} is available (set as system environment variable)`,
        });
      } else if (!allExportedVars.has(v)) {
        findings.push({
          severity: 'info',
          message: `${v} is correctly configured and available`,
        });
      }
    }
  } else {
    // macOS/Linux: keys in wrong profile
    for (const v of varsInInteractiveOnlyProfile) {
      if (!varsInNonInteractiveProfile.has(v) && !env[v]) {
        const interactiveProfile = profiles.find(
          (p) => !p.nonInteractive && p.exportedVars.includes(v),
        );
        const recommendedProfile = profiles.find((p) => p.recommendation === 'recommended');

        if (interactiveProfile && recommendedProfile) {
          findings.push({
            severity: 'error',
            message: `${v} is in ~/${path.basename(interactiveProfile.path)} (interactive-only) but not available in subprocesses`,
            fix: `Move the export line from ~/${path.basename(interactiveProfile.path)} to ~/${path.basename(recommendedProfile.path)}`,
          });
        }
      }
    }

    // Vars in env and in non-interactive profile = healthy
    for (const v of varsInEnv) {
      if (varsInNonInteractiveProfile.has(v)) {
        findings.push({
          severity: 'info',
          message: `${v} is correctly configured and available`,
        });
      } else if (varsInInteractiveOnlyProfile.has(v)) {
        const recommendedProfile = profiles.find((p) => p.recommendation === 'recommended');
        if (recommendedProfile) {
          findings.push({
            severity: 'warn',
            message: `${v} works in your terminal but may fail in subprocesses (CI, Docker, Claude Code Bash)`,
            fix: `Move the export line to ~/${path.basename(recommendedProfile.path)}`,
          });
        }
      }
    }
  }

  // Determine health
  let health: HealthStatus = 'healthy';
  if (findings.some((f) => f.severity === 'error')) {
    health = 'broken';
  } else if (findings.some((f) => f.severity === 'warn')) {
    health = 'degraded';
  } else if (varsInEnv.length === 0 && allExportedVars.size === 0) {
    health = 'broken';
    const fixTarget = platform === 'win32'
      ? 'Use setx or Settings > System > Environment Variables'
      : `Add export lines to ~/${path.basename(profiles.find((p) => p.recommendation === 'recommended')?.path ?? specs[0].file)}`;
    findings.push({
      severity: 'error',
      message: 'No API keys found in env vars or shell profiles',
      fix: fixTarget,
    });
  }

  return {
    platform,
    shell: shellName || 'unknown',
    profiles,
    findings,
    health,
  };
}

// ── Quick diagnosis (lightweight, for verify output) ─────────────────────────

export function quickDiagnosis(options?: DoctorOptions): QuickDiagnosisResult {
  const home = options?.homeDir ?? os.homedir();
  const shell = options?.shell ?? process.env.SHELL ?? '';
  const platform = options?.platform ?? os.platform();
  const env = options?.envOverride ?? process.env;
  const knownVars = getKnownEnvVarNames();

  // Only check the 2-3 most common profiles
  const shellName = path.basename(shell);
  let quickProfiles: ProfileSpec[];
  if (shellName === 'zsh' || shell.endsWith('/zsh') || platform === 'darwin') {
    quickProfiles = [
      { file: '.zshenv', nonInteractive: true, recommendation: 'recommended' },
      { file: '.zshrc', nonInteractive: false, recommendation: 'interactive-only' },
    ];
  } else {
    quickProfiles = [
      { file: '.bashrc', nonInteractive: false, recommendation: 'recommended' },
      { file: '.bash_profile', nonInteractive: false, recommendation: 'login-only' },
    ];
  }

  const wrongProfile: string[] = [];
  const allFound = new Set<string>();

  for (const spec of quickProfiles) {
    const fullPath = path.join(home, spec.file);
    const exported = scanProfile(fullPath, knownVars);
    for (const v of exported) {
      allFound.add(v);
      // In an interactive-only profile and not in env = wrong profile
      if (!spec.nonInteractive && !env[v]) {
        wrongProfile.push(v);
      }
    }
  }

  // Vars not found in any checked profile and not in env
  const missingEverywhere = knownVars.filter((v) => !allFound.has(v) && !env[v]);

  return { wrongProfile, missingEverywhere };
}

// ── Auto-fix: copy exports to the correct profile ────────────────────────────

/**
 * Detects export lines in wrong shell profiles and copies them to the
 * correct location automatically.
 *
 * Platform behavior:
 *   macOS/zsh:  Copies from .zshrc to .zshenv (appends)
 *   Linux/bash: Copies from .bash_profile/.profile to .bashrc (inserts
 *               BEFORE the interactive guard so non-interactive shells see them)
 *   Windows:    Reads values from PowerShell $PROFILE, runs setx to set
 *               persistent user environment variables
 *
 * Non-destructive: does not remove lines from the original profile.
 * Returns null if nothing needs fixing.
 */
export function fixProfiles(options?: DoctorOptions): FixResult | null {
  const home = options?.homeDir ?? os.homedir();
  const shell = options?.shell ?? process.env.SHELL ?? '';
  const platform = options?.platform ?? os.platform();
  const dryRun = options?.dryRun ?? false;
  const knownVars = getKnownEnvVarNames();
  const specs = resolveProfileSpecs(shell, platform);

  // ── Windows: extract values from PS profile, run setx ──────────────────
  if (platform === 'win32') {
    return fixWindowsProfiles(home, specs, knownVars, options?.envOverride ?? process.env, dryRun);
  }

  // ── macOS / Linux: copy export lines to correct profile ────────────────
  const recommendedSpec = specs.find((s) => s.recommendation === 'recommended');
  if (!recommendedSpec) return null;

  const targetPath = path.join(home, recommendedSpec.file);
  const targetVars = scanProfile(targetPath, knownVars);
  const targetVarSet = new Set(targetVars);

  // Find vars in non-recommended profiles that are NOT already in the recommended profile
  const varsToFix: string[] = [];
  const sourceLines = new Map<string, string>();
  let primarySource = '';

  for (const spec of specs) {
    if (spec.file === recommendedSpec.file) continue;
    const sourcePath = path.join(home, spec.file);
    const lines = extractExportLines(sourcePath, knownVars);

    for (const [varName, line] of lines) {
      if (!targetVarSet.has(varName) && !sourceLines.has(varName)) {
        varsToFix.push(varName);
        sourceLines.set(varName, line);
        if (!primarySource) primarySource = spec.file;
      }
    }
  }

  if (varsToFix.length === 0) return null;

  // Build the block of export lines
  const linesToAppend = varsToFix.map((v) => sourceLines.get(v)!);
  const block = '\n# Added by secretless-ai (moved from wrong shell profile)\n'
    + linesToAppend.join('\n') + '\n';

  const created = !fs.existsSync(targetPath);
  const existing = created ? '' : fs.readFileSync(targetPath, 'utf-8');

  // On Linux/bash: insert BEFORE the interactive guard so non-interactive shells see the exports
  const isLinuxBash = recommendedSpec.file === '.bashrc';
  if (isLinuxBash && !created) {
    const guardLine = findBashInteractiveGuard(existing);
    if (guardLine > 0) {
      const lines = existing.split('\n');
      lines.splice(guardLine, 0, ...block.split('\n'));
      fs.writeFileSync(targetPath, lines.join('\n'));
    } else {
      // No guard found — safe to append
      fs.writeFileSync(targetPath, existing + block);
    }
  } else {
    // macOS/zsh or fresh file — append
    fs.writeFileSync(targetPath, existing + block);
  }

  return {
    fixed: varsToFix,
    sourceProfile: primarySource,
    targetProfile: recommendedSpec.file,
    created,
  };
}

/** Windows-specific fix: extract values from PS profile and run setx */
function fixWindowsProfiles(
  home: string,
  specs: ProfileSpec[],
  knownVars: string[],
  env: Record<string, string | undefined>,
  dryRun: boolean,
): FixResult | null {
  const varsToFix: string[] = [];
  const varValues = new Map<string, string>();
  let primarySource = '';

  for (const spec of specs) {
    const sourcePath = path.join(home, spec.file);
    const lines = extractExportLines(sourcePath, knownVars, 'powershell');

    for (const [varName, line] of lines) {
      // Only fix vars not already in system env
      if (!env[varName] && !varValues.has(varName)) {
        const value = extractPsValue(line);
        if (value) {
          varsToFix.push(varName);
          varValues.set(varName, value);
          if (!primarySource) primarySource = spec.file;
        }
      }
    }
  }

  if (varsToFix.length === 0) return null;

  const commands: string[] = [];
  for (const varName of varsToFix) {
    const value = varValues.get(varName)!;
    commands.push(`setx ${varName} "${value}"`);
    if (!dryRun) {
      try {
        execFileSync('setx', [varName, value], { stdio: 'pipe' });
      } catch {
        // setx failed — continue with remaining vars
      }
    }
  }

  return {
    fixed: varsToFix,
    sourceProfile: primarySource,
    targetProfile: 'System Environment Variables (setx)',
    created: false,
    commands,
  };
}
