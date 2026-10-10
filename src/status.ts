/**
 * Check Secretless AI protection status for a project.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { detectAITools, type AITool, type Enforcement } from './detect';
import { scan, newScanStats, coverageIncomplete } from './scan';
import { discoverTranscripts, scanTranscriptFile } from './transcript';
import { isWatchRunning } from './watch';
import { defaultAnnotationsPath, readAnnotations } from './secret-annotations';
import { needsRotation } from './secret-exposure';

/**
 * How many of the most recent transcripts `status` reads. A full pass is a
 * `clean --dry-run` job (tens of seconds over thousands of files); `status` is
 * expected to answer immediately. Exported so the renderer and the tests state
 * the same number rather than each hardcoding their own.
 */
export const TRANSCRIPT_SAMPLE_SIZE = 3;

/** How `status` names the user-level Claude Code settings file. */
export const USER_SETTINGS_PATH = '~/.claude/settings.json';

/**
 * What `~/.claude/settings.json` contributes to a project that is not the home
 * directory itself. Claude Code applies that file in every project, so a
 * project with no install of its own can still be covered by it.
 */
export interface UserSettingsStatus {
  path: string;
  /** The file wires a Secretless hook: the PreToolUse guard or the Stop hook. */
  secretlessInstalled: boolean;
  /** PreToolUse runs a `secretless-guard` command. */
  guardWired: boolean;
  /**
   * That command names a script that exists when it runs from this project.
   * `init` writes it as `"$CLAUDE_PROJECT_DIR"/.claude/hooks/...`, which from
   * the user-level file resolves to THIS project's hooks directory, not to
   * the home directory where `init` ran. Wired is not the same as running.
   */
  guardReachable: boolean;
  /** Null when the file could not be read as written, as for the project. */
  denyRuleCount: number | null;
  stopHookInstalled: boolean;
  unreadable?: { path: string; reason: string };
  ambiguous?: { path: string; reason: string };
  /**
   * The file protects this project on its own: it wires Secretless, reads as
   * written, and either its guard runs here or its deny patterns apply here.
   */
  coversProject: boolean;
}

export interface StatusResult {
  isProtected: boolean;
  /**
   * Which settings scope `isProtected` rests on: `project` when this project's
   * own install does, `user` when only `~/.claude/settings.json` does, null
   * when neither does.
   */
  protectionScope: 'project' | 'user' | null;
  /**
   * `~/.claude/settings.json`, when it exists and is not this project's own
   * settings file (running `status` from the home directory reads it once, as
   * the project's). Null otherwise.
   */
  userSettings: UserSettingsStatus | null;
  /**
   * The strongest mechanism `isProtected` rests on. `none` whenever it is
   * false, and in the one case below where it is true.
   *
   * `isProtected` is true for a project whose only configuration is an
   * instruction file, which is advice: nothing enforces it. That boolean and
   * `summary.verdict` are what consumers gate on, so they keep their meaning;
   * this field carries the difference they do not. `hook` means Claude Code
   * applies a guard hook or deny patterns from this project's settings or from
   * user-level settings that reach it. `ignore-file` and `advisory` mean
   * nothing of that kind is in place: see `Enforcement`. `none` is also
   * reported while `isProtected` is true when that rests on a guard script no
   * settings file runs, and no tool is configured.
   */
  enforcement: Enforcement;
  /** AI tools found in the project, configured or not. */
  detectedTools: AITool[];
  configuredTools: AITool[];
  /**
   * The tools in `configuredTools` that are listed for an ignore file rather
   * than an instruction file.
   */
  ignoreFileTools: AITool[];
  /** The guard script `init` writes exists in `.claude/hooks/`. */
  hookInstalled: boolean;
  /**
   * `.claude/settings.json` runs a `secretless-guard` command from PreToolUse,
   * and the script it names exists when it runs from this project. Claude Code
   * runs only what a settings file wires, so a script on disk with no entry
   * here enforces nothing: `hookInstalled` alone is not the hook.
   */
  hookWired: boolean;
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
   * True when the scan behind `secretsFound` could not cover the whole tree
   * (file cap reached, a path unreadable, or a file skipped for size), so the
   * count is a lower bound rather than a verdict. `scan()` discards this when
   * no stats object is passed, which is how `status --json` reported
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
    /** Which settings file the Stop hook was found in, project first. */
    stopHookScope: 'project' | 'user' | null;
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
  /**
   * Stored secrets with an open exposure: recorded by `secret exposed`, `clean`
   * or `watch`, not yet closed by `secret set` with a new value (#236). Read
   * from the metadata file alone, so `status` never unlocks the store. Null
   * when that file could not be read: a count over an unread file is not one.
   */
  exposuresOpen: number | null;
}

/** A Claude Code settings file, read the way `status` reports on one. */
interface SettingsRead {
  /** The parsed top-level object; undefined when the file did not parse as one. */
  settings?: any;
  unreadable?: { path: string; reason: string };
  ambiguous?: { path: string; reason: string };
  denyRuleCount: number | null;
}

/**
 * Read one settings file. The project's and the user's go through the same
 * steps, so both scopes report an unreadable or colliding file the same way.
 */
async function readClaudeSettings(settingsPath: string, displayPath: string): Promise<SettingsRead> {
  const read: SettingsRead = { denyRuleCount: 0 };

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
      read.unreadable = {
        path: displayPath,
        reason: 'its top level is not a JSON object',
      };
    } else {
      settings = parsed;
    }
  } catch (err) {
    read.unreadable = {
      path: displayPath,
      reason: (err as Error).message,
    };
  }

  if (!settings) {
    // Could not read it at all: the initial 0 would read as a measurement.
    read.denyRuleCount = null;
    return read;
  }

  // Scanned on the RAW TEXT — the same bytes JSON.parse consumed, never the
  // parsed object, because the parser resolves a repeated member before any
  // consumer can see it.
  //
  // Ordered AFTER the parse has classified the file, not because the scan
  // needs the result but because the two failures are DIFFERENT states: text
  // that does not parse is `unreadable`, and running the scan on it first set
  // both flags and collapsed the distinction the fix exists to create. A file
  // only reaches here if it parsed.
  try {
    const { firstDuplicateMember } = await import('@opena2a/atx-verify');
    const dup = firstDuplicateMember(rawSettings);
    if (dup !== null) {
      read.ambiguous = {
        path: displayPath,
        reason: `repeats "${dup}", so only the last copy is in effect`,
      };
    }
  } catch (err) {
    // The scan could not run over text that DID parse: an installation
    // fault, or input the parser accepted and the scanner will not vouch
    // for. Reported, not thrown — this is a reporting command and an
    // installation fault is not a broken project — and not swallowed,
    // which would restore the green this exists to remove.
    read.ambiguous = {
      path: displayPath,
      reason: `keys could not be checked for collisions: ${(err as Error).message}`,
    };
  }

  read.settings = settings;
  // Left null when a collision means the file does not say what it reads as.
  read.denyRuleCount = read.ambiguous
    ? null
    : settings?.permissions?.deny?.length || 0;
  return read;
}

/** The command strings a settings object registers for one hook event. */
function hookCommands(settings: any, event: string): string[] {
  const entries = settings?.hooks?.[event];
  if (!Array.isArray(entries)) return [];
  const commands: string[] = [];
  for (const entry of entries) {
    const hooks = entry?.hooks;
    if (!Array.isArray(hooks)) continue;
    for (const hook of hooks) {
      if (typeof hook?.command === 'string') commands.push(hook.command);
    }
  }
  return commands;
}

/**
 * The file a hook command runs, as Claude Code would resolve it from this
 * project, or null when it names a variable this cannot expand. Expands the
 * forms `init` and hand edits use: `$CLAUDE_PROJECT_DIR`, `$HOME` and `~`.
 */
function hookScriptPath(command: string, marker: string, projectDir: string, homeDir: string): string | null {
  const word = command.split(/\s+/).find(w => w.includes(marker));
  if (!word) return null;
  const expanded = word
    .replace(/["']/g, '')
    .replace(/^\$(?:\{CLAUDE_PROJECT_DIR\}|CLAUDE_PROJECT_DIR)(?=\/)/, () => projectDir)
    .replace(/^\$(?:\{HOME\}|HOME)(?=\/)/, () => homeDir)
    .replace(/^~(?=\/)/, () => homeDir);
  if (expanded.includes('$')) return null;
  return path.resolve(projectDir, expanded);
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/**
 * Whether a settings object wires the guard into PreToolUse, and whether a
 * command it wires names a script that exists when it runs from this project.
 */
function guardWiring(settings: any, projectDir: string, homeDir: string): { wired: boolean; reachable: boolean } {
  const commands = hookCommands(settings, 'PreToolUse').filter(c => c.includes('secretless-guard'));
  const reachable = commands.some(c => {
    const script = hookScriptPath(c, 'secretless-guard', projectDir, homeDir);
    return script !== null && isFile(script);
  });
  return { wired: commands.length > 0, reachable };
}

/** True when `filePath` is a regular file whose text holds one of `markers`. */
function fileCarries(filePath: string, markers: string[]): boolean {
  try {
    if (!fs.statSync(filePath).isFile()) return false;
    const content = fs.readFileSync(filePath, 'utf-8');
    return markers.some(marker => content.includes(marker));
  } catch {
    return false; // Absent or unreadable: not evidence either way
  }
}

function sameFile(a: string, b: string): boolean {
  try {
    return fs.realpathSync(a) === fs.realpathSync(b);
  } catch {
    return path.resolve(a) === path.resolve(b);
  }
}

/**
 * Check the current protection status of the project.
 *
 * `homeDir` locates `~/.claude/settings.json`; it defaults to the user's home
 * directory.
 */
export async function status(projectDir: string, options?: { homeDir?: string }): Promise<StatusResult> {
  const homeDir = options?.homeDir ?? os.homedir();
  const result: StatusResult = {
    isProtected: false,
    protectionScope: null,
    userSettings: null,
    enforcement: 'none',
    detectedTools: [],
    configuredTools: [],
    ignoreFileTools: [],
    hookInstalled: false,
    hookWired: false,
    denyRuleCount: 0,
    secretsFound: 0,
    scanIncomplete: false,
    transcriptProtection: {
      stopHookInstalled: false,
      stopHookScope: null,
      watcherRunning: false,
      transcriptFiles: 0,
      transcriptFilesScanned: 0,
      transcriptSecretsFound: 0,
    },
    exposuresOpen: null,
  };

  // Check Claude Code hook
  const hookPath = path.join(projectDir, '.claude', 'hooks', 'secretless-guard.sh');
  result.hookInstalled = fs.existsSync(hookPath);

  // Check Claude Code deny rules and Stop hook
  const settingsPath = path.join(projectDir, '.claude', 'settings.json');
  const projectSettingsExists = fs.existsSync(settingsPath);
  if (projectSettingsExists) {
    const read = await readClaudeSettings(settingsPath, '.claude/settings.json');
    if (read.unreadable) result.settingsUnreadable = read.unreadable;
    if (read.ambiguous) result.settingsAmbiguous = read.ambiguous;
    result.denyRuleCount = read.denyRuleCount;
    result.hookWired = guardWiring(read.settings, projectDir, homeDir).reachable;

    // Check for Stop hook
    if (hookCommands(read.settings, 'Stop').some(c => c.includes('secretless-ai'))) {
      result.transcriptProtection.stopHookInstalled = true;
      result.transcriptProtection.stopHookScope = 'project';
    }
  }

  // User-level settings apply in every project, so a project with no install
  // of its own was reported "Not protected" while Claude Code was enforcing
  // the deny patterns and running the Stop hook from `~/.claude/settings.json`.
  // Read it as a second scope — unless it IS this project's settings file,
  // which is the case when `status` runs from the home directory.
  const userSettingsPath = path.join(homeDir, '.claude', 'settings.json');
  if (fs.existsSync(userSettingsPath)
    && !(projectSettingsExists && sameFile(settingsPath, userSettingsPath))) {
    const read = await readClaudeSettings(userSettingsPath, USER_SETTINGS_PATH);
    const guard = guardWiring(read.settings, projectDir, homeDir);
    const guardReachable = guard.reachable;
    const stopHookInstalled = hookCommands(read.settings, 'Stop').some(c => c.includes('secretless-ai'));
    const secretlessInstalled = guard.wired || stopHookInstalled;
    const user: UserSettingsStatus = {
      path: USER_SETTINGS_PATH,
      secretlessInstalled,
      guardWired: guard.wired,
      guardReachable,
      denyRuleCount: read.denyRuleCount,
      stopHookInstalled,
      coversProject: secretlessInstalled
        && !read.unreadable
        && !read.ambiguous
        && (guardReachable || (read.denyRuleCount ?? 0) > 0),
    };
    if (read.unreadable) user.unreadable = read.unreadable;
    if (read.ambiguous) user.ambiguous = read.ambiguous;
    result.userSettings = user;

    if (stopHookInstalled && !result.transcriptProtection.stopHookInstalled) {
      result.transcriptProtection.stopHookInstalled = true;
      result.transcriptProtection.stopHookScope = 'user';
    }
  }

  // Check which tools have Secretless AI instructions: a tool counts once any
  // file `init` writes its block into carries it. Read through the detector's
  // `instructionFiles`, not `settingsFile` — for Cursor that was a settings
  // path `init` never wrote, so an initialised Cursor project reported
  // "Not protected"; for Cline it is a directory in the documented layout,
  // and reading it threw.
  //
  // A tool `init` configures through an ignore file is read there first.
  // Aider was never listed after `init`, which writes `.aiderignore` and no
  // instruction block: `init` printed `Configured: Aider` and `status` then
  // printed `Not protected` for the same directory.
  const detected = detectAITools(projectDir);
  result.detectedTools = detected.map(d => d.tool);
  for (const tool of detected) {
    if (tool.ignoreFile && fileCarries(path.join(projectDir, tool.ignoreFile.path), [tool.ignoreFile.marker])) {
      result.configuredTools.push(tool.tool);
      result.ignoreFileTools.push(tool.tool);
      continue;
    }
    for (const rel of tool.instructionFiles) {
      if (fileCarries(path.join(projectDir, rel), ['secretless:managed', 'Secretless AI'])) {
        result.configuredTools.push(tool.tool);
        break;
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
  const scanStats = newScanStats();
  const findings = scan(projectDir, { scanGlobal: false }, scanStats);
  result.secretsFound = findings.length;
  result.scanIncomplete = coverageIncomplete(scanStats);

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

  try {
    result.exposuresOpen = needsRotation(readAnnotations(defaultAnnotationsPath())).length;
  } catch {
    // Left null: the metadata file exists but could not be read.
  }

  // Protected if hook is installed OR instructions are present in at least one tool
  // An unreadable `.claude/settings.json` means the deny rules and the
  // PreToolUse wiring could not be read at all. The guard script existing on
  // disk is not protection on its own, so claiming `isProtected` here would be
  // asserting something we never verified — fail closed instead.
  //
  // Otherwise the project's own install decides first; user-level settings
  // count only where they actually reach this project (`coversProject`).
  const projectProtects = result.hookInstalled || result.configuredTools.length > 0;
  const userProtects = result.userSettings?.coversProject === true;
  result.isProtected = !result.settingsUnreadable && (projectProtects || userProtects);
  result.protectionScope = !result.isProtected ? null : projectProtects ? 'project' : 'user';

  // Which of the terms above made `isProtected` true, strongest first. An
  // instruction file and a guard hook both set that boolean, and reporting
  // them as one state called advice a control.
  //
  // `hookInstalled` is one of those terms, and it only says the script is on
  // disk. That install enforces something when the settings run the guard or
  // carry deny patterns Claude Code applies; a script nothing runs is neither,
  // and with no tool configured beside it nothing is enforced at all.
  const projectEnforces = result.hookWired
    || (result.hookInstalled && (result.denyRuleCount ?? 0) > 0);
  if (!result.isProtected) {
    result.enforcement = 'none';
  } else if (projectEnforces || userProtects) {
    result.enforcement = 'hook';
  } else if (result.ignoreFileTools.length > 0) {
    result.enforcement = 'ignore-file';
  } else if (result.configuredTools.length > 0) {
    result.enforcement = 'advisory';
  } else {
    result.enforcement = 'none';
  }

  return result;
}
