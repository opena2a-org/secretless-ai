/**
 * Initialize Secretless for a project.
 * Auto-detects AI tools and installs appropriate protections.
 */

import * as fs from 'fs';
import * as path from 'path';
import { detectAITools, toolDisplayName, type AITool } from './detect';
import { SECRET_FILE_PATTERNS, CREDENTIAL_PATTERNS, CONFIG_FILES, KNOWN_EXAMPLE_KEYS, PLACEHOLDER_INDICATORS } from './patterns';
import { loadCustomRulesDetailed, customRulesToDenyRules, customRulesToHookBlocks, customRulesToFilePatterns, filesystemPathForm, mergeRules } from './custom-rules';
import type { CustomRules, RulesFileIssue } from './custom-rules';
import { loadSecretlessIgnore } from './secretlessignore';

/** Known API services with their auth header formats */
const SERVICE_HINTS: Record<string, { service: string; authHeader: string }> = {
  // Existing services
  ANTHROPIC_API_KEY: { service: 'Anthropic Messages API', authHeader: 'x-api-key: $ANTHROPIC_API_KEY' },
  OPENAI_API_KEY: { service: 'OpenAI API', authHeader: 'Authorization: Bearer $OPENAI_API_KEY' },
  GAMMA_API_KEY: { service: 'Gamma API', authHeader: 'X-API-KEY: $GAMMA_API_KEY' },
  AWS_ACCESS_KEY_ID: { service: 'AWS', authHeader: '(use AWS SDK or aws configure)' },
  GITHUB_TOKEN: { service: 'GitHub API', authHeader: 'Authorization: Bearer $GITHUB_TOKEN' },
  SLACK_TOKEN: { service: 'Slack API', authHeader: 'Authorization: Bearer $SLACK_TOKEN' },
  GOOGLE_API_KEY: { service: 'Google API', authHeader: 'key=$GOOGLE_API_KEY (query param)' },
  STRIPE_SECRET_KEY: { service: 'Stripe API', authHeader: 'Authorization: Bearer $STRIPE_SECRET_KEY' },
  SENDGRID_API_KEY: { service: 'SendGrid API', authHeader: 'Authorization: Bearer $SENDGRID_API_KEY' },
  SUPABASE_SERVICE_ROLE_KEY: { service: 'Supabase', authHeader: 'apikey: $SUPABASE_SERVICE_ROLE_KEY' },
  AZURE_API_KEY: { service: 'Azure', authHeader: 'api-key: $AZURE_API_KEY' },
  // AI/ML
  GROQ_API_KEY: { service: 'Groq API', authHeader: 'Authorization: Bearer $GROQ_API_KEY' },
  OPENROUTER_API_KEY: { service: 'OpenRouter API', authHeader: 'Authorization: Bearer $OPENROUTER_API_KEY' },
  REPLICATE_API_TOKEN: { service: 'Replicate API', authHeader: 'Authorization: Token $REPLICATE_API_TOKEN' },
  HUGGING_FACE_HUB_TOKEN: { service: 'Hugging Face', authHeader: 'Authorization: Bearer $HUGGING_FACE_HUB_TOKEN' },
  PERPLEXITY_API_KEY: { service: 'Perplexity API', authHeader: 'Authorization: Bearer $PERPLEXITY_API_KEY' },
  FIREWORKS_API_KEY: { service: 'Fireworks AI', authHeader: 'Authorization: Bearer $FIREWORKS_API_KEY' },
  // Developer platforms
  GITLAB_TOKEN: { service: 'GitLab API', authHeader: 'PRIVATE-TOKEN: $GITLAB_TOKEN' },
  NPM_TOKEN: { service: 'npm Registry', authHeader: '//registry.npmjs.org/:_authToken=$NPM_TOKEN' },
  // Cloud providers
  DIGITALOCEAN_TOKEN: { service: 'DigitalOcean API', authHeader: 'Authorization: Bearer $DIGITALOCEAN_TOKEN' },
  HEROKU_API_KEY: { service: 'Heroku API', authHeader: 'Authorization: Bearer $HEROKU_API_KEY' },
  NETLIFY_AUTH_TOKEN: { service: 'Netlify API', authHeader: 'Authorization: Bearer $NETLIFY_AUTH_TOKEN' },
  FLY_API_TOKEN: { service: 'Fly.io API', authHeader: 'Authorization: Bearer $FLY_API_TOKEN' },
  // Monitoring
  SENTRY_AUTH_TOKEN: { service: 'Sentry API', authHeader: 'Authorization: Bearer $SENTRY_AUTH_TOKEN' },
  NEW_RELIC_API_KEY: { service: 'New Relic API', authHeader: 'API-Key: $NEW_RELIC_API_KEY' },
  LINEAR_API_KEY: { service: 'Linear API', authHeader: 'Authorization: $LINEAR_API_KEY' },
  // Communication
  TELEGRAM_BOT_TOKEN: { service: 'Telegram Bot API', authHeader: 'URL path: /bot$TELEGRAM_BOT_TOKEN/' },
  TWILIO_API_KEY: { service: 'Twilio API', authHeader: 'Basic auth with $TWILIO_API_KEY:$TWILIO_API_SECRET' },
  // Database
  MONGODB_URI: { service: 'MongoDB', authHeader: '(connection string)' },
  DATABASE_URL: { service: 'Database', authHeader: '(connection string)' },
};

interface InitResult {
  toolsDetected: AITool[];
  toolsConfigured: AITool[];
  filesCreated: string[];
  filesModified: string[];
  secretsFound: number;
  /**
   * Total deny rules now in `.claude/settings.json` after merge. Useful for
   * rendering "21 deny patterns" in the configured-tools line.
   */
  denyRulesTotal: number;
  /**
   * Deny rules added during this `init` invocation. Zero when re-running
   * over an already-configured project. Used by `runInit` to tell the user
   * "Added 21 deny patterns" vs "Already up to date".
   */
  denyRulesAdded: number;
  /**
   * Deprecated deny rules pruned during this `init` invocation (migration).
   * Non-zero when an older config carried a broad glob (e.g. `Read(.env*)`)
   * that newer versions replaced with enumerated rules. Lets `runInit` report
   * "removed N deprecated pattern(s)" so a re-run isn't a silent no-op.
   */
  denyRulesRemoved: number;
  /**
   * True when the managed guard hook (`.claude/hooks/secretless-guard.sh`) was
   * rewritten this run because its content was stale relative to the version
   * `init` generates. Older `init` only wrote the hook when absent, so an
   * outdated hook would persist across upgrades.
   */
  hookRefreshed: boolean;
  /**
   * Set when `.claude/settings.json` exists but could not be merged into, so
   * `init` deliberately left it untouched. Its presence means the deny rules
   * and the guard-hook wiring were NOT installed: the guard script on disk is
   * inert until settings.json references it, so the project is unprotected.
   * `runInit` reports this and exits non-zero — an init that configured
   * nothing is not a pass.
   */
  settingsUnusable?: { path: string; kind: SettingsUnusableKind; reason: string };
  /**
   * Set when `.secretless-rules.yaml` exists but part or all of it could not
   * be honoured. 'unrecognised-content': the parser did not read some lines,
   * so the patterns on them generate no deny rules (any lines that WERE read
   * are still applied). 'load-error': the file was refused outright (e.g.
   * unsafe pattern characters) and none of it was applied. Either way the
   * operator wrote restrictions that are not in force, so `runInit` reports
   * it and exits non-zero — silence here is the defect this field closes.
   */
  rulesFileProblem?:
    | { kind: 'unrecognised-content'; issues: RulesFileIssue[] }
    | { kind: 'load-error'; reason: string };
  /**
   * Project-relative paths `init` refused to write through, with the tool
   * each was for. A path is refused when it, or a directory on the way to
   * it, is a symbolic link, is not the kind of entry the layout needs, or
   * resolves outside the project. The tool is then absent from
   * `toolsConfigured` and nothing was written for it: following a link out
   * of the project would create or append to a file the user never pointed
   * `init` at.
   */
  pathsRefused: Array<{ tool: AITool; path: string; reason: string }>;
}

/**
 * Deny rules that older versions of `init` generated but newer versions no
 * longer do — `init` prunes these on every run so an upgrade actually migrates
 * an existing `.claude/settings.json` instead of leaving stale rules in place.
 *
 * `Read(.env*)` / `Grep(*.env*)`: broad globs replaced (0.18.1, #82) by an
 * enumerated real-env-file list so committed templates (`.env.example` etc.)
 * are no longer blocked. The enumerated replacements are re-added in the same
 * run, so pruning here never leaves a real env file unprotected.
 */
export const DEPRECATED_DENY_RULES: readonly string[] = [
  'Read(.env*)',
  'Grep(*.env*)',
];

/**
 * Initialize Secretless protections for the project.
 * This is the main entry point called by `npx secretless-ai init`.
 */
export function init(projectDir: string): InitResult {
  const result: InitResult = {
    toolsDetected: [],
    toolsConfigured: [],
    filesCreated: [],
    filesModified: [],
    secretsFound: 0,
    denyRulesTotal: 0,
    denyRulesAdded: 0,
    denyRulesRemoved: 0,
    hookRefreshed: false,
    pathsRefused: [],
  };

  // Detect AI tools
  const detected = detectAITools(projectDir);
  result.toolsDetected = detected.map(d => d.tool);

  // If no tools detected, default to Claude Code (most common for npx users)
  if (detected.length === 0) {
    detected.push({
      tool: 'claude-code',
      configDir: '.claude',
      settingsFile: '.claude/settings.json',
      instructionFiles: ['CLAUDE.md'],
      hooksSupported: true,
    });
  }

  // Quick scan for existing secrets
  result.secretsFound = quickScan(projectDir);

  // Load custom rules HERE, not inside configureClaudeCode: a rules file that
  // cannot be honoured must reach the result even when Claude Code is not
  // among the configured tools — otherwise an operator with only .cursorrules
  // and a broken rules file gets exit 0 and no mention of it. The previous
  // bare catch inside configureClaudeCode was worse still: a file refused for
  // unsafe patterns configured nothing and `init` exited 0.
  let projectCustomRules: CustomRules | null = null;
  try {
    const loaded = loadCustomRulesDetailed(projectDir);
    projectCustomRules = loaded.rules;
    if (loaded.status === 'unrecognised-content') {
      result.rulesFileProblem = { kind: 'unrecognised-content', issues: loaded.issues ?? [] };
    }
  } catch (err) {
    result.rulesFileProblem = {
      kind: 'load-error',
      reason: err instanceof Error ? err.message : String(err),
    };
  }

  // Configure each detected tool
  for (const tool of detected) {
    switch (tool.tool) {
      case 'claude-code':
        configureClaudeCode(projectDir, result, projectCustomRules);
        break;
      case 'cursor':
        configureCursor(projectDir, result);
        break;
      case 'copilot':
        configureCopilot(projectDir, result);
        break;
      case 'windsurf':
        configureWindsurf(projectDir, result);
        break;
      case 'cline':
        configureCline(projectDir, result);
        break;
      case 'aider':
        configureAider(projectDir, result);
        break;
    }
    // A tool whose settings file we refused to touch was not configured.
    // Listing it under "Configured:" would restore the defect this release
    // exists to fix, one line further down the same output.
    if (tool.tool === 'claude-code' && result.settingsUnusable) continue;
    // Likewise a tool whose instruction path was refused (a symbolic link, or
    // a destination outside the project) had nothing written for it.
    if (result.pathsRefused.some(r => r.tool === tool.tool)) continue;
    result.toolsConfigured.push(tool.tool);
  }

  return result;
}

// ============================================================================
// Claude Code Configuration
// ============================================================================

const OUTPUT_CHECK_NAME = 'secretless-output-check';
const OUTPUT_CHECK_FILE = `${OUTPUT_CHECK_NAME}.cjs`;

function configureClaudeCode(
  projectDir: string,
  result: InitResult,
  projectCustomRules: CustomRules | null,
): void {
  const claudeDir = path.join(projectDir, '.claude');
  const hooksDir = path.join(claudeDir, 'hooks');

  // Ensure directories exist
  fs.mkdirSync(hooksDir, { recursive: true });

  // 1. Install (or refresh) the PreToolUse guard hook. The hook is a managed
  // file we own — older `init` only wrote it when absent, so an outdated hook
  // (e.g. one without the template-exempt arm shipped in 0.18.1) would survive
  // an upgrade. Regenerate and compare: write only when the content differs, so
  // a fresh project Creates it and an upgraded project Modifies it in place.
  const hookPath = path.join(hooksDir, 'secretless-guard.sh');
  const desiredHook = generateClaudeHookScript(projectCustomRules);
  if (!fs.existsSync(hookPath)) {
    fs.writeFileSync(hookPath, desiredHook, { mode: 0o755 });
    result.filesCreated.push('.claude/hooks/secretless-guard.sh');
  } else if (fs.readFileSync(hookPath, 'utf-8') !== desiredHook) {
    fs.writeFileSync(hookPath, desiredHook, { mode: 0o755 });
    result.filesModified.push('.claude/hooks/secretless-guard.sh');
    result.hookRefreshed = true;
  }

  // The PostToolUse output check is managed the same way: regenerated, written
  // only when it differs. It covers what the guard above cannot see (#129).
  const outputCheckPath = path.join(hooksDir, OUTPUT_CHECK_FILE);
  const desiredOutputCheck = generateClaudeOutputCheckScript();
  if (!fs.existsSync(outputCheckPath)) {
    fs.writeFileSync(outputCheckPath, desiredOutputCheck, { mode: 0o755 });
    result.filesCreated.push(`.claude/hooks/${OUTPUT_CHECK_FILE}`);
  } else if (fs.readFileSync(outputCheckPath, 'utf-8') !== desiredOutputCheck) {
    fs.writeFileSync(outputCheckPath, desiredOutputCheck, { mode: 0o755 });
    result.filesModified.push(`.claude/hooks/${OUTPUT_CHECK_FILE}`);
  }

  // 2. Update settings.json with hook config and deny rules.
  //
  // A settings file we cannot merge into is never overwritten. Writing a
  // Secretless-only document over it would discard every user key with no
  // backup, so `init` reports the refusal and leaves the file byte-identical
  // (#122). CLAUDE.md handling below still runs — it is additive and safe.
  const settingsPath = path.join(claudeDir, 'settings.json');
  const read = readSettingsFile(settingsPath);
  if (read.status === 'unusable') {
    result.settingsUnusable = {
      path: '.claude/settings.json',
      kind: read.kind,
      reason: read.reason,
    };
    // No Stop hook is added on this path, so the block says nothing about a cleanup.
    addSecretlessInstructions(path.join(projectDir, 'CLAUDE.md'), 'claude-code', result, '', false);
    return;
  }
  const settings = read.status === 'ok' ? read.data : {};

  // Add hooks config
  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];

  const hookExists = settings.hooks.PreToolUse.some(
    (h: any) => h.hooks?.some((hh: any) => hh.command?.includes('secretless-guard'))
  );

  if (!hookExists) {
    settings.hooks.PreToolUse.push({
      matcher: 'Read|Grep|Glob|Bash|Write|Edit',
      hooks: [{
        type: 'command',
        command: '"$CLAUDE_PROJECT_DIR"/.claude/hooks/secretless-guard.sh',
      }],
    });
    result.filesModified.push('.claude/settings.json');
  }

  // Add the PostToolUse output check for Bash. Bash is the channel #129 names:
  // a command that fetches credentials over the network names no local path,
  // so nothing that runs before it has anything to match. Read, Grep and Glob
  // are gated on the path they open.
  if (!settings.hooks.PostToolUse) settings.hooks.PostToolUse = [];

  const outputCheckExists = settings.hooks.PostToolUse.some(
    (h: any) => h.hooks?.some((hh: any) => hh.command?.includes(OUTPUT_CHECK_NAME))
  );

  if (!outputCheckExists) {
    settings.hooks.PostToolUse.push({
      matcher: 'Bash',
      hooks: [{
        type: 'command',
        command: `"$CLAUDE_PROJECT_DIR"/.claude/hooks/${OUTPUT_CHECK_FILE}`,
      }],
    });
    if (!result.filesModified.includes('.claude/settings.json')) {
      result.filesModified.push('.claude/settings.json');
    }
  }

  // Add Stop hook for transcript cleaning after conversations
  if (!settings.hooks.Stop) settings.hooks.Stop = [];

  const hasTranscriptHook = hasTranscriptStopHook(settings.hooks.Stop);

  if (!hasTranscriptHook) {
    settings.hooks.Stop.push({
      matcher: '',
      hooks: [{
        type: 'command',
        command: 'npx secretless-ai clean --last 2>/dev/null || true',
      }],
    });
  }

  // Add deny rules for secret files
  if (!settings.permissions) settings.permissions = {};
  if (!settings.permissions.deny) settings.permissions.deny = [];

  const denyRules = [
    // Block Read access to secret files.
    // Enumerate REAL env files instead of a broad `.env*` glob: Claude Code deny
    // globs can't negate and `deny` beats `allow`, so a broad `.env*` would also
    // block committed template files (`.env.example`, `.env.sample`, `.env.template`,
    // `.env.dist`) with no way to exempt them. Templates hold placeholders, not real
    // secrets, and are meant to be read/edited/committed — they fall through this
    // enumerated list. (Matches the user's global config precedent, 2026-06-01.)
    'Read(.env)',
    'Read(.env.local)',
    'Read(.env.*.local)',
    'Read(.env.development)',
    'Read(.env.production)',
    'Read(.env.staging)',
    'Read(.env.test)',
    'Read(*.env)', // name.env (prod.env, staging.env) — distinct from .env*
    'Read(*.key)',
    'Read(*.pem)',
    'Read(*.p12)',
    'Read(*.pfx)',
    'Read(*.crt)',
    'Read(*.tfstate)',
    'Read(*.tfvars)',
    'Read(.aws/credentials)',
    'Read(.ssh/*)',
    // Block Read access to secretless data directory
    'Read(~/.secretless-ai/*)',
    // Block Grep from searching secret files (Issue #1).
    // Enumerated like the Read rules above so template files stay greppable.
    'Grep(.env)',
    'Grep(.env.local)',
    'Grep(.env.*.local)',
    'Grep(.env.development)',
    'Grep(.env.production)',
    'Grep(.env.staging)',
    'Grep(.env.test)',
    'Grep(*.env)',
    'Grep(*.key)',
    'Grep(*.pem)',
    'Grep(*.p12)',
    'Grep(*.pfx)',
    'Grep(*.crt)',
    // The credentials STORE, not the topic word. `credentials*` is a prefix glob,
    // so a project-root `credentials-guide.md` was denied to Grep for naming the
    // subject. Same drift as the guard hook's path fragment above — patterns.ts
    // already spells this rule `credentials/`.
    'Grep(credentials/*)',
    'Grep(*.tfstate)',
    'Grep(*.tfvars)',
    // Block Bash commands that read secret files (Issue #2 - expanded)
    'Bash(cat .env*)',
    'Bash(cat *.key)',
    'Bash(cat *.pem)',
    'Bash(grep * .env*)',
    'Bash(grep * *.key)',
    'Bash(grep * *.pem)',
    'Bash(awk * .env*)',
    'Bash(awk * *.key)',
    'Bash(sed * .env*)',
    'Bash(sed * *.key)',
    'Bash(strings .env*)',
    'Bash(strings *.key)',
    'Bash(strings *.pem)',
    'Bash(xxd .env*)',
    'Bash(xxd *.key)',
    'Bash(xxd *.pem)',
    'Bash(python3 -c*open*.env*)',
    'Bash(python3 -c*open*.key*)',
    'Bash(python3 -c*open*.pem*)',
    'Bash(node -e*readFile*.env*)',
    'Bash(node -e*readFile*.key*)',
    'Bash(node -e*readFile*.pem*)',
    // Block python/node env var extraction
    'Bash(python3 -c*os.environ*SECRET*)',
    'Bash(python3 -c*os.environ*API_KEY*)',
    'Bash(python3 -c*os.environ*TOKEN*)',
    'Bash(python3 -c*os.environ*PASSWORD*)',
    'Bash(python3 -c*os.environ*CREDENTIAL*)',
    'Bash(node -e*process.env*SECRET*)',
    'Bash(node -e*process.env*API_KEY*)',
    'Bash(node -e*process.env*TOKEN*)',
    'Bash(node -e*process.env*PASSWORD*)',
    'Bash(node -e*process.env*CREDENTIAL*)',
    // Block eval-based env var extraction
    'Bash(eval echo*SECRET*)',
    'Bash(eval echo*API_KEY*)',
    'Bash(eval echo*TOKEN*)',
    'Bash(eval echo*PASSWORD*)',
    // Block echoing/printing secret env vars (Issue #4 - expanded)
    'Bash(echo $*SECRET*)',
    'Bash(echo $*PASSWORD*)',
    'Bash(echo $*API_KEY*)',
    'Bash(echo $*TOKEN*)',
    'Bash(echo $*VAULT*)',
    'Bash(echo $*CREDENTIAL*)',
    'Bash(echo $*PRIVATE_KEY*)',
    'Bash(echo $*ACCESS_KEY*)',
    'Bash(echo $*DATABASE_URL*)',
    'Bash(printenv *TOKEN*)',
    'Bash(printenv *SECRET*)',
    'Bash(printenv *KEY*)',
    'Bash(printenv *PASSWORD*)',
    'Bash(printenv *CREDENTIAL*)',
    'Bash(printenv *VAULT*)',
    'Bash(printenv *DATABASE_URL*)',
    // Bare `printenv` dumps the whole environment.
    'Bash(printenv)',
    // Block secretless-ai secret extraction (Issue #3)
    'Bash(*secretless-ai secret get*--force*)',
    // Block secretless-ai run with env dumping (Issue #6)
    'Bash(*secretless-ai run*-- env*)',
    'Bash(*secretless-ai run*-- printenv*)',
    // Block secretless-ai vault exec with env dumping — same shape as `run --
    // env` but for the identity vault: it injects a namespace credential into
    // the child, which `env`/`printenv` would then print (issue #99).
    'Bash(*secretless-ai vault exec*-- env*)',
    'Bash(*secretless-ai vault exec*-- printenv*)',
    // Block full-store plaintext dump via `secretless-ai env` (release-test
    // 2026-07-16 P1). The command exists for the user's shell-profile eval
    // hook, which never runs through the agent — no agent use is legitimate.
    'Bash(*secretless-ai env*)',
    // Block access to secretless data directory (Issue #5)
    'Bash(cat *secretless-ai*)',
    'Bash(*secretless-ai/store*)',
    'Bash(*secretless-ai/mcp-backups*)',
  ];

  // Merge custom rules from .secretless-rules.yaml (if loaded above)
  const allDenyRules = projectCustomRules
    ? mergeRules(denyRules, customRulesToDenyRules(projectCustomRules))
    : denyRules;

  let added = 0;
  for (const rule of allDenyRules) {
    if (!settings.permissions.deny.includes(rule)) {
      settings.permissions.deny.push(rule);
      added++;
    }
  }

  // Migration: prune deprecated rules an older `init` generated but the current
  // version no longer does (e.g. the broad `Read(.env*)` glob replaced above by
  // the enumerated list). Done AFTER the add loop so the enumerated replacements
  // are already present — pruning never leaves a real env file unprotected. Skip
  // a deprecated rule if it's somehow also a current rule (none are today).
  const deprecated = new Set(
    DEPRECATED_DENY_RULES.filter(r => !allDenyRules.includes(r)),
  );
  let removed = 0;
  if (deprecated.size > 0) {
    const before = settings.permissions.deny.length;
    settings.permissions.deny = settings.permissions.deny.filter(
      (r: string) => !deprecated.has(r),
    );
    removed = before - settings.permissions.deny.length;
  }

  if ((added > 0 || removed > 0) && !result.filesModified.includes('.claude/settings.json')) {
    result.filesModified.push('.claude/settings.json');
  }
  result.denyRulesAdded += added;
  result.denyRulesRemoved += removed;
  result.denyRulesTotal = settings.permissions.deny.length;

  writeJsonFile(settingsPath, settings);

  // 3. Add Secretless instructions to CLAUDE.md. The block describes the
  // Stop-hook cleanup only when the settings just written carry that hook.
  const claudeMdPath = path.join(projectDir, 'CLAUDE.md');
  addSecretlessInstructions(
    claudeMdPath, 'claude-code', result, '', hasTranscriptStopHook(settings.hooks.Stop),
  );
}

/** True when a Stop hook entry runs a `secretless-ai` command. */
function hasTranscriptStopHook(stop: any[]): boolean {
  return stop.some((h: any) => h.hooks?.some((hh: any) => hh.command?.includes('secretless-ai')));
}

// ============================================================================
// Cursor Configuration
// ============================================================================

/**
 * Frontmatter for the Cursor rule file Secretless owns. `alwaysApply: true`
 * is what makes Cursor attach the rule to every chat rather than only when a
 * glob matches or the model decides the description is relevant.
 */
const CURSOR_MDC_FRONTMATTER = [
  '---',
  'description: Secretless credential protection (managed by secretless-ai)',
  'alwaysApply: true',
  '---',
  '',
].join('\n');

const CURSOR_MDC = '.cursor/rules/secretless.mdc';
const CURSOR_LEGACY = '.cursorrules';

function configureCursor(projectDir: string, result: InitResult): void {
  // Every path this writer may create or traverse is checked first, and one
  // refusal means nothing is written for Cursor at all (AC8): a half-written
  // tool would be listed by `status` from the one file that did land.
  if (refuseUnsafePaths(projectDir, 'cursor', ['.cursor', '.cursor/rules', CURSOR_MDC, CURSOR_LEGACY], result)) {
    return;
  }

  // Cursor documents project rules as `.cursor/rules/*.mdc`, so the block goes
  // into a rule file Secretless owns there, created alongside whatever `.mdc`
  // files the user already has (which are never touched). The single-file
  // `.cursorrules` is the legacy form and is never created.
  //
  // Held cell: a project whose rules live in `.cursorrules` and that has no
  // `.mdc` under `.cursor/rules/` keeps that layout. The block is appended to
  // `.cursorrules` and no `.mdc` is created, because nothing has yet observed,
  // on a current Cursor, that adding the first `.mdc` leaves a `.cursorrules`
  // rule applied. Once that is observed the branch below goes away and the
  // `.mdc` is written for this project too.
  const legacyIsFile = pathKind(path.join(projectDir, CURSOR_LEGACY)) === 'file';
  if (legacyIsFile && !dirHoldsMdc(path.join(projectDir, '.cursor', 'rules'))) {
    writeInstructionFile(projectDir, CURSOR_LEGACY, 'cursor', result);
    return;
  }

  writeInstructionFile(projectDir, CURSOR_MDC, 'cursor', result, CURSOR_MDC_FRONTMATTER);
  // A project that already carries both forms gets the block in both, so the
  // instructions reach Cursor whichever file it reads.
  if (legacyIsFile) {
    writeInstructionFile(projectDir, CURSOR_LEGACY, 'cursor', result);
  }
}

/** True when `dir` is a directory holding at least one `.mdc` entry. */
function dirHoldsMdc(dir: string): boolean {
  if (pathKind(dir) !== 'dir') return false;
  return fs.readdirSync(dir).some(name => name.endsWith('.mdc'));
}

// ============================================================================
// GitHub Copilot Configuration
// ============================================================================

function configureCopilot(projectDir: string, result: InitResult): void {
  const githubDir = path.join(projectDir, '.github');
  fs.mkdirSync(githubDir, { recursive: true });

  const instructionsPath = path.join(githubDir, 'copilot-instructions.md');
  addSecretlessInstructions(instructionsPath, 'copilot', result);
}

// ============================================================================
// Windsurf Configuration
// ============================================================================

const WINDSURF_RULES = '.windsurfrules';

function configureWindsurf(projectDir: string, result: InitResult): void {
  // The same checks as Cursor and Cline. Writing straight to the path followed
  // a `.windsurfrules` link wherever it led, created the target of a dangling
  // one, and threw EISDIR on a directory, which left every tool configured
  // after Windsurf (Cline, Aider) unconfigured.
  if (refuseUnsafePaths(projectDir, 'windsurf', [WINDSURF_RULES], result)) {
    return;
  }
  writeInstructionFile(projectDir, WINDSURF_RULES, 'windsurf', result);
}

// ============================================================================
// Cline Configuration
// ============================================================================

const CLINE_LEGACY = '.clinerules';
const CLINE_DIR_FILE = '.clinerules/secretless.md';
const CLINE_RULES_FILE = '.cline/rules/secretless.md';

function configureCline(projectDir: string, result: InitResult): void {
  // As for Cursor: check every path first, write nothing on a refusal (AC8).
  const guarded = [CLINE_LEGACY, '.cline', '.cline/rules', CLINE_DIR_FILE, CLINE_RULES_FILE];
  if (refuseUnsafePaths(projectDir, 'cline', guarded, result)) {
    return;
  }

  // Cline documents `.clinerules` as either a single file or a directory of
  // rule files, and also reads `.cline/rules/`. Follow the layout the project
  // already uses; where there is none, create the documented directory form.
  // The previous writer assumed a regular file and threw EISDIR on the
  // directory form, which took every tool configured after Cline down with it.
  const legacyKind = pathKind(path.join(projectDir, CLINE_LEGACY));

  if (legacyKind === 'file') {
    // A regular `.clinerules` is never created, but one the user already has
    // keeps working: append there and make no directory.
    writeInstructionFile(projectDir, CLINE_LEGACY, 'cline', result);
    return;
  }

  if (legacyKind === 'dir') {
    writeInstructionFile(projectDir, CLINE_DIR_FILE, 'cline', result);
    return;
  }

  if (pathKind(path.join(projectDir, '.cline', 'rules')) === 'dir') {
    writeInstructionFile(projectDir, CLINE_RULES_FILE, 'cline', result);
    return;
  }

  writeInstructionFile(projectDir, CLINE_DIR_FILE, 'cline', result);
}

// ============================================================================
// Aider Configuration
// ============================================================================

function configureAider(projectDir: string, result: InitResult): void {
  const ignorePath = path.join(projectDir, '.aiderignore');
  const existing = fs.existsSync(ignorePath) ? fs.readFileSync(ignorePath, 'utf-8') : '';

  if (!existing.includes('# Secretless')) {
    const secretPatterns = [
      '',
      '# Secretless: keep secrets out of AI context',
      '.env',
      '.env.*',
      // Un-ignore committed template files — placeholders, not real secrets.
      '!.env.example',
      '!.env.sample',
      '!.env.template',
      '!.env.dist',
      '*.key',
      '*.pem',
      '*.p12',
      '*.pfx',
      '*.tfstate',
      '*.tfvars',
      '.aws/',
      '.ssh/',
      'secrets/',
      'credentials/',
    ].join('\n');

    fs.writeFileSync(ignorePath, existing + secretPatterns + '\n');
    if (existing) {
      result.filesModified.push('.aiderignore');
    } else {
      result.filesCreated.push('.aiderignore');
    }
  }
}

// ============================================================================
// Shared Utilities
// ============================================================================

const SECRETLESS_MARKER = '<!-- secretless:managed -->';

// The "Command output is not guarded" paragraph is the documented floor for the
// channel no layer here covers (#129): every guard arm matches the command text
// or a local path before the command runs, and no hook reads tool output, so a
// credential returned by a provider API reaches context unchecked. It is an
// instruction to the assistant, not an enforced control, and says so.
//
// The last section says what happens to a credential that reaches the
// conversation: it has already been sent to the model, so it is treated as
// exposed. Nothing redacts it. The Stop hook's `clean --last` rewrites the
// local session file after the turn, and only Claude Code has that hook, so
// the cleanup is described only in a Claude Code file whose settings carry it.
function buildSecretlessInstructions(tool: string, cleanupHookInstalled: boolean): string {
  // Detect which env vars are actually set
  const availableKeys: string[] = [];
  for (const envVar of Object.keys(SERVICE_HINTS)) {
    if (process.env[envVar] && process.env[envVar]!.length > 0) {
      availableKeys.push(envVar);
    }
  }

  let keyTable = '';
  if (availableKeys.length > 0) {
    keyTable = `\n**Available API keys** (set as env vars — use \`$VAR_NAME\` in commands, never ask for values):\n\n`;
    keyTable += `| Env Var | Service | Auth Header |\n|---------|---------|-------------|\n`;
    for (const envVar of availableKeys) {
      const hint = SERVICE_HINTS[envVar];
      keyTable += `| \`$${envVar}\` | ${hint.service} | \`${hint.authHeader}\` |\n`;
    }
  }

  const cleanup = tool === 'claude-code' && cleanupHookInstalled
    ? '- After each turn, a Claude Code hook runs `secretless-ai clean --last`, which rewrites the newest session file in each project directory under `~/.claude/projects` and replaces values that match known credential patterns. It does not stop a value from reaching the model or its provider. Do not rely on it to remove a value\n'
    : '';

  return `
${SECRETLESS_MARKER}
## Secretless Mode

This project uses Secretless to protect credentials from AI context.
${keyTable}
**Blocked file patterns** (never read, write, or reference):
- \`.env\`, \`.env.local\`, \`.env.*.local\`, \`.env.{development,production,staging,test}\` — real environment variable files
  (template files \`.env.example\`, \`.env.sample\`, \`.env.template\`, \`.env.dist\` are NOT blocked — they hold placeholders and are meant to be committed/edited)
- \`*.key\`, \`*.pem\`, \`*.p12\`, \`*.pfx\` — private key files
- \`.aws/credentials\`, \`.ssh/*\` — cloud/SSH credentials
- \`*.tfstate\`, \`*.tfvars\` — Terraform state with secrets
- \`secrets/\`, \`credentials/\` — secret directories

**If you need a credential:**
1. Reference it via \`$VAR_NAME\` in shell commands or \`process.env.VAR_NAME\` in code
2. Never hardcode credentials in source files
3. Never print or echo key values — only reference them as variables

**Command output is not guarded.** The guard checks a command before it runs and cannot see what the command prints. A command that returns credential values (\`aws secretsmanager get-secret-value\`, \`kubectl get secret -o yaml\`, a provider API that returns keys or environment variable values) puts them into this conversation, and nothing here blocks it. Do not run one to look at a credential; read only the named, non-secret fields you need (\`--query\`, \`jq\`) instead of dumping whole objects.

**If you find a hardcoded credential:**
1. Replace it with an environment variable reference
2. Add the variable name to \`.env.example\`
3. Warn the user to rotate the exposed credential

Verify setup: \`npx secretless-ai verify\`

## Credentials in the conversation
- NEVER ask users to paste API keys, tokens, or passwords into the conversation
- If a user pastes a credential, immediately warn them and suggest using environment variables
- A credential value that appears in this conversation has already reached the model and its provider. Treat it as exposed and tell the user to rotate it
${cleanup}`;
}

/** What is at a path: a regular file, a directory, something else, or nothing. */
function pathKind(p: string): 'file' | 'dir' | 'other' | 'absent' {
  try {
    const st = fs.statSync(p);
    if (st.isFile()) return 'file';
    if (st.isDirectory()) return 'dir';
    return 'other';
  } catch {
    return 'absent';
  }
}

/** Same, without following a symbolic link at the path itself. */
function linkAwareKind(p: string): 'file' | 'dir' | 'symlink' | 'other' | 'absent' {
  try {
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) return 'symlink';
    if (st.isFile()) return 'file';
    if (st.isDirectory()) return 'dir';
    return 'other';
  } catch {
    return 'absent';
  }
}

/**
 * Why a project-relative path must not be created or appended to, or null
 * when it may be. Every existing component on the way is checked with
 * `lstat`, so a symbolic link anywhere in the path is refused rather than
 * followed. The deepest existing component is then resolved, and must lie
 * inside the project's real path: a link `init` follows out of the project
 * would create or append to a file the user never pointed it at (the M2 cells
 * of the security entry on this change).
 *
 * In `'write'` mode the path is about to be written, so an intermediate
 * component must be a directory and the last one, when present, a regular
 * file. In `'links'` mode (the pre-check over every path a writer might use)
 * a component of another kind just ends the walk: the layout the writer picks
 * decides whether that path is used at all.
 */
function unsafePathReason(
  projectDir: string,
  rel: string,
  mode: 'write' | 'links',
): { path: string; reason: string } | null {
  const parts = rel.split('/');
  let deepestExisting = projectDir;
  for (let i = 0; i < parts.length; i++) {
    const relSoFar = parts.slice(0, i + 1).join('/');
    const abs = path.join(projectDir, ...parts.slice(0, i + 1));
    const kind = linkAwareKind(abs);
    if (kind === 'absent') break;
    if (kind === 'symlink') return { path: relSoFar, reason: 'is a symbolic link' };
    const last = i === parts.length - 1;
    const expected = last ? 'file' : 'dir';
    if (kind !== expected) {
      if (mode === 'links') break;
      return { path: relSoFar, reason: last ? 'is not a regular file' : 'is not a directory' };
    }
    deepestExisting = abs;
  }

  let projectReal: string;
  let real: string;
  try {
    projectReal = fs.realpathSync(projectDir);
    real = fs.realpathSync(deepestExisting);
  } catch (err) {
    return { path: rel, reason: `could not be resolved (${(err as Error).message})` };
  }
  if (real !== projectReal && !real.startsWith(projectReal + path.sep)) {
    return { path: rel, reason: `resolves outside the project (${real})` };
  }
  return null;
}

/**
 * Record every linked or escaping path among `rels` for `tool` in
 * `result.pathsRefused`. Returns true when at least one was refused, in which
 * case the caller writes nothing for that tool. Whether a path is the right
 * kind for the layout is the writer's concern, checked at the write.
 */
function refuseUnsafePaths(projectDir: string, tool: AITool, rels: string[], result: InitResult): boolean {
  let refused = false;
  for (const rel of rels) {
    const unsafe = unsafePathReason(projectDir, rel, 'links');
    if (unsafe) {
      recordRefusal(result, tool, unsafe);
      refused = true;
    }
  }
  return refused;
}

/** One entry per (tool, path): several guarded paths may share a linked ancestor. */
function recordRefusal(result: InitResult, tool: AITool, unsafe: { path: string; reason: string }): void {
  if (result.pathsRefused.some(r => r.tool === tool && r.path === unsafe.path)) return;
  result.pathsRefused.push({ tool, ...unsafe });
}

/**
 * Create or append the Secretless block at a project-relative path, after a
 * final check that nothing on the way to it is a link or leads outside the
 * project. A refusal is recorded and nothing is written.
 */
function writeInstructionFile(
  projectDir: string,
  rel: string,
  tool: AITool,
  result: InitResult,
  preamble = '',
): void {
  const unsafe = unsafePathReason(projectDir, rel, 'write');
  if (unsafe) {
    recordRefusal(result, tool, unsafe);
    return;
  }
  const filePath = path.join(projectDir, rel);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });

  // The check above ran on paths, and a path-based write follows whatever link
  // is put there after it. So the file is opened without following a link at
  // its last component, and the open file is then confirmed to be the regular
  // file the path names inside the project before it is read or written. A
  // directory on the way swapped for a link before the open can still leave an
  // empty file where that link leads; the block is never written to it.
  let fd: number;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDWR | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW ?? 0));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ELOOP') {
      recordRefusal(result, tool, { path: rel, reason: 'is a symbolic link' });
      return;
    }
    // A rule file that cannot be opened for writing (read-only, immutable, or
    // on a read-only mount) and already carries the block needs no write, so
    // it is left as it is instead of failing the run and every tool after it.
    if ((code === 'EACCES' || code === 'EPERM' || code === 'EROFS') && alreadyCarriesBlock(projectDir, rel)) {
      return;
    }
    throw err;
  }
  try {
    const unsafeNow = openedFileUnsafe(projectDir, rel, fd);
    if (unsafeNow) {
      recordRefusal(result, tool, unsafeNow);
      return;
    }
    // Reading through the descriptor leaves its position at the end, so the
    // write below appends; on an empty file it starts at the beginning.
    const existing = fs.readFileSync(fd, 'utf-8');
    if (existing.includes(SECRETLESS_MARKER)) return;
    fs.writeFileSync(fd, (existing ? '' : preamble) + buildSecretlessInstructions(tool, false));
    (existing ? result.filesModified : result.filesCreated).push(path.relative(process.cwd(), filePath));
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * True when `rel`, opened read-only without following a link at its last
 * component, passes the same checks as a rule file opened for writing and
 * already carries the Secretless block. O_NONBLOCK keeps a FIFO put there
 * from blocking the open; it then fails the regular-file check.
 */
function alreadyCarriesBlock(projectDir: string, rel: string): boolean {
  let fd: number;
  try {
    fd = fs.openSync(
      path.join(projectDir, rel),
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0),
    );
  } catch {
    return false;
  }
  try {
    return openedFileUnsafe(projectDir, rel, fd) === null
      && fs.readFileSync(fd, 'utf-8').includes(SECRETLESS_MARKER);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Why the file open on `fd` must not be read or written for `rel`, or null
 * when it is the regular file the path names inside the project.
 */
function openedFileUnsafe(projectDir: string, rel: string, fd: number): { path: string; reason: string } | null {
  const opened = fs.fstatSync(fd);
  return !opened.isFile()
    ? { path: rel, reason: 'is not a regular file' }
    : unsafePathReason(projectDir, rel, 'write')
      ?? (sameEntry(path.join(projectDir, rel), opened) ? null : { path: rel, reason: 'was replaced while init was writing it' });
}

/** True when `p`, not followed, is the same file system entry as `opened`. */
function sameEntry(p: string, opened: fs.Stats): boolean {
  try {
    const now = fs.lstatSync(p);
    return now.dev === opened.dev && now.ino === opened.ino;
  } catch {
    return false;
  }
}

/**
 * Append the Secretless block to `filePath`, creating the file when absent.
 * A file that already carries the marker is left byte-identical. `preamble`
 * is written ahead of the block only when the file is being created, for
 * formats that need a header (the Cursor `.mdc` frontmatter).
 * `cleanupHookInstalled` is true only when this run left the Claude Code Stop
 * hook in place; the block then describes the cleanup it runs.
 */
function addSecretlessInstructions(
  filePath: string,
  tool: string,
  result: InitResult,
  preamble = '',
  cleanupHookInstalled = false,
): void {
  const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf-8') : '';

  if (existing.includes(SECRETLESS_MARKER)) {
    return; // Already configured
  }

  const head = existing ? existing : preamble;
  fs.writeFileSync(filePath, head + buildSecretlessInstructions(tool, cleanupHookInstalled));
  if (existing) {
    result.filesModified.push(path.relative(process.cwd(), filePath));
  } else {
    result.filesCreated.push(path.relative(process.cwd(), filePath));
  }
}

// Words that mark an environment variable as holding a secret. Kept in one place
// so the hook's regexes and the native deny globs above (`echo $*API_KEY*`,
// `printenv *KEY*`) agree on what counts.
const SECRET_VAR_WORDS = [
  'SECRET', 'PASSWORD', 'PASSWD', 'API_?KEY', 'ACCESS_KEY', 'TOKEN',
  'PRIVATE_KEY', 'VAULT', 'CREDENTIAL', 'DATABASE_URL', 'CONNECTION_STRING',
].join('|');

// A shell variable reference whose NAME merely CONTAINS one of those words.
// The prefix is the whole point: real variables are named $ANTHROPIC_API_KEY,
// $GITHUB_TOKEN, $AWS_SECRET_ACCESS_KEY, ${SENDGRID_API_KEY}. Anchoring right
// after the `$`, as this did before, only ever caught the bare $API_KEY form,
// so every name anyone actually uses walked past the hook. The native
// permissions.deny globs already allowed the prefix, so the two layers
// disagreed and the hook was the weaker one.
const SECRET_VAR_REF = '\\$\\{?[A-Za-z0-9_]*(' + SECRET_VAR_WORDS + ')';

// Same, for commands that take a bare variable NAME with no `$` (printenv FOO).
const SECRET_VAR_NAME = '[A-Za-z0-9_]*(' + SECRET_VAR_WORDS + ')';

// The span between `echo` and the variable must stay inside ONE command. With a
// bare `.*` the match ran to the end of the whole line, so any compound command
// that happened to contain an `echo` anywhere was judged by a `$SECRET` far away
// in an unrelated command: `echo "starting"; curl -H "Bearer $API_KEY"` was
// blocked even though passing a secret to curl is the intended way to use one.
// Over-blocking legitimate use is not a safe default, it is how a guard gets
// switched off. Stopping at a command separator keeps `echo $API_KEY` and
// `echo "value:" $API_KEY` blocked while letting the next command through, and
// a separate `echo $SECRET` later on still matches on its own.
const SAME_COMMAND = '[^;&|\\n]*';

// Command position: line start, or after a separator, `(` or a backtick,
// optionally behind a wrapper (sudo, xargs, watch, ...) and a directory
// (/bin/ps). A command name matched after it is the program being run, not a
// word inside an argument: `docker compose ps web` and a commit message that
// mentions ps are not read as a call to ps.
const CMD_POSITION =
  '(^|[;&|({`])\\s*((sudo|command|exec|nohup|time|nice|xargs|watch)(\\s+-[^[:space:]]*)*\\s+)*([^[:space:];&|()]*/)?';

// A secret file extension must END there. Without a boundary, `.key` matched
// `.keys()` and `.keychain`, and `.env` matched `.envelope`, so ordinary work
// was blocked: `python3 -c "...json.load(f).keys()"` was refused as if it were
// reading a private key. grep -E has no lookahead, so the boundary consumes one
// character or end-of-string. `.env.local` still matches, because the character
// after `.env` is a dot, not an identifier character.
const SECRET_FILE_EXT = '\\.(env|key|pem|p12|pfx)([^A-Za-z0-9]|$)';

function generateClaudeHookScript(customRules?: CustomRules | null): string {
  // Three categories of secret-file signals. Each matches differently:
  //  - extensions: suffix match on basename, e.g. `server.key`, `prod.env`, `id_rsa.pem`.
  //    The previous `^\.key` anchored form only caught literal dotfiles (`.key`) and
  //    silently allowed the far more common `name.key`/`prod.env` suffix form.
  //  - dotfileNames: exact basename match for credential dotfiles with no suffix form.
  //  - pathFragments: case-insensitive substring match anywhere in the path.
  const secretExtensions = ['env', 'key', 'pem', 'p12', 'pfx', 'crt', 'tfstate', 'tfvars'];
  const dotfileNames = ['.npmrc', '.pypirc', '.git-credentials', '.netrc'];
  // Key the credentials rule on the STORE (`credentials/`), never on the bare
  // topic word. A bare `credentials` becomes the case glob `*credentials*` below
  // and matches ANY path merely NAMING the subject: the only tracked file in this
  // repository it caught was `docs/use-cases/protect-my-credentials.md`, our own
  // use-case page, which holds no credential and cannot reach the template-suffix
  // exemption because it is a `.md`. The canonical list already had the store
  // form — SECRET_FILE_PATTERNS in patterns.ts spells it `credentials/` — and this
  // list had drifted from it by one slash. The store itself loses nothing:
  // `credentials/prod.json` still matches here, `~/.aws/credentials` matches the
  // next fragment, and `.git-credentials` is an exact basename in dotfileNames.
  const pathFragments = [
    'credentials/', '.aws/credentials', '.ssh/', '.docker/config.json',
    'secrets/', '.opena2a/secretless-ai/', '.secretless-ai/',
  ];

  // Merge custom file patterns from .secretless-rules.yaml into the right
  // bucket. Each bucket below becomes a glob matched against the path the tool
  // was given, so a pattern an operator wrote in the deny-rule grammar's
  // absolute `//` form is reduced to the single slash a real path carries
  // first: `*//srv/app/creds/*.json*` matches no path that exists, which left
  // the guard hook — the layer that actually refuses the read — inert for
  // exactly the pattern the operator wrote to be protected.
  if (customRules?.files) {
    for (const raw of customRules.files) {
      const p = filesystemPathForm(raw.trim());
      if (!p) continue;
      const extMatch = p.match(/^\*?\.([A-Za-z0-9]+)$/); // `*.foo` or `.foo`
      if (extMatch && !p.includes('/')) {
        const ext = extMatch[1].toLowerCase();
        if (!secretExtensions.includes(ext)) secretExtensions.push(ext);
      } else if (p.startsWith('.') && !p.includes('/') && !p.includes('*')) {
        if (!dotfileNames.includes(p)) dotfileNames.push(p);
      } else if (!pathFragments.includes(p)) {
        pathFragments.push(p);
      }
    }
  }

  const extAlternation = secretExtensions.join('|');
  const dotfileCases = dotfileNames.map(n => n.toLowerCase()).join('|');
  // Emit fragments as UNQUOTED case globs so a custom rule's `*` keeps glob semantics
  // (`private*` must still match `private_key.txt`). Single-quoting made the `*` literal,
  // silently neutering wildcard custom rules. Custom rules are restricted upstream by
  // validateRules' SAFE_PATTERN (alphanumerics + `_ * . - / [ ] { } ?` only — no quotes,
  // `)`, `;`, `|`, backtick or `$`), so an unquoted glob cannot break out of the `case`.
  const fragmentCases = pathFragments.map(f => `*${f.toLowerCase()}*`).join('|');

  return `#!/bin/bash
# Secretless Guard — PreToolUse hook for Claude Code
# Blocks file access to secrets before they enter AI context.
# Managed by secretless-ai. Do not edit manually.

set -euo pipefail

# Match bytewise, not by the ambient locale.
#
# In a UTF-8 locale grep decodes each line as characters, and a line carrying an
# invalid byte sequence cannot be decoded, so any pattern using a bracket
# expression stops matching on that line while a plain literal pattern still
# does. That is an evasion: appending one invalid byte to a secret-reading
# command made the bracket-expression guards below fall silent. LC_ALL=C removes
# the decoding step, so a command cannot change how it is matched by carrying
# undecodable bytes, and matching no longer varies with the developer's locale.
export LC_ALL=C

INPUT=$(cat)
# Each field is optional depending on the tool (a Bash call has no file_path; a
# Read call has no command), so a non-matching grep is normal, not an error. The
# trailing \`|| true\` keeps a no-match from returning non-zero and tripping
# \`set -euo pipefail\` — without it the whole Bash-command branch below was dead:
# every Bash call died at the FILE_PATH line (grep found no file_path) before any
# command guard ran. Regression: release-test 2026-07-16.
# Parse tool_name with a real JSON parser when one is available, for the same
# reason the command extraction below does. The grep form requires COMPACT JSON:
# it matches '"tool_name":"…"' with no space after the colon, so a client that
# pretty-prints its hook payload yields an empty TOOL_NAME, the Bash branch below
# is skipped entirely, and every command guard silently fails OPEN. That is the
# same dead-branch class as the 2026-07-16 FILE_PATH regression, reached through
# formatting rather than through \`set -euo pipefail\`. The grep remains as the
# fallback for hosts without python3.
TOOL_NAME=""
if command -v python3 >/dev/null 2>&1; then
  # Emit ONLY a non-empty string. str() of a number, bool or dict would produce
  # a non-empty WRONG value ('123', 'True', "{'a': 1}"), which suppresses the
  # grep fallback below and leaves the guard reading a field that isn't there.
  TOOL_NAME=$(printf '%s' "$INPUT" | python3 -c 'import json,sys
try:
    v = json.load(sys.stdin).get("tool_name")
    sys.stdout.write(v if isinstance(v, str) else "")
except Exception:
    pass' 2>/dev/null || true)
fi
if [ -z "$TOOL_NAME" ]; then
  TOOL_NAME=$(echo "$INPUT" | grep -o '"tool_name":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
fi

# Extract file path from tool input (handles Read, Grep, Glob, Edit, Write).
# Same compact-JSON brittleness as TOOL_NAME above: a pretty-printed payload
# leaves FILE_PATH empty and the file guard never runs. Parse properly when
# python3 is available, keep the greps as the fallback.
# Collect EVERY candidate path, not just the first. The structured parse reads
# the documented top-level fields; the greps additionally sweep the whole
# payload, so a nested shape (MultiEdit-style edit lists, MCP tool payloads)
# whose secret path is not at the top level is still seen. Checking the union
# is what keeps the structured parse from NARROWING the older grep behaviour.
# Only non-empty strings are emitted, for the same reason as TOOL_NAME above.
FILE_PATH_CANDIDATES=""
if command -v python3 >/dev/null 2>&1; then
  FILE_PATH_CANDIDATES=$(printf '%s' "$INPUT" | python3 -c 'import json,sys
def walk(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ("file_path", "path") and isinstance(v, str) and v:
                yield v
            else:
                yield from walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from walk(v)
try:
    sys.stdout.write("\\n".join(walk(json.load(sys.stdin))))
except Exception:
    pass' 2>/dev/null || true)
fi
FILE_PATH_CANDIDATES=$(printf '%s\\n%s\\n%s\\n' \
  "$FILE_PATH_CANDIDATES" \
  "$(echo "$INPUT" | grep -o '"file_path":"[^"]*"' | cut -d'"' -f4 || true)" \
  "$(echo "$INPUT" | grep -o '"path":"[^"]*"' | cut -d'"' -f4 || true)" \
  | grep -v '^$' | sort -u || true)
FILE_PATH=$(printf '%s' "$FILE_PATH_CANDIDATES" | head -1 || true)

# For Bash tool, check the command for secret access patterns
if [ "$TOOL_NAME" = "Bash" ]; then
  # Extract the command with a real JSON parser when one is available. The old
  # grep 'command":"[^"]*"' stopped at the FIRST double quote, so any command
  # containing a quote (\`x="" ; cat .env\`, \`eval "$(secretless-ai env)"\`) was
  # truncated before the dangerous part and slipped past every guard below.
  # python3's json module handles the escaping correctly; the grep is only a
  # fallback for hosts without python3 (there the native permissions.deny rules
  # remain the enforcing layer). Regression: adressed 2026-07-16 (issue #99).
  COMMAND=""
  if command -v python3 >/dev/null 2>&1; then
    # surrogatepass so a lone surrogate in the command can't raise mid-write and
    # leave us empty; write bytes so no encoding step can fail.
    COMMAND=$(printf '%s' "$INPUT" | python3 -c 'import json,sys
try:
    ti = (json.load(sys.stdin).get("tool_input") or {})
    sys.stdout.buffer.write((ti.get("command") or "").encode("utf-8","surrogatepass"))
except Exception:
    pass' 2>/dev/null || true)
  fi
  # Fail CLOSED: if python is absent OR its extraction produced nothing (parse
  # error, odd input), fall back to the grep extraction rather than leaving
  # COMMAND empty — an empty COMMAND would skip every guard below. The grep
  # truncates at an embedded quote, but a truncated match is still better than no
  # match, and the native permissions.deny rules remain in front.
  if [ -z "$COMMAND" ]; then
    COMMAND=$(echo "$INPUT" | grep -o '"command":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
  fi
  # NOTE ON TEMPLATE FILES. The command guard refuses \`cat <name>.env.example\`
  # even though the file-path guard below allows template files, so the two
  # layers disagree about committed placeholders. That is a known, deliberate
  # over-block, NOT an oversight.
  #
  # The obvious fix — subtract template-suffixed tokens from the command before
  # matching — was implemented, tested against a 50-command corpus, and then
  # REVERTED, because it is a credential bypass. This guard is a denylist over
  # command TEXT, and its only evidence is the literal secret path appearing
  # after a verb. Removing that literal hands the attacker the deletion:
  #
  #     cat "$(basename <name>.env.example .example)"
  #
  # reconstructs the real path from the very token the scrub erased, needs no
  # preconditions (basename is pure string manipulation, the template need not
  # exist), and was measured reading a real secret. Requiring the extension
  # match at the end of the token fails the same way, because the template token
  # still never matches. Any textual exemption for the template NAME permits
  # deriving the real name from it.
  #
  # Closing the disagreement safely needs the guard to resolve the path a
  # command would actually open, rather than pattern-matching its text. Until
  # then, over-blocking a placeholder file is the correct trade against leaking
  # a real one.
  #
  # Block commands that dump secret files (expanded to cover grep, awk, sed, strings, xxd)
  if echo "$COMMAND" | grep -qiE '(cat|head|tail|less|more|type|grep|awk|sed|strings|xxd)\\s+.*${SECRET_FILE_EXT}'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked command that reads secret files. This guard matches command text and cannot tell a filename from a search pattern, so a committed template (like .env.example) or a pattern that merely contains a secret-file token is blocked too. Safe path: open committed template files with the Read tool and search with the Grep tool instead of Bash."}}'
    exit 0
  fi
  # Block python/node one-liners that read secret files. Same dead-end as the arm
  # above had: a one-liner that only COMPILES a regex naming a secret-file token
  # (node -e with new RegExp, python3 -c with re.compile) opens nothing and is
  # refused all the same, because this is a denylist over command TEXT. The
  # decision has to stand — see NOTE ON TEMPLATE FILES — so the reason carries the
  # ambiguity and the route out.
  if echo "$COMMAND" | grep -qiE '(python3?|node)\\s+-(c|e).*${SECRET_FILE_EXT}'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked script command that reads secret files. This guard matches command text and cannot tell a filename from a search pattern, so a one-liner that merely names a secret-file token inside a regex is blocked too. Safe path: open committed template files with the Read tool and search with the Grep tool instead of Bash."}}'
    exit 0
  fi
  # Block python/node one-liners that read env vars containing secrets
  if echo "$COMMAND" | grep -qiE '(python3?|node)\\s+-(c|e).*(os\\.environ|process\\.env).*(${SECRET_VAR_WORDS})'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked script command that reads secret environment variables"}}'
    exit 0
  fi
  # Block eval-based env var extraction
  if echo "$COMMAND" | grep -qiE '(eval\\s+echo|\\$\\{!).*${SECRET_VAR_REF}'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked eval-based secret extraction"}}'
    exit 0
  fi
  # Block commands that echo secret env vars. The variable name may carry any
  # prefix: $ANTHROPIC_API_KEY and \${GITHUB_TOKEN} count, not just $API_KEY.
  if echo "$COMMAND" | grep -qiE '(echo|printenv)\\s+${SAME_COMMAND}${SECRET_VAR_REF}'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked command that exposes secret environment variables"}}'
    exit 0
  fi
  # printenv takes a bare NAME with no \`$\`, so the arm above never sees it.
  if echo "$COMMAND" | grep -qiE 'printenv\\s+(-[A-Za-z0]+\\s+)*${SECRET_VAR_NAME}'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked command that exposes secret environment variables"}}'
    exit 0
  fi
  # Bare \`printenv\` prints the whole environment, which is the same disclosure as
  # naming every secret variable at once. \`env\` is NOT matched here: it is
  # overwhelmingly used as a prefix (\`env -u VAR cmd\`), so its dump form has its
  # own arm below that tells the two apart.
  if echo "$COMMAND" | grep -qiE '(^|[;&|]\\s*)printenv\\s*(-0\\s*)?$'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked full environment dump via printenv"}}'
    exit 0
  fi
  # Process listings that print environments or full command lines (#187).
  # Refusing printenv alone left the other routes open: \`ps -E\` (and the BSD \`e\`
  # modifier) prints a process environment outright, \`/proc/<pid>/environ\` holds
  # it, and a full command line carries it for a process that rewrites its title
  # (\`npm exec\` does), so \`pgrep -l\`/\`-a\`, \`ps ... ww\` and \`ps -o command\`
  # print it too. The patterns are matched case-sensitively, because \`ps -e\`
  # (every process, on macOS and Linux) and \`ps -E\` (the environment) differ only
  # in case; command names are bracketed instead, so \`PS\` on a case-insensitive
  # disk is still caught. \`ps\` and \`pgrep\` are matched in command position (line
  # start, after a separator, \`(\` or a backtick, after sudo/xargs/watch-style
  # prefixes, or as a path like /bin/ps), so \`docker compose ps web\` and a commit
  # message that mentions ps are not refused.
  #
  # A plain listing (\`ps aux\`, \`ps -ef\`) prints the command column too and is
  # NOT matched: it is the everyday process listing, and refusing it is how a
  # guard gets switched off. Matched are the forms that ask for the environment,
  # for unlimited width or for the command column by name. When output is not a
  # terminal, macOS ps already uses unlimited width, so there \`ps aux\` prints
  # the same lines as \`ps auxww\`; that gap is known, not closed.
  #   1. pgrep with -l/-a in a flag cluster, or --list-name/--list-full. The
  #      cluster is restricted to pgrep's own flag letters, so a pattern such as
  #      \`pgrep -f "java -jar"\` is not mistaken for one.
  #   2. ps with E or ww in a dashed cluster, or e or ww in a dashless (BSD
  #      style) first argument: \`ps -E\`, \`ps -axww\`, \`ps eww <pid>\`, \`ps auxww\`.
  #   3. ps -o/-O/--format (or BSD \`o\`) naming command, args or cmd; comm,
  #      ucomm and ucmd print the program name without its arguments.
  #   4. Any reference to a /proc environ file.
  if echo "$COMMAND" | grep -qE \\
      -e '${CMD_POSITION}[Pp][Gg][Rr][Ee][Pp](\\s[^;&|]*)?\\s(-[acfilnoqvwxAIS]*[la][acfilnoqvwxAIS]*([^A-Za-z0-9_-]|$)|--list-(name|full))' \\
      -e '${CMD_POSITION}[Pp][Ss]((\\s[^;&|]*)?\\s-[A-Za-z]*(E|ww)|\\s+[A-Za-z]*(e|ww)[A-Za-z]*([^A-Za-z0-9_-]|$))' \\
      -e '${CMD_POSITION}[Pp][Ss]((\\s[^;&|]*)?\\s(-[A-Za-z]*[oO]|--format)|\\s+[A-Za-z]*[oO])([^;&|]*[^A-Za-z0-9_])?(command|args|cmd)([^A-Za-z0-9_]|$)' \\
      -e '/proc/.*environ([^A-Za-z0-9_]|$)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked process listing that can print environment variables or full command lines, which can hold the credentials of other processes. Safe path: pgrep -f <pattern> prints process IDs only, and ps -p <pid> -o pid,comm prints the program name without its arguments."}}'
    exit 0
  fi
  # A bare \`env\` prints the whole environment, the same disclosure as a bare
  # printenv. \`env\` followed only by its own options and NAME=value assignments
  # runs no command and so prints the environment (\`env -u X\`, \`env FOO=1\`,
  # \`env | grep KEY\`); once a command word follows (\`env -u X git push\`,
  # \`/usr/bin/env node\`) it is a prefix and is allowed.
  if echo "$COMMAND" | grep -qE '${CMD_POSITION}[Ee][Nn][Vv](\\s+(-[iv0]+|-|--(ignore-environment|null|debug)|-u\\s*[A-Za-z_][A-Za-z0-9_]*|--unset[=[:space:]]\\s*[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*=[^[:space:];&|]*))*\\s*($|[;&|)}\`<>]|[0-9]+>)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked full environment dump via env. Safe path: printenv NAME prints one non-secret variable, and env as a prefix that runs a command (env -u NAME cmd) is not blocked."}}'
    exit 0
  fi
  # Block secretless-ai secret extraction with --force
  if echo "$COMMAND" | grep -qiE 'secretless-ai\\s+secret\\s+get.*--force'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked forced secret extraction"}}'
    exit 0
  fi
  # Block secretless-ai run with env/printenv to dump injected secrets. The
  # trailing boundary keeps env/printenv a whole word so "-- envsubst" (a legit
  # templating program) is not caught.
  if echo "$COMMAND" | grep -qiE 'secretless-ai\\s+run.*--\\s*(env|printenv)([^a-zA-Z0-9_]|$)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked secret dump via secretless-ai run"}}'
    exit 0
  fi
  # Block secretless-ai vault exec with env/printenv (same shape as run -- env,
  # for the identity vault's injected namespace credential).
  if echo "$COMMAND" | grep -qiE 'secretless-ai\\s+vault\\s+exec.*--\\s*(env|printenv)([^a-zA-Z0-9_]|$)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked secret dump via secretless-ai vault exec"}}'
    exit 0
  fi
  # Block the full-store plaintext dump: secretless-ai env prints every stored
  # secret as export statements. The shell-profile eval hook never runs through
  # the agent, so no agent invocation of it is legitimate.
  # \`env\` as a whole subcommand: followed by any non-identifier char (space,
  # \`)\` in \`$(secretless-ai env)\`, \`;\`, \`|\`, a quote) or end of string — but
  # NOT a word char, so \`environment\` does not match.
  if echo "$COMMAND" | grep -qiE 'secretless-ai\\s+env([^a-zA-Z0-9_]|$)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked full secret-store dump via secretless-ai env"}}'
    exit 0
  fi
  # Block every reader of the secretless data directory except secretless-ai
  # itself. This arm used to list reading verbs (cat, head, awk, ...) and so
  # allowed every reader it did not name: python3, node, ruby and perl
  # one-liners and a plain shell redirect (\`< ~/.secretless-ai/config.json\`)
  # all read the store through it, and no list of verbs can name every program
  # that opens a file. The rule is now an allowlist: a command naming the
  # directory is refused unless the WHOLE command is one plain secretless-ai
  # invocation.
  #
  # "Plain" is what keeps the allowlist from being a prefix test. The command
  # must be one line holding the program name and words made only of letters,
  # digits and \`_ . / ~ : = @ + , -\`. That leaves out every shell operator that
  # can start a second program (\`; & | < > ( )\`, a backquote, \`$\`, a line
  # break) and every quote and backslash, so the words the shell runs are the
  # words matched here and \`"run"\` or \`r\\un\` cannot hide a subcommand. \`run\` and
  # \`vault exec\` start a program of the caller's choice, so a command carrying
  # either word is refused too. A copy reached by another name
  # (\`./secretless-ai\`, \`node dist/cli.js\`) is not on the list.
  #
  # The search-pattern over-block is kept: a source search FOR the directory
  # name (grep -rn for the literal string) reads no store and is refused anyway,
  # so the reason names it and points at the tools whose path guard can tell the
  # difference.
  if echo "$COMMAND" | grep -qiE '\\.secretless-ai|\\.opena2a/secretless-ai'; then
    SECRETLESS_ONLY=0
    case "$COMMAND" in
      *$'\\n'*) ;;
      *)
        if printf '%s' "$COMMAND" | grep -qE '^[[:blank:]]*(npx[[:blank:]]+(-y[[:blank:]]+|--yes[[:blank:]]+)?)?secretless-ai(@[A-Za-z0-9._-]+)?([[:blank:]]+[A-Za-z0-9_./~:=@+,-]+)*[[:blank:]]*$'; then
          # The words are plain here, so a case match finds them. It is not a
          # negated grep on purpose: under pipefail, a writer killed by SIGPIPE
          # after grep -q exits early would turn that negation into an allow.
          case " $COMMAND " in
            *[[:blank:]][Rr][Uu][Nn][[:blank:]]*|*[[:blank:]][Ee][Xx][Ee][Cc][[:blank:]]*) ;;
            *) SECRETLESS_ONLY=1 ;;
          esac
        fi
        ;;
    esac
    if [ "$SECRETLESS_ONLY" -eq 0 ]; then
      echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked access to secretless data directory. Only one plain secretless-ai command may name it; any other program, a shell redirect, or a command that chains, substitutes or starts another program is refused. This guard matches command text and cannot tell a filename from a search pattern, so a command that merely searches source for the directory name is blocked too. Safe path: open files with the Read tool and search with the Grep tool instead of Bash."}}'
      exit 0
    fi
  fi
${customRules ? customRulesToHookBlocks(customRules) : ''}  exit 0
fi

# Skip if no file path found
if [ -z "$FILE_PATH_CANDIDATES" ]; then
  exit 0
fi

# Check EVERY candidate path. A payload carrying both a benign top-level path
# and a secret one nested deeper must block on the secret one, so the loop only
# skips a template candidate rather than exiting on it.
while IFS= read -r CANDIDATE; do
  [ -z "$CANDIDATE" ] && continue

  # Normalize path for matching (case-insensitive: server.KEY and prod.ENV must match too)
  BASENAME=$(basename "$CANDIDATE")
  LOWER_BASENAME=$(echo "$BASENAME" | tr '[:upper:]' '[:lower:]')
  LOWER_PATH=$(echo "$CANDIDATE" | tr '[:upper:]' '[:lower:]')

  # Allow committed template/example files (.env.example, config.sample, etc.) — these
  # hold placeholders, not real secrets, and are meant to be read/edited/committed.
  # Checked BEFORE any block logic so it wins over the .env extension/dotfile rules below.
  case "$LOWER_BASENAME" in
    *.example|*.sample|*.template|*.dist) continue ;;
  esac

  BLOCKED=0
  # Block by secret file extension as a suffix: server.key, prod.env, id_rsa.pem, terraform.tfstate
  if echo "$LOWER_BASENAME" | grep -qE '\\.(${extAlternation})$'; then BLOCKED=1; REASON="secret file extension"; fi
  # Block .env dotfile families (.env, .env.local, .envrc, .env.production)
  case "$LOWER_BASENAME" in
    .env|.env.*|.envrc) BLOCKED=1; REASON=".env" ;;
    ${dotfileCases}) BLOCKED=1; REASON="$LOWER_BASENAME" ;;
  esac
  # Block by path fragment anywhere in the path (credentials, .ssh/, secrets/, ...)
  case "$LOWER_PATH" in
    ${fragmentCases}) BLOCKED=1; REASON="secret path" ;;
  esac

  if [ "\${BLOCKED:-0}" = "1" ]; then
    echo "{\\"hookSpecificOutput\\":{\\"hookEventName\\":\\"PreToolUse\\",\\"permissionDecision\\":\\"deny\\",\\"permissionDecisionReason\\":\\"Secretless: blocked access to secret file matching pattern '$REASON'\\"}}"
    exit 0
  fi
done <<EOF
$FILE_PATH_CANDIDATES
EOF

exit 0
`;
}

/**
 * The PostToolUse output check (#129). Every arm of the guard above matches a
 * command's text or a local path before the command runs, so a command that
 * fetches credentials (a provider API, `aws secretsmanager get-secret-value`,
 * `kubectl get secret -o yaml`) passes it with a clean command string and its
 * output lands in context unread. This hook reads that output after the command
 * has run and warns when it matches the credential catalog.
 *
 * It is detection after exposure, not prevention: the value is already in the
 * conversation when the hook sees it, and a format outside the catalog passes
 * unflagged. The messages say so, and they name the pattern, never the value.
 *
 * Node, not bash: the catalog is JavaScript regex (lookahead, `\d`, the `i`
 * flag), and embedding it verbatim keeps one source of truth instead of a
 * hand-translated ERE copy that drifts. `init` itself runs on Node, so it is
 * present. The `.cjs` extension keeps it CommonJS under a `"type": "module"`
 * package.json.
 */
function generateClaudeOutputCheckScript(): string {
  const patterns = CREDENTIAL_PATTERNS.map(p => [p.name, p.regex.source, p.regex.flags.replace('g', '')]);

  return `#!/usr/bin/env node
// Secretless output check — PostToolUse hook for Claude Code
// Warns when a command's output matches a credential pattern. The command has
// already run, so this cannot keep the value out of the conversation.
// Managed by secretless-ai. Do not edit manually.
'use strict';

const PATTERNS = ${JSON.stringify(patterns)};
const KNOWN_EXAMPLE_KEYS = new Set(${JSON.stringify([...KNOWN_EXAMPLE_KEYS])});
const PLACEHOLDER_INDICATORS = ${JSON.stringify(PLACEHOLDER_INDICATORS)};

// Scan long output in overlapping windows. Some catalog patterns have an
// unbounded run before a separator, which is quadratic over one long run of
// matching characters (a base64 blob, a minified response body). Windowing
// keeps the cost linear in output size. Windows overlap by more than the
// shortest text any catalog pattern needs to match, so a credential that starts
// too close to one window's end to match there still matches in the next.
const WINDOW = 16384;
const OVERLAP = 2048;

function collect(value, out, depth) {
  if (typeof value === 'string') { if (value) out.push(value); return; }
  if (!value || typeof value !== 'object' || depth > 8) return;
  for (const v of Array.isArray(value) ? value : Object.values(value)) collect(v, out, depth + 1);
}

// The value half of the scanner's allowlist (isKnownExample in scan.ts); its
// line-context rules need a source line, which command output does not have.
function isPlaceholder(value) {
  if (KNOWN_EXAMPLE_KEYS.has(value)) return true;
  const lower = value.toLowerCase();
  if (PLACEHOLDER_INDICATORS.some(p => lower.includes(p))) return true;
  return value.length >= 20 && new Set(value).size <= 6;
}

function matches(re, text) {
  for (let start = 0; start < text.length; start += WINDOW - OVERLAP) {
    const chunk = text.slice(start, start + WINDOW);
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(chunk)) !== null) {
      if (!isPlaceholder(m[1] ?? m[0])) return true;
      if (m[0].length === 0) re.lastIndex++;
    }
    if (start + WINDOW >= text.length) break;
  }
  return false;
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  let payload;
  try { payload = JSON.parse(input); } catch { return; }
  const texts = [];
  collect(payload && payload.tool_response, texts, 0);
  if (texts.length === 0) return;

  const names = [];
  for (const [name, source, flags] of PATTERNS) {
    const re = new RegExp(source, flags + 'g');
    if (!names.includes(name) && texts.some(t => matches(re, t))) names.push(name);
  }
  if (names.length === 0) return;

  const matched = (names.length === 1 ? 'a credential pattern' : names.length + ' credential patterns') +
    ' (' + names.join(', ') + ')';
  process.stdout.write(JSON.stringify({
    systemMessage: 'Secretless: the output of this command matched ' + matched + '. ' +
      'The matched text is now in the conversation and the session transcript. This check runs after the ' +
      'command, so it warns but cannot keep the value out. If it is a live credential, rotate it; ' +
      'npx secretless-ai clean redacts saved transcripts.',
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext: 'Secretless: the output of the command that just ran matched ' + matched + '. ' +
        'Treat the matched text as an exposed credential. Do not repeat it, copy it into files or commands, or use it. ' +
        'Tell the user which command printed it so they can rotate it. To read configuration ' +
        'without credentials, select named non-secret fields (--query, jq) instead of printing whole objects.',
    },
  }) + '\\n');
});
`;
}

function quickScan(projectDir: string): number {
  let count = 0;
  // Honor `.secretlessignore` + defaults so the count rendered after
  // `init` matches what `secretless-ai scan` would report.
  let ignore: ReturnType<typeof loadSecretlessIgnore> | null = null;
  try {
    ignore = loadSecretlessIgnore(projectDir);
  } catch {
    // Best-effort — fall through.
  }
  for (const configFile of CONFIG_FILES) {
    if (ignore && ignore.matches(configFile)) continue;
    const fullPath = path.join(projectDir, configFile);
    if (!fs.existsSync(fullPath)) continue;

    try {
      const stat = fs.statSync(fullPath);
      if (stat.size > 10 * 1024 * 1024) continue; // Skip files > 10MB

      const content = fs.readFileSync(fullPath, 'utf-8');
      for (const line of content.split('\n')) {
        if (line.length > 4096) continue; // ReDoS protection
        for (const pattern of CREDENTIAL_PATTERNS) {
          if (pattern.regex.test(line)) {
            count++;
            break; // One finding per line
          }
        }
      }
    } catch {
      // Skip unreadable files
    }
  }
  return count;
}

/**
 * Result of reading a settings file we intend to merge into and write back.
 *
 * The distinction is load-bearing. The old `readJsonFile` collapsed "absent"
 * and "present but unreadable" into `null`, the caller turned that into `{}`,
 * and the write-back then replaced the user's file with a Secretless-only
 * document — every user key gone, no backup, while `init` printed
 * "added 96 deny patterns" (#122).
 *
 * `unusable` therefore means: there is a file here, it holds bytes we did not
 * author, and we cannot merge into it. The only safe action is to leave it
 * alone and say so.
 */
/**
 * Why a settings file could not be merged into. The three kinds need three
 * different remediations, and collapsing them produced a dead end: a file whose
 * top level is `null`, an array or a string parses as perfectly valid JSON, so
 * the `JSON.parse` verify command printed for all of them exits 0 and tells the
 * user the file is fine, under advice to remove comments it does not contain.
 *
 * Carried as a discriminator rather than recovered from `reason` at the point of
 * display: the caller would be re-deriving the kind by matching on prose it does
 * not own, and a rule per spelling never converges.
 */
export type SettingsUnusableKind = 'unreadable' | 'parse-error' | 'not-an-object';

type SettingsRead =
  | { status: 'absent' }
  | { status: 'ok'; data: any }
  | { status: 'unusable'; kind: SettingsUnusableKind; reason: string };

function describeJsonTopLevel(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  return `a ${typeof value}`;
}

/**
 * Read a settings file for an additive merge.
 *
 * A file that is empty or entirely whitespace is reported as `absent`: it
 * provably carries no user content, so writing a fresh document over it loses
 * nothing. Anything else that does not parse as a JSON **object** is
 * `unusable` — including a valid-JSON `null`, array, string or number, each of
 * which reached the destructive path before this change:
 *
 *   - `null`   -> `null || {}` -> full overwrite.
 *   - array    -> properties assigned to an array are dropped by
 *                 `JSON.stringify`, so `init` wrote the array back untouched
 *                 while reporting 96 deny patterns added. Nothing was
 *                 destroyed and nothing was configured — a fail-open with a
 *                 success message.
 *   - string   -> `Cannot create property 'hooks' on string` escaped to the
 *                 user as a raw TypeError with no file named and no fix.
 */
function readSettingsFile(filePath: string): SettingsRead {
  if (!fs.existsSync(filePath)) return { status: 'absent' };

  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    return { status: 'unusable', kind: 'unreadable', reason: `could not be read (${(err as Error).message})` };
  }

  if (raw.trim() === '') return { status: 'absent' };

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { status: 'unusable', kind: 'parse-error', reason: (err as Error).message };
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      status: 'unusable',
      kind: 'not-an-object',
      reason: `its top level is ${describeJsonTopLevel(parsed)}, but Claude Code settings must be a JSON object`,
    };
  }

  return { status: 'ok', data: parsed };
}

function writeJsonFile(filePath: string, data: any): void {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}
