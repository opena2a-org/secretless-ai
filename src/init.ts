/**
 * Initialize Secretless for a project.
 * Auto-detects AI tools and installs appropriate protections.
 */

import * as fs from 'fs';
import * as path from 'path';
import { detectAITools, toolDisplayName, type AITool } from './detect';
import { SECRET_FILE_PATTERNS, CREDENTIAL_PATTERNS, CONFIG_FILES } from './patterns';
import { loadCustomRulesDetailed, customRulesToDenyRules, customRulesToHookBlocks, customRulesToFilePatterns, mergeRules } from './custom-rules';
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
    result.toolsConfigured.push(tool.tool);
  }

  return result;
}

// ============================================================================
// Claude Code Configuration
// ============================================================================

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
    addSecretlessInstructions(path.join(projectDir, 'CLAUDE.md'), 'claude-code', result);
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

  // Add Stop hook for transcript cleaning after conversations
  if (!settings.hooks.Stop) settings.hooks.Stop = [];

  const hasTranscriptHook = settings.hooks.Stop.some(
    (h: any) => h.hooks?.some((hh: any) => hh.command?.includes('secretless-ai'))
  );

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
    'Grep(credentials*)',
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

  // 3. Add Secretless instructions to CLAUDE.md
  const claudeMdPath = path.join(projectDir, 'CLAUDE.md');
  addSecretlessInstructions(claudeMdPath, 'claude-code', result);
}

// ============================================================================
// Cursor Configuration
// ============================================================================

function configureCursor(projectDir: string, result: InitResult): void {
  const rulesPath = path.join(projectDir, '.cursorrules');
  addSecretlessInstructions(rulesPath, 'cursor', result);
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

function configureWindsurf(projectDir: string, result: InitResult): void {
  const rulesPath = path.join(projectDir, '.windsurfrules');
  addSecretlessInstructions(rulesPath, 'windsurf', result);
}

// ============================================================================
// Cline Configuration
// ============================================================================

function configureCline(projectDir: string, result: InitResult): void {
  const rulesPath = path.join(projectDir, '.clinerules');
  addSecretlessInstructions(rulesPath, 'cline', result);
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

function buildSecretlessInstructions(): string {
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

**If you find a hardcoded credential:**
1. Replace it with an environment variable reference
2. Add the variable name to \`.env.example\`
3. Warn the user to rotate the exposed credential

Verify setup: \`npx secretless-ai verify\`

## Transcript Protection
- NEVER ask users to paste API keys, tokens, or passwords into the conversation
- If a user pastes a credential, immediately warn them and suggest using environment variables
- Credentials in this conversation are automatically redacted by Secretless AI
`;
}

function addSecretlessInstructions(filePath: string, tool: string, result: InitResult): void {
  const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf-8') : '';

  if (existing.includes(SECRETLESS_MARKER)) {
    return; // Already configured
  }

  fs.writeFileSync(filePath, existing + buildSecretlessInstructions());
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
  const pathFragments = [
    'credentials', '.aws/credentials', '.ssh/', '.docker/config.json',
    'secrets/', '.opena2a/secretless-ai/', '.secretless-ai/',
  ];

  // Merge custom file patterns from .secretless-rules.yaml into the right bucket.
  if (customRules?.files) {
    for (const raw of customRules.files) {
      const p = raw.trim();
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
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked command that reads secret files"}}'
    exit 0
  fi
  # Block python/node one-liners that read secret files
  if echo "$COMMAND" | grep -qiE '(python3?|node)\\s+-(c|e).*${SECRET_FILE_EXT}'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked script command that reads secret files"}}'
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
  # naming every secret variable at once. \`env\` is deliberately NOT matched here:
  # it is overwhelmingly used as a prefix (\`env -u VAR cmd\`), and the full-dump
  # form is covered by the deny rules.
  if echo "$COMMAND" | grep -qiE '(^|[;&|]\\s*)printenv\\s*(-0\\s*)?$'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked full environment dump via printenv"}}'
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
  # Block direct access to secretless data directory
  if echo "$COMMAND" | grep -qiE '(cat|head|tail|less|more|grep|awk|sed|strings|xxd|ls)\\s+.*\\.secretless-ai'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked access to secretless data directory"}}'
    exit 0
  fi
${customRules ? customRulesToHookBlocks(customRules) : ''}  exit 0
fi

# Skip if no file path found
if [ -z "$FILE_PATH_CANDIDATES" ]; then
  exit 0
fi

# Resolve a candidate to its canonical, EXISTING target, or print nothing.
#
# This is what closes the symlink hole: the template-suffix exemption below trusts
# the BASENAME, so a symlink NAMED like a template (foo.env.example) but pointing
# at a real secret file would otherwise be waved through. Resolving FIRST means the
# block rules re-run against the real target's name, not the link's name.
#
# The -e flag is load-bearing. WITHOUT it, realpath/readlink print a broken
# symlink's dangling target and exit 0, silently un-fail-closing the broken-link
# case; WITH it, a link that does not resolve to an existing file prints nothing
# and the caller denies. Portability mirrors the python3-with-grep fallback used
# above: prefer realpath, fall back to readlink for hosts that lack it.
resolve_real_target() {
  if command -v realpath >/dev/null 2>&1; then
    realpath -e -- "$1" 2>/dev/null || true
  elif command -v readlink >/dev/null 2>&1; then
    readlink -e -- "$1" 2>/dev/null || true
  fi
}

# Check EVERY candidate path. A payload carrying both a benign top-level path
# and a secret one nested deeper must block on the secret one, so the loop only
# skips a template candidate rather than exiting on it.
while IFS= read -r CANDIDATE; do
  [ -z "$CANDIDATE" ] && continue

  # Resolve symlinks to the REAL target BEFORE any allow/deny decision, so a
  # template-suffixed NAME cannot mask a secret TARGET (the fail-open this fixes).
  RESOLVED=$(resolve_real_target "$CANDIDATE")
  if [ -z "$RESOLVED" ]; then
    if [ -L "$CANDIDATE" ]; then
      # A symlink that resolves to nothing (broken link, resolve error, empty
      # result) is FAIL-CLOSED: deny rather than trust its template-suffixed name.
      echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked access to unresolvable symlink (possible secret target)"}}'
      exit 0
    fi
    # Not a symlink and not resolvable (e.g. a not-yet-created template file being
    # written): judge it by the path as given, preserving prior behaviour.
    RESOLVED="$CANDIDATE"
  fi

  # Normalize the RESOLVED path for matching (case-insensitive: server.KEY and prod.ENV must match too)
  BASENAME=$(basename "$RESOLVED")
  LOWER_BASENAME=$(echo "$BASENAME" | tr '[:upper:]' '[:lower:]')
  LOWER_PATH=$(echo "$RESOLVED" | tr '[:upper:]' '[:lower:]')

  # Allow committed template/example files (.env.example, config.sample, etc.) — these
  # hold placeholders, not real secrets, and are meant to be read/edited/committed.
  # Checked on the RESOLVED name (a symlink to a real secret no longer qualifies) and
  # BEFORE any block logic so it wins over the .env extension/dotfile rules below.
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
