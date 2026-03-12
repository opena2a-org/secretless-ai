/**
 * Initialize Secretless for a project.
 * Auto-detects AI tools and installs appropriate protections.
 */

import * as fs from 'fs';
import * as path from 'path';
import { detectAITools, toolDisplayName, type AITool } from './detect';
import { SECRET_FILE_PATTERNS, CREDENTIAL_PATTERNS, CONFIG_FILES } from './patterns';

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
}

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

  // Configure each detected tool
  for (const tool of detected) {
    switch (tool.tool) {
      case 'claude-code':
        configureClaudeCode(projectDir, result);
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
    result.toolsConfigured.push(tool.tool);
  }

  return result;
}

// ============================================================================
// Claude Code Configuration
// ============================================================================

function configureClaudeCode(projectDir: string, result: InitResult): void {
  const claudeDir = path.join(projectDir, '.claude');
  const hooksDir = path.join(claudeDir, 'hooks');

  // Ensure directories exist
  fs.mkdirSync(hooksDir, { recursive: true });

  // 1. Install PreToolUse hook
  const hookPath = path.join(hooksDir, 'secretless-guard.sh');
  if (!fs.existsSync(hookPath)) {
    fs.writeFileSync(hookPath, generateClaudeHookScript(), { mode: 0o755 });
    result.filesCreated.push('.claude/hooks/secretless-guard.sh');
  }

  // 2. Update settings.json with hook config and deny rules
  const settingsPath = path.join(claudeDir, 'settings.json');
  const settings = readJsonFile(settingsPath) || {};

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
    // Block Read access to secret files
    'Read(.env*)',
    'Read(*.key)',
    'Read(*.pem)',
    'Read(*.p12)',
    'Read(*.pfx)',
    'Read(*.tfstate)',
    'Read(*.tfvars)',
    'Read(.aws/credentials)',
    'Read(.ssh/*)',
    // Block Read access to secretless data directory
    'Read(~/.secretless-ai/*)',
    // Block Grep from searching secret files (Issue #1)
    'Grep(*.env*)',
    'Grep(*.key)',
    'Grep(*.pem)',
    'Grep(*.p12)',
    'Grep(*.pfx)',
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
    // Block echoing/printing secret env vars (Issue #4 - expanded)
    'Bash(echo $*SECRET*)',
    'Bash(echo $*PASSWORD*)',
    'Bash(echo $*API_KEY*)',
    'Bash(echo $*TOKEN*)',
    'Bash(echo $*VAULT*)',
    'Bash(echo $*CREDENTIAL*)',
    'Bash(printenv *TOKEN*)',
    'Bash(printenv *SECRET*)',
    'Bash(printenv *KEY*)',
    // Block secretless-ai secret extraction (Issue #3)
    'Bash(*secretless-ai secret get*--force*)',
    // Block secretless-ai run with env dumping (Issue #6)
    'Bash(*secretless-ai run*-- env*)',
    'Bash(*secretless-ai run*-- printenv*)',
    // Block access to secretless data directory (Issue #5)
    'Bash(cat *secretless-ai*)',
    'Bash(*secretless-ai/store*)',
    'Bash(*secretless-ai/mcp-backups*)',
  ];

  for (const rule of denyRules) {
    if (!settings.permissions.deny.includes(rule)) {
      settings.permissions.deny.push(rule);
    }
  }

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
- \`.env\`, \`.env.*\` — environment variable files
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

function generateClaudeHookScript(): string {
  // Build pattern list for the shell script
  const filePatterns = [
    '.env', '.env.local', '.env.development', '.env.production', '.env.staging',
    '.key', '.pem', '.p12', '.pfx', '.crt',
    'credentials', '.aws/credentials', '.ssh/',
    '.docker/config.json', '.git-credentials',
    '.npmrc', '.pypirc',
    '.tfstate', '.tfvars',
    'secrets/', '.opena2a/secretless-ai/',
    '.secretless-ai/',
  ];

  return `#!/bin/bash
# Secretless Guard — PreToolUse hook for Claude Code
# Blocks file access to secrets before they enter AI context.
# Managed by secretless-ai. Do not edit manually.

set -euo pipefail

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | grep -o '"tool_name":"[^"]*"' | head -1 | cut -d'"' -f4)

# Extract file path from tool input (handles Read, Grep, Glob, Edit, Write)
FILE_PATH=$(echo "$INPUT" | grep -o '"file_path":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$FILE_PATH" ]; then
  FILE_PATH=$(echo "$INPUT" | grep -o '"path":"[^"]*"' | head -1 | cut -d'"' -f4)
fi

# For Bash tool, check the command for secret access patterns
if [ "$TOOL_NAME" = "Bash" ]; then
  COMMAND=$(echo "$INPUT" | grep -o '"command":"[^"]*"' | head -1 | cut -d'"' -f4)
  # Block commands that dump secret files (expanded to cover grep, awk, sed, strings, xxd)
  if echo "$COMMAND" | grep -qiE '(cat|head|tail|less|more|type|grep|awk|sed|strings|xxd)\\s+.*\\.(env|key|pem|p12|pfx)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked command that reads secret files"}}'
    exit 0
  fi
  # Block python/node one-liners that read secret files
  if echo "$COMMAND" | grep -qiE '(python3?|node)\\s+-(c|e).*\\.(env|key|pem|p12|pfx)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked script command that reads secret files"}}'
    exit 0
  fi
  # Block commands that echo secret env vars (expanded with TOKEN, VAULT, CREDENTIAL)
  if echo "$COMMAND" | grep -qiE '(echo|printenv)\\s+.*\\$(SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY|VAULT|CREDENTIAL)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked command that exposes secret environment variables"}}'
    exit 0
  fi
  # Block secretless-ai secret extraction with --force
  if echo "$COMMAND" | grep -qiE 'secretless-ai\\s+secret\\s+get.*--force'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked forced secret extraction"}}'
    exit 0
  fi
  # Block secretless-ai run with env/printenv to dump injected secrets
  if echo "$COMMAND" | grep -qiE 'secretless-ai\\s+run.*--\\s*(env|printenv)'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked secret dump via secretless-ai run"}}'
    exit 0
  fi
  # Block direct access to secretless data directory
  if echo "$COMMAND" | grep -qiE '(cat|head|tail|less|more|grep|awk|sed|strings|xxd|ls)\\s+.*\\.secretless-ai'; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked access to secretless data directory"}}'
    exit 0
  fi
  exit 0
fi

# Skip if no file path found
if [ -z "$FILE_PATH" ]; then
  exit 0
fi

# Normalize path for matching
BASENAME=$(basename "$FILE_PATH")
LOWER_PATH=$(echo "$FILE_PATH" | tr '[:upper:]' '[:lower:]')

# Block patterns
${filePatterns.map(p => {
    if (p.startsWith('.') && !p.includes('/')) {
      // Extension or dotfile match
      if (p.includes('*')) {
        return `# Match ${p}\nif echo "$BASENAME" | grep -qE '\\${p.replace('*', '.*')}$'; then BLOCKED=1; REASON="${p}"; fi`;
      }
      return `# Match ${p}\nif [ "$BASENAME" = "${p}" ] || echo "$BASENAME" | grep -qE '^\\${p}'; then BLOCKED=1; REASON="${p}"; fi`;
    }
    // Path fragment match
    return `# Match ${p}\nif echo "$LOWER_PATH" | grep -qi '${p}'; then BLOCKED=1; REASON="${p}"; fi`;
  }).join('\n')}

if [ "\${BLOCKED:-0}" = "1" ]; then
  echo "{\\"hookSpecificOutput\\":{\\"hookEventName\\":\\"PreToolUse\\",\\"permissionDecision\\":\\"deny\\",\\"permissionDecisionReason\\":\\"Secretless: blocked access to secret file matching pattern '$REASON'\\"}}"
  exit 0
fi

exit 0
`;
}

function quickScan(projectDir: string): number {
  let count = 0;
  for (const configFile of CONFIG_FILES) {
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

function readJsonFile(filePath: string): any {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch {
    return null;
  }
}

function writeJsonFile(filePath: string, data: any): void {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}
