/**
 * Custom deny rules — user-defined patterns for organization-specific secrets.
 *
 * Reads .secretless-rules.yaml and translates glob patterns into
 * Claude Code deny rules and shell hook regex patterns.
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CustomRules {
  /** Env var name patterns to block (glob, e.g. ACME_*) */
  env: string[];
  /** File patterns to block (glob, e.g. *.acme-credentials) */
  files: string[];
  /** Bash command patterns to block (glob, e.g. acme-vault*get*) */
  bash: string[];
}

export const RULES_FILENAME = '.secretless-rules.yaml';

// Only allow safe characters in patterns to prevent shell injection
const SAFE_PATTERN = /^[a-zA-Z0-9_*.\-/\[\]{}?]+$/;

// ---------------------------------------------------------------------------
// Minimal YAML parser (flat key: list-of-strings only)
// ---------------------------------------------------------------------------

/**
 * Parse a minimal YAML subset: top-level keys mapping to lists of strings.
 * Supports: comments (#), quoted strings, blank lines.
 * Does NOT support: anchors, multiline strings, nested objects, flow syntax.
 */
export function parseRulesYaml(content: string): CustomRules {
  const result: CustomRules = { env: [], files: [], bash: [] };
  let currentKey: keyof CustomRules | null = null;

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trimEnd();

    // Skip empty lines and comment-only lines
    if (!line.trim() || line.trim().startsWith('#')) continue;

    // Top-level key (e.g., "env:", "files:", "bash:", or unknown like "custom_section:")
    const keyMatch = line.match(/^([a-zA-Z0-9_-]+):\s*$/);
    if (keyMatch) {
      const key = keyMatch[1] as string;
      if (key === 'env' || key === 'files' || key === 'bash') {
        currentKey = key;
      } else {
        currentKey = null; // Unknown key — skip its items
      }
      continue;
    }

    // List item (e.g., "  - ACME_*" or '  - "*.acme-credentials"')
    const itemMatch = line.match(/^\s+-\s+(.+)$/);
    if (itemMatch && currentKey) {
      let value = itemMatch[1].trim();

      // Strip inline comments
      const commentIdx = value.indexOf(' #');
      if (commentIdx >= 0) {
        value = value.slice(0, commentIdx).trim();
      }

      // Strip surrounding quotes
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }

      if (value) {
        result[currentKey].push(value);
      }
      continue;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Pattern validation
// ---------------------------------------------------------------------------

/**
 * Validate a pattern contains only safe characters.
 * Rejects patterns that could cause shell injection.
 */
export function validatePattern(pattern: string): boolean {
  return SAFE_PATTERN.test(pattern);
}

/**
 * Validate all patterns in a CustomRules object.
 * Returns list of invalid patterns with their section.
 */
export function validateRules(rules: CustomRules): string[] {
  const invalid: string[] = [];
  for (const section of ['env', 'files', 'bash'] as const) {
    for (const p of rules[section]) {
      if (!validatePattern(p)) {
        invalid.push(`${section}: ${p}`);
      }
    }
  }
  return invalid;
}

// ---------------------------------------------------------------------------
// Glob to deny rule translation
// ---------------------------------------------------------------------------

/**
 * Convert a glob pattern to shell regex for use in hook script grep -qiE.
 * * -> .* and . -> \\.
 */
export function globToShellRegex(glob: string): string {
  return glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // Escape regex metacharacters except *
    .replace(/\*/g, '.*');                    // Convert glob * to regex .*
}

/**
 * Generate settings.json deny rules from a single env var name pattern.
 * Each env pattern generates rules for echo, printenv, python3, node, and eval.
 */
export function envPatternToDenyRules(pattern: string): string[] {
  return [
    `Bash(echo $*${pattern})`,
    `Bash(printenv *${pattern})`,
    `Bash(python3 -c*os.environ*${pattern})`,
    `Bash(node -e*process.env*${pattern})`,
    `Bash(eval echo*${pattern})`,
  ];
}

/**
 * Generate settings.json deny rules from a single file pattern.
 * Each file pattern generates Read, Grep, and Bash command rules.
 */
export function filePatternToDenyRules(pattern: string): string[] {
  const cmds = ['cat', 'grep *', 'awk *', 'sed *', 'strings', 'xxd'];
  const rules: string[] = [
    `Read(${pattern})`,
    `Grep(${pattern})`,
  ];
  for (const cmd of cmds) {
    rules.push(`Bash(${cmd} ${pattern})`);
  }
  return rules;
}

/**
 * Convert all custom rules into settings.json deny rule strings.
 */
export function customRulesToDenyRules(rules: CustomRules): string[] {
  const denyRules: string[] = [];

  for (const pattern of rules.env) {
    denyRules.push(...envPatternToDenyRules(pattern));
  }

  for (const pattern of rules.files) {
    denyRules.push(...filePatternToDenyRules(pattern));
  }

  for (const pattern of rules.bash) {
    denyRules.push(`Bash(${pattern})`);
  }

  return denyRules;
}

// ---------------------------------------------------------------------------
// Hook script generation
// ---------------------------------------------------------------------------

/**
 * Generate shell script blocks for custom rules to append to the hook script.
 * Returns bash if-blocks that integrate with the existing hook script structure.
 */
export function customRulesToHookBlocks(rules: CustomRules): string {
  const blocks: string[] = [];

  // Custom env var patterns — combine into single alternation regex
  if (rules.env.length > 0) {
    const envAlternation = rules.env.map(globToShellRegex).join('|');
    blocks.push(
      `  # Custom env var patterns (from .secretless-rules.yaml)\n` +
      `  if echo "$COMMAND" | grep -qiE '(echo|printenv)\\s+.*\\$(${envAlternation})'; then\n` +
      `    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked custom env var pattern"}}'\n` +
      `    exit 0\n` +
      `  fi\n` +
      `  if echo "$COMMAND" | grep -qiE '(python3?|node)\\s+-(c|e).*(os\\.environ|process\\.env).*(${envAlternation})'; then\n` +
      `    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked custom env var extraction"}}'\n` +
      `    exit 0\n` +
      `  fi`,
    );
  }

  // Custom bash command patterns
  if (rules.bash.length > 0) {
    const bashAlternation = rules.bash.map(globToShellRegex).join('|');
    blocks.push(
      `  # Custom bash command patterns (from .secretless-rules.yaml)\n` +
      `  if echo "$COMMAND" | grep -qiE '(${bashAlternation})'; then\n` +
      `    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Secretless: blocked custom bash pattern"}}'\n` +
      `    exit 0\n` +
      `  fi`,
    );
  }

  return blocks.join('\n');
}

/**
 * Generate additional file patterns for the hook script's path-based blocking.
 * Returns patterns to add to the filePatterns array in the hook script.
 */
export function customRulesToFilePatterns(rules: CustomRules): string[] {
  return rules.files.map((pattern) => {
    // Convert glob to shell-compatible lowercase match pattern
    return globToShellRegex(pattern);
  });
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

/**
 * Load custom rules from .secretless-rules.yaml in a directory.
 * Returns null if no rules file exists.
 * Throws on invalid patterns (shell injection prevention).
 */
/**
 * Result of loading custom rules, distinguishing "no file" from "file is empty".
 */
export interface LoadResult {
  rules: CustomRules | null;
  /** 'missing' = no file, 'empty' = file exists but no active rules, 'loaded' = has rules */
  status: 'missing' | 'empty' | 'loaded';
}

export function loadCustomRules(dir: string): CustomRules | null {
  return loadCustomRulesDetailed(dir).rules;
}

export function loadCustomRulesDetailed(dir: string): LoadResult {
  const rulesPath = path.join(dir, RULES_FILENAME);
  if (!fs.existsSync(rulesPath)) return { rules: null, status: 'missing' };

  const content = fs.readFileSync(rulesPath, 'utf-8');
  const rules = parseRulesYaml(content);

  // Validate all patterns are safe
  const invalid = validateRules(rules);
  if (invalid.length > 0) {
    throw new Error(
      `Invalid patterns in ${RULES_FILENAME} (only alphanumeric, *, ., -, _, / allowed):\n` +
      invalid.map((p) => `  ${p}`).join('\n'),
    );
  }

  // Return empty status if all sections are empty
  if (rules.env.length === 0 && rules.files.length === 0 && rules.bash.length === 0) {
    return { rules: null, status: 'empty' };
  }

  return { rules, status: 'loaded' };
}

/**
 * Merge custom deny rules with built-in rules, deduplicating.
 */
export function mergeRules(builtIn: string[], custom: string[]): string[] {
  const seen = new Set(builtIn);
  const merged = [...builtIn];
  for (const rule of custom) {
    if (!seen.has(rule)) {
      seen.add(rule);
      merged.push(rule);
    }
  }
  return merged;
}

/**
 * Generate a starter .secretless-rules.yaml template.
 */
export function generateTemplate(): string {
  return `# Custom deny rules for your organization
# Safe to commit -- contains patterns, not secrets
#
# Patterns use glob syntax: * matches any characters
# Run: npx secretless-ai init  (to apply changes)

# Environment variable name patterns to block
# Blocks: echo, printenv, python3 os.environ, node process.env
env:
  # - ACME_*
  # - INTERNAL_*
  # - CORP_DB_*

# File patterns to block AI from reading
# Blocks: Read, Grep, cat, grep, awk, sed, strings, xxd
files:
  # - "*.acme-credentials"
  # - ".internal-config"
  # - "corp-secrets/"

# Bash command patterns to block (advanced)
bash:
  # - "curl*internal.corp.com*"
  # - "corp-vault*get*"
`;
}
