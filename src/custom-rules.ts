/**
 * Custom deny rules — user-defined patterns for organization-specific secrets.
 *
 * Reads .secretless-rules.yaml and translates glob patterns into
 * Claude Code deny rules and shell hook regex patterns.
 */

import * as fs from 'fs';
import * as path from 'path';
import { nearestMatch } from './near-miss';

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

/** The top-level section keys this build reads. Everything else is reported, never bound. */
export const KNOWN_RULES_KEYS: readonly string[] = ['env', 'files', 'bash'];

/**
 * A non-empty line of the rules file the parser did not read. Every issue means
 * a line the operator wrote that produced no deny rule — the file "loaded"
 * while restricting less than it says, which is exactly the failure the status
 * value below exists to make visible.
 */
export interface RulesFileIssue {
  /** 1-based line number in the rules file. */
  line: number;
  /** The offending line, trimmed. */
  text: string;
  /** What the parser could not do with the line, and what to write instead. */
  message: string;
}

export interface RulesParseResult {
  rules: CustomRules;
  /** Non-empty, non-comment lines that were not read. Empty when every line was understood. */
  issues: RulesFileIssue[];
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
 *
 * Every non-empty, non-comment line the parser does not read comes back as an
 * issue. An unknown key is reported with a nearest-match hint but never
 * auto-corrected, and a pattern is never bound to a section the operator did
 * not put it under — the same rule the policy envelope check enforces
 * (`KNOWN_ENVELOPE_KEYS` in broker/policy.ts).
 */
export function parseRulesYamlDetailed(content: string): RulesParseResult {
  const result: CustomRules = { env: [], files: [], bash: [] };
  const issues: RulesFileIssue[] = [];
  let currentKey: keyof CustomRules | null = null;
  // The unknown key whose section is open, so dropped patterns under it can
  // name the key that killed them rather than reporting context-free.
  let currentUnknownKey: string | null = null;

  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const line = lines[i].trimEnd();

    // Skip empty lines and comment-only lines
    if (!line.trim() || line.trim().startsWith('#')) continue;

    // Top-level key (e.g., "env:", "files:", "bash:", or unknown like "custom_section:")
    const keyMatch = line.match(/^([a-zA-Z0-9_-]+):\s*$/);
    if (keyMatch) {
      const key = keyMatch[1] as string;
      if (key === 'env' || key === 'files' || key === 'bash') {
        currentKey = key;
        currentUnknownKey = null;
      } else {
        currentKey = null;
        currentUnknownKey = key;
        const near = nearestMatch(key, KNOWN_RULES_KEYS);
        issues.push({
          line: lineNo,
          text: line.trim(),
          message:
            `Unknown top-level key "${key}"${near ? ` (did you mean "${near}"?)` : ''}. ` +
            `A rules file may carry: ${KNOWN_RULES_KEYS.join(', ')}. Patterns under a key this ` +
            `build does not read are never loaded, and nothing downstream can tell that from a ` +
            `file that declared no such patterns.`,
        });
      }
      continue;
    }

    // List item (e.g., "  - ACME_*" or '  - "*.acme-credentials"')
    const itemMatch = line.match(/^\s+-\s+(.+)$/);
    if (itemMatch) {
      if (currentKey) {
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
      } else {
        issues.push({
          line: lineNo,
          text: line.trim(),
          message: currentUnknownKey
            ? KNOWN_RULES_KEYS.includes(currentUnknownKey)
              ? `Pattern not loaded: the "${currentUnknownKey}:" line above it was not read, so the section never opened.`
              : `Pattern not loaded: it sits under "${currentUnknownKey}", which this build does not read.`
            : `Pattern not loaded: it does not sit under any recognised section (${KNOWN_RULES_KEYS.join(', ')}).`,
        });
      }
      continue;
    }

    // Neither a section line nor a list item. A key with content on the same
    // line closes any open section: binding the items that follow to the
    // PREVIOUS section would attach patterns to a section the operator did not
    // put them under, and an env pattern misread as a file pattern (or vice
    // versa) generates the wrong deny rules entirely.
    const inlineKey = line.match(/^([a-zA-Z0-9_-]+):\s*(\S.*)$/);
    if (inlineKey) {
      const key = inlineKey[1] as string;
      const trailing = inlineKey[2];
      currentKey = null;
      currentUnknownKey = key;
      const known = KNOWN_RULES_KEYS.includes(key);
      const near = known ? undefined : nearestMatch(key, KNOWN_RULES_KEYS);
      issues.push({
        line: lineNo,
        text: line.trim(),
        message: trailing.startsWith('#')
          ? `A comment on the same line as "${key}:" is not supported by this parser, so the ` +
            `section never opens and the patterns beneath it are not read. Put the comment on ` +
            `its own line.`
          : `Content on the same line as "${key}:" is not read (this parser does not support ` +
            `flow syntax or inline values)` +
            `${known ? '' : `, and "${key}" is not a section this build reads` +
              `${near ? ` (did you mean "${near}"?)` : ''}`}. ` +
            `Put each pattern on its own indented "- pattern" line below the key.`,
      });
      continue;
    }

    issues.push({
      line: lineNo,
      text: line.trim(),
      message:
        `Unrecognised line: not a "key:" section line or an indented "- pattern" item, ` +
        `so it was not read.`,
    });
  }

  return { rules: result, issues };
}

/**
 * Rules-only form of `parseRulesYamlDetailed`, discarding the issue list.
 * Callers that report to an operator must use the detailed form — this one
 * cannot distinguish a file that parsed clean from one that silently lost
 * patterns.
 */
export function parseRulesYaml(content: string): CustomRules {
  return parseRulesYamlDetailed(content).rules;
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

  // Trailing newline is REQUIRED. The caller interpolates this directly ahead of
  // `  exit 0`, so without it the last block's `fi` and that `exit 0` collide on
  // one line (`  fi  exit 0`) and the generated hook is not valid bash. The hook
  // then exits 2 on EVERY tool call, for every tool, in any project that defines
  // `env:` or `bash:` rules. It fails closed, but a guard that blocks `ls -la`
  // gets uninstalled. `files:`-only rules produce an empty string here and so
  // never hit it, which is why this survived: the existing `bash -n` coverage
  // only exercised a `files:` rule.
  return blocks.length > 0 ? blocks.join('\n') + '\n' : '';
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
  /**
   * 'missing' = no file, 'empty' = file exists but no active rules, 'loaded' =
   * has rules and every line was read. 'unrecognised-content' = the file has
   * lines the parser did not read; `rules` still carries what WAS read (null
   * when nothing was). It takes precedence over 'empty' and 'loaded' because
   * both would report the file as fully honoured when part of what the
   * operator wrote produced no deny rules.
   */
  status: 'missing' | 'empty' | 'loaded' | 'unrecognised-content';
  /** The unread lines. Present exactly when status is 'unrecognised-content'. */
  issues?: RulesFileIssue[];
}

export function loadCustomRules(dir: string): CustomRules | null {
  return loadCustomRulesDetailed(dir).rules;
}

export function loadCustomRulesDetailed(dir: string): LoadResult {
  const rulesPath = path.join(dir, RULES_FILENAME);
  if (!fs.existsSync(rulesPath)) return { rules: null, status: 'missing' };

  const content = fs.readFileSync(rulesPath, 'utf-8');
  const { rules, issues } = parseRulesYamlDetailed(content);

  // Validate all patterns are safe
  const invalid = validateRules(rules);
  if (invalid.length > 0) {
    throw new Error(
      `Invalid patterns in ${RULES_FILENAME} (only alphanumeric, *, ., -, _, / allowed):\n` +
      invalid.map((p) => `  ${p}`).join('\n'),
    );
  }

  const empty = rules.env.length === 0 && rules.files.length === 0 && rules.bash.length === 0;

  if (issues.length > 0) {
    return { rules: empty ? null : rules, status: 'unrecognised-content', issues };
  }

  // Return empty status if all sections are empty
  if (empty) {
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
