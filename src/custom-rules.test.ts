import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import {
  parseRulesYaml,
  parseRulesYamlDetailed,
  validatePattern,
  validateRules,
  globToShellRegex,
  envPatternToDenyRules,
  filePatternToDenyRules,
  customRulesToDenyRules,
  customRulesToHookBlocks,
  customRulesToFilePatterns,
  loadCustomRules,
  loadCustomRulesDetailed,
  mergeRules,
  generateTemplate,
  RULES_FILENAME,
} from './custom-rules';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-rules-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// YAML Parser
// ---------------------------------------------------------------------------

describe('parseRulesYaml', () => {
  it('parses all three sections', () => {
    const yaml = `
env:
  - ACME_*
  - INTERNAL_*
files:
  - "*.acme-credentials"
  - .corp-config
bash:
  - curl*internal.corp.com*
`;
    const result = parseRulesYaml(yaml);
    expect(result.env).toEqual(['ACME_*', 'INTERNAL_*']);
    expect(result.files).toEqual(['*.acme-credentials', '.corp-config']);
    expect(result.bash).toEqual(['curl*internal.corp.com*']);
  });

  it('handles empty file', () => {
    const result = parseRulesYaml('');
    expect(result).toEqual({ env: [], files: [], bash: [] });
  });

  it('handles comments and blank lines', () => {
    const yaml = `
# This is a comment
env:
  # Skip this line
  - MY_SECRET_*

  - OTHER_*  # inline comment
`;
    const result = parseRulesYaml(yaml);
    expect(result.env).toEqual(['MY_SECRET_*', 'OTHER_*']);
  });

  it('handles single-quoted strings', () => {
    const yaml = `
files:
  - '*.internal-config'
`;
    const result = parseRulesYaml(yaml);
    expect(result.files).toEqual(['*.internal-config']);
  });

  it('handles only some sections', () => {
    const yaml = `
env:
  - CORP_*
`;
    const result = parseRulesYaml(yaml);
    expect(result.env).toEqual(['CORP_*']);
    expect(result.files).toEqual([]);
    expect(result.bash).toEqual([]);
  });

  it('ignores unknown top-level keys', () => {
    const yaml = `
env:
  - FOO_*
unknown:
  - should-be-ignored
files:
  - "*.bar"
`;
    const result = parseRulesYaml(yaml);
    expect(result.env).toEqual(['FOO_*']);
    expect(result.files).toEqual(['*.bar']);
  });

  it('ignores unknown keys with underscores/hyphens/numbers', () => {
    const yaml = `
env:
  - FOO_*
bogus_section:
  - should-not-leak
custom-rules-v2:
  - also-ignored
section3:
  - nope
files:
  - "*.bar"
`;
    const result = parseRulesYaml(yaml);
    expect(result.env).toEqual(['FOO_*']);
    expect(result.files).toEqual(['*.bar']);
    expect(result.bash).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Pattern Validation
// ---------------------------------------------------------------------------

describe('validatePattern', () => {
  it('accepts valid patterns', () => {
    expect(validatePattern('ACME_*')).toBe(true);
    expect(validatePattern('*.pem')).toBe(true);
    expect(validatePattern('corp-secrets/')).toBe(true);
    expect(validatePattern('curl*internal.corp.com*')).toBe(true);
    expect(validatePattern('.env*')).toBe(true);
  });

  it('rejects patterns with shell metacharacters', () => {
    expect(validatePattern('$(whoami)')).toBe(false);
    expect(validatePattern('`rm -rf /`')).toBe(false);
    expect(validatePattern('; echo pwned')).toBe(false);
    expect(validatePattern('| cat /etc/passwd')).toBe(false);
    expect(validatePattern("'; DROP TABLE secrets;--")).toBe(false);
  });
});

describe('validateRules', () => {
  it('returns empty for valid rules', () => {
    const rules = { env: ['ACME_*'], files: ['*.pem'], bash: ['curl*corp*'] };
    expect(validateRules(rules)).toEqual([]);
  });

  it('returns invalid patterns with section', () => {
    const rules = { env: ['$(whoami)'], files: ['*.pem'], bash: [] };
    expect(validateRules(rules)).toEqual(['env: $(whoami)']);
  });
});

// ---------------------------------------------------------------------------
// Glob Translation
// ---------------------------------------------------------------------------

describe('globToShellRegex', () => {
  it('converts * to .*', () => {
    expect(globToShellRegex('ACME_*')).toBe('ACME_.*');
  });

  it('escapes dots', () => {
    expect(globToShellRegex('*.pem')).toBe('.*\\.pem');
  });

  it('escapes multiple special characters', () => {
    expect(globToShellRegex('file.name[0]')).toBe('file\\.name\\[0\\]');
  });

  it('handles patterns with no wildcards', () => {
    expect(globToShellRegex('exactmatch')).toBe('exactmatch');
  });
});

// ---------------------------------------------------------------------------
// Deny Rule Generation
// ---------------------------------------------------------------------------

describe('envPatternToDenyRules', () => {
  it('generates 5 rules per env pattern', () => {
    const rules = envPatternToDenyRules('ACME_*');
    expect(rules).toHaveLength(5);
    expect(rules).toContain('Bash(echo $*ACME_*)');
    expect(rules).toContain('Bash(printenv *ACME_*)');
    expect(rules).toContain('Bash(python3 -c*os.environ*ACME_*)');
    expect(rules).toContain('Bash(node -e*process.env*ACME_*)');
    expect(rules).toContain('Bash(eval echo*ACME_*)');
  });
});

describe('filePatternToDenyRules', () => {
  it('generates Read, Grep, and Bash rules', () => {
    const rules = filePatternToDenyRules('*.acme-credentials');
    expect(rules).toContain('Read(*.acme-credentials)');
    expect(rules).toContain('Grep(*.acme-credentials)');
    expect(rules).toContain('Bash(cat *.acme-credentials)');
    expect(rules).toContain('Bash(strings *.acme-credentials)');
    expect(rules.length).toBeGreaterThanOrEqual(8); // Read + Grep + 6 Bash cmds
  });
});

describe('customRulesToDenyRules', () => {
  it('combines all sections', () => {
    const rules = {
      env: ['ACME_*'],
      files: ['*.corp-secret'],
      bash: ['acme-vault*get*'],
    };
    const deny = customRulesToDenyRules(rules);
    // 5 env + 8 file + 1 bash
    expect(deny.length).toBe(14);
    expect(deny).toContain('Bash(echo $*ACME_*)');
    expect(deny).toContain('Read(*.corp-secret)');
    expect(deny).toContain('Bash(acme-vault*get*)');
  });

  it('handles empty rules', () => {
    expect(customRulesToDenyRules({ env: [], files: [], bash: [] })).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Hook Script Generation
// ---------------------------------------------------------------------------

describe('customRulesToHookBlocks', () => {
  it('generates env var hook blocks', () => {
    const rules = { env: ['ACME_*', 'INTERNAL_*'], files: [], bash: [] };
    const blocks = customRulesToHookBlocks(rules);
    expect(blocks).toContain('ACME_.*');
    expect(blocks).toContain('INTERNAL_.*');
    expect(blocks).toContain('grep -qiE');
    expect(blocks).toContain('.secretless-rules.yaml');
  });

  it('generates bash command hook blocks', () => {
    const rules = { env: [], files: [], bash: ['acme-vault*get*'] };
    const blocks = customRulesToHookBlocks(rules);
    expect(blocks).toContain('acme-vault.*get.*');
  });

  it('returns empty string for empty rules', () => {
    expect(customRulesToHookBlocks({ env: [], files: [], bash: [] })).toBe('');
  });
});

describe('customRulesToFilePatterns', () => {
  it('converts file globs to shell regex', () => {
    const rules = { env: [], files: ['*.acme-credentials', '.corp-config'], bash: [] };
    const patterns = customRulesToFilePatterns(rules);
    expect(patterns).toEqual(['.*\\.acme-credentials', '\\.corp-config']);
  });
});

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

describe('loadCustomRules', () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('returns null when no rules file exists', () => {
    expect(loadCustomRules(dir)).toBeNull();
  });

  it('loads and parses rules file', () => {
    fs.writeFileSync(path.join(dir, RULES_FILENAME), `
env:
  - CORP_*
files:
  - "*.corp-secret"
`);
    const rules = loadCustomRules(dir);
    expect(rules).not.toBeNull();
    expect(rules!.env).toEqual(['CORP_*']);
    expect(rules!.files).toEqual(['*.corp-secret']);
  });

  it('returns null for empty rules', () => {
    fs.writeFileSync(path.join(dir, RULES_FILENAME), `
# All commented out
env:
  # - NOTHING
`);
    expect(loadCustomRules(dir)).toBeNull();
  });

  it('returns empty status for empty rules via detailed', () => {
    fs.writeFileSync(path.join(dir, RULES_FILENAME), `
# All commented out
env:
  # - NOTHING
`);
    const result = loadCustomRulesDetailed(dir);
    expect(result.status).toBe('empty');
    expect(result.rules).toBeNull();
  });

  it('returns missing status when no file exists via detailed', () => {
    const result = loadCustomRulesDetailed(dir);
    expect(result.status).toBe('missing');
    expect(result.rules).toBeNull();
  });

  it('returns loaded status with rules via detailed', () => {
    fs.writeFileSync(path.join(dir, RULES_FILENAME), `
env:
  - CORP_*
`);
    const result = loadCustomRulesDetailed(dir);
    expect(result.status).toBe('loaded');
    expect(result.rules).not.toBeNull();
    expect(result.rules!.env).toEqual(['CORP_*']);
  });

  it('throws on invalid patterns', () => {
    fs.writeFileSync(path.join(dir, RULES_FILENAME), `
env:
  - "$(whoami)"
`);
    expect(() => loadCustomRules(dir)).toThrow('Invalid patterns');
  });
});

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

describe('mergeRules', () => {
  it('appends custom rules after built-in', () => {
    const builtIn = ['Read(.env*)', 'Read(*.key)'];
    const custom = ['Read(*.corp-secret)', 'Read(*.key)']; // *.key is a dupe
    const merged = mergeRules(builtIn, custom);
    expect(merged).toEqual(['Read(.env*)', 'Read(*.key)', 'Read(*.corp-secret)']);
  });

  it('handles empty custom rules', () => {
    const builtIn = ['Read(.env*)'];
    expect(mergeRules(builtIn, [])).toEqual(['Read(.env*)']);
  });
});

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

describe('generateTemplate', () => {
  it('generates valid YAML template', () => {
    const template = generateTemplate();
    expect(template).toContain('env:');
    expect(template).toContain('files:');
    expect(template).toContain('bash:');
    expect(template).toContain('secretless-ai init');
    // Template should parse without error (all items are commented out)
    const parsed = parseRulesYaml(template);
    expect(parsed.env).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Detailed parser — every unread line is an issue, never a silent drop
// ---------------------------------------------------------------------------

describe('parseRulesYamlDetailed', () => {
  it('reports an unknown top-level key with a nearest-match hint', () => {
    const { rules, issues } = parseRulesYamlDetailed(`
file:
  - "*.corp-secret"
`);
    expect(rules).toEqual({ env: [], files: [], bash: [] });
    const keyIssue = issues.find(i => i.message.includes('Unknown top-level key "file"'));
    expect(keyIssue).toBeDefined();
    expect(keyIssue!.message).toContain('did you mean "files"?');
    expect(keyIssue!.message).toContain('env, files, bash');
  });

  it('hints on a case variant of a known key', () => {
    const { issues } = parseRulesYamlDetailed('Files:\n  - "*.a"\n');
    expect(issues[0].message).toContain('Unknown top-level key "Files"');
    expect(issues[0].message).toContain('did you mean "files"?');
  });

  it('reports every pattern dropped under an unknown key, naming the key', () => {
    const { rules, issues } = parseRulesYamlDetailed(`
envs:
  - ACME_*
  - CORP_*
`);
    expect(rules.env).toEqual([]);
    const dropped = issues.filter(i => i.message.includes('sits under "envs"'));
    expect(dropped.map(d => d.text)).toEqual(['- ACME_*', '- CORP_*']);
    expect(dropped.map(d => d.line)).toEqual([3, 4]);
  });

  it('does not auto-correct: a hinted near-miss key still binds nothing', () => {
    const { rules } = parseRulesYamlDetailed('file:\n  - "*.corp-secret"\n');
    expect(rules.files).toEqual([]);
    expect(rules.env).toEqual([]);
    expect(rules.bash).toEqual([]);
  });

  it('reports flow syntax instead of silently dropping it', () => {
    const { rules, issues } = parseRulesYamlDetailed('env: [ACME_*]\n');
    expect(rules.env).toEqual([]);
    expect(issues).toHaveLength(1);
    expect(issues[0].line).toBe(1);
    expect(issues[0].message).toContain('flow syntax');
  });

  it('a failed section line does not bind following items to the previous section', () => {
    const { rules, issues } = parseRulesYamlDetailed(`env:
  - FOO_*
files: [inline]
  - "*.key-material"
`);
    // The shipped parser bound *.key-material to env, generating echo/printenv
    // deny rules for a file pattern. It must be dropped and reported instead.
    expect(rules.env).toEqual(['FOO_*']);
    expect(rules.files).toEqual([]);
    const dropped = issues.find(i => i.text.includes('key-material'));
    expect(dropped).toBeDefined();
    expect(dropped!.message).toContain('section never opened');
  });

  it('reports a comment on a section line as unsupported', () => {
    const { rules, issues } = parseRulesYamlDetailed('env: # main envs\n  - ACME_*\n');
    expect(rules.env).toEqual([]);
    expect(issues).toHaveLength(2);
    expect(issues[0].message).toContain('comment on the same line');
    expect(issues[1].message).toContain('section never opened');
  });

  it('reports a zero-indent list item instead of silently dropping it', () => {
    const { rules, issues } = parseRulesYamlDetailed('env:\n- ACME_*\n');
    expect(rules.env).toEqual([]);
    expect(issues).toHaveLength(1);
    expect(issues[0].line).toBe(2);
  });

  it('reports a pattern with no section at all', () => {
    const { issues } = parseRulesYamlDetailed('  - ORPHAN_*\n');
    expect(issues).toHaveLength(1);
    expect(issues[0].message).toContain('does not sit under any recognised section');
  });

  it('returns no issues for a clean file or the generated template', () => {
    const clean = parseRulesYamlDetailed('env:\n  - ACME_*\nfiles:\n  - "*.a"\n');
    expect(clean.issues).toEqual([]);
    expect(parseRulesYamlDetailed(generateTemplate()).issues).toEqual([]);
  });

  it('issue line numbers are 1-based file positions', () => {
    const { issues } = parseRulesYamlDetailed('\n# comment\nbogus:\n');
    expect(issues).toHaveLength(1);
    expect(issues[0].line).toBe(3);
  });

  it('parseRulesYaml still returns the same rules object shape', () => {
    const content = 'env:\n  - A_*\nbogus:\n  - dropped\n';
    expect(parseRulesYaml(content)).toEqual(parseRulesYamlDetailed(content).rules);
  });
});

// ---------------------------------------------------------------------------
// Load status — a file with unread lines must not report 'loaded' or 'empty'
// ---------------------------------------------------------------------------

describe('loadCustomRulesDetailed with unrecognised content', () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('reports unrecognised-content, not empty, when everything sat under a misspelled key', () => {
    fs.writeFileSync(path.join(dir, RULES_FILENAME), `
file:
  - "*.corp-secret"
`);
    const result = loadCustomRulesDetailed(dir);
    expect(result.status).toBe('unrecognised-content');
    expect(result.rules).toBeNull();
    expect(result.issues!.length).toBeGreaterThan(0);
    expect(result.issues![0].message).toContain('did you mean "files"?');
  });

  it('reports unrecognised-content, not loaded, when only part of the file was read', () => {
    fs.writeFileSync(path.join(dir, RULES_FILENAME), `
env:
  - ACME_*
file:
  - "*.corp-secret"
`);
    const result = loadCustomRulesDetailed(dir);
    expect(result.status).toBe('unrecognised-content');
    expect(result.rules).not.toBeNull();
    expect(result.rules!.env).toEqual(['ACME_*']);
    expect(result.rules!.files).toEqual([]);
  });

  it('carries no issues field on loaded and empty files', () => {
    fs.writeFileSync(path.join(dir, RULES_FILENAME), 'env:\n  - CORP_*\n');
    expect(loadCustomRulesDetailed(dir).issues).toBeUndefined();
    fs.writeFileSync(path.join(dir, RULES_FILENAME), '# nothing\n');
    expect(loadCustomRulesDetailed(dir).issues).toBeUndefined();
  });

  it('does not throw on unsafe characters under an unknown key — nothing binds, so it reports instead', () => {
    fs.writeFileSync(path.join(dir, RULES_FILENAME), 'bogus:\n  - "$(whoami)"\n');
    const result = loadCustomRulesDetailed(dir);
    expect(result.status).toBe('unrecognised-content');
    expect(result.rules).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Unreadable headers close the open section (adversarial-review finding:
// "files :" left the previous section open and mis-bound the items below it)
// ---------------------------------------------------------------------------

describe('parseRulesYamlDetailed — unreadable headers close the section', () => {
  it('a header with a space before the colon does not bind following items to the previous section', () => {
    const { rules, issues } = parseRulesYamlDetailed('env:\n  - FOO_*\nfiles :\n  - "*.key-material"\n');
    expect(rules.env).toEqual(['FOO_*']);
    expect(rules.files).toEqual([]);
    const dropped = issues.find(i => i.text.includes('key-material'));
    expect(dropped).toBeDefined();
    expect(dropped!.message).toContain('does not sit under any recognised section');
  });

  it('a tab-indented header closes the section the same way', () => {
    const { rules, issues } = parseRulesYamlDetailed('env:\n  - FOO_*\n\tfiles:\n  - "*.key-material"\n');
    expect(rules.env).toEqual(['FOO_*']);
    expect(rules.files).toEqual([]);
    expect(issues.some(i => i.text.includes('key-material'))).toBe(true);
  });

  it('a dropped item after an unreadable header does not blame an earlier unknown key', () => {
    const { issues } = parseRulesYamlDetailed('envs:\n  - A_*\nfiles :\n  - B_*\n');
    const b = issues.find(i => i.text === '- B_*');
    expect(b).toBeDefined();
    expect(b!.message).not.toContain('envs');
    expect(b!.message).toContain('does not sit under any recognised section');
  });

  it('strips a leading BOM so the first key parses', () => {
    const { rules, issues } = parseRulesYamlDetailed('\uFEFFenv:\n  - ACME_*\n');
    expect(rules.env).toEqual(['ACME_*']);
    expect(issues).toEqual([]);
  });

  it('points at invisible characters when a correct-looking line is not read', () => {
    const { issues } = parseRulesYamlDetailed('env\u00A0:\n');
    expect(issues).toHaveLength(1);
    expect(issues[0].message).toContain('invisible');
  });

  it('reports an empty quoted item instead of silently skipping it', () => {
    const { rules, issues } = parseRulesYamlDetailed("env:\n  - \"\"\n  - ''\n");
    expect(rules.env).toEqual([]);
    expect(issues).toHaveLength(2);
    expect(issues[0].message).toContain('no pattern left');
  });

  it('advises on the key, not on indentation, for an unknown key with an inline value', () => {
    const { issues } = parseRulesYamlDetailed('version: 1\n');
    expect(issues).toHaveLength(1);
    expect(issues[0].message).toContain('is not a section this build reads');
    expect(issues[0].message).not.toContain('indented');
  });
});
