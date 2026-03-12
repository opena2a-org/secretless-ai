import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import {
  parseRulesYaml,
  validatePattern,
  validateRules,
  globToShellRegex,
  envPatternToDenyRules,
  filePatternToDenyRules,
  customRulesToDenyRules,
  customRulesToHookBlocks,
  customRulesToFilePatterns,
  loadCustomRules,
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
