import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';
import { scan } from './scan';
import { status } from './status';
import { detectAITools } from './detect';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-ai-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('init', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('creates Claude Code protections by default when no tools detected', () => {
    const result = init(dir);

    expect(result.toolsConfigured).toContain('claude-code');
    expect(result.filesCreated).toContain('.claude/hooks/secretless-guard.sh');

    // Hook script exists and is executable
    const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
    expect(fs.existsSync(hookPath)).toBe(true);
    const stat = fs.statSync(hookPath);
    expect(stat.mode & 0o111).toBeGreaterThan(0); // executable

    // Settings file has deny rules
    const settings = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8'));
    expect(settings.permissions.deny).toContain('Read(.env*)');
    expect(settings.permissions.deny).toContain('Read(*.key)');
    expect(settings.permissions.deny).toContain('Read(*.pem)');

    // Hook is configured in settings
    expect(settings.hooks.PreToolUse.length).toBeGreaterThan(0);
    expect(settings.hooks.PreToolUse[0].matcher).toContain('Read');

    // CLAUDE.md has instructions
    const claudeMd = fs.readFileSync(path.join(dir, 'CLAUDE.md'), 'utf-8');
    expect(claudeMd).toContain('Secretless Mode');
    expect(claudeMd).toContain('secretless:managed');
  });

  // Regression: the generated guard hook must block secret files by their EXTENSION
  // suffix (server.key, prod.env, id_rsa.pem), not only literal dotfiles (.key, .env).
  // The previous `^\.key`-anchored matcher silently allowed every `name.key` form and
  // was case-sensitive, so `.KEY` / `server.PEM` bypassed it on case-insensitive disks.
  describe('generated guard hook blocks secret files by suffix and case', () => {
    function runHook(hookPath: string, filePath: string): boolean {
      const input = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: filePath } });
      const out = execSync(`bash ${JSON.stringify(hookPath)}`, { input, encoding: 'utf-8' });
      return /"permissionDecision":"deny"/.test(out);
    }

    it('blocks name.ext suffix forms and case variants, allows benign files', () => {
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

      const mustBlock = [
        '.env', 'prod.env', 'staging.env',
        'server.key', 'client.pem', 'id_rsa.pem',
        '.KEY', 'secrets.PEM', 'cert.crt',
        'terraform.tfstate', 'main.tfvars',
        '.npmrc', '.aws/credentials', '.ssh/id_rsa',
      ];
      for (const f of mustBlock) {
        expect(runHook(hookPath, f), `expected hook to BLOCK ${f}`).toBe(true);
      }

      const mustAllow = ['app.config', 'README.md', 'index.ts', 'environment.ts'];
      for (const f of mustAllow) {
        expect(runHook(hookPath, f), `expected hook to ALLOW ${f}`).toBe(false);
      }
    });
  });

  it('detects existing Claude Code project', () => {
    fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), '{}');

    const detected = detectAITools(dir);
    expect(detected[0].tool).toBe('claude-code');
  });

  it('detects Cursor project', () => {
    fs.writeFileSync(path.join(dir, '.cursorrules'), '');
    const detected = detectAITools(dir);
    expect(detected.some(d => d.tool === 'cursor')).toBe(true);
  });

  it('configures Cursor with instructions', () => {
    fs.writeFileSync(path.join(dir, '.cursorrules'), '# Existing rules\n');

    const result = init(dir);

    expect(result.toolsConfigured).toContain('cursor');
    const rules = fs.readFileSync(path.join(dir, '.cursorrules'), 'utf-8');
    expect(rules).toContain('Secretless Mode');
    expect(rules).toContain('# Existing rules'); // Preserves existing content
  });

  it('configures Copilot with instructions', () => {
    fs.mkdirSync(path.join(dir, '.github'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.github', 'copilot-instructions.md'), '');

    const result = init(dir);

    expect(result.toolsConfigured).toContain('copilot');
    const instructions = fs.readFileSync(path.join(dir, '.github', 'copilot-instructions.md'), 'utf-8');
    expect(instructions).toContain('Secretless Mode');
  });

  it('configures Aider with .aiderignore', () => {
    fs.writeFileSync(path.join(dir, '.aider.conf.yml'), '');

    const result = init(dir);

    expect(result.toolsConfigured).toContain('aider');
    const ignore = fs.readFileSync(path.join(dir, '.aiderignore'), 'utf-8');
    expect(ignore).toContain('.env');
    expect(ignore).toContain('*.key');
    expect(ignore).toContain('secrets/');
  });

  it('is idempotent — running init twice does not duplicate', () => {
    init(dir);
    const firstSettings = fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8');

    init(dir);
    const secondSettings = fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8');

    expect(firstSettings).toBe(secondSettings);
  });

  it('configures multiple tools in one project', () => {
    fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), '{}');
    fs.writeFileSync(path.join(dir, '.cursorrules'), '');

    const result = init(dir);

    expect(result.toolsConfigured).toContain('claude-code');
    expect(result.toolsConfigured).toContain('cursor');
  });
});

describe('scan', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('finds Anthropic API key in config', () => {
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({
      apiKey: 'sk-ant-api03-abc123def456abc123def456abc123'
    }));

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(1);
    expect(findings[0].patternName).toBe('Anthropic API Key');
    expect(findings[0].preview).toContain('REDACTED');
  });

  it('finds AWS key in .env', () => {
    fs.writeFileSync(path.join(dir, '.env'), 'AWS_KEY=AKIA4MCVFLRTSQBH6Z2N');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(1);
    expect(findings[0].patternName).toBe('AWS Access Key');
  });

  it('does not flag environment variable references', () => {
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({
      apiKey: '${ANTHROPIC_API_KEY}'
    }));

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(0);
  });

  it('handles missing files gracefully', () => {
    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(0);
  });

  it('redacts secrets in preview', () => {
    fs.writeFileSync(path.join(dir, '.env'), 'TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(1);
    expect(findings[0].preview).not.toContain('ghp_');
    expect(findings[0].preview).toContain('REDACTED');
  });

  it('finds hardcoded API key in JavaScript source file', () => {
    fs.writeFileSync(path.join(dir, 'app.js'), 'const key = "sk-proj-abc123def456ghi789jkl012mno345";');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(1);
    expect(findings[0].patternName).toBe('OpenAI Project Key');
    expect(findings[0].file).toBe('app.js');
    expect(findings[0].severity).toBe('high');
  });

  it('finds hardcoded API key in TypeScript source file', () => {
    fs.writeFileSync(path.join(dir, 'config.ts'), 'export const API_KEY = "sk-ant-api03-abc123def456abc123def456abc123";');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(1);
    expect(findings[0].patternName).toBe('Anthropic API Key');
    expect(findings[0].file).toBe('config.ts');
  });

  it('finds hardcoded API key in Python source file', () => {
    fs.writeFileSync(path.join(dir, 'main.py'), 'api_key = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(1);
    expect(findings[0].patternName).toBe('GitHub Token');
    expect(findings[0].file).toBe('main.py');
  });

  it('skips node_modules when scanning source files', () => {
    fs.mkdirSync(path.join(dir, 'node_modules', 'some-pkg'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'node_modules', 'some-pkg', 'index.js'),
      'const key = "sk-proj-abc123def456ghi789jkl012mno345";');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(0);
  });

  it('skips process.env references in source files', () => {
    fs.writeFileSync(path.join(dir, 'config.ts'), 'const key = process.env.ANTHROPIC_API_KEY;');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(0);
  });

  it('skips test files by default', () => {
    fs.writeFileSync(path.join(dir, 'auth.test.ts'), 'const key = "sk-proj-abc123def456ghi789jkl012mno345";');
    fs.writeFileSync(path.join(dir, 'auth.spec.js'), 'const key = "sk-proj-abc123def456ghi789jkl012mno345";');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(0);
  });

  it('includes test files when --include-tests is set', () => {
    fs.writeFileSync(path.join(dir, 'auth.test.ts'), 'const key = "sk-proj-abc123def456ghi789jkl012mno345";');

    const findings = scan(dir, { scanGlobal: false, includeTests: true });
    expect(findings.length).toBe(1);
    expect(findings[0].file).toBe('auth.test.ts');
  });

  it('skips test directories by default', () => {
    fs.mkdirSync(path.join(dir, '__tests__'), { recursive: true });
    fs.writeFileSync(path.join(dir, '__tests__', 'auth.js'), 'const key = "sk-proj-abc123def456ghi789jkl012mno345";');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(0);
  });

  it('excludes known AWS example key AKIAIOSFODNN7EXAMPLE', () => {
    fs.writeFileSync(path.join(dir, '.env'), 'AWS_KEY=AKIAIOSFODNN7EXAMPLE');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(0);
  });

  it('excludes credentials with placeholder indicators', () => {
    fs.writeFileSync(path.join(dir, 'config.ts'),
      'const key = "sk-proj-your_api_key_here_replace_me_placeholder";');

    const findings = scan(dir, { scanGlobal: false });
    expect(findings.length).toBe(0);
  });

  it('can disable source file scanning', () => {
    fs.writeFileSync(path.join(dir, 'app.js'), 'const key = "sk-proj-abc123def456ghi789jkl012mno345";');

    const findings = scan(dir, { scanGlobal: false, scanSource: false });
    expect(findings.length).toBe(0);
  });
});

describe('status', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('reports unprotected project', () => {
    const s = status(dir);
    expect(s.isProtected).toBe(false);
    expect(s.configuredTools).toHaveLength(0);
    expect(s.hookInstalled).toBe(false);
  });

  it('reports protected project after init', () => {
    init(dir);

    const s = status(dir);
    expect(s.isProtected).toBe(true);
    expect(s.hookInstalled).toBe(true);
    expect(s.denyRuleCount).toBeGreaterThan(0);
  });

  it('counts secrets found', () => {
    fs.writeFileSync(path.join(dir, '.env'), 'KEY=sk-ant-api03-abc123def456abc123def456abc123');

    const s = status(dir);
    expect(s.secretsFound).toBe(1);
  });
});
