import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawnSync } from 'child_process';
import { doctor, quickDiagnosis, fixProfiles } from './doctor';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-ai-doctor-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('doctor', () => {
  let home: string;

  beforeEach(() => {
    home = tmpDir();
  });

  afterEach(() => {
    cleanup(home);
  });

  it('detects healthy state: key in .zshenv and in process.env', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      'export ANTHROPIC_API_KEY="sk-ant-..."\nexport OPENAI_API_KEY="sk-proj-..."\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {
        ANTHROPIC_API_KEY: 'set',
        OPENAI_API_KEY: 'set',
      },
    });

    expect(result.health).toBe('healthy');
    expect(result.shell).toBe('zsh');
    expect(result.platform).toBe('darwin');

    const infoFindings = result.findings.filter((f) => f.severity === 'info');
    expect(infoFindings.length).toBe(2);
    expect(infoFindings[0].message).toContain('correctly configured');
  });

  it('detects wrong profile: key in .zshrc only, not in process.env', () => {
    // .zshrc is interactive-only, so non-interactive shells won't source it
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      'export ANTHROPIC_API_KEY="sk-ant-..."\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {},
    });

    expect(result.health).toBe('broken');
    const errorFindings = result.findings.filter((f) => f.severity === 'error');
    expect(errorFindings.length).toBeGreaterThanOrEqual(1);

    const wrongProfileFinding = errorFindings.find((f) =>
      f.message.includes('ANTHROPIC_API_KEY') && f.message.includes('interactive-only'),
    );
    expect(wrongProfileFinding).toBeDefined();
    expect(wrongProfileFinding!.fix).toContain('.zshenv');
  });

  it('detects no keys anywhere', () => {
    // No profile files, no env vars
    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {},
    });

    expect(result.health).toBe('broken');
    const errorFindings = result.findings.filter((f) => f.severity === 'error');
    expect(errorFindings.some((f) => f.message.includes('No API keys found'))).toBe(true);
  });

  it('handles missing profile files gracefully', () => {
    // home dir exists but no profile files — should not throw
    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {},
    });

    expect(result.profiles.every((p) => !p.exists)).toBe(true);
    expect(result.profiles.every((p) => p.exportedVars.length === 0)).toBe(true);
  });

  it('detects bash on Linux', () => {
    fs.writeFileSync(
      path.join(home, '.bashrc'),
      'export AWS_ACCESS_KEY_ID="AKIA..."\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '/bin/bash',
      platform: 'linux',
      envOverride: {},
    });

    expect(result.shell).toBe('bash');
    expect(result.platform).toBe('linux');

    // .bashrc profiles should be checked
    const bashrcProfile = result.profiles.find((p) => p.path.endsWith('.bashrc'));
    expect(bashrcProfile).toBeDefined();
    expect(bashrcProfile!.exportedVars).toContain('AWS_ACCESS_KEY_ID');
  });

  it('ignores commented-out exports', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      '# export ANTHROPIC_API_KEY="sk-ant-..."\nexport OPENAI_API_KEY="sk-proj-..."\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: { OPENAI_API_KEY: 'set' },
    });

    const zshenvProfile = result.profiles.find((p) => p.path.endsWith('.zshenv'));
    expect(zshenvProfile).toBeDefined();
    // Commented line should be ignored
    expect(zshenvProfile!.exportedVars).not.toContain('ANTHROPIC_API_KEY');
    // Uncommented line should be found
    expect(zshenvProfile!.exportedVars).toContain('OPENAI_API_KEY');
  });

  it('warns when key is in env but only in interactive profile', () => {
    // Key is in .zshrc and happens to be in env (because we're in an interactive shell)
    // but it won't work in non-interactive subprocesses
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      'export ANTHROPIC_API_KEY="sk-ant-..."\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: { ANTHROPIC_API_KEY: 'set' },
    });

    expect(result.health).toBe('degraded');
    const warnFindings = result.findings.filter((f) => f.severity === 'warn');
    expect(warnFindings.length).toBeGreaterThanOrEqual(1);
    expect(warnFindings[0].message).toContain('may fail in subprocesses');
  });

  it('marks a profile it could not read instead of reporting it as holding no keys', () => {
    fs.writeFileSync(path.join(home, '.zshenv'), 'export ANTHROPIC_API_KEY="sk-ant-..."\n');
    // A directory where the profile should be: it exists, and reading it fails.
    fs.mkdirSync(path.join(home, '.zshrc'));

    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: { ANTHROPIC_API_KEY: 'set' },
    });

    const zshrc = result.profiles.find((p) => p.path.endsWith('.zshrc'))!;
    expect(zshrc.exists).toBe(true);
    expect(zshrc.readError).toBe('EISDIR');
    expect(zshrc.exportedVars).toEqual([]);
    const zshenv = result.profiles.find((p) => p.path.endsWith('.zshenv'))!;
    expect(zshenv.readError).toBeUndefined();
    // The health value is unchanged; the CLI qualifies the verdict it prints.
    expect(result.health).toBe('healthy');
  });

  it('reports all zsh profiles with correct metadata', () => {
    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: { ANTHROPIC_API_KEY: 'set' },
    });

    expect(result.profiles.length).toBe(3);

    const zshenv = result.profiles.find((p) => p.path.endsWith('.zshenv'));
    expect(zshenv!.nonInteractive).toBe(true);
    expect(zshenv!.recommendation).toBe('recommended');

    const zshrc = result.profiles.find((p) => p.path.endsWith('.zshrc'));
    expect(zshrc!.nonInteractive).toBe(false);
    expect(zshrc!.recommendation).toBe('interactive-only');

    const zprofile = result.profiles.find((p) => p.path.endsWith('.zprofile'));
    expect(zprofile!.nonInteractive).toBe(false);
    expect(zprofile!.recommendation).toBe('login-only');
  });

  it('defaults to zsh on macOS when shell is unknown', () => {
    const result = doctor({
      homeDir: home,
      shell: '',
      platform: 'darwin',
      envOverride: {},
    });

    // Should check zsh profiles since platform is darwin
    expect(result.profiles.some((p) => p.path.endsWith('.zshenv'))).toBe(true);
  });

  it('defaults to bash on linux when shell is unknown', () => {
    const result = doctor({
      homeDir: home,
      shell: '',
      platform: 'linux',
      envOverride: {},
    });

    // Should check bash profiles since platform is linux
    expect(result.profiles.some((p) => p.path.endsWith('.bashrc'))).toBe(true);
  });

  // ── Windows tests ──────────────────────────────────────────────────────

  it('detects Windows PowerShell profile with $env: syntax', () => {
    const psDir = path.join(home, 'Documents', 'PowerShell');
    fs.mkdirSync(psDir, { recursive: true });
    fs.writeFileSync(
      path.join(psDir, 'Microsoft.PowerShell_profile.ps1'),
      '$env:ANTHROPIC_API_KEY = "sk-ant-test-value"\n$env:OPENAI_API_KEY = "sk-proj-test-value"\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '',
      platform: 'win32',
      envOverride: {},
    });

    expect(result.shell).toBe('powershell');
    expect(result.platform).toBe('win32');

    const psProfile = result.profiles.find((p) => p.path.includes('PowerShell'));
    expect(psProfile).toBeDefined();
    expect(psProfile!.exportedVars).toContain('ANTHROPIC_API_KEY');
    expect(psProfile!.exportedVars).toContain('OPENAI_API_KEY');
  });

  it('reports error when Windows key is in PS profile but not in system env', () => {
    const psDir = path.join(home, 'Documents', 'PowerShell');
    fs.mkdirSync(psDir, { recursive: true });
    fs.writeFileSync(
      path.join(psDir, 'Microsoft.PowerShell_profile.ps1'),
      '$env:ANTHROPIC_API_KEY = "sk-ant-test-value"\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '',
      platform: 'win32',
      envOverride: {},
    });

    expect(result.health).toBe('broken');
    const errors = result.findings.filter((f) => f.severity === 'error');
    expect(errors.some((f) => f.message.includes('ANTHROPIC_API_KEY') && f.message.includes('session-only'))).toBe(true);
    expect(errors[0].fix).toContain('setx');
  });

  it('reports healthy when Windows key is in system env', () => {
    const psDir = path.join(home, 'Documents', 'PowerShell');
    fs.mkdirSync(psDir, { recursive: true });
    fs.writeFileSync(
      path.join(psDir, 'Microsoft.PowerShell_profile.ps1'),
      '$env:ANTHROPIC_API_KEY = "sk-ant-test-value"\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '',
      platform: 'win32',
      envOverride: { ANTHROPIC_API_KEY: 'set' },
    });

    expect(result.health).toBe('healthy');
    const infoFindings = result.findings.filter((f) => f.severity === 'info');
    expect(infoFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('ignores commented-out PowerShell exports', () => {
    const psDir = path.join(home, 'Documents', 'PowerShell');
    fs.mkdirSync(psDir, { recursive: true });
    fs.writeFileSync(
      path.join(psDir, 'Microsoft.PowerShell_profile.ps1'),
      '# $env:ANTHROPIC_API_KEY = "sk-ant-old-key"\n$env:OPENAI_API_KEY = "sk-proj-test"\n',
    );

    const result = doctor({
      homeDir: home,
      shell: '',
      platform: 'win32',
      envOverride: { OPENAI_API_KEY: 'set' },
    });

    const psProfile = result.profiles.find((p) => p.path.includes('PowerShell'));
    expect(psProfile!.exportedVars).not.toContain('ANTHROPIC_API_KEY');
    expect(psProfile!.exportedVars).toContain('OPENAI_API_KEY');
  });

  it('gives Windows-specific advice when no keys found', () => {
    const result = doctor({
      homeDir: home,
      shell: '',
      platform: 'win32',
      envOverride: {},
    });

    expect(result.health).toBe('broken');
    const errors = result.findings.filter((f) => f.severity === 'error');
    expect(errors.some((f) => f.fix?.includes('setx') || f.fix?.includes('Environment Variables'))).toBe(true);
  });
});

describe('quickDiagnosis', () => {
  let home: string;

  beforeEach(() => {
    home = tmpDir();
  });

  afterEach(() => {
    cleanup(home);
  });

  it('finds keys in wrong profile', () => {
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      'export ANTHROPIC_API_KEY="sk-ant-..."\nexport OPENAI_API_KEY="sk-proj-..."\n',
    );

    const result = quickDiagnosis({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {},
    });

    expect(result.wrongProfile).toContain('ANTHROPIC_API_KEY');
    expect(result.wrongProfile).toContain('OPENAI_API_KEY');
  });

  it('returns empty when keys are correctly in .zshenv', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      'export ANTHROPIC_API_KEY="sk-ant-..."\n',
    );

    const result = quickDiagnosis({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: { ANTHROPIC_API_KEY: 'set' },
    });

    expect(result.wrongProfile).toEqual([]);
  });

  it('reports vars missing everywhere', () => {
    const result = quickDiagnosis({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: {},
    });

    // All known vars should be reported as missing everywhere
    expect(result.missingEverywhere.length).toBeGreaterThan(0);
    expect(result.missingEverywhere).toContain('ANTHROPIC_API_KEY');
  });

  it('works with bash profiles', () => {
    fs.writeFileSync(
      path.join(home, '.bash_profile'),
      'export GITHUB_TOKEN="ghp_..."\n',
    );

    const result = quickDiagnosis({
      homeDir: home,
      shell: '/bin/bash',
      platform: 'linux',
      envOverride: {},
    });

    // .bash_profile is login-only, key not in env
    expect(result.wrongProfile).toContain('GITHUB_TOKEN');
  });
});

describe('doctor: secrets under names outside the known list', () => {
  let home: string;
  // A synthetic value; the assertions below check it never leaves the profile.
  const VALUE = 'FAKE-synthetic-jira-value-7f3a9c';

  beforeEach(() => {
    home = tmpDir();
  });

  afterEach(() => {
    cleanup(home);
  });

  it('lists a plain-text export per profile and does not call it healthy', () => {
    fs.writeFileSync(path.join(home, '.zprofile'), `export JIRA_TOKEN=${VALUE}\n`);
    fs.writeFileSync(path.join(home, '.zshenv'), 'export ANTHROPIC_API_KEY="sk-ant-..."\n');

    const result = doctor({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
      envOverride: { ANTHROPIC_API_KEY: 'set' },
    });

    const zprofile = result.profiles.find((p) => p.path.endsWith('.zprofile'))!;
    expect(zprofile.secretExports).toEqual([{ name: 'JIRA_TOKEN', line: 1, plainText: true }]);
    const zshenv = result.profiles.find((p) => p.path.endsWith('.zshenv'))!;
    expect(zshenv.secretExports).toEqual([{ name: 'ANTHROPIC_API_KEY', line: 1, plainText: true }]);

    expect(result.health).toBe('degraded');
    const plainText = result.findings.filter((f) => f.kind === 'plain-text');
    expect(plainText).toHaveLength(1);
    expect(plainText[0].severity).toBe('warn');
    expect(plainText[0].message).toBe('JIRA_TOKEN is stored in plain text in ~/.zprofile (line 1)');
    expect(plainText[0].fix).toContain('secretless-ai secret set JIRA_TOKEN');
    expect(plainText[0].fix).toContain('remove line 1 from ~/.zprofile');
    expect(plainText[0].verify).toBe("grep -noE '^[[:space:]]*export[[:space:]]+JIRA_TOKEN=' ~/.zprofile");
    expect(JSON.stringify(result)).not.toContain(VALUE);
  });

  it('does not call a file path a plain-text secret, quoted or not', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      [
        'export SIGNING_KEY=/Users/me/.keys/signing',
        'export SIGNING_KEY="/Users/me/.keys/signing"',
        "export SIGNING_KEY='/Users/me/.keys/signing'",
        'export SSH_KEY=./keys/id_ed25519',
        'export SSH_KEY="./keys/id_ed25519"',
        "export SSH_KEY='../keys/id_ed25519'",
        'export SSH_KEY=../keys/id_ed25519',
        '',
      ].join('\n'),
    );

    const result = doctor({ homeDir: home, shell: '/bin/zsh', platform: 'darwin', envOverride: {} });

    const zshenv = result.profiles.find((p) => p.path.endsWith('.zshenv'))!;
    expect(zshenv.secretExports.map((e) => [e.name, e.line, e.plainText])).toEqual([
      ['SIGNING_KEY', 1, false],
      ['SIGNING_KEY', 2, false],
      ['SIGNING_KEY', 3, false],
      ['SSH_KEY', 4, false],
      ['SSH_KEY', 5, false],
      ['SSH_KEY', 6, false],
      ['SSH_KEY', 7, false],
    ]);
    expect(result.findings.filter((f) => f.kind === 'plain-text')).toHaveLength(0);
    // A file path is not an API key, so with nothing else the verdict is BROKEN.
    expect(result.health).toBe('broken');
    expect(result.findings.filter((f) => f.severity === 'error').map((f) => f.message)).toEqual([
      'No API keys found in env vars or shell profiles',
    ]);

    // The literal JIRA_TOKEN beside them is still reported.
    fs.writeFileSync(path.join(home, '.zprofile'), `export JIRA_TOKEN=${VALUE}\n`);
    const withLiteral = doctor({ homeDir: home, shell: '/bin/zsh', platform: 'darwin', envOverride: {} });
    expect(withLiteral.findings.filter((f) => f.kind === 'plain-text').map((f) => f.message)).toEqual([
      'JIRA_TOKEN is stored in plain text in ~/.zprofile (line 1)',
    ]);
    expect(withLiteral.health).toBe('degraded');
  });

  const itPosix = process.platform !== 'win32' ? it : it.skip;

  itPosix('gives a Verify command that finds the line and never prints the value', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      `export PATH="$HOME/bin:$PATH"\n  export   JIRA_TOKEN="${VALUE}"\n`,
    );

    const result = doctor({ homeDir: home, shell: '/bin/zsh', platform: 'darwin', envOverride: {} });

    const [finding] = result.findings.filter((f) => f.kind === 'plain-text');
    expect(finding.message).toBe('JIRA_TOKEN is stored in plain text in ~/.zshenv (line 2)');
    const res = spawnSync('/bin/sh', ['-c', finding.verify!], {
      encoding: 'utf-8',
      env: { PATH: process.env.PATH, HOME: home },
    });
    expect(res.status).toBe(0);
    expect(res.stdout.trim()).toBe('2:  export   JIRA_TOKEN=');
    expect(res.stdout).not.toContain(VALUE);
  });

  it('reports the line of each export, not only the first', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      `# tokens\nexport PATH="$HOME/bin:$PATH"\nexport DB_PASSWORD='${VALUE}'\nexport CLIENT_SECRET="${VALUE}"\n`,
    );

    const result = doctor({ homeDir: home, shell: '/bin/zsh', platform: 'darwin', envOverride: {} });

    const zshenv = result.profiles.find((p) => p.path.endsWith('.zshenv'))!;
    expect(zshenv.secretExports.map((e) => [e.name, e.line])).toEqual([
      ['DB_PASSWORD', 3],
      ['CLIENT_SECRET', 4],
    ]);
    expect(result.findings.filter((f) => f.kind === 'plain-text').map((f) => f.message)).toEqual([
      'DB_PASSWORD is stored in plain text in ~/.zshenv (line 3)',
      'CLIENT_SECRET is stored in plain text in ~/.zshenv (line 4)',
    ]);
  });

  it('lists a secret fetched at shell start without calling it plain text', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      [
        'export GH_TOKEN=$(gh auth token)',
        'export JIRA_TOKEN="$(cat ~/.config/jira)"',
        'export NPM_KEY=`pass show npm`',
        'export DEPLOY_SECRET="${OTHER_SECRET}"',
        'export SIGNING_KEY=~/.keys/signing',
        'export EMPTY_TOKEN=',
        'export BLANK_TOKEN=""',
        '',
      ].join('\n'),
    );

    const result = doctor({ homeDir: home, shell: '/bin/zsh', platform: 'darwin', envOverride: {} });

    const zshenv = result.profiles.find((p) => p.path.endsWith('.zshenv'))!;
    expect(zshenv.secretExports.map((e) => e.name)).toEqual([
      'GH_TOKEN', 'JIRA_TOKEN', 'NPM_KEY', 'DEPLOY_SECRET', 'SIGNING_KEY', 'EMPTY_TOKEN', 'BLANK_TOKEN',
    ]);
    expect(zshenv.secretExports.every((e) => !e.plainText)).toBe(true);
    expect(result.findings.filter((f) => f.kind === 'plain-text')).toHaveLength(0);
    // Listed, but a value looked up at shell start is not an API key doctor
    // found, so with nothing else the verdict is BROKEN.
    expect(result.findings.some((f) => f.message === 'No API keys found in env vars or shell profiles')).toBe(true);
    expect(result.health).toBe('broken');
  });

  it('does not list exports whose names do not read as secrets', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      'export EDITOR=vim\nexport PASSWORD_STORE_DIR=/opt/pass\nexport KEYTIMEOUT=1\nexport MONKEY=1\nexport TOKENIZERS_PARALLELISM=false\n',
    );

    const result = doctor({ homeDir: home, shell: '/bin/zsh', platform: 'darwin', envOverride: {} });

    expect(result.profiles.every((p) => p.secretExports.length === 0)).toBe(true);
    expect(result.findings.filter((f) => f.kind === 'plain-text')).toHaveLength(0);
  });

  it('ignores commented-out secret exports', () => {
    fs.writeFileSync(path.join(home, '.zshrc'), `# export JIRA_TOKEN=${VALUE}\n`);

    const result = doctor({ homeDir: home, shell: '/bin/zsh', platform: 'darwin', envOverride: {} });

    expect(result.profiles.every((p) => p.secretExports.length === 0)).toBe(true);
  });

  it('reports a plain-text $env: assignment in a PowerShell profile', () => {
    const psDir = path.join(home, 'Documents', 'PowerShell');
    fs.mkdirSync(psDir, { recursive: true });
    fs.writeFileSync(
      path.join(psDir, 'Microsoft.PowerShell_profile.ps1'),
      `$env:JIRA_TOKEN = "${VALUE}"\n$env:VAULT_TOKEN = (Get-Secret vault)\n`,
    );

    const result = doctor({ homeDir: home, platform: 'win32', envOverride: {} });

    const ps = result.profiles.find((p) => p.path.includes(path.join('Documents', 'PowerShell')))!;
    expect(ps.secretExports).toEqual([
      { name: 'JIRA_TOKEN', line: 1, plainText: true },
      { name: 'VAULT_TOKEN', line: 2, plainText: false },
    ]);
    const plainText = result.findings.filter((f) => f.kind === 'plain-text');
    expect(plainText.map((f) => f.message)).toEqual([
      'JIRA_TOKEN is stored in plain text in ~/Microsoft.PowerShell_profile.ps1 (line 1)',
    ]);
    const psRel = path.join('Documents', 'PowerShell', 'Microsoft.PowerShell_profile.ps1');
    expect(plainText[0].verify).toBe(
      `Select-String -Path "$HOME${path.sep}${psRel}" -Pattern '^\\s*\\$env:JIRA_TOKEN\\s*=' | ForEach-Object LineNumber`,
    );
    expect(result.health).toBe('degraded');
  });

  it('leaves --fix copying known keys only', () => {
    fs.writeFileSync(path.join(home, '.zprofile'), `export JIRA_TOKEN=${VALUE}\n`);

    const result = fixProfiles({ homeDir: home, shell: '/bin/zsh', platform: 'darwin' });

    expect(result).toBeNull();
    expect(fs.existsSync(path.join(home, '.zshenv'))).toBe(false);
  });
});

describe('doctor CLI output for a secret outside the known list', () => {
  const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');
  const itIfBuilt = fs.existsSync(CLI_PATH) && process.platform !== 'win32' ? it : it.skip;
  const VALUE = 'FAKE-synthetic-jira-value-7f3a9c';
  let home: string;

  beforeEach(() => {
    home = tmpDir();
  });

  afterEach(() => {
    cleanup(home);
  });

  function runDoctorCli(): { status: number | null; stdout: string } {
    const res = spawnSync(process.execPath, [CLI_PATH, 'doctor'], {
      encoding: 'utf-8',
      env: { PATH: process.env.PATH, HOME: home, SHELL: '/bin/zsh', SECRETLESS_OS_KEYCHAIN: 'off' },
    });
    return { status: res.status, stdout: res.stdout };
  }

  itIfBuilt('names the export and its line, says how to store it, and exits 1', () => {
    fs.writeFileSync(path.join(home, '.zprofile'), `export JIRA_TOKEN=${VALUE}\n`);
    fs.writeFileSync(path.join(home, '.zshenv'), 'export ANTHROPIC_API_KEY=placeholder-value\n');

    const { status, stdout } = runDoctorCli();

    expect(stdout).toContain('~/.zprofile (login-only): 1 key(s)');
    expect(stdout).toContain('JIRA_TOKEN (line 1)');
    expect(stdout).toContain('ANTHROPIC_API_KEY (line 1)');
    expect(stdout).toContain('[WARN] JIRA_TOKEN is stored in plain text in ~/.zprofile (line 1)');
    expect(stdout).toContain("Verify: grep -noE '^[[:space:]]*export[[:space:]]+JIRA_TOKEN=' ~/.zprofile");
    expect(stdout).toContain('secretless-ai secret set JIRA_TOKEN');
    expect(stdout).toContain('DEGRADED: A shell profile holds a secret in plain text.');
    expect(stdout).not.toContain('HEALTHY');
    expect(stdout).not.toContain('doctor --fix');
    expect(stdout).not.toContain(VALUE);
    expect(status).toBe(1);
  });

  itIfBuilt('lists a secret fetched rather than written out and stays BROKEN with no API key', () => {
    fs.writeFileSync(path.join(home, '.zshenv'), 'export JIRA_TOKEN="$(cat ~/.config/jira)"\n');

    const { status, stdout } = runDoctorCli();

    expect(stdout).toContain('JIRA_TOKEN (line 1)');
    expect(stdout).not.toContain('plain text');
    expect(stdout).toContain('[ERROR] No API keys found in env vars or shell profiles');
    expect(stdout).toContain('BROKEN');
    expect(stdout).not.toContain('HEALTHY');
    expect(status).toBe(1);
  });
});

describe('fixProfiles', () => {
  let home: string;

  beforeEach(() => {
    home = tmpDir();
  });

  afterEach(() => {
    cleanup(home);
  });

  it('copies exports from .zshrc to .zshenv', () => {
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      '# my config\nexport ANTHROPIC_API_KEY="sk-ant-test123"\nexport OPENAI_API_KEY="sk-proj-test456"\naliases...\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('ANTHROPIC_API_KEY');
    expect(result!.fixed).toContain('OPENAI_API_KEY');
    expect(result!.sourceProfile).toBe('.zshrc');
    expect(result!.targetProfile).toBe('.zshenv');
    expect(result!.created).toBe(true);

    // Verify .zshenv was created with the export lines
    const zshenv = fs.readFileSync(path.join(home, '.zshenv'), 'utf-8');
    expect(zshenv).toContain('export ANTHROPIC_API_KEY="sk-ant-test123"');
    expect(zshenv).toContain('export OPENAI_API_KEY="sk-proj-test456"');
    expect(zshenv).toContain('# Added by secretless-ai');
  });

  it('appends to existing .zshenv without overwriting', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      '# existing content\nexport PATH="/usr/local/bin:$PATH"\n',
    );
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      'export ANTHROPIC_API_KEY="sk-ant-test123"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    expect(result).not.toBeNull();
    expect(result!.created).toBe(false);

    const zshenv = fs.readFileSync(path.join(home, '.zshenv'), 'utf-8');
    // Original content preserved
    expect(zshenv).toContain('export PATH="/usr/local/bin:$PATH"');
    // New export added
    expect(zshenv).toContain('export ANTHROPIC_API_KEY="sk-ant-test123"');
  });

  it('returns null when nothing needs fixing', () => {
    // Key already in the correct profile
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      'export ANTHROPIC_API_KEY="sk-ant-test123"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    expect(result).toBeNull();
  });

  it('skips vars already in .zshenv', () => {
    fs.writeFileSync(
      path.join(home, '.zshenv'),
      'export ANTHROPIC_API_KEY="sk-ant-already-here"\n',
    );
    fs.writeFileSync(
      path.join(home, '.zshrc'),
      'export ANTHROPIC_API_KEY="sk-ant-also-here"\nexport OPENAI_API_KEY="sk-proj-only-here"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    expect(result).not.toBeNull();
    // ANTHROPIC already in .zshenv, should not be copied again
    expect(result!.fixed).not.toContain('ANTHROPIC_API_KEY');
    // OPENAI only in .zshrc, should be copied
    expect(result!.fixed).toContain('OPENAI_API_KEY');
  });

  it('copies exports from .bash_profile to .bashrc on Linux', () => {
    fs.writeFileSync(
      path.join(home, '.bash_profile'),
      'export GITHUB_TOKEN="ghp_abcdef1234567890abcdef1234567890abcd"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/bash',
      platform: 'linux',
    });

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('GITHUB_TOKEN');
    expect(result!.sourceProfile).toBe('.bash_profile');
    expect(result!.targetProfile).toBe('.bashrc');

    const bashrc = fs.readFileSync(path.join(home, '.bashrc'), 'utf-8');
    expect(bashrc).toContain('export GITHUB_TOKEN=');
  });

  it('returns null when no profiles exist', () => {
    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    expect(result).toBeNull();
  });

  it('does not modify the source profile', () => {
    const originalContent = '# my zshrc\nexport ANTHROPIC_API_KEY="sk-ant-test123"\nsome other stuff\n';
    fs.writeFileSync(path.join(home, '.zshrc'), originalContent);

    fixProfiles({
      homeDir: home,
      shell: '/bin/zsh',
      platform: 'darwin',
    });

    // Source file should be untouched
    const afterContent = fs.readFileSync(path.join(home, '.zshrc'), 'utf-8');
    expect(afterContent).toBe(originalContent);
  });

  // ── Linux: insert before interactive guard ─────────────────────────────

  it('inserts before bash interactive guard on Linux', () => {
    // Simulate a typical Ubuntu .bashrc with interactive guard
    const bashrc = [
      '# ~/.bashrc: executed by bash(1) for non-login shells.',
      '',
      '# If not running interactively, don\'t do anything',
      'case $- in',
      '    *i*) ;;',
      '      *) return;;',
      'esac',
      '',
      '# some other stuff',
      'alias ll="ls -la"',
    ].join('\n');

    fs.writeFileSync(path.join(home, '.bashrc'), bashrc);
    fs.writeFileSync(
      path.join(home, '.bash_profile'),
      'export ANTHROPIC_API_KEY="sk-ant-test123"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/bash',
      platform: 'linux',
    });

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('ANTHROPIC_API_KEY');

    // Verify the export was inserted BEFORE the interactive guard
    const fixed = fs.readFileSync(path.join(home, '.bashrc'), 'utf-8');
    const exportIdx = fixed.indexOf('export ANTHROPIC_API_KEY=');
    const guardIdx = fixed.indexOf('case $- in');
    expect(exportIdx).toBeLessThan(guardIdx);
    expect(exportIdx).toBeGreaterThan(-1);
  });

  it('appends to .bashrc when no interactive guard exists', () => {
    // Simple .bashrc without guard
    const bashrc = '# simple bashrc\nalias ll="ls -la"\n';
    fs.writeFileSync(path.join(home, '.bashrc'), bashrc);
    fs.writeFileSync(
      path.join(home, '.bash_profile'),
      'export OPENAI_API_KEY="sk-proj-test456"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/bash',
      platform: 'linux',
    });

    expect(result).not.toBeNull();
    const fixed = fs.readFileSync(path.join(home, '.bashrc'), 'utf-8');
    // Should be appended since no guard
    expect(fixed).toContain('export OPENAI_API_KEY="sk-proj-test456"');
    expect(fixed.startsWith('# simple bashrc')).toBe(true);
  });

  it('handles [ -z "$PS1" ] guard variant', () => {
    const bashrc = '# bashrc\n[ -z "$PS1" ] && return\nalias ll="ls -la"\n';
    fs.writeFileSync(path.join(home, '.bashrc'), bashrc);
    fs.writeFileSync(
      path.join(home, '.bash_profile'),
      'export AWS_ACCESS_KEY_ID="AKIATEST1234567890AB"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '/bin/bash',
      platform: 'linux',
    });

    expect(result).not.toBeNull();
    const fixed = fs.readFileSync(path.join(home, '.bashrc'), 'utf-8');
    const exportIdx = fixed.indexOf('export AWS_ACCESS_KEY_ID=');
    const guardIdx = fixed.indexOf('[ -z "$PS1" ]');
    expect(exportIdx).toBeLessThan(guardIdx);
  });

  // ── Windows: setx fix ─────────────────────────────────────────────────

  it('generates setx commands for Windows fix (dry run)', () => {
    const psDir = path.join(home, 'Documents', 'PowerShell');
    fs.mkdirSync(psDir, { recursive: true });
    fs.writeFileSync(
      path.join(psDir, 'Microsoft.PowerShell_profile.ps1'),
      '$env:ANTHROPIC_API_KEY = "sk-ant-test-value"\n$env:OPENAI_API_KEY = "sk-proj-test-value"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '',
      platform: 'win32',
      envOverride: {},
      dryRun: true,
    });

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('ANTHROPIC_API_KEY');
    expect(result!.fixed).toContain('OPENAI_API_KEY');
    expect(result!.targetProfile).toContain('setx');
    expect(result!.commands).toBeDefined();
    expect(result!.commands!.length).toBe(2);
    expect(result!.commands![0]).toContain('setx ANTHROPIC_API_KEY');
    expect(result!.commands![1]).toContain('setx OPENAI_API_KEY');
  });

  it('skips Windows vars already in system env', () => {
    const psDir = path.join(home, 'Documents', 'PowerShell');
    fs.mkdirSync(psDir, { recursive: true });
    fs.writeFileSync(
      path.join(psDir, 'Microsoft.PowerShell_profile.ps1'),
      '$env:ANTHROPIC_API_KEY = "sk-ant-test-value"\n$env:OPENAI_API_KEY = "sk-proj-test-value"\n',
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '',
      platform: 'win32',
      envOverride: { ANTHROPIC_API_KEY: 'already-set' },
      dryRun: true,
    });

    expect(result).not.toBeNull();
    // ANTHROPIC already in env, should not be in commands
    expect(result!.fixed).not.toContain('ANTHROPIC_API_KEY');
    expect(result!.fixed).toContain('OPENAI_API_KEY');
    expect(result!.commands!.length).toBe(1);
  });

  it('returns null on Windows when no PS profiles exist', () => {
    const result = fixProfiles({
      homeDir: home,
      shell: '',
      platform: 'win32',
      envOverride: {},
      dryRun: true,
    });

    expect(result).toBeNull();
  });

  it('handles single-quoted PS values', () => {
    const psDir = path.join(home, 'Documents', 'PowerShell');
    fs.mkdirSync(psDir, { recursive: true });
    fs.writeFileSync(
      path.join(psDir, 'Microsoft.PowerShell_profile.ps1'),
      "$env:GITHUB_TOKEN = 'ghp_abcdef1234567890abcdef1234567890abcd'\n",
    );

    const result = fixProfiles({
      homeDir: home,
      shell: '',
      platform: 'win32',
      envOverride: {},
      dryRun: true,
    });

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('GITHUB_TOKEN');
    expect(result!.commands![0]).toContain('ghp_abcdef1234567890abcdef1234567890abcd');
  });
});
