import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync, execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';

// The file-path guard admits committed templates (.env.example, .sample,
// .template, .dist) by name, and the docs say so, but the Bash guard refused
// `cat .env.example`, and it refused `ls -a | grep '^\.env'`, a listing of
// names that opens no file. The analyzer now sets a template operand aside, and
// takes ls as a program that reads no file, only when it parses the whole
// command: no expansion anywhere, every program one that neither runs a
// command nor reads names from its input, the operand literal, without a glob
// or a leading ~, and reached through no symbolic link. These tests pin the
// commands from the report as allowed, the real reads and the derivations as
// refused, and the refusal naming the token that tripped it.
//
// Each check starts bash and python3, so the bound is raised for a loaded machine.
describe('the Bash guard honours the template exemption of the file-path guard', { timeout: 60_000 }, () => {
  let dir: string;
  let hookPath: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-template-'));
    init(dir);
    hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
    fs.writeFileSync(path.join(dir, '.env'), 'API_KEY=real\n');
    fs.writeFileSync(path.join(dir, '.env.example'), 'API_KEY=\n');
  });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  function decide(command: string, env?: NodeJS.ProcessEnv): string | null {
    const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command } });
    const out = execFileSync(bashPath(), [hookPath], {
      input, encoding: 'utf-8', cwd: dir, env: env ?? process.env,
    });
    if (!/"permissionDecision":"deny"/.test(out)) return null;
    return JSON.parse(out).hookSpecificOutput.permissionDecisionReason;
  }

  const hasPython3 = (() => {
    try { execSync('command -v python3', { stdio: 'ignore' }); return true; } catch { return false; }
  })();

  (hasPython3 ? it : it.skip)('allows the four commands from the report', () => {
    for (const c of [
      'cat .env.example',
      'grep -rn "env.example" docs',
      String.raw`ls -a | grep '^\.env'`,
      "cat <<'EOF' > docs/setup.md\nCopy .env.example to .env and fill API_KEY.\nEOF",
    ]) {
      expect(decide(c), `expected ALLOW: ${JSON.stringify(c)}`).toBeNull();
    }
  });

  (hasPython3 ? it : it.skip)('allows a template operand of every suffix, as an argument or a redirection', () => {
    for (const c of [
      'head -n 5 .env.sample',
      'tail config/.env.template',
      'grep KEY .env.dist',
      'cat < .env.example',
      'grep -c KEY .env.example | wc -l',
      'cat ./config/server.key.example',
      'cat .ENV.EXAMPLE',
    ]) {
      expect(decide(c), `expected ALLOW: ${JSON.stringify(c)}`).toBeNull();
    }
  });

  it('still refuses a real secret read, whatever template sits beside it', () => {
    for (const c of [
      'cat .env',
      'echo "$(cat .env)"',
      'cat .env.example .env',
      'cat .env.example && cat .env',
      'cat .env.example.real',
      'cat .env;.example',
    ]) {
      expect(decide(c), `expected BLOCK: ${JSON.stringify(c)}`).not.toBeNull();
    }
  });

  it('refuses a template operand the analyzer cannot vouch for', () => {
    fs.symlinkSync('.env', path.join(dir, 'config.env.example'));
    fs.mkdirSync(path.join(dir, 'real'));
    fs.writeFileSync(path.join(dir, 'real', '.env'), 'API_KEY=real\n');
    fs.symlinkSync('.env', path.join(dir, 'real', 'x.env.example'));
    fs.symlinkSync('real', path.join(dir, 'linked'));
    for (const c of [
      // A link carries any name.
      'cat config.env.example',
      'cat linked/.env.example',
      // A derivation of the real name from the template's.
      'cat "$(basename .env.example .example)"',
      'cat .env.example | xargs cat',
      String.raw`ls -a | grep -x '\.env' | xargs cat`,
      // A glob or a tilde the shell expands.
      'cat .env*.example',
      'cat ~/.env.example',
    ]) {
      expect(decide(c), `expected BLOCK: ${JSON.stringify(c)}`).not.toBeNull();
    }
  });

  it('the refusal names the secret-file token that tripped it', () => {
    const cells: Array<[string, string]> = [
      ['cat .env', '.env'],
      ['cat .env.example .env', '.env'],
      ['cat .envelope prod.env', 'prod.env'],
      ['head -5 config/server.key', 'config/server.key'],
    ];
    for (const [c, token] of cells) {
      const reason = decide(c);
      expect(reason, `expected BLOCK: ${c}`).not.toBeNull();
      expect(reason, `the reason must name the token for: ${c}`)
        .toContain('a reader verb, then `' + token + '`, a secret-file name');
    }
  });

  // Without python3 nothing is parsed, so a template read is matched on its
  // text and refused as before.
  it('without python3 a template read is still refused', () => {
    const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-template-nopy-'));
    try {
      for (const tool of ['cat', 'grep', 'head', 'cut', 'sed', 'sort', 'basename', 'tr', 'tail', 'readlink']) {
        const real = execSync(`command -v ${tool}`, { encoding: 'utf-8' }).trim();
        fs.symlinkSync(real, path.join(bin, tool));
      }
      const env = { PATH: bin, HOME: dir };
      expect(decide('ls -la', env)).toBeNull();
      expect(decide('cat .env.example', env)).not.toBeNull();
    } finally {
      fs.rmSync(bin, { recursive: true, force: true });
    }
  });
});

function bashPath(): string {
  return execSync('command -v bash', { encoding: 'utf-8' }).trim();
}
