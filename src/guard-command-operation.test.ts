import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync, execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';

// The generated guard's Bash arms match command TEXT. They refused commands that
// only carry a secret-file token and open nothing: a count-only grep whose
// pattern names `.env` inside a JavaScript regex, a grep for the shell-hook line,
// and a heredoc that writes a note mentioning a shell rc file and `.env`. The hook
// now drops a plain grep's pattern and a heredoc's body before the arms run, and
// only when it understands the whole command. These tests pin both halves: the
// three refused shapes are allowed, and every command that opens a secret file,
// or could turn the dropped text back into a filename, is still refused.
//
// Each check starts bash and python3, so the bound is raised for a loaded machine
// (same reasoning as the `init` suite).
describe('guard keys on the file a command opens, not on text it only carries', { timeout: 60_000 }, () => {
  let dir: string;
  let hookPath: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-op-'));
    init(dir);
    hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
  });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  function decide(command: string, env?: NodeJS.ProcessEnv): string | null {
    const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command } });
    const out = execFileSync(bashPath(), [hookPath], { input, encoding: 'utf-8', env: env ?? process.env });
    if (!/"permissionDecision":"deny"/.test(out)) return null;
    return JSON.parse(out).hookSpecificOutput.permissionDecisionReason;
  }

  const hasPython3 = (() => {
    try { execSync('command -v python3', { stdio: 'ignore' }); return true; } catch { return false; }
  })();

  // The three shapes from the report, each refused before this change.
  const countOnlyGrepOnDotfileRegex = String.raw`grep -c '/\.env(\.local)?$/' src/init.ts`;
  const grepForShellHookLine = `grep -c 'eval "$(secretless-ai env)"' src/setup.ts`;
  const heredocWritingANote = [
    "cat > notes/unit.md <<'EOF'",
    '# Guard follow-up',
    'The shell hook is appended to ~/.zshrc; reading more of .env than needed is the risk.',
    'Do not run `cat ~/.ssh/id_rsa` or printenv here.',
    'EOF',
  ].join('\n');

  (hasPython3 ? it : it.skip)('allows a count-only grep whose pattern names a dotfile inside a regex', () => {
    for (const c of [
      countOnlyGrepOnDotfileRegex,
      'grep -rn "dotenv(.env)" src',
      String.raw`grep -c '\.pem' src/tls.ts`,
      String.raw`grep -rl '\.env' src | wc -l`,
      String.raw`grep -rn --include=*.ts -e '\.env' -e '\.key' src`,
    ]) {
      expect(decide(c), `expected ALLOW: ${c}`).toBeNull();
    }
  });

  (hasPython3 ? it : it.skip)('allows a grep whose pattern is the shell-hook command', () => {
    for (const c of [grepForShellHookLine, 'grep -n "secretless-ai env" README.md']) {
      expect(decide(c), `expected ALLOW: ${c}`).toBeNull();
    }
  });

  (hasPython3 ? it : it.skip)('allows a heredoc that only writes text naming a shell rc file and secret files', () => {
    for (const c of [
      heredocWritingANote,
      "tee notes/b.md <<'EOF' >/dev/null\nthen cat .env and head server.key\nEOF",
      'cat > notes/c.md <<EOF\nmore of .env than needed\nEOF',
    ]) {
      expect(decide(c), `expected ALLOW: ${c}`).toBeNull();
    }
  });

  it('still refuses a real read of a secret file', () => {
    for (const c of [
      'cat .env',
      'grep -c x .env',
      String.raw`grep -c '\.env' .env`,
      'grep -c x < .env',
      String.raw`grep -e '\.env' .env`,
      'head -5 prod.env',
      'cat .env.example',
      `${countOnlyGrepOnDotfileRegex} && cat .env`,
      `${heredocWritingANote}\ncat .env`,
      'secretless-ai env',
    ]) {
      expect(decide(c), `expected BLOCK: ${c}`).not.toBeNull();
    }
  });

  // The data-directory arm refuses any command that names the directory unless
  // the whole command is one plain secretless-ai invocation, and it reads the full
  // command: a search for the directory name and a heredoc that names it are
  // refused although the analyzer understands both.
  it('the data-directory arm still reads the whole command', () => {
    for (const c of [
      String.raw`grep -rn "\.secretless-ai" src`,
      "cat > notes/d.md <<'EOF'\nthe store lives in ~/.secretless-ai\nEOF",
    ]) {
      const reason = decide(c);
      expect(reason, `expected BLOCK: ${c}`).not.toBeNull();
      expect(reason).toMatch(/secretless data directory/);
    }
  });

  // Each of these could turn the pattern or the heredoc body back into a file the
  // command opens, or depends on parsing the analyzer does not attempt. All were
  // refused before the change and must stay refused.
  it('still refuses a command that could reuse the dropped text as a filename', () => {
    for (const c of [
      String.raw`grep -o '\.env' notes.md | xargs cat`,
      String.raw`ls -a | grep -x '\.env' | xargs cat`,
      String.raw`grep -c '\.env' src/a.ts; cat "$_"`,
      String.raw`grep -c '\.env' "$(echo src/a.ts)"`,
      'grep -c .env* src/a.ts',
      'grep -c {x,.env} src/a.ts',
      'grep -c x -e .env',
      'POSIXLY_CORRECT=1 grep x -e .env',
      String.raw`grep --rege='\.x' .env`,
      String.raw`grep -C '\.x' .env`,
      'grep -c "1">x .env',
      'grep <1-5> pat .env',
      String.raw`git grep -n "dotenv(.env)"`,
      'cat > notes.md <<EOF\n$(cat .env)\nEOF',
      "cat > x.sh <<'EOF'\ncat .env\nEOF\nsh x.sh",
      "bash <<'EOF'\ncat .env\nEOF",
      "cat <<'EOF' | sh\ncat .env\nEOF",
      String.raw`grep -h 'cat \.env' notes.md | sort --files0-from=-`,
    ]) {
      expect(decide(c), `expected BLOCK: ${c}`).not.toBeNull();
    }
  });

  // Without python3 nothing is reduced, so the guard falls back to matching the
  // whole command and refuses the pattern-only shapes as it always did. (That
  // fallback extracts the command with a grep that stops at the first embedded
  // double quote, so the shell-hook shape is spelled here without one.)
  it('without python3 the pattern-only shapes are refused, not let through', () => {
    const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-nopy-'));
    try {
      for (const tool of ['cat', 'grep', 'head', 'cut', 'sort', 'basename', 'tr']) {
        const real = execSync(`command -v ${tool}`, { encoding: 'utf-8' }).trim();
        fs.symlinkSync(real, path.join(bin, tool));
      }
      const env = { PATH: bin, HOME: dir };
      expect(decide('ls -la', env)).toBeNull();
      for (const c of [countOnlyGrepOnDotfileRegex, "grep -n 'secretless-ai env' README.md", heredocWritingANote]) {
        expect(decide(c, env), `expected BLOCK without python3: ${c}`).not.toBeNull();
      }
    } finally {
      fs.rmSync(bin, { recursive: true, force: true });
    }
  });
});

function bashPath(): string {
  return execSync('command -v bash', { encoding: 'utf-8' }).trim();
}
