import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync, execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';

// A whole-environment print is the costliest single command an agent can run:
// every credential in the shell reaches the conversation at once. The guard
// refused a few spellings of it by matching command text (a bare printenv, a
// bare env, a process listing), and every other shape walked through: a bare
// `set`, `export -p`, `declare -p`, `compgen -v`, a one-liner printing
// os.environ, `docker inspect`, and any of them behind `bash -c`, `eval`, a
// subshell or a pipe. The hook now parses the whole command into the simple
// commands the shell runs and judges each by what it does, and refuses a
// command it cannot parse. These tests pin one cell per shape on each side.
//
// Each check starts bash and python3, so the bound is raised for a loaded
// machine, and no test checks more than about twenty commands.
const hasPython3 = (() => {
  try { execSync('command -v python3', { stdio: 'ignore' }); return true; } catch { return false; }
})();

describe('guard refuses every command shape that prints the environment', { timeout: 60_000 }, () => {
  let dir: string;
  let hookPath: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-envprint-'));
    init(dir);
    hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
  });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  function decide(command: string, env?: NodeJS.ProcessEnv): string | null {
    const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command } });
    const out = execFileSync(bashPath(), [hookPath], { input, encoding: 'utf-8', env: env ?? process.env });
    if (!out.trim()) return null;
    const hso = JSON.parse(out).hookSpecificOutput;
    expect(hso.permissionDecision, `unexpected hook output for ${JSON.stringify(command)}`).toBe('deny');
    return hso.permissionDecisionReason;
  }

  function expectBlocked(commands: string[]): void {
    for (const c of commands) {
      const reason = decide(c);
      expect(reason, `expected BLOCK: ${JSON.stringify(c)}`).not.toBeNull();
      expect(reason, `deny reason must name a safe path for: ${JSON.stringify(c)}`).toMatch(/Safe path: \S/);
    }
  }

  function expectAllowed(commands: string[]): void {
    for (const c of commands) {
      expect(decide(c), `expected ALLOW: ${JSON.stringify(c)}`).toBeNull();
    }
  }

  (hasPython3 ? it : it.skip)('refuses set unless its first word is a literal option that turns on no tracing', () => {
    expectBlocked([
      'set',
      'set "$X"',
      'set $X',
      'set -x',
      'set -o xtrace',
      'set -o',
      'set -e -x',
      'set -eo xtrace',
      'set -a',
      // zsh spells set -x as setopt xtrace.
      'setopt xtrace',
      'setopt ALL_EXPORT',
      'set --',
      'set -- a b',
      'SET',
      '\\set',
      "$'\\x73et'",
    ]);
  });

  (hasPython3 ? it : it.skip)('allows set with a literal option', () => {
    expectAllowed([
      'set -e',
      'set -euo pipefail',
      'set +e',
      'set -o pipefail',
      'set -Eeuo pipefail',
      'set -o errexit -o nounset',
      'setopt pipefail',
    ]);
  });

  (hasPython3 ? it : it.skip)('refuses printenv in every form, env with no program after it, and compgen', () => {
    expectBlocked([
      'printenv',
      'printenv -0',
      'printenv HOME',
      'env',
      'env -u X',
      'env | grep K',
      'env -i',
      'env FOO=1',
      '/usr/bin/printenv',
      'PRINTENV',
      'compgen -v',
      'compgen -A variable',
    ]);
  });

  (hasPython3 ? it : it.skip)('allows env as a prefix that runs a program', () => {
    expectAllowed([
      'env -u X cmd',
      'env FOO=1 cmd',
      '/usr/bin/env node x.js',
      'env -i PATH=/usr/bin:/bin node -e "console.log(1)"',
      'env -C /tmp ls',
      'env -- cmd',
    ]);
  });

  (hasPython3 ? it : it.skip)('refuses export, declare, typeset, local and readonly when they list variables', () => {
    expectBlocked([
      'export',
      'export -p',
      'declare',
      'declare -p',
      'declare -p FOO',
      'declare -f',
      'typeset',
      'typeset -m X',
      'typeset -x',
      'local',
      'readonly -p',
      // zsh prints a set variable for a bare NAME with no option.
      'typeset FOO',
      'declare FOO',
      'local FOO',
      'export "$X"',
    ]);
  });

  (hasPython3 ? it : it.skip)('allows export, declare, typeset, local and readonly as assignments', () => {
    expectAllowed([
      'export FOO=1',
      'export FOO',
      'export FOO="$BAR"',
      'declare -x FOO=1',
      'declare -a arr',
      'declare -a arr=(1 2)',
      'local x=1',
      'readonly X=1',
      'readonly FOO',
      'typeset -g FOO',
    ]);
  });

  (hasPython3 ? it : it.skip)('refuses an interpreter program that names the whole environment', () => {
    expectBlocked([
      "python3 -c 'import os;print(os.environ)'",
      "python3 -c 'print(dict(os.environ))'",
      "node -e 'console.log(process.env)'",
      'node -p process.env',
      "node --eval 'console.log(JSON.stringify(process.env))'",
      "ruby -e 'p ENV'",
      "perl -e 'print %ENV'",
      "perl -lne 'print %ENV'",
      "php -r 'print_r(getenv());'",
      "deno eval 'console.log(Deno.env.toObject())'",
      "awk 'BEGIN{for(k in ENVIRON) print k}'",
      "python3 - <<'EOF'\nimport os; print(os.environ)\nEOF",
      "echo 'console.log(process.env)' | node",
    ]);
  });

  (hasPython3 ? it : it.skip)('allows an interpreter program that reads one variable by name', () => {
    expectAllowed([
      `python3 -c 'import os;print(os.environ.get("HOME"))'`,
      "node -e 'console.log(process.env.HOME)'",
      `node -e 'console.log(process.env["HOME"])'`,
      `ruby -e 'puts ENV["HOME"]'`,
      'python3 -c "import sys; print(sys.version)"',
      'cat file.json | python3 -m json.tool',
      "awk '{print $1}' f",
    ]);
  });

  (hasPython3 ? it : it.skip)('refuses docker inspect without an Env-free format, a container run of env, and tmux show-environment', () => {
    expectBlocked([
      'docker inspect c1',
      "docker inspect --format '{{.Config.Env}}' c1",
      "docker inspect --format '{{json .Config}}' c1",
      'docker exec c1 env',
      'docker exec -it c1 sh -c printenv',
      'docker run --rm -e A=1 img printenv',
      'docker compose exec web env',
      'kubectl exec -it pod -- env',
      'tmux show-environment',
      'tmux showenv -g',
      'launchctl getenv HOME',
    ]);
  });

  (hasPython3 ? it : it.skip)('allows docker, compose and tmux commands that print no environment', () => {
    expectAllowed([
      "docker inspect --format '{{.State.Status}}' c1",
      'docker compose ps web',
      'docker exec c1 ls /',
      'kubectl exec pod -- ls',
      'tmux ls',
    ]);
  });

  (hasPython3 ? it : it.skip)('finds the command wherever the shell runs it', () => {
    expectBlocked([
      "bash -c 'set'",
      'sh -c "printenv"',
      'eval set',
      '$(set)',
      '(set)',
      '{ set; }',
      'x=1; set',
      'true && set',
      'true | set',
      'sudo env',
      'xargs printenv',
      'command set',
      'exec printenv',
      'echo "$(env)"',
      'if true; then set; fi',
      'for x in a; do set; done',
      'time (set)',
      "case x in a) set;; esac",
      "bash <<'EOF'\nset\nEOF",
      "printf 'x\\nprintenv' | sh",
    ]);
  });

  (hasPython3 ? it : it.skip)('refuses a nested shell or a program name it cannot read before it runs', () => {
    expectBlocked([
      'X=set; $X',
      '${CMD:-env}',
      'eval "$(ssh-agent -s)"',
      'bash -c "echo $X; ls"',
      'source <(echo set)',
      'bash -xc "echo hi"',
      'alias e=env',
      "trap 'printenv' EXIT",
      'watch -n 1 set',
      'find . -exec printenv \\;',
      'timeout 5 printenv',
    ]);
  });

  (hasPython3 ? it : it.skip)('allows text that only names those programs, and everyday commands', () => {
    expectAllowed([
      "grep -n 'printenv' src",
      'git commit -m "set the flag"',
      'npm test',
      'env -u GITHUB_TOKEN git push',
      "bash -c 'set -e; npm test'",
      `sh -c 'echo "$1"' _ "$X"`,
      'if [ -n "$X" ]; then echo set; fi',
      'case "$x" in *.ts) echo ts;; *) echo other;; esac',
      'for f in *.ts; do echo "$f"; done',
      "cat > notes.md <<'EOF'\nprintenv and set and env\nEOF",
      `git commit -m "$(cat <<'EOF'\nFix: it's done\nEOF\n)"`,
      'kill $(pgrep -f mk-1)',
      'f() { echo hi; }; f',
      'time (cd /tmp && ls)',
      'echo $((1 + 2))',
      'command -v set',
      "trap 'rm -f \"$tmp\"' EXIT",
    ]);
  });

  (hasPython3 ? it : it.skip)('refuses a command it cannot parse and names the span it could not read', () => {
    for (const c of ["echo 'unbalanced", 'echo "unbalanced', 'echo $(ls', 'echo ${X', 'ls )']) {
      const reason = decide(c);
      expect(reason, `expected BLOCK: ${JSON.stringify(c)}`).not.toBeNull();
      expect(reason).toContain('cannot parse');
      expect(reason).toContain('Unparsed at `');
    }
  });

  (hasPython3 ? it : it.skip)('the deny reason quotes the command and names what it prints', () => {
    const reason = decide('declare -p') as string;
    expect(reason).toContain('Matched `declare -p`');
    expect(reason).toContain('[ -n "$NAME" ]');
    expect(decide("bash -c 'set'")).toContain("Matched `bash -c 'set'`");
    expect(decide('set -x')).toContain('traces each later command with its variables expanded');
  });

  // Without python3 nothing parses the command, so a command that runs one of
  // the programs able to print the environment is refused on its name, with
  // the missing precondition named. The PATH holds the programs the hook
  // calls and no python3.
  it('without python3 a command naming a program that can print the environment is refused', () => {
    const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-envprint-nopy-'));
    try {
      for (const tool of ['bash', 'cat', 'cut', 'grep', 'head', 'sed', 'sort', 'tr', 'basename', 'readlink']) {
        fs.symlinkSync(execSync(`command -v ${tool}`, { encoding: 'utf-8' }).trim(), path.join(bin, tool));
      }
      const env = { PATH: bin, HOME: dir };
      expect(
        () => execSync('command -v python3', { env, shell: path.join(bin, 'bash'), stdio: 'ignore' }),
        'python3 must not be reachable on the test PATH',
      ).toThrow();
      for (const c of [
        'set -e',
        'set',
        'env -u X cmd',
        'printenv HOME',
        'export -p',
        'declare -p',
        'typeset',
        'local x=1',
        'readonly X=1',
        'compgen -v',
        'ps aux',
        'pgrep -f node',
        'tmux ls',
        'docker inspect c1',
        "bash -c 'set'",
        'echo hi\nset',
      ]) {
        const reason = decide(c, env);
        expect(reason, `expected BLOCK without python3: ${JSON.stringify(c)}`).not.toBeNull();
      }
      expect(decide('set -e', env)).toContain('python3 is missing');
      for (const c of ['npm test', 'git commit -m "set the flag"', "grep -n 'printenv' src", 'docker compose ps web']) {
        expect(decide(c, env), `expected ALLOW without python3: ${JSON.stringify(c)}`).toBeNull();
      }
    } finally {
      fs.rmSync(bin, { recursive: true, force: true });
    }
  });
});

function bashPath(): string {
  return execSync('command -v bash', { encoding: 'utf-8' }).trim();
}
