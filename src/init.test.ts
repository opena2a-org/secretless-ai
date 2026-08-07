import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init, DEPRECATED_DENY_RULES } from './init';
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

    // Settings file has deny rules. Env files are enumerated (not a broad `.env*`
    // glob) so committed template files like `.env.example` stay readable — see the
    // dedicated "env template" describe block below.
    const settings = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8'));
    expect(settings.permissions.deny).toContain('Read(.env)');
    expect(settings.permissions.deny).toContain('Read(.env.local)');
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

    // Regression: a custom wildcard file rule (`private*`) must keep glob semantics in the
    // generated hook. Single-quoting the fragment turned `*` literal and silently neutered
    // the rule, so `private_key.txt` was allowed despite the user asking to block it.
    // Any project with `env:` or `bash:` rules generated a hook whose last
    // custom block ended `  fi  exit 0` on one line — not valid bash. The hook
    // exited 2 on every tool call, for every tool. `files:`-only rules produce
    // an empty block string and so never hit it, which is exactly why the
    // pre-existing `bash -n` test below never caught it.
    it('generates valid bash for env: and bash: custom rules, not just files:', () => {
      fs.writeFileSync(
        path.join(dir, '.secretless-rules.yaml'),
        'env:\n  - MY_CUSTOM_TOKEN\nbash:\n  - mytool-dump\n',
      );
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

      // Guard the fixture itself: if the rules were rejected by the validator
      // they never reach the hook and this test proves nothing.
      const script = fs.readFileSync(hookPath, 'utf-8');
      expect(script, 'custom rules must actually reach the generated hook').toContain('MY_CUSTOM_TOKEN');
      expect(script).toContain('mytool-dump');

      execSync(`bash -n ${JSON.stringify(hookPath)}`);

      // And it must actually run: a benign command exits 0, not 2.
      const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls -la' } });
      const out = execSync(`bash ${JSON.stringify(hookPath)}`, { input, encoding: 'utf-8' });
      expect(/"permissionDecision":"deny"/.test(out)).toBe(false);
    });

    it('honors custom wildcard file rules (private*) in the generated case glob', () => {
      fs.writeFileSync(path.join(dir, '.secretless-rules.yaml'), 'files:\n  - "private*"\n');
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

      // Generated hook must be syntactically valid bash (no quote/glob breakout).
      execSync(`bash -n ${JSON.stringify(hookPath)}`);

      expect(runHook(hookPath, 'private_key.txt')).toBe(true);
      expect(runHook(hookPath, 'myprivatestuff')).toBe(true);
      expect(runHook(hookPath, 'normalfile.txt')).toBe(false);
    });
  });

  // Committed template files (`.env.example`, `config.sample`, etc.) hold placeholders,
  // not real secrets, and must stay readable/editable/committable. They were previously
  // blocked by the broad `.env*` deny glob + the hook's `.env.*` dotfile arm. This guards
  // all three generated layers: deny rules, the guard hook, and the .aiderignore.
  describe('env template files (.env.example etc.) are exempt', () => {
    function runHook(hookPath: string, filePath: string): boolean {
      const input = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: filePath } });
      const out = execSync(`bash ${JSON.stringify(hookPath)}`, { input, encoding: 'utf-8' });
      return /"permissionDecision":"deny"/.test(out);
    }

    it('generated hook allows template files but still blocks real env/secret files', () => {
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

      const mustAllow = [
        '.env.example', '.env.sample', '.env.template', '.env.dist',
        '.env.local.example', 'config/.env.example', 'database.yml.sample',
        '.ENV.EXAMPLE', // case-insensitive
      ];
      for (const f of mustAllow) {
        expect(runHook(hookPath, f), `expected hook to ALLOW template ${f}`).toBe(false);
      }

      const mustBlock = ['.env', '.env.local', '.env.production', 'prod.env', 'id_rsa.pem'];
      for (const f of mustBlock) {
        expect(runHook(hookPath, f), `expected hook to BLOCK real secret ${f}`).toBe(true);
      }
    });

    it('generated deny rules enumerate real env files and drop the broad .env* glob', () => {
      init(dir);
      const settings = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8'));
      const deny: string[] = settings.permissions.deny;

      // Broad globs that would also catch templates must be gone.
      expect(deny).not.toContain('Read(.env*)');
      expect(deny).not.toContain('Grep(*.env*)');

      // Real env files are enumerated for both Read and Grep.
      for (const r of [
        'Read(.env)', 'Read(.env.local)', 'Read(.env.*.local)',
        'Read(.env.development)', 'Read(.env.production)', 'Read(.env.staging)', 'Read(.env.test)',
        'Grep(.env)', 'Grep(.env.production)',
      ]) {
        expect(deny, `expected deny rule ${r}`).toContain(r);
      }
    });

    it('generated .aiderignore un-ignores template files so they stay committable', () => {
      fs.writeFileSync(path.join(dir, '.aider.conf.yml'), ''); // trigger aider detection
      init(dir);
      const ignore = fs.readFileSync(path.join(dir, '.aiderignore'), 'utf-8');
      expect(ignore).toContain('.env.*');
      for (const neg of ['!.env.example', '!.env.sample', '!.env.template', '!.env.dist']) {
        expect(ignore, `expected ${neg}`).toContain(neg);
      }
    });
  });

  // Release-test 2026-07-16 P1: `secretless-ai env` prints every stored secret as
  // plaintext export statements. `secret get` is TTY-guarded and `run -- env` was
  // already denied, but the direct `env` command had neither a deny rule nor a
  // guard-hook arm — an agent inside a "protected" project could exfiltrate the
  // entire machine-global store with one documented command. Both generated
  // layers must block it. (The command stays available to the user's shell
  // profile eval hook, which never executes through the agent.)
  describe('agent cannot dump the store via `secretless-ai env`', () => {
    function runHookCmd(hookPath: string, command: string): boolean {
      const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command } });
      const out = execSync(`bash ${JSON.stringify(hookPath)}`, { input, encoding: 'utf-8' });
      return /"permissionDecision":"deny"/.test(out);
    }

    it('deny rules include the env store-dump rule', () => {
      init(dir);
      const settings = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8'));
      expect(settings.permissions.deny).toContain('Bash(*secretless-ai env*)');
    });

    it('generated hook blocks env dump forms and allows legitimate commands', () => {
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

      const mustBlock = [
        'secretless-ai env',
        'secretless-ai env --only STRIPE_SECRET_KEY',
        'npx secretless-ai env',
      ];
      for (const c of mustBlock) {
        expect(runHookCmd(hookPath, c), `expected hook to BLOCK: ${c}`).toBe(true);
      }

      const mustAllow = [
        'secretless-ai run --only STRIPE_SECRET_KEY -- node app.js',
        'secretless-ai verify',
        'secretless-ai scan .',
        'secretless-ai secret list',
      ];
      for (const c of mustAllow) {
        expect(runHookCmd(hookPath, c), `expected hook to ALLOW: ${c}`).toBe(false);
      }
    });

    // The Bash branch of the hook was entirely dead before the release-test fix:
    // every Bash command died at the FILE_PATH extraction under `set -euo
    // pipefail` (grep found no file_path, returned non-zero) before reaching any
    // command guard. This asserts the branch is now REACHABLE — a pre-existing
    // guard (`cat .env`) must fire, and a benign command must exit cleanly. On the
    // pre-fix hook, `runHookCmd` throws because the script exits non-zero.
    it('Bash branch is reachable: pre-existing file-read guard fires, benign command exits 0', () => {
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

      expect(runHookCmd(hookPath, 'cat .env'), 'expected hook to BLOCK `cat .env`').toBe(true);
      expect(runHookCmd(hookPath, 'ls -la'), 'expected hook to ALLOW `ls -la`').toBe(false);
    });

    // The command guard and the file-path guard disagreed about template files:
    // `Read(.env.example)` was allowed while `cat .env.example` was refused, so
    // ordinary work on committed placeholder files was blocked by one layer and
    // permitted by the other. The command guard now drops path tokens whose FINAL
    // suffix is a template suffix before applying the secret-file patterns.
    //
    // The anchoring is the whole security argument. `.env.example.real` ends in
    // `.real`, not a template suffix, so it survives the scrub and still blocks;
    // and because the scrub works per path token rather than per command, a
    // template mentioned anywhere in the command cannot whitelist a real secret
    // read elsewhere in the same command.
    // The hook extracted tool_name / file_path with greps that require COMPACT
    // JSON ('"tool_name":"Bash"'). A pretty-printed payload left both empty, so
    // the Bash branch and the file guard were skipped and every guard failed
    // OPEN. Same dead-branch class as the 2026-07-16 FILE_PATH regression,
    // reached through payload formatting instead of `set -euo pipefail`.
    describe('guards do not depend on the payload being compact JSON', () => {
      function runHookRaw(hookPath: string, input: string): boolean {
        const out = execSync(`bash ${JSON.stringify(hookPath)}`, { input, encoding: 'utf-8' });
        return /"permissionDecision":"deny"/.test(out);
      }

      it('blocks a secret read when the payload is pretty-printed', () => {
        init(dir);
        const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

        const pretty = JSON.stringify(
          { tool_name: 'Bash', tool_input: { command: 'cat .env' } },
          null,
          2,
        );
        expect(pretty, 'fixture must actually be pretty-printed').toMatch(/"tool_name": "Bash"/);
        expect(
          runHookRaw(hookPath, pretty),
          'a pretty-printed payload must not bypass the command guard',
        ).toBe(true);
      });

      it('blocks a secret file read when the payload is pretty-printed', () => {
        init(dir);
        const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

        const pretty = JSON.stringify(
          { tool_name: 'Read', tool_input: { file_path: '/tmp/project/.env' } },
          null,
          2,
        );
        expect(
          runHookRaw(hookPath, pretty),
          'a pretty-printed payload must not bypass the file-path guard',
        ).toBe(true);
      });

      it('allows a benign command when the payload is pretty-printed', () => {
        init(dir);
        const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

        const pretty = JSON.stringify(
          { tool_name: 'Bash', tool_input: { command: 'ls -la' } },
          null,
          2,
        );
        expect(runHookRaw(hookPath, pretty)).toBe(false);
      });

      it('allows a template file read through the FILE guard when pretty-printed', () => {
        init(dir);
        const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

        // The file guard exempts templates; the COMMAND guard deliberately does
        // not (see the revert note in init.ts). This asserts the file-guard half
        // still works once the payload parses.
        const pretty = JSON.stringify(
          { tool_name: 'Read', tool_input: { file_path: '/p/.env.example' } },
          null,
          2,
        );
        expect(runHookRaw(hookPath, pretty)).toBe(false);
      });
    });

    // A template exemption in the COMMAND guard was implemented, then reverted:
    // subtracting template-suffixed tokens from the command text is a credential
    // bypass, because the command can rebuild the real path from the token that
    // was deleted. These cases lock that the guard stays closed.
    describe('the command guard must not be weakened by template names', () => {
      it('blocks a command that derives a real secret path from a template name', () => {
        init(dir);
        const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

        const mustBlock = [
          'cat "$(basename .env.example .example)"',
          'cat "$(printf %s .env.example | cut -d. -f1-2)"',
          'head "$(basename .env.example .example)"',
          'cat "$(basename server.key.example .example)"',
          'python3 -c "print(open(\'.env.example\'.replace(\'.example\',\'\')).read())"',
        ];
        for (const c of mustBlock) {
          expect(
            runHookCmd(hookPath, c),
            `a command that reconstructs a real secret path must stay BLOCKED: ${c}`,
          ).toBe(true);
        }
      });

      it('still blocks direct secret reads', () => {
        init(dir);
        const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

        for (const c of [
          'cat .env',
          'cat .env.local',
          'cat .env.production',
          'cat prod.env',
          'cat server.key',
          'cat id_rsa.pem',
          'cat .env.example && cat .env',
          'cat .env;.example',
        ]) {
          expect(runHookCmd(hookPath, c), `expected hook to BLOCK: ${c}`).toBe(true);
        }
      });
    });

    // The structured parse must not NARROW the older whole-payload grep: a
    // secret path nested below the documented top-level fields (MultiEdit-style
    // edit lists, MCP tool payloads) has to be seen too.
    describe('every candidate path in the payload is checked', () => {
      function runHookRaw(hookPath: string, input: string): boolean {
        const out = execSync(`bash ${JSON.stringify(hookPath)}`, { input, encoding: 'utf-8' });
        return /"permissionDecision":"deny"/.test(out);
      }

      it('blocks a secret path nested under a benign top-level path', () => {
        init(dir);
        const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

        const nested = JSON.stringify({
          tool_name: 'Edit',
          tool_input: { path: 'README.md', edits: [{ file_path: '/project/.env' }] },
        });
        expect(
          runHookRaw(hookPath, nested),
          'a nested secret path must not be masked by a benign top-level path',
        ).toBe(true);
      });

      it('does not block when every candidate is benign', () => {
        init(dir);
        const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

        const benign = JSON.stringify({
          tool_name: 'Edit',
          tool_input: { path: 'README.md', edits: [{ file_path: '/project/src/index.ts' }] },
        });
        expect(runHookRaw(hookPath, benign)).toBe(false);
      });

      it('does not block when the only candidate is a template file', () => {
        init(dir);
        const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

        const tpl = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/p/.env.example' } });
        expect(runHookRaw(hookPath, tpl)).toBe(false);
      });

      it('blocks a non-string field without letting it suppress the real path', () => {
        init(dir);
        const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

        const odd = JSON.stringify({
          tool_name: 'Read',
          tool_input: { path: 123, edits: [{ file_path: '/project/.env' }] },
        });
        expect(runHookRaw(hookPath, odd)).toBe(true);
      });
    });
  });

  // Issue #99: two guard-hook / deny-rule gaps found by adversarial review of the
  // env fix. The tool-level agent-runtime gate is the primary enforcement; these
  // harden the best-effort Claude-layer.
  describe('guard-hook hardening (#99)', () => {
    const hasPython3 = (() => {
      try { execSync('command -v python3', { stdio: 'ignore' }); return true; } catch { return false; }
    })();

    function runHookCmd(hookPath: string, command: string): boolean {
      const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command } });
      const out = execSync(`bash ${JSON.stringify(hookPath)}`, { input, encoding: 'utf-8' });
      return /"permissionDecision":"deny"/.test(out);
    }

    // The old grep `"command":"[^"]*"` truncated at the first embedded quote, so a
    // command with a quote before the dangerous part evaded every guard. With a
    // real JSON parser the full command is inspected. Gated on python3 (the robust
    // path); on a host without it the hook falls back to the truncating grep and
    // the native deny rules remain the enforcing layer.
    (hasPython3 ? it : it.skip)('a quote before a secret-read no longer evades the hook', () => {
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

      // Each pairs a benign quoted prefix with a real secret-read; pre-fix these
      // were truncated at the first `"` and allowed.
      const mustBlock = [
        'x="" ; cat .env',
        'eval "$(secretless-ai env)"',
        'echo ""; secretless-ai secret get X --force',
        'echo "starting"; cat config.pem',
      ];
      for (const c of mustBlock) {
        expect(runHookCmd(hookPath, c), `expected hook to BLOCK: ${c}`).toBe(true);
      }

      // A quote in a genuinely benign command must still be allowed.
      const mustAllow = [
        'echo "hello world"',
        'git commit -m "improve the env parser"',
        'node -e "console.log(1+1)"',
      ];
      for (const c of mustAllow) {
        expect(runHookCmd(hookPath, c), `expected hook to ALLOW: ${c}`).toBe(false);
      }
    });

    // Fail CLOSED: a command whose value contains a lone surrogate made the old
    // `sys.stdout.write` raise (swallowed -> empty COMMAND -> every guard
    // skipped). surrogatepass + a grep fallback on empty output keep the secret
    // read visible. Works on both the python and grep paths, so not gated.
    it('a lone surrogate in the command does not fail the guard open', () => {
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
      // '\uD800' is a lone high surrogate — valid in a JSON string, unencodable
      // as strict UTF-8.
      expect(runHookCmd(hookPath, 'cat .env \uD800'), 'expected BLOCK despite lone surrogate').toBe(true);
    });

    // The hook's env-var arm used to anchor the secret word immediately after the
    // `$`, so it only ever caught the bare `$API_KEY` form. Every variable name
    // anyone actually uses carries a prefix, and all of them walked straight past
    // it while the native deny globs (`echo $*API_KEY*`) were already catching
    // them. The two layers disagreed and the hook was the weaker one.
    it('echo/printenv of a PREFIXED secret variable is blocked', () => {
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

      const mustBlock = [
        // Every one of these was ALLOWED before the fix.
        'echo $ANTHROPIC_API_KEY',
        'echo $OPENAI_API_KEY',
        'echo $GITHUB_TOKEN',
        'echo $SENDGRID_API_KEY',
        'echo $AWS_SECRET_ACCESS_KEY',
        'echo $DATABASE_URL',
        'echo ${GITHUB_TOKEN}',
        'echo "value:" $GITHUB_TOKEN',
        // A separator resets the span, but a fresh echo after it still matches.
        'echo "starting"; echo $ANTHROPIC_API_KEY',
        'printenv ANTHROPIC_API_KEY',
        'printenv DATABASE_URL',
        'printenv',
        'echo done; printenv',
        // The unprefixed forms that already worked must keep working.
        'echo $API_KEY',
        'echo $SECRET',
        'echo $TOKEN',
      ];
      for (const c of mustBlock) {
        expect(runHookCmd(hookPath, c), `expected hook to BLOCK: ${c}`).toBe(true);
      }

      const mustAllow = [
        'echo $HOME',
        'echo $PATH',
        'echo "building the api"',
        'printenv PATH',
        'printenv HOME',
        // Passing a secret to a program is the intended way to use one. An echo
        // earlier in the same line must not condemn a later, unrelated command.
        'echo "starting"; curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" https://api.anthropic.com/v1/models',
        'echo "deploying" && vercel deploy --token $VERCEL_TOKEN',
        'echo done | tee log; psql "$DATABASE_URL" -c "select 1"',
        // `env` as a prefix command is legitimate and must not be caught by the
        // bare-printenv arm.
        'env -u GITHUB_TOKEN git push',
        'npm run build',
      ];
      for (const c of mustAllow) {
        expect(runHookCmd(hookPath, c), `expected hook to ALLOW: ${c}`).toBe(false);
      }
    });

    // `.key` used to match `.keys()`, so ordinary work was refused as if it
    // were reading a private key. A guard that blocks the day job gets switched
    // off, which is the real security cost.
    it('a secret file extension must end there, not merely appear', () => {
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');

      const mustAllow = [
        'python3 -c "import json; d=json.load(open(\'package.json\')); print(d.keys())"',
        'node -e "console.log(Object.keys(process.versions))"',
        'grep -rn "keychain" src/',
        'cat notes.keynote',
        'sed -n 1p envelope.txt',
      ];
      for (const c of mustAllow) {
        expect(runHookCmd(hookPath, c), `expected hook to ALLOW: ${c}`).toBe(false);
      }

      // The real thing must still be caught, including the dotted suffix form.
      const mustBlock = [
        'cat .env',
        'cat .env.local',
        'cat server.key',
        'grep -n secret id_rsa.pem',
        'python3 -c "print(open(\'.env\').read())"',
        'node -e "require(\'fs\').readFileSync(\'server.key\')"',
      ];
      for (const c of mustBlock) {
        expect(runHookCmd(hookPath, c), `expected hook to BLOCK: ${c}`).toBe(true);
      }
    });

    it('deny rules cover the same prefixed variables as the hook', () => {
      init(dir);
      const settings = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8'));
      for (const rule of [
        'Bash(echo $*API_KEY*)',
        'Bash(echo $*PRIVATE_KEY*)',
        'Bash(echo $*ACCESS_KEY*)',
        'Bash(echo $*DATABASE_URL*)',
        'Bash(printenv *PASSWORD*)',
        'Bash(printenv *CREDENTIAL*)',
        'Bash(printenv)',
      ]) {
        expect(settings.permissions.deny, `missing deny rule ${rule}`).toContain(rule);
      }
    });

    // `env` as a whole subcommand terminated by `)` (in `$(secretless-ai env)`),
    // `;`, `|`, or a quote — but `environment` must not match.
    it('env subcommand is caught at non-identifier boundaries, not in "environment"', () => {
      init(dir);
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
      expect(runHookCmd(hookPath, 'secretless-ai env;echo done')).toBe(true);
      expect(runHookCmd(hookPath, 'secretless-ai env|tee dump')).toBe(true);
      expect(runHookCmd(hookPath, 'echo improve secretless-ai environment')).toBe(false);
    });

    // vault exec injects a namespace credential into the child; `-- env`/`-- printenv`
    // would print it. Same shape as the already-denied `run -- env`.
    it('vault exec -- env/printenv is blocked by deny rule and hook arm', () => {
      init(dir);
      const settings = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8'));
      expect(settings.permissions.deny).toContain('Bash(*secretless-ai vault exec*-- env*)');
      expect(settings.permissions.deny).toContain('Bash(*secretless-ai vault exec*-- printenv*)');

      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
      expect(runHookCmd(hookPath, 'secretless-ai vault exec myns -- env')).toBe(true);
      expect(runHookCmd(hookPath, 'secretless-ai vault exec myns -- printenv')).toBe(true);
      // Legitimate vault exec of a real program must still pass — including
      // env-PREFIXED programs (the word boundary keeps `env` whole so `envsubst`
      // and `environment-check` are not caught). Same boundary on the run arm.
      expect(runHookCmd(hookPath, 'secretless-ai vault exec myns -- curl https://api.example.com')).toBe(false);
      expect(runHookCmd(hookPath, 'secretless-ai vault exec myns -- envsubst tpl.conf')).toBe(false);
      expect(runHookCmd(hookPath, 'secretless-ai run --only X -- envsubst tpl.conf')).toBe(false);
    });
  });

  // Older `init` was additive-only: it appended new deny rules and only wrote
  // the guard hook when absent. So upgrading the CLI did NOT migrate an existing
  // `.claude/settings.json` — the broad `.env*` glob and a stale hook survived,
  // re-blocking `.env.example` while `init` reported "Already up to date". These
  // tests pin the migration: prune deprecated rules + refresh the hook on re-run.
  describe('migration: re-running init upgrades an older config', () => {
    function runHook(hookPath: string, filePath: string): boolean {
      const input = JSON.stringify({ tool_name: 'Read', tool_input: { file_path: filePath } });
      const out = execSync(`bash ${JSON.stringify(hookPath)}`, { input, encoding: 'utf-8' });
      return /"permissionDecision":"deny"/.test(out);
    }

    function seedStaleConfig(): void {
      const claudeDir = path.join(dir, '.claude');
      fs.mkdirSync(path.join(claudeDir, 'hooks'), { recursive: true });
      fs.writeFileSync(path.join(claudeDir, 'settings.json'), JSON.stringify({
        permissions: { deny: ['Read(.env*)', 'Grep(*.env*)', 'Read(*.key)'] },
      }, null, 2));
      // A stale managed hook: real content but missing the template-exempt arm.
      fs.writeFileSync(path.join(claudeDir, 'hooks', 'secretless-guard.sh'),
        '#!/usr/bin/env bash\n# old stale guard hook\nexit 0\n', { mode: 0o755 });
    }

    it('prunes deprecated broad-glob deny rules and reports the count', () => {
      seedStaleConfig();
      const result = init(dir);

      const deny: string[] = JSON.parse(
        fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8'),
      ).permissions.deny;

      for (const dep of DEPRECATED_DENY_RULES) {
        expect(deny, `deprecated rule ${dep} should be pruned`).not.toContain(dep);
      }
      // Enumerated replacements are present (prune never leaves env unprotected).
      expect(deny).toContain('Read(.env)');
      expect(deny).toContain('Read(*.env)');
      expect(result.denyRulesRemoved).toBe(2);
      expect(result.filesModified).toContain('.claude/settings.json');
    });

    it('refreshes a stale managed guard hook in place', () => {
      seedStaleConfig();
      const hookPath = path.join(dir, '.claude', 'hooks', 'secretless-guard.sh');
      const before = fs.readFileSync(hookPath, 'utf-8');

      const result = init(dir);

      const after = fs.readFileSync(hookPath, 'utf-8');
      expect(after).not.toBe(before);
      expect(result.hookRefreshed).toBe(true);
      expect(result.filesModified).toContain('.claude/hooks/secretless-guard.sh');
      // The refreshed hook now exempts templates and still blocks real env files.
      expect(runHook(hookPath, '.env.example')).toBe(false);
      expect(runHook(hookPath, '.env')).toBe(true);
    });

    it('migrated config equals a config initialized fresh', () => {
      seedStaleConfig();
      init(dir);
      const migrated = new Set<string>(
        JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8')).permissions.deny,
      );

      const fresh = tmpDir();
      try {
        init(fresh);
        const pristine = new Set<string>(
          JSON.parse(fs.readFileSync(path.join(fresh, '.claude', 'settings.json'), 'utf-8')).permissions.deny,
        );
        expect(migrated).toEqual(pristine);
      } finally {
        cleanup(fresh);
      }
    });

    it('is a no-op on an already-current config (no churn on re-run)', () => {
      init(dir);                 // first run: now current
      const result = init(dir);  // second run
      expect(result.denyRulesRemoved).toBe(0);
      expect(result.denyRulesAdded).toBe(0);
      expect(result.hookRefreshed).toBe(false);
      expect(result.filesModified).not.toContain('.claude/settings.json');
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

  // #122. `init` used to collapse "absent" and "present but unparseable" into
  // the same `null`, turn it into `{}`, and write a Secretless-only document
  // over the user's file — every key gone, no backup — while reporting
  // "added 96 deny patterns". These tests pin both directions: a file we CAN
  // merge into is still merged and preserved, and a file we cannot is left
  // byte-identical and reported as a failure.
  describe('a settings.json we cannot merge into is never overwritten (#122)', () => {
    const settingsPath = (): string => path.join(dir, '.claude', 'settings.json');

    function seed(content: string): string {
      fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
      fs.writeFileSync(settingsPath(), content);
      return content;
    }

    // The trigger from the field: JSONC, i.e. what VS Code writes and what
    // people hand-edit into Claude Code settings.
    const JSONC = `{
  // Team-wide settings - do not delete
  "model": "opus",
  "permissions": {
    "allow": ["Bash(npm test:*)"],
    "deny": ["Read(prod-secrets.json)"],
  },
  "statusLine": { "type": "command", "command": "./sl.sh" }
}`;

    // Every top-level shape that is valid JSON but not a mergeable object.
    // Each reached a distinct failure before the fix: `null` took the same
    // overwrite path as a parse error; an array had its assigned properties
    // silently dropped by JSON.stringify, so init reported 96 deny patterns
    // added and wrote back an array holding none; a string threw a raw
    // TypeError ("Cannot create property 'hooks' on string") at the user.
    const NON_OBJECT: Array<[string, string]> = [
      ['null', 'null'],
      ['an array', '["model", "statusLine"]'],
      ['a string', '"myCustomKey"'],
      ['a number', '42'],
    ];

    it('preserves every user key when the file IS valid JSON', () => {
      seed(JSON.stringify({
        model: 'opus',
        myCustomKey: 1,
        permissions: { allow: ['Bash(npm test:*)'], deny: ['Read(prod-secrets.json)'] },
        statusLine: { type: 'command', command: './sl.sh' },
      }, null, 2));

      const result = init(dir);
      const after = JSON.parse(fs.readFileSync(settingsPath(), 'utf-8'));

      expect(result.settingsUnusable).toBeUndefined();
      expect(after.model).toBe('opus');
      expect(after.myCustomKey).toBe(1);
      expect(after.statusLine).toEqual({ type: 'command', command: './sl.sh' });
      expect(after.permissions.allow).toContain('Bash(npm test:*)');
      // The user's own deny entry survives alongside the ones we add.
      expect(after.permissions.deny).toContain('Read(prod-secrets.json)');
      expect(after.permissions.deny).toContain('Read(.env)');
      expect(result.denyRulesAdded).toBeGreaterThan(0);
      expect(result.filesModified).toContain('.claude/settings.json');
    });

    it('leaves a JSONC settings.json byte-identical instead of clobbering it', () => {
      const before = seed(JSONC);

      const result = init(dir);

      expect(fs.readFileSync(settingsPath(), 'utf-8')).toBe(before);
      expect(result.settingsUnusable?.path).toBe('.claude/settings.json');
      // Every user key is still there, in the original text.
      for (const marker of ['"model": "opus"', 'Bash(npm test:*)', 'Read(prod-secrets.json)', 'statusLine']) {
        expect(fs.readFileSync(settingsPath(), 'utf-8')).toContain(marker);
      }
    });

    it('does not report deny patterns it did not add', () => {
      seed(JSONC);

      const result = init(dir);

      // The reported line is the aggravating half of #122: "added 96 deny
      // patterns" told the user an additive merge had happened.
      expect(result.denyRulesAdded).toBe(0);
      expect(result.denyRulesRemoved).toBe(0);
      expect(result.denyRulesTotal).toBe(0);
      expect(result.filesModified).not.toContain('.claude/settings.json');
    });

    it('does not claim the tool was configured', () => {
      seed(JSONC);

      const result = init(dir);

      // The guard script on disk is inert until settings.json wires it into
      // PreToolUse, so listing claude-code as configured would be a second
      // false success in the same output.
      expect(result.toolsConfigured).not.toContain('claude-code');
    });

    it.each(NON_OBJECT)('leaves settings.json untouched when the top level is %s', (_label, content) => {
      const before = seed(content);

      const result = init(dir);

      expect(fs.readFileSync(settingsPath(), 'utf-8')).toBe(before);
      expect(result.settingsUnusable).toBeDefined();
      expect(result.denyRulesAdded).toBe(0);
      expect(result.toolsConfigured).not.toContain('claude-code');
    });

    it('still configures a file that is empty, which cannot hold user content', () => {
      seed('   \n');

      const result = init(dir);
      const after = JSON.parse(fs.readFileSync(settingsPath(), 'utf-8'));

      expect(result.settingsUnusable).toBeUndefined();
      expect(after.permissions.deny).toContain('Read(.env)');
      expect(result.denyRulesAdded).toBeGreaterThan(0);
    });

    it('reports the parse error so the user can find it', () => {
      seed(JSONC);

      const result = init(dir);

      // Naming the file without naming the fault is a dead end.
      expect(result.settingsUnusable?.reason).toMatch(/JSON|position|token/i);
    });

    it('status reports unreadable settings as unknown, not as zero rules', () => {
      seed(JSONC);
      init(dir);

      const s = status(dir);

      // "0 deny patterns" and "could not read the deny patterns" are different
      // answers. Reporting the first for the second made an unprotected
      // project look identical to a healthy one.
      expect(s.settingsUnreadable?.path).toBe('.claude/settings.json');
      expect(s.isProtected).toBe(false);
    });
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

// A next step that no-ops for the very state that printed it is a dead end.
// `status` used to send a project with an unparseable settings.json to
// `init`, which now refuses on exactly that project.
describe('status next steps stay runnable when settings.json does not parse', () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('does not claim protection from a guard script nothing wires in', () => {
    fs.mkdirSync(path.join(dir, '.claude', 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), '{\n // c\n "model": "opus"\n}\n');
    // The script exists on disk but settings.json never references it.
    fs.writeFileSync(path.join(dir, '.claude', 'hooks', 'secretless-guard.sh'), '#!/bin/sh\n', { mode: 0o755 });

    const s = status(dir);

    expect(s.hookInstalled).toBe(true);      // the file is really there
    expect(s.isProtected).toBe(false);       // but it is not wired in
    expect(s.settingsUnreadable).toBeDefined();
  });
});
