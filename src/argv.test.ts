import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { prepareArgv, prepareBinArgv, supportedFlags, VERBS, MCP_WRAPPER, EXIT_USAGE } from './argv';

/**
 * The argv layer, unit level.
 *
 * These cannot be red-proofed against v0.22.0 — `src/argv.ts` does not exist
 * there, so every one of them fails on a missing import rather than on its own
 * assertion, which proves nothing. The red-proof for this fix lives in
 * `cli.test.ts`, driving the built CLI, where the behaviour existed before and
 * after. What these add is the per-spelling matrix that a behavioural test
 * cannot cover cheaply, and the two guards at the bottom, whose oracle is the
 * SOURCE rather than the table they check.
 */

describe('prepareArgv: the equals spelling binds', () => {
  // The positive control for the whole file. `--only NAME` already worked on
  // 0.22.0; if this row ever fails, the matrix below is measuring the harness
  // and not the fix.
  it('CONTROL: the space form binds, as it always did', () => {
    const p = prepareArgv('run', ['run', '--only', 'DEPLOY_TOKEN', '--', 'npm', 'test']);
    expect(p.args).toEqual(['run', '--only', 'DEPLOY_TOKEN', '--', 'npm', 'test']);
    expect(p.errors).toEqual([]);
  });

  it('`--only=NAME` becomes `--only` `NAME`', () => {
    const p = prepareArgv('run', ['run', '--only=DEPLOY_TOKEN', '--', 'npm', 'test']);
    expect(p.args).toEqual(['run', '--only', 'DEPLOY_TOKEN', '--', 'npm', 'test']);
    expect(p.errors).toEqual([]);
  });

  // `--only=` is the flag WITH an empty value, not the flag absent. The
  // difference is the whole defect: absent means "inject every credential in
  // the store", and #110 established that an empty selector must fail closed.
  it('`--only=` keeps the empty value rather than dropping the flag', () => {
    const p = prepareArgv('run', ['run', '--only=', '--', 'npm', 'test']);
    expect(p.args).toEqual(['run', '--only', '', '--', 'npm', 'test']);
    expect(p.errors).toEqual([]);
  });

  it('a value containing `=` survives intact', () => {
    const p = prepareArgv('clean', ['clean', '--path=/tmp/a=b/c']);
    expect(p.args).toEqual(['clean', '--path', '/tmp/a=b/c']);
  });

  it.each([
    ['clean', '--path', '/tmp/t'],
    ['scan', '--max-files', '20000'],
    ['scan', '--min-confidence', '0.8'],
    ['scan', '--max-file-size', '20mb'],
    ['env', '--only', 'A,B'],
    ['warm', '--ttl', '3600'],
    ['broker', '--port', '9999'],
    ['migrate', '--from', 'local'],
    ['protect-mcp', '--backend', 'keychain'],
  ])('%s %s=%s binds like the space form', (verb, flag, value) => {
    const equals = prepareArgv(verb, [verb, `${flag}=${value}`]);
    const spaced = prepareArgv(verb, [verb, flag, value]);
    expect(equals.args).toEqual(spaced.args);
    expect(equals.errors).toEqual([]);
  });
});

describe('prepareArgv: a flag never widens scope', () => {
  it('a near-miss safety flag on a destructive verb refuses the run', () => {
    const p = prepareArgv('clean', ['clean', '--dryrun']);
    expect(p.errors).toHaveLength(1);
    expect(p.errors[0]).toContain('--dryrun');
    expect(p.errors[0]).toContain('--dry-run');
  });

  it('`clean-history --dryrun` refuses — it has no path flag and targets real history', () => {
    const p = prepareArgv('clean-history', ['clean-history', '--dryrun']);
    expect(p.errors).toHaveLength(1);
  });

  it('an unknown flag with no near miss still refuses on a destructive verb', () => {
    const p = prepareArgv('clean', ['clean', '--zzzzzz']);
    expect(p.errors).toHaveLength(1);
    expect(p.errors[0]).not.toContain('did you mean');
  });

  it('a value-taking flag given last, with no value, refuses', () => {
    const p = prepareArgv('clean', ['clean', '--path']);
    expect(p.errors).toEqual(['--path needs a value, but none was given.']);
  });

  it('a boolean flag given a value refuses rather than inventing a positional', () => {
    const p = prepareArgv('clean', ['clean', '--dry-run=true']);
    expect(p.errors).toHaveLength(1);
    expect(p.errors[0]).toContain('does not take a value');
  });

  // An unregistered flag is left WHOLE. If it were split, `bar` would land in
  // the positional list, and for scan or clean a positional is a path — a
  // target the user never typed.
  it('an unregistered `--foo=bar` never becomes a positional', () => {
    const p = prepareArgv('scan', ['scan', '--foo=bar', './src']);
    expect(p.positionals).toEqual(['./src']);
    expect(p.args).toContain('--foo=bar');
  });

  it('a flag value is never counted as a positional', () => {
    const p = prepareArgv('scan', ['scan', '--max-files', '20000', './src']);
    expect(p.positionals).toEqual(['./src']);
  });

  // The measured 0.22.0 defect: `--max-files` eats the path, leaving no
  // positional, and the scan silently retargets to the working directory.
  // Binding is not enough on its own — cli.ts must then refuse the value.
  it('a flag given the path as its value leaves no positional to scan', () => {
    const p = prepareArgv('scan', ['scan', '--max-files', './src']);
    expect(p.positionals).toEqual([]);
  });
});

describe('prepareArgv: the child command after `--` is untouched', () => {
  it('does not rewrite the child\'s own equals flags', () => {
    const p = prepareArgv('run', ['run', '--only=A', '--', 'npm', 'run', 'x', '--flag=keepme']);
    expect(p.args).toEqual(['run', '--only', 'A', '--', 'npm', 'run', 'x', '--flag=keepme']);
  });

  it('does not judge the child\'s flags as unknown', () => {
    const p = prepareArgv('run', ['run', '--', 'node', '--zzzzzz']);
    expect(p.errors).toEqual([]);
    expect(p.warnings).toEqual([]);
  });

  it('a second `--` belongs to the child', () => {
    const p = prepareArgv('run', ['run', '--only=A', '--', 'sh', '-c', '--', 'x']);
    expect(p.args.slice(3)).toEqual(['--', 'sh', '-c', '--', 'x']);
  });

  it('a non-passthrough verb treats `--` as an ordinary token', () => {
    const p = prepareArgv('clean', ['clean', '--path=/tmp/t']);
    expect(p.args).toEqual(['clean', '--path', '/tmp/t']);
  });
});

describe('prepareArgv: a verb whose output is the answer refuses a flag it cannot bind', () => {
  /**
   * #81's intent survives and is strengthened. It complained that `scan`
   * silently swallowed a typo'd flag and asked for the typo to be surfaced;
   * it settled for a warning because it was scoped as polish, on a build with
   * no exit-2 contract to reach for. It even cited `init`'s refusal as the
   * consistent behaviour.
   *
   * What retired the warning was measuring what it does on a CLEAN tree:
   * exit 0 and `No hardcoded credentials found.` over a scan whose scope the
   * user asked to change and did not get. The earlier evidence that this was
   * safe recorded exit 1 — but that 1 was the FINDING, from a tree that
   * happened to contain a credential, not the flag.
   */
  it('scan refuses a typo\'d flag rather than answering with a narrowed scope', () => {
    const p = prepareArgv('scan', ['scan', '--show-placeholder', './src']);
    expect(p.warnings).toEqual([]);
    expect(p.errors).toHaveLength(1);
    // #81's actual ask: the typo is surfaced and the intended flag is named.
    expect(p.errors[0]).toContain('--show-placeholder');
    expect(p.errors[0]).toContain('--show-placeholders');
  });

  it('the pre-commit gate refuses too — it has no JSON channel and stderr is swallowed', () => {
    const p = prepareArgv('scan-staged', ['scan-staged', '--no-ignoree']);
    expect(p.warnings).toEqual([]);
    expect(p.errors).toHaveLength(1);
    expect(p.errors[0]).toContain('--no-ignore');
  });

  it('CONTROL: a verb that reports no verdict still warns and runs', () => {
    const p = prepareArgv('diff', ['diff', '--nosuchflag']);
    expect(p.errors).toEqual([]);
    expect(p.warnings).toHaveLength(1);
  });

  it('CONTROL: a flag the verb DOES accept produces neither', () => {
    const p = prepareArgv('scan', ['scan', '--show-placeholders', './src']);
    expect(p.errors).toEqual([]);
    expect(p.warnings).toEqual([]);
  });

  it('an unknown verb is left entirely alone for the dispatcher to report', () => {
    const p = prepareArgv('not-a-command', ['not-a-command', '--only=X']);
    expect(p.args).toEqual(['not-a-command', '--only=X']);
    expect(p.errors).toEqual([]);
  });
});

/**
 * The two guards below take their oracle from the SOURCE, not from the table
 * they are checking, so the table cannot satisfy them by agreeing with itself.
 *
 * They exist because the registry has one dangerous failure direction: a flag a
 * verb really does accept, missing from its row, becomes an "unknown option"
 * and a command that works today starts exiting 2.
 */
describe('the registry is derived from the source, not from itself', () => {
  const SRC = path.resolve(__dirname);

  function sourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { out.push(...sourceFiles(full)); continue; }
      if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) out.push(full);
    }
    return out;
  }

  /**
   * Flag literals that are arguments we pass to ANOTHER program, not flags we
   * accept. Each is listed with the program it belongs to, because an entry
   * added here without a reason is how a real flag gets excused from the guard.
   */
  const NOT_OURS = new Map<string, string>([
    ['--version', 'top-level, handled before dispatch (cli.ts:65)'],
    ['--help', 'global, in GLOBAL_FLAGS'],
    // `--json` is deliberately NOT excused here any more. As of 0.23.0 it is
    // declared by the verbs that implement it, so it must be found in the
    // registry like any other flag — which is what makes the guard below able
    // to catch a verb that starts reading `--json` without declaring it.
  ]);

  /**
   * A line that TESTS a flag literal, as opposed to printing it in help text,
   * naming it in a comment, or passing it to `git`.
   *
   * The looser first draft of this predicate matched a comment in
   * `mcp/rewrite.ts` that happened to quote the flags it builds, and reported
   * two flags as unregistered that no parser reads. It also matched, correctly,
   * `ignore`'s real `--pattern` parse site, which the registry was missing —
   * so the tightening below was checked in both directions before it was
   * trusted: it must still catch `--pattern`.
   */
  const TESTS_A_FLAG = /(===|!==|includes\(|indexOf\(|startsWith\()\s*'(--[a-z][a-z0-9-]*)'/g;

  function parseSites(): { file: string; flag: string }[] {
    const sites: { file: string; flag: string }[] = [];
    for (const file of sourceFiles(SRC)) {
      const text = fs.readFileSync(file, 'utf-8');
      for (const raw of text.split('\n')) {
        const line = raw.trim();
        if (line.startsWith('//') || line.startsWith('*') || line.startsWith('/*')) continue;
        for (const m of line.matchAll(TESTS_A_FLAG)) {
          sites.push({ file: path.relative(SRC, file), flag: m[2] });
        }
      }
    }
    return sites;
  }

  // A guard that found nothing would pass whether or not the registry is
  // complete. Pin the predicate on flags known to be parsed, so a regex that
  // stops matching fails here rather than going quietly green.
  it('the parse-site predicate still finds the flags it is supposed to find', () => {
    const found = new Set(parseSites().map((s) => s.flag));
    for (const flag of ['--dry-run', '--path', '--only', '--pattern', '--check-only', '--yes']) {
      expect(found.has(flag), `predicate no longer finds ${flag}`).toBe(true);
    }
  });

  it('every flag literal compared against argv in src/ is in the registry', () => {
    const registered = new Set<string>();
    for (const spec of [...Object.values(VERBS), MCP_WRAPPER]) {
      for (const flag of Object.keys(spec.flags)) registered.add(flag);
    }

    const missing = parseSites()
      .filter((s) => !NOT_OURS.has(s.flag) && !registered.has(s.flag))
      .map((s) => `${s.file}: ${s.flag}`);
    expect(missing).toEqual([]);
  });

  it('every verb the dispatcher accepts has a registry row', () => {
    const cli = fs.readFileSync(path.join(SRC, 'cli.ts'), 'utf-8');
    const verbs = [...cli.matchAll(/^\s+case '([a-z][a-z-]*)':/gm)].map((m) => m[1]);
    // Sanity: if the regex stops matching, an empty list would pass vacuously.
    expect(verbs.length).toBeGreaterThan(25);
    const unregistered = verbs.filter((v) => !VERBS[v]);
    expect(unregistered).toEqual([]);
  });

  it('every verb that can write refuses unknown flags', () => {
    // Named rather than derived: this is the release's whole claim, so the list
    // is the assertion. A new writing verb added with 'warn' must show up here
    // as a deliberate edit, not slip through a predicate.
    const writers = [
      'clean', 'clean-history', 'run', 'env', 'init', 'doctor', 'import', 'setup',
      'secret', 'watch', 'hook', 'warm', 'install', 'protect-mcp', 'mcp-unprotect',
      'ignore', 'telemetry', 'rules', 'backend', 'migrate', 'cache', 'scope', 'broker', 'vault',
    ];
    for (const verb of writers) {
      expect(VERBS[verb], `${verb} has no registry row`).toBeDefined();
      expect(VERBS[verb].unknownFlags, `${verb} must reject unknown flags`).toBe('reject');
    }
  });

  /**
   * The policy, pinned in BOTH directions.
   *
   * A test that only asserts the refusing verbs passes when the whole table is
   * flipped to `reject`, which would break every hand-edited MCP client config
   * — so the exceptions are asserted as exceptions. A test that only asserts
   * the exceptions passes when a verdict verb is demoted. Both lists are named
   * rather than derived, because this is the release's claim and a predicate
   * that drifts with the table cannot check it.
   */
  it('the unknown-flag policy is pinned per verb, presence AND absence', () => {
    // Verdict-emitting: their output is the answer, so a dropped flag is a
    // wrong verdict rather than a wasted run.
    for (const verb of ['scan', 'scan-staged', 'scan-history', 'status', 'verify']) {
      expect(VERBS[verb], `${verb} has no registry row`).toBeDefined();
      expect(VERBS[verb].unknownFlags, `${verb} must refuse an unknown flag`).toBe('reject');
    }
    // The ONLY verbs that may warn, each for a recorded reason. `mcp-status` is
    // a deliberately temporary entry, carried with its sibling defect.
    const mayWarn = ['mcp-status', 'feedback', 'diff'];
    for (const verb of mayWarn) {
      expect(VERBS[verb].unknownFlags, `${verb} is a documented warn exception`).toBe('warn');
    }
    // Nothing else warns. Derived, so a NEW verb added with 'warn' fails here
    // rather than joining the exception list silently.
    const warning = Object.keys(VERBS).filter((v) => VERBS[v].unknownFlags === 'warn');
    expect(warning.sort()).toEqual([...mayWarn].sort());

    // The second bin keeps `warn` on purpose: its argv lines live in
    // hand-edited MCP client configs, where a refusal is a server that will not
    // start. Flipping the table wholesale must fail here.
    expect(MCP_WRAPPER.unknownFlags).toBe('warn');
  });
});

describe('secretless-mcp, the second bin, gets the same normalisation', () => {
  // Its argv has no leading verb — the first token is already a flag — so a
  // layer that assumed args[0] was a verb would silently drop `--server`.
  it('binds the first token, which is a flag and not a verb', () => {
    const p = prepareBinArgv(MCP_WRAPPER, ['--server=github', '--client=claude', '--', 'npx', 'server']);
    expect(p.args).toEqual(['--server', 'github', '--client', 'claude', '--', 'npx', 'server']);
  });

  it('`--vault-dir=` no longer falls back to the default vault', () => {
    const p = prepareBinArgv(MCP_WRAPPER, ['--vault-dir=/tmp/v', '--', 'x']);
    expect(p.args).toEqual(['--vault-dir', '/tmp/v', '--', 'x']);
  });

  it('leaves the wrapped MCP server\'s own argv alone', () => {
    const p = prepareBinArgv(MCP_WRAPPER, ['--server=a', '--', 'npx', '-y', 'pkg', '--port=3000']);
    expect(p.args.slice(2)).toEqual(['--', 'npx', '-y', 'pkg', '--port=3000']);
  });
});

/**
 * `protect-mcp` installs the wrapper by copying `dist/` — and only `dist/` — to
 * `~/.secretless-ai/bin`, then writes that path into the user's MCP configs. So
 * any module the wrapper reaches that requires something OUTSIDE dist/ is
 * missing in the installed layout, and every protected MCP server fails to
 * start.
 *
 * This is not hypothetical: adding `import { CLI_BARE } from './commands/utils'`
 * to argv.ts did exactly that, because that module does
 * `require('../../package.json')`. `mcp/e2e.test.ts` caught it, but only after
 * building a real vault. This asserts the same property in one spawn, so the
 * next import that breaks it fails here first and says why.
 */
describe('the mcp-wrapper require graph is self-contained within dist/', () => {
  const DIST = path.resolve(__dirname, '..', 'dist');
  const hasBuild = fs.existsSync(path.join(DIST, 'mcp-wrapper.js'));
  const itIfBuilt = hasBuild ? it : it.skip;

  itIfBuilt('starts from a standalone copy of dist/, as protect-mcp installs it', () => {
    const { execFileSync } = require('child_process') as typeof import('child_process');
    const os = require('os') as typeof import('os');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-wrapper-standalone-'));
    try {
      fs.cpSync(DIST, path.join(tmp, 'bin'), { recursive: true });
      let stderr = '';
      let exitCode = 0;
      try {
        execFileSync(process.execPath, [path.join(tmp, 'bin', 'mcp-wrapper.js')], {
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch (err) {
        const e = err as { status?: number; stderr?: string };
        exitCode = e.status ?? -1;
        stderr = e.stderr ?? '';
      }
      // It must reach its own usage message. Reaching ANY of its own output
      // proves the module graph loaded; a MODULE_NOT_FOUND never gets there.
      expect(stderr).not.toMatch(/MODULE_NOT_FOUND|Cannot find module/);
      expect(stderr).toMatch(/secretless-mcp: Usage:/);
      expect(exitCode).toBe(1);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('EXIT_USAGE matches the code the CLI already uses for a usage error', () => {
  it('is 2, not the scanner\'s 1', () => {
    // 1 means "credentials found" for scan; a usage error must not be readable
    // as a finding by a CI consumer.
    expect(EXIT_USAGE).toBe(2);
  });
});

/**
 * A refusal message may not advertise a flag the verb does not implement.
 *
 * `supportedFlags` unioned GLOBAL_FLAGS into every verb, so refusing a command
 * line printed `Supported: ..., --json, ...` for all 32 verbs while two honor
 * it — and `verify --json` prints human text and exits 0. That is a promise of
 * a machine-readable mode that does not exist, made in the one place a user
 * reads after hitting an error, and it contradicted this release's own note
 * that `--json` is unchanged. Accepting the flag is unchanged; naming it is not.
 */
describe('supportedFlags names only what the verb honors', () => {
  it('exactly the verbs implementing --json advertise it', () => {
    const advertising = Object.entries(VERBS)
      .filter(([, spec]) => supportedFlags(spec).includes('--json'))
      .map(([verb]) => verb)
      .sort();
    // Oracle is the SOURCE: the verbs whose dispatch actually reads the flag.
    const cli = fs.readFileSync(path.join(path.resolve(__dirname), 'cli.ts'), 'utf-8');
    const implementing = cli.split('\n').filter((l) => l.includes("includes('--json')")).length;
    expect(implementing).toBe(2);
    expect(advertising).toEqual(['scan', 'status']);
  });

  it('a destructive verb does not offer --json in its refusal', () => {
    const p = prepareArgv('clean', ['clean', '--dryrun']);
    expect(p.errors).toHaveLength(1);
    expect(supportedFlags(VERBS.clean)).not.toContain('--json');
  });

  it('CONTROL: the flags a verb DOES honor are still all named', () => {
    // The filter must remove one flag, not shrink the list generally.
    const listed = supportedFlags(VERBS.clean);
    for (const f of ['--dry-run', '--last', '--path <value>', '--help']) {
      expect(listed).toContain(f);
    }
  });
});
