import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { prepareArgv, prepareBinArgv, supportedFlags, jsonVerbs, VERBS, MCP_WRAPPER, EXIT_USAGE } from './argv';

/**
 * `--json` is honored or refused — never accepted and ignored (#126).
 *
 * The 2026-08-12 `[CHIEF-CPO]` ruling: a flag the tool accepts is a flag the
 * tool honors. Measured on 0.22.1 across all 32 verbs — 2 honored it, and of
 * the other 30, 15 truly ignored it, 11 mistook it for a SUBCOMMAND and 4
 * mistook it for a POSITIONAL. The last group is why this is a correctness fix
 * rather than a tidy-up: `verify --json` resolved `--json` as the project
 * directory and printed `AI context: clean (no credentials found)` about a
 * directory whose `CLAUDE.md` held a live key.
 */

describe('--json is refused by every verb that does not implement it', () => {
  const honoring = jsonVerbs();

  it('CONTROL: the registry names exactly the verbs cli.ts reads --json for', () => {
    // The oracle is the SOURCE, not the table being checked, so the two cannot
    // agree by construction. A verb that starts implementing --json without
    // declaring it, or declares it without implementing it, fails here.
    const cli = fs.readFileSync(path.join(__dirname, 'cli.ts'), 'utf-8');

    // Segment the dispatch switch at each `case`, so a read site is attributed
    // to the verb whose block CONTAINS it. A window-based regex reads across
    // the boundary and blamed `init` for `scan`'s read of the flag.
    const marks = [...cli.matchAll(/^\s+case '([a-z-]+)':/gm)];
    expect(marks.length, 'the case-boundary predicate found no verbs').toBeGreaterThan(25);

    const readSites: string[] = [];
    for (let i = 0; i < marks.length; i++) {
      const start = marks[i].index! + marks[i][0].length;
      const end = i + 1 < marks.length ? marks[i + 1].index! : cli.length;
      if (cli.slice(start, end).includes("args.includes('--json')")) readSites.push(marks[i][1]);
    }

    expect(readSites.length, 'the --json read-site predicate found nothing').toBeGreaterThan(0);
    expect([...new Set(readSites)].sort()).toEqual(honoring);
  });

  it('CONTROL: a verb that honors --json binds it with no error', () => {
    for (const verb of honoring) {
      const p = prepareArgv(verb, [verb, '--json']);
      expect(p.errors, `${verb} must accept --json`).toEqual([]);
      expect(p.warnings).toEqual([]);
      expect(p.args).toContain('--json');
    }
  });

  it('CONTROL: --json binds in the LEADING position too, not only trailing', () => {
    // `docs/testing/release-smoke.md` runs the leading form and README the
    // trailing one, so a fix tested in one order only would break the other.
    for (const verb of honoring) {
      const lead = prepareArgv(verb, [verb, '--json', '/some/dir']);
      const trail = prepareArgv(verb, [verb, '/some/dir', '--json']);
      expect(lead.errors, `${verb} --json <dir>`).toEqual([]);
      expect(trail.errors, `${verb} <dir> --json`).toEqual([]);
      // The path is the positional in both orders; --json never becomes one.
      expect(lead.positionals).toEqual(['/some/dir']);
      expect(trail.positionals).toEqual(['/some/dir']);
    }
  });

  const nonHonoring = Object.keys(VERBS).filter((v) => VERBS[v].honorsJson !== true);

  it('there are non-honoring verbs to test, and they are the majority', () => {
    // Guards against a future registry change making the sweep below vacuous.
    expect(nonHonoring.length).toBeGreaterThan(20);
    expect(honoring.length).toBeGreaterThan(0);
  });

  it.each(nonHonoring)('%s refuses --json rather than ignoring it', (verb) => {
    const p = prepareArgv(verb, [verb, '--json']);
    expect(p.errors.length, `${verb} accepted --json`).toBe(1);
    expect(p.errors[0]).toMatch(/--json is not implemented/);
    // The refusal has to say where JSON DOES live, or it is a dead end.
    for (const h of honoring) expect(p.errors[0]).toContain(h);
    // An error, never a warning: a warning would leave exit 0 in place.
    expect(p.warnings).toEqual([]);
  });

  /**
   * The trap this test exists for: routing `--json` through the ordinary
   * unknown-flag path would refuse it on the twelve verbs that REJECT and
   * merely warn on the read-only ones — leaving exit 0 plus human text, which
   * is the false-clean shape the ruling names. These six are the warn verbs.
   */
  it.each(Object.keys(VERBS).filter((v) => VERBS[v].unknownFlags === 'warn' && VERBS[v].honorsJson !== true))(
    '%s refuses --json even though it WARNS about other unknown flags',
    (verb) => {
      const json = prepareArgv(verb, [verb, '--json']);
      expect(json.errors.length, `${verb} warned about --json instead of refusing`).toBe(1);
      expect(json.warnings).toEqual([]);

      // CONTROL, same verb, same run: an ordinary unknown flag still warns and
      // still runs, because #81's warn-and-continue is deliberate and survives.
      const other = prepareArgv(verb, [verb, '--nosuchflag']);
      expect(other.errors, `${verb} must still warn on a non-json unknown flag`).toEqual([]);
      expect(other.warnings.length).toBe(1);
    },
  );

  it('the refusal exit code is the usage code, not the scanner findings code', () => {
    expect(EXIT_USAGE).toBe(2);
  });
});

describe('--json is not advertised where it is not implemented', () => {
  it('only the honoring verbs list it as supported', () => {
    for (const [verb, spec] of Object.entries(VERBS)) {
      const listed = supportedFlags(spec).some((f) => f.startsWith('--json'));
      expect(listed, `${verb} advertises --json`).toBe(spec.honorsJson === true);
    }
  });

  /**
   * `supportedFlags` hid `--json` from the "Supported:" line while
   * `nearestMatch` still suggested it two lines earlier, because the suggestion
   * ranked against the global set. Measured on 0.22.1:
   *
   *   verify --jsonn
   *     Unknown option: --jsonn (did you mean --json?)
   *     Supported: --all, --help
   *
   * One message pointed at a flag the next line withheld — and following the
   * suggestion produced the silent mistarget. Since `--json` is no longer in a
   * non-honoring verb's known set, it can no longer be suggested by one.
   */
  it('a near miss of --json is never suggested by a verb that does not implement it', () => {
    for (const verb of Object.keys(VERBS)) {
      if (VERBS[verb].honorsJson === true) continue;
      const p = prepareArgv(verb, [verb, '--jsonn']);
      const text = [...p.errors, ...p.warnings].join(' ');
      expect(text, `${verb} suggested --json`).not.toMatch(/did you mean.*--json/);
    }
  });

  it('CONTROL: a verb that DOES implement it still suggests it on a near miss', () => {
    const p = prepareArgv('scan', ['scan', '--jsonn']);
    const text = [...p.errors, ...p.warnings].join(' ');
    expect(text).toMatch(/did you mean --json/);
  });
});

describe('the second bin keeps its own contract', () => {
  /**
   * `secretless-mcp`'s argv lines are written into MCP client configs by
   * `protect-mcp` and hand-edited afterwards, so refusing an unrecognised token
   * there breaks a user's MCP server at startup. Its `warn` policy is a
   * deliberate decision with a different blast radius, and the `--json`
   * refusal — a statement about THIS CLI's verb contract — does not reach it.
   */
  it('secretless-mcp warns about --json rather than refusing to start', () => {
    const p = prepareBinArgv(MCP_WRAPPER, ['--server', 'github', '--json', '--', 'npx', 'srv']);
    expect(p.errors).toEqual([]);
    expect(p.warnings.length).toBe(1);
    expect(p.warnings[0]).toMatch(/--json/);
  });

  it('CONTROL: it still binds the flags it does implement', () => {
    const p = prepareBinArgv(MCP_WRAPPER, ['--vault-dir=/tmp/v', '--', 'x']);
    expect(p.errors).toEqual([]);
    expect(p.args).toEqual(['--vault-dir', '/tmp/v', '--', 'x']);
  });
});
