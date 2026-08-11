import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Every command this project's own docs tell a user to run must actually be a
 * command. A reader copies these verbatim; one that does not parse is a dead
 * end no amount of proofreading finds, because reading the page cannot tell
 * you whether the CLI accepts it.
 *
 * Caught in the 0.21.0 release test: `docs/use-cases/team-setup.md` published
 *
 *     "postinstall": "npx secretless-ai init --ci"
 *
 * directly under "Now every `npm install` configures AI tool protections
 * automatically." `init` takes an optional directory path and no flags, so it
 * exits 2 with "Unknown option: --ci" — the documented hook failed every
 * `npm install` for every developer on a team that followed the guide.
 *
 * The docs were right when they were written. Issue #62 made `init` reject
 * unknown flags (before that, `init --dry-run` created a literal `--dry-run/`
 * directory), and tightening the parser is what turned a silently-wrong
 * documented command into a loudly-broken one. A release that tightens a
 * parser has to re-check every command its docs publish.
 */

const REPO_ROOT = path.resolve(__dirname, '..');

/**
 * Commands the CLI actually dispatches, read from `cli.ts` itself so the list
 * cannot drift from the implementation.
 *
 * Two dispatch sites, and missing either produces false failures: the main
 * `switch (command)`, and the handful intercepted before it (`telemetry` is
 * handled ahead of the switch so its own invocation is not tracked).
 */
function dispatchedCommands(): Set<string> {
  const cli = fs.readFileSync(path.join(REPO_ROOT, 'src', 'cli.ts'), 'utf-8');
  const commands = new Set<string>();
  for (const m of cli.matchAll(/^\s*case '([a-z][a-z-]*)':/gm)) {
    commands.add(m[1]);
  }
  for (const m of cli.matchAll(/command === '([a-z][a-z-]*)'/g)) {
    commands.add(m[1]);
  }
  return commands;
}

/**
 * Command references only. A doc sentence containing the package name followed
 * by a word ("common secretless-ai workflows") is prose, and `npm view
 * secretless-ai dist.attestations` is an npm invocation. Require the reference
 * to be inside backticks or on a fenced code line, which is how a reader tells
 * the difference too.
 */
function commandReferences(line: string): string[] {
  const verbs: string[] = [];
  const inCode = /^\s{4,}\S/.test(line) || /^\s*[$>]/.test(line);
  const candidates = [...line.matchAll(/`([^`]+)`/g)].map(m => m[1]);
  if (inCode) candidates.push(line);

  for (const snippet of candidates) {
    if (/npm\s+\w+\s+secretless-ai/.test(snippet)) continue;
    for (const m of snippet.matchAll(/(?:^|[$\s(])(?:npx\s+)?secretless-ai\s+([a-z][a-z-]*)/g)) {
      verbs.push(m[1]);
    }
  }
  return verbs;
}

/**
 * npm lifecycle scripts that run as part of an ordinary `npm install`. Anything
 * here that exits non-zero fails the install itself, so a command wired into one
 * of them must be one that cannot fail — and `init` is not, by design.
 */
const INSTALL_LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];

/**
 * A JSON script entry that runs a secretless-ai command from an install-time
 * lifecycle hook. Returns the hook name, or null.
 *
 * Matching the hook and the command on one line is deliberate: this is the shape
 * docs actually publish (`"postinstall": "npx secretless-ai init"`), and a
 * predicate that tried to track JSON structure across lines would be a parser,
 * which is the thing that keeps producing defects here.
 */
function installHookWiring(line: string): string | null {
  const m = line.match(/"(\w+)"\s*:\s*"([^"]*secretless-ai[^"]*)"/);
  if (!m) return null;
  return INSTALL_LIFECYCLE_HOOKS.includes(m[1]) ? m[1] : null;
}

/** Markdown the project publishes to users. */
function docFiles(): string[] {
  const files: string[] = [];
  const readme = path.join(REPO_ROOT, 'README.md');
  if (fs.existsSync(readme)) files.push(readme);

  const walk = (dir: string): void => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.md')) files.push(full);
    }
  };
  walk(path.join(REPO_ROOT, 'docs'));
  return files;
}

describe('documented commands exist', () => {
  const commands = dispatchedCommands();
  const files = docFiles();

  it('derives a real command list from both dispatch sites', () => {
    // Guard against the extraction silently matching nothing, which would make
    // every assertion below vacuously true.
    expect(commands.size).toBeGreaterThan(20);
    expect(commands.has('init')).toBe(true);
    expect(commands.has('scan')).toBe(true);
    // Dispatched before the switch — missing this site is what made the first
    // version of this test report `telemetry` as undefined.
    expect(commands.has('telemetry')).toBe(true);
  });

  it('distinguishes a command reference from prose and from npm invocations', () => {
    // The extractor is the part most likely to go quietly wrong, so pin both
    // directions rather than trusting a green run over the real docs.
    expect(commandReferences('Run `secretless-ai scan` to check.')).toEqual(['scan']);
    expect(commandReferences('guides for common secretless-ai workflows.')).toEqual([]);
    expect(commandReferences('`npm view secretless-ai dist.attestations --json`')).toEqual([]);
    expect(commandReferences('# secretless-ai release smoke test')).toEqual([]);
    expect(commandReferences('    npx secretless-ai init')).toEqual(['init']);
  });

  it('finds docs to check', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it('never documents a flag on `init`, which accepts a path and no flags', () => {
    // The exact shape that shipped broken. `init` is the highest-risk case:
    // it is the command teams wire into automation, so a rejected flag fails
    // `npm install` rather than merely printing an error someone reads.
    const offenders: string[] = [];
    for (const file of files) {
      const text = fs.readFileSync(file, 'utf-8');
      text.split('\n').forEach((line, i) => {
        if (/secretless-ai\s+init\s+--/.test(line)) {
          offenders.push(`${path.relative(REPO_ROOT, file)}:${i + 1}: ${line.trim()}`);
        }
      });
    }
    expect(offenders).toEqual([]);
  });

  it('distinguishes an install-time lifecycle hook from an ordinary script', () => {
    // Pin the predicate in BOTH directions before running it over the real docs,
    // or a green result below says nothing about whether it can fire at all.
    expect(installHookWiring('    "postinstall": "npx secretless-ai init"')).toBe('postinstall');
    expect(installHookWiring('    "prepare": "secretless-ai init"')).toBe('prepare');
    // A named script a user runs deliberately is the recommended shape, not a defect.
    expect(installHookWiring('    "protect": "secretless-ai init"')).toBeNull();
    // A lifecycle hook that does not run this tool is none of our business.
    expect(installHookWiring('    "postinstall": "npm run build"')).toBeNull();
  });

  it('never wires a secretless-ai command into an install-time lifecycle hook', () => {
    // The 0.21.0 breakage (a rejected `--ci` flag) and the 0.21.3 breakage (`init`
    // exiting 1 on an unparseable settings.json) are the same defect reached two
    // different ways, in the same documented hook. The flag was never the cause:
    // `init` is allowed to fail, and `postinstall` turns any failure into a failed
    // `npm install` for the whole team. Guard the coupling, not the spelling —
    // a rule per flag never converges.
    const offenders: string[] = [];
    for (const file of files) {
      const text = fs.readFileSync(file, 'utf-8');
      text.split('\n').forEach((line, i) => {
        const hook = installHookWiring(line);
        if (hook) {
          offenders.push(`${path.relative(REPO_ROOT, file)}:${i + 1}: "${hook}" — ${line.trim()}`);
        }
      });
    }
    expect(offenders).toEqual([]);
  });

  it('only names commands the CLI dispatches', () => {
    const offenders: string[] = [];
    for (const file of files) {
      const text = fs.readFileSync(file, 'utf-8');
      text.split('\n').forEach((line, i) => {
        for (const verb of commandReferences(line)) {
          if (!commands.has(verb)) {
            offenders.push(`${path.relative(REPO_ROOT, file)}:${i + 1}: "${verb}" — ${line.trim()}`);
          }
        }
      });
    }
    expect(offenders).toEqual([]);
  });
});
