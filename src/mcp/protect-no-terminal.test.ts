import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runProtectMcp } from '../commands/mcp';

/**
 * protect-mcp where no one can answer a keychain prompt: stdin is not a
 * terminal, as in a tool call, CI or a script. HOME is a fresh directory with
 * no backend configured, so the run stores in the platform keychain the
 * default upgrades to (see createBackend).
 *
 * Each OS keychain backend runs a stand-in through its internal seam
 * (MacOSKeychainInternals, LinuxKeychainInternals), never /usr/bin/security
 * or the secret-tool on PATH, and the platform reads as the one each cell
 * names, so the same backend is built on every runner. The stand-ins are perl
 * scripts: a native start, so a call they answer returns in milliseconds.
 * Each keeps its entries in files beside itself. With a file named `hang`
 * beside it, the stand-in is a locked keychain whose unlock dialog no one
 * sees: a call that waits on that dialog writes its pid and never answers.
 * For `security` that is every call. For `secret-tool` it is `store` and
 * `lookup`; `clear` and `search` act on unlocked items only and never open
 * the dialog (libsecret), so they answer at once, locked or not.
 *
 * Every run is under a two-second alarm. Fixture values are assembled at run
 * time and are not credentials.
 */

const standIn = vi.hoisted(() => ({ security: '', secretTool: '' }));

vi.mock('../backends/keychain-macos', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../backends/keychain-macos')>();
  // Every argument the factory passes is passed on; only the program is the stand-in.
  class StandInKeychain extends actual.MacOSKeychainBackend {
    constructor(...args: ConstructorParameters<typeof actual.MacOSKeychainBackend>) {
      const [config, internals, ...rest] = args;
      super(config, { ...internals, securityProgram: standIn.security }, ...rest);
    }
  }
  return { ...actual, MacOSKeychainBackend: StandInKeychain };
});

vi.mock('../backends/keychain-linux', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../backends/keychain-linux')>();
  class StandInSecretService extends actual.LinuxKeychainBackend {
    constructor(...args: ConstructorParameters<typeof actual.LinuxKeychainBackend>) {
      const [config, internals, ...rest] = args;
      super(config, { ...internals, secretToolProgram: standIn.secretTool }, ...rest);
    }
  }
  return { ...actual, LinuxKeychainBackend: StandInSecretService };
});

/** The alarm every run is under. */
const ALARM_MS = 2000;
/** The bar a run with no one to answer meets: an outcome within one second. */
const OUTCOME_MS = 1000;

/** Shared by both stand-ins: the call log, the `hang` switch (a locked keychain) and the entry files. */
const PERL_PROLOGUE = String.raw`#!/usr/bin/perl
use strict;
use warnings;
my ($dir) = $0 =~ m{^(.*)/[^/]+$};
open(my $calls, '>>', "$dir/calls.log") or die "calls.log: $!";
print $calls (defined $ARGV[0] ? $ARGV[0] : ''), "\n";
close $calls;
my $locked = -e "$dir/hang";
sub waits_on_dialog {
  open(my $p, '>', "$dir/hang.pid") or die "hang.pid: $!";
  print $p $$;
  close $p;
  sleep 60;
  exit 1;
}
sub item { my ($s, $a) = @_; return "$dir/item-" . unpack('H*', (defined $s ? $s : '') . "\0" . (defined $a ? $a : '')); }
sub keep { my ($file, $hex) = @_; open(my $f, '>', $file) or return 0; print $f $hex; close $f; return 1; }
sub kept { my ($file) = @_; open(my $f, '<', $file) or return undef; my $hex = <$f>; close $f; return pack('H*', $hex); }
`;

/** `security`: add-generic-password (one line on stdin with -i), find-generic-password, delete-generic-password. Locked, every call waits. */
const SECURITY_STAND_IN = PERL_PROLOGUE + String.raw`
waits_on_dialog() if $locked;
sub opt { my ($args, $flag) = @_; for my $i (0 .. $#$args - 1) { return $args->[$i + 1] if $args->[$i] eq $flag; } return undef; }
sub has { my ($args, $flag) = @_; return scalar grep { $_ eq $flag } @$args; }
sub tokens {
  my ($line) = @_; my @out; my $cur = ''; my $q = 0; my $has = 0; my @c = split //, $line;
  for (my $i = 0; $i < @c; $i++) {
    my $ch = $c[$i];
    if ($q) { if ($ch eq '\\' && $i + 1 < @c) { $cur .= $c[++$i]; } elsif ($ch eq '"') { $q = 0; } else { $cur .= $ch; } }
    elsif ($ch eq '"') { $q = 1; $has = 1; }
    elsif ($ch eq ' ' || $ch eq "\t") { if ($has || length $cur) { push @out, $cur; $cur = ''; $has = 0; } }
    else { $cur .= $ch; $has = 1; }
  }
  push @out, $cur if $has || length $cur;
  return @out;
}
my $NOT_FOUND = "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n";
sub run {
  my @cmd = @_; my $sub = defined $cmd[0] ? $cmd[0] : '';
  my $file = item(opt(\@cmd, '-s'), opt(\@cmd, '-a'));
  if ($sub eq 'add-generic-password') {
    my $hex = opt(\@cmd, '-X');
    return 2 unless defined $hex;
    return keep($file, $hex) ? 0 : 1;
  }
  if ($sub eq 'find-generic-password') {
    my $bytes = kept($file);
    unless (defined $bytes) { print STDERR $NOT_FOUND; return 44; }
    my $printable = $bytes !~ /[^\x20-\x7e]/;
    if (has(\@cmd, '-g')) { print STDERR $printable ? "password: \"$bytes\"\n" : 'password: 0x' . uc(unpack('H*', $bytes)) . "\n"; return 0; }
    print STDOUT (($printable ? $bytes : unpack('H*', $bytes)), "\n") if has(\@cmd, '-w');
    return 0;
  }
  if ($sub eq 'delete-generic-password') {
    unless (-e $file) { print STDERR $NOT_FOUND; return 44; }
    unlink $file;
    return 0;
  }
  if ($sub eq 'default-keychain') { print STDOUT "    \"/Users/x/Library/Keychains/login.keychain-db\"\n"; return 0; }
  print STDERR "security: unknown command\n";
  return 1;
}
if ((defined $ARGV[0] ? $ARGV[0] : '') eq '-i') {
  my $status = 0;
  while (my $line = <STDIN>) { chomp $line; next unless length $line; $status = run(tokens($line)); }
  exit $status;
}
exit run(@ARGV);
`;

/**
 * `secret-tool`: store (value on stdin), lookup, search and clear, by service
 * and account. Locked, `store` and `lookup` wait on the unlock dialog; `clear`
 * and `search` never open it: `clear` removes unlocked items only, so it
 * leaves the entry and exits 0, and `search` lists the entry without its value.
 */
const SECRET_TOOL_STAND_IN = PERL_PROLOGUE + String.raw`
my %attr; my @rest = @ARGV; my $sub = shift @rest; $sub = '' unless defined $sub;
while (@rest) { my $k = shift @rest; if ($k =~ /^--/) { next; } $attr{$k} = shift @rest; }
my $file = item($attr{service}, $attr{account});
waits_on_dialog() if $locked && ($sub eq 'store' || $sub eq 'lookup');
if ($sub eq 'store') { local $/; my $value = <STDIN>; $value = '' unless defined $value; exit(keep($file, unpack('H*', $value)) ? 0 : 1); }
if ($sub eq 'lookup') { my $value = kept($file); exit 1 unless defined $value; print STDOUT $value; exit 0; }
if ($sub eq 'search') { exit 0 unless -e $file; print STDOUT "[/1]\nlabel = x\n"; exit 0; }
if ($sub eq 'clear') { unlink $file if -e $file && !$locked; exit 0; }
exit 2;
`;

const ALPHA_NAME = ['ALPHA', 'API', 'KEY'].join('_');
const BETA_NAME = ['BETA', 'TOKEN'].join('_');
const ALPHA_VALUE = ['stand', 'in', 'alpha', String(process.pid)].join('-');
const BETA_VALUE = ['stand', 'in', 'beta', String(process.pid)].join('-');
const FIXTURE_VALUES = [ALPHA_VALUE, BETA_VALUE];

const savedPlatform = Object.getOwnPropertyDescriptor(process, 'platform')!;
let savedHome: string | undefined;
let savedPath: string | undefined;
let home: string;
let project: string;
let mcpJson: string;
let original: string;
let standInDir: string;

/** Under the repository's own cache, where execution is known to be allowed (see child-recorder.test-support.ts). */
function standInDirectory(): string {
  const base = path.resolve(process.cwd(), 'node_modules', '.cache', 'secretless-child-recorders');
  fs.mkdirSync(base, { recursive: true });
  return fs.mkdtempSync(path.join(base, 'secretless-keychain-perl-'));
}

beforeEach(() => {
  savedHome = process.env.HOME;
  savedPath = process.env.PATH;
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-no-terminal-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-no-terminal-project-'));
  process.env.HOME = home;
  standInDir = standInDirectory();
  standIn.security = path.join(standInDir, 'security');
  standIn.secretTool = path.join(standInDir, 'secret-tool');
  fs.writeFileSync(standIn.security, SECURITY_STAND_IN, { mode: 0o755 });
  fs.writeFileSync(standIn.secretTool, SECRET_TOOL_STAND_IN, { mode: 0o755 });
  mcpJson = path.join(project, '.mcp.json');
  original = JSON.stringify({
    mcpServers: {
      'alpha-docs': { command: 'node', args: ['alpha.js'], env: { [ALPHA_NAME]: ALPHA_VALUE } },
      'beta-search': { command: 'node', args: ['beta.js'], env: { [BETA_NAME]: BETA_VALUE } },
    },
  }, null, 2);
  fs.writeFileSync(mcpJson, original);
});

afterEach(() => {
  Object.defineProperty(process, 'platform', savedPlatform);
  // A stand-in still waiting (a run the alarm ended) is stopped before its files go.
  const pid = hangPid();
  if (pid !== null && alive(pid)) process.kill(pid, 'SIGKILL');
  for (const [name, value] of [['HOME', savedHome], ['PATH', savedPath]] as const) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  for (const dir of [home, project, standInDir]) fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * The platform each cell names. On Linux the default upgrades to the Secret
 * Service only where `secret-tool` is on PATH, so the stand-in's directory is
 * put first on it: the cell then does not depend on what the runner installed.
 */
function onPlatform(platform: 'darwin' | 'linux'): void {
  Object.defineProperty(process, 'platform', { value: platform, configurable: true });
  if (platform === 'linux') process.env.PATH = [standInDir, savedPath ?? ''].join(path.delimiter);
}

function neverAnswers(): void {
  fs.writeFileSync(path.join(standInDir, 'hang'), '');
}

/** Each call the stand-ins were started for, by its first argument. */
function calls(): string[] {
  const file = path.join(standInDir, 'calls.log');
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf-8').split('\n').filter((line) => line.length > 0) : [];
}

function hangPid(): number | null {
  const file = path.join(standInDir, 'hang.pid');
  return fs.existsSync(file) ? Number(fs.readFileSync(file, 'utf-8')) : null;
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** The value of each entry the stand-ins hold. */
function storedValues(): string[] {
  return fs.readdirSync(standInDir)
    .filter((name) => name.startsWith('item-'))
    .map((name) => Buffer.from(fs.readFileSync(path.join(standInDir, name), 'utf-8'), 'hex').toString('utf-8'));
}

/** Every file under `dir` holding one of `values`, as text or as hex. */
function filesHolding(dir: string, values: string[]): string[] {
  const forms = values.flatMap((value) => [value, Buffer.from(value, 'utf-8').toString('hex')]);
  const found: string[] = [];
  const walk = (at: string): void => {
    for (const entry of fs.readdirSync(at, { withFileTypes: true })) {
      const full = path.join(at, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && forms.some((form) => fs.readFileSync(full, 'utf-8').includes(form))) found.push(full);
    }
  };
  walk(dir);
  return found;
}

interface Outcome {
  code: number | 'alarm';
  ms: number;
  lines: string[];
  /** How many stand-in calls had started when a line naming the keychain was first printed. */
  callsAtKeychainLine: number | null;
}

/** protect-mcp in this process, from the project directory, under the alarm. */
async function protectMcp(stdinIsTTY: boolean, args: string[] = []): Promise<Outcome> {
  const lines: string[] = [];
  let callsAtKeychainLine: number | null = null;
  const capture = (...parts: unknown[]) => {
    const line = parts.map(String).join(' ');
    if (callsAtKeychainLine === null && /Keychain|Secret Service/.test(line)) callsAtKeychainLine = calls().length;
    lines.push(line);
  };
  const log = vi.spyOn(console, 'log').mockImplementation(capture);
  const error = vi.spyOn(console, 'error').mockImplementation(capture);
  const cwd = vi.spyOn(process, 'cwd').mockReturnValue(project);
  let timer: NodeJS.Timeout | undefined;
  const started = performance.now();
  try {
    const code = await Promise.race([
      runProtectMcp(args, { stdinIsTTY }),
      new Promise<'alarm'>((resolve) => { timer = setTimeout(() => resolve('alarm'), ALARM_MS); }),
    ]);
    return { code, ms: performance.now() - started, lines: lines.flatMap((line) => line.split('\n')), callsAtKeychainLine };
  } finally {
    clearTimeout(timer);
    log.mockRestore();
    error.mockRestore();
    cwd.mockRestore();
  }
}

/**
 * Each OS keychain, and the first call a protect-mcp run makes to it: the
 * write of the first binding, which is the call that waits on the unlock
 * dialog. On Linux that is `secret-tool store`. The legacy `clear` follows
 * it: put first, it would answer at once (it never opens the dialog), use up
 * the one bounded call, and leave `store` the 30 s bound.
 */
const KEYCHAINS = [
  { platform: 'darwin' as const, store: 'macOS Keychain', firstCall: '-i' },
  { platform: 'linux' as const, store: 'Secret Service', firstCall: 'store' },
];

describe('protect-mcp with stdin not a terminal and a keychain that never answers', () => {
  for (const { platform, store, firstCall } of KEYCHAINS) {
    for (const args of [[], ['--backend', 'keychain']]) {
      it(`refuses within one second, names --backend and stores nothing (${store}, protect-mcp ${args.join(' ') || 'with no flags'})`, async () => {
        onPlatform(platform);
        neverAnswers();
        const outcome = await protectMcp(false, args);

        expect(outcome.code, `an outcome within ${ALARM_MS} ms`).not.toBe('alarm');
        expect(outcome.ms).toBeLessThan(OUTCOME_MS);
        expect(outcome.code).toBe(1);
        expect(outcome.lines.filter((line) => line.includes('--backend')).length).toBeGreaterThan(0);
        expect(outcome.lines.filter((line) => /^\s+Fix:/.test(line)).length).toBeGreaterThan(1);
        expect(outcome.lines.filter((line) => /^\s+at /.test(line))).toEqual([]);

        // The run stopped at its first keychain call, the write that waits on
        // the dialog: it alone was started, and it is gone.
        expect(calls()).toEqual([firstCall]);
        const pid = hangPid();
        expect(pid).not.toBeNull();
        expect(alive(pid!)).toBe(false);

        // Nothing was stored anywhere, and the config is as it was.
        expect(storedValues()).toEqual([]);
        expect(filesHolding(home, FIXTURE_VALUES)).toEqual([]);
        expect(fs.readFileSync(mcpJson, 'utf-8')).toBe(original);
      }, 10_000);
    }
  }
});

describe('protect-mcp with a keychain that answers', () => {
  for (const { platform, store } of KEYCHAINS) {
    for (const stdinIsTTY of [true, false]) {
      it(`stores both servers' secrets in it and rewrites the config (${store}, stdin ${stdinIsTTY ? 'a terminal' : 'not a terminal'})`, async () => {
        onPlatform(platform);
        const outcome = await protectMcp(stdinIsTTY);

        expect(outcome.code, `an outcome within ${ALARM_MS} ms`).not.toBe('alarm');
        expect(outcome.code).toBe(0);
        const output = outcome.lines.join('\n');
        expect(output).toContain('+ claude-code/alpha-docs');
        expect(output).toContain('+ claude-code/beta-search');
        expect(output).toContain('2 secret(s) encrypted across 2 server(s).');
        expect(storedValues()).toEqual(expect.arrayContaining(FIXTURE_VALUES));
        const rewritten = fs.readFileSync(mcpJson, 'utf-8');
        for (const value of FIXTURE_VALUES) expect(rewritten).not.toContain(value);
        expect(outcome.lines.filter((line) => /^\s+at /.test(line))).toEqual([]);
      }, 10_000);
    }
  }
});

describe('protect-mcp names the OS keychain before its first access', () => {
  for (const { platform, store } of KEYCHAINS) {
    for (const stdinIsTTY of [true, false]) {
      it(`says the step stores in the ${store} and names --backend, before any keychain call (stdin ${stdinIsTTY ? 'a terminal' : 'not a terminal'})`, async () => {
        onPlatform(platform);
        const outcome = await protectMcp(stdinIsTTY);

        expect(outcome.code).toBe(0);
        expect(outcome.callsAtKeychainLine, 'a line naming the keychain').not.toBeNull();
        expect(outcome.callsAtKeychainLine).toBe(0);
        const first = outcome.lines.findIndex((line) => line.includes(store));
        expect(outcome.lines.slice(first, first + 3).some((line) => line.includes('--backend'))).toBe(true);
      }, 10_000);
    }
  }

  it('says nothing of a keychain when the configured store is the encrypted file', async () => {
    onPlatform('darwin');
    fs.mkdirSync(path.join(home, '.secretless-ai'), { recursive: true });
    fs.writeFileSync(path.join(home, '.secretless-ai', 'config.json'), JSON.stringify({ backend: 'local' }));
    const outcome = await protectMcp(false);

    expect(outcome.code).toBe(0);
    expect(outcome.callsAtKeychainLine).toBeNull();
    expect(calls()).toEqual([]);
    expect(outcome.lines.join('\n')).toContain('2 secret(s) encrypted across 2 server(s).');
  }, 10_000);
});
