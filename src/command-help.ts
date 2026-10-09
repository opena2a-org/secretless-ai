/**
 * Per-command help, reached from the `--help` / `-h` interception in cli.ts.
 *
 * WHY. `migrate --help` printed the 150-line global help, which names neither
 * `--from` nor `--to` — the two flags the refusal `migrate` prints points the
 * user at (`Run \`secretless-ai migrate --help\` for usage.`). The interception
 * stays exactly where it is, because it is what keeps `init --help` from
 * creating a `--help/` directory and `broker start --help` from launching the
 * daemon; it now answers with the verb's own flags instead of the whole list.
 *
 * THE FLAGS COME FROM `VERBS`. The option block is walked from the registry in
 * argv.ts, not written out here, so a flag the parser accepts is always named
 * and a flag it refuses is never advertised. The table below only adds the
 * human description and a value placeholder; a flag registered without an entry
 * still prints, with a generic `<value>`.
 *
 * BRANDING follows help.ts: the `Secretless v<version>` banner only when
 * standalone, every citation through `CLI` so an embedding host's prefix
 * (SECRETLESS_CLI_PREFIX) renders natively. No line here may spell the
 * standalone bin name literally.
 */
import { VERSION, CLI, IS_EMBEDDED } from './commands/utils';
import { printHelp } from './commands/help';
import { VERBS } from './argv';
import {
  CONFIG_FILES,
  CONFIG_SHAPED_BASENAMES,
  CONFIG_SHAPED_EXTENSIONS,
  SOURCE_FILE_EXTENSIONS,
  SOURCE_SKIP_DIRS,
} from './patterns';
import { DEFAULT_IGNORE_PATTERNS } from './secretlessignore';
import {
  SOURCE_SKIP_REASONS,
  TEST_DIRS,
  TEST_FILE_GLOBS,
  KEY_FILE_EXTENSIONS,
  ENV_TEMPLATE_SUFFIXES,
  GLOBAL_CONFIG_LABELS,
  isEnvFile,
} from './scan';

/** `[placeholder, description]` for a value-taking flag; a description alone otherwise. */
type FlagDoc = string | [string, string];

interface VerbDoc {
  /** One line: what the verb does. */
  summary: string;
  /** Synopses after `<CLI> <verb>`; an empty string is the bare verb. */
  usage: string[];
  /** Descriptions for the flags `VERBS[verb].flags` registers. */
  flags?: Record<string, FlagDoc>;
  /** Lines printed after the options, e.g. what each subcommand does. */
  notes?: string[];
}

const BACKENDS = 'local, keychain, 1password, vault, gcp-sm';
const JSON_DOC = 'Machine-readable JSON output (for CI)';

/** Help lines stay inside an 80-column terminal, counting the 4-space notes indent. */
const NOTE_WIDTH = 76;

/**
 * Pack `items` into lines no wider than NOTE_WIDTH. The first line starts with
 * `lead`, the rest with `indent`; pass both the same length.
 */
function wrapList(items: readonly string[], indent: string, sep = ' ', lead = indent): string[] {
  const lines: string[] = [];
  let line = '';
  for (const item of items) {
    const next = line ? `${line}${sep}${item}` : item;
    if (line && indent.length + next.length > NOTE_WIDTH) {
      lines.push((lines.length ? indent : lead) + line);
      line = item;
    } else {
      line = next;
    }
  }
  if (line) lines.push((lines.length ? indent : lead) + line);
  return lines;
}

/**
 * What each source-walk skip reason covers, keyed like `SOURCE_SKIP_REASONS`.
 *
 * Typed as a Record over the catalog's keys, so a reason added to the walk
 * without a line here does not compile. Each list is read from the set the
 * walk consults rather than written out, and the test-file globs are checked
 * against `isTestFile` by a test, so a list cannot name something the walk
 * opens.
 */
function skipReasonDetails(): Record<keyof typeof SOURCE_SKIP_REASONS, string[]> {
  const at = ' '.repeat(6);
  const pruned = new Set([...TEST_DIRS, ...SOURCE_SKIP_DIRS]);
  const ignoreOnly = DEFAULT_IGNORE_PATTERNS.filter((p) => !pruned.has(p.replace(/\/$/, '')));
  const buildDirs = [...SOURCE_SKIP_DIRS].filter((d) => d !== '.git').map((d) => `${d}/`);
  return {
    unsupportedType: [
      `${at}any other file, e.g. notes.txt, README.md, report.ipynb, and`,
      `${at}generated lockfiles such as package-lock.json`,
    ],
    configNotListed: [
      `${at}a config-format file whose name is not listed above, e.g.`,
      `${at}secrets.json, values.yaml, app.toml; by extension:`,
      ...wrapList([...CONFIG_SHAPED_EXTENSIONS], at),
      `${at}and by name:`,
      ...wrapList([...CONFIG_SHAPED_BASENAMES, 'Dockerfile.*', '*.Dockerfile'], at),
    ],
    testFile: wrapList(TEST_FILE_GLOBS, at, '  '),
    testDir: wrapList([...TEST_DIRS].map((d) => `${d}/`), at, '  '),
    ignoreRule: [
      `${at}a path in .secretlessignore or in the default-ignore list,`,
      `${at}which also holds ${ignoreOnly.join(' ')}`,
    ],
    hiddenDir: [`${at}source files under .claude/, .vscode/ or any other dot-directory`],
    buildOutput: [...wrapList(buildDirs, at), `${at}no flag enters these`],
    gitMetadata: [`${at}.git/`],
  };
}

/**
 * The `scan --help` notes: what a directory scan opens, what it does not and
 * the reason the scan reports for each skip, and that naming a path scans it.
 *
 * The help named only dependency and build output as unread, while the scan
 * prints one of several reasons beside each path it skipped. The reason labels
 * below are the exact strings the scan prints, so a user can look one up here.
 */
function scanCoverageNotes(): string[] {
  const templates = [...ENV_TEMPLATE_SUFFIXES].map((t) => `.env.${t}`).join(' ');
  const configNames = CONFIG_FILES.filter((f) => !isEnvFile(f));
  const details = skipReasonDetails();
  const reasons = (Object.keys(SOURCE_SKIP_REASONS) as Array<keyof typeof SOURCE_SKIP_REASONS>)
    .flatMap((key) => [`  ${SOURCE_SKIP_REASONS[key]}`, ...details[key]]);
  return [
    'A directory scan opens only these files:',
    ...wrapList([...SOURCE_FILE_EXTENSIONS], ' '.repeat(11), ' ', '  source   '),
    '  config   .env and .env.*, except the templates',
    `           ${templates}; and by name:`,
    ...wrapList(configNames, ' '.repeat(11)),
    `  key      ${[...KEY_FILE_EXTENSIONS].join(' ')}`,
    '           (a .p12, .pfx or .secretless-bundle file is a finding by its',
    '           presence alone)',
    // Read on every directory scan, from outside the directory: "it opens
    // nothing else" was untrue while these went unnamed.
    ...wrapList([...GLOBAL_CONFIG_LABELS], ' '.repeat(11), ' ', '  home     '),
    '           (AI tool settings in your home directory)',
    '',
    'It opens nothing else. These are the reasons the scan reports for what',
    'it skipped, each with the flag that opens it, where one does:',
    ...reasons,
    '',
    'Name a path to scan it. A named file is opened whatever its type, and no',
    'ignore or test-file rule applies to it (scan notes.txt). A named directory',
    'is walked with the rules above, even one a scan of its parent skips',
    '(scan dist, scan .claude).',
  ];
}

const DOCS: Readonly<Record<string, VerbDoc>> = {
  scan: {
    summary: 'Scan config and source files for hardcoded secrets.',
    usage: ['[dir] [options]', '--history'],
    flags: {
      '--history': 'Scan shell history for credentials instead of files',
      '--include-tests': 'Include test files in the source scan',
      '--include-config': 'Also scan config files not on the built-in list',
      '--explain': 'Detailed per-finding view with remediation',
      '--no-ignore': 'Disable .secretlessignore and the default-ignore list',
      '--show-placeholders': 'Show values hidden as placeholders',
      '--min-confidence': ['<n>', 'Drop findings with composite confidence below n (0-1)'],
      '--max-files': ['<n>', 'Raise the file-count cap (default 5000)'],
      '--max-file-size': ['<size>', 'Raise the per-file size cap (e.g. 20mb, 500kb)'],
      '--json': JSON_DOC,
    },
    notes: scanCoverageNotes(),
  },
  status: {
    summary: 'Show protection status.',
    usage: ['[dir] [--json]'],
    flags: { '--json': JSON_DOC },
  },
  verify: {
    summary: 'Verify keys are usable but hidden from AI.',
    usage: ['[dir] [--all]'],
    flags: { '--all': 'List every known env var, not only the summary' },
  },
  'scan-staged': {
    summary: 'Scan the files staged for commit (the pre-commit hook body).',
    usage: ['[--no-ignore]'],
    flags: { '--no-ignore': 'Disable .secretlessignore and the default-ignore list' },
  },
  'scan-history': {
    summary: 'Scan shell history for credentials.',
    usage: [''],
  },
  'mcp-status': {
    summary: 'Show MCP protection status.',
    usage: [''],
  },
  feedback: {
    summary: 'Star, file an issue, or join the discussion.',
    usage: [''],
  },
  diff: {
    summary: 'Show how secretless-managed files have changed vs a git ref (default HEAD).',
    usage: ['[<ref>]'],
  },
  clean: {
    summary: 'Scan and redact credentials in AI transcripts.',
    usage: ['[--dry-run] [--last] [--path <p>]'],
    flags: {
      '--dry-run': 'Report findings without redacting or marking secrets exposed',
      '--last': 'Only clean the most recent session per project',
      '--path': ['<p>', 'Scan a specific file or directory'],
    },
    notes: [
      'A redacted value that matches a stored secret marks that secret exposed',
      '(`secret list --needs-rotation`). To find the match, the stored values are',
      'read whenever a credential is found, on a dry run too, so a keychain store',
      'can ask to be unlocked.',
    ],
  },
  'clean-history': {
    summary: 'Redact credentials in shell history.',
    usage: ['[--dry-run]'],
    flags: { '--dry-run': 'Preview without modifying' },
  },
  run: {
    summary: 'Run a command with secrets injected into its environment.',
    usage: ['[--only KEY1,KEY2] [--allow-argv] -- <command> [args...]'],
    flags: {
      '--only': ['KEY1,KEY2', 'Inject only the named secrets'],
      '--allow-argv': 'Start the command even when a secret value is on its command line',
    },
    notes: [
      'A secret value on the command line is visible in process listings (ps), so',
      'run refuses one of eight or more characters, verbatim or URL-encoded, unless',
      '--allow-argv is given. Shorter values are not checked. Let the command read',
      'the value from its environment instead.',
    ],
  },
  env: {
    summary: 'Output export statements for the shell.',
    usage: ['[--only KEY1,KEY2]'],
    flags: { '--only': ['KEY1,KEY2', 'Export only the named secrets'] },
  },
  init: {
    summary: 'Set up protections for your AI tools.',
    usage: ['[dir]'],
  },
  doctor: {
    summary: 'Diagnose shell profile issues and plaintext git credential files.',
    usage: ['[--fix]'],
    flags: { '--fix': 'Apply the shell profile fixes it finds' },
    notes: [
      'Also reports ~/.git-credentials, ~/.config/git/credentials and ~/.netrc lines',
      'that hold a credential (count and line numbers, never values) and a',
      'credential.helper set to store. --fix does not change these.',
    ],
  },
  import: {
    summary: 'Import secrets from a .env file, or from a bundle written by `export`.',
    usage: ['<file>', '--detect', '<bundle> [--force]'],
    flags: {
      '--detect': 'Auto-find and import .env files',
      '--force': 'Replace names already in this machine\'s store (bundle only)',
    },
    notes: [
      'A bundle asks for its passphrase in the terminal, or reads SECRETLESS_EXPORT_PASSPHRASE.',
      'Nothing is written when the passphrase is wrong or a name already exists without --force.',
    ],
  },
  export: {
    summary: 'Write secrets to an encrypted bundle, to move them to another machine.',
    usage: ['--out <file>.secretless-bundle [--only KEY1,KEY2]'],
    flags: {
      '--out': ['<file>.secretless-bundle', 'The bundle to create; an existing file is never replaced'],
      '--only': ['KEY1,KEY2', 'Export only the named secrets'],
    },
    notes: [
      'The passphrase is asked for twice in the terminal, or read from SECRETLESS_EXPORT_PASSPHRASE;',
      'it is never accepted as an argument. Import the bundle with `import <bundle>`.',
    ],
  },
  setup: {
    summary: 'Set up secrets from the .secretless manifest.',
    usage: ['[--check]'],
    flags: { '--check': 'Check for missing required secrets without prompting (CI)' },
  },
  secret: {
    summary: 'Store, list, describe, retrieve, remove, sync or push secrets, and track exposed ones until rotated.',
    usage: [
      'set <NAME[=VALUE]> [--description <text>] [--meta <key=value>]...',
      'set <NAME> --from-clipboard [--keep-clipboard] [--description <text>] [--meta <key=value>]...',
      'list [--long] [--json] [--app <name>] [--needs-rotation]',
      'show [--json] <NAME>',
      'exposed <NAME> --where <note> [--at <date>]',
      'get [--force] <NAME>',
      'rm <NAME>',
      'sync --from <backend> [--only K1,K2 | --manifest <file>] [--dry-run] [--force]',
      'push <NAME[,NAME2...]> --to <azure-kv|vault|gcp-sm> [--vault <name>] [--as <names>] [--dry-run]',
    ],
    flags: {
      '--force': 'get: retrieve in non-interactive contexts. sync: replace local values that differ',
      '--description': ['<text>', 'set: record what the secret is for'],
      '--meta': ['<key=value>', 'set: record a metadata field; repeatable; key= removes it'],
      '--from-clipboard': 'set: read the value from the clipboard, then clear it (recommended for a key copied from a web page)',
      '--keep-clipboard': 'set: with --from-clipboard, leave the value in the clipboard',
      '--long': 'list: show descriptions and metadata',
      '--app': ['<name>', 'list: only secrets recorded with --meta app=<name>'],
      '--needs-rotation': 'list: exposed secrets not yet rotated; exits 1 while any is open',
      '--where': ['<note>', 'exposed: where the value was exposed (never the value)'],
      '--at': ['<date>', 'exposed: when, as 2026-10-07 or an ISO 8601 time (default now)'],
      '--json': 'list, show: machine-readable JSON output',
      '--from': ['<backend>', `sync: backend to copy from (${BACKENDS})`],
      '--only': ['K1,K2', 'sync: copy only the named secrets'],
      '--manifest': ['<file>', 'sync: copy the required names of this .secretless file'],
      '--dry-run': 'sync, push: report what each name would get (created, updated, a new version); write nothing',
      '--to': ['<target>', 'push: cloud store to write to (azure-kv, vault, gcp-sm)'],
      '--vault': ['<name>', 'push: the Azure Key Vault to write to (--to azure-kv)'],
      '--as': ['<names>', 'push: the names to use in the target, one per secret, in order'],
    },
    notes: [
      'To store a key copied from a web page, use `set NAME --from-clipboard`: the value',
      'never reaches the command line, the screen or shell history, and the clipboard',
      'is cleared afterwards unless it changed since it was read. `set NAME` on a',
      'terminal prompts with input hidden.',
      'Descriptions and metadata are not secrets: they are kept beside the store in',
      'plain text and printed by `show` and `list --long`. Values never are.',
      'Keys are free-form; app, provider, scopes, tokenTtl, redirectUri and expiresAt',
      'are conventions, not a schema. Without --description or --meta, `set` keeps',
      'what was recorded before, so rotating a value does not erase it.',
      'sync copies by name into this machine\'s store; values are never printed.',
      'Without --only or --manifest it copies the required names of ./.secretless.',
      'A local value that differs is left as is and reported unless --force is given.',
      'push sends each value in an HTTPS request body, never on a command line, and',
      'prints the identifier, version and the reference to use next; never the value.',
      'A name not stored here stops the push before anything is written.',
      '`exposed` records exposedAt and exposedWhere in the metadata. `set` with a',
      'different value closes the exposure and records rotatedAt; the same value',
      'leaves it open. `clean` and `watch` mark a stored secret exposed when they',
      'redact its value. A value written by `sync`, `import` (a .env file or a',
      'bundle) or `setup` closes or leaves an exposure the same way, but those',
      'commands do not print which; `list --needs-rotation` shows what is open.',
    ],
  },
  watch: {
    summary: 'Monitor transcripts in real time.',
    usage: ['<start|stop|status|install|uninstall>'],
    notes: [
      'start       Start watching (foreground)',
      'stop        Stop the watcher',
      'status      Check if watcher is running',
      'install     Install as macOS LaunchAgent (auto-start on login)',
      'uninstall   Remove LaunchAgent',
    ],
  },
  hook: {
    summary: 'Manage the pre-commit secret scanner.',
    usage: ['<install|uninstall|status>', '--check-only'],
    flags: { '--check-only': 'Session check (for PreToolUse hooks)' },
  },
  'git-credential': {
    summary: 'Serve a stored token to git over HTTPS, instead of a plaintext credential file.',
    usage: [
      'install --host <host> --name <NAME> [--username <user>]',
      'uninstall --host <host>',
    ],
    flags: {
      '--host': ['<host>', 'Host name, with :port if the remote uses one (github.com)'],
      '--name': ['<NAME>', 'Secret store name holding the token (GITHUB_TOKEN)'],
      '--username': ['<user>', 'Username to send (default: the remote URL\'s, else x-access-token)'],
    },
    notes: [
      'install adds an empty entry and this helper to credential.https://<host>.helper',
      'in the global git config. The empty entry keeps other helpers, such as store,',
      'from being asked for that host or handed the token. No value is written to any',
      'config file. uninstall removes those two entries and nothing else.',
      'get, store and erase are run by git. get answers only https requests for its',
      'host and refuses when stdin or stdout is a terminal; store and erase write nothing.',
    ],
  },
  warm: {
    summary: 'Warm the biometric session (Touch ID on macOS).',
    usage: ['[--ttl <duration>] [--no-broker]'],
    flags: {
      '--ttl': ['<duration>', 'Set session TTL (300, 5m, 1h, 1d)'],
      '--no-broker': 'Skip auto-starting the broker daemon',
    },
  },
  install: {
    summary: 'Install the broker as a login daemon (macOS).',
    usage: ['', 'uninstall', 'status'],
  },
  'protect-mcp': {
    summary: 'Encrypt MCP server secrets.',
    usage: ['[--backend <type>]'],
    flags: { '--backend': ['<type>', `Backend for the MCP secrets (${BACKENDS})`] },
  },
  'mcp-unprotect': {
    summary: 'Restore original MCP configs.',
    usage: [''],
  },
  ignore: {
    summary: 'Append a path or glob to .secretlessignore.',
    usage: ['<path>', '--pattern <glob>'],
    flags: { '--pattern': ['<glob>', 'Append a glob pattern rather than a path'] },
  },
  telemetry: {
    summary: 'Show or change anonymous usage telemetry.',
    usage: ['[on|off|status]'],
  },
  rules: {
    summary: 'List, create or test custom deny rules.',
    usage: ['', 'init', 'test <pattern> [--env|--file|--bash]'],
    flags: {
      '--env': 'Test the pattern as an environment variable rule',
      '--file': 'Test the pattern as a file rule',
      '--bash': 'Test the pattern as a bash command rule',
    },
  },
  backend: {
    summary: 'Show or change the secret storage backend.',
    usage: ['', 'set <type>', 'list', 'purge [--prefix mcp|secret] [--yes]'],
    flags: {
      '--yes': 'Skip the confirmation prompt (purge)',
      '--prefix': ['mcp|secret', 'Limit purge to one kind of entry'],
      '--from': ['<backend>', `Source backend (${BACKENDS})`],
      '--to': ['<backend>', `Destination backend (${BACKENDS})`],
    },
  },
  migrate: {
    summary: 'Migrate secrets between backends.',
    usage: ['--from <backend> --to <backend>'],
    flags: {
      '--from': ['<backend>', `Backend to read secrets from (${BACKENDS})`],
      '--to': ['<backend>', `Backend to write them to (${BACKENDS})`],
    },
  },
  cache: {
    summary: 'Secret cache (reduces OS auth prompts for keychain/1password).',
    usage: ['', 'ttl <duration>', 'clear'],
    notes: [
      'ttl <duration>   Set TTL (5m, 1h, 1d, off)',
      'clear            Clear cached secrets',
    ],
  },
  scope: {
    summary: 'Discover and check the permissions an agent uses.',
    usage: ['discover <name>', 'check <name>', 'list', 'reset <name>'],
  },
  broker: {
    summary: 'Control the credential broker daemon.',
    usage: ['start [options]', 'stop', 'status'],
    flags: {
      '--aim-url': ['<url>', 'AIM server URL for identity verification'],
      '--aim-token': ['<token>', 'Bearer token for AIM auth (or env SECRETLESS_AIM_TOKEN)'],
      '--port': ['<port>', 'HTTP port (default: 19421)'],
      '--policy-file': ['<path>', 'Policy file path'],
    },
  },
  vault: {
    summary: 'Identity vault (requires @opena2a/aim-core).',
    usage: [
      'init',
      'register <namespace> [options]',
      'list',
      'rotate <namespace> [--env <VAR>]',
      'revoke <namespace>',
      'exec <namespace> [--env-name <VAR>] -- <command> [args...]',
      'audit [--limit <n>] [--since <ISO-date>] [--namespace <ns>]',
      'scan [dir]',
      'test',
      'migrate [--env-file <path>] [--dry-run]',
    ],
    flags: {
      '--name': ['<name>', 'Agent name (init)'],
      '--value': ['<value>', 'Value as an argument (shell history keeps it); omit it to be prompted'],
      '--env': ['<VAR>', 'Read the value from an environment variable'],
      '--description': ['<desc>', 'Namespace description'],
      '--operations': ['<ops>', 'Comma-separated: read,write,delete,admin'],
      '--url-patterns': ['<pats>', 'Comma-separated URL patterns'],
      '--limit': ['<n>', 'Max audit events to show (default: 50)'],
      '--since': ['<ISO-date>', 'Audit events after this timestamp'],
      '--namespace': ['<ns>', 'Filter audit events by namespace'],
      '--env-name': ['<VAR>', 'Env var name for the credential (default: NAMESPACE)'],
      '--env-file': ['<path>', 'Migrate from a .env file'],
      '--dry-run': 'Preview the migration without writing',
    },
    notes: [
      'register and rotate read the value from a prompt, a pipe or --env <VAR>, which',
      'keeps it out of shell history and the process list.',
    ],
  },
};

/** `--path <p>` for a value-taking flag, `--dry-run` otherwise. */
function label(flag: string, takesValue: boolean, doc: FlagDoc | undefined): string {
  if (!takesValue) return flag;
  const placeholder = Array.isArray(doc) ? doc[0] : '<value>';
  return `${flag} ${placeholder}`;
}

function description(doc: FlagDoc | undefined): string {
  if (doc === undefined) return '';
  return Array.isArray(doc) ? doc[1] : doc;
}

/**
 * Print help for one registered verb. A token that is not a key of `VERBS`
 * (`--help` itself, `-h`, or an unknown command) gets the global help, which is
 * what the interception printed for everything before this module existed.
 */
export function printCommandHelp(verb: string): void {
  const spec = VERBS[verb];
  if (!spec) {
    printHelp();
    return;
  }
  const doc = DOCS[verb] ?? { summary: `Run \`${verb}\`.`, usage: ['[options]'] };
  const banner = IS_EMBEDDED ? '' : `  Secretless v${VERSION}\n`;

  const rows: Array<[string, string]> = Object.keys(spec.flags).map((flag) => [
    label(flag, spec.flags[flag], doc.flags?.[flag]),
    description(doc.flags?.[flag]),
  ]);
  rows.push(['-h, --help', 'Show this help']);
  const width = Math.max(...rows.map(([l]) => l.length)) + 3;

  const lines: string[] = [];
  lines.push('');
  if (banner) lines.push(banner.replace(/\n$/, ''));
  lines.push(`  ${doc.summary}`);
  lines.push('');
  lines.push('  Usage:');
  for (const u of doc.usage) {
    lines.push(`    ${CLI} ${verb}${u ? ` ${u}` : ''}`);
  }
  lines.push('');
  lines.push('  Options:');
  for (const [l, d] of rows) {
    lines.push(`    ${d ? l.padEnd(width) + d : l}`);
  }
  if (doc.notes && doc.notes.length > 0) {
    lines.push('');
    for (const n of doc.notes) lines.push(n ? `    ${n}` : '');
  }
  lines.push('');
  lines.push(`  Run \`${CLI} --help\` for every command.`);
  lines.push('');
  console.log(lines.join('\n'));
}
