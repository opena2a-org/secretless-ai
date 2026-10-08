/**
 * `git-credential` — serve a stored token to git over HTTPS (#238).
 *
 *   git-credential install --host <host> --name <NAME> [--username <user>]
 *   git-credential uninstall --host <host>
 *   git-credential get|store|erase      (run by git, never by hand)
 *
 * The protocol actions write only to git: `get` answers on stdout, which git
 * reads through a pipe, and refuses when either end is a terminal. Every
 * message for a person goes to stderr, which git passes through.
 */

import { SecretStore } from '../secret-store';
import { EXIT_USAGE } from '../argv';
import { nearestMatch } from '../near-miss';
import { CLI, CLI_BARE, formatCommandError } from './utils';
import {
  GIT_PROTOCOL_ACTIONS,
  DEFAULT_GIT_USERNAME,
  MAX_REQUEST_BYTES,
  type GitRunner,
  type HelperMapping,
  runGit,
  hostProblem,
  hostShapeProblem,
  nameProblem,
  usernameProblem,
  parseCredentialRequest,
  matchRequest,
  valueProblem,
  formatAnswer,
  installHelper,
  uninstallHelper,
} from '../git-credential';

const ACTIONS = ['install', 'uninstall', ...GIT_PROTOCOL_ACTIONS];

const VALUE_FLAGS = ['--host', '--name', '--username'];

/** Which flags each action reads. A flag outside its action's list is refused. */
const ACTION_FLAGS: Record<string, readonly string[]> = {
  install: ['--host', '--name', '--username'],
  uninstall: ['--host'],
  get: ['--host', '--name', '--username'],
  store: ['--host', '--name', '--username'],
  erase: ['--host', '--name', '--username'],
};

export interface GitCredentialDeps {
  /** The store `get` reads from. */
  createStore?: () => Pick<SecretStore, 'getSecret'>;
  /** Runs git for install and uninstall. */
  git?: GitRunner;
  /** The request git wrote on stdin. */
  readInput?: () => Promise<string>;
  /** Where the answer to `get` goes. */
  writeAnswer?: (text: string) => void;
  stdinIsTTY?: boolean;
  stdoutIsTTY?: boolean;
}

/** stdin up to EOF, refusing more than MAX_REQUEST_BYTES. */
function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    process.stdin.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) {
        process.stdin.destroy();
        reject(new Error(`the request on stdin is larger than ${MAX_REQUEST_BYTES} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    process.stdin.on('error', reject);
  });
}

function usage(): void {
  console.error(`  Usage: ${CLI_BARE} git-credential install --host <host> --name <NAME> [--username <user>]`);
  console.error(`         ${CLI_BARE} git-credential uninstall --host <host>`);
  console.error(`  Run \`${CLI_BARE} git-credential --help\` for details.`);
}

interface Parsed {
  action: string | undefined;
  values: Record<string, string>;
  errors: string[];
}

/** argv after the verb. `--flag=value` is already split by the shared argv layer. */
function parse(args: string[]): Parsed {
  const values: Record<string, string> = {};
  const positionals: string[] = [];
  const errors: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (VALUE_FLAGS.includes(a)) {
      values[a] = args[i + 1] ?? '';
      i++;
      continue;
    }
    positionals.push(a);
  }
  const action = positionals[0];
  if (positionals.length > 1) {
    errors.push(`git-credential takes one action, but was given: ${positionals.join(' ')}`);
  }
  if (action !== undefined && ACTIONS.includes(action)) {
    for (const flag of Object.keys(values)) {
      if (!ACTION_FLAGS[action].includes(flag)) errors.push(`${flag} does not apply to \`git-credential ${action}\`.`);
    }
  }
  return { action, values, errors };
}

/** The mapping named by the flags, or the reason it cannot be used. */
function mappingFrom(values: Record<string, string>, needName: boolean): HelperMapping | string {
  const host = values['--host']?.toLowerCase();
  if (!host) return '--host is required, e.g. --host github.com';
  // Only `uninstall` takes no name. It checks the shape alone, so an entry
  // written before the port range was checked can still be removed.
  const hp = needName ? hostProblem(host) : hostShapeProblem(host);
  if (hp) return hp;
  const name = values['--name'];
  if (needName) {
    if (!name) return '--name is required: the secret store name holding the token, e.g. --name GITHUB_TOKEN';
    const np = nameProblem(name);
    if (np) return np;
  }
  const username = values['--username'];
  if (username !== undefined) {
    const up = usernameProblem(username);
    if (up) return up;
  }
  return { host, name: name ?? '', ...(username !== undefined ? { username } : {}) };
}

export async function runGitCredential(args: string[], deps: GitCredentialDeps = {}): Promise<number> {
  const parsed = parse(args);
  const { action } = parsed;

  if (action === undefined) {
    console.error('\n  git-credential needs an action.');
    usage();
    console.error();
    return EXIT_USAGE;
  }
  if (!ACTIONS.includes(action)) {
    const near = nearestMatch(action, ACTIONS);
    console.error(`\n  Unknown git-credential action: ${action}${near ? ` (did you mean \`${near}\`?)` : ''}`);
    console.error('  Nothing was changed.');
    usage();
    console.error();
    return EXIT_USAGE;
  }
  if (parsed.errors.length > 0) {
    for (const e of parsed.errors) console.error(`  ${e}`);
    console.error(`  \`git-credential ${action}\` was not run. Nothing was changed.`);
    return EXIT_USAGE;
  }

  switch (action) {
    case 'install':
      return runInstall(parsed.values, deps.git ?? runGit);
    case 'uninstall':
      return runUninstall(parsed.values, deps.git ?? runGit);
    case 'get':
      return runGet(parsed.values, deps);
    default:
      return runIgnoredAction(action, parsed.values, deps);
  }
}

function runInstall(values: Record<string, string>, git: GitRunner): number {
  const mapping = mappingFrom(values, true);
  if (typeof mapping === 'string') {
    console.error(`  ${mapping}`);
    console.error('  `git-credential install` was not run. Nothing was changed.');
    return EXIT_USAGE;
  }
  let change;
  try {
    change = installHelper(git, CLI, mapping);
  } catch (err) {
    console.error(formatCommandError(err));
    return 1;
  }
  const user = mapping.username ?? `${DEFAULT_GIT_USERNAME} (or the user in the remote URL)`;
  console.log();
  console.log(change.changed
    ? `  git now asks ${CLI_BARE} for ${mapping.host} credentials over HTTPS.`
    : `  Already installed for ${mapping.host}. Nothing was changed.`);
  console.log(`    Secret:    ${mapping.name}, sent with username ${user}`);
  console.log(`    Config:    ${change.key} (global git config)`);
  console.log('               An empty entry comes first, so no other helper, such as store,');
  console.log(`               is asked for ${mapping.host} or handed the token.`);
  console.log('    No credential value was written to any file.');
  console.log();
  console.log(`  Verify:  git config --global --get-all ${change.key}`);
  console.log(`  Store:   ${CLI} secret set ${mapping.name}   (if it is not stored yet)`);
  console.log(`  Undo:    ${CLI} git-credential uninstall --host ${mapping.host}`);
  console.log();
  return 0;
}

function runUninstall(values: Record<string, string>, git: GitRunner): number {
  const mapping = mappingFrom(values, false);
  if (typeof mapping === 'string') {
    console.error(`  ${mapping}`);
    console.error('  `git-credential uninstall` was not run. Nothing was changed.');
    return EXIT_USAGE;
  }
  let change;
  try {
    change = uninstallHelper(git, mapping.host);
  } catch (err) {
    console.error(formatCommandError(err));
    return 1;
  }
  console.log();
  if (!change.changed) {
    console.log(`  No ${CLI_BARE} helper for ${mapping.host} in the global git config. Nothing was changed.`);
    console.log();
    return 0;
  }
  const removed = change.before.length - change.after.length;
  console.log(`  Removed ${removed} entr${removed === 1 ? 'y' : 'ies'} from ${change.key} (global git config).`);
  if (change.after.length > 0) {
    console.log(`  ${change.after.length} other entr${change.after.length === 1 ? 'y is' : 'ies are'} still configured for ${mapping.host} and were left as they were.`);
  }
  console.log('  Stored secrets were not changed.');
  console.log();
  console.log(`  Verify:  git config --global --get-all ${change.key}`);
  console.log();
  return 0;
}

async function runGet(values: Record<string, string>, deps: GitCredentialDeps): Promise<number> {
  const stdoutIsTTY = deps.stdoutIsTTY ?? !!process.stdout.isTTY;
  const stdinIsTTY = deps.stdinIsTTY ?? !!process.stdin.isTTY;
  // Refused before the store is opened, so a terminal never shows a value and
  // a keychain prompt is never raised for a request git did not make.
  if (stdoutIsTTY || stdinIsTTY) {
    console.error(`  ${CLI_BARE}: \`git-credential get\` answers git's credential protocol and does not print a value to a terminal.`);
    console.error('  Nothing was read from the secret store.');
    console.error(`  To see whether a secret is stored, without its value: ${CLI} secret show <NAME>`);
    return 1;
  }
  const mapping = mappingFrom(values, true);
  if (typeof mapping === 'string') {
    console.error(`  ${CLI_BARE} git-credential: ${mapping}`);
    console.error(`  Re-run: ${CLI} git-credential install --host <host> --name <NAME>`);
    return EXIT_USAGE;
  }

  let input: string;
  try {
    input = await (deps.readInput ?? readStdin)();
  } catch (err) {
    console.error(`  ${CLI_BARE} git-credential: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
  const match = matchRequest(parseCredentialRequest(input), mapping);
  // Not ours: answer nothing, so git asks its next helper or prompts.
  if (!match.ours) {
    if (process.env.SECRETLESS_DEBUG) console.error(`  ${CLI_BARE} git-credential: not answered: ${match.reason}`);
    return 0;
  }

  let value: string | undefined;
  try {
    const store = deps.createStore ? deps.createStore() : new SecretStore();
    value = await store.getSecret(mapping.name);
  } catch (err) {
    console.error(`  ${CLI_BARE}: could not read ${mapping.name} for ${mapping.host}, so git was given no credential.`);
    console.error(formatCommandError(err));
    return 1;
  }
  if (value === undefined) {
    console.error(`  ${CLI_BARE}: ${mapping.name} is not in the secret store, so git was given no credential for ${mapping.host}.`);
    console.error(`  Store it: ${CLI} secret set ${mapping.name}`);
    return 1;
  }
  const problem = valueProblem(value);
  if (problem) {
    console.error(`  ${CLI_BARE}: the stored ${mapping.name} ${problem}, so it was not sent to git.`);
    console.error(`  Store it again as a single line: ${CLI} secret set ${mapping.name}`);
    return 1;
  }
  (deps.writeAnswer ?? ((t: string) => { process.stdout.write(t); }))(formatAnswer(match.username, value));
  return 0;
}

/**
 * `store` and `erase`. Git sends `store` with the credential that just worked
 * and `erase` with one the server rejected. Both are read to the end, so git
 * never meets a closed pipe, and dropped: the token stays where it is, in the
 * store, and nothing is written in plaintext.
 */
async function runIgnoredAction(action: string, values: Record<string, string>, deps: GitCredentialDeps): Promise<number> {
  let input = '';
  if (!(deps.stdinIsTTY ?? !!process.stdin.isTTY)) {
    try {
      input = await (deps.readInput ?? readStdin)();
    } catch {
      return 0;
    }
  }
  if (action !== 'erase') return 0;
  const mapping = mappingFrom(values, true);
  if (typeof mapping === 'string') return 0;
  const match = matchRequest(parseCredentialRequest(input), mapping);
  if (!match.ours) return 0;
  console.error(`  ${CLI_BARE}: ${mapping.host} did not accept the token stored as ${mapping.name}. It was left in the store.`);
  console.error(`  Replace it: ${CLI} secret set ${mapping.name}`);
  return 0;
}
