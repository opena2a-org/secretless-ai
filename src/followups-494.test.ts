/**
 * `git-credential` offered `secret set NAME` for a `--name` that `secret set`
 * refuses (#494). `--name` takes any name the store takes, and the store takes
 * a name that starts with a digit, '_' or '-', which `secret set` refuses. The
 * install summary, `get` with no stored value, `get` with a stored value git
 * cannot carry, and `erase` each printed that command, which stores nothing.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runGitCredential, type GitCredentialDeps } from './commands/git-credential';
import { CLI, CLI_BARE } from './commands/utils';
import { isSettableSecretName, isValidSecretName } from './secret-store';
import type { GitRunner } from './git-credential';

let out: string[];
let err: string[];
let answers: string[];
let added: string[];

beforeEach(() => {
  out = [];
  err = [];
  answers = [];
  added = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
});
afterEach(() => vi.restoreAllMocks());

/** A global git config with no entry for the host. Records each value added. */
const git: GitRunner = (args) => {
  if (args.includes('--get-all')) return { status: 1, stdout: '', stderr: '' };
  if (args.includes('--add')) added.push(args[args.length - 1]);
  return { status: 0, stdout: '', stderr: '' };
};

function deps(input: string, stored: Record<string, string>): GitCredentialDeps {
  return {
    createStore: () => ({ getSecret: async (name: string) => stored[name] }),
    readInput: async () => input,
    writeAnswer: (t) => { answers.push(t); },
    stdinIsTTY: false,
    stdoutIsTTY: false,
    git,
  };
}

const REQUEST = 'protocol=https\nhost=github.com\n\n';
const REFUSED = ['_GH_TOKEN', '1GH_TOKEN', '-GH_TOKEN'];
const INSTALL_AGAIN = `then run: ${CLI} git-credential install --host github.com --name <NAME>`;

function reason(name: string): string {
  return `  "${name}" cannot be stored by \`secret set\`, which takes a letter, then letters, digits, '_' or '-'`;
}

describe('git-credential names no `secret set` command for a name `secret set` refuses (#494)', () => {
  it.each(REFUSED)('%s is a name the store takes and `secret set` refuses', (name) => {
    expect(isValidSecretName(name)).toBe(true);
    expect(isSettableSecretName(name)).toBe(false);
  });

  it.each(REFUSED)('install, for %s, prints the reason in place of the Store line and keeps Verify and Undo', async (name) => {
    expect(await runGitCredential(['install', '--host', 'github.com', '--name', name], deps('', {}))).toBe(0);

    const lines = out.join('\n').split('\n');
    expect(lines.filter((line) => line.includes(`secret set ${name}`) || line.includes('Store:'))).toEqual([]);
    expect(lines.slice(-4)).toEqual([
      '  Verify:  git config --global --get-all credential.https://github.com.helper',
      `${reason(name)}; if it is not stored yet, store the token under a name \`secret set\` takes, ${INSTALL_AGAIN}`,
      `  Undo:    ${CLI} git-credential uninstall --host github.com`,
      '',
    ]);
    // The entries were still written: the store can hold the name.
    expect(added).toHaveLength(2);
    expect(added[1]).toMatch(new RegExp(` git-credential --host github\\.com --name ${name}$`));
  });

  it.each(REFUSED)('get, with nothing stored as %s, prints the reason in place of the Store it line', async (name) => {
    expect(await runGitCredential(['--host', 'github.com', '--name', name, 'get'], deps(REQUEST, {}))).toBe(1);

    expect(answers).toEqual([]);
    expect(err).toEqual([
      `  ${CLI_BARE}: ${name} is not in the secret store, so git was given no credential for github.com.`,
      `${reason(name)}; store the token under a name \`secret set\` takes, ${INSTALL_AGAIN}`,
    ]);
  });

  it.each(REFUSED)('get, with a stored %s holding a line break, prints the reason in place of the single-line Store line', async (name) => {
    const stored = { [name]: 'not-a-real-token\nhost=evil.example' };
    expect(await runGitCredential(['--host', 'github.com', '--name', name, 'get'], deps(REQUEST, stored))).toBe(1);

    expect(answers).toEqual([]);
    expect(err).toEqual([
      `  ${CLI_BARE}: the stored ${name} holds a line break, which the git credential protocol cannot carry, so it was not sent to git.`,
      `${reason(name)}; store the token as a single line under a name \`secret set\` takes, ${INSTALL_AGAIN}`,
    ]);
    expect(err.join('\n')).not.toContain('not-a-real-token');
  });

  it.each(REFUSED)('erase, for %s, prints the reason in place of the Replace it line', async (name) => {
    expect(await runGitCredential(['--host', 'github.com', '--name', name, 'erase'], deps(REQUEST, {}))).toBe(0);

    expect(err).toEqual([
      `  ${CLI_BARE}: github.com did not accept the token stored as ${name}. It was left in the store.`,
      `${reason(name)}; store the new token under a name \`secret set\` takes, ${INSTALL_AGAIN}`,
    ]);
  });

  it('the install command named keeps the --username the helper was installed with', async () => {
    const args = ['--host', 'github.com', '--name', '_GH_TOKEN', '--username', 'bot'];
    expect(await runGitCredential([...args, 'get'], deps(REQUEST, {}))).toBe(1);
    expect(await runGitCredential([...args, 'erase'], deps(REQUEST, {}))).toBe(0);
    expect(await runGitCredential(['install', ...args], deps('', {}))).toBe(0);

    const named = [...err, ...out].filter((line) => line.includes(INSTALL_AGAIN));
    expect(named).toHaveLength(3);
    for (const line of named) expect(line.endsWith(`${INSTALL_AGAIN} --username bot`)).toBe(true);
  });

  it('the install command named, given a name `secret set` takes, points git at that name', async () => {
    const args = ['--host', 'github.com', '--name', '_GH_TOKEN', '--username', 'bot'];
    expect(await runGitCredential([...args, 'erase'], deps(REQUEST, {}))).toBe(0);
    const marker = `then run: ${CLI} `;
    const command = err[1].slice(err[1].indexOf(marker) + marker.length).replace('<NAME>', 'GH_TOKEN');
    const argv = command.split(' ');
    expect(argv[0]).toBe('git-credential');

    expect(await runGitCredential(argv.slice(1), deps('', {}))).toBe(0);
    expect(added).toEqual(['', expect.stringMatching(/ git-credential --host github\.com --name GH_TOKEN --username bot$/)]);
    expect(out).toContain(`  Store:   ${CLI} secret set GH_TOKEN   (if it is not stored yet)`);
  });

  it('CONTROL: a name `secret set` takes still gets the `secret set` command in each of the four places', async () => {
    const name = 'GH_TOKEN';
    expect(await runGitCredential(['install', '--host', 'github.com', '--name', name], deps('', {}))).toBe(0);
    expect(await runGitCredential(['--host', 'github.com', '--name', name, 'get'], deps(REQUEST, {}))).toBe(1);
    expect(await runGitCredential(['--host', 'github.com', '--name', name, 'get'], deps(REQUEST, { [name]: 'not-a-real-token\nx' }))).toBe(1);
    expect(await runGitCredential(['--host', 'github.com', '--name', name, 'erase'], deps(REQUEST, {}))).toBe(0);

    expect(out).toContain(`  Store:   ${CLI} secret set GH_TOKEN   (if it is not stored yet)`);
    expect(err).toContain(`  Store it: ${CLI} secret set GH_TOKEN`);
    expect(err).toContain(`  Store it again as a single line: ${CLI} secret set GH_TOKEN`);
    expect(err).toContain(`  Replace it: ${CLI} secret set GH_TOKEN`);
    expect([...out, ...err].join('\n')).not.toContain('cannot be stored by');
  });
});
