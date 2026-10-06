import * as fs from 'fs';
import * as path from 'path';
import { SecretStore, isValidSecretName } from '../secret-store';
import { getShellHookLine, SHELL_HOOK_MARKER } from '../env';
import { CLI, CLI_BARE, formatCommandError } from './utils';
import { describeSecretShape } from '../secret-value';
import { isEmptyUpdate } from '../secret-annotations';
import type { AnnotationUpdate, SecretAnnotation } from '../secret-annotations';
import { createBackend } from '../backends/factory';
import type { SelectableBackendType } from '../backends/config';
import type { SecretBackend } from '../backends/types';
import { parseManifestDetailed, MANIFEST_FORMAT_HINT } from '../manifest';
import { syncSecrets, displayName } from '../secret-sync';
import type { SyncAction, SyncResult } from '../secret-sync';
import { resolveGcpProject, repositoryProjectNote } from '../backends/gcp-project';

/**
 * Ensure the shell profile has the eval hook for auto-loading secrets.
 * Called after `secret set` to make stored secrets available as env vars.
 */
function ensureShellHook(): void {
  const os = require('os');
  const fs = require('fs');

  const home = os.homedir();
  const shell = process.env.SHELL ?? '';
  const platform = os.platform();

  // Determine the right profile to modify
  let profilePath: string;
  if (platform === 'darwin' || shell.endsWith('/zsh')) {
    profilePath = path.join(home, '.zshenv');
  } else {
    profilePath = path.join(home, '.bashrc');
  }

  // Check if hook already exists
  let existing = '';
  try {
    existing = fs.readFileSync(profilePath, 'utf-8');
  } catch {
    // File doesn't exist — will create it
  }

  if (existing.includes(SHELL_HOOK_MARKER) || existing.includes('secretless-ai env')) {
    return; // Already installed
  }

  // Append the hook
  const hookLine = getShellHookLine();
  const block = `\n${SHELL_HOOK_MARKER}\n${hookLine}\n`;
  fs.writeFileSync(profilePath, existing + block);

  const profileName = path.basename(profilePath);
  console.log(`  Shell hook installed in ~/${profileName}`);
  console.log(`  Run: source ~/${profileName}   (or open a new terminal)`);
}

/** Flags read by one subcommand only. Another subcommand refuses them (#172). */
const SECRET_SUBCOMMAND_FLAGS: Readonly<Record<string, readonly string[]>> = {
  set: ['--description', '--meta'],
  list: ['--long', '--json', '--app'],
  show: ['--json'],
};
const SECRET_SUBCOMMANDS = new Set(['set', 'list', 'show', 'get', 'rm', 'remove', 'delete']);
const SCOPED_FLAGS = new Set(['--description', '--meta', '--long', '--json', '--app']);
const VALUE_FLAGS = new Set(['--description', '--meta', '--app']);

interface ParsedSecretArgs {
  /** Every token that is not one of SCOPED_FLAGS, in order (`--force` stays here). */
  rest: string[];
  values: Map<string, string[]>;
  switches: Set<string>;
}

/**
 * Pull the subcommand-scoped flags out of `args`, or return the reason they
 * cannot be read. `--force` and positionals are left in `rest` exactly as
 * before, so `get`, `rm` and `list` see the tokens they always saw.
 */
function parseSecretArgs(subcommand: string, args: string[]): ParsedSecretArgs | string {
  const parsed: ParsedSecretArgs = { rest: [], values: new Map(), switches: new Set() };
  // An unknown subcommand is reported as one, not as a misplaced flag.
  if (!SECRET_SUBCOMMANDS.has(subcommand)) {
    parsed.rest.push(...args);
    return parsed;
  }
  const allowed = SECRET_SUBCOMMAND_FLAGS[subcommand] ?? [];
  for (let i = 0; i < args.length; i++) {
    const token = args[i];
    const eq = token.indexOf('=');
    const flag = token.startsWith('--') && eq !== -1 ? token.slice(0, eq) : token;
    if (!SCOPED_FLAGS.has(flag)) {
      parsed.rest.push(token);
      continue;
    }
    if (!allowed.includes(flag)) {
      const owners = Object.keys(SECRET_SUBCOMMAND_FLAGS)
        .filter((s) => SECRET_SUBCOMMAND_FLAGS[s].includes(flag))
        .map((s) => `\`secret ${s}\``)
        .join(' and ');
      return `${flag} is read by ${owners}, not by \`secret ${subcommand}\`, so it would have been ignored.`;
    }
    if (VALUE_FLAGS.has(flag)) {
      const value = flag === token ? args[++i] : token.slice(eq + 1);
      if (value === undefined) return `${flag} needs a value, but none was given.`;
      const seen = parsed.values.get(flag) ?? [];
      if (seen.length > 0 && flag !== '--meta') {
        return `${flag} was given more than once; only one value can apply, so give it once.`;
      }
      parsed.values.set(flag, [...seen, value]);
      continue;
    }
    if (flag !== token) return `${flag} does not take a value.`;
    parsed.switches.add(flag);
  }
  return parsed;
}

/**
 * The annotation a `secret set` command line asks for, or the reason it cannot
 * be read. `--meta key=` (empty value) removes that key.
 */
function annotationFromArgs(parsed: ParsedSecretArgs): AnnotationUpdate | string {
  const update: AnnotationUpdate = {};
  const description = parsed.values.get('--description');
  if (description) update.description = description[0];
  const pairs = parsed.values.get('--meta') ?? [];
  if (pairs.length > 0) {
    const meta: Record<string, string> = {};
    for (const pair of pairs) {
      const eq = pair.indexOf('=');
      if (eq <= 0) {
        return '--meta takes key=value (for example --meta app=marketing_agent); '
          + 'give an empty value, --meta key=, to remove a key.';
      }
      const key = pair.slice(0, eq);
      if (Object.prototype.hasOwnProperty.call(meta, key)) {
        return `--meta ${key.slice(0, 64)} was given more than once; only one value can apply.`;
      }
      Object.defineProperty(meta, key, { value: pair.slice(eq + 1), enumerable: true, writable: true, configurable: true });
    }
    update.meta = meta;
  }
  return update;
}

/**
 * Text from the annotation file, made safe for a terminal. `set` refuses
 * control characters, but the file is plain JSON and may have been edited by
 * hand; an escape sequence in it must not reach the screen.
 */
function printable(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
}

/** `key=value` lines for display, in key order. */
function metaLines(meta: Record<string, string>): string[] {
  return Object.keys(meta).sort().map((k) => printable(`${k}=${meta[k]}`));
}

/** One line saying what a name now carries, after `secret set`. */
function describeAnnotation(annotation: SecretAnnotation | undefined): string {
  if (!annotation) return 'no description or metadata';
  const parts: string[] = [];
  if (annotation.description !== undefined) parts.push('a description');
  const keys = Object.keys(annotation.meta).sort();
  if (keys.length > 0) parts.push(`metadata ${keys.join(', ')}`);
  return parts.join(' and ');
}

/** The JSON form of one name's annotation, shared by `list --json` and `show --json`. */
function annotationJson(name: string, annotation: SecretAnnotation | undefined): Record<string, unknown> {
  return {
    name,
    description: annotation?.description ?? null,
    meta: annotation?.meta ?? {},
    recordedAt: annotation?.recordedAt ?? null,
    updatedAt: annotation?.updatedAt ?? null,
  };
}

/** Flags only `secret sync` reads. Refused on the other subcommands (below). */
const SYNC_ONLY_FLAGS = ['--from', '--only', '--manifest', '--dry-run'];

export interface RunSecretOptions {
  /** `--json`, as read by the dispatcher. */
  json?: boolean;
  /** Store factory. For DI/testing. */
  createStore?: () => SecretStore;
  /** Called after a successful `secret set`. For DI/testing. */
  afterSet?: () => void;
}

export async function runSecret(args: string[], options: RunSecretOptions = {}): Promise<number> {
  const subcommand = args[0];
  const createStore = options.createStore ?? (() => new SecretStore());
  const afterSet = options.afterSet ?? ensureShellHook;

  const parsedOrError = parseSecretArgs(subcommand ?? '', args.slice(1));
  if (typeof parsedOrError === 'string') {
    console.error(`\n  ${parsedOrError}`);
    console.error(`  Run \`${CLI_BARE} secret --help\` for usage.\n`);
    return 2;
  }
  const parsed = parsedOrError;
  const json = options.json === true || parsed.switches.has('--json');

  // The `secret` verb registers one flag list for all its subcommands. A sync
  // flag given to another subcommand would be dropped without a word, and
  // `secret set --dry-run NAME=VALUE` would then store the value it was asked
  // only to preview.
  if (subcommand !== 'sync') {
    const misplaced = args.slice(1).find((a) => SYNC_ONLY_FLAGS.includes(a));
    if (misplaced !== undefined) {
      console.error(`\n  ${misplaced} applies to \`secret sync\` only. \`secret ${subcommand}\` was not run. Nothing was changed.\n`);
      return 2;
    }
  }

  switch (subcommand) {
    case 'sync':
      return runSecretSync(args.slice(1));

    case 'set': {
      const nameArg = parsed.rest[0];
      if (!nameArg) {
        console.error(`\n  Usage: ${CLI_BARE} secret set <NAME[=VALUE]> [--description <text>] [--meta <key=value>]...\n`);
        return 1;
      }

      const annotation = annotationFromArgs(parsed);
      if (typeof annotation === 'string') {
        console.error(`\n  ${annotation}\n`);
        return 2;
      }

      // Validate secret name format
      const SECRET_NAME_RE = /^[a-zA-Z][a-zA-Z0-9_-]*$/;

      let name: string;
      let value: string | null;
      // Check for inline value: NAME=VALUE
      const eqIdx = nameArg.indexOf('=');
      if (eqIdx !== -1) {
        name = nameArg.slice(0, eqIdx);
        value = nameArg.slice(eqIdx + 1);
        if (!value) {
          console.error('  Error: no value provided.');
          console.error(`  Usage: ${CLI_BARE} secret set NAME=VALUE\n`);
          return 1;
        }
        if (!SECRET_NAME_RE.test(name)) {
          console.error('  Error: Invalid secret name. Use letters, numbers, underscores, hyphens. Must start with a letter.\n');
          return 1;
        }
      } else {
        // Read value from stdin
        name = nameArg;
        if (!SECRET_NAME_RE.test(name)) {
          console.error('  Error: Invalid secret name. Use letters, numbers, underscores, hyphens. Must start with a letter.\n');
          return 1;
        }
        value = await readSecretFromStdin(name);
        if (value === null) {
          console.error('  Error: no value provided.');
          console.error(`  Usage: ${CLI_BARE} secret set NAME=VALUE`);
          console.error(`  Or:    echo "value" | ${CLI_BARE} secret set NAME\n`);
          return 1;
        }
      }

      const store = createStore();
      // Named before the write, so a value never lands in a project the
      // repository chose without the user seeing which one (#177).
      const projectNote = repositoryProjectNote(store.backendName);
      if (projectNote) console.log(`  ${projectNote}`);
      try {
        await store.setSecret(name, value, annotation);
        // Shape, never content. A capture that lost most of the value reads
        // as "19 chars" next to a token the user knows is 40 (#104).
        console.log(`  Stored: ${name} (${describeSecretShape(value)})`);
        if (!isEmptyUpdate(annotation)) {
          console.log(`  Recorded: ${describeAnnotation(store.getAnnotation(name))}  (${CLI_BARE} secret show ${name})`);
        }
        afterSet();
        return 0;
      } catch (err) {
        console.error(formatCommandError(err));
        return 1;
      }
    }

    case 'list': {
      // `secret list` takes no argument (help.ts, README). It used to ACCEPT
      // one and ignore it: measured on 0.22.1, `secret list ZZZ_NO_SUCH_PREFIX`
      // returned all 81 stored names, byte-identical to the unfiltered run, at
      // exit 0, with nothing saying the token was dropped. A user who believes
      // they filtered and sees every name reads that as "these all match".
      //
      // Refused rather than implemented as a filter: adding a filter is a
      // feature with its own design questions (substring or prefix? case
      // sensitivity? exit code on no match?), and inventing one here to excuse
      // a swallowed token is how a parsing surface grows. Naming the token is
      // the fix; the feature is a separate decision. `--app` is that decision
      // for one field: an exact match on recorded metadata (#172).
      const extra = parsed.rest[0];
      if (extra !== undefined) {
        console.error(`\n  \`secret list\` takes no arguments other than --long, --json and --app <name>, but "${extra}" was given.`);
        console.error('  It lists every stored name, and it was NOT filtered by that token.');
        console.log(`\n  List all:  ${CLI_BARE} secret list`);
        console.log(`  By app:    ${CLI_BARE} secret list --app <name>`);
        console.log(`  Filter:    ${CLI_BARE} secret list | grep ${JSON.stringify(extra)}\n`);
        return 2;
      }
      const app = parsed.values.get('--app')?.[0];
      if (app === '') {
        console.error('\n  --app needs an app name, but an empty one was given.\n');
        return 2;
      }
      const long = parsed.switches.has('--long');
      const store = createStore();
      try {
        const names = await store.listSecrets();
        // Descriptions and metadata are read only when asked for, so a plain
        // `secret list` behaves exactly as it did before they existed.
        const annotations = long || json || app !== undefined ? store.listAnnotations() : new Map<string, SecretAnnotation>();
        const shown = app === undefined ? names : names.filter((n) => annotations.get(n)?.meta.app === app);

        if (json) {
          console.log(JSON.stringify({
            scope: 'global',
            backend: store.backendName,
            filter: app === undefined ? null : { app },
            count: shown.length,
            secrets: shown.map((n) => annotationJson(n, annotations.get(n))),
          }, null, 2));
          return 0;
        }

        // Scope disclosure: the store is machine-global (one backend per machine
        // config), not project-scoped — running `secret list` in any directory
        // shows the same secrets. Say so, and name the backend, so a user is
        // never unsure whether they are looking at project or global state.
        // The one exception is a gcp-sm project named by this repository's
        // .secretless (#177): that list belongs to this repository only.
        const gcpProject = store.backendName === 'gcp-sm' ? resolveGcpProject() : undefined;
        const scopeNote = !gcpProject?.projectId
          ? `  Scope: global (${store.backendName} backend) — shared across all projects on this machine`
          : gcpProject.source === 'manifest'
            ? `  Scope: this repository (gcp-sm backend, project ${gcpProject.projectId} named by ${gcpProject.from})`
            : `  Scope: global (gcp-sm backend, project ${gcpProject.projectId}) — shared by every project on this machine whose .secretless names no GCP project`;
        if (names.length === 0) {
          console.log('\n  No secrets stored.');
          console.log(scopeNote);
          console.log(`  Store one:    ${CLI} secret set MY_KEY=my_value`);
          console.log(`  Import .env:  ${CLI} import .env\n`);
          return 0;
        }
        if (shown.length === 0) {
          const apps = [...new Set(names.map((n) => annotations.get(n)?.meta.app).filter((a): a is string => a !== undefined))].sort();
          console.log(`\n  No stored secret has app=${app} (${names.length} secret(s) stored).`);
          console.log(apps.length > 0 ? `  Apps recorded: ${printable(apps.join(', '))}` : '  No secret has an app recorded.');
          console.log(scopeNote);
          console.log(`  Record one:   ${CLI} secret set NAME --meta app=${app}\n`);
          return 0;
        }
        const heading = app === undefined ? `${shown.length} secret(s)` : `${shown.length} secret(s) with app=${app}`;
        console.log(`\n  ${heading}:\n`);
        for (const n of shown) {
          console.log(`    ${n}`);
          if (!long) continue;
          const annotation = annotations.get(n);
          if (annotation?.description !== undefined) console.log(`      ${printable(annotation.description)}`);
          for (const line of metaLines(annotation?.meta ?? {})) console.log(`      ${line}`);
        }
        console.log();
        console.log(scopeNote);
        if (long) console.log('  Values are never printed. Descriptions and metadata are not secrets.');
        console.log();
        return 0;
      } catch (err) {
        console.error(formatCommandError(err));
        return 1;
      }
    }

    case 'show': {
      const [name, ...extra] = parsed.rest;
      if (!name || name.startsWith('--') || extra.length > 0) {
        console.error(`\n  Usage: ${CLI_BARE} secret show <NAME> [--json]\n`);
        return name ? 2 : 1;
      }
      const store = createStore();
      try {
        const annotation = store.getAnnotation(name);
        // Whether the value exists, never what it is: it is read into memory
        // to answer that and goes no further.
        const stored = (await store.getSecret(name)) !== undefined;
        if (json) {
          console.log(JSON.stringify({ ...annotationJson(name, annotation), stored, backend: store.backendName }, null, 2));
          return stored ? 0 : 1;
        }
        if (!stored && !annotation) {
          console.error(`  Secret not found: ${name}`);
          return 1;
        }
        console.log(`\n  ${name}\n`);
        if (annotation) {
          if (annotation.description !== undefined) console.log(`    Description  ${printable(annotation.description)}`);
          const lines = metaLines(annotation.meta);
          lines.forEach((line, i) => console.log(`    ${i === 0 ? 'Metadata    ' : '            '} ${line}`));
          const updated = annotation.updatedAt !== annotation.recordedAt ? ` (updated ${annotation.updatedAt})` : '';
          console.log(`    Recorded     ${annotation.recordedAt}${updated}`);
        } else {
          console.log('    No description or metadata recorded.');
        }
        console.log(stored
          ? `    Value        stored (${store.backendName} backend), never printed by this command`
          : `    Value        NOT in the ${store.backendName} store`);
        if (!annotation) {
          console.log(`\n  Record one:  ${CLI} secret set ${name} --description "what it is for" --meta app=<name>`);
        }
        console.log();
        return stored ? 0 : 1;
      } catch (err) {
        console.error(formatCommandError(err));
        return 1;
      }
    }

    case 'get': {
      const positional = parsed.rest.filter(a => !a.startsWith('--'));
      const name = positional[0];
      if (!name) {
        console.error(`\n  Usage: ${CLI_BARE} secret get <NAME>\n`);
        return 1;
      }

      // Block output in non-interactive contexts (AI tools capture stdout).
      if (!process.stdout.isTTY && !parsed.rest.includes('--force')) {
        console.error('  secretless: Blocked -- secret values cannot be read in non-interactive contexts.');
        console.error('  AI tools capture stdout, which would expose the secret in their context.');
        console.error('');
        console.error('  To inject secrets into a command:');
        console.error(`    ${CLI} run -- <command>`);
        console.error('');
        console.error('  To force output (e.g. piping to clipboard):');
        console.error(`    ${CLI} secret get <NAME> --force`);
        console.error('');
        console.error('  To see what a secret is for without its value:');
        console.error(`    ${CLI} secret show <NAME>`);
        return 1;
      }

      const store = createStore();
      try {
        const value = await store.getSecret(name);
        if (value === undefined) {
          console.error(`  Secret not found: ${name}`);
          return 1;
        }
        process.stdout.write(value);
        // Add newline if stdout is a terminal
        if (process.stdout.isTTY) {
          process.stdout.write('\n');
        }
        return 0;
      } catch (err) {
        console.error(formatCommandError(err));
        return 1;
      }
    }

    case 'rm':
    case 'remove':
    case 'delete': {
      const name = parsed.rest[0];
      if (!name) {
        console.error(`\n  Usage: ${CLI_BARE} secret rm <NAME>\n`);
        return 1;
      }
      const store = createStore();
      try {
        const removed = await store.removeSecret(name);
        if (removed) {
          console.log(`  Removed: ${name}`);
          return 0;
        }
        console.error(`  Secret not found: ${name}`);
        return 1;
      } catch (err) {
        console.error(formatCommandError(err));
        return 1;
      }
    }

    default:
      // No subcommand is an exploration, not an error — show usage cleanly and succeed
      // (#80). Reserve the "Unknown secret command" error for a real unrecognized token.
      if (subcommand === undefined) {
        console.log(`\n  Usage: ${CLI_BARE} secret <set|list|get|rm> [args]`);
        console.log(`         ${CLI_BARE} secret show <NAME>   (description and metadata, never the value)`);
        console.log(`         ${CLI_BARE} secret sync --from <backend> [--only K1,K2 | --manifest <file>]\n`);
        return 0;
      }
      console.error(`\n  Unknown secret command: ${subcommand}`);
      console.log(`  Usage: ${CLI_BARE} secret <set|list|get|rm> [args]`);
      console.log(`         ${CLI_BARE} secret show <NAME>   (description and metadata, never the value)`);
      console.log(`         ${CLI_BARE} secret sync --from <backend> [--only K1,K2 | --manifest <file>]\n`);
      return 1;
  }
}

const SYNC_SOURCES: readonly SelectableBackendType[] = ['local', 'keychain', '1password', 'vault', 'gcp-sm'];

/** The command that checks a source backend by itself, same as the factory's. */
const SOURCE_VERIFY: Partial<Record<SelectableBackendType, string>> = {
  '1password': 'op account get',
  vault: 'vault token lookup',
  'gcp-sm': 'gcloud auth application-default print-access-token',
};

/** Row label per action: `[after a run, on a dry run]`. */
const SYNC_LABEL: Record<SyncAction, [string, string]> = {
  create: ['created', 'would create'],
  update: ['updated', 'would update'],
  unchanged: ['unchanged', 'unchanged'],
  conflict: ['conflict', 'conflict'],
  'local-only': ['kept', 'kept'],
  'not-found': ['not found', 'not found'],
  failed: ['failed', 'failed'],
};

export interface SecretSyncDeps {
  /** Builds the source backend. Default: the factory, strict, in the source role (no cache layer). */
  createSource?: (type: SelectableBackendType) => SecretBackend;
  /** This machine's store. Default: the configured backend. */
  store?: SecretStore;
  /** Directory whose `.secretless` is the default selection. Default: the working directory. */
  cwd?: string;
}

/**
 * `secret sync --from <backend> [--only K1,K2 | --manifest <file>] [--dry-run] [--force]`
 *
 * Copies the selected names from a shared backend into this machine's store
 * (#176). The selection is `--only`, else the required names of `--manifest`,
 * else the required names of `.secretless` in the working directory. Prints
 * names and what happened to each; never a value.
 *
 * Exit 0 when every selected name ends up stored here with nothing left over,
 * 1 when a name conflicts, is in neither store, or fails, 2 on a usage error.
 * A dry run exits as the real run would, except for a write that would fail:
 * it never writes, so only the real run finds that.
 */
export async function runSecretSync(args: string[], deps: SecretSyncDeps = {}): Promise<number> {
  let from: string | undefined;
  let only: string[] | undefined;
  let manifestArg: string | undefined;
  let dryRun = false;
  let force = false;
  const stray: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--from') { from = args[++i]; continue; }
    if (a === '--only') { only = (args[++i] ?? '').split(',').map((n) => n.trim()).filter(Boolean); continue; }
    if (a === '--manifest') { manifestArg = args[++i]; continue; }
    if (a === '--dry-run') { dryRun = true; continue; }
    if (a === '--force') { force = true; continue; }
    stray.push(a);
  }

  const usage = `  Usage: ${CLI_BARE} secret sync --from <${SYNC_SOURCES.join('|')}> [--only K1,K2 | --manifest <file>] [--dry-run] [--force]\n`;
  const usageError = (message: string): number => {
    console.error(`\n  ${message}`);
    console.error('  Nothing was read or written.\n');
    console.error(usage);
    return 2;
  };

  if (stray.length > 0) {
    return usageError(`\`secret sync\` takes no positional arguments, but "${stray[0]}" was given.`);
  }
  if (from === undefined) {
    return usageError('--from is required: name the backend to copy from.');
  }
  if (!(SYNC_SOURCES as readonly string[]).includes(from)) {
    return usageError(`Unknown backend "${from}". Valid: ${SYNC_SOURCES.join(', ')}.`);
  }
  const fromType = from as SelectableBackendType;
  if (only !== undefined && manifestArg !== undefined) {
    return usageError('--only and --manifest both choose the names to sync; give one of them.');
  }
  if (only !== undefined && only.length === 0) {
    return usageError('--only was given but named no secrets.');
  }
  const badName = only?.find((n) => !isValidSecretName(n));
  if (badName !== undefined) {
    return usageError(`"${badName}" is not a secret name. Names allow letters, digits, '-' and '_'.`);
  }

  // Selection.
  let names: string[];
  let selection: string;
  // `setup --check` reads `.secretless` in the working directory, so it is the
  // check to point at only when that is the manifest the names came from.
  let setupChecksSelection = false;
  if (only !== undefined) {
    names = [...new Set(only)];
    selection = `${names.length} named by --only`;
  } else {
    const cwd = deps.cwd ?? process.cwd();
    const given = manifestArg ?? '.secretless';
    let manifestPath = path.resolve(cwd, given);
    if (fs.existsSync(manifestPath) && fs.statSync(manifestPath).isDirectory()) {
      manifestPath = path.join(manifestPath, '.secretless');
    }
    if (!fs.existsSync(manifestPath)) {
      if (manifestArg === undefined) {
        console.error('\n  No .secretless manifest in this directory, so no names were chosen to sync.');
        console.error('  Nothing was read or written.\n');
        console.error(`  Fix:     ${CLI} secret sync --from ${fromType} --only NAME1,NAME2`);
        console.error(`  Or:      ${CLI} secret sync --from ${fromType} --manifest <path to .secretless>\n`);
        return 2;
      }
      console.error(`\n  Manifest not found: ${given}`);
      console.error('  Nothing was read or written.\n');
      return 1;
    }
    const parsed = parseManifestDetailed(fs.readFileSync(manifestPath, 'utf-8'));
    if (parsed.errors.length > 0) {
      console.error(`\n  ${given} could not be parsed.\n`);
      for (const e of parsed.errors) {
        console.error(`    line ${e.line}: ${e.text}`);
        console.error(`             ${e.reason}`);
      }
      console.error('\n  ' + MANIFEST_FORMAT_HINT.split('\n').join('\n  ') + '\n');
      console.error('  Nothing was read or written, because the file does not say which names to sync.\n');
      return 1;
    }
    names = parsed.entries.filter((e) => e.required).map((e) => e.name);
    if (names.length === 0) {
      console.log(`\n  ${given} declares no required names, so there is nothing to sync.`);
      console.log(`  To copy optional ones, name them:  ${CLI} secret sync --from ${fromType} --only NAME1,NAME2\n`);
      return 0;
    }
    setupChecksSelection = manifestPath === path.resolve(cwd, '.secretless');
    selection = `${names.length} required in ${given}`;
  }

  let store: SecretStore;
  let source: SecretBackend;
  try {
    store = deps.store ?? new SecretStore();
    source = deps.createSource
      ? deps.createSource(fromType)
      : createBackend(fromType, undefined, true, { role: 'source' });
  } catch (err) {
    console.error(`\n  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }

  const fromName = displayName(source.name);
  const toName = store.backendName;
  if (fromName === toName) {
    return usageError(`--from ${fromType} is this machine's own store (${toName}), so there is nothing to copy.`);
  }

  console.log('\n  Secretless Sync\n');
  console.log(`  From:   ${fromName}`);
  console.log(`  To:     ${toName} (this machine)`);
  const projectNote = repositoryProjectNote(toName);
  if (projectNote) console.log(`          ${projectNote}`);
  console.log(`  Names:  ${selection}`);
  if (dryRun) console.log('  Dry run: nothing is written.');
  console.log();

  let result: SyncResult;
  try {
    result = await syncSecrets(source, store, names, { dryRun, force });
  } catch (err) {
    console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
    const verify = SOURCE_VERIFY[fromType];
    if (verify) console.error(`\n  Verify:  ${verify}`);
    console.error();
    return 1;
  }

  printSyncReport(result, fromName);

  const rerun = [`--from ${fromType}`];
  if (only !== undefined) rerun.push(`--only ${names.join(',')}`);
  else if (manifestArg !== undefined) rerun.push(`--manifest ${shellWord(manifestArg)}`);

  const ofAction = (action: SyncAction): string[] =>
    result.entries.filter((e) => e.action === action).map((e) => e.name);
  const conflicts = ofAction('conflict');
  const missing = ofAction('not-found');
  const writes = ofAction('create').length + ofAction('update').length;

  if (conflicts.length > 0) {
    console.log(`  The local value of ${conflicts.join(', ')} differs from ${fromName}'s and was left as is.`);
    console.log(`  Fix:     ${CLI} secret sync --from ${fromType} --only ${conflicts.join(',')} --force   (replace it with ${fromName}'s)\n`);
  }
  if (missing.length > 0) {
    console.log(`  Not in ${fromName} and not stored on this machine: ${missing.join(', ')}`);
    const verify = SOURCE_VERIFY[fromType];
    if (verify) console.log(`  Verify:  ${verify}`);
    console.log(`  Fix:     ${CLI} secret set ${missing[0]}   (or add it to ${fromName} and sync again)\n`);
  }
  if (result.dryRun && writes > 0) {
    console.log(`  Apply:   ${CLI} secret sync ${[...rerun, ...(force ? ['--force'] : [])].join(' ')}\n`);
  }
  if (!result.dryRun && result.ok) {
    console.log(`  Verify:  ${CLI} ${setupChecksSelection ? 'setup --check' : 'secret list'}\n`);
  }
  return result.ok ? 0 : 1;
}

function printSyncReport(result: SyncResult, fromName: string): void {
  const col = result.dryRun ? 1 : 0;
  const labelWidth = Math.max(...result.entries.map((e) => SYNC_LABEL[e.action][col].length));
  const nameWidth = Math.max(...result.entries.map((e) => e.name.length));
  for (const e of result.entries) {
    const detail = syncDetail(e.action, result.dryRun, fromName) ?? e.error ?? '';
    const row = `    ${SYNC_LABEL[e.action][col].padEnd(labelWidth)}  ${e.name.padEnd(nameWidth)}  ${detail}`;
    console.log(row.trimEnd());
  }

  const counts = new Map<SyncAction, number>();
  for (const e of result.entries) counts.set(e.action, (counts.get(e.action) ?? 0) + 1);
  const parts = [...counts].map(([action, n]) => `${n} ${SYNC_LABEL[action][col]}`);
  console.log(`\n  ${result.entries.length} name(s): ${parts.join(', ')}\n`);
}

function syncDetail(action: SyncAction, dryRun: boolean, fromName: string): string | undefined {
  switch (action) {
    case 'create': return '';
    case 'update': return dryRun ? 'the local value would be replaced (--force)' : 'the local value was replaced (--force)';
    case 'unchanged': return 'the local value already matches';
    case 'conflict': return 'the local value differs; left as is (--force replaces it)';
    case 'local-only': return `not in ${fromName}; the local value is left as is`;
    case 'not-found': return `not in ${fromName}, and not stored on this machine`;
    case 'failed': return undefined;
  }
}

/** A path as one shell word, quoted only when it needs to be. */
function shellWord(word: string): string {
  return /^[\w./-]+$/.test(word) ? word : JSON.stringify(word);
}

/**
 * Read a secret value from stdin. In TTY mode, reads one line (until Enter).
 * In piped mode, reads until stdin closes. Returns null if value is empty.
 */
function readSecretFromStdin(name: string): Promise<string | null> {
  return new Promise((resolve) => {
    let input = '';
    process.stdin.setEncoding('utf-8');

    if (process.stdin.isTTY) {
      process.stderr.write(`  Enter value for ${name}: `);
    }

    let resolved = false;
    const finish = (value: string): void => {
      if (resolved) return;
      resolved = true;
      const trimmed = value.trim();
      resolve(trimmed === '' ? null : trimmed);
    };

    process.stdin.on('data', (chunk) => {
      input += chunk;
      // In TTY mode, each Enter press delivers a line — store immediately.
      // In piped mode, we may get multiple chunks; wait for 'end'.
      if (process.stdin.isTTY) {
        finish(input);
      }
    });

    // Piped mode: wait for stdin to close, then store
    process.stdin.on('end', () => {
      finish(input);
    });
  });
}
