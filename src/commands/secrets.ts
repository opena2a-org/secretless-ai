import * as fs from 'fs';
import * as path from 'path';
import { SecretStore, isSettableSecretName, isValidSecretName, notSettableReason } from '../secret-store';
import { detectAgentRuntime, planShellHook, writeShellHook } from '../env';
import type { InstallShellHookOptions } from '../env';
import { CLI, CLI_BARE, formatCommandError } from './utils';
import { escapeForDisplay, escapePathForDisplay, hasDisplayHazard } from '../display-safe';
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
import { Clipboard, clipboardInstallHint } from '../clipboard';
import { canReadHidden, readHiddenLine } from '../hidden-line';
import type { PromptOutput, TtyInput } from '../hidden-line';
import { pushSecrets, PushError, MissingLocalNamesError, PUSH_TARGETS, VaultPushTarget, GcpPushTarget } from '../secret-push';
import type { PushAction, PushResult, PushTarget, PushTargetType } from '../secret-push';
import { AzureKeyVaultTarget, vaultNameFromArg, vaultNameProblem } from '../backends/azure-kv';
import { VaultBackend } from '../backends/vault';
import { GCPSecretManagerBackend } from '../backends/gcp-sm';
import { needsRotation, parseExposureTime } from '../secret-exposure';
import type { NeedsRotation } from '../secret-exposure';
import type { RotationOutcome } from '../secret-store';
import { fixCommand, NAME_PLACEHOLDER, PLACEHOLDER_NAME } from '../fix-command';
import type { FixNames } from '../fix-command';

export interface EnsureShellHookOptions extends InstallShellHookOptions {
  /** The name `secret set` stored, for the `run --only` line. */
  name?: string;
  /** `secret set --no-shell-hook`: leave the profile as it is and do not ask. */
  noShellHook?: boolean;
  /** Asks a yes/no question; null when there is no terminal to ask on. For DI/testing. */
  ask?: (question: string) => Promise<boolean | null>;
}

/**
 * Ask `question` on `output` and read one line from `input`. `y` or `yes` is
 * a yes and `n` or `no` is a no; any other line, an empty one included, is
 * `defaultAnswer`, which is no unless the caller says otherwise (a `[Y/n]`
 * question passes true). Resolves null without asking when either stream is
 * not a terminal, so piped input is never taken for an answer.
 */
export function askOnTerminal(
  question: string,
  input: TtyInput = process.stdin,
  output: PromptOutput & { isTTY?: boolean } = process.stderr,
  defaultAnswer = false,
): Promise<boolean | null> {
  if (input.isTTY !== true || output.isTTY !== true) return Promise.resolve(null);
  output.write(question);
  return new Promise((resolve) => {
    const done = (line: string | null): void => {
      input.removeListener('data', onData);
      input.removeListener('end', onEnd);
      input.pause();
      if (line === null) {
        resolve(false);
      } else if (/^\s*y(es)?\s*$/i.test(line)) {
        resolve(true);
      } else if (/^\s*n(o)?\s*$/i.test(line)) {
        resolve(false);
      } else {
        resolve(defaultAnswer);
      }
    };
    const onData = (chunk: string | Buffer): void => done(String(chunk));
    const onEnd = (): void => {
      output.write('\n');
      done(null);
    };
    input.on('data', onData);
    input.on('end', onEnd);
    input.resume();
  });
}

/** The way to give one command one stored secret, printed after the shell-hook step. */
function runOnlyLine(name: string): string {
  return `  To give one command this secret:  ${CLI_BARE} run --only ${name} -- <command>`;
}

/**
 * Offer the shell hook that exports every stored secret in each new shell.
 * Called after `secret set`. The profile is written only after a yes on a
 * terminal; `--no-shell-hook`, a no, or no terminal to ask on leaves it as it
 * is and names `run --only` instead (#412).
 */
export async function ensureShellHook(options: EnsureShellHookOptions = {}): Promise<void> {
  const plan = planShellHook(options);
  if (plan === null) return;

  const profileName = path.basename(plan.profilePath);
  const name = options.name ?? 'NAME';
  if (options.noShellHook === true) {
    console.log('  Shell profile not changed (--no-shell-hook).');
    console.log(runOnlyLine(name));
    return;
  }
  if (plan.action === 'repaired') {
    console.log(`  The shell hook in ~/${profileName} runs a command that was not found, so new shells receive no secrets.`);
  }
  const question = plan.action === 'installed'
    ? `  Add a hook to ~/${profileName} that exports every stored secret in each new shell? [y/N] `
    : `  Point the hook in ~/${profileName} at this copy of secretless-ai? [y/N] `;
  const answer = await (options.ask ?? askOnTerminal)(question);
  if (answer !== true) {
    console.log(answer === null
      ? `  Shell profile not changed: there is no terminal to ask on before editing ~/${profileName}.`
      : '  Shell profile not changed.');
    console.log(runOnlyLine(name));
    console.log(answer === null
      ? `  The next \`${CLI_BARE} secret set\` run in a terminal asks again.`
      : `  To skip this question:  ${CLI_BARE} secret set <NAME> --no-shell-hook`);
    return;
  }

  const change = writeShellHook(plan);
  console.log(change.action === 'installed'
    ? `  Shell hook installed in ~/${profileName}`
    : `  Shell hook in ~/${profileName} updated: the command it ran was not found`);
  if (!change.cliOnPath) {
    // The hook runs this copy by its path, so it works without a global
    // install, but only while this copy stays where it is (#333).
    console.log('  secretless-ai is not on PATH, so the hook runs this copy by its full path:');
    console.log(`    ${escapePathForDisplay(change.command[change.command.length - 1])}`);
    console.log('  If that copy is removed (clearing the npm cache removes an npx copy), new terminals');
    console.log(`  receive no secrets until a \`${CLI} secret set\` in a terminal updates the hook. To keep a copy: npm install -g secretless-ai`);
  }
  console.log(`  Run: source ~/${profileName}   (or open a new terminal)`);
  console.log(runOnlyLine(name));
}

/** Flags read by one subcommand only. Another subcommand refuses them (#172). */
const SECRET_SUBCOMMAND_FLAGS: Readonly<Record<string, readonly string[]>> = {
  set: ['--description', '--meta', '--from-clipboard', '--keep-clipboard', '--no-shell-hook'],
  list: ['--long', '--json', '--app', '--needs-rotation'],
  show: ['--json'],
  exposed: ['--where', '--at'],
};
const SECRET_SUBCOMMANDS = new Set(['set', 'list', 'show', 'get', 'rm', 'remove', 'delete', 'exposed']);
const SCOPED_FLAGS = new Set(['--description', '--meta', '--from-clipboard', '--keep-clipboard', '--no-shell-hook', '--long', '--json', '--app', '--needs-rotation', '--where', '--at']);
const VALUE_FLAGS = new Set(['--description', '--meta', '--app', '--where', '--at']);

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

/** A name a Fix gives `secret set`, printed as `<name>` when `secret set` refuses it. */
function settable(name: string): FixNames {
  return { names: [name], accepts: isSettableSecretName };
}

/**
 * A name a hint gives `secret get` or `secret show`, printed as `<name>` when
 * the store cannot hold it or it would be read as a flag.
 */
function storable(name: string): FixNames {
  return { names: [name], accepts: (n) => isValidSecretName(n) && !n.startsWith('-') };
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

/**
 * What `secret set` says about an open exposure (#236). Never the value.
 * `setCommand` is the form the user ran, so the Fix line repeats it. Both
 * callers are `secret set` itself, after it checked `name`.
 */
function reportRotation(name: string, rotation: RotationOutcome, setCommand = fixCommand(['secret', 'set', settable(name)], CLI_BARE)): void {
  switch (rotation.kind) {
    case 'closed':
      console.log(`  Rotated: the exposure recorded ${printable(rotation.exposure.exposedAt)} is closed (rotatedAt ${rotation.rotatedAt}).`);
      return;
    case 'still-open': {
      const where = rotation.exposure.exposedWhere ? `, ${printable(rotation.exposure.exposedWhere)}` : '';
      console.log(`  Still exposed: this is the value that was already stored, so the exposure recorded ${printable(rotation.exposure.exposedAt)}${where} stays open.`);
      console.log(`  Fix:     replace the key at its provider, then  ${setCommand}  with the new value`);
      return;
    }
    case 'unknown':
      console.log(`  Not checked: whether ${name} had an open exposure; the metadata file could not be read.`);
      console.log(`  Verify:  ${CLI_BARE} secret list --needs-rotation`);
      return;
    case 'none':
      return;
  }
}

/** The JSON form of one open exposure, for `list --needs-rotation --json`. */
function exposureJson(entry: NeedsRotation): Record<string, unknown> {
  return {
    name: entry.name,
    exposedAt: entry.exposedAt,
    exposedWhere: entry.exposedWhere,
    provider: entry.provider,
  };
}

/**
 * Flags only `secret sync` or `secret push` reads, and which of the two reads
 * each. Refused on every other subcommand (below).
 */
const TRANSFER_FLAG_OWNERS: Readonly<Record<string, readonly string[]>> = {
  '--from': ['sync'],
  '--only': ['sync'],
  '--manifest': ['sync'],
  '--dry-run': ['sync', 'push'],
  '--to': ['push'],
  '--vault': ['push'],
  '--as': ['push'],
};

/** What `secret set` passes to `afterSet`. */
export interface AfterSetContext {
  name: string;
  /** `--no-shell-hook` was given. */
  noShellHook: boolean;
}

export interface RunSecretOptions {
  /** `--json`, as read by the dispatcher. */
  json?: boolean;
  /** Store factory. For DI/testing. */
  createStore?: () => SecretStore;
  /** Called after a successful `secret set`. For DI/testing. */
  afterSet?: (context: AfterSetContext) => void | Promise<void>;
  /** Where `secret set NAME` reads a value from. For DI/testing. */
  stdin?: TtyInput;
  /** Whether stdin is a pipe or a file rather than a terminal. For DI/testing. */
  stdinIsPiped?: () => boolean;
  /** Clipboard for `secret set --from-clipboard`. For DI/testing. */
  clipboard?: Clipboard;
  /** Environment `secret get` reads for an AI-agent runtime marker. For DI/testing. */
  env?: NodeJS.ProcessEnv;
}

/** True when a value may be arriving on stdin from a pipe or a redirected file. */
function stdinIsPiped(): boolean {
  try {
    const st = fs.fstatSync(0);
    return st.isFIFO() || st.isFile();
  } catch {
    return false;
  }
}

export async function runSecret(args: string[], options: RunSecretOptions = {}): Promise<number> {
  const subcommand = args[0];
  const createStore = options.createStore ?? (() => new SecretStore());
  const afterSet = options.afterSet ?? ((context: AfterSetContext) => ensureShellHook(context));

  const parsedOrError = parseSecretArgs(subcommand ?? '', args.slice(1));
  if (typeof parsedOrError === 'string') {
    console.error(`\n  ${parsedOrError}`);
    console.error(`  Run \`${CLI_BARE} secret --help\` for usage.\n`);
    return 2;
  }
  const parsed = parsedOrError;
  const json = options.json === true || parsed.switches.has('--json');

  // The `secret` verb registers one flag list for all its subcommands. A sync
  // or push flag given to another subcommand would be dropped without a word,
  // and `secret set --dry-run NAME=VALUE` would then store the value it was
  // asked only to preview.
  const misplaced = args.slice(1).find((a) => {
    const owners = TRANSFER_FLAG_OWNERS[a];
    return owners !== undefined && !owners.includes(subcommand ?? '');
  });
  if (misplaced !== undefined) {
    const owners = TRANSFER_FLAG_OWNERS[misplaced].map((o) => `\`secret ${o}\``).join(' and ');
    console.error(`\n  ${misplaced} applies to ${owners} only. \`secret ${subcommand}\` was not run. Nothing was changed.\n`);
    return 2;
  }

  switch (subcommand) {
    case 'sync':
      return runSecretSync(args.slice(1));

    case 'push':
      return runSecretPush(args.slice(1));

    case 'set': {
      const nameArg = parsed.rest[0];
      if (!nameArg) {
        console.error(`\n  Usage: ${CLI_BARE} secret set <NAME[=VALUE]> [--description <text>] [--meta <key=value>]...`);
        console.error(`  Or:    ${CLI_BARE} secret set <NAME> --from-clipboard [--keep-clipboard]\n`);
        return 1;
      }

      const annotation = annotationFromArgs(parsed);
      if (typeof annotation === 'string') {
        console.error(`\n  ${annotation}\n`);
        return 2;
      }

      const fromClipboard = parsed.switches.has('--from-clipboard');
      const keepClipboard = parsed.switches.has('--keep-clipboard');
      const noShellHook = parsed.switches.has('--no-shell-hook');
      if (keepClipboard && !fromClipboard) {
        console.error('\n  --keep-clipboard applies with --from-clipboard only. Nothing was stored.\n');
        return 2;
      }

      let name: string;
      let value: string | null;
      // Check for inline value: NAME=VALUE
      const eqIdx = nameArg.indexOf('=');
      if (fromClipboard) {
        if (eqIdx !== -1) {
          console.error('\n  --from-clipboard reads the value from the clipboard, so NAME=VALUE cannot also give one. Nothing was stored.');
          console.error(`  Fix:     ${fixCommand(['secret', 'set', settable(nameArg.slice(0, eqIdx)), '--from-clipboard'], CLI_BARE)}\n`);
          return 2;
        }
        if ((options.stdinIsPiped ?? stdinIsPiped)()) {
          console.error('\n  --from-clipboard reads the value from the clipboard, but stdin is a pipe or a file that may carry another one. Nothing was stored.');
          // Two spaces set the command apart from the words around it.
          console.error(`  Fix:     run  ${fixCommand(['secret', 'set', settable(nameArg), '--from-clipboard'], CLI_BARE)}  without a pipe or redirect,`);
          console.error('           or drop --from-clipboard to store what is piped in.\n');
          return 2;
        }
        name = nameArg;
        if (!isSettableSecretName(name)) {
          console.error('  Error: Invalid secret name. Use letters, numbers, underscores, hyphens. Must start with a letter.\n');
          return 1;
        }
        return storeFromClipboard(name, annotation, keepClipboard, options.clipboard ?? new Clipboard(), createStore,
          () => afterSet({ name, noShellHook }));
      }
      if (eqIdx !== -1) {
        name = nameArg.slice(0, eqIdx);
        value = nameArg.slice(eqIdx + 1);
        if (!value) {
          console.error('  Error: no value provided.');
          console.error(`  Usage: ${CLI_BARE} secret set NAME=VALUE\n`);
          return 1;
        }
        if (!isSettableSecretName(name)) {
          console.error('  Error: Invalid secret name. Use letters, numbers, underscores, hyphens. Must start with a letter.\n');
          return 1;
        }
        // The note `vault register --value` carries in its help, for the
        // inline form README.md describes as putting the value in shell
        // history (#413).
        console.error(`  The value was given as an argument (shell history keeps it); \`${CLI_BARE} secret set ${name}\` prompts with input hidden.`);
      } else {
        // Read value from stdin
        name = nameArg;
        if (!isSettableSecretName(name)) {
          console.error('  Error: Invalid secret name. Use letters, numbers, underscores, hyphens. Must start with a letter.\n');
          return 1;
        }
        const read = await readSecretFromStdin(name, options.stdin ?? process.stdin);
        if (read === CANCELLED) {
          console.error('  Cancelled. Nothing was stored.\n');
          return 130;
        }
        if (read === ECHO_ON) {
          // Typed here, the value would show on screen and stay in
          // scrollback (#437); the clipboard form and a pipe from a file do
          // not type it.
          console.error('  Error: this terminal cannot hide typed input, so no value was read. Nothing was stored.');
          console.error(`  Fix:     ${fixCommand(['secret', 'set', settable(name), '--from-clipboard'], CLI_BARE)}`);
          console.error(`  Or:      ${pipedFromFile(name)}\n`);
          return 1;
        }
        value = read;
        if (value === null) {
          console.error('  Error: no value provided.');
          console.error(`  Usage: ${CLI_BARE} secret set NAME --from-clipboard`);
          console.error(`  Or:    ${pipedFromFile('NAME')}\n`);
          return 1;
        }
      }

      const store = createStore();
      // Named before the write, so a value never lands in a project the
      // repository chose without the user seeing which one (#177).
      const projectNote = repositoryProjectNote(store.backendName);
      if (projectNote) console.log(`  ${projectNote}`);
      try {
        const { rotation } = await store.setSecret(name, value, annotation);
        // Shape, never content. A capture that lost most of the value reads
        // as "19 chars" next to a token the user knows is 40 (#104).
        console.log(`  Stored: ${name} (${describeSecretShape(value)})`);
        if (!isEmptyUpdate(annotation)) {
          console.log(`  Recorded: ${describeAnnotation(store.getAnnotation(name))}  (${CLI_BARE} secret show ${name})`);
        }
        reportRotation(name, rotation);
        await afterSet({ name, noShellHook });
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
        console.error(`\n  \`secret list\` takes no arguments other than --long, --json, --app <name> and --needs-rotation, but "${escapeForDisplay(extra)}" was given.`);
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
      if (parsed.switches.has('--needs-rotation')) {
        return listNeedsRotation(createStore(), { app, long, json });
      }
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
          // The name only: MY_KEY=my_value is the form that leaves the value
          // in shell history (#413).
          console.log(`  Store one:    ${CLI} secret set MY_KEY   (prompts, input hidden)`);
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
        // A description is recorded by `secret set`, and the store holds names
        // it refuses, so `Record one:` is offered only for a name it takes.
        if (!annotation && isSettableSecretName(name)) {
          console.log(`\n  Record one:  ${CLI} secret set ${name} --description "what it is for" --meta app=<name>`);
        } else if (!annotation) {
          console.log(`\n  ${notSettableReason(name)}; no description can be recorded for it.`);
        }
        console.log();
        return stored ? 0 : 1;
      } catch (err) {
        console.error(formatCommandError(err));
        return 1;
      }
    }

    case 'exposed': {
      const [name, ...extra] = parsed.rest;
      const usage = `\n  Usage: ${CLI_BARE} secret exposed <NAME> --where "<short note>" [--at <date>]\n`;
      if (!name || name.startsWith('--') || extra.length > 0) {
        console.error(usage);
        return 2;
      }
      const where = parsed.values.get('--where')?.[0];
      if (where === undefined || where.trim() === '') {
        console.error('\n  --where is required: a short note saying where the value was exposed (for example "pasted into a chat").');
        console.error(usage);
        return 2;
      }
      const atArg = parsed.values.get('--at')?.[0];
      const at = atArg === undefined ? new Date() : parseExposureTime(atArg);
      if (typeof at === 'string') {
        console.error(`\n  ${at}\n`);
        return 2;
      }
      const store = createStore();
      try {
        const { previous } = await store.recordExposure(name, where, at);
        console.log(`  Recorded: ${name} exposed ${at.toISOString()} (${printable(where)})`);
        if (previous) {
          console.log(`  Replaces: the open exposure recorded ${printable(previous.exposedAt)}${previous.exposedWhere ? ` (${printable(previous.exposedWhere)})` : ''}`);
        }
        console.log('  The value stays valid until it is replaced at its provider.');
        // A new value stored under the name closes the exposure, whichever
        // command stores it; `secret set` is offered only for a name it takes.
        if (isSettableSecretName(name)) {
          console.log(`  Next:     rotate it at the provider, then  ${CLI_BARE} secret set ${name}`);
        } else {
          console.log('  Next:     rotate it at the provider, then store the new value the way this one was first stored');
          console.log(`            ${notSettableReason(name)}.`);
        }
        console.log(`  Open:     ${CLI_BARE} secret list --needs-rotation\n`);
        return 0;
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

      // `--force` overrides the terminal check below, for a user who pipes a
      // value on purpose. Inside an AI-agent runtime the value would enter the
      // agent's context, so `--force` is refused there on the check `env` and
      // `export` use. That check reads a variable the agent sets in the
      // commands it runs, not the command line, so it holds where no guard
      // hook or deny rule sees the command. The store is not opened first.
      const force = parsed.rest.includes('--force');
      const agentRuntime = detectAgentRuntime(options.env ?? process.env);
      if (force && agentRuntime) {
        console.error(`\n  Refused: '${CLI_BARE} secret get --force' prints a secret value.`);
        console.error(`  An AI agent runtime is set (${agentRuntime}), so this output would enter the agent's context.\n`);
        console.error('  Inject the secret into one command instead:');
        console.error(`    ${CLI_BARE} run --only ${isSettableSecretName(name) ? name : 'NAME'} -- <command>\n`);
        return 1;
      }

      // Block output in non-interactive contexts (AI tools capture stdout).
      if (!process.stdout.isTTY && !force) {
        console.error('  secretless: Blocked -- secret values cannot be read in non-interactive contexts.');
        console.error('  AI tools capture stdout, which would expose the secret in their context.');
        console.error('');
        console.error('  To inject secrets into a command:');
        console.error(`    ${CLI} run -- <command>`);
        console.error('');
        // Not offered where it is refused (above). Each line names the secret
        // asked for: pasted, a `<NAME>` placeholder is a shell redirection.
        if (!agentRuntime) {
          console.error('  To force output (e.g. piping to clipboard):');
          console.error(`    ${fixCommand(['secret', 'get', storable(name), '--force'])}`);
          console.error('');
        }
        console.error('  To see what a secret is for without its value:');
        console.error(`    ${fixCommand(['secret', 'show', storable(name)])}`);
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
        console.log(`         ${CLI_BARE} secret exposed <NAME> --where "<note>" [--at <date>]`);
        console.log(`         ${CLI_BARE} secret list --needs-rotation [--json]`);
        console.log(`         ${CLI_BARE} secret sync --from <backend> [--only K1,K2 | --manifest <file>]`);
        console.log(`         ${CLI_BARE} secret push NAME[,NAME2] --to <azure-kv|vault|gcp-sm> [--vault <name>] [--as <names>]\n`);
        return 0;
      }
      console.error(`\n  Unknown secret command: ${escapeForDisplay(subcommand)}`);
      console.log(`  Usage: ${CLI_BARE} secret <set|list|get|rm> [args]`);
      console.log(`         ${CLI_BARE} secret show <NAME>   (description and metadata, never the value)`);
      console.log(`         ${CLI_BARE} secret exposed <NAME> --where "<note>" [--at <date>]`);
      console.log(`         ${CLI_BARE} secret list --needs-rotation [--json]`);
      console.log(`         ${CLI_BARE} secret sync --from <backend> [--only K1,K2 | --manifest <file>]`);
      console.log(`         ${CLI_BARE} secret push NAME[,NAME2] --to <azure-kv|vault|gcp-sm> [--vault <name>] [--as <names>]\n`);
      return 2;
  }
}

/**
 * `secret list --needs-rotation`: every open exposure, from the metadata file
 * alone, so it never unlocks the store (#236). Exits 1 while any is open, so a
 * script or CI job can gate on it.
 */
function listNeedsRotation(
  store: SecretStore,
  options: { app: string | undefined; long: boolean; json: boolean },
): number {
  let annotations: Map<string, SecretAnnotation>;
  try {
    annotations = store.listAnnotations();
  } catch (err) {
    console.error(formatCommandError(err));
    return 1;
  }
  const open = needsRotation(annotations).filter((e) => options.app === undefined || annotations.get(e.name)?.meta.app === options.app);
  if (options.json) {
    console.log(JSON.stringify({
      scope: 'global',
      filter: { needsRotation: true, app: options.app ?? null },
      count: open.length,
      secrets: open.map(exposureJson),
    }, null, 2));
    return open.length > 0 ? 1 : 0;
  }
  const scope = options.app === undefined ? '' : ` with app=${printable(options.app)}`;
  if (open.length === 0) {
    console.log(`\n  No exposed secret${scope} is waiting for rotation.`);
    console.log(`  Record one:  ${CLI_BARE} secret exposed NAME --where "<short note>"\n`);
    return 0;
  }
  console.log(`\n  ${open.length} exposed secret(s)${scope} need rotation:\n`);
  for (const entry of open) {
    console.log(`    ${entry.name}`);
    console.log(`      exposed ${printable(entry.exposedAt)}${entry.exposedWhere ? `  ${printable(entry.exposedWhere)}` : ''}`);
    if (entry.provider) console.log(`      provider=${printable(entry.provider)}`);
    if (!options.long) continue;
    const annotation = annotations.get(entry.name);
    if (annotation?.description !== undefined) console.log(`      ${printable(annotation.description)}`);
  }
  console.log('\n  A redacted or deleted copy does not end an exposure; a new value does.');
  console.log(`  Fix:     replace each key at its provider, then  ${fixCommand(['secret', 'set', NAME_PLACEHOLDER], CLI_BARE)}  with the new value\n`);
  return 1;
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
  // Escaped: each message quotes a value from the command line, and a line
  // feed in it started a line of its own.
  const usageError = (message: string): number => {
    console.error(`\n  ${escapeForDisplay(message)}`);
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
        // The Fix of a dry run is a dry run too, as `secret push`'s is.
        console.error(`  Fix:     ${fixCommand(['secret', 'sync', '--from', fromType, ...(dryRun ? ['--dry-run'] : []), '--only', NAME_PLACEHOLDER])}`);
        console.error(`  Or:      ${CLI} secret sync --from ${fromType} --manifest <path to .secretless>\n`);
        return 2;
      }
      console.error(`\n  Manifest not found: ${escapePathForDisplay(given)}`);
      console.error('  Nothing was read or written.\n');
      return 1;
    }
    const parsed = parseManifestDetailed(fs.readFileSync(manifestPath, 'utf-8'));
    if (parsed.errors.length > 0) {
      console.error(`\n  ${escapePathForDisplay(given)} could not be parsed.\n`);
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
    console.error(formatCommandError(err));
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
    const message = err instanceof Error ? err.message : String(err);
    const verify = SOURCE_VERIFY[fromType];
    console.error(formatCommandError(verify ? `${message}\n\n  Verify:  ${verify}` : message));
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
    const conflicting: FixNames = { names: conflicts, accepts: isValidSecretName };
    // What the Fix does is said on the line above it: pasted, a remark in
    // parentheses after the command is part of it, and bash refuses the `(`.
    console.log(`  To replace it with ${fromName}'s:`);
    console.log(`  Fix:     ${fixCommand(['secret', 'sync', '--from', fromType, '--only', conflicting, '--force', ...(dryRun ? ['--dry-run'] : [])])}\n`);
  }
  if (missing.length > 0) {
    console.log(`  Not in ${fromName} and not stored on this machine: ${missing.join(', ')}`);
    // `--only` and `.secretless` take a name that starts with a digit, '_' or
    // '-', and `secret set` refuses each of those. Such a name gets a line with
    // the half of the Fix that still applies, and the Fix names the first
    // missing name `secret set` takes; with none, there is no Fix line.
    for (const name of missing) {
      if (isSettableSecretName(name)) continue;
      console.log(`  ${notSettableReason(name)}; add it to ${fromName} and sync again.`);
    }
    const verify = SOURCE_VERIFY[fromType];
    if (verify) console.log(`  Verify:  ${verify}`);
    const first = missing.find((name) => isSettableSecretName(name));
    if (first === undefined) {
      console.log('');
    } else {
      // The other way is a line of its own under the command, for the reason
      // given above the conflict's Fix.
      console.log(`  Fix:     ${fixCommand(['secret', 'set', settable(first)])}`);
      console.log(`           or add it to ${fromName} and sync again\n`);
    }
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

export interface SecretPushDeps {
  /** This machine's store. Default: the configured backend. */
  store?: SecretStore;
  /** Builds the target. Default: the real client for `--to`. */
  createTarget?: (type: PushTargetType, vaultName: string | undefined) => PushTarget;
}

const PUSH_LABEL: Record<PushAction, string> = {
  'would-create': 'would create',
  'would-add-version': 'would add a version',
  pushed: 'pushed',
  failed: 'failed',
  skipped: 'not pushed',
};

function createPushTarget(type: PushTargetType, vaultName: string | undefined): PushTarget {
  switch (type) {
    case 'azure-kv': return new AzureKeyVaultTarget(vaultName ?? '');
    case 'vault': return new VaultPushTarget(new VaultBackend());
    case 'gcp-sm': return new GcpPushTarget(new GCPSecretManagerBackend());
  }
}

/**
 * An `--as` name in angle brackets that is not a placeholder, such as `<2fa>`,
 * `<_name>` or `<>`. It is still a name to fill in, not one to make a name
 * from: `_2fa_` is not a name anyone chose.
 */
const BRACKETED_NAME = /^<.*>$/s;

/** A `Verify:` or `Fix:` block; a second line continues under the first. */
function labelled(label: string, lines: readonly string[]): string[] {
  return lines.map((line, i) => `  ${i === 0 ? `${label}:`.padEnd(9) : ' '.repeat(9)}${line}`);
}

/**
 * `secret push NAME[,NAME2...] --to <azure-kv|vault|gcp-sm> [--vault <name>] [--as <names>] [--dry-run]`
 *
 * Writes named secrets from this machine's store to a cloud secret store
 * (#235), so a deployment can read them from there. Each value goes from the
 * store into an HTTPS request body inside this process; it is never on a
 * command line, and nothing prints it. The output names each entry, the
 * identifier and version written, and the command that references it next.
 *
 * A name not stored here, a name the target cannot hold, and a target that
 * cannot authenticate each stop the push before anything is written. The
 * first write that fails stops the rest.
 *
 * Exit 0 when every name was pushed (on a dry run: classified), 1 when a name
 * is not stored here, the target refuses or a write fails, 2 on a usage error.
 */
export async function runSecretPush(args: string[], deps: SecretPushDeps = {}): Promise<number> {
  const usage = `  Usage: ${CLI_BARE} secret push NAME[,NAME2...] --to <${PUSH_TARGETS.join('|')}> [--vault <name>] [--as <names>] [--dry-run]\n`;
  // Escaped, as `secret sync`'s are.
  const usageError = (message: string): number => {
    console.error(`\n  ${escapeForDisplay(message)}`);
    console.error('  Nothing was read or pushed.\n');
    console.error(usage);
    return 2;
  };

  let to: string | undefined;
  let vaultArg: string | undefined;
  let asArg: string | undefined;
  let dryRun = false;
  const given: string[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--to' || a === '--vault' || a === '--as') {
      if (seen.has(a)) return usageError(`${a} was given more than once; only one value can apply, so give it once.`);
      seen.add(a);
      const v = args[++i];
      if (v === undefined || v.startsWith('-')) return usageError(`${a} needs a value, but none was given.`);
      if (a === '--to') to = v;
      else if (a === '--vault') vaultArg = v;
      else asArg = v;
      continue;
    }
    if (a === '--dry-run') { dryRun = true; continue; }
    if (a.startsWith('-')) return usageError(`${a} is not read by \`secret push\`, so it would have been ignored.`);
    given.push(...a.split(',').map((n) => n.trim()).filter(Boolean));
  }

  if (given.length === 0) return usageError('Name the secrets to push.');
  // A NAME=VALUE argument already put the value on this command line; the
  // refusal must not print it a second time.
  const assignment = given.find((n) => n.includes('='));
  if (assignment !== undefined) {
    return usageError(`"${assignment.slice(0, assignment.indexOf('='))}=..." gives a value. \`secret push\` reads each value from this machine's store; give names only.`);
  }
  const names = [...new Set(given)];
  const badName = names.find((n) => !isValidSecretName(n));
  if (badName !== undefined) {
    return usageError(`"${badName}" is not a secret name. Names allow letters, digits, '-' and '_'.`);
  }
  // The names are read with whitespace and empty names dropped, so ` -x` and
  // `,-x` are read as `-x` is, which this command reads as an option. A Fix
  // or Apply line prints the names as one word, and one that starts with '-'
  // would be refused that way.
  if (names[0].startsWith('-')) {
    return usageError(`"${names[0]}" cannot be the first name: \`secret push\` reads a word that starts with '-' as an option. Give another name before it.`);
  }
  if (to === undefined) return usageError('--to is required: name the store to push to.');
  if (!(PUSH_TARGETS as readonly string[]).includes(to)) {
    return usageError(`Unknown target "${to}". Valid: ${PUSH_TARGETS.join(', ')}.`);
  }
  const toType = to as PushTargetType;

  let vaultName: string | undefined;
  if (toType === 'azure-kv') {
    if (vaultArg === undefined) return usageError('--to azure-kv needs --vault <name>: the Key Vault to push to.');
    vaultName = vaultNameFromArg(vaultArg);
    const problem = vaultNameProblem(vaultName);
    if (problem !== undefined) return usageError(`"${vaultArg}" is not a Key Vault name: ${problem}.`);
  } else if (vaultArg !== undefined) {
    return usageError(`--vault names an Azure Key Vault, so it applies to --to azure-kv only.`);
  }

  let remotes: string[];
  if (asArg !== undefined) {
    remotes = asArg.split(',').map((n) => n.trim());
    if (remotes.length !== names.length || remotes.some((r) => r === '')) {
      return usageError(`--as gives ${remotes.length} name(s) for ${names.length} secret(s); give one per secret, in the same order.`);
    }
    // ` -x,a.b` is read as `-x,a.b` is, and `--as -x,a.b` is refused for
    // giving no value, so a Fix or Apply line could not give this one back.
    if (remotes[0].startsWith('-')) {
      return usageError(`"${remotes[0]}" cannot be the first --as name: \`secret push\` reads an --as value that starts with '-' as no value. Choose another name for ${names[0]}.`);
    }
  } else {
    remotes = [...names];
  }

  let target: PushTarget;
  let store: SecretStore;
  try {
    target = deps.createTarget ? deps.createTarget(toType, vaultName) : createPushTarget(toType, vaultName);
    store = deps.store ?? new SecretStore();
  } catch (err) {
    console.error(formatCommandError(err));
    return 1;
  }

  const tail = ['--to', toType, ...(vaultName !== undefined ? ['--vault', vaultName] : [])];
  // The Fix of a dry run is a dry run too, so running it as printed writes
  // nothing. `--dry-run` comes before `--as`, so the names to fill in end the
  // line. Each `<name>` is quoted (fixCommand). Pasted unedited, the line is
  // refused for naming a placeholder, and nothing is written.
  const fixLine = (operands: readonly string[]): string => `  Fix:     ${fixCommand([
    'secret', 'push', { names, accepts: isValidSecretName }, ...tail, ...(dryRun ? ['--dry-run'] : []),
    '--as', { names: operands, accepts: (r) => target.nameProblem(r) === undefined },
  ])}\n`;
  const problems = remotes.map((r) => target.nameProblem(r));
  // Every given name passed `isValidSecretName` and the --as names passed the
  // target's `nameProblem`, so none holds a character `escapeForDisplay`
  // rewrites, and the line prints them as given. It quotes the earlier
  // secret's name, and a later one that differs from it only in case as
  // well, so neither reads as the other secret's.
  const mergeLine = (holder: number, i: number): string => {
    const also = remotes[i] === remotes[holder] ? '' : `, since "${remotes[i]}" differs from it only in case`;
    return `  ${names[holder]} and ${names[i]} would both be pushed as "${remotes[holder]}"${also}.`;
  };
  const first = problems.findIndex((p) => p !== undefined);
  if (first !== -1) {
    // A name with a control character prints escaped, so a line feed in it
    // starts no line; the Fix cannot spell such a name as a command word, so
    // it leaves `<name>` for the user to fill in, as it does for a name in
    // angle brackets that is not a placeholder, rather than offer a name
    // made from its characters. `--as` reads a value that starts with '-' as
    // a missing value, so a replacement that would start with '-' leaves
    // `<name>` as well. Any other refused name is replaced by one
    // the target accepts, so the Fix is not the command that was just
    // refused. A replacement that would push as the same name as
    // another --as name, given or offered, leaves `<name>` too, and so does
    // an accepted name the store would merge with an earlier accepted one, so
    // the Fix is not refused for two secrets sharing one name; either way a
    // line names the secret that holds that name. Each `<name>` left unfilled
    // is said to be a placeholder and stays in the Fix to be replaced, not
    // turned into a name made from its letters.
    const isPlaceholder = (r: string): boolean => PLACEHOLDER_NAME.test(r);
    const holders = new Map<string, { index: number; spelled: string }>();
    remotes.forEach((r, i) => {
      const folded = target.foldName(r);
      if (problems[i] === undefined && !holders.has(folded)) holders.set(folded, { index: i, spelled: r });
    });
    const holderLines: string[] = [];
    const unspelled = new Set<number>();
    const operands = remotes.map((r, i) => {
      if (problems[i] === undefined) {
        // The first accepted name to fold this way holds it, ahead of any
        // suggestion, so a holder at another index is an earlier one.
        const holder = holders.get(target.foldName(r));
        if (holder !== undefined && holder.index !== i) {
          holderLines.push(mergeLine(holder.index, i));
          return '<name>';
        }
        return r;
      }
      if (isPlaceholder(r)) return r;
      if (hasDisplayHazard(r) || BRACKETED_NAME.test(r)) {
        unspelled.add(i);
        return '<name>';
      }
      const suggested = target.suggestName(r);
      if (suggested.startsWith('-')) {
        unspelled.add(i);
        return '<name>';
      }
      const folded = target.foldName(suggested);
      const holder = holders.get(folded);
      if (holder !== undefined) {
        const as = holder.spelled === suggested ? '' : ` as "${escapeForDisplay(holder.spelled)}", which differs only in case`;
        holderLines.push(`  "${escapeForDisplay(suggested)}" is taken by ${names[holder.index]}${as}; choose another name for ${names[i]}.`);
        return '<name>';
      }
      holders.set(folded, { index: i, spelled: suggested });
      return suggested;
    });
    const refused = problems.findIndex((p, i) => p !== undefined && !isPlaceholder(remotes[i]));
    console.error();
    problems.forEach((p, i) => {
      if (p !== undefined && isPlaceholder(remotes[i])) {
        console.error(`  "${remotes[i]}" in --as is a placeholder: replace it with the name ${names[i]} should have in ${target.label}; ${p}.`);
      }
    });
    // The first refused name other than a placeholder gets the line that
    // gives the rule. So does each name the Fix leaves as `<name>` because it
    // cannot offer a name made from it: one in angle brackets that is not a
    // placeholder, one that holds
    // a character printed escaped, and one whose replacement would start
    // with '-'. Each of those gets the line wherever it stands, ending with
    // the secret it was given for. A name left as `<name>` because its
    // replacement is taken gets the "is taken by" line below; when it is the
    // first refused name, it gets the line that gives the rule as well. One
    // left as `<name>` because the store would merge it with an earlier name
    // is accepted, so it gets only the "would both be pushed as" line below.
    remotes.forEach((r, i) => {
      if (i !== refused && !unspelled.has(i)) return;
      const whose = unspelled.has(i) ? `; choose another name for ${names[i]}` : '';
      console.error(`  "${escapeForDisplay(r)}" cannot name a secret in ${target.label}: ${problems[i]}${whose}.`);
    });
    for (const line of holderLines) console.error(line);
    console.error('  Nothing was read or pushed.\n');
    console.error(fixLine(operands));
    return 2;
  }
  // Every name is accepted, but the store would merge two of them. Each
  // secret after the first to hold a name is named with the one that holds
  // it, and leaves `<name>` in the Fix, so the Fix is not this refusal again.
  const folded = remotes.map((r) => target.foldName(r));
  const clashes = folded.flatMap((f, i) => (folded.indexOf(f) !== i ? [i] : []));
  if (clashes.length > 0) {
    const lines = clashes.map((i) => mergeLine(folded.indexOf(folded[i]), i));
    console.error(`\n${lines.join('\n')}`);
    console.error('  Nothing was read or pushed.\n');
    const operands = remotes.map((r, i) => (clashes.includes(i) ? '<name>' : r));
    console.error(fixLine(operands));
    return 2;
  }

  console.log('\n  Secretless Push\n');
  console.log(`  From:   ${store.backendName} (this machine)`);
  console.log(`  To:     ${target.label}`);
  console.log(`  Names:  ${names.length}`);
  if (dryRun) console.log('  Dry run: nothing is written.');

  const plan = names.map((name, i) => ({ name, remote: remotes[i] }));
  let result: PushResult;
  try {
    result = await pushSecrets(store, target, plan, { dryRun });
  } catch (err) {
    console.log();
    if (err instanceof MissingLocalNamesError) {
      // `secret push` reads a later name that starts with '-', a digit or '_',
      // and `secret set` refuses each of those, so `secret set -x` is no Fix.
      // Such a name gets a line saying so, and the Fix names the first missing
      // name `secret set` takes; with none, there is no Fix line (#323). Every
      // name here passed `isValidSecretName`, so each prints as given.
      console.error(`  ${err.message}`);
      for (const name of err.names) {
        if (isSettableSecretName(name)) continue;
        console.error(`  "${name}" cannot be stored by \`secret set\`, which takes a name that starts with a letter; give the name the secret is stored under.`);
      }
      console.error('  Nothing was pushed.\n');
      console.error(`  Verify:  ${CLI} secret list`);
      const first = err.names.find((name) => isSettableSecretName(name));
      if (first !== undefined) console.error(`  Fix:     ${fixCommand(['secret', 'set', settable(first)])}`);
      console.error();
      return 1;
    }
    const failure = err instanceof PushError ? err : new PushError(err instanceof Error ? err.message : String(err));
    for (const line of failure.message.split('\n')) console.error(line.startsWith('  ') ? line : `  ${line}`);
    console.error('  Nothing was pushed.\n');
    for (const line of [...labelled('Verify', failure.verify), ...labelled('Fix', failure.fix)]) console.error(line);
    console.error();
    return 1;
  }

  if (result.auth !== undefined) console.log(`  Auth:   ${result.auth}`);
  console.log();
  printPushReport(result);

  if (result.failure !== undefined) {
    const pushed = result.entries.filter((e) => e.action === 'pushed').map((e) => e.name);
    for (const line of result.failure.message.split('\n')) console.error(line.startsWith('  ') ? line : `  ${line}`);
    console.error(pushed.length > 0
      ? `  Pushed before it stopped: ${pushed.join(', ')}. Those versions stay in place.\n`
      : `  Nothing was ${dryRun ? 'written' : 'pushed'}.\n`);
    for (const line of [...labelled('Verify', result.failure.verify), ...labelled('Fix', result.failure.fix)]) console.error(line);
    console.error();
    return 1;
  }

  if (result.dryRun) {
    const as = remotes.some((r, i) => r !== names[i]) ? [`--as ${remotes.join(',')}`] : [];
    console.log(`  Apply:   ${CLI} secret push ${names.join(',')} ${[...tail, ...as].join(' ')}\n`);
    return 0;
  }
  for (const line of target.nextSteps(result.entries)) console.log(line);
  console.log();
  return 0;
}

function printPushReport(result: PushResult): void {
  const labelWidth = Math.max(...result.entries.map((e) => PUSH_LABEL[e.action].length));
  const nameWidth = Math.max(...result.entries.map((e) => e.name.length));
  for (const e of result.entries) {
    const renamed = e.remote !== e.name ? `as ${e.remote}` : '';
    let detail: string;
    switch (e.action) {
      case 'pushed': detail = `version ${e.version}  ${e.id}`; break;
      case 'failed': detail = e.error ?? ''; break;
      case 'skipped': detail = 'not attempted after the failure above'; break;
      default: detail = renamed;
    }
    console.log(`    ${PUSH_LABEL[e.action].padEnd(labelWidth)}  ${e.name.padEnd(nameWidth)}  ${detail}`.trimEnd());
  }

  const counts = new Map<PushAction, number>();
  for (const e of result.entries) counts.set(e.action, (counts.get(e.action) ?? 0) + 1);
  const parts = [...counts].map(([action, n]) => `${n} ${PUSH_LABEL[action]}`);
  console.log(`\n  ${result.entries.length} name(s): ${parts.join(', ')}\n`);
}

/** A path as one shell word, quoted only when it needs to be. */
function shellWord(word: string): string {
  return /^[\w./-]+$/.test(word) ? word : JSON.stringify(word);
}

/**
 * `secret set NAME --from-clipboard`: store what the clipboard holds, then
 * clear it unless it changed since it was read or --keep-clipboard was given.
 * The value reaches this process through the clipboard tool's stdout only;
 * it is never in argv, and only its shape is printed.
 */
async function storeFromClipboard(
  name: string,
  annotation: AnnotationUpdate,
  keep: boolean,
  clipboard: Clipboard,
  createStore: () => SecretStore,
  afterSet: () => void | Promise<void>,
): Promise<number> {
  const rerun = fixCommand(['secret', 'set', settable(name), '--from-clipboard'], CLI_BARE);
  const read = clipboard.read();
  if (!read.ok) {
    if (read.reason === 'no-tool') {
      console.error(`\n  No clipboard tool was found (tried ${read.tried.join(', ')}). Nothing was stored.`);
      console.error(`  Fix:     ${clipboardInstallHint(clipboard.platform)}\n`);
    } else {
      console.error(`\n  The clipboard could not be read: ${read.detail}. Nothing was stored.`);
      console.error(`  Fix:     copy the key again, then run: ${rerun}\n`);
    }
    return 1;
  }
  const value = read.text.trim();
  if (value === '') {
    console.error('\n  The clipboard is empty. Nothing was stored.');
    console.error(`  Fix:     copy the key again, then run: ${rerun}\n`);
    return 1;
  }

  const store = createStore();
  let rotation: RotationOutcome;
  try {
    ({ rotation } = await store.setSecret(name, value, annotation));
  } catch (err) {
    console.error(formatCommandError(err));
    return 1;
  }
  console.log(`  Stored: ${name} (${describeSecretShape(value)}, from the clipboard)`);
  if (!isEmptyUpdate(annotation)) {
    console.log(`  Recorded: ${describeAnnotation(store.getAnnotation(name))}  (${CLI_BARE} secret show ${name})`);
  }
  // The clipboard form closes or leaves an exposure exactly like the typed
  // and piped forms, so it reports the outcome the same way (#236), and its
  // Fix line names the clipboard form again.
  reportRotation(name, rotation, rerun);

  let code = 0;
  if (keep) {
    console.log('  Clipboard: kept (--keep-clipboard). It still holds the value.');
  } else {
    // Clear only what was read: a newer copy made since then is the user's.
    const again = clipboard.read();
    if (again.ok && again.text !== read.text) {
      console.log('  Clipboard: left as is. It changed after the value was read.');
    } else {
      const failure = again.ok ? clipboard.clear(read.tool) : `it could not be read again (${again.reason === 'failed' ? again.detail : 'no tool'})`;
      if (failure === null) {
        console.log('  Clipboard: cleared.');
      } else {
        console.error(`  Clipboard: NOT cleared, ${failure}. It may still hold the value.`);
        console.error('  Fix:     copy something else to replace it.');
        code = 1;
      }
    }
  }
  await afterSet();
  return code;
}

/** `readSecretFromStdin` result when the user pressed Ctrl-C at the prompt. */
const CANCELLED = Symbol('cancelled');

/** `readSecretFromStdin` result when stdin is a terminal that cannot turn echo off (#437). */
const ECHO_ON = Symbol('echo-on');

/**
 * The piped form of `secret set NAME` a hint offers. The value comes from a
 * file, so the line typed, which shell history keeps, does not carry it; the
 * form offered before, `echo "value" | secret set NAME`, did (#439).
 */
function pipedFromFile(name: string): string {
  return `cat token.txt | ${CLI_BARE} secret set ${name}`;
}

/**
 * Read a secret value from stdin. On a terminal, reads one line with echo
 * off; a terminal whose input has no raw mode is not read, since a cooked
 * read shows the value on screen and keeps it in scrollback (#437).
 * In piped mode, reads until stdin closes. Returns null if value is empty.
 */
async function readSecretFromStdin(name: string, stdin: TtyInput): Promise<string | null | typeof CANCELLED | typeof ECHO_ON> {
  if (canReadHidden(stdin)) {
    const result = await readHiddenLine(stdin, process.stderr, `  Enter value for ${name} (input hidden): `);
    if (result.kind === 'cancelled') return CANCELLED;
    // Ctrl-D on an empty line gives no value, as Enter on one does.
    if (result.kind === 'ended') return null;
    const trimmed = result.value.trim();
    return trimmed === '' ? null : trimmed;
  }
  if (stdin.isTTY === true) return ECHO_ON;
  return new Promise((resolve) => {
    // Piped mode: the value may arrive in several chunks, so wait for stdin
    // to close, then store.
    let input = '';
    stdin.setEncoding('utf-8');
    stdin.on('data', (chunk) => {
      input += chunk;
    });
    stdin.on('end', () => {
      const trimmed = input.trim();
      resolve(trimmed === '' ? null : trimmed);
    });
  });
}
