/**
 * Secret injection — run any command with secrets injected as env vars.
 *
 * Replaces .env files entirely. Loads secrets from the SecretStore,
 * merges them into the environment, and spawns the child process.
 */

import { spawn } from 'child_process';
import type { ChildProcess } from 'child_process';
import * as path from 'path';
import { SecretStore } from './secret-store';
import type { SecretStoreOptions } from './secret-store';
import { leaksAny, scrubOrDrop } from './redact';

export interface RunOptions extends SecretStoreOptions {
  /** Only inject these specific secret names. If undefined, inject all. */
  only?: string[];
  /** Start the child even when a resolved value is on its command line (`--allow-argv`). */
  allowArgv?: boolean;
}

/**
 * Shortest value checked for on the child's command line.
 *
 * Below it, a stored value is more often configuration than credential
 * (`NODE_ENV=test`, `PORT=3000`), and containment refuses ordinary commands
 * (`run -- npm test`). A credential shorter than this is not caught here.
 */
const MIN_ARGV_VALUE = 8;

/**
 * Run a command with secrets injected as environment variables.
 *
 * Returns the child process exit code.
 */
export async function runWithSecrets(
  command: string,
  args: string[],
  options?: RunOptions,
): Promise<number> {
  const store = new SecretStore(options);
  const secrets = await store.loadSecrets(options?.only);

  // A zero count only means "backend failure" when we asked for EVERYTHING and
  // got nothing. With `--only`, a zero count means the filter matched nothing,
  // and loadSecrets has already thrown naming the unmatched names — so this
  // guard no longer answers a question nobody asked (#110). Scoping it also
  // closes the empty-store path, where `--only` used to be ignored entirely and
  // the command ran with nothing injected.
  const secretCount = Object.keys(secrets).length;
  if (secretCount === 0 && !options?.only) {
    // Check if the store actually has secrets (backend may have failed to load them)
    const allSecrets = await store.listSecrets();
    if (allSecrets.length > 0) {
      process.stderr.write(
        `secretless: Backend returned 0 secrets but the store contains ${allSecrets.length} entries. ` +
        'This may indicate a backend failure. Aborting to prevent running without secrets.\n',
      );
      return 1;
    }
    process.stderr.write(
      'secretless: No secrets found. Use `secretless-ai secret set <NAME>` to store secrets.\n',
    );
  }

  // Refuse a resolved value on the child's command line. A process's arguments
  // are readable by every local process for as long as it runs — `ps`, process
  // monitors and crash reports all capture them — so `run --only DB_URL -- psql
  // "$DB_URL"` published the whole connection URL for the life of the psql
  // session. `run` never interpolates anything itself: the calling shell
  // expanded the reference before this process started. What `run` can do is
  // decline to hand the value on, and point at the shape that keeps it in the
  // environment it was injected into.
  const onArgv = secretsOnArgv(command, args, secrets);
  if (onArgv.length > 0) {
    if (!options?.allowArgv) {
      process.stderr.write(argvRefusalMessage(onArgv, programName(command, Object.values(secrets))));
      return 1;
    }
    process.stderr.write(
      `secretless: warning: ${onArgv.join(', ')} ${onArgv.length === 1 ? 'is' : 'are'} on the command line (--allow-argv). ` +
      'The value is visible in process listings (ps) for as long as the command runs.\n',
    );
  }

  const childEnv = { ...process.env, ...secrets };

  // Refuse a value the child environment cannot carry, BEFORE handing it to
  // Node — because Node's own refusal prints the value.
  //
  // `ERR_INVALID_ARG_VALUE` embeds what it rejected: "must be a string without
  // null bytes. Received 'sk-live-...'". The throw is synchronous, so the
  // `child.on('error')` handler below is never reached and the message goes
  // straight to the top-level handler and out to stderr — which is what CI
  // logs capture (#117). A NUL-bearing value is not exotic: macOS returns some
  // passwords hex-encoded precisely because they are binary, and the local
  // backend imposes no constraint at all.
  //
  // Checking first also lets the error name every offending secret rather than
  // whichever one Node reached first, and name only the NAME.
  const unusable = Object.keys(secrets).filter(
    (name) => name.includes('\0') || secrets[name].includes('\0'),
  );
  if (unusable.length > 0) {
    process.stderr.write(unusableSecretMessage(unusable));
    return 1;
  }

  let child: ChildProcess;
  try {
    child = spawn(command, args, {
      env: childEnv,
      stdio: 'inherit',
    });
  } catch (err) {
    // The check above covers what this version of Node rejects today. This
    // covers what it rejects tomorrow, on another platform, or for a reason
    // nobody anticipated — with every resolved value scrubbed out, and the
    // whole detail dropped if any survives.
    process.stderr.write(spawnFailureMessage(command, err, Object.values(secrets)));
    return 1;
  }

  // Forward signals to child
  const signals: NodeJS.Signals[] = ['SIGTERM', 'SIGINT', 'SIGHUP'];
  const handlers: Array<() => void> = [];
  for (const sig of signals) {
    const handler = () => child.kill(sig);
    handlers.push(handler);
    process.on(sig, handler);
  }

  return new Promise<number>((resolve) => {
    child.on('close', (code) => {
      // Clean up signal handlers
      for (let i = 0; i < signals.length; i++) {
        process.removeListener(signals[i], handlers[i]);
      }
      resolve(code ?? 1);
    });

    child.on('error', (err) => {
      // Same redaction as the synchronous path. This message has never been
      // observed carrying a value, but "has not been observed" is not a
      // property of the error, and both paths print to the same stderr.
      process.stderr.write(spawnFailureMessage(command, err, Object.values(secrets)));
      for (let i = 0; i < signals.length; i++) {
        process.removeListener(signals[i], handlers[i]);
      }
      resolve(1);
    });
  });
}

/**
 * Names of the secrets whose value appears in the command or its arguments,
 * verbatim or URL-encoded — a password inside a connection URL is carried
 * percent-encoded, so the stored form never matches it.
 */
function secretsOnArgv(command: string, args: string[], secrets: Record<string, string>): string[] {
  const argv = [command, ...args];
  return Object.keys(secrets).filter((name) => {
    const value = secrets[name];
    if (value.length < MIN_ARGV_VALUE) return false;
    const forms = [value];
    try {
      const encoded = encodeURIComponent(value);
      if (encoded !== value) forms.push(encoded);
    } catch {
      // A lone surrogate has no URL form; the verbatim check still applies.
    }
    return argv.some((arg) => forms.some((form) => arg.includes(form)));
  });
}

/** The program's base name, or null when printing it would show a stored value. */
function programName(command: string, values: string[]): string | null {
  const base = path.basename(command);
  return leaksAny(base, values) ? null : base;
}

/** Programs that read their connection settings from the libpq environment. */
const LIBPQ_PROGRAMS = new Set(['psql', 'pg_dump', 'pg_dumpall', 'pg_restore']);

/**
 * Why the command was not started, and the shape that keeps the value in the
 * environment for this program. Names only — never the value, and never the
 * command line that carries it.
 */
function argvRefusalMessage(names: string[], program: string | null): string {
  const plural = names.length !== 1;
  const owner = program ? `${program}'s` : 'the';
  const lines = [
    `secretless: ${names.join(', ')} ${plural ? 'are' : 'is'} on ${owner} command line. The command was not run.`,
    '',
    '  A process\'s arguments are readable by every local process (ps, process',
    '  monitors, crash reports) for as long as it runs. A "$NAME" reference in the',
    '  command is expanded by your shell before secretless-ai starts, so the value',
    '  arrived here as an argument. It is already in the command\'s environment.',
    '',
  ];

  if (program && LIBPQ_PROGRAMS.has(program)) {
    lines.push(
      `  ${program} reads the password from PGPASSWORD and the rest from PGHOST, PGPORT,`,
      '  PGUSER and PGDATABASE, or from a service= entry in pg_service.conf. Store the',
      '  password on its own and pass only the non-secret parts as arguments:',
      '',
      '  Fix:     secretless-ai secret set PGPASSWORD',
      `           secretless-ai run --only PGPASSWORD -- ${program} -h <host> -U <user> -d <database>`,
    );
  } else if (program === 'curl') {
    lines.push(
      '  curl reads a header from stdin with -H @- (or from a file with -H @file, or',
      '  from --config). printf is a shell builtin, so the value reaches curl without',
      '  appearing on any command line:',
      '',
      `  Fix:     secretless-ai run --only ${names[0]} -- sh -c 'printf "Authorization: Bearer %s\\n" "$${names[0]}" | curl -H @- <url>'`,
    );
  } else {
    lines.push(
      `  Have the program read ${names[0]} from its environment instead:`,
      '',
      `  Fix:     secretless-ai run --only ${names[0]} -- <command without the value>`,
    );
  }

  lines.push(
    '',
    '  To start it anyway, with the value visible in process listings:',
    '           secretless-ai run --allow-argv -- <command>',
    '',
  );
  return lines.join('\n');
}

/**
 * Names the secrets that cannot be passed, and nothing else about them.
 *
 * The name is safe — `secret list` prints it, and the Verify line points there.
 * The value is the thing being protected, so it is not shown, not summarised,
 * and not counted in bytes.
 */
function unusableSecretMessage(names: string[]): string {
  const plural = names.length === 1 ? '' : 's';
  return [
    `secretless: ${names.join(', ')} cannot be passed in an environment variable.`,
    '',
    `  The stored value${plural} contain${names.length === 1 ? 's' : ''} a null byte. Nothing was injected and the`,
    '  command was not run.',
    '',
    '  This is usually a value that was mangled when it was stored — a paste that',
    '  captured terminal escape sequences, or a binary value read back as text.',
    '',
    '  Verify:  secretless-ai secret list',
    `  Fix:     secretless-ai secret set ${names[0]}`,
    '',
  ].join('\n');
}

/**
 * A spawn failure, with every resolved secret scrubbed out of the detail.
 *
 * If any value survives the scrub the detail is dropped entirely rather than
 * trimmed — the residue is what leaks. The command name and our own framing
 * always remain, so the message is never empty.
 */
function spawnFailureMessage(command: string, err: unknown, values: string[]): string {
  const raw = err instanceof Error ? err.message : String(err);
  const detail = scrubOrDrop(raw, values);

  // The command is echoed back, and it is user-supplied: a secret exported in
  // the calling shell can be sitting in the argv we are about to print. Checked
  // separately from the framing around it, so a run coinciding with our own
  // wording ("secret", "list") cannot suppress a detail that was fine.
  const shown = leaksAny(command, values) ? '<command>' : command;

  const lines = [`secretless: Failed to start ${shown}.`];
  lines.push(
    detail
      ? `  ${detail.split('\n').join('\n  ')}`
      : '  The underlying error was withheld: it carried a stored secret value.',
  );
  lines.push(
    '',
    '  Verify:  secretless-ai secret list',
    '  Fix:     secretless-ai run -- <command>',
    '',
  );
  return lines.join('\n');
}
