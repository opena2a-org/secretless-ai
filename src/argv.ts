/**
 * argv normalisation — one derivation, applied once at the entry point.
 *
 * WHY THIS FILE EXISTS. Every command used to parse its own argv, and each
 * parser recognised exactly the spellings its author happened to think of.
 * `--only=NAME` was not one of them, so `run` dropped the selector and injected
 * the ENTIRE credential store into the child process. `--dryrun` was not one of
 * them, so `clean` performed the irreversible in-place redaction it had been
 * asked to preview. `--path=DIR` was not one of them, so `clean` walked every
 * transcript on the machine instead of the one directory named — measured at
 * 9,119 files against the 1 the user asked for.
 *
 * Those are not three bugs. They are one: a token the user typed is discarded,
 * and the command proceeds with a scope WIDER than the one requested, exits 0,
 * and says nothing. `--only` and `--path` are both scope NARROWING flags, which
 * is what makes dropping them dangerous rather than merely annoying.
 *
 * THE RULE. A flag that is present, in any spelling, never widens scope. It
 * binds, or the command refuses to run.
 *
 * WHY IT IS NOT AN `=` BRANCH PER COMMAND. That was the obvious fix and it is
 * the wrong one: it adds a parsing surface to every command, and a parsing
 * surface per command is precisely what produced this class. Normalisation
 * happens once, here, before dispatch. Every existing downstream consumer —
 * `args.includes('--dry-run')`, `args.indexOf('--path')` — keeps working
 * unchanged, because by the time it runs it is looking at the split form.
 *
 * SAFETY PROPERTY OF AN INCOMPLETE REGISTRY. Splitting only ever happens for a
 * flag this file records as taking a value. An unregistered `--foo=bar` is left
 * whole and falls through to the unknown-flag path exactly as it does today, so
 * a gap in the table degrades to the OLD behaviour and can never invent a
 * positional argument the user did not type. The direction of that failure is
 * deliberate.
 */

/**
 * IMPORTS ARE LOAD-BEARING HERE. `mcp-wrapper.ts` imports this module, and
 * `protect-mcp` installs the wrapper by copying `dist/` — and ONLY `dist/` — to
 * `~/.secretless-ai/bin`. Anything this module reaches that lives outside
 * `dist/` is therefore missing in the installed layout. An earlier draft
 * imported `commands/utils` for its `CLI_BARE` constant, which does
 * `require('../../package.json')`; in the copied tree that path does not exist,
 * so every protected MCP server died at startup with MODULE_NOT_FOUND. Caught
 * by `mcp/e2e.test.ts`, which spawns the wrapper from a real installed copy.
 *
 * Keep this module's dependencies to leaf modules with no package-relative
 * requires. Presentation that needs `CLI_BARE` lives in `cli.ts` instead.
 */
import { nearestMatch } from './near-miss';

/**
 * Exit code for a usage error, matching what the CLI already uses for one:
 * `scan` refusing multiple paths and `rejectUnknownFlagAsDirArg` both return 2.
 * Reserved from the scanner's own 0/1, where 1 means "credentials found".
 */
export const EXIT_USAGE = 2;

/** How a verb treats a flag it does not recognise. */
export type UnknownFlagPolicy =
  /** Refuse to run, exit EXIT_USAGE, before any side effect. */
  | 'reject'
  /** Print a warning and continue — the behaviour `scan` has shipped since #81. */
  | 'warn';

export interface VerbSpec {
  /** Flag spelling -> whether it consumes the FOLLOWING argv token as its value. */
  flags: Record<string, boolean>;
  /**
   * What to do with a flag not in `flags`. `reject` on every verb that can
   * write, because a misspelled safety flag there is a destroyed file; `warn`
   * on read-only verbs, where the cost of a typo is a wasted run.
   */
  unknownFlags: UnknownFlagPolicy;
  /**
   * True when everything from the first bare `--` is a child command. That tail
   * is the CHILD's argv, not ours: rewriting `--only=x` inside it would corrupt
   * the command the user is wrapping.
   */
  passthrough?: boolean;
  /**
   * True when this verb actually implements `--json`.
   *
   * Acceptance of `--json` is global and unchanged (see GLOBAL_FLAGS); this
   * governs only whether we NAME it as supported when refusing a command line.
   * Naming it on the 30 verbs that ignore it would advertise a machine-readable
   * mode that does not exist, in the text a user reads at the moment they hit
   * an error — the same false-clean class this release exists to close, and it
   * would contradict this release's own note that `--json` is unchanged.
   */
  honorsJson?: boolean;
}

/**
 * Accepted by every verb.
 *
 * `--json` is here because 20 verbs accept and silently ignore it today. The
 * 2026-08-12 `[CHIEF-CPO]` ruling is that a flag the tool accepts is a flag the
 * tool honors, and that `--json` on a verb that does not implement it must exit
 * 2 naming the verbs that do. That is a consumer-visible exit-code change and
 * belongs to its own release, so it is NOT made here. Listing `--json` keeps
 * this release's behaviour byte-identical and leaves the ruling exactly one
 * place to land: delete this entry and give the implementing verbs their own.
 *
 * ACCEPTING it globally is not the same as ADVERTISING it globally. Only verbs
 * marked `honorsJson` name it in a refusal message — see `supportedFlags`.
 */
const GLOBAL_FLAGS: Readonly<Record<string, boolean>> = {
  '--help': false,
  '-h': false,
  '--json': false,
};

/**
 * Every verb the dispatcher accepts, with the flags it actually reads.
 *
 * `unknownFlags` is keyed on whether the verb can WRITE — mutate a file, the
 * credential store, or system state — not on how dangerous it feels. `clean`
 * and `clean-history` are the sharpest cases: both are destructive by default
 * and `--dry-run` is the only thing that makes either a preview, so a
 * misspelling of that flag has to stop the run rather than degrade to it.
 *
 * A verb whose flag list is incomplete would reject a working command, so
 * `argv.test.ts` derives the flag literals from the source and asserts this
 * table covers them. The test reads the source, not this table, so the two
 * cannot agree by construction.
 */
export const VERBS: Readonly<Record<string, VerbSpec>> = {
  // --- read-only: a typo costs a wasted run, so warn and continue -----------
  scan: {
    flags: {
      '--history': false,
      '--include-tests': false,
      '--explain': false,
      '--no-ignore': false,
      '--show-placeholders': false,
      '--min-confidence': true,
      '--max-files': true,
      '--max-file-size': true,
    },
    unknownFlags: 'warn',
    honorsJson: true,
  },
  // `status` already refuses an unknown flag today, via
  // `rejectUnknownFlagAsDirArg` — the flag falls through as its directory
  // argument. Keeping it at `reject` preserves that exit code while replacing a
  // message that called the flag a bad path with one that calls it a bad flag.
  status: { flags: {}, unknownFlags: 'reject', honorsJson: true },
  // `verify` is the one read-only verb where a swallowed flag changes the
  // ANSWER rather than wasting the run: `verify --alll` silently returns the
  // short report, and the user reads "36 known env vars not set (use --all to
  // list)" believing they ran the full listing.
  verify: { flags: { '--all': false }, unknownFlags: 'reject' },
  'scan-staged': { flags: { '--no-ignore': false }, unknownFlags: 'warn' },
  'scan-history': { flags: {}, unknownFlags: 'warn' },
  'mcp-status': { flags: {}, unknownFlags: 'warn' },
  feedback: { flags: {}, unknownFlags: 'warn' },
  // No flags of its own: `diff` reads one positional ref (commands/diff.ts:292).
  // The `--no-color`, `--verify` and `--show-toplevel` literals in that file are
  // arguments it passes to `git`, not flags it accepts — the distinction matters
  // because listing them here would make the tool silently accept three flags it
  // does not implement.
  diff: { flags: {}, unknownFlags: 'warn' },

  // --- writing verbs: a swallowed flag is a changed file --------------------
  clean: {
    flags: { '--dry-run': false, '--last': false, '--path': true },
    unknownFlags: 'reject',
  },
  'clean-history': {
    flags: { '--dry-run': false },
    unknownFlags: 'reject',
  },
  run: {
    flags: { '--only': true },
    unknownFlags: 'reject',
    passthrough: true,
  },
  env: {
    flags: { '--only': true },
    unknownFlags: 'reject',
  },
  init: { flags: {}, unknownFlags: 'reject' },
  doctor: { flags: { '--fix': false }, unknownFlags: 'reject' },
  import: { flags: { '--detect': false }, unknownFlags: 'reject' },
  setup: { flags: { '--check': false }, unknownFlags: 'reject' },
  secret: { flags: { '--force': false }, unknownFlags: 'reject' },
  watch: { flags: {}, unknownFlags: 'reject' },
  hook: { flags: { '--check-only': false }, unknownFlags: 'reject' },
  warm: { flags: { '--ttl': true, '--no-broker': false }, unknownFlags: 'reject' },
  install: { flags: {}, unknownFlags: 'reject' },
  'protect-mcp': { flags: { '--backend': true }, unknownFlags: 'reject' },
  'mcp-unprotect': { flags: {}, unknownFlags: 'reject' },
  ignore: { flags: { '--pattern': true }, unknownFlags: 'reject' },
  telemetry: { flags: {}, unknownFlags: 'reject' },
  rules: { flags: { '--env': false, '--file': false, '--bash': false }, unknownFlags: 'reject' },
  backend: {
    flags: { '--yes': false, '--prefix': true, '--from': true, '--to': true },
    unknownFlags: 'reject',
  },
  migrate: { flags: { '--from': true, '--to': true }, unknownFlags: 'reject' },
  cache: { flags: {}, unknownFlags: 'reject' },
  scope: { flags: {}, unknownFlags: 'reject' },
  broker: {
    flags: {
      '--aim-url': true,
      '--aim-token': true,
      '--port': true,
      '--policy-file': true,
    },
    unknownFlags: 'reject',
  },
  vault: {
    // The union of every subcommand's flags rather than a per-subcommand table:
    // accepting `--limit` on `vault add` is what the tool does today and is not
    // what this release is about, while a per-subcommand table would be a
    // second parsing surface — the thing this file exists to avoid.
    flags: {
      '--name': true,
      '--value': true,
      '--env': true,
      '--description': true,
      '--operations': true,
      '--url-patterns': true,
      '--limit': true,
      '--since': true,
      '--namespace': true,
      '--env-name': true,
      '--env-file': true,
      '--dry-run': false,
    },
    unknownFlags: 'reject',
    passthrough: true,
  },
};

/**
 * `secretless-mcp`, the second published bin (package.json `bin`).
 *
 * It is not a verb of `secretless-ai` and has never been swept, which is the
 * whole reason it is here: the broker fail-open survived two dedicated sweeps
 * because both swept per COMMAND SURFACE, and this wrapper is a command surface
 * nobody was looking at. It carries the identical
 * `argv[i] === '--server' && argv[i + 1]` idiom, so `--vault-dir=/path` is
 * dropped and the wrapper silently reads the DEFAULT vault instead of the one
 * named — the same substitution as `clean --path=`, one bin over.
 *
 * `unknownFlags: 'warn'` rather than 'reject': these argv lines are written
 * into MCP client configs by `protect-mcp` and are edited by hand afterwards,
 * so refusing an unrecognised token would break a user's MCP server at startup
 * for a flag that may simply be new. Binding the ones we do know is the fix;
 * refusing the ones we do not is a separate decision with a different blast
 * radius.
 */
export const MCP_WRAPPER: VerbSpec = {
  flags: {
    '--server': true,
    '--client': true,
    '--vault-dir': true,
    '--vault-key': true,
    '--backend': true,
  },
  unknownFlags: 'warn',
  passthrough: true,
};

export interface PreparedArgv {
  /** argv with every registered `--flag=value` split into two tokens. */
  args: string[];
  /**
   * Non-flag tokens after the verb, with flag VALUES excluded — so a path is
   * never mistaken for a value and a value is never mistaken for a path.
   */
  positionals: string[];
  /** Print to stderr; the command still runs. */
  warnings: string[];
  /** Print to stderr and exit EXIT_USAGE; the command must NOT run. */
  errors: string[];
}

/** `--path <value>` for a value-taking flag, `--dry-run` otherwise. */
function usageOf(flag: string, takesValue: boolean): string {
  return takesValue ? `${flag} <value>` : flag;
}

/** Every flag a verb accepts, in a stable order, for an error message. */
export function supportedFlags(spec: VerbSpec): string[] {
  const all = { ...GLOBAL_FLAGS, ...spec.flags };
  return Object.keys(all)
    .filter((f) => f !== '-h')
    // `--json` is accepted by every verb and implemented by two. Listing it as
    // "Supported" everywhere promises a machine-readable mode that does not
    // exist — and promises it in the one place a user reads after a refusal.
    .filter((f) => f !== '--json' || spec.honorsJson === true)
    .sort()
    .map((f) => usageOf(f, all[f]));
}

/**
 * Normalise and validate one command line.
 *
 * `args` is the FULL argv after the node binary and script — `args[0]` is the
 * verb — so the caller can keep passing the same array it always did.
 */
export function prepareArgv(verb: string | undefined, args: string[]): PreparedArgv {
  const spec = verb ? VERBS[verb] : undefined;
  // An unrecognised verb is the dispatcher's error to report, with its own help
  // output. Rewriting argv for a command that will not run helps nobody.
  if (!verb || !spec) return { args, positionals: [], warnings: [], errors: [] };
  // args[0] is the verb; flags start at 1.
  return prepareWithSpec(spec, args, 1);
}

/**
 * The same normalisation for a bin whose argv has no leading verb — the
 * `secretless-mcp` wrapper, whose first token is already a flag.
 */
export function prepareBinArgv(spec: VerbSpec, args: string[]): PreparedArgv {
  return prepareWithSpec(spec, args, 0);
}

function prepareWithSpec(spec: VerbSpec, args: string[], firstFlagIndex: number): PreparedArgv {
  // Split at the first bare `--` BEFORE touching anything, so the child's argv
  // is preserved byte for byte.
  const sepIdx = spec.passthrough ? args.indexOf('--') : -1;
  const head = sepIdx === -1 ? args : args.slice(0, sepIdx);
  const tail = sepIdx === -1 ? [] : args.slice(sepIdx);

  const known: Record<string, boolean> = { ...GLOBAL_FLAGS, ...spec.flags };
  const knownNames = Object.keys(known);

  const out: string[] = [];
  const positionals: string[] = [];
  const warnings: string[] = [];
  const errors: string[] = [];
  const unknown: string[] = [];

  for (let i = 0; i < head.length; i++) {
    const token = head[i];

    // The verb itself, where there is one.
    if (i < firstFlagIndex) { out.push(token); continue; }

    if (!token.startsWith('--')) {
      out.push(token);
      positionals.push(token);
      continue;
    }

    const eq = token.indexOf('=');
    const name = eq === -1 ? token : token.slice(0, eq);
    const inline = eq === -1 ? undefined : token.slice(eq + 1);
    const takesValue = known[name];

    if (takesValue === undefined) {
      // Left WHOLE on purpose. Splitting an unregistered `--foo=bar` would push
      // `bar` into the positional list, and for `scan` or `clean` a stray
      // positional is a path — a token the user never typed becoming a target.
      unknown.push(token);
      out.push(token);
      continue;
    }

    if (takesValue) {
      if (inline !== undefined) {
        // `--only=` (empty) is the flag WITH an empty value, not the flag
        // absent. That distinction is load-bearing: `--only ''` fails closed
        // downstream while a missing `--only` injects everything (#110).
        out.push(name, inline);
        continue;
      }
      if (i + 1 >= head.length) {
        errors.push(`${name} needs a value, but none was given.`);
        out.push(token);
        continue;
      }
      out.push(name, head[i + 1]);
      // Consumed, so the value can never be re-read as a flag or a positional.
      i++;
      continue;
    }

    if (inline !== undefined) {
      errors.push(`${name} does not take a value, but was given "${inline}".`);
      out.push(name);
      continue;
    }
    out.push(token);
  }

  if (unknown.length > 0) {
    const lines = unknown.map((u) => {
      const near = nearestMatch(u, knownNames);
      return near ? `${u} (did you mean ${usageOf(near, known[near])}?)` : u;
    });
    const plural = unknown.length > 1 ? 's' : '';
    if (spec.unknownFlags === 'reject') {
      errors.push(`Unknown option${plural}: ${lines.join(', ')}`);
    } else {
      warnings.push(`Warning: ignoring unknown flag${plural} ${lines.join(', ')}.`);
    }
  }

  return { args: out.concat(tail), positionals, warnings, errors };
}

