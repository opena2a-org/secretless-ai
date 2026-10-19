/**
 * The prompt check: `hook --check-prompt` reads the text a user is about to
 * submit and refuses it when it carries a credential, before it is sent (#237).
 *
 * The guard hook and the Stop hook act around a tool call and after a turn.
 * Nothing looked at the prompt itself, so a key pasted into one was sent, then
 * redacted from the local transcript, and nothing said so. Once a value has
 * reached the provider it has to be rotated; refusing the prompt is the one
 * point where nothing needs rotating.
 *
 * Two comparisons, both made in this process:
 *   - the credential catalog (`patterns.ts`), with the scanner's placeholder
 *     allowlist, so a documented example key is not refused; this one reads
 *     nothing outside the process;
 *   - the values of the stored secrets, read through the configured backend
 *     and compared in memory, so a prompt that pastes `secret set` output of
 *     a format outside the catalog is refused too. That read is local for
 *     the local store and the OS keychain. For Vault and GCP Secret Manager
 *     it is a request to that service, and for 1Password a run of the `op`
 *     CLI, on the first prompt and again whenever the value cache (300 s by
 *     default) has expired; a GCP project named by a manifest has no cache,
 *     so every prompt sends one.
 *
 * Claude Code runs it as a UserPromptSubmit hook. Exit 2 with the reason on
 * stderr is "do not send this prompt, show the user why"; the same decision
 * goes to stdout as JSON for a reader of that form. Exit 0 with no output
 * lets the prompt through. The reason names a pattern or a stored secret's
 * name, never a value.
 */

import { CREDENTIAL_PATTERNS, KNOWN_EXAMPLE_KEYS, PLACEHOLDER_INDICATORS } from './patterns';
import { SecretStore } from './secret-store';
import { CLI_BARE } from './commands/utils';

export const CHECK_PROMPT_FLAG = '--check-prompt';

/** The exit code of a refused prompt: Claude Code reads 2 from a UserPromptSubmit hook as "do not send". */
export const PROMPT_REFUSED_EXIT = 2;

/**
 * A stored value shorter than this is not looked for in the prompt: a short
 * value is found inside ordinary words. The same floor `clean` and `watch`
 * apply when they compare a redacted span with the store (#236).
 */
export const MIN_STORED_VALUE_LENGTH = 8;

// The prompt is matched in overlapping windows, as the output check is. Some
// catalog patterns have an unbounded run before a separator, quadratic over
// one long run of matching characters. Windows overlap by more than the
// shortest text any catalog pattern needs, so a credential that starts too
// close to one window's end to match there matches in the next.
const WINDOW = 16384;
const OVERLAP = 2048;

/** The catalog with a global copy of each regex, built once. */
const GLOBAL_PATTERNS = CREDENTIAL_PATTERNS.map((p) => ({
  id: p.id,
  name: p.name,
  envPrefix: p.envPrefix,
  regex: new RegExp(p.regex.source, p.regex.flags.replace('g', '') + 'g'),
}));

export interface MatchedPattern {
  id: string;
  name: string;
  /** The variable name the catalog suggests for this kind of credential. */
  envPrefix: string;
}

export interface PromptCheck {
  /** Catalog patterns a value in the prompt matches, in catalog order, each once. */
  patterns: MatchedPattern[];
  /** Stored secrets whose value is in the prompt, sorted by name. */
  storedNames: string[];
}

/**
 * The value half of the scanner's allowlist (`isKnownExample` in scan.ts). Its
 * line-context rules need a source line, which a prompt is not.
 */
function isPlaceholder(value: string): boolean {
  if (KNOWN_EXAMPLE_KEYS.has(value)) return true;
  const lower = value.toLowerCase();
  if (PLACEHOLDER_INDICATORS.some((p) => lower.includes(p))) return true;
  return value.length >= 20 && new Set(value).size <= 6;
}

function matchesSomewhere(re: RegExp, text: string): boolean {
  for (let start = 0; start < text.length; start += WINDOW - OVERLAP) {
    const chunk = text.slice(start, start + WINDOW);
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(chunk)) !== null) {
      if (!isPlaceholder(m[1] ?? m[0])) return true;
      if (m[0].length === 0) re.lastIndex++;
    }
    if (start + WINDOW >= text.length) break;
  }
  return false;
}

/** The catalog patterns that a non-placeholder value in `text` matches. */
export function matchedPatterns(text: string): MatchedPattern[] {
  const out: MatchedPattern[] = [];
  for (const p of GLOBAL_PATTERNS) {
    if (matchesSomewhere(p.regex, text)) out.push({ id: p.id, name: p.name, envPrefix: p.envPrefix });
  }
  return out;
}

/**
 * The names of the stored secrets whose value is in `text`. Compared in
 * memory; the values go nowhere.
 */
export function storedValuesIn(text: string, stored: Readonly<Record<string, string>>): string[] {
  const names: string[] = [];
  for (const name of Object.keys(stored).sort()) {
    const value = stored[name];
    if (typeof value !== 'string' || value.length < MIN_STORED_VALUE_LENGTH) continue;
    if (text.includes(value)) names.push(name);
  }
  return names;
}

/** Both comparisons over one prompt. `stored` is the store's content, when it could be read. */
export function checkPromptText(text: string, stored?: Readonly<Record<string, string>>): PromptCheck {
  return {
    patterns: matchedPatterns(text),
    storedNames: stored ? storedValuesIn(text, stored) : [],
  };
}

/**
 * The reason a prompt is refused, as the user reads it: what was found, by
 * pattern name or stored secret name, and what to write instead. Empty when
 * nothing was found. Never a value.
 */
export function refusalReason(check: PromptCheck): string {
  const parts: string[] = [];
  if (check.patterns.length === 1) {
    parts.push(`a value that matches the ${check.patterns[0].name} pattern`);
  } else if (check.patterns.length > 1) {
    parts.push(`values that match ${check.patterns.length} credential patterns (${check.patterns.map((p) => p.name).join(', ')})`);
  }
  if (check.storedNames.length === 1) {
    parts.push(`the value of your stored secret ${check.storedNames[0]}`);
  } else if (check.storedNames.length > 1) {
    parts.push(`the values of your stored secrets ${check.storedNames.join(', ')}`);
  }
  if (parts.length === 0) return '';

  let reason = `Secretless: prompt not sent: it holds ${parts.join(', and ')}.`;
  if (check.storedNames.length > 0) {
    const refs = check.storedNames.map((n) => `$${n}`);
    const list = refs.length === 1 ? refs[0] : `${refs.slice(0, -1).join(', ')} and ${refs[refs.length - 1]}`;
    reason += ` Refer to ${check.storedNames.length === 1 ? 'it' : 'them'} by name instead: write ${list} in the prompt.`;
  }
  if (check.patterns.length > 0) {
    const name = check.patterns[0].envPrefix || 'NAME';
    reason += ` Store ${check.patterns.length === 1 ? 'the value' : 'each value'} and refer to it by name: ${CLI_BARE} secret set ${name}, then write $${name} in the prompt.`;
  }
  return reason;
}

/**
 * The prompt text in what a hook receives: the `prompt` member of the JSON
 * Claude Code sends a UserPromptSubmit hook, or the whole input when it is not
 * JSON with one, so plain text piped in is checked as itself.
 */
export function promptTextOf(input: string): string {
  const trimmed = input.trim();
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object' && typeof parsed.prompt === 'string') return parsed.prompt;
    } catch {
      // Not JSON: the input is the prompt.
    }
  }
  return input;
}

function readAll(stream: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve, reject) => {
    let input = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk: string | Buffer) => { input += String(chunk); });
    stream.on('end', () => resolve(input));
    stream.on('error', reject);
  });
}

export interface PromptCheckRunOptions {
  /** The hook's input; stdin unless given. */
  input?: NodeJS.ReadableStream;
  /** The store whose values are compared; the configured one unless given. */
  createStore?: () => SecretStore;
  stdout?: { write(chunk: string): unknown };
  stderr?: { write(chunk: string): unknown };
}

/**
 * Run the check on the hook's input and answer as a UserPromptSubmit hook.
 *
 * A store that cannot be read (a locked keychain, a backend that is down)
 * leaves the stored-value comparison out and the catalog comparison in: the
 * check still answers, and says nothing about it, because a hook's output on
 * a prompt it lets through is shown to the user or added to context.
 */
export async function runPromptCheck(options: PromptCheckRunOptions = {}): Promise<number> {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const text = promptTextOf(await readAll(options.input ?? process.stdin));
  if (text === '') return 0;

  let stored: Record<string, string> | undefined;
  try {
    stored = await (options.createStore ?? (() => new SecretStore()))().loadSecrets();
  } catch {
    stored = undefined;
  }
  const check = checkPromptText(text, stored);
  const reason = refusalReason(check);
  if (reason === '') return 0;

  stdout.write(JSON.stringify({ decision: 'block', reason }) + '\n');
  stderr.write(reason + '\n');
  return PROMPT_REFUSED_EXIT;
}
