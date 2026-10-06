/**
 * What a stored secret is for: a description and free-form key/value metadata
 * (`app`, `provider`, `scopes`, `tokenTtl`, `redirectUri`, `expiresAt`, ...),
 * kept beside the store and never inside it (#172).
 *
 * Plain JSON, not encrypted, because none of it is a secret and it has to be
 * readable without unlocking the store: an OS keychain prompt to learn which
 * app a client id belongs to defeats the point. The value never enters this
 * file. `checkAnnotation` refuses an annotation that contains the value or
 * holds something credential-shaped, because every path that reads this file
 * prints it.
 *
 * Keys are conventions, not a schema: nothing here gives `scopes` or `app` a
 * meaning beyond being a string the CLI can filter on.
 */

import * as fs from 'fs';
import * as path from 'path';
import { CREDENTIAL_PATTERNS } from './patterns';

const ANNOTATIONS_FILE = 'secret-annotations.json';
const SUPPORTED_VERSION = 1;

/** Longest description accepted. One line of prose, not a document. */
export const MAX_DESCRIPTION_LENGTH = 500;
/** Longest metadata value accepted. Room for a long scope list or URL. */
export const MAX_META_VALUE_LENGTH = 1024;
/** Most metadata keys one secret may carry. */
export const MAX_META_KEYS = 50;

/** A metadata key: starts with a letter, then letters, digits, `_`, `.` or `-`. */
const META_KEY = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
/**
 * Line breaks, tabs, escape sequences and other control characters. A value
 * carrying one could rewrite the terminal it is printed to or split one entry
 * into two lines of `secret list --long`.
 */
const CONTROL_CHAR = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * A whole value shorter than this is not checked for containment: a two-digit
 * value would otherwise forbid every metadata string that happens to contain
 * those digits. An annotation EQUAL to the value is refused at any length.
 */
const MIN_CONTAINED_VALUE = 8;

export interface SecretAnnotation {
  description?: string;
  meta: Record<string, string>;
  /** When an annotation was first recorded for this name (ISO 8601). */
  recordedAt: string;
  /** When it last changed (ISO 8601). */
  updatedAt: string;
}

/**
 * A change to one secret's annotation. Absent fields are left as they are, so
 * rotating a value does not erase what the credential is for.
 */
export interface AnnotationUpdate {
  /** Replaces the description. An empty string removes it. */
  description?: string;
  /** Sets each key. An empty value removes that key. */
  meta?: Record<string, string>;
}

interface AnnotationFileShape {
  version: number;
  secrets: Record<string, SecretAnnotation>;
}

/**
 * Keyed by secret name. A Map, not an object: `__proto__` and `constructor`
 * are valid secret names, and as object keys one rewrites the prototype and
 * the other reads one.
 */
export type AnnotationMap = Map<string, SecretAnnotation>;

/** `~/.secretless-ai/secret-annotations.json`, resolved at call time. */
export function defaultAnnotationsPath(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
  return path.join(home, '.secretless-ai', ANNOTATIONS_FILE);
}

export function isEmptyUpdate(update: AnnotationUpdate | undefined): boolean {
  if (!update) return true;
  return update.description === undefined && Object.keys(update.meta ?? {}).length === 0;
}

function unreadableAnnotationsError(filePath: string, reason: string): Error {
  return new Error(
    [
      'The secret descriptions and metadata could not be read.',
      '',
      '  Nothing was read from it. Refusing to report secrets as unannotated,',
      '  because an empty file and an unreadable one are not the same thing.',
      '',
      `  File:    ${filePath}`,
      `  Reason:  ${reason}`,
      '',
      '  Stored values are untouched. This file holds descriptions and metadata only.',
      '',
      `  Verify:  node -e "JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'))" ${filePath}`,
      '  Fix:     repair it, or move it aside and re-add annotations with',
      '           secretless-ai secret set NAME --description "..." --meta key=value',
    ].join('\n'),
  );
}

function isStringRecord(value: unknown): value is Record<string, string> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  return Object.values(value).every((v) => typeof v === 'string');
}

function isAnnotation(value: unknown): value is SecretAnnotation {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const a = value as Record<string, unknown>;
  return (a.description === undefined || typeof a.description === 'string')
    && isStringRecord(a.meta)
    && typeof a.recordedAt === 'string'
    && typeof a.updatedAt === 'string';
}

/**
 * Read every annotation, or throw.
 *
 * Returns an empty map only when the file does not exist. Any other failure is a state
 * this function cannot describe, so it does not guess. The parse error is not
 * quoted: it would echo the file's contents.
 */
export function readAnnotations(filePath: string): AnnotationMap {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return new Map();
    throw unreadableAnnotationsError(filePath, (err as Error).message);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw unreadableAnnotationsError(filePath, 'not valid JSON');
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw unreadableAnnotationsError(filePath, 'not a JSON object');
  }
  const file = parsed as Partial<AnnotationFileShape>;
  if (file.version !== SUPPORTED_VERSION) {
    const found = typeof file.version === 'number' ? `version ${file.version}` : 'no version number';
    throw unreadableAnnotationsError(filePath, `${found}; this build reads version ${SUPPORTED_VERSION}`);
  }
  const secrets = file.secrets;
  if (typeof secrets !== 'object' || secrets === null || Array.isArray(secrets)) {
    throw unreadableAnnotationsError(filePath, '"secrets" is not an object');
  }
  const out: AnnotationMap = new Map();
  for (const [name, entry] of Object.entries(secrets)) {
    if (!isAnnotation(entry)) {
      throw unreadableAnnotationsError(filePath, 'an entry is not a description and metadata record');
    }
    out.set(name, entry);
  }
  return out;
}

/** Write the whole file through a temporary file, so a crash leaves the old one. */
function writeAnnotations(filePath: string, secrets: AnnotationMap): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  // Own data properties, so a `__proto__` name is written as a key like any other.
  const sorted: Record<string, SecretAnnotation> = {};
  for (const name of [...secrets.keys()].sort()) {
    Object.defineProperty(sorted, name, { value: secrets.get(name), enumerable: true, writable: true, configurable: true });
  }
  const body: AnnotationFileShape = { version: SUPPORTED_VERSION, secrets: sorted };
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(body, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

/**
 * Why an annotation cannot be recorded for this value, or null if it can.
 *
 * The reason names the field, never its content: the content is what is
 * suspected of being a credential.
 */
export function checkAnnotation(update: AnnotationUpdate, value: string): string | null {
  const fields: Array<[string, string]> = [];
  if (update.description !== undefined) {
    if (update.description.length > MAX_DESCRIPTION_LENGTH) {
      return `--description is ${update.description.length} characters; the limit is ${MAX_DESCRIPTION_LENGTH}.`;
    }
    if (CONTROL_CHAR.test(update.description)) {
      return '--description contains a line break or another control character; give it as one line.';
    }
    fields.push(['--description', update.description]);
  }

  const meta = update.meta ?? {};
  for (const [key, v] of Object.entries(meta)) {
    if (!META_KEY.test(key)) {
      return `--meta key "${key.slice(0, 64)}" is not usable. A key starts with a letter, then letters, digits, '_', '.' or '-' (64 characters at most).`;
    }
    if (v.length > MAX_META_VALUE_LENGTH) {
      return `--meta ${key} is ${v.length} characters; the limit is ${MAX_META_VALUE_LENGTH}.`;
    }
    if (CONTROL_CHAR.test(v)) {
      return `--meta ${key} contains a line break or another control character; give it as one line.`;
    }
    fields.push([`--meta ${key}`, v]);
  }

  for (const [label, text] of fields) {
    if (!text) continue;
    if (text === value || (value.length >= MIN_CONTAINED_VALUE && text.includes(value))) {
      return `${label} contains the secret's own value. Descriptions and metadata are printed by \`secret show\` and \`secret list --long\`, so the value cannot go there.`;
    }
    const pattern = CREDENTIAL_PATTERNS.find((p) => p.regex.test(text));
    if (pattern) {
      return `${label} looks like a credential (${pattern.name}). Descriptions and metadata are stored in plain text and printed; store a credential as its own secret instead.`;
    }
  }
  return null;
}

/** Apply an update to a record, or return null when nothing is left to keep. */
function applyUpdate(
  current: SecretAnnotation | undefined,
  update: AnnotationUpdate,
  now: string,
): SecretAnnotation | null {
  const meta: Record<string, string> = { ...(current?.meta ?? {}) };
  for (const [key, v] of Object.entries(update.meta ?? {})) {
    if (v === '') delete meta[key];
    else meta[key] = v;
  }
  let description = current?.description;
  if (update.description !== undefined) {
    description = update.description === '' ? undefined : update.description;
  }
  if (description === undefined && Object.keys(meta).length === 0) return null;

  const next: SecretAnnotation = {
    meta,
    recordedAt: current?.recordedAt ?? now,
    updatedAt: now,
  };
  if (description !== undefined) next.description = description;
  return next;
}

/**
 * The annotations for one store. All methods read the file fresh.
 *
 * A null path keeps them in memory instead, for a store built on an injected
 * backend: a test store must never read or rewrite the annotations of the
 * user's real one.
 */
export class SecretAnnotations {
  private memory: AnnotationMap | null;

  constructor(readonly filePath: string | null = defaultAnnotationsPath()) {
    this.memory = filePath === null ? new Map() : null;
  }

  all(): AnnotationMap {
    return this.memory ? new Map(this.memory) : readAnnotations(this.filePath!);
  }

  get(name: string): SecretAnnotation | undefined {
    return this.all().get(name);
  }

  private save(secrets: AnnotationMap): void {
    if (this.memory) this.memory = secrets;
    else writeAnnotations(this.filePath!, secrets);
  }

  /**
   * The record `update` would leave for `name`, without writing it. Throws if
   * the file cannot be read, or if the record would carry more than
   * `MAX_META_KEYS` keys, so a caller can refuse before changing anything else.
   */
  preview(name: string, update: AnnotationUpdate, now: Date = new Date()): SecretAnnotation | null {
    return this.next(this.all(), name, update, now);
  }

  private next(secrets: AnnotationMap, name: string, update: AnnotationUpdate, now: Date): SecretAnnotation | null {
    const next = applyUpdate(secrets.get(name), update, now.toISOString());
    if (next && Object.keys(next.meta).length > MAX_META_KEYS) {
      throw new Error(`A secret can carry at most ${MAX_META_KEYS} metadata keys; ${name} would have ${Object.keys(next.meta).length}.`);
    }
    return next;
  }

  /** Apply `update` to `name`'s record. Throws as `preview` does. */
  update(name: string, update: AnnotationUpdate, now: Date = new Date()): SecretAnnotation | undefined {
    const secrets = this.all();
    const next = this.next(secrets, name, update, now);
    if (next) secrets.set(name, next);
    else secrets.delete(name);
    this.save(secrets);
    return next ?? undefined;
  }

  /** Drop `name`'s record. Returns true if there was one. Never creates the file. */
  remove(name: string): boolean {
    if (!this.memory && !fs.existsSync(this.filePath!)) return false;
    const secrets = this.all();
    if (!secrets.delete(name)) return false;
    this.save(secrets);
    return true;
  }
}
