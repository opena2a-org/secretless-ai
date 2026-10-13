import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { PUSH_TARGETS, type PushTargetType } from './secret-push';

/**
 * The README said "Secretless never reads or transmits credential values it
 * manages" and "Values never enter AI context, transcripts, or shell history"
 * (#339). Neither held: `run`, `env` and the shell hook read values to inject
 * them, `clean` and `watch` read them to find them in transcripts, `secret set`
 * compares them, and `secret push` sends them in an HTTPS body to a cloud
 * store. The README's own text names `secret set NAME=VALUE` as putting a value
 * in shell history. What holds is narrower: no value goes to OpenA2A, and a
 * value is read when a command the user runs needs it. These tests keep the
 * absolute wording out and hold the replacement to the CLI it describes. The
 * replacement line moved with "Verifying what was installed" to
 * docs/install.md, and the pages the README's sections moved to are read for
 * the absolute wording as the README is.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const read = (rel: string) => fs.readFileSync(path.join(REPO_ROOT, rel), 'utf-8');
const README = read('README.md');
const INSTALL_DOC_PATH = 'docs/install.md';
const MOVED_TO = [INSTALL_DOC_PATH, 'docs/how-it-works.md', 'docs/managing-secrets.md', 'docs/commands.md'];
const FENCE = /^\s*(```|~~~)/;

/** Lines outside fenced code blocks. */
function proseLines(text: string): string[] {
  const out: string[] = [];
  let inFence = false;
  for (const line of text.split('\n')) {
    if (FENCE.test(line)) { inFence = !inFence; continue; }
    if (!inFence) out.push(line);
  }
  return out;
}

/** Commands `cli.ts` dispatches, read from its `case` labels and pre-switch checks. */
function dispatchedCommands(): Set<string> {
  const cli = fs.readFileSync(path.join(REPO_ROOT, 'src', 'cli.ts'), 'utf-8');
  const commands = new Set<string>();
  for (const m of cli.matchAll(/^\s*case '([a-z][a-z-]*)':/gm)) commands.add(m[1]);
  for (const m of cli.matchAll(/command === '([a-z][a-z-]*)'/g)) commands.add(m[1]);
  return commands;
}

/** The store each `secret push --to` target writes to, as the README names it. */
const PUSH_TARGET_NAMES: Record<PushTargetType, string> = {
  'azure-kv': 'Azure Key Vault',
  vault: 'HashiCorp Vault',
  'gcp-sm': 'GCP Secret Manager',
};

const VALUE_LINE_START = 'Secretless sends no credential value to OpenA2A';

describe('README statements about reading and sending credential values', () => {
  const prose = [README, ...MOVED_TO.map(read)].flatMap(proseLines);
  const installProse = proseLines(read(INSTALL_DOC_PATH));

  it('no line says Secretless never reads or never transmits the values it manages', () => {
    expect(prose.filter((l) => /\bnever (reads|transmits)\b/i.test(l))).toEqual([]);
  });

  it('no line says values never reach shell history while the README names a form that puts one there', () => {
    expect(README).toMatch(/`secret set NAME=VALUE` puts (it|the value) in shell history/);
    expect(prose.filter((l) => /never enter[^.]*shell history/i.test(l))).toEqual([]);
  });

  it('states that no value goes to OpenA2A, and the Telemetry section backs it', () => {
    const line = installProse.find((l) => l.startsWith(VALUE_LINE_START));
    expect(line, `${INSTALL_DOC_PATH} must keep its "${VALUE_LINE_START}" line`).toBeDefined();
    expect(line).toContain('[telemetry](../README.md#telemetry)');
    const at = README.indexOf('\n## Telemetry\n');
    expect(at, 'README.md must keep its "## Telemetry" section').toBeGreaterThan(-1);
    const telemetry = README.slice(at);
    expect(telemetry).toMatch(/No content is collected\.[^\n]*no env-var values/);
  });

  it('names only commands the CLI dispatches, and every store `secret push` writes to', () => {
    const line = installProse.find((l) => l.startsWith(VALUE_LINE_START))!;
    const commands = dispatchedCommands();
    const named = [...line.matchAll(/`(?:secretless-ai )?([a-z][a-z-]*)(?: [a-z-]+)?`/g)].map((m) => m[1]);
    expect(named).toContain('secret');
    for (const command of named) {
      expect(commands.has(command), `\`${command}\` is not a command cli.ts dispatches`).toBe(true);
    }
    expect(line).toContain('`secret push`');
    for (const target of PUSH_TARGETS) {
      expect(line, `the line must name the store \`--to ${target}\` writes to`).toContain(PUSH_TARGET_NAMES[target]);
    }
  });
});
