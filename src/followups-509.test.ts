/**
 * `clean` named `secret set NAME` as the next step for each stored secret whose
 * value it redacted, also for a name `secret set` refuses (#509). The store
 * takes a name that starts with a digit, '_' or '-', and `secret set` refuses
 * each of those.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runClean } from './commands/transcript';
import { SecretStore, isSettableSecretName, isValidSecretName } from './secret-store';
import { LocalBackend } from './backends/local';

// Plainly fake. A transcript line `DEMO_TOKEN=<value>` is redacted as the value
// of a secret-named variable, and clean compares each redacted value with the
// stored ones.
const TAKEN_VALUE = 'FAKE-demo-token-5678';
const REFUSED_VALUE = 'FAKE-demo-token-1234';
const REFUSED = ['_DEMO_TOKEN', '1DEMO_TOKEN', '-DEMO_TOKEN'];

const WARNING = '  A redacted value still works until it is replaced at its provider.';
const STEP = '  Next:     rotate each one at its provider, then store its new value';
const OPEN = '  Open:     secretless-ai secret list --needs-rotation';
const DRY_OPEN = `${OPEN}   (run without --dry-run to record)`;

/** The line that stands where `secret set` would be offered for `name`. */
function reasonLine(name: string): string {
  return `            "${name}" cannot be stored by \`secret set\`, which takes a letter, then letters, digits, '_' or '-'; `
    + 'store its new value the way it was first stored.';
}

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-509-'));
});
afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
});

function store(): SecretStore {
  const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
  return new SecretStore({ backend, annotationsPath: path.join(dir, 'secret-annotations.json') });
}

/** A transcript with one line per value, each holding it as `DEMO_TOKEN=<value>`. */
function transcript(name: string, values: string[]): void {
  const file = path.join(dir, 'projects', 'p1', name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const lines = values.map((value, i) => JSON.stringify({
    uuid: `u${i + 1}`,
    message: { content: [{ type: 'text', text: `DEMO_TOKEN=${value}` }] },
  }));
  fs.writeFileSync(file, lines.join('\n') + '\n');
}

/** Runs clean over the transcripts; its exit code and the lines it printed. */
async function clean(args: string[], createStore: () => SecretStore = store): Promise<{ code: number; lines: string[] }> {
  const out: string[] = [];
  const log = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  let code: number;
  try {
    code = await runClean([...args, '--path', path.join(dir, 'projects')], { createStore });
  } finally {
    log.mockRestore();
    error.mockRestore();
  }
  const text = out.join('\n');
  expect(text).not.toContain(TAKEN_VALUE);
  expect(text).not.toContain(REFUSED_VALUE);
  return { code, lines: text.split('\n') };
}

/** The lines from the one under the list of stored secrets to `Open:`. */
function nextSteps(lines: string[]): string[] {
  const from = lines.indexOf(WARNING);
  expect(from).toBeGreaterThan(-1);
  const to = lines.findIndex((line, i) => i > from && line.startsWith('  Open:'));
  expect(to).toBeGreaterThan(from);
  return lines.slice(from, to + 1);
}

describe('clean names no `secret set` command for a stored name `secret set` refuses (#509)', () => {
  it('one name `secret set` takes and one it refuses: the command for the first, the reason in place of it for the second', async () => {
    await store().setSecret('DEMO_TOKEN', TAKEN_VALUE);
    await store().setSecret('_DEMO_TOKEN', REFUSED_VALUE);
    transcript('session.jsonl', [REFUSED_VALUE, TAKEN_VALUE]);

    const { code, lines } = await clean(['--dry-run']);
    expect(code).toBe(0);
    expect(lines).toContain('  Stored secrets among the redacted values: 2');
    expect(lines.filter((line) => / {4}_?DEMO_TOKEN {2}would be marked exposed \(transcript /.test(line))).toHaveLength(2);
    expect(nextSteps(lines)).toEqual([
      WARNING,
      STEP,
      '            secretless-ai secret set DEMO_TOKEN',
      reasonLine('_DEMO_TOKEN'),
      DRY_OPEN,
    ]);
    expect(lines.join('\n')).not.toContain('secret set _DEMO_TOKEN');
    expect(lines.join('\n')).not.toContain('secret set NAME');
  });

  it.each(REFUSED)('%s alone gets the reason and no `secret set` command, and its exposure is recorded', async (name) => {
    expect(isValidSecretName(name)).toBe(true);
    expect(isSettableSecretName(name)).toBe(false);
    await store().setSecret(name, REFUSED_VALUE);
    transcript('session.jsonl', [REFUSED_VALUE]);

    const { code, lines } = await clean([]);
    expect(code).toBe(0);
    expect(lines.filter((line) => line.startsWith(`    ${name}  marked exposed (transcript `))).toHaveLength(1);
    expect(nextSteps(lines)).toEqual([WARNING, STEP, reasonLine(name), OPEN]);
    expect(lines.join('\n')).not.toContain('secretless-ai secret set');
    expect(store().getAnnotation(name)?.meta.exposedWhere).toMatch(/\(found by clean\)$/);
  });

  it('a name already marked exposed gets the same step as one marked by this run', async () => {
    await store().setSecret('DEMO_TOKEN', TAKEN_VALUE);
    await store().setSecret('_DEMO_TOKEN', REFUSED_VALUE);
    await store().recordExposure('DEMO_TOKEN', 'pasted into a chat', new Date('2026-10-01T00:00:00Z'));
    await store().recordExposure('_DEMO_TOKEN', 'pasted into a chat', new Date('2026-10-01T00:00:00Z'));
    transcript('session.jsonl', [REFUSED_VALUE, TAKEN_VALUE]);

    const { lines } = await clean(['--dry-run']);
    expect(lines.filter((line) => / {4}_?DEMO_TOKEN {2}already marked exposed since /.test(line))).toHaveLength(2);
    expect(nextSteps(lines)).toEqual([
      WARNING,
      STEP,
      '            secretless-ai secret set DEMO_TOKEN',
      reasonLine('_DEMO_TOKEN'),
      DRY_OPEN,
    ]);
  });

  it('a name whose exposure could not be recorded gets the same step as one that was', async () => {
    await store().setSecret('DEMO_TOKEN', TAKEN_VALUE);
    await store().setSecret('_DEMO_TOKEN', REFUSED_VALUE);
    transcript('session.jsonl', [REFUSED_VALUE, TAKEN_VALUE]);
    const failing = store();
    vi.spyOn(failing, 'recordExposure').mockRejectedValue(new Error('metadata file not writable'));

    const { lines } = await clean([], () => failing);
    expect(lines).toContain('    DEMO_TOKEN  NOT marked exposed: metadata file not writable');
    expect(lines).toContain('    _DEMO_TOKEN  NOT marked exposed: metadata file not writable');
    expect(nextSteps(lines)).toEqual([
      WARNING,
      STEP,
      '            secretless-ai secret set DEMO_TOKEN',
      reasonLine('_DEMO_TOKEN'),
      OPEN,
    ]);
  });

  it('names `secret set` takes keep the one Next line with `secret set NAME`', async () => {
    await store().setSecret('DEMO_TOKEN', TAKEN_VALUE);
    transcript('session.jsonl', [TAKEN_VALUE]);

    const { lines } = await clean(['--dry-run']);
    expect(nextSteps(lines)).toEqual([
      WARNING,
      '  Next:     rotate each one at its provider, then  secretless-ai secret set NAME',
      DRY_OPEN,
    ]);
  });
});
