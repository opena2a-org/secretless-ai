/**
 * `watch` logged `secret set NAME` for a stored secret it marked exposed, also
 * for a name `secret set` refuses (#499). The store takes a name that starts
 * with a digit, '_' or '-', and `secret set` refuses each of those, so the
 * logged command stored nothing.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { processFile } from './watch';
import { runSecret } from './commands/secrets';
import { SecretStore, isSettableSecretName, isValidSecretName } from './secret-store';
import { LocalBackend } from './backends/local';

// Plainly fake. The transcript redacts it as the value of a secret-named
// variable, and watch compares each redacted value with the stored ones.
const VALUE = 'FAKE-demo-token-1234';
const REFUSED = ['_DEMO_TOKEN', '1DEMO_TOKEN', '-DEMO_TOKEN'];

let dir: string;
let err: string[];

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-499-'));
  err = [];
  // The watch log is written to stderr as well as to its file.
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
});
afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
});

function store(): SecretStore {
  const backend = new LocalBackend({ storeDir: path.join(dir, 'store'), key: 'test-key' });
  return new SecretStore({ backend, annotationsPath: path.join(dir, 'secret-annotations.json') });
}

/**
 * Stores VALUE under `name` through the store, which takes the name, has watch
 * process a transcript that holds it, and returns the log line about that
 * secret.
 */
async function exposedLine(name: string): Promise<string> {
  await store().setSecret(name, VALUE);
  const file = path.join(dir, 'projects', 'p1', 'session.jsonl');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const text = `DEMO_TOKEN=${VALUE}`;
  fs.writeFileSync(file, JSON.stringify({ uuid: 'u1', message: { content: [{ type: 'text', text }] } }) + '\n');
  const logPath = path.join(dir, 'watch.log');
  await processFile(file, logPath, store);
  const log = fs.readFileSync(logPath, 'utf-8');
  expect(log).not.toContain(VALUE);
  const lines = log.split('\n')
    .filter((line) => line.includes(`Stored secret ${name} `))
    .map((line) => line.replace(/^\[[^\]]+\] /, ''));
  expect(lines).toHaveLength(1);
  return lines[0];
}

describe('watch names no `secret set` command for a stored name `secret set` refuses (#499)', () => {
  it.each(REFUSED)('%s is a name the store takes and `secret set` refuses without opening the store', async (name) => {
    expect(isValidSecretName(name)).toBe(true);
    expect(isSettableSecretName(name)).toBe(false);
    const createStore = vi.fn(store);
    expect(await runSecret(['set', name], { createStore, afterSet: () => {} })).toBe(1);
    expect(err.join('\n')).toContain('Must start with a letter.');
    expect(createStore).not.toHaveBeenCalled();
  });

  it.each(REFUSED)('the line for %s gives the reason in place of the command, and the exposure is recorded', async (name) => {
    const line = await exposedLine(name);
    expect(line).toBe(
      `Stored secret ${name} marked exposed. Rotate it at its provider, `
      + 'then store the new value the way this one was first stored. '
      + `"${name}" cannot be stored by \`secret set\`, which takes a letter, then letters, digits, '_' or '-'.`,
    );
    expect(line).not.toContain(`secret set ${name}`);
    expect(store().getAnnotation(name)?.meta.exposedWhere).toMatch(/\(found by watch\)$/);
  });

  it('a name `secret set` takes still gets the command', async () => {
    expect(await exposedLine('DEMO_TOKEN')).toBe(
      'Stored secret DEMO_TOKEN marked exposed. Rotate it at its provider, then: secretless-ai secret set DEMO_TOKEN',
    );
    expect(store().getAnnotation('DEMO_TOKEN')?.meta.exposedWhere).toMatch(/\(found by watch\)$/);
  });
});
