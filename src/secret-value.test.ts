import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { findSecretValueProblem, describeSecretShape, unstorableMcpSecretError } from './secret-value';
import { SecretStore } from './secret-store';
import { LocalBackend } from './backends/local';

const ESC = String.fromCharCode(0x1b);
const NUL = String.fromCharCode(0);

/**
 * #104 §2 — a 40-character hex token pasted at the interactive prompt was
 * stored as 19 bytes of control characters and U+FFFD, with no warning, and
 * surfaced much later as a TypeError inside an unrelated consumer.
 */
describe('findSecretValueProblem', () => {
  it('rejects a bracketed paste that captured its own escape sequences', () => {
    // What the terminal actually sends around a paste: ESC [ 2 0 0 ~ ... ~
    const pasted = `${ESC}[200~sk-live-QQ7ZX9WKPV4${ESC}[201~`;
    const problem = findSecretValueProblem(pasted);
    expect(problem?.kind).toBe('control-char');
    expect(problem?.at).toBe(1);
  });

  it('rejects U+FFFD, because the original bytes are already gone', () => {
    expect(findSecretValueProblem('sk-live-�-tail')?.kind).toBe('replacement-char');
  });

  it('rejects a null byte', () => {
    expect(findSecretValueProblem('sk-live' + NUL)?.kind).toBe('null-byte');
  });

  it('rejects DEL', () => {
    expect(findSecretValueProblem('sk-live' + String.fromCharCode(0x7f))?.kind)
      .toBe('control-char');
  });

  it('rejects C1 control characters, including the 8-bit CSI (#230)', () => {
    // U+009B is ESC [ in one character: refusing ESC and accepting it would
    // store the same terminal sequence in its other encoding.
    const csi = findSecretValueProblem('abc' + String.fromCharCode(0x9b) + '[2J');
    expect(csi).toEqual({ kind: 'control-char', found: 'a C1 control character (U+009B)', at: 4 });
    for (const code of [0x80, 0x85, 0x9f]) {
      expect(findSecretValueProblem('abc' + String.fromCharCode(code))?.kind, code.toString(16))
        .toBe('control-char');
    }
  });

  it('CONTROL: accepts the first character after C1 and non-ASCII letters', () => {
    // U+00A0 and above are printable, and a password may hold them.
    expect(findSecretValueProblem('abc' + String.fromCharCode(0xa0))).toBeNull();
    expect(findSecretValueProblem('pässwörd-ñ-日本')).toBeNull();
  });

  it('accepts the credentials people actually store', () => {
    // The other direction, and the one that decides whether this rule is
    // usable: rejecting too widely would block real secrets.
    const real = [
      'sk-ant-api03-QQ7ZX9WKPV4RJT2MHB6NDY8FGC3L',
      'd41d8cd98f00b204e9800998ecf8427e',
      'ghp_QQ7ZX9WKPV4RJT2MHB6NDY8FGC3Lab',
      'postgres://user:p%40ss@host:5432/db?sslmode=require',
      'eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.QQ7ZX9WKPV4RJT2MHB6NDY8FGC3L',
      'p@ssw0rd! #$%^&*()_+-=[]{}|;:\'",.<>/?`~',
    ];
    for (const value of real) {
      expect(findSecretValueProblem(value), value).toBeNull();
    }
  });

  it('accepts a multi-line PEM key', () => {
    // Newline, carriage return and tab are the reason the allowed set is not
    // empty — a PEM piped in whole is a legitimate stored secret.
    const pem = '-----BEGIN PRIVATE KEY-----\r\n\tMIIEvQIBADANBg\n-----END PRIVATE KEY-----';
    expect(findSecretValueProblem(pem)).toBeNull();
  });
});

describe('describeSecretShape', () => {
  it('reports length and class, and no content', () => {
    // The #104 token was 40 hex characters and was stored as 19. "19 chars"
    // next to a token the user knows is 40 is the whole point.
    expect(describeSecretShape('d41d8cd98f00b204e9800998ecf8427e')).toBe('32 chars, hex');
    expect(describeSecretShape('sk-ant-QQ7ZX9')).toBe('13 chars, printable ASCII');
    expect(describeSecretShape('QQ7ZX9WK')).toBe('8 chars, alphanumeric');
    expect(describeSecretShape('a\nb')).toBe('3 chars, multi-line');
  });

  it('never includes the value itself', () => {
    const value = 'sk-live-QQ7ZX9WKPV4RJT2MHB6NDY8FGC3L';
    const shape = describeSecretShape(value);
    for (let i = 0; i + 4 <= value.length; i++) {
      expect(shape).not.toContain(value.slice(i, i + 4));
    }
  });
});

describe('SecretStore.setSecret rejects an unstorable value (#104)', () => {
  let dir: string;
  let store: SecretStore;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-setval-'));
    store = new SecretStore({ backend: new LocalBackend({ storeDir: dir, key: 'k' }) });
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('refuses, names the character and position, and shows no value', async () => {
    const mangled = `${ESC}[200~sk-live-QQ7ZX9WKPV4~`;
    const err = await store.setSecret('API_KEY', mangled).then(() => null, (e: Error) => e);

    expect(err).not.toBeNull();
    expect(err!.message).toMatch(/API_KEY.*was not stored/);
    expect(err!.message).toContain('escape character (0x1B)');
    expect(err!.message).toContain('secretless-ai secret set API_KEY');
    for (let i = 0; i + 4 <= mangled.length; i++) {
      expect(err!.message).not.toContain(mangled.slice(i, i + 4));
    }
  });

  it('refuses an 8-bit CSI and stores nothing (#230)', async () => {
    const mangled = 'sk-live-QQ7ZX9' + String.fromCharCode(0x9b) + '[2J';
    const err = await store.setSecret('API_KEY', mangled).then(() => null, (e: Error) => e);

    expect(err!.message).toMatch(/API_KEY.*was not stored/);
    expect(err!.message).toContain('C1 control character (U+009B) at character 15');
    expect(await store.listSecrets()).toEqual([]);
  });

  it('stores nothing when it refuses', async () => {
    await store.setSecret('API_KEY', ESC + 'x').catch(() => undefined);
    expect(await store.listSecrets()).toEqual([]);
  });

  it('CONTROL: an ordinary value is still stored', async () => {
    await store.setSecret('API_KEY', 'sk-live-QQ7ZX9WKPV4RJT2MHB6NDY8FGC3L');
    expect(await store.listSecrets()).toEqual(['API_KEY']);
  });
});

describe('unstorableMcpSecretError escapes the env key it names (#229)', () => {
  const RAW_CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/;

  it('writes C0, DEL and C1 controls in the key as escapes on every line', () => {
    for (const key of [`X${ESC}[2J_TOKEN`, 'X\u007f_TOKEN', 'X\u009b2J_TOKEN']) {
      const message = unstorableMcpSecretError('claude-code', 'demo', key, findSecretValueProblem(ESC)!).message;
      expect(message).not.toMatch(RAW_CONTROL);
    }
    const message = unstorableMcpSecretError('claude-code', 'demo', 'X\u009b2J_TOKEN', findSecretValueProblem(ESC)!).message;
    expect(message).toContain('"X\\u009b2J_TOKEN" for MCP server claude-code/demo was not stored');
    expect(message).toContain('  Fix:     correct "X\\u009b2J_TOKEN" in the "demo" env block of that file,');
  });

  it('CONTROL: an ordinary key is quoted in the first line and listed as it is in the Fix line', () => {
    const message = unstorableMcpSecretError('cursor', 'github', 'GITHUB_TOKEN', findSecretValueProblem(ESC)!).message;
    expect(message).toContain('"GITHUB_TOKEN" for MCP server cursor/github was not stored');
    expect(message).toContain('  Fix:     correct GITHUB_TOKEN in the "github" env block of that file,');
  });
});
