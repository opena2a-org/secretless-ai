import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CREDENTIAL_PATTERNS } from '../patterns';
import { githubToken, leaksRun, literalValue, seeded } from '../mcp-env-secret.test-support';
import {
  MCP_ENV_SECRET_ID,
  MCP_ENV_SECRET_NAME,
  envFindingPreview,
  envFindingsOnLine,
  envFixOf,
  envSecretKind,
  envValueKind,
  homeMcpConfigPaths,
  isProjectMcpConfig,
  maskEnvSecrets,
  mcpEnvFix,
  mcpEnvSecrets,
  mcpEnvSecretsByLine,
  readMcpEnv,
  vendorMatchOf,
} from './env-secrets';

/**
 * The one decision every command applies to a project MCP config's env, and
 * the one pass that finds where each value is written. Every value a test
 * expects reported is built at runtime: forty characters, no placeholder word
 * and more than six distinct characters, so no value rule hides it.
 */

const KEY = 'SVC_API_KEY';
/** `{"mcpServers": {<name>: {"env": <env>}}}` as one line, the env written as given. */
const oneLine = (servers: Record<string, string>): string =>
  `{"mcpServers":{${Object.entries(servers).map(([name, env]) => `"${name}":{"command":"npx","env":{${env}}}`).join(',')}}}`;
const entry = (key: string, value: string): string => `"${key}":"${value}"`;

const dirs: string[] = [];
function tempDir(): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-env-secrets-')));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('envValueKind: what a value under a secret name is', () => {
  it('an empty value is empty', () => {
    expect(envValueKind('')).toBe('empty');
  });

  it.each([
    ['${NAME}', ['${', 'SVC_API_KEY', '}']],
    ['${NAME:-default}', ['${', 'SVC_API_KEY', ':-', 'fallback', '}']],
    ['${env:NAME}', ['${', 'env:', 'SVC_API_KEY', '}']],
    ['${input:ID}', ['${', 'input:', 'svc-api-key', '}']],
  ])('a whole-value expansion %s is an expansion', (_form, parts) => {
    expect(envValueKind(parts.join(''))).toBe('expansion');
  });

  it('an expansion with other text around it is a literal: only the whole value is an expansion', () => {
    expect(envValueKind(['${', 'SVC_API_KEY', '}', seeded(711, 8)].join(''))).toBe('literal');
    expect(envValueKind([seeded(712, 8), '${', 'SVC_API_KEY', '}'].join(''))).toBe('literal');
  });

  it('a bare $NAME is a literal: no client expansion of it is relied on', () => {
    expect(envValueKind(['$', 'SVC_API_KEY'].join(''))).toBe('literal');
    expect(envValueKind(`$${seeded(713, 39)}`)).toBe('literal');
  });

  it('a value the value rules call a placeholder is a placeholder', () => {
    expect(envValueKind(['your', '_service_', 'key'].join(''))).toBe('placeholder');
    expect(envValueKind('ab'.repeat(12))).toBe('placeholder');
  });

  it('a random value is a literal', () => {
    expect(envValueKind(literalValue(714))).toBe('literal');
  });
});

describe('envSecretKind: the decision for one env entry', () => {
  it('a literal or a placeholder under a secret name is that kind', () => {
    expect(envSecretKind(KEY, literalValue(721))).toBe('literal');
    expect(envSecretKind(KEY, ['your', '_service_', 'key'].join(''))).toBe('placeholder');
  });

  it('an empty value or an expansion under a secret name is no secret', () => {
    expect(envSecretKind(KEY, '')).toBeUndefined();
    expect(envSecretKind(KEY, ['${', KEY, '}'].join(''))).toBeUndefined();
  });

  it('a random value under a name that is not a secret name is no secret', () => {
    expect(envSecretKind('LOG_LEVEL', literalValue(722))).toBeUndefined();
  });
});

describe('readMcpEnv: one forward pass over the text', () => {
  it('reads every occurrence of a key written twice, in text order, an empty last value included', () => {
    const [first, second] = [literalValue(731), literalValue(732)];
    const text = oneLine({ a: [entry(KEY, first), entry(KEY, second), entry(KEY, '')].join(',') });
    expect(readMcpEnv(text).map((v) => v.value)).toEqual([first, second, '']);
    expect(mcpEnvSecrets(text).map((s) => s.value)).toEqual([first, second]);
  });

  it('decodes an escaped key and records the value token as written', () => {
    const value = literalValue(733);
    const text = oneLine({ svc: entry('\\u0053VC_API_KEY', value) });
    const [secret] = mcpEnvSecrets(text);
    expect(secret).toMatchObject({ server: 'svc', key: KEY, value, kind: 'literal', line: 1 });
    expect(text.slice(secret.from, secret.to)).toBe(`"${value}"`);
  });

  it('decodes an escaped value and records its token as written, escapes included', () => {
    const [head, tail] = [seeded(734, 20), seeded(735, 19)];
    const raw = `${head}\\/${tail}`;
    const text = oneLine({ svc: entry(KEY, raw) });
    const [secret] = mcpEnvSecrets(text);
    expect(secret.value).toBe(`${head}/${tail}`);
    expect(text.slice(secret.from, secret.to)).toBe(`"${raw}"`);
  });

  it('numbers lines as text.split("\\n") does, with CRLF line ends too', () => {
    const value = literalValue(736);
    const config = { mcpServers: { svc: { command: 'npx', env: { LOG_LEVEL: 'info', [KEY]: value } } } };
    for (const text of [JSON.stringify(config, null, 2), JSON.stringify(config, null, 2).replace(/\n/g, '\r\n')]) {
      const lines = text.split('\n');
      const [secret] = mcpEnvSecrets(text);
      expect(lines[secret.line - 1].slice(secret.from, secret.to)).toBe(`"${value}"`);
      expect(mcpEnvSecretsByLine(text).get(secret.line)?.map((s) => s.value)).toEqual([value]);
    }
  });

  it('reads the servers map a client names `servers`', () => {
    const value = literalValue(737);
    const text = JSON.stringify({ servers: { svc: { command: 'npx', env: { [KEY]: value } } } });
    expect(mcpEnvSecrets(text).map((s) => s.value)).toEqual([value]);
  });

  it('reads the server maps under `projects` only when asked to', () => {
    const value = literalValue(738);
    const text = JSON.stringify({ projects: { '/work/p': { mcpServers: { svc: { command: 'npx', env: { [KEY]: value } } } } } });
    expect(readMcpEnv(text)).toEqual([]);
    expect(readMcpEnv(text, { projectMaps: true }).map((v) => ({ projectKey: v.projectKey, value: v.value }))).toEqual([
      { projectKey: '/work/p', value },
    ]);
  });

  it('reads nothing from text that is not one JSON object', () => {
    const json = JSON.stringify({ mcpServers: { svc: { command: 'npx', env: { [KEY]: literalValue(739) } } } });
    expect(readMcpEnv(`// a comment\n${json}`)).toEqual([]);
    expect(readMcpEnv(json.replace(/}}}}$/, '},}}}'))).toEqual([]);
    expect(readMcpEnv(json.slice(0, -2))).toEqual([]);
  });

  it('reads no value outside a server env', () => {
    const value = literalValue(740);
    const text = JSON.stringify({ mcpServers: { svc: { command: 'npx', args: [value], headers: { [KEY]: value } } }, env: { [KEY]: value } });
    expect(readMcpEnv(text)).toEqual([]);
  });
});

describe('previews: no character of an env value', () => {
  it('a finding made for an env value previews the key and a marker, built from the key', () => {
    expect(envFindingPreview(KEY, MCP_ENV_SECRET_NAME)).toBe(`"${KEY}": "[${MCP_ENV_SECRET_NAME} REDACTED]"`);
    const long = `SVC_${'A'.repeat(60)}_API_KEY`;
    expect(envFindingPreview(long, MCP_ENV_SECRET_NAME)).toBe(`"${long.slice(0, 48)}...": "[${MCP_ENV_SECRET_NAME} REDACTED]"`);
  });

  it('masks each secret token on a line as written, and leaves a value that is not a secret as it is', () => {
    const [secret, other] = [literalValue(751), literalValue(752)];
    const text = oneLine({ svc: [entry('\\u0053VC_API_KEY', secret), entry('LOG_LEVEL', other)].join(',') });
    const masked = maskEnvSecrets(text, mcpEnvSecrets(text));
    expect(leaksRun(masked, [secret])).toBe(false);
    expect(masked).toContain(`"[${MCP_ENV_SECRET_NAME} REDACTED]"`);
    expect(masked).toContain(other);
  });

  it('masks every occurrence of a duplicate key and a value written with escapes, two servers on one line', () => {
    const [head, tail, second, third] = [seeded(753, 20), seeded(754, 19), literalValue(755), literalValue(756)];
    const raw = `${head}\\/${tail}`;
    const text = oneLine({ a: [entry(KEY, raw), entry(KEY, second)].join(','), b: entry(KEY, third) });
    const secrets = mcpEnvSecrets(text);
    expect(secrets).toHaveLength(3);
    const masked = maskEnvSecrets(text, secrets);
    expect(leaksRun(masked, [`${head}/${tail}`, raw, second, third])).toBe(false);
  });

  it('a vendor-shaped value is masked under its pattern name', () => {
    const token = githubToken(757);
    const name = CREDENTIAL_PATTERNS.find((p) => p.id === 'github-pat')!.name;
    const text = oneLine({ svc: entry('GITHUB_TOKEN', token) });
    const masked = maskEnvSecrets(text, mcpEnvSecrets(text));
    expect(masked).toContain(`"[${name} REDACTED]"`);
    expect(leaksRun(masked, [token])).toBe(false);
  });
});

describe('envFindingsOnLine: one finding per name and line', () => {
  it('reports a literal as MCP Server Env Secret and a vendor-shaped value once, under its pattern name', () => {
    const [value, token] = [literalValue(761), githubToken(762)];
    const text = oneLine({ svc: [entry(KEY, value), entry('GITHUB_TOKEN', token)].join(',') });
    const found = envFindingsOnLine(mcpEnvSecrets(text), undefined);
    expect(found.map((f) => [f.secret.value === value, f.vendor?.pattern.id ?? MCP_ENV_SECRET_ID])).toEqual([
      [true, MCP_ENV_SECRET_ID],
      [false, 'github-pat'],
    ]);
    expect(vendorMatchOf(token)?.pattern.id).toBe('github-pat');
    expect(vendorMatchOf(value)).toBeUndefined();
  });

  it('a placeholder is counted as hidden, and reported with showPlaceholders', () => {
    const text = oneLine({ svc: entry(KEY, ['your', '_service_', 'key'].join('')) });
    let hidden = 0;
    expect(envFindingsOnLine(mcpEnvSecrets(text), undefined, { onSuppressed: () => hidden++ })).toEqual([]);
    expect(hidden).toBe(1);
    expect(envFindingsOnLine(mcpEnvSecrets(text), undefined, { showPlaceholders: true }).map((f) => f.secret.kind)).toEqual(['placeholder']);
  });

  it('a secret whose token the pattern finding on the line covers is that finding', () => {
    const text = oneLine({ svc: entry('GITHUB_TOKEN', githubToken(763)) });
    const [secret] = mcpEnvSecrets(text);
    expect(envFindingsOnLine([secret], { from: secret.from + 1, to: secret.to - 1 })).toEqual([]);
  });
});

describe('which configs the env rule reads, and the fix it gives', () => {
  it('reads a project-level config at any depth, and no per-user config in the home directory', () => {
    const [home, project] = [tempDir(), tempDir()];
    const homeConfigs = homeMcpConfigPaths(home);
    for (const rel of ['.mcp.json', 'mcp.json', path.join('.cursor', 'mcp.json'), path.join('sub', 'deep', '.mcp.json')]) {
      expect(isProjectMcpConfig(path.join(project, rel), homeConfigs), rel).toBe(true);
    }
    for (const rel of [path.join('.cursor', 'mcp.json'), path.join('.vscode', 'mcp.json'), path.join('.windsurf', 'mcp.json'), '.claude.json']) {
      expect(isProjectMcpConfig(path.join(home, rel), homeConfigs), rel).toBe(false);
    }
    expect(isProjectMcpConfig(path.join(project, 'settings.json'), homeConfigs)).toBe(false);
  });

  it('names protect-mcp for a .mcp.json and the move-and-rotate step otherwise, with the directory to run in', () => {
    const project = tempDir();
    expect(mcpEnvFix(path.join(project, '.mcp.json'), project)).toBe('Run npx secretless-ai protect-mcp to encrypt exposed secrets.');
    expect(mcpEnvFix(path.join(project, '.cursor', 'mcp.json'), project)).toBe(
      'Move each value out of its file and rotate it, then run npx secretless-ai mcp-status again.',
    );
    fs.mkdirSync(path.join(project, 'sub'));
    expect(mcpEnvFix(path.join(project, 'sub', '.mcp.json'), project)).toBe('Run npx secretless-ai protect-mcp in sub to encrypt exposed secrets.');
  });

  it('envFixOf gives the config fix mcpEnvFix gives, on every call', () => {
    const project = tempDir();
    const config = path.join(project, '.mcp.json');
    const fix = envFixOf(config);
    expect(fix()).toBe(mcpEnvFix(config));
    expect(fix()).toBe(mcpEnvFix(config));
  });
});
