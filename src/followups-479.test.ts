import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as ts from 'typescript';
import { AzureKeyVaultTarget } from './backends/azure-kv';
import type { AzureDeps } from './backends/azure-kv';
import { LocalBackend } from './backends/local';
import { runSecretPush } from './commands/secrets';
import { SecretStore } from './secret-store';

/**
 * #479: when `secret push --to azure-kv` failed, two of its `Fix:` blocks
 * printed a remark in parentheses after the command, on the line of the
 * command: `az keyvault list --query "[].name" -o tsv   (find the vault name)`
 * for a vault name that does not resolve, and `(then push again)` and
 * `(removes the deleted versions for good)` after the `recover` and `purge`
 * commands for a deleted secret that Key Vault keeps for recovery (HTTP 409).
 * Pasted, bash refuses each such line with
 * ``syntax error near unexpected token `('``. Each remark is now a line of its
 * own, above or under its command, as #475 did for `secret sync`,
 * `scope check` and `init`.
 *
 * Those lines are the `verify` and `fix` arrays of a `PushError`, which
 * `labelled()` in src/commands/secrets.ts prints under its label. The checks
 * of the source in src/followups-471.test.ts and src/followups-476.test.ts
 * read a line that prints a `Fix:` or `Verify:` label, or a string that starts
 * ten or more spaces in, so neither saw them. The last block here reads the
 * `verify` and `fix` lines of each `PushError` in the source.
 *
 * The store is a `LocalBackend` with an explicit key in a temporary directory,
 * so no test reaches the OS keychain. Key Vault is a stand-in for `fetch`, and
 * the Azure CLI a stand-in for the child process.
 */

const REPO_ROOT = path.resolve(__dirname, '..');

// A remark after the command, as src/followups-471.test.ts defines it for a
// line that prints its label: a `#` with whitespace on each side, or a `#` or
// `(` set off from the command by two or more spaces, written plainly or as
// the start of a style call such as `${c.dim('# ...')}`. A `(` one space after
// a word is prose, as in `the directory (tenant) ID`.
const REMARK_AFTER_COMMAND = /\s#\s|\S\s{2,}(\$\{c\.\w+\(['"`])?[#(]/;

/** What `bash -n` (read, do not run) prints for `line`, or '' when bash reads it without error. */
function bashSyntaxError(line: string): string {
  const r = spawnSync('bash', ['-n', '-c', line], { encoding: 'utf-8' });
  expect(r.error, 'bash did not start').toBeUndefined();
  return r.status === 0 ? '' : r.stderr.trim();
}

describe('secret push --to azure-kv: each Fix line ends at its command (#479)', () => {
  let tmp: string;
  let store: SecretStore;
  let out: string[];

  beforeEach(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-479-'));
    store = new SecretStore({ backend: new LocalBackend({ storeDir: path.join(tmp, 'store'), key: 'test-key' }) });
    await store.setSecret('API_KEY', 'FAKE-push-value-479');
    out = [];
    const capture = (...a: unknown[]): void => { out.push(a.map(String).join(' ')); };
    vi.spyOn(console, 'log').mockImplementation(capture);
    vi.spyOn(console, 'error').mockImplementation(capture);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  /** The Azure CLI, signed in: `az account get-access-token` prints a token. */
  const azSignedIn: AzureDeps['runChild'] = async () => ({
    status: 0,
    signal: null,
    stdout: JSON.stringify({ accessToken: 'FAKE-az-cli-token-479', expiresOn: '2026-10-20 12:00:00' }),
    stderr: '',
    timedOut: false,
    spawnError: null,
  });

  /** `secret push API_KEY --to azure-kv --vault <vault> --as API-KEY`, with `answer` for each request to the vault. */
  async function pushTo(vault: string, answer: () => Response): Promise<string[]> {
    vi.stubGlobal('fetch', async (url: string) => {
      // No managed identity: the VM metadata address does not answer.
      if (url.startsWith('http://169.254.169.254/')) throw new TypeError('fetch failed');
      return answer();
    });
    const code = await runSecretPush(['API_KEY', '--to', 'azure-kv', '--vault', vault, '--as', 'API-KEY'], {
      store,
      createTarget: (_type, name) => new AzureKeyVaultTarget(name ?? '', { env: {}, runChild: azSignedIn }),
    });
    expect(code).toBe(1);
    return out.join('\n').split('\n');
  }

  /** The lines from the `Verify:` label to the blank line that ends the block. */
  function verifyAndFix(lines: string[]): string[] {
    const start = lines.findIndex((l) => l.startsWith('  Verify:'));
    expect(start, lines.join('\n')).toBeGreaterThan(-1);
    const end = lines.indexOf('', start);
    return lines.slice(start, end === -1 ? undefined : end);
  }

  /** The `az` commands of a block, from the `az` on each line to its end, without the label, the indent or the words before it. */
  function commands(block: string[]): string[] {
    return block.flatMap((l) => /(?:^|\s)(az .*)$/.exec(l)?.[1] ?? []);
  }

  it('CONTROL: bash refuses the Fix line printed before, so a line it reads is a measurement', () => {
    expect(bashSyntaxError('az keyvault list --query "[].name" -o tsv   (find the vault name)'))
      .toContain("syntax error near unexpected token `('");
  });

  it('a vault name that does not resolve: what the list is for is the line under it', async () => {
    const block = verifyAndFix(await pushTo('kv-missing', () => {
      throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } });
    }));

    expect(block).toEqual([
      '  Verify:  az keyvault show --name kv-missing --query properties.vaultUri -o tsv',
      '  Fix:     az keyvault list --query "[].name" -o tsv',
      '           find the vault name in its output, then push again with it in --vault',
    ]);
    expect(commands(block)).toHaveLength(2);
    for (const command of commands(block)) expect(bashSyntaxError(command), command).toBe('');
  });

  it('a deleted secret kept for recovery (HTTP 409): no remark follows a command on its line', async () => {
    const block = verifyAndFix(await pushTo('kv-demo', () => new Response(
      JSON.stringify({ error: { code: 'Conflict', message: 'FAKE detail', innererror: { code: 'ObjectIsDeletedButRecoverable' } } }),
      { status: 409, headers: { 'Content-Type': 'application/json' } },
    )));

    // The purge follows `or,` on its line (#481), so an interactive bash given
    // the whole block does not run it: src/followups-481.test.ts.
    expect(block).toEqual([
      '  Verify:  az keyvault secret show-deleted --vault-name kv-demo --name API-KEY --query recoveryId -o tsv',
      '  Fix:     az keyvault secret recover --vault-name kv-demo --name API-KEY',
      '           then push again',
      '           or, to remove the deleted versions for good: az keyvault secret purge --vault-name kv-demo --name API-KEY',
    ]);
    expect(commands(block)).toHaveLength(3);
    for (const command of commands(block)) expect(bashSyntaxError(command), command).toBe('');
  });
});

// --- The Verify and Fix lines of each PushError in the source ----------------

interface PushErrorLines {
  /** The file and line of each call of the `PushError` constructor. */
  calls: string[];
  /** Each line a call passes as `verify` or `fix`, with the file and line of the literal it was read from. */
  lines: Array<{ where: string; text: string }>;
  /** Each expression the reader met and could not read in the ways `readPushErrorLines` names; its line is not checked, so the check fails on it. */
  unread: string[];
}

/**
 * Reads the `verify` and `fix` lines that the calls of the `PushError`
 * constructor pass in the ways named here. Each call of the constructor in
 * `classFile`, `new PushError(...)` and a subclass's `super(...)` alike, is
 * found through the type checker, and its second and third arguments are read
 * as arrays of lines: the elements of an array, a spread into one, and both
 * branches of a conditional. A name is followed to the value it is declared
 * with, to each value `push` or `unshift` adds to it and to each value an `=`
 * assignment gives it; a parameter is followed to the argument passed by each
 * call the type checker resolves to its function, or to its default where a
 * call passes none. A template is read as it is written, with each `${...}`
 * in place. An expression in one of those places that is none of these, such
 * as a call, goes to `unread`. A line given to a `PushError` another way is
 * neither read nor listed in `unread`: for example by an element assignment,
 * through another name for the array, by `splice`, through a function passed
 * by reference, or in a spread of all the arguments.
 */
function readPushErrorLines(program: ts.Program, root: string, classFile: string): PushErrorLines {
  const checker = program.getTypeChecker();
  const sources = program.getSourceFiles().filter((sf) => !sf.isDeclarationFile && sf.fileName.startsWith(root));
  const where = (node: ts.Node): string => {
    const sf = node.getSourceFile();
    return `${path.relative(root, sf.fileName).replace(/\\/g, '/')}:${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1}`;
  };

  const classDecl = program.getSourceFile(classFile)?.statements
    .find((s): s is ts.ClassDeclaration => ts.isClassDeclaration(s) && s.name?.text === 'PushError');
  const ctor = classDecl?.members.find(ts.isConstructorDeclaration);
  expect(ctor, `no PushError constructor in ${classFile}`).toBeDefined();

  const invocations: Array<ts.CallExpression | ts.NewExpression> = [];
  const nodes: ts.Node[] = [];
  for (const sf of sources) {
    const visit = (node: ts.Node): void => {
      nodes.push(node);
      if (ts.isCallExpression(node) || ts.isNewExpression(node)) invocations.push(node);
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  const resolvesTo = (call: ts.CallExpression | ts.NewExpression, decl: ts.Node): boolean =>
    checker.getResolvedSignature(call)?.declaration === decl;
  const symbolOf = (node: ts.Node): ts.Symbol | undefined => {
    const symbol = checker.getSymbolAtLocation(node);
    return symbol !== undefined && symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
  };

  type Line = { where: string; text: string };
  const unread: string[] = [];
  const following = new Set<ts.Node>();
  const cannotRead = (expr: ts.Node): Line[] => {
    unread.push(`${where(expr)}: ${expr.getText()}`);
    return [];
  };
  const inner = (expr: ts.Expression): ts.Expression => {
    let e = expr;
    while (ts.isParenthesizedExpression(e) || ts.isAsExpression(e)) e = e.expression;
    return e;
  };

  /** The values a name can hold, each read with `read`. */
  const followName = (id: ts.Identifier, read: (e: ts.Expression) => Line[], array: boolean): Line[] => {
    const symbol = symbolOf(id);
    const decl = symbol?.valueDeclaration;
    if (symbol === undefined || decl === undefined || following.has(decl)) return cannotRead(id);
    following.add(decl);
    try {
      if (ts.isVariableDeclaration(decl)) {
        const values: Line[] = decl.initializer !== undefined ? read(decl.initializer) : [];
        for (const node of nodes) {
          if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
            && ts.isIdentifier(node.left) && symbolOf(node.left) === symbol) values.push(...read(node.right));
          if (array && ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
            && ['push', 'unshift'].includes(node.expression.name.text) && symbolOf(node.expression.expression) === symbol) {
            for (const arg of node.arguments) values.push(...(ts.isSpreadElement(arg) ? linesOf(arg.expression) : lineOf(arg)));
          }
        }
        return values;
      }
      if (ts.isParameter(decl) && ts.isFunctionLike(decl.parent)) {
        const fn = decl.parent;
        const index = fn.parameters.indexOf(decl);
        return invocations.filter((call) => resolvesTo(call, fn)).flatMap((call) => {
          const arg = call.arguments?.[index];
          if (arg !== undefined) return read(arg);
          return decl.initializer !== undefined ? read(decl.initializer) : [];
        });
      }
      return cannotRead(id);
    } finally {
      following.delete(decl);
    }
  };

  /** The text of an expression that is one line. */
  function lineOf(expr: ts.Expression): Line[] {
    const e = inner(expr);
    if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return [{ where: where(e), text: e.text }];
    if (ts.isTemplateExpression(e)) return [{ where: where(e), text: e.getText().slice(1, -1) }];
    if (ts.isConditionalExpression(e)) return [...lineOf(e.whenTrue), ...lineOf(e.whenFalse)];
    if (ts.isIdentifier(e)) return followName(e, lineOf, false);
    return cannotRead(e);
  }

  /** The lines of an expression that is an array of lines. */
  function linesOf(expr: ts.Expression): Line[] {
    const e = inner(expr);
    if (ts.isArrayLiteralExpression(e)) {
      return e.elements.flatMap((el) => (ts.isSpreadElement(el) ? linesOf(el.expression) : lineOf(el)));
    }
    if (ts.isConditionalExpression(e)) return [...linesOf(e.whenTrue), ...linesOf(e.whenFalse)];
    if (ts.isIdentifier(e)) return followName(e, linesOf, true);
    return cannotRead(e);
  }

  const calls: string[] = [];
  const lines: Line[] = [];
  for (const call of invocations) {
    const constructs = ts.isNewExpression(call) || call.expression.kind === ts.SyntaxKind.SuperKeyword;
    if (!constructs || !resolvesTo(call, ctor!)) continue;
    calls.push(where(call));
    // The arguments after the message: `verify`, then `fix`.
    for (const arg of call.arguments?.slice(1) ?? []) {
      lines.push(...(ts.isSpreadElement(arg) ? cannotRead(arg) : linesOf(arg)));
    }
  }
  return { calls, lines, unread };
}

/** The `verify` and `fix` lines that have a remark after the command, as `file:line: text`. */
function remarks(read: PushErrorLines): string[] {
  return read.lines.filter((l) => REMARK_AFTER_COMMAND.test(l.text)).map((l) => `${l.where}: ${l.text}`);
}

describe('the Verify and Fix lines of each PushError in the source have no `#` or parenthesized remark after the command (#479)', () => {
  it('the reader follows a line to a PushError in each way it reads, and the check finds a remark on each', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sls-479-src-'));
    try {
      fs.writeFileSync(path.join(dir, 'push-error.ts'), [
        'export class PushError extends Error {',
        '  constructor(message: string, readonly verify: readonly string[] = [], readonly fix: readonly string[] = []) {',
        '    super(message);',
        '  }',
        '}',
        '',
      ].join('\n'));
      fs.writeFileSync(path.join(dir, 'target.ts'), [
        "import { PushError } from './push-error';",
        'const c = { dim: (s: string): string => s };',
        'const LIST = \'az keyvault list --query "[].name" -o tsv   (find the vault name)\';',
        'export function missing(vault: string): PushError {',
        '  return new PushError(`no ${vault}`, [`az keyvault show --name ${vault}`], [LIST as string]);',
        '}',
        'export function deleted(vault: string, name: string): PushError {',
        '  const fix = [`az keyvault secret recover --vault-name ${vault} --name ${name}   (then push again)`];',
        '  fix.push(`or: az keyvault secret purge --vault-name ${vault} --name ${name}   (removes the deleted versions for good)`);',
        "  return new PushError('deleted', [], fix);",
        '}',
        "function unreachable(verify = 'printenv IDENTITY_ENDPOINT   (the endpoint)'): PushError {",
        "  return new PushError('no answer', [verify]);",
        '}',
        "export const timedOut = (): PushError => unreachable('curl -sI https://kv-demo.vault.azure.net/ # any answer');",
        'export const noEndpoint = (): PushError => unreachable();',
        'export function throttled(first: boolean): PushError {',
        "  let verify = ['az keyvault show --name kv-demo'];",
        "  if (first) verify = ['az keyvault show --name kv-demo   # the vault'];",
        "  const fix = ['wait a minute and push again'];",
        "  fix.unshift('az monitor metrics list   (the request rate)');",
        "  return new PushError('throttled', [...verify], fix);",
        '}',
        'export class Refused extends PushError {',
        '  constructor(rbac: boolean) {',
        "    super('refused', [], [(rbac ? 'az role assignment list -o table' : `az keyvault show --name kv-demo   ${c.dim('(the vault)')}`)]);",
        '  }',
        '}',
        "export const prose = new PushError('prose', ['set AZURE_TENANT_ID to the directory (tenant) ID'], ['see https://github.com/opena2a-org/secretless-ai#readme']);",
        'export const mapped = (names: string[]): PushError => new PushError(\'mapped\', [], names.map((n) => `secret set ${n}`));',
        '',
      ].join('\n'));
      const program = ts.createProgram([path.join(dir, 'target.ts')], {
        target: ts.ScriptTarget.ES2020,
        module: ts.ModuleKind.CommonJS,
        strict: true,
        noEmit: true,
        types: [],
      });

      const read = readPushErrorLines(program, dir, path.join(dir, 'push-error.ts'));

      expect(read.calls).toEqual(['target.ts:5', 'target.ts:10', 'target.ts:13', 'target.ts:22', 'target.ts:26', 'target.ts:29', 'target.ts:30']);
      expect(remarks(read)).toEqual([
        // A constant, named in the array.
        'target.ts:3: az keyvault list --query "[].name" -o tsv   (find the vault name)',
        // The value a name is declared with, and a value `push` adds to it.
        'target.ts:8: az keyvault secret recover --vault-name ${vault} --name ${name}   (then push again)',
        'target.ts:9: or: az keyvault secret purge --vault-name ${vault} --name ${name}   (removes the deleted versions for good)',
        // A parameter: the argument a call passes, and the default for a call that passes none.
        'target.ts:15: curl -sI https://kv-demo.vault.azure.net/ # any answer',
        'target.ts:12: printenv IDENTITY_ENDPOINT   (the endpoint)',
        // A spread of a name an assignment gives a value, and a value `unshift` adds.
        'target.ts:19: az keyvault show --name kv-demo   # the vault',
        'target.ts:21: az monitor metrics list   (the request rate)',
        // A branch of a conditional in a subclass's super(), the remark in a style call.
        "target.ts:26: az keyvault show --name kv-demo   ${c.dim('(the vault)')}",
      ]);
      expect(read.lines.map((l) => l.text)).toEqual(expect.arrayContaining([
        'az keyvault show --name ${vault}',
        'az keyvault show --name kv-demo',
        'wait a minute and push again',
        'az role assignment list -o table',
        'set AZURE_TENANT_ID to the directory (tenant) ID',
        'see https://github.com/opena2a-org/secretless-ai#readme',
      ]));
      // An expression the reader meets that is none of the forms it reads is reported, not passed unseen.
      expect(read.unread).toEqual(['target.ts:30: names.map((n) => `secret set ${n}`)']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it('no Verify or Fix line of a PushError in the source has a `#` or parenthesized remark after its command', () => {
    const { config } = ts.readConfigFile(path.join(REPO_ROOT, 'tsconfig.json'), ts.sys.readFile);
    // The build's own input set: tsconfig excludes the test files.
    const parsed = ts.parseJsonConfigFileContent(config, ts.sys, REPO_ROOT);
    const program = ts.createProgram(parsed.fileNames, parsed.options);

    const read = readPushErrorLines(program, REPO_ROOT, path.join(REPO_ROOT, 'src', 'secret-push.ts'));

    // CONTROL: the reader reached the files that build a PushError, and a
    // line by each way one reaches it here, so an empty list below is a
    // measurement, not an empty search.
    expect(read.calls.map((w) => w.replace(/:\d+$/, ''))).toEqual(expect.arrayContaining([
      'src/backends/azure-kv.ts',
      'src/commands/secrets.ts',
      'src/secret-push.ts',
    ]));
    expect(read.lines.map((l) => l.text)).toEqual(expect.arrayContaining([
      // In the array literal of the call.
      'az keyvault show --name ${this.vaultName} --query properties.vaultUri -o tsv',
      // Through a constant, TOKEN_VERIFY.
      'az account get-access-token --resource ${KEY_VAULT_RESOURCE} --query expiresOn -o tsv',
      // Through a parameter of unreachable(), at the call that passes it.
      'curl -sI ${authority}/',
      // Through `fix.push()`.
      "or, on a vault that uses access policies: az keyvault set-policy --name ${this.vaultName} --upn <you> --secret-permissions ${op === 'set' ? 'set' : 'list'}",
      // A branch of a conditional.
      'correct AZURE_TENANT_ID, AZURE_CLIENT_ID or the credential',
    ]));
    expect(read.unread).toEqual([]);
    expect(remarks(read)).toEqual([]);
  }, 60_000);
});
