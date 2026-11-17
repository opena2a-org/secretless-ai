import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';
import { VERSION } from './commands/utils';

// The guard hook init writes is generated text: a bash script with python
// programs embedded in it. A change that only moves where that text is kept,
// such as a program moved out of a string constant into a file of its own,
// must leave every byte of the hook as it was. The verdict snapshot cannot
// show that: two hooks can decide every corpus command alike and still
// differ. This test compares the hook init writes, in the default
// configuration and under the custom rules in fixtures/guard-custom-rules.yaml,
// with the bytes recorded in fixtures/guard-hook-default.txt and
// fixtures/guard-hook-custom-rules.txt, and names the first byte and line
// that differ.
//
// One line of the hook changes with every release:
// `# Written by secretless-ai <version>`. The comparison replaces this build's
// version on that line, and on no other, with the text `<version>`; every
// other byte is compared as written.
//
// A change meant to alter the hook records the new bytes:
//
//   SECRETLESS_UPDATE_GUARD_HOOK_BYTES=1 npx vitest run src/guard-hook.bytes.test.ts
//
// and commits both recordings with it, so their diff is the change to the hook.
const FIXTURES = path.join(__dirname, 'fixtures');
const CUSTOM_RULES = fs.readFileSync(path.join(FIXTURES, 'guard-custom-rules.yaml'), 'utf-8');
const RECORDED_DEFAULT = path.join(FIXTURES, 'guard-hook-default.txt');
const RECORDED_CUSTOM_RULES = path.join(FIXTURES, 'guard-hook-custom-rules.txt');
const UPDATE = process.env.SECRETLESS_UPDATE_GUARD_HOOK_BYTES === '1';

const VERSION_LINE = `# Written by secretless-ai ${VERSION}`;
const VERSION_LINE_RECORDED = '# Written by secretless-ai <version>';

// The guard hook init writes into a new project, with `rules` as the
// project's .secretless-rules.yaml when given.
function hookInitWrites(rules?: string): Buffer {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-guard-bytes-'));
  try {
    if (rules !== undefined) fs.writeFileSync(path.join(dir, '.secretless-rules.yaml'), rules);
    const result = init(dir);
    expect(result.rulesFileProblem, 'the rules file must load in full').toBeUndefined();
    return fs.readFileSync(path.join(dir, '.claude', 'hooks', 'secretless-guard.sh'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// The hook with this build's version on its "Written by" line replaced by
// `<version>`. Throws unless that line occurs in the hook exactly once.
function withVersionMasked(hook: Buffer): Buffer {
  const needle = Buffer.from(`\n${VERSION_LINE}\n`, 'utf-8');
  const at = hook.indexOf(needle);
  if (at === -1 || hook.indexOf(needle, at + 1) !== -1) {
    throw new Error(`the hook must carry the line ${JSON.stringify(VERSION_LINE)} exactly once`);
  }
  return Buffer.concat([
    hook.subarray(0, at),
    Buffer.from(`\n${VERSION_LINE_RECORDED}\n`, 'utf-8'),
    hook.subarray(at + needle.length),
  ]);
}

// '' when the two are the same bytes. Otherwise the first byte that differs,
// its line in the recording, both lengths, and that line as each holds it.
function difference(generated: Buffer, recorded: Buffer): string {
  if (generated.equals(recorded)) return '';
  const shorter = Math.min(generated.length, recorded.length);
  let at = 0;
  while (at < shorter && generated[at] === recorded[at]) at++;
  let line = 1;
  for (let i = 0; i < at; i++) if (recorded[i] === 0x0a) line++;
  const lineOf = (bytes: Buffer): string => {
    if (at >= bytes.length) return '(ends before this byte)';
    const start = at === 0 ? 0 : bytes.lastIndexOf(0x0a, at - 1) + 1;
    const end = bytes.indexOf(0x0a, at);
    return JSON.stringify(bytes.subarray(start, end === -1 ? bytes.length : end).toString('utf-8')).slice(0, 240);
  };
  return `first difference at byte ${at} (line ${line}); lengths: generated ${generated.length}, recorded ${recorded.length}\n` +
    `  generated: ${lineOf(generated)}\n` +
    `  recorded:  ${lineOf(recorded)}`;
}

function bytesThatDiffer(a: Buffer, b: Buffer): number {
  let count = Math.abs(a.length - b.length);
  const shorter = Math.min(a.length, b.length);
  for (let i = 0; i < shorter; i++) if (a[i] !== b[i]) count++;
  return count;
}

describe('guard hook bytes', () => {
  const configurations: Array<{ name: string; rules?: string; recorded: string }> = [
    { name: 'in the default configuration', recorded: RECORDED_DEFAULT },
    { name: 'under fixtures/guard-custom-rules.yaml', rules: CUSTOM_RULES, recorded: RECORDED_CUSTOM_RULES },
  ];

  for (const c of configurations) {
    it(`the hook init writes ${c.name} equals the recorded bytes, with only the version on its "Written by" line masked`, () => {
      const hook = withVersionMasked(hookInitWrites(c.rules));
      if (UPDATE) {
        fs.writeFileSync(c.recorded, hook);
        return;
      }
      expect(
        difference(hook, fs.readFileSync(c.recorded)),
        `the hook differs from fixtures/${path.basename(c.recorded)}. ` +
          'If the change is meant, record it with SECRETLESS_UPDATE_GUARD_HOOK_BYTES=1 and commit the recording.',
      ).toBe('');
    });
  }

  it('masking changes the "Written by" line and no other line', () => {
    const hook = hookInitWrites();
    const before = hook.toString('utf-8').split('\n');
    const after = withVersionMasked(hook).toString('utf-8').split('\n');
    expect(after.length).toBe(before.length);
    const changed = before.flatMap((text, i) => (text === after[i] ? [] : [[text, after[i]]]));
    expect(changed).toEqual([[VERSION_LINE, VERSION_LINE_RECORDED]]);
  });

  // The cells below give the comparison input that is not the recording, and
  // assert that it reports the difference.

  it('reports a hook generated with one custom rule changed by one byte', () => {
    const changedRules = CUSTOM_RULES.replace('"acme-cli*get*"', '"acme-cli*set*"');
    expect(changedRules, 'the rules fixture must hold the command pattern this cell changes').not.toBe(CUSTOM_RULES);
    const hook = withVersionMasked(hookInitWrites(changedRules));
    const recorded = fs.readFileSync(RECORDED_CUSTOM_RULES);
    expect(bytesThatDiffer(hook, recorded), 'bytes that differ from the recording').toBe(1);
    expect(difference(hook, recorded)).toMatch(/^first difference at byte \d+ \(line \d+\); lengths: generated (\d+), recorded \1\n/);
  });

  it('reports a hook without the recording\'s last newline', () => {
    const recorded = fs.readFileSync(RECORDED_DEFAULT);
    expect(recorded[recorded.length - 1], 'the recording ends with a newline').toBe(0x0a);
    const report = difference(recorded.subarray(0, recorded.length - 1), recorded);
    expect(report).toContain(`lengths: generated ${recorded.length - 1}, recorded ${recorded.length}`);
    expect(report).toContain('generated: (ends before this byte)');
  });

  it('reports the default hook against the custom-rule recording, so the custom rules reach the hook', () => {
    const hook = withVersionMasked(hookInitWrites());
    expect(difference(hook, fs.readFileSync(RECORDED_CUSTOM_RULES))).toMatch(/^first difference at byte \d+/);
  });
});
