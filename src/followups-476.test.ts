import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * #476: on a missing directory, `init` printed
 * `mkdir -p <path> && npx secretless-ai init <path>   # or create this directory first`
 * on a line under its `Fix:` label. Pasted into `zsh -f -i`, which does not
 * take `#` as a comment, the line passed `#` and five more words to `init`
 * after the path. The check of the source in src/followups-471.test.ts reads
 * only a line that prints a `Fix:` or `Verify:` label, so it did not see this
 * one. This file holds the lines printed under such a label to the same rule.
 * The lines `init` prints are covered in src/followups-272.test.ts.
 */

const REPO_ROOT = path.resolve(__dirname, '..');

function sourceFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(full);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') && !entry.name.endsWith('.test-support.ts') ? [full] : [];
  });
}

// A line under a `Fix:` or `Verify:` label starts ten spaces in, where the
// command after the label starts, so a source line is held to the rule when
// it has a string that starts ten or more spaces in. Its remark is a `#` with
// whitespace on each side, or a `#` set off from the command by two or more
// spaces, written plainly or in a style call, as in
// `${c.dim('# or create this directory first')}`.
const REMARK_UNDER_A_LABEL = /['"`] {10,}\S.*(\s#\s|\S\s{2,}(\$\{c\.\w+\(['"`])?#)/;

describe('lines printed under a Fix or Verify label in the source have no `#` remark after the command (#476)', () => {
  it('the check finds a `#` remark on a line under a label, written plainly or in a style call, and passes the lines that replaced it', () => {
    for (const line of [
      "      console.error(`          mkdir -p ${quoted} && ${CLI} init ${quoted}   ${c.dim('# or create this directory first')}\\n`);",
      "      '          mkdir -p <path> && npx secretless-ai init <path>   # or create this directory first',",
    ]) {
      expect(REMARK_UNDER_A_LABEL.test(line), line).toBe(true);
    }
    for (const line of [
      "      console.error(`          ${c.dim('run from inside your project')}`);",
      "      console.error(`          ${c.dim('or create this directory first:')}`);",
      '      console.error(`          mkdir -p ${quoted} && ${CLI} init ${quoted}\\n`);',
      "      '          https://github.com/opena2a-org/secretless-ai#readme',",
    ]) {
      expect(REMARK_UNDER_A_LABEL.test(line), line).toBe(false);
    }
  });

  it('no line printed under a Fix or Verify label in the source has a `#` remark after its command', () => {
    const hits = sourceFiles(path.join(REPO_ROOT, 'src')).flatMap((file) => fs.readFileSync(file, 'utf-8')
      .split('\n')
      .flatMap((line, i) => (REMARK_UNDER_A_LABEL.test(line) ? [`${path.relative(REPO_ROOT, file)}:${i + 1}`] : [])));
    expect(hits).toEqual([]);
  });
});
