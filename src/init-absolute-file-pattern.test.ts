import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { init } from './init';
import { RULES_FILENAME } from './custom-rules';

// An absolute custom file pattern (`/srv/app/creds/*.json` under `files:`) must
// reach `.claude/settings.json` as `Read(//srv/app/creds/*.json)`. A single
// leading `/` in a project-scope Read rule resolves under the project root, so
// the deny an operator wrote for an absolute path never matched it. Re-running
// `init` over a config that already carries the inert single-slash rule must
// add the `//` form through the ordinary add loop; the inert entry denies
// nothing and is left alone here (pruning it is out of this task's scope).

const ABSOLUTE_PATTERN = '/srv/app/creds/*.json';
const INERT_RULE = `Read(${ABSOLUTE_PATTERN})`;
const EFFECTIVE_RULE = `Read(/${ABSOLUTE_PATTERN})`;

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-abs-pattern-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

function readDeny(dir: string): string[] {
  const settings = JSON.parse(fs.readFileSync(path.join(dir, '.claude', 'settings.json'), 'utf-8'));
  return settings.permissions.deny;
}

describe('init with an absolute custom file pattern', () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
    fs.writeFileSync(path.join(dir, RULES_FILENAME), `files:\n  - "${ABSOLUTE_PATTERN}"\n`);
  });
  afterEach(() => { cleanup(dir); });

  it('QGF-307.AC4 installs the double-slash Read deny on a project with no prior settings file', () => {
    const result = init(dir);

    expect(result.rulesFileProblem).toBeUndefined();
    const deny = readDeny(dir);
    expect(deny).toContain(EFFECTIVE_RULE);
    expect(deny).toContain(`Bash(cat ${ABSOLUTE_PATTERN})`);
  });

  it('QGF-307.AC4 adds the double-slash Read deny when settings already carry the single-slash rule', () => {
    const claudeDir = path.join(dir, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({ permissions: { deny: [INERT_RULE] } }, null, 2) + '\n',
    );

    const result = init(dir);

    expect(result.rulesFileProblem).toBeUndefined();
    expect(result.settingsUnusable).toBeUndefined();
    const deny = readDeny(dir);
    expect(deny).toContain(EFFECTIVE_RULE);
    // The repaired config is reported as modified, not as already up to date.
    expect(result.filesModified).toContain('.claude/settings.json');
  });
});
