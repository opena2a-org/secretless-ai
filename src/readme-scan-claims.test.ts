import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scan } from './scan';
import { CREDENTIAL_PATTERNS } from './patterns';

/**
 * The README and `--help` say what a scan reads. A directory scan opens source
 * files by extension, key files, and the config files it recognizes by name;
 * it prints "No hardcoded credentials found." with exit 0 over every other
 * file in the tree. The README used to say it scanned "config files and
 * source code", which read as covering `values.yaml`, `main.tf`, workflows and
 * notebooks. These tests hold the published text and the walker's file filter
 * together: a change that starts opening one of these files fails here, and
 * the text has to change with it.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const README = fs.readFileSync(path.join(REPO_ROOT, 'README.md'), 'utf8');

const TEXT_DRIFT =
  'README.md How it works step 1, the README paragraph on what a directory scan checks, ' +
  'the README dot-directory paragraph, the scan help line and the website docs sentence ' +
  'say a directory scan does not open this file; update them in the same change that starts opening it.';

// The real-looking AWS key src/scan.test.ts already plants, joined at run
// time so that no single source line has the shape of a provider token.
const VALUE = 'AKIA' + 'REALKEY1234567890';

const NOT_OPENED: Record<string, string> = {
  'deploy/values.yaml': `aws:\n  accessKeyId: ${VALUE}\n`,
  'infra/main.tf': `provider "aws" {\n  access_key = "${VALUE}"\n}\n`,
  '.github/workflows/deploy.yml': `jobs:\n  deploy:\n    env:\n      AWS_ACCESS_KEY_ID: ${VALUE}\n`,
  'notebook.ipynb': `{\n  "cells": [\n    { "cell_type": "code", "source": ["aws_key = '${VALUE}'"] }\n  ]\n}\n`,
  'docs/guide.md': `Deploy with \`AWS_ACCESS_KEY_ID=${VALUE}\`.\n`,
};

function tmpProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'readme-claims-'));
  const files = { ...NOT_OPENED, 'control.js': `const key = "${VALUE}";\n` };
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

describe('README claims about the pattern catalog', () => {
  it('states the pattern count and the pinned catalog version', () => {
    const m = README.match(/(\d+) credential patterns from \[`@opena2a\/credential-patterns@(\d+\.\d+\.\d+)`\]/);
    expect(m, 'README.md How it works step 1 no longer names the pattern count and catalog version').not.toBeNull();
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
    expect(Number(m![1])).toBe(CREDENTIAL_PATTERNS.length);
    expect(m![2]).toBe(pkg.dependencies['@opena2a/credential-patterns']);
  });
});

describe('README claims about what a directory scan opens', () => {
  it('a directory scan reports the source-file control and none of the files it does not open', () => {
    const dir = tmpProject();
    try {
      const findings = scan(dir, { scanGlobal: false });
      const root = fs.realpathSync(dir);
      const files = [...new Set(findings.map(f => path.relative(root, fs.realpathSync(path.resolve(dir, f.file)))))].sort();
      for (const rel of Object.keys(NOT_OPENED)) {
        expect(files, `${rel}: ${TEXT_DRIFT}`).not.toContain(rel);
      }
      expect(files).toEqual(['control.js']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('naming each of those files scans it', () => {
    const dir = tmpProject();
    try {
      for (const rel of Object.keys(NOT_OPENED)) {
        const findings = scan(path.join(dir, rel), { scanGlobal: false });
        expect(findings.length, `scan ${rel}`).toBe(1);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the step 1 link target exists and holds the directory-scan paragraph', () => {
    const lines = README.split('\n');
    const heading = '### Incomplete scans do not report clean';
    const at = lines.flatMap((l, i) => (l === heading ? [i] : []));
    expect(at, `README.md must hold exactly one "${heading}" heading`).toHaveLength(1);

    let inFence = false;
    let found = false;
    for (const line of lines.slice(at[0] + 1)) {
      if (line.startsWith('```')) inFence = !inFence;
      if (!inFence && /^#{1,6} /.test(line)) break;
      if (line.startsWith('A directory scan checks')) {
        found = true;
        break;
      }
    }
    expect(found, `the paragraph beginning "A directory scan checks" must follow "${heading}" before the next heading`).toBe(true);
  });
});
