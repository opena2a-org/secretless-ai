import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scan, KEY_FILE_EXTENSIONS } from './scan';
import { CREDENTIAL_PATTERNS, CONFIG_FILES } from './patterns';

/**
 * The README and `--help` say what a scan reads. A directory scan opens source
 * files by extension, key files, and the config files it recognizes by name;
 * it prints "No hardcoded credentials found." with exit 0 over every other
 * file in the tree. The README used to say it scanned "config files and
 * source code", which read as covering `values.yaml`, `main.tf`, workflows and
 * notebooks. These tests hold the published text and the walker's file filter
 * together: a change that starts opening one of these files fails here, and
 * the text has to change with it. The full paragraph lives in
 * docs/scanning.md, which the README's How it works step 1 links to.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const README = fs.readFileSync(path.join(REPO_ROOT, 'README.md'), 'utf8');
const SCAN_DOC_PATH = 'docs/scanning.md';
const SCAN_DOC = fs.readFileSync(path.join(REPO_ROOT, SCAN_DOC_PATH), 'utf8');

const TEXT_DRIFT =
  `README.md How it works step 1, the ${SCAN_DOC_PATH} paragraph beginning "A directory scan checks", ` +
  `the ${SCAN_DOC_PATH} paragraph beginning "Dot-directories are among" and the scan line of --help ` +
  '(src/commands/help.ts) say a directory scan does not open this file; update them in the ' +
  'same change that starts opening it.';

/** The published paragraph that says what a directory scan opens. */
function directoryScanParagraph(): string {
  const para = SCAN_DOC.split('\n').filter(l => l.startsWith('A directory scan checks'));
  expect(para, `${SCAN_DOC_PATH} must hold exactly one paragraph beginning "A directory scan checks"`).toHaveLength(1);
  expect(README, 'README.md must not hold a second copy of the directory-scan paragraph').not.toMatch(/^A directory scan checks/m);
  return para[0];
}

/** GitHub's anchor for a heading: lowercase, punctuation dropped, spaces to hyphens. */
function headingAnchor(text: string): string {
  return text.trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/\s/g, '-');
}

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

  it('the paragraph names every key-file extension the walker opens', () => {
    const para = directoryScanParagraph();
    for (const ext of KEY_FILE_EXTENSIONS) {
      expect(para, `the ${SCAN_DOC_PATH} directory-scan paragraph does not name \`${ext}\` (KEY_FILE_EXTENSIONS in src/scan.ts)`).toContain(`\`${ext}\``);
    }
  });

  it('a workflow is opened only when its file name is a recognized config name, and the paragraph says so', () => {
    // No config name points into .github/workflows, but config names match by
    // basename inside dot-directories, so a workflow named config.yml is opened
    // while deploy.yml is not. The published text must not state the absolute.
    expect(CONFIG_FILES.filter(name => name.includes('.github/workflows'))).toEqual([]);
    expect(CONFIG_FILES).toContain('config.yml');
    expect(directoryScanParagraph()).toContain('GitHub Actions workflows other than one whose file name is a recognized config name (such as `.github/workflows/config.yml`)');
    const dir = tmpProject();
    try {
      const workflow = path.join(dir, '.github/workflows/config.yml');
      fs.writeFileSync(workflow, NOT_OPENED['.github/workflows/deploy.yml']);
      const findings = scan(dir, { scanGlobal: false });
      const root = fs.realpathSync(dir);
      const files = [...new Set(findings.map(f => path.relative(root, fs.realpathSync(path.resolve(dir, f.file)))))].sort();
      expect(files).toEqual(['.github/workflows/config.yml', 'control.js']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the paragraph names --include-config, which reads the config-format files it names', () => {
    expect(directoryScanParagraph()).toContain('`scan --include-config` also reads config-format files outside dot-directories, such as `values.yaml` and `main.tf`');
    const dir = tmpProject();
    try {
      const findings = scan(dir, { scanGlobal: false, includeConfig: true });
      const root = fs.realpathSync(dir);
      const files = [...new Set(findings.map(f => path.relative(root, fs.realpathSync(path.resolve(dir, f.file)))))].sort();
      expect(files).toEqual(['control.js', 'deploy/values.yaml', 'infra/main.tf']);
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
    const step1 = README.split('\n').filter(l => l.startsWith('1. **Scans**'));
    expect(step1, 'README.md must hold exactly one How it works step beginning "1. **Scans**"').toHaveLength(1);
    const link = step1[0].match(/\]\(([^)#\s]+)#([^)\s]+)\)/);
    expect(link, 'README.md How it works step 1 no longer links to the paragraph that says what a directory scan opens').not.toBeNull();
    const [, target, anchor] = link!;
    expect(target, 'the step 1 link must point at the scan coverage page').toBe(SCAN_DOC_PATH);

    const lines = SCAN_DOC.split('\n');
    const at = lines.flatMap((l, i) => {
      const h = l.match(/^#{1,6} (.+)$/);
      return h && headingAnchor(h[1]) === anchor ? [i] : [];
    });
    expect(at, `${SCAN_DOC_PATH} must hold exactly one heading whose anchor is #${anchor}`).toHaveLength(1);

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
    expect(found, `the paragraph beginning "A directory scan checks" must follow the #${anchor} heading before the next heading`).toBe(true);
  });
});
