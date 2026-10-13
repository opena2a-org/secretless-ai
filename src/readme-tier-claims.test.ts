import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * `vault exec` (Tier 2) resolves only from the Identity Vault under
 * `~/.aim/vault`, which `vault register` fills. A secret stored with
 * `secret set` lives in the configured storage backend (local, keychain,
 * 1password, vault, gcp-sm), which `run --only` and the broker read; asked for
 * that name, `vault exec` reports `Namespace "<name>" not found`. The README
 * said each tier "works against any supported backend", and the
 * bring-your-own-vault guide showed `vault exec` as the way to use the backend
 * it had just connected (#328). These tests hold that text and vault-core.ts
 * together: a change that lets `vault exec` read the configured backend fails
 * here, and the text has to change with it. The Architecture section moved
 * from the README to docs/how-it-works.md, and is held there.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const read = (rel: string) => fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
const ARCH_DOC_PATH = 'docs/how-it-works.md';
const ARCH_DOC = read(ARCH_DOC_PATH);
const BYOV_PATH = 'docs/use-cases/bring-your-own-vault.md';
const BYOV = read(BYOV_PATH);
const BROKER_DOC_PATH = 'docs/use-cases/run-broker.md';

/** The text of a `## ` section, up to the next `## ` heading. */
function section(doc: string, heading: string): string {
  const start = doc.indexOf(`\n## ${heading}\n`);
  expect(start, `${ARCH_DOC_PATH} must hold a "## ${heading}" section`).toBeGreaterThan(-1);
  const end = doc.indexOf('\n## ', start + 1);
  return doc.slice(start, end === -1 ? undefined : end);
}

/** Sentences of the prose, with fenced code blocks and headings dropped. */
function sentences(text: string): string[] {
  const prose = text
    .replace(/^```[^\n]*\n[\s\S]*?^```$/gm, '')
    .split('\n')
    .filter(l => !l.startsWith('#'))
    .join('\n');
  return prose
    .split(/\n{2,}/)
    .map(p => p.replace(/\n/g, ' '))
    .flatMap(p => p.split(/(?<=[.!?])\s+/))
    .map(s => s.trim())
    .filter(Boolean);
}

/** GitHub's anchor for a heading: lowercase, punctuation dropped, spaces to hyphens. */
function headingAnchor(text: string): string {
  return text.trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/\s/g, '-');
}

const ARCHITECTURE = section(ARCH_DOC, 'Architecture');

describe('which store vault exec reads (#328)', () => {
  it('vault-core.ts opens the Identity Vault and no configured storage backend', () => {
    const src = read('src/vault-core.ts');
    expect(src, 'vaultExec no longer resolves from ~/.aim/vault').toMatch(/path\.join\(HOME, '\.aim', 'vault'\)/);
    expect(
      src,
      `src/vault-core.ts now reaches the configured storage backend; ${ARCH_DOC_PATH} Architecture and ` +
        `${BYOV_PATH} say \`vault exec\` does not read it, update them in the same change`,
    ).not.toMatch(/(from|require\()\s*'\.\/(secret-store|backends)/);
  });

  it('no sentence says Tier 2 or vault exec works against a storage backend', () => {
    const subject = /Tier 2|Vault Exec|`vault exec`|\bEach\b/;
    const store = /backend|existing vault/i;
    const claims = [
      ...sentences(ARCHITECTURE).map(s => `${ARCH_DOC_PATH}: ${s}`),
      ...sentences(BYOV).map(s => `${BYOV_PATH}: ${s}`),
    ].filter(s => subject.test(s) && store.test(s) && !/\bnot\b/.test(s));
    expect(claims).toEqual([]);
  });

  it('the Tier 2 paragraph names the store it reads and the command for a backend secret', () => {
    const tier2 = ARCHITECTURE.split('\n').filter(l => l.startsWith('**Tier 2: Vault Exec.**'));
    expect(tier2, `${ARCH_DOC_PATH} Architecture must hold one "**Tier 2: Vault Exec.**" paragraph`).toHaveLength(1);
    expect(tier2[0]).toContain('`~/.aim/vault`');
    expect(tier2[0]).toContain('`vault register`');
    expect(ARCHITECTURE, `${ARCH_DOC_PATH} Architecture must show \`run --only\` for a secret in the configured backend`)
      .toMatch(/^npx secretless-ai run --only [A-Z_]+ -- /m);
  });

  it('the bring-your-own-vault guide shows run --only, not vault exec, for the backend it connects', () => {
    const commands = BYOV.split('\n').filter(l => l.startsWith('npx secretless-ai '));
    expect(commands.filter(c => c.startsWith('npx secretless-ai vault exec'))).toEqual([]);
    expect(commands.some(c => c.startsWith('npx secretless-ai run --only '))).toBe(true);
    const mentions = sentences(BYOV).filter(s => s.includes('`vault exec`'));
    for (const s of mentions) expect(s, `${BYOV_PATH}: a \`vault exec\` sentence must say it does not read this backend`).toMatch(/does not read/);
  });

  it(`links into ${BROKER_DOC_PATH} land on a heading`, () => {
    const headings = new Set(
      read(BROKER_DOC_PATH).split('\n').filter(l => /^#{1,6} /.test(l)).map(l => headingAnchor(l.replace(/^#+ /, ''))),
    );
    const links = [...`${ARCH_DOC}\n${BYOV}`.matchAll(/run-broker\.md#([\w-]+)/g)].map(m => m[1]);
    expect(links.length, `${ARCH_DOC_PATH} or the guide must link to the two stores in Run the Broker`).toBeGreaterThan(0);
    for (const anchor of links) expect(headings, `#${anchor}`).toContain(anchor);
  });
});
