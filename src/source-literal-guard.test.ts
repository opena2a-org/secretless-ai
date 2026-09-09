import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/**
 * Source-literal guard: the detector test file must never carry a whole
 * provider-shaped credential literal in its committed source. Fixtures are
 * assembled from parts at run time (join / concat / repeat) so the detectors
 * see the assembled string while the tree never carries it — and GitHub
 * secret scanning has nothing to flag in our own scanner's tests.
 *
 * The shape set is carried inline, not imported from the live catalog, so
 * weakening a detector can never weaken this guard.
 */
const PROVIDER_SHAPES: ReadonlyArray<{ name: string; regex: RegExp }> = [
  { name: 'aws-access-or-sts', regex: /(AKIA|ASIA)[0-9A-Z]{16}/g },
  { name: 'google-api-key', regex: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'slack-token', regex: /xox[abprs]-[0-9A-Za-z-]{20,}/g },
  { name: 'github-pat', regex: /ghp_[A-Za-z0-9]{36}/g },
  { name: 'github-fine-grained-pat', regex: /github_pat_[A-Za-z0-9_]{22,}/g },
  { name: 'anthropic-api-key', regex: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'mongodb-srv-userinfo-uri', regex: /mongodb\+srv:\/\/[^:\/@\s]+:[^@\s]+@[^\/\s]+/g },
  { name: 'generic-live-key', regex: /live_[A-Za-z0-9_-]{30,}/g },
];

/**
 * The detector test files this guard scans, relative to this file. Scoped to
 * the files whose fixtures are assembled from parts — not all of src — since
 * other test files still carry shapes GitHub's live pattern set does not
 * alert on (documented example keys, checksum-invalid tokens).
 */
const SCANNED_FILES = ['patterns.test.ts'];

interface ShapeFinding {
  file: string;
  line: number;
  shape: string;
  /** First 4 chars + length only — a finding must never restate the shape. */
  masked: string;
}

function scanSourceForProviderShapes(filePath: string): ShapeFinding[] {
  const source = fs.readFileSync(filePath, 'utf8');
  const findings: ShapeFinding[] = [];
  for (const { name, regex } of PROVIDER_SHAPES) {
    for (const match of source.matchAll(regex)) {
      findings.push({
        file: filePath,
        line: source.slice(0, match.index).split('\n').length,
        shape: name,
        masked: `${match[0].slice(0, 4)}…[${match[0].length} chars masked]`,
      });
    }
  }
  return findings;
}

function guardVerdict(files: string[]): { pass: boolean; findings: ShapeFinding[] } {
  const findings = files.flatMap(scanSourceForProviderShapes);
  return { pass: findings.length === 0, findings };
}

describe('source-literal guard', () => {
  it('OPA-12.AC1 detector test source carries zero contiguous provider-shape literals', () => {
    const verdict = guardVerdict(SCANNED_FILES.map(f => path.join(__dirname, f)));
    expect(verdict.findings).toEqual([]);
    expect(verdict.pass).toBe(true);
  });

  it('OPA-12.AC2 guard refuses a scratch copy with a planted provider-shape literal', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-shape-guard-'));
    try {
      // The planted value is itself assembled at plant time so this guard
      // file stays clean under its own scan.
      const planted = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
      const scratchCopy = path.join(tmpDir, 'patterns.test.ts');
      const original = fs.readFileSync(path.join(__dirname, 'patterns.test.ts'), 'utf8');
      fs.writeFileSync(scratchCopy, `${original}\nconst plantedFixture = '${planted}';\n`);

      const verdict = guardVerdict([scratchCopy]);
      expect(verdict.pass).toBe(false);
      expect(verdict.findings.map(f => f.file)).toContain(scratchCopy);
      expect(verdict.findings.some(f => f.shape === 'aws-access-or-sts')).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
