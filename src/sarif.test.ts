import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { pathToFileURL } from 'url';
import { scanToSarif, SARIF_SCHEMA_URL, SARIF_VERSION, SRCROOT } from './sarif';
import type { ScanFinding } from './scan';

/**
 * `scan --format sarif` writes the findings of `--json` as SARIF 2.1.0: one
 * result per finding with its file, line and pattern id, one rule per pattern
 * id, and paths GitHub code scanning can map onto the repository. These tests
 * hold the converter to that on findings built by hand; commands/scan-sarif.test.ts
 * holds it to a real scan.
 */

let dir: string;
beforeAll(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sarif-')); });
afterAll(() => { fs.rmSync(dir, { recursive: true, force: true }); });

function finding(over: Partial<ScanFinding> = {}): ScanFinding {
  return {
    file: 'config.js',
    line: 3,
    patternId: 'anthropic',
    patternName: 'Anthropic API Key',
    severity: 'high',
    preview: 'const k = "[Anthropic API Key REDACTED]";',
    fix: 'Move to env var ANTHROPIC_API_KEY.',
    confidence: 0.92,
    confidenceTier: 'high',
    looksLikeFixture: false,
    ...over,
  };
}

const SUMMARY = { total: 1, truncated: false };

function sarif(findings: ScanFinding[], projectDir = dir) {
  return scanToSarif({ version: '0.0.0-test', projectDir, findings, summary: SUMMARY });
}

describe('scanToSarif', () => {
  it('names the schema, the version and the tool', () => {
    const doc = sarif([finding()]);
    expect(doc.$schema).toBe(SARIF_SCHEMA_URL);
    expect(doc.version).toBe(SARIF_VERSION);
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs).toHaveLength(1);
    expect(doc.runs[0].tool.driver).toMatchObject({
      name: 'secretless-ai',
      version: '0.0.0-test',
      informationUri: 'https://opena2a.org/secretless',
    });
  });

  it('writes one result per finding, in order, with the file, line and pattern id of each', () => {
    const doc = sarif([
      finding(),
      finding({ file: '.env', line: 1, patternId: 'aws-access', patternName: 'AWS Access Key', severity: 'critical' }),
    ]);
    const [first, second] = doc.runs[0].results;
    expect(doc.runs[0].results).toHaveLength(2);
    expect(first.ruleId).toBe('anthropic');
    expect(first.level).toBe('error');
    expect(first.locations[0].physicalLocation.artifactLocation).toEqual({ uri: 'config.js', uriBaseId: SRCROOT });
    expect(first.locations[0].physicalLocation.region).toEqual({ startLine: 3 });
    expect(second.ruleId).toBe('aws-access');
    expect(second.locations[0].physicalLocation.artifactLocation).toEqual({ uri: '.env', uriBaseId: SRCROOT });
    expect(second.locations[0].physicalLocation.region).toEqual({ startLine: 1 });
    expect(second.properties).toEqual({ severity: 'critical', confidence: 0.92, confidenceTier: 'high', looksLikeFixture: false });
  });

  it('writes one rule per pattern id, and each result indexes the rule it names', () => {
    const doc = sarif([
      finding({ line: 3 }),
      finding({ file: 'lib/client.js', line: 8 }),
      finding({ file: '.env', line: 1, patternId: 'aws-access', patternName: 'AWS Access Key', severity: 'critical' }),
    ]);
    const { rules } = doc.runs[0].tool.driver;
    expect(rules.map((r) => r.id)).toEqual(['anthropic', 'aws-access']);
    expect(rules.map((r) => r.shortDescription.text)).toEqual(['Anthropic API Key', 'AWS Access Key']);
    for (const result of doc.runs[0].results) {
      expect(rules[result.ruleIndex].id).toBe(result.ruleId);
    }
  });

  it('gives security-severity 9.0 to a critical pattern and 7.0 to a high one', () => {
    const high = sarif([finding({ severity: 'high' })]).runs[0].tool.driver.rules[0];
    const critical = sarif([finding({ severity: 'critical' })]).runs[0].tool.driver.rules[0];
    expect(high.properties['security-severity']).toBe('7.0');
    expect(critical.properties['security-severity']).toBe('9.0');
    expect(high.defaultConfiguration).toEqual({ level: 'error' });
    expect(high.properties.tags).toEqual(['security', 'credential']);
  });

  it('a pattern found at both severities carries 9.0, whichever is seen first', () => {
    const highFirst = sarif([finding({ severity: 'high' }), finding({ file: '.env', line: 1, severity: 'critical' })]);
    const criticalFirst = sarif([finding({ file: '.env', line: 1, severity: 'critical' }), finding({ severity: 'high' })]);
    expect(highFirst.runs[0].tool.driver.rules).toHaveLength(1);
    expect(highFirst.runs[0].tool.driver.rules[0].properties['security-severity']).toBe('9.0');
    expect(criticalFirst.runs[0].tool.driver.rules[0].properties['security-severity']).toBe('9.0');
  });

  it('the message names the pattern, the location and the fix, and the document holds no preview line', () => {
    const doc = sarif([finding()]);
    expect(doc.runs[0].results[0].message.text).toBe('Anthropic API Key found in config.js:3. Move to env var ANTHROPIC_API_KEY.');
    expect(JSON.stringify(doc)).not.toContain('REDACTED');
  });

  it('a path under the scanned directory is relative to %SRCROOT%, which names the directory as a file: URL ending in /', () => {
    const doc = sarif([finding({ file: 'src/config.js' })]);
    expect(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation).toEqual({ uri: 'src/config.js', uriBaseId: SRCROOT });
    expect(doc.runs[0].originalUriBaseIds).toEqual({ [SRCROOT]: { uri: `${pathToFileURL(dir).href}/` } });
    expect(doc.runs[0].originalUriBaseIds[SRCROOT].uri.endsWith('/')).toBe(true);
  });

  it('percent-encodes a segment with a space or a # and keeps the separators', () => {
    const doc = sarif([finding({ file: 'deploy/my app/config#1.js' })]);
    expect(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('deploy/my%20app/config%231.js');
  });

  it('a home-directory file is an absolute file: URI with no base', () => {
    const doc = sarif([finding({ file: '~/.claude/CLAUDE.md', severity: 'critical' })]);
    const location = doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation;
    expect(location.uri).toBe(pathToFileURL(path.join(os.homedir(), '.claude', 'CLAUDE.md')).href);
    expect(location.uriBaseId).toBeUndefined();
    expect(doc.runs[0].results[0].message.text).toContain('found in ~/.claude/CLAUDE.md:3.');
  });

  it('an absolute path is a file: URI with no base', () => {
    const named = path.join(dir, 'named.js');
    const doc = sarif([finding({ file: named })]);
    expect(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation).toEqual({ uri: pathToFileURL(named).href });
  });

  it('a named file puts %SRCROOT% at the working directory, which its finding path is relative to', () => {
    const named = path.join(dir, 'named.js');
    fs.writeFileSync(named, 'export const x = 1;\n');
    const doc = sarif([finding({ file: 'named.js' })], named);
    const cwd = pathToFileURL(process.cwd()).href;
    expect(doc.runs[0].originalUriBaseIds[SRCROOT].uri).toBe(cwd.endsWith('/') ? cwd : `${cwd}/`);
  });

  it('carries the summary on the run', () => {
    expect(sarif([finding()]).runs[0].properties).toEqual({ summary: SUMMARY });
  });

  it('a clean scan is an empty results list and an empty rules list', () => {
    const doc = sarif([]);
    expect(doc.runs[0].results).toEqual([]);
    expect(doc.runs[0].tool.driver.rules).toEqual([]);
  });
});
