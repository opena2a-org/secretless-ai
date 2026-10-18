/**
 * SARIF 2.1.0 for `scan --format sarif`.
 *
 * The document carries what `--json` carries for each finding: one result per
 * finding with the file and the line, the pattern id as `ruleId`, and the
 * pattern name and the fix in the message; one rule per pattern id. It is
 * written for GitHub code scanning (`github/codeql-action/upload-sarif`) and
 * for the editors that read SARIF. The preview line of a finding is not in
 * it: the document is uploaded and kept, and a masked line is still a line
 * from a file that holds a credential.
 *
 * Severity: every result is `error`, because a finding sets exit 1 and the
 * Security tab should not say less. The two severities the scanner has are
 * given on the rule as `security-severity`, which GitHub reads: `9.0` for
 * `critical` and `7.0` for `high`, the bands it shows as Critical and High.
 * A pattern that appears at both severities in one run carries the higher.
 *
 * Paths: a path under the scanned directory is given relative to it, with
 * `%SRCROOT%` resolved in `originalUriBaseIds` to that directory, so a reader
 * that resolves base ids finds the file under the checkout when the scan ran
 * inside it, at its root or in a subdirectory. The home-directory files a scan also reads
 * (GLOBAL_CONFIG_LABELS) and a named file outside the working directory are
 * absolute `file:` URIs: they are outside any checkout, and a relative path
 * would map them onto a repository file they are not.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { pathToFileURL } from 'url';
import { GLOBAL_CONFIG_LABELS, type ScanFinding } from './scan';
import { escapePathForDisplay } from './display-safe';

/** The schema's own id: the OASIS SARIF 2.1.0 errata01 schema. */
export const SARIF_SCHEMA_URL =
  'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json';
export const SARIF_VERSION = '2.1.0';
/** The `uriBaseId` of every path under the scanned directory. */
export const SRCROOT = '%SRCROOT%';
const INFORMATION_URI = 'https://opena2a.org/secretless';

/**
 * GitHub's `security-severity` bands: 9.0 and above is shown as Critical, 7.0
 * to 8.9 as High. The scanner has these two severities and no other.
 */
const SECURITY_SEVERITY: Readonly<Record<ScanFinding['severity'], string>> = {
  critical: '9.0',
  high: '7.0',
};

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SarifRule {
  id: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: 'error' };
  properties: { tags: string[]; 'security-severity': string };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'error';
  message: { text: string };
  locations: Array<{
    physicalLocation: { artifactLocation: SarifArtifactLocation; region: { startLine: number } };
  }>;
  properties: {
    severity: ScanFinding['severity'];
    confidence: number;
    confidenceTier: ScanFinding['confidenceTier'];
    looksLikeFixture: boolean;
  };
}

export interface SarifLog {
  $schema: string;
  version: typeof SARIF_VERSION;
  runs: [{
    tool: { driver: { name: string; version: string; informationUri: string; rules: SarifRule[] } };
    originalUriBaseIds: Record<string, { uri: string }>;
    results: SarifResult[];
    properties: { summary: Record<string, unknown> };
  }];
}

export interface SarifScanInput {
  /** The scanner's version, written as the tool's. */
  version: string;
  /** The scanned directory or file, as `runScan` received it. */
  projectDir: string;
  findings: ScanFinding[];
  /**
   * The `summary` of `--json`, kept on the run so a reader of the document can
   * tell a clean scan from an unfinished one without the exit code.
   */
  summary: Record<string, unknown>;
}

/**
 * The directory relative finding paths are under. A directory scan reports
 * them relative to the directory; a named file is reported relative to the
 * working directory, or as an absolute path when it is outside it
 * (scan.ts, scanSingleFile).
 */
function sourceRoot(projectDir: string): string {
  try {
    if (fs.statSync(projectDir).isFile()) return process.cwd();
  } catch {
    // A target that cannot be read was reported by the scan itself; the path
    // as given still names the base.
  }
  return projectDir;
}

/** A directory as a base URI: a `file:` URL ending in `/`, as SARIF requires of a base. */
function directoryUri(dir: string): string {
  const href = pathToFileURL(dir).href;
  return href.endsWith('/') ? href : `${href}/`;
}

/** A relative path as a URI reference: `/` between segments, each segment percent-encoded. */
function relativeUri(file: string): string {
  const segments = path.sep === '\\' ? file.split(/[\\/]/) : file.split('/');
  return segments.map(encodeURIComponent).join('/');
}

function artifactLocation(file: string): SarifArtifactLocation {
  if (GLOBAL_CONFIG_LABELS.includes(file)) {
    return { uri: pathToFileURL(path.join(os.homedir(), file.slice('~/'.length))).href };
  }
  if (path.isAbsolute(file)) return { uri: pathToFileURL(file).href };
  return { uri: relativeUri(file), uriBaseId: SRCROOT };
}

/** The SARIF document for one scan, built from the findings `--json` reports. */
export function scanToSarif(input: SarifScanInput): SarifLog {
  const rules: SarifRule[] = [];
  const indexOf = new Map<string, number>();
  for (const f of input.findings) {
    const at = indexOf.get(f.patternId);
    if (at === undefined) {
      indexOf.set(f.patternId, rules.length);
      rules.push({
        id: f.patternId,
        shortDescription: { text: f.patternName },
        defaultConfiguration: { level: 'error' },
        properties: { tags: ['security', 'credential'], 'security-severity': SECURITY_SEVERITY[f.severity] },
      });
    } else if (f.severity === 'critical') {
      rules[at].properties['security-severity'] = SECURITY_SEVERITY.critical;
    }
  }

  const results = input.findings.map((f): SarifResult => ({
    ruleId: f.patternId,
    ruleIndex: indexOf.get(f.patternId)!,
    level: 'error',
    message: { text: `${f.patternName} found in ${escapePathForDisplay(f.file)}:${f.line}. ${f.fix}` },
    locations: [{
      physicalLocation: { artifactLocation: artifactLocation(f.file), region: { startLine: f.line } },
    }],
    properties: {
      severity: f.severity,
      confidence: f.confidence,
      confidenceTier: f.confidenceTier,
      looksLikeFixture: f.looksLikeFixture,
    },
  }));

  return {
    $schema: SARIF_SCHEMA_URL,
    version: SARIF_VERSION,
    runs: [{
      tool: { driver: { name: 'secretless-ai', version: input.version, informationUri: INFORMATION_URI, rules } },
      originalUriBaseIds: { [SRCROOT]: { uri: directoryUri(sourceRoot(input.projectDir)) } },
      results,
      properties: { summary: input.summary },
    }],
  };
}
