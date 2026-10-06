/**
 * Which GCP project the gcp-sm backend resolves names from, and why.
 *
 * Order: explicit backend config > the repository's `.secretless`
 * (`gcp.projectId: <id>`) > `~/.secretless-ai/config.json` `gcp.projectId` >
 * the service account key's `project_id` > the ADC `quota_project_id`.
 *
 * One machine can work for two organisations whose secrets must never share an
 * IAM boundary (#177). A repository that names its own project therefore never
 * falls back to another: a `gcp.projectId` line that cannot be used is an
 * error, not a reason to read the user-wide project instead.
 *
 * Kept free of imports from the rest of the tool: the manifest parser and the
 * backend both read the directive through this module, so the two cannot
 * disagree about what a line means.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/** The manifest file, as in manifest.ts. */
const MANIFEST_FILENAME = '.secretless';

/** The manifest key that names the project. */
export const GCP_PROJECT_KEY = 'gcp.projectId';

/**
 * A project id (6-30 lowercase letters, digits and hyphens, starting with a
 * letter) or a numeric project number. The value is interpolated into the
 * Secret Manager URL path, and a manifest arrives with whatever repository was
 * cloned, so nothing outside this shape is accepted.
 */
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const PROJECT_NUMBER = /^[1-9][0-9]{0,19}$/;

export function isGcpProjectRef(value: string): boolean {
  return PROJECT_ID.test(value) || PROJECT_NUMBER.test(value);
}

export type GcpProjectDirective =
  | { projectId: string }
  | { reason: string };

/**
 * Read one manifest line, comment removed and trimmed, as a `gcp.projectId`
 * line. Returns undefined when the line is not one. A reason never contains
 * text copied from the line.
 */
export function parseGcpProjectDirective(beforeComment: string): GcpProjectDirective | undefined {
  if (!beforeComment.startsWith(`${GCP_PROJECT_KEY}:`)) return undefined;
  const tokens = beforeComment.slice(GCP_PROJECT_KEY.length + 1).split(/\s+/).filter(Boolean);
  if (tokens.length === 0) {
    return { reason: `${GCP_PROJECT_KEY} needs a project id after the colon` };
  }
  if (tokens.length > 1) {
    return { reason: `${GCP_PROJECT_KEY} takes one project id; only a # comment may follow it` };
  }
  if (!isGcpProjectRef(tokens[0])) {
    return { reason: `${GCP_PROJECT_KEY} value is not a GCP project id or project number` };
  }
  return { projectId: tokens[0] };
}

export type GcpProjectSetting =
  | { line: number; projectId: string }
  | { line: number; reason: string };

/**
 * The `gcp.projectId` setting of a manifest, or undefined when it has none.
 * A second `gcp.projectId` line is an error: which of two projects was meant
 * is not something to guess.
 */
export function readGcpProjectSetting(content: string): GcpProjectSetting | undefined {
  let setting: GcpProjectSetting | undefined;
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const commentIdx = lines[i].indexOf('#');
    const beforeComment = (commentIdx !== -1 ? lines[i].slice(0, commentIdx) : lines[i]).trim();
    const directive = parseGcpProjectDirective(beforeComment);
    if (!directive) continue;
    if (setting) {
      return { line: i + 1, reason: `${GCP_PROJECT_KEY} is set twice (first on line ${setting.line}); keep one` };
    }
    setting = { line: i + 1, ...directive };
    if ('reason' in setting) return setting;
  }
  return setting;
}

/**
 * The manifests that may name the project for commands run in `startDir`,
 * nearest first: `startDir` and its parents up to the repository root (the
 * nearest directory holding `.git`). Outside a repository only `startDir`
 * itself is consulted, so a `.secretless` in a shared parent such as `/tmp`
 * or the home directory is never picked up by accident.
 */
export function projectManifestCandidates(startDir: string): string[] {
  const start = path.resolve(startDir);
  const dirs: string[] = [];
  for (let dir = start; ; dir = path.dirname(dir)) {
    dirs.push(dir);
    if (fs.existsSync(path.join(dir, '.git'))) break;
    if (path.dirname(dir) === dir) {
      dirs.length = 1;
      break;
    }
  }
  return dirs.map((dir) => path.join(dir, MANIFEST_FILENAME));
}

export type GcpProjectSource =
  | 'explicit'
  | 'manifest'
  | 'user-config'
  | 'service-account-key'
  | 'adc-quota-project'
  | 'none';

export interface GcpProjectResolution {
  /** Absent when no project could be resolved, or when `error` is set. */
  projectId?: string;
  source: GcpProjectSource;
  /** Where the project id was read, for display. Never a value. */
  from?: string;
  /**
   * Set when the repository's manifest names a project that cannot be used.
   * The backend refuses rather than falling back to another project.
   */
  error?: string;
}

export interface ResolveGcpProjectOptions {
  /** A project id passed in the backend config. Wins over everything. */
  explicit?: string;
  /** Directory commands run in. Default: the current working directory. */
  projectDir?: string;
  /** Service account key path from the backend config. */
  keyFilePath?: string;
}

export function resolveGcpProject(options: ResolveGcpProjectOptions = {}): GcpProjectResolution {
  if (options.explicit) {
    return { projectId: options.explicit, source: 'explicit', from: 'backend configuration' };
  }

  for (const manifest of projectManifestCandidates(options.projectDir ?? process.cwd())) {
    if (!isFile(manifest)) continue;
    let content: string;
    try {
      content = fs.readFileSync(manifest, 'utf-8');
    } catch (err) {
      return {
        source: 'manifest',
        from: manifest,
        error: `${manifest} could not be read, so the GCP project it may name is unknown (${(err as Error).message})`,
      };
    }
    const setting = readGcpProjectSetting(content);
    if (!setting) continue;
    const from = `${manifest} line ${setting.line}`;
    if ('reason' in setting) {
      return { source: 'manifest', from, error: `${from}: ${setting.reason}` };
    }
    return { projectId: setting.projectId, source: 'manifest', from };
  }

  const userConfig = path.join(os.homedir(), '.secretless-ai', 'config.json');
  try {
    const config = JSON.parse(fs.readFileSync(userConfig, 'utf-8')) as { gcp?: { projectId?: string } };
    if (config.gcp?.projectId) {
      return { projectId: config.gcp.projectId, source: 'user-config', from: `${userConfig} (gcp.projectId)` };
    }
  } catch {
    // No config or invalid JSON
  }

  const keyPath = options.keyFilePath ?? process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (keyPath) {
    try {
      const key = JSON.parse(fs.readFileSync(keyPath, 'utf-8')) as { project_id?: string };
      if (key.project_id) {
        return { projectId: key.project_id, source: 'service-account-key', from: `${keyPath} (project_id)` };
      }
    } catch {
      // Invalid key file
    }
  }

  const adcPath = path.join(os.homedir(), '.config', 'gcloud', 'application_default_credentials.json');
  try {
    const adc = JSON.parse(fs.readFileSync(adcPath, 'utf-8')) as { quota_project_id?: string };
    if (adc.quota_project_id) {
      return { projectId: adc.quota_project_id, source: 'adc-quota-project', from: `${adcPath} (quota_project_id)` };
    }
  } catch {
    // No ADC file
  }

  return { source: 'none' };
}

/** A GCP project a repository's `.secretless` named, and the line that named it. */
export interface RepositoryProject {
  projectId: string;
  from: string;
}

/**
 * The project a write to `backendName` lands in when this repository's
 * `.secretless` named it, rather than the machine's own settings. Undefined
 * for another backend or a project chosen any other way. Resolved from the
 * working directory, as the store's gcp-sm backend resolves it.
 */
export function repositoryProject(backendName: string): RepositoryProject | undefined {
  if (backendName !== 'gcp-sm') return undefined;
  const project = resolveGcpProject();
  return project.source === 'manifest' && project.projectId && project.from
    ? { projectId: project.projectId, from: project.from }
    : undefined;
}

/**
 * The line every write command prints BEFORE writing to a project the
 * repository named (#177). The manifest arrives with whatever repository was
 * cloned, so a write it sends to another project is said out loud before it
 * is made. Empty in every other case, which prints as before.
 */
export function repositoryProjectNote(backendName: string): string {
  const project = repositoryProject(backendName);
  return project ? describeRepositoryProject(project) : '';
}

/** The text of that line, for a caller that already holds the project. */
export function describeRepositoryProject(project: RepositoryProject): string {
  return `In GCP project ${project.projectId}, named by ${project.from}`;
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}
