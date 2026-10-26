/**
 * The command a line tells its reader to run, where the line promises what
 * this build does: the wrapper's refusals and the lines `protect-mcp` and
 * `mcp-status` print. Run without a version, npx starts the first copy npm
 * finds (the project's node_modules/.bin, npm's global bin, then any version
 * in the project or the global tree), which may be an earlier build that does
 * none of it. So the command names this build: its exact version, which npx
 * runs only from a copy whose package id is that version, and the unversioned
 * form only when the version is not an exact one, as for a wrapper copy that
 * records none.
 *
 * The wrapper loads this module from the copy of `dist/` that protect-mcp
 * installs, which has no package.json above it, so it stays a leaf: no
 * package-relative require (see `argv.ts`), and the version is the caller's
 * (`VERSION` in the CLI, `readWrapperVersion` in the wrapper).
 */

/**
 * Whether `version` names one exact release, the only version a shell line
 * carries: a range, a tag or anything else does not.
 */
export function isExactVersion(version: string): boolean {
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version);
}

/** `command` as a line names it for the build whose version is `version`. */
export function printedCommand(command: string, version: string): string {
  if (isExactVersion(version)) return `npx secretless-ai@${version} ${command}`;
  return `npx secretless-ai ${command}`;
}
