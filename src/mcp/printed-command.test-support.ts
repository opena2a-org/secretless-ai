import { VERSION } from '../commands/utils';

/**
 * A command as the tests expect a line to name it. The CLI run in the test
 * process, from its source, names this build's exact version for npx; the
 * built CLI and wrapper under dist/ name the same. printed-commands.test.ts
 * holds the forms themselves to their cases.
 */

/** `command` as the CLI's source, run in the test process, prints it. */
export function sourceCommand(command: string): string {
  return `npx secretless-ai@${VERSION} ${command}`;
}

/** `command` as the built CLI and wrapper under dist/ print it. */
export function builtCommand(command: string): string {
  return `npx secretless-ai@${VERSION} ${command}`;
}
