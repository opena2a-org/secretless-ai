import * as path from 'path';
import { VERSION } from '../commands/utils';
import { printedCommand } from '../printed-command';

/**
 * A command as the tests expect a line to name it. The CLI run in the test
 * process, from its source, has no cli.js beside the renderer, so it names
 * this build's exact version for npx; the built CLI and wrapper under dist/
 * name the node binary and dist/cli.js as two quoted paths.
 * printed-command.test.ts and printed-commands.test.ts hold each form to its
 * case.
 */

const CLI_PATH = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');

/** `command` as the CLI's source, run in the test process, prints it. */
export function sourceCommand(command: string): string {
  return `npx secretless-ai@${VERSION} ${command}`;
}

/** `command` as the built CLI and wrapper under dist/ print it, started with this process's PATH. */
export function builtCommand(command: string): string {
  return printedCommand(command, VERSION, { script: CLI_PATH });
}
