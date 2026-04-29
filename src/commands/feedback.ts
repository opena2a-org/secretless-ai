/**
 * `secretless-ai feedback` — opt-in star/feedback subcommand.
 *
 * Background: prior to 0.16.4, every `init` invocation printed the
 * "Helpful? Star the project" line. That conflated the operational
 * outcome with marketing fluff and violated the "no dead ends" rule
 * (the only place a user could act on the line was their browser).
 *
 * The redesign moved the marketing ask out of the per-action output
 * and into a one-command opt-in. Users who want to leave feedback
 * run `secretless-ai feedback`; everyone else gets clean output.
 */

import { c } from './colors';

export function runFeedback(): number {
  console.log();
  console.log(`  ${c.boldWhite('Secretless feedback')}`);
  console.log();
  console.log('  Helpful? Star the project:  https://github.com/opena2a-org/secretless-ai');
  console.log('  Feedback / issues:          https://github.com/opena2a-org/secretless-ai/issues/new');
  console.log('  Discussions:                https://github.com/opena2a-org/secretless-ai/discussions');
  console.log();
  console.log('  Thanks — every issue and discussion sharpens the tool.');
  console.log();
  return 0;
}
