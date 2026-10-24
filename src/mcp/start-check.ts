/**
 * Whether the secretless-mcp wrapper starts a server: the whole decision it
 * makes before it spawns one, in its order.
 *
 * `mcp-wrapper.ts` imports this module, so it imports only what the wrapper
 * already runs: the binding checks of the vault and the place checks of
 * discovery.
 */

import { checkLaunch } from './vault';
import type { McpBinding, McpLaunch, McpLaunchVerdict, McpVault } from './vault';
import { checkLaunchPlace } from './discover';
import type { McpPlaceVerdict } from './discover';

/**
 * What checkStart decided: the server starts with the pair's secrets, or the
 * check that refused it. `binding` is the pair's binding, for every check
 * after checkLaunch passed it. Names, paths and codes only: a line that reads
 * it never prints a value, an id or a digest.
 */
export type McpStartVerdict =
  /** It starts, and the wrapper gives it these secrets. */
  | { starts: true; binding: McpBinding; secrets: Record<string, string> }
  /** checkLaunch refused it: the entry carries no binding, or not the pair's, or another command. */
  | { starts: false; launch: Exclude<McpLaunchVerdict, { refused: false }> }
  /** checkLaunchPlace refused it, from the start directory. */
  | { starts: false; binding: McpBinding; place: Exclude<McpPlaceVerdict, { refused: false }> }
  /** No secret is stored under the pair, so nothing would be given to it. */
  | { starts: false; binding: McpBinding; empty: true };

/**
 * The checks the wrapper runs before it starts a server, in this order:
 * checkLaunch (the entry carries the pair's binding and its bound command),
 * then checkLaunchPlace (where it is started), then that a secret is stored
 * under the pair. The wrapper's main() calls it, and so does mcp-status for
 * each entry it reports, with its own directory as `startDir`, so the line
 * and the launch agree by construction. The secrets are read only after every
 * other check passed; mcp-status counts their names and drops them.
 */
export async function checkStart(
  vault: McpVault,
  launch: McpLaunch,
  options: { startDir?: string; home?: string } = {},
): Promise<McpStartVerdict> {
  const verdict = await checkLaunch(vault, launch);
  if (verdict.refused !== false) return { starts: false, launch: verdict };
  const place = checkLaunchPlace(verdict.binding, options);
  if (place.refused !== false) return { starts: false, binding: verdict.binding, place };
  const secrets = await vault.getServerSecrets(launch.client, launch.server);
  if (Object.keys(secrets).length === 0) return { starts: false, binding: verdict.binding, empty: true };
  return { starts: true, binding: verdict.binding, secrets };
}
