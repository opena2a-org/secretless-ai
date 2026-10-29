#!/usr/bin/env node

/**
 * secretless-mcp — Lightweight MCP server wrapper.
 *
 * Decrypts secrets from the Secretless vault, injects them as env vars,
 * and spawns the real MCP server. Designed to add <10ms overhead.
 *
 * A server is started only from the config entry `protect-mcp` bound the
 * pair's secrets to, with the command that entry had when it was bound: the
 * entry carries the binding's id (`--binding`), and the binding stored beside
 * the pair holds the id and the command's digest (see checkLaunch). A
 * project-level binding starts only in its project's directory or below it,
 * and no binding starts while another project-level config visible from the
 * start directory holds its id (see checkLaunchPlace).
 *
 * Usage:
 *   secretless-mcp --server <name> --client <client> --binding <id> [--vault-dir <path>] [--vault-key <key>] -- <command> [args...]
 *   secretless-mcp --version
 */

import { spawn } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import { McpVault, boundEntryName } from "./mcp/vault";
import type { McpLaunchVerdict } from "./mcp/vault";
import { resolveBackendType } from "./backends/config";
import { readWrapperArgv, wrapperFlag } from "./argv";
import { readWrapperVersion } from "./mcp/wrapper-version";
import { printedCommand } from "./printed-command";
import type { McpPlaceVerdict } from "./mcp/discover";
import { checkStart } from "./mcp/start-check";
import { listedName } from "./secret-value";
import { escapeForDisplay } from "./display-safe";

function parseArgs(argv: string[]): {
  server: string;
  client: string;
  vaultDir: string;
  vaultKey: string;
  backend: string;
  binding: string | undefined;
  childCommand: string;
  childArgs: string[];
} | null {
  // Normalise before parsing, so `--server=NAME` binds here exactly as it does
  // in the CLI. Without it every flag below is dropped on the equals spelling:
  // `--vault-dir=/path` silently falls back to the DEFAULT vault and
  // `--backend=1password` silently falls back to the configured backend, so the
  // wrapper reads credentials from somewhere other than where it was told to.
  // The child command after `--` is left untouched. protect-mcp and
  // mcp-status read an entry's args with the same function.
  const read = readWrapperArgv(argv);

  // `!== undefined`, not truthiness: `--server ''` is the flag WITH an empty
  // value. Read as "flag absent" it produced an empty server name, and an
  // empty name looks up no secrets — so the wrapper spawned the MCP server
  // with none of its credentials and said nothing. Same shape as #110.
  const server = wrapperFlag(read, "--server") ?? "";
  const client = wrapperFlag(read, "--client") ?? "";
  let vaultDir = wrapperFlag(read, "--vault-dir") ?? "";
  let vaultKey = wrapperFlag(read, "--vault-key") ?? "";
  for (const val of read.values.get("--backend") ?? []) {
    if (
      val !== "local" &&
      val !== "keychain" &&
      val !== "1password" &&
      val !== "vault" &&
      val !== "gcp-sm"
    ) {
      process.stderr.write(
        `secretless-mcp: Unknown backend: ${val}. Use 'local', 'keychain', '1password', 'vault', or 'gcp-sm'.\n`,
      );
      process.exit(1);
    }
  }
  const backend = wrapperFlag(read, "--backend") ?? "";

  if (read.child === undefined) return null;

  // `--vault-dir` and `--vault-key` choose the encrypted file for `local`: given
  // either, the store has a key, this one when `--vault-key` gives none. Given
  // neither, the store has no key and is built as `protect-mcp` builds it, so
  // for `local` both read and write one store: with no backend configured,
  // the OS keychain where one is available, and otherwise the encrypted file.
  // A key here made `local` the file while `protect-mcp` stored in the
  // keychain, and a server it protected found none of its secrets (#513).
  const home = os.homedir();
  if (vaultDir && !vaultKey)
    vaultKey = `${home}-secretless-${process.env.USER ?? "default"}`;
  if (!vaultDir) vaultDir = path.join(home, ".secretless-ai", "mcp-vault");

  return {
    server,
    client,
    vaultDir,
    vaultKey,
    backend,
    binding: wrapperFlag(read, "--binding"),
    childCommand: read.child.command,
    childArgs: read.child.args,
  };
}

const USAGE =
  "Usage: secretless-mcp --server <name> --client <client> -- <command> [args...]";

/** `command` as the lines below name it: for the build this wrapper copy is (see printed-command.ts). */
function cliCommand(command: string): string {
  return printedCommand(command, readWrapperVersion(__dirname));
}

/** The line every refusal of checkLaunch ends with: what to look at, then what to run. */
const bindingFix = (): string =>
  `secretless-mcp: Run '${cliCommand("mcp-status")}' to see which config entries are bound, then '${cliCommand("protect-mcp")}' to bind the entries it protected.\n`;

/**
 * Print why checkLaunch refused this launch, then the fix line, and exit 1
 * with nothing started. Names, paths and the store's name only: never a
 * value, an id or a digest.
 */
async function refuseLaunch(
  verdict: Exclude<McpLaunchVerdict, { refused: false }>,
  client: string,
  server: string,
  vault: McpVault,
): Promise<never> {
  const entry = `client "${listedName(client)}", server "${listedName(server)}"`;
  switch (verdict.refused) {
    case "entry-not-bound":
      process.stderr.write(
        `secretless-mcp: The config entry for ${entry} is not bound to its stored secrets, so no secret was read. The server was not started.\n`,
      );
      break;
    case "no-binding-stored": {
      const store = vault.backendName;
      process.stderr.write(
        `secretless-mcp: No binding for ${entry} is stored in the ${store} backend, so no secret was read. The server was not started.\n`,
      );
      const pairs = await storedPairs(vault);
      if (pairs !== null) {
        process.stderr.write(
          pairs.length > 0
            ? `secretless-mcp: Stored client/server pairs: ${pairs.join(", ")}\n`
            : `secretless-mcp: The ${store} backend holds no MCP server secrets.\n`,
        );
      }
      break;
    }
    case "other-binding":
      process.stderr.write(
        `secretless-mcp: The binding in the config entry for ${entry} does not match the one stored for its secrets, which belongs to ${boundEntryName(verdict.binding)}, so no secret was read. The server was not started.\n`,
      );
      break;
    case "other-command":
      process.stderr.write(
        `secretless-mcp: The command or arguments in the config entry for ${entry} are not the ones its stored secrets were bound to, so no secret was read. The server was not started.\n`,
      );
      break;
  }
  process.stderr.write(bindingFix());
  process.exit(1);
}

/**
 * Print why checkLaunchPlace refused this launch, then the fix line, and exit
 * 1 with nothing started. Names and paths only: never the id.
 */
function refusePlace(
  verdict: Exclude<McpPlaceVerdict, { refused: false }>,
  client: string,
  server: string,
  scope: "home" | "project",
): never {
  const entry = `client "${listedName(client)}", server "${listedName(server)}"`;
  process.stderr.write(`secretless-mcp: ${placeRefusal(verdict, entry, scope)}\n`);
  process.stderr.write(bindingFix());
  process.exit(1);
}

/**
 * The fix for a home binding found in a copy: protect-mcp run in the
 * directory this entry was started in, which replaces the binding, so no copy
 * found from there starts; then the copy removed. In this order: removing the
 * copy first leaves the binding as it was.
 */
const HOME_COPY_FIX = (startDir: string): string =>
  `Run '${cliCommand("protect-mcp")}' in ${listedName(startDir)}: it replaces the binding, so no copy found from there starts. Then remove that copy.`;

/** The directory this process was started in, resolved as checkLaunchPlace resolves it. */
function startDirectory(): string {
  try {
    return fs.realpathSync(process.cwd());
  } catch {
    return process.cwd();
  }
}

/** The line that says why checkLaunchPlace refused a launch, for a binding of `scope`. */
function placeRefusal(
  verdict: Exclude<McpPlaceVerdict, { refused: false }>,
  entry: string,
  scope: "home" | "project",
): string {
  const notStarted = "so no secret was read. The server was not started.";
  switch (verdict.refused) {
    case "outside-project":
      return `The secrets stored for ${entry} are bound to the project in ${listedName(verdict.project)}, and this entry was started in ${listedName(verdict.startDir)}, ${notStarted}`;
    case "project-unresolved":
      return `The secrets stored for ${entry} are bound to the project in ${listedName(verdict.project)}, and ${listedName(verdict.path)} could not be resolved (${verdict.code}), ${notStarted}`;
    case "start-unresolved":
      return `The directory the entry for ${entry} was started in could not be resolved (${verdict.code}), ${notStarted}`;
    case "copy-found": {
      // protect-mcp replaces a home binding; a project binding's copy is removed.
      const fix = scope === "home" ? HOME_COPY_FIX(startDirectory()) : "Remove that copy.";
      return `The binding of the secrets stored for ${entry} also appears in ${listedName(verdict.file)}, and a bound entry starts only from the config protect-mcp bound it in, ${notStarted} ${fix}`;
    }
    case "copy-unchecked":
      return `${listedName(verdict.file)} could not be checked for a copy of the binding of the secrets stored for ${entry} (${verdict.why}), ${notStarted}`;
  }
}

/**
 * The client/server pairs the store holds secrets for, sorted, each as
 * listedName writes it, or null when they could not be listed. Names only,
 * never values: a hint beside a refusal, which stands without it.
 */
async function storedPairs(vault: McpVault): Promise<string[] | null> {
  try {
    return (await vault.listEntries())
      .map((e) => `${e.client}/${e.server}`)
      .sort()
      .map(listedName);
  } catch {
    return null;
  }
}

async function main(): Promise<void> {
  const rawArgs = process.argv.slice(2);
  // Only the wrapper's own arguments, the ones before `--`, can ask for help or
  // the version. Everything after `--` belongs to the MCP server: read from the
  // whole argv, a server started as `-- mcp-server -h <host>` printed this usage
  // and exited 0 instead of starting.
  const separator = rawArgs.indexOf("--");
  const ownArgs = separator === -1 ? rawArgs : rawArgs.slice(0, separator);
  if (ownArgs.includes("--help") || ownArgs.includes("-h")) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  // `protect-mcp` copies this bin to a stable directory and MCP configs point
  // at the copy, which does not update with the package: the version is how an
  // installed copy says which build it is.
  if (ownArgs.includes("--version") || ownArgs.includes("-v")) {
    process.stdout.write(`secretless-mcp ${readWrapperVersion(__dirname)}\n`);
    return;
  }
  const args = parseArgs(rawArgs);

  if (!args) {
    process.stderr.write(`secretless-mcp: ${USAGE}\n`);
    process.exit(1);
  }

  // Refuse rather than spawn an unprotected child. An empty server or client
  // name matches no vault entry, so the wrapper would hand the MCP server an
  // environment with none of the credentials it was installed to inject — and
  // the server would start anyway, looking installed and doing nothing. The
  // whole point of this bin is that the child gets its secrets; if we cannot
  // say which secrets those are, not starting is the safe answer.
  if (!args.server || !args.client) {
    const missing = [!args.server && "--server", !args.client && "--client"]
      .filter(Boolean)
      .join(" and ");
    process.stderr.write(
      `secretless-mcp: ${missing} must be given a non-empty value. The server was not started.\n`,
    );
    process.stderr.write(`secretless-mcp: ${USAGE}\n`);
    process.exit(1);
  }

  // Resolve backend: explicit --backend flag > config file > default ('local').
  // This ensures that switching backends via `backend set 1password` applies
  // to existing MCP configs that were written without a --backend flag.
  const backendType = args.backend || resolveBackendType();

  // Validate vault directory exists (only needed for local backend)
  if (backendType === "local") {
    if (!fs.existsSync(args.vaultDir)) {
      process.stderr.write(
        `secretless-mcp: Vault directory not found: ${listedName(args.vaultDir)}\n`,
      );
      process.stderr.write(
        `secretless-mcp: Run '${cliCommand("protect-mcp")}' to set up MCP secret protection.\n`,
      );
      process.exit(1);
    }
  }

  // Load secrets from vault
  let secrets: Record<string, string> = {};
  let vault: McpVault;
  try {
    vault = new McpVault({
      storeDir: args.vaultDir,
      ...(args.vaultKey ? { key: args.vaultKey } : {}),
      backendType,
    });
    // Before a value is read: this entry carries the id of the binding
    // protect-mcp stored for the pair, and starts the command that entry was
    // bound with. An entry another file supplies, such as a project's
    // .mcp.json that came with a repository, carries no id this machine's
    // protect-mcp wrote, and a changed command does not match the digest.
    // Then where it was started: a project-level binding only in its
    // project's directory or below it, and no other project-level config
    // visible from that directory holds its id. checkStart runs these
    // checks in this order, and mcp-status runs the same function.
    const start = await checkStart(vault, {
      client: args.client,
      server: args.server,
      binding: args.binding,
      command: args.childCommand,
      args: args.childArgs,
    });
    if ("launch" in start) {
      await refuseLaunch(start.launch, args.client, args.server, vault);
      return;
    }
    if ("place" in start) refusePlace(start.place, args.client, args.server, start.binding.scope);
    // An empty pair reaches the refusal below with no secrets.
    if (start.starts) secrets = start.secrets;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      `secretless-mcp: Failed to load secrets for ${listedName([args.client, args.server].join("/"))}: ${escapeForDisplay(msg)}\n`,
    );
    process.stderr.write(
      `secretless-mcp: Run '${cliCommand("mcp-unprotect")}' to restore original configs.\n`,
    );
    process.exit(1);
  }

  // `protect-mcp` rewrites a server to run through this bin only after moving
  // at least one secret of its into the vault, so a protected pair always has
  // secrets. None for this pair means it names nothing that was protected: a
  // typo, a client that is not a real client, or a vault in another backend.
  // Starting the child would run it with none of its credentials while the
  // config still reads as protected, so refuse, as for an empty name, and say
  // which pairs do exist (names only, never values). The backend is named as
  // built: `local` with no key is the OS keychain while no backend is configured.
  if (Object.keys(secrets).length === 0) {
    const store = vault.backendName;
    process.stderr.write(
      `secretless-mcp: No secrets are stored for client "${listedName(args.client)}", server "${listedName(args.server)}" in the ${store} backend. The server was not started.\n`,
    );
    // Listing is a hint; the refusal above stands without it.
    const pairs = await storedPairs(vault);
    if (pairs !== null) {
      process.stderr.write(
        pairs.length > 0
          ? `secretless-mcp: Stored client/server pairs: ${pairs.join(", ")}\n`
          : `secretless-mcp: The ${store} backend holds no MCP server secrets.\n`,
      );
    }
    process.stderr.write(
      `secretless-mcp: Run '${cliCommand("mcp-status")}' to list protected servers, or '${cliCommand("protect-mcp")}' to protect this one.\n`,
    );
    process.exit(1);
  }

  // Merge secrets into env (secrets override existing env vars)
  const childEnv = { ...process.env, ...secrets };

  // Spawn the real MCP server
  const child = spawn(args.childCommand, args.childArgs, {
    env: childEnv,
    stdio: ["inherit", "inherit", "inherit"],
  });

  // Forward signals
  const signals: NodeJS.Signals[] = ["SIGTERM", "SIGINT", "SIGHUP"];
  for (const sig of signals) {
    process.on(sig, () => child.kill(sig));
  }

  // Forward exit code
  child.on("close", (code) => {
    process.exit(code ?? 1);
  });

  child.on("error", (err) => {
    process.stderr.write(
      `secretless-mcp: Failed to start ${args.childCommand}: ${err.message}\n`,
    );
    process.stderr.write(
      `secretless-mcp: Run '${cliCommand("mcp-unprotect")}' to restore original configs.\n`,
    );
    process.exit(1);
  });
}

main();
