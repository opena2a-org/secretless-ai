# I want to protect MCP server credentials

**Time:** 3 minutes
**Prerequisites:** Node.js 20.19+, at least one MCP client configured

MCP (Model Context Protocol) client configs often hold API keys in plaintext JSON. The client application reads the config to start each server. The model sees a key only if an assistant reads the file, and any assistant that can read files on your machine can read it.

## Where MCP credentials live

Each AI tool stores MCP server configs in a different location. `protect-mcp` and `mcp-status` look in these paths, under your home directory (`~`) and under the directory you run them in:

| Client | Home directory | Project |
|--------|----------------|---------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `~/.config/Claude/claude_desktop_config.json` (Linux) | |
| Claude Code | `~/.claude.json`, `~/.claude/settings.json`, `~/.claude/settings.local.json` | `.mcp.json` |
| Cursor | `~/.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code | `~/.vscode/mcp.json` | `.vscode/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json` | `.windsurf/mcp.json` |

They read `mcp.json` in the project too. Which client writes a bare `mcp.json` is not established, so it is shown by its path alone, as `scan` shows it. When neither command finds a config, it lists every path it looked in.

Claude Code keeps its user-scope servers at the top level of `~/.claude.json` and its local-scope servers under `projects`, one entry for each project path. Both commands read the servers at the top level and those of each project, and `mcp-status` lists a project's servers under a heading that names the project, such as `claude-code (/Users/you/.claude.json, project /Users/you/app)`.

`protect-mcp` stores the secrets of each server under its client and server name, and a protected server reads them back by that name. When two servers of one client have the same name, as a user-scope and a local-scope server can, `protect-mcp` protects the one it reads first and leaves the other as it is, listed as `not protected` with the config of the server whose name it shares. It reads the top level of `~/.claude.json` before its projects, and your home directory before the project. A server is left the same way when a server protected in an earlier run reads its secrets by that name. It is left the same way when a protected server in a project-level config that `protect-mcp` does not rewrite, such as `.cursor/mcp.json` in the project, reads its secrets by that name. `protect-mcp` stores the secrets of a server that does not yet run through the wrapper only under a name that holds no stored secret, or holds only the server's own, the same `env` names with the same values, and a value from a project-level config, `.mcp.json` included, only under a name that holds no stored secret. Otherwise it leaves the server as it is and lists it under `secrets not moved`, with a reason that names the client and server name and the `env` names stored under it, never a value. The store takes only `A-Z`, `a-z`, `0-9`, `-` and `_` in a name, so a server with another character in its name, such as `my.server`, is left as it is and listed as `not protected` with that reason, and `protect-mcp` goes on to the next server.

A project-level config is usually committed with the repository. `protect-mcp` rewrites `.mcp.json` and leaves the other project-level configs as they are, because the wrapper path it writes belongs to one machine. It lists them as not checked, and `mcp-status` shows their servers. An entry in one of those configs that runs through the wrapper is never bound. The wrapper refuses a bound entry while a project-level config other than the one its binding was made in, in the start directory or a directory above it, holds that binding, so a copy in one of those configs does not start from its project, and `mcp-status` names each. An entry bound in `.mcp.json` starts only in that project's directory or below it. In `.mcp.json`, `protect-mcp` binds an entry an earlier version protected only to secrets its first backup of the file holds, and binds an entry again after its command or arguments change only when it stores the entry's values. A copy of the project in another directory does not start an entry bound in `.mcp.json`, and the refusal names the project directory the secrets are bound to.

A typical MCP config looks like this:

```json
{
  "mcpServers": {
    "browserbase": {
      "command": "npx",
      "args": ["-y", "@browserbasehq/mcp-server"],
      "env": {
        "BROWSERBASE_API_KEY": "sk-bb-live-abc123...",
        "BROWSERBASE_PROJECT_ID": "proj-456..."
      }
    }
  }
}
```

The `BROWSERBASE_API_KEY` value is stored in plaintext. The client application reads this config to start the MCP server and passes the key to it as an environment variable. Any assistant that can read files on your machine can read the key from the same file.

## Step 1: Encrypt MCP credentials

```bash
npx secretless-ai protect-mcp
```

Expected output:

```
  Secretless MCP Protection

  Scanned 1 client(s)

  + claude-desktop/browserbase
      BROWSERBASE_API_KEY (encrypted)
  + claude-desktop/github
      GITHUB_PERSONAL_ACCESS_TOKEN (encrypted)
  + claude-desktop/stripe
      STRIPE_SECRET_KEY (encrypted)

  3 secret(s) encrypted across 3 server(s).

  Protected servers start as before.
  Run `npx secretless-ai mcp-status` to check status anytime.
  Run `npx secretless-ai mcp-unprotect` to restore originals.
```

Secretless moves each secret value into your configured storage backend and replaces the plaintext value in the JSON config with a reference. The MCP server still starts normally because secretless injects the real value at launch time.

Non-secret environment variables (URLs, project IDs, region identifiers) are left untouched.

## Step 2: Verify protection

```bash
npx secretless-ai verify
```

Expected output includes MCP-specific entries:

```
  Checking protections...

  MCP: claude-desktop/browserbase
    BROWSERBASE_API_KEY        encrypted, stored in local backend
  MCP: claude-desktop/github
    GITHUB_PERSONAL_ACCESS_TOKEN  encrypted, stored in local backend

  All secrets protected.
```

## Step 3: Check MCP status

To see which MCP servers are protected and which still have plaintext credentials:

```bash
npx secretless-ai mcp-status
```

Expected output:

```
  Secretless MCP Status

  Backend: keychain-macos

  claude-desktop (/Users/you/Library/Application Support/Claude/claude_desktop_config.json)
    + browserbase: protected and bound
    + github: protected and bound
    + stripe: protected and bound

  All protected servers use the keychain-macos backend for secret storage.
```

`Backend:` names where the secrets are stored. A server that still has a plaintext secret is listed as `! <name>: EXPOSED (1 plaintext secret(s))`, and a server with no secret in its `env` as `* <name>: clean (no secrets in env)`.

A server listed as `+ <name>: protected and bound` runs through the wrapper, no secret was found in its `env`, and the wrapper starts it: `protect-mcp` bound the secrets it stored to that config entry and to the command the entry starts. The wrapper reads a server's secrets only for that entry, started with that command. Another entry that reads them by the same client and server name, or the same entry after its command or arguments change, is refused, and nothing is started. So is a bound entry while a project-level config other than its own, in the directory it is started in or a directory above it, holds its binding, and an entry bound in `.mcp.json` started outside that project's directory; `protect-mcp` replaces a home binding it finds in a copy of its entry, so the copy no longer starts. `mcp-status` marks such an entry with `?` and says why the wrapper does not start it; `npx secretless-ai protect-mcp` binds the entries it protected and names each entry it cannot bind, and why. The wrapper does not take a value out of the file, so a secret added to the `env` of such a server after `protect-mcp` rewrote it lists the server as `EXPOSED`. Run `npx secretless-ai protect-mcp` again to move the value into the backend, under the name the wrapper reads its secrets by. It leaves the value in place and names the server when the client or server name the wrapper reads by is empty or holds a character other than `A-Z`, `a-z`, `0-9`, `-` or `_`, which the store refuses, and the wrapper does not start a server by such a name either; when another protected server in a config it reads, a project-level one it does not rewrite included, reads its secrets by the same name; when another value is stored there under the same `env` name, since the wrapper gives the server the stored value; when the server's arguments give `--vault-dir` or `--vault-key`; or when its wrapper reads from another store than the one `protect-mcp` stores in, and the reason names that store. The wrapper reads from the backend its `--backend` argument names, or the configured backend when it gives none, and builds it as `protect-mcp` does, so with no backend configured `local` is the OS keychain where one is available for both. With `--vault-dir` or `--vault-key` in its arguments, the wrapper reads `local` from the encrypted file. For a server in the project's `.mcp.json`, `protect-mcp` also leaves the value in place when any secret is already stored under that name, since it stores a value from a project-level config only under a name that holds no stored secret.

## Using a different storage backend

With no backend configured, secrets are stored in the OS keychain where one is available (macOS Keychain, or Linux Secret Service when `secret-tool` is installed), and otherwise in an AES-256-GCM encrypted local file. `npx secretless-ai backend set local` selects the encrypted file on any platform. To use a team-friendly backend:

```bash
npx secretless-ai protect-mcp --backend 1password
npx secretless-ai protect-mcp --backend keychain
npx secretless-ai protect-mcp --backend vault
npx secretless-ai protect-mcp --backend gcp-sm
```

On the `gcp-sm` backend, each secret of a server is a secret in the GCP project named after its client, server and env name: `GITHUB_TOKEN` of the `github` server in Cursor is `mcp--cursor--github--GITHUB__TOKEN`. Letters and digits are kept, `_` is written `__`, and each UTF-8 byte of any other character is written as `_` and two hex digits, so `-` is `_2D`. The secret carries the label `secretless-ai=store-key`, and the wrapper gives a server only the labelled secrets under its own client and server name, never another secret in the project. `protect-mcp` adds a version only to a secret that carries the label, so it never writes to a secret of that name that it did not create; it stops and prints the `gcloud` command that shows that secret. A server protected on `gcp-sm` by secretless-ai 0.23.0 or earlier is protected again with `npx secretless-ai mcp-unprotect`, then `npx secretless-ai protect-mcp --backend gcp-sm`.

A pair stored in a backend several machines read (1password, vault, gcp-sm) can be read from another machine; the OS keychain and the encrypted local file are this machine's alone. On a backend several machines read, a stored server name belongs to one config entry: `protect-mcp` on a second machine leaves a server whose client and server name is already bound to another entry, names that entry, and says to rename the server and run `protect-mcp` again. Each developer protects the configs on their own machine, against the one shared backend.

## Restoring original configs

If you need to revert to the original plaintext configs (for example, before uninstalling secretless):

```bash
npx secretless-ai mcp-unprotect
```

Secretless keeps a backup of the original config file and restores it exactly as it was. It writes back the whole file, so a change made to the file after `protect-mcp` rewrote it, such as a server added to `~/.claude.json` since, is undone as well. A later `protect-mcp` run that rewrites the file while a server in it runs through the wrapper keeps that backup, so the file is restored as it was before the first run, and the secrets the later run moved stay in the backend. A run that rewrites the file when no server in it runs through the wrapper, as after `mcp-unprotect` restored it, backs it up as it is then.

## What happened

The `protect-mcp` command did three things:

1. **Scanned** all known MCP client config paths on your machine
2. **Identified** environment variables that contain secrets (API keys, tokens) versus non-secrets (URLs, IDs)
3. **Moved** secret values to encrypted storage and replaced them with references in the config file

The MCP servers continue to work because secretless resolves the references at server start time.

## Next steps

- [Protect My Credentials](protect-my-credentials.md): Block AI tools from reading all credential files
- [Team Setup](team-setup.md): Share one secret backend across your team, and protect each developer's MCP configs on their own machine
- [Migrate from .env](migrate-from-dotenv.md): Move .env file secrets into the same backend
