# Store and use secrets

How to put a key in a storage backend, use it by name, record what it is for, move it to another machine, track it after an exposure, hand it to git and push it to a cloud secret store.

## Store secrets and use them in AI sessions

Move keys out of files and into a storage backend, then use them by name: commands and AI tools see the name, and the value goes to the process that uses it. Two ways a value still gets out are described below: `secret set NAME=VALUE` puts it in shell history, and a command whose own output is a credential puts it in AI context (see [What the guard cannot see](#what-the-guard-cannot-see)).

```bash
npx secretless-ai secret set STRIPE_SECRET_KEY --from-clipboard   # key copied from a web page
npx secretless-ai secret set STRIPE_SECRET_KEY   # or type or paste it at a prompt, input hidden
npx secretless-ai import .env                    # or migrate an existing .env in one step
npx secretless-ai secret list                    # names only, values are never printed
```

`--from-clipboard` is the recommended way to store a key copied from a web dashboard. It reads the clipboard through `pbpaste` (macOS), `wl-paste`, `xclip` or `xsel` (Linux) or `Get-Clipboard` (Windows), so the value never appears on the command line, the screen or in shell history, and it prints only the value's length and character classes. After storing it, it clears the clipboard, unless the clipboard changed since it was read or `--keep-clipboard` is given. An empty clipboard or a missing clipboard tool stores nothing and exits 1. `secret set NAME=VALUE` puts the value in shell history, and `pbpaste | secret set NAME` leaves it in the clipboard.

On a terminal, `secret set` then asks whether to add a shell hook to `~/.zshenv` or `~/.bashrc` that runs `secretless-ai env` by the full path of node and of the copy that ran `secret set`, so new terminals export every stored secret as an environment variable, with or without a global install. The default answer is no. `--no-shell-hook` skips the question, and when stdin or stderr is not a terminal, as when the value is piped in, the profile is left as it is. When `secretless-ai` is not on PATH, `secret set` prints that path; if that copy is removed (clearing the npm cache removes an npx copy), the next `secret set` in a terminal asks to point the hook at the copy running it. To inject one secret into a single command instead of the whole shell:

```bash
npx secretless-ai run --only STRIPE_SECRET_KEY -- node charge.js
```

The command reads the value from its environment. `run` refuses to start a command whose arguments carry a stored value of eight or more characters, verbatim or URL-encoded, because `ps` shows a process's arguments to every local process; for `psql`, store the password as `PGPASSWORD` and pass host, user and database as arguments. `--allow-argv` starts it anyway, with a warning.

Reading a value back is TTY-gated: `secret get NAME` prints it in an interactive terminal, but is blocked in piped or AI-driven contexts unless `--force` is passed. Where one of the variables an AI agent sets in the commands it runs holds a value (`CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CURSOR_TRACE_ID` or `AIDER_MODEL`), `secret get --force` is refused and prints no value, as are `env` and `export`; `run --only NAME -- <command>` still passes the value to the one command. `init` installs deny rules so AI tools cannot run the `--force` form or dump an injected environment (`run -- env`).

### Record what a credential is for

A value alone does not say which app it belongs to or what it may do. `secret set` takes a description and repeatable `--meta key=value` fields, and `secret show` reads them back without the value:

```bash
npx secretless-ai secret set LINKEDIN_CLIENT_SECRET \
  --description "Client secret, marketing agent app" \
  --meta provider=linkedin --meta app=marketing_agent \
  --meta scopes=r_basicprofile,w_member_social --meta tokenTtl=5184000
npx secretless-ai secret show LINKEDIN_CLIENT_SECRET      # description and metadata, never the value
npx secretless-ai secret list --long --app marketing_agent  # every entry recorded for one app
```

Descriptions and metadata are not secrets. They are kept in plain text beside the store (`~/.secretless-ai/secret-annotations.json`) and printed by `secret show` and `secret list --long`; neither command prints a value, and neither is blocked by the deny rules `init` installs. `set` refuses a description or field that contains the value or looks like a credential. Keys are free-form; `app`, `provider`, `scopes`, `tokenTtl`, `redirectUri` and `expiresAt` are conventions, not a schema. `--meta key=` removes a field, `set` without either flag keeps what was recorded, and `secret rm` removes both. `secret list --json` and `secret show --json` include the same fields.

### Move secrets to another machine

A keychain or local store cannot be copied as a file. `export` writes the stored secrets into one bundle encrypted with a passphrase (scrypt, AES-256-GCM); `import` on the other machine stores them in that machine's backend:

```bash
npx secretless-ai export --out team.secretless-bundle            # add --only K1,K2 for a subset
npx secretless-ai import team.secretless-bundle                  # on the other machine
```

The passphrase is asked for in the terminal, or read from `SECRETLESS_EXPORT_PASSPHRASE`; it is never accepted as an argument, and no value is printed. `import` writes nothing when the passphrase is wrong or a name already exists (`--force` replaces it), then reads each name back from the store and reports whether all of them resolve. The bundle also carries the `required` flag and description from the exporting project's `.secretless`. `scan` and `scan-staged` flag a `*.secretless-bundle` file, `clean` redacts a bundle printed into a transcript, and `verify` fails while one is in a recent transcript. Delete the bundle on both machines once it is imported. `export` refuses to run inside an AI agent session.

### Track an exposed key until it is rotated

Redacting a transcript does not revoke a key. When a stored value has been pasted into a chat, shown on screen or committed, record it, and the record stays open until the stored value changes:

```bash
npx secretless-ai secret exposed OPENAI_API_KEY --where "pasted into a chat"   # --at 2026-10-07 for an earlier date
npx secretless-ai secret list --needs-rotation          # exits 1 while any exposure is open (--json for CI)
npx secretless-ai secret set OPENAI_API_KEY             # the new value from the provider closes it
```

The record is `exposedAt` and `exposedWhere` in the secret's metadata, never the value. `secret set` compares the new value with the stored one in memory: a different value closes the exposure and records `rotatedAt`; the same value leaves it open and says so. When `clean` or `watch` redacts a value equal to a stored secret, it marks that secret exposed and prints its name and the next step. `status` shows the open count.

### Give git a stored token over HTTPS

A hosting token in `~/.git-credentials` or `~/.netrc` sits on disk in plaintext. `status` flags each of those files (count and line numbers, never values) and a `credential.helper` set to `store` on a row that points to `doctor`, which prints Verify and Fix lines for each; `status --json` carries the same lines in `gitCredentials.findings`. To keep the token in the store and let git read it from there:

```bash
npx secretless-ai secret set GITHUB_TOKEN
npx secretless-ai git-credential install --host github.com --name GITHUB_TOKEN   # [--username <user>]
npx secretless-ai git-credential uninstall --host github.com                     # removes only what install added
```

`install` adds two entries to `credential.https://github.com.helper` in the global git config: an empty one, which stops git asking any helper configured before it (such as `store`) for that host, and the helper itself. The helper names the node binary and CLI file of the copy that ran `install`, or `npx --yes secretless-ai@<version>` with `npm_config_offline=true` when that copy's paths cannot be resolved; the pre-commit hook and the Claude Code Stop hook are written the same way. Re-run `install` if either path moves. No value is written to any config file. Git runs the helper as `git-credential get`, which answers only HTTPS requests for its host and refuses when stdin or stdout is a terminal; `store` and `erase` write nothing. `init` blocks an AI tool from running `git-credential get` or `git credential fill`, which would print the token.

### Ask your AI assistant to use a secret

After `init`, the assistant's instruction file (`CLAUDE.md`, `.cursor/rules/secretless.mdc`, ...) lists which keys are available as environment variables and tells the tool to reference them as `$VAR_NAME` without reading values. So this works in Claude Code:

> Call the Stripe API and list the last 5 charges.

Claude writes the command with a variable reference. The shell substitutes the value inside the subprocess; nothing enters the model's context:

```bash
curl -s "https://api.stripe.com/v1/charges?limit=5" -H "Authorization: Bearer $STRIPE_SECRET_KEY"
```

For a key stored after `init`, or one `init` doesn't recognize, name the variable in your prompt ("use `$GAMMA_API_KEY` for auth") or add a row to the key table in `CLAUDE.md`. To keep the assistant away from raw values entirely, ask it to run commands under the injector:

> Run the deploy script with `secretless-ai run --only DEPLOY_TOKEN -- ./deploy.sh`.

### What the guard cannot see

The hook and the deny rules check a command before it runs, by its text and the local paths it names. Neither can see what the command prints. A command that returns credential values (`aws secretsmanager get-secret-value`, `kubectl get secret -o yaml`, a provider API that returns keys or environment variable values) puts them into the model's context, and nothing in Secretless blocks it. `init` tells the assistant not to run such commands and to read only named, non-secret fields. That is an instruction, not an enforced control.

In Claude Code, `init` also installs a PostToolUse hook (`.claude/hooks/secretless-output-check.cjs`) that reads each Bash command's output after it runs. When the output matches a pattern in the credential catalog, the hook warns you and tells the assistant to treat the value as exposed. It names the pattern and never repeats the value. This is detection after exposure, not prevention: the value is already in context when the hook sees it, and a credential format outside the catalog passes unflagged. If it fires on a live credential, rotate it; `npx secretless-ai clean` redacts saved transcripts.

## Push secrets to a cloud secret store

To put a stored secret into a deployment, `secret push` writes it to a cloud secret store. Each value goes from this machine's store into an HTTPS request body, never onto a command line, and the output carries names, identifiers and versions only. Key Vault secret names allow letters, digits and `-`, so `--as` gives the name to use there:

```bash
npx secretless-ai secret push OPENAI_API_KEY --to azure-kv --vault kv-prod --as OPENAI-API-KEY --dry-run  # would create / would add a version
npx secretless-ai secret push OPENAI_API_KEY --to azure-kv --vault kv-prod --as OPENAI-API-KEY            # prints the secret URI and version
az containerapp secret set -n <app> -g <rg> \
  --secrets openai-api-key=keyvaultref:https://kv-prod.vault.azure.net/secrets/OPENAI-API-KEY,identityref:<identity-id>
```

The Key Vault token comes from the standard Azure credential chain: `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` with `AZURE_CLIENT_SECRET` or `AZURE_FEDERATED_TOKEN_FILE`, then a managed identity, then the signed-in Azure CLI. Pushing needs the Key Vault Secrets Officer role on the vault (or `set` in its access policy); the container app's identity needs Key Vault Secrets User to read the reference. `--to vault` and `--to gcp-sm` push to HashiCorp Vault and GCP Secret Manager the same way, at the names `secret sync --from` reads. A name that is not stored on this machine stops the push before anything is written, and the first write that fails stops the rest. `--dry-run` reads metadata only, so a write the target would refuse is found by the real run.
