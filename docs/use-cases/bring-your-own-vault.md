# I already have a vault

**Time:** 3 minutes
**Prerequisites:** An existing secrets backend you trust (HashiCorp Vault, GCP Secret Manager, or 1Password)

If your team already runs a vault, you don't need another one. Point Secretless at the vault you already have and everything downstream (`secret set`, `run --only`, `protect-mcp`, the broker) resolves against it.

You don't need an AIM account for any of this. The backend is local to your configuration; Secretless is the client.

## Step 1: Pick your backend

Five backends are wired into the CLI today:

| Backend | Shared across machines? | Requires |
|---------|-------------------------|----------|
| `local` | No (single machine, encrypted file) | Nothing |
| `keychain` | No (macOS Keychain / Linux Secret Service) | Native OS keychain |
| `1password` | Yes | `op` CLI installed and signed in |
| `vault` | Yes | A reachable HashiCorp Vault with a token |
| `gcp-sm` | Yes | GCP Application Default Credentials |

For AWS Secrets Manager and Azure Key Vault, use the Go AIM backend instead. Those aren't part of this CLI today. Track status on the AIM repo.

## Step 2: Connect to HashiCorp Vault (canonical walk-through)

Every external backend follows the same pattern: set env vars, run `backend set <name>`, verify. HashiCorp Vault is the most common. The other backends work identically.

```bash
export VAULT_ADDR=https://vault.yourcompany.com
export VAULT_TOKEN=<your-token>
npx secretless-ai backend set vault
```

Expected output:

```
  Backend set to: vault

  Run `npx secretless-ai protect-mcp` to re-protect MCP servers with the new backend.
  Or use `npx secretless-ai migrate` to migrate existing secrets.
```

Confirm the CLI sees it:

```bash
npx secretless-ai backend
```

```
  Current:      vault
  Config file:  vault
  Vault:        configured (https://vault.yourcompany.com)
  ...
```

## Step 3: Round-trip a credential

```bash
npx secretless-ai secret set GITHUB_TOKEN=ghp_<your-real-token>
npx secretless-ai run --only GITHUB_TOKEN -- sh -c 'printf "Authorization: Bearer %s\n" "$GITHUB_TOKEN" | curl -s -H @- https://api.github.com/user'
```

The token is injected into the environment of `sh`, and `printf` is a shell builtin, so it reaches curl on stdin (`-H @-`). Passing it as `-H "Authorization: Bearer $GITHUB_TOKEN"` would put it on curl's command line, where `ps` shows it to every local process; `run` refuses that shape unless `--allow-argv` is given.

The credential is stored in Vault under `<mount>/secret/GITHUB_TOKEN`. Default mount is `secret`, so full Vault path is `secret/secret/GITHUB_TOKEN`. Read it back with stock Vault tooling to confirm:

```bash
vault kv get secret/secret/GITHUB_TOKEN
```

```
==== Data ====
Key      Value
---      -----
value    ghp_<your-real-token>
```

That's the point: the credential is a normal Vault entry. No Secretless-proprietary encoding, no wrapper format, nothing that would make it hard to migrate off later.

## Same pattern: other backends

| Backend | Env vars to set |
|---------|-----------------|
| `1password` | `op` CLI signed in (or `OP_SERVICE_ACCOUNT_TOKEN` for CI) |
| `gcp-sm` | Application Default Credentials or `GOOGLE_APPLICATION_CREDENTIALS`; the project from `gcp.projectId: <id>` in the repository's `.secretless` or `~/.secretless-ai/config.json` |

Then:

```bash
npx secretless-ai backend set <name>
npx secretless-ai secret set MY_KEY=<value>
npx secretless-ai run --only MY_KEY -- <command>
```

## Run one command with a secret from your backend

Once your backend is connected, `run --only` runs one command with the named secret set in that command's environment, without exporting it to your parent shell. It is the command from Step 3:

```bash
npx secretless-ai run --only GITHUB_TOKEN -- sh -c 'printf "Authorization: Bearer %s\n" "$GITHUB_TOKEN" | curl -s -H @- https://api.github.com/user'
```

The child process gets `$GITHUB_TOKEN`. The parent shell does not. The child's output is not masked: a command that prints the secret shows it to whoever ran it, an AI assistant included.

`vault exec` (Tier 2) does not read this backend. It reads the separate Identity Vault (`~/.aim/vault`), which `vault register` fills, so a secret stored with `secret set` gives `Vault resolution denied: Namespace "<name>" not found` there. [Two separate stores](run-broker.md#storage-two-separate-stores) says which command reads which store.

## When would I add AIM?

You don't need AIM to use any of the above. AIM unlocks:

- **Identity-bound policy** at the broker: rules that gate by agent trust score or capability, not just agent ID
- **Shared policy** across a team: one AIM instance enforces the same rules for every developer's broker
- **Cross-team audit**: AIM-side logs of which agent requested which credential from which host

If none of that matches your use case, stick with `secret set` and `run --only` against your existing vault. You can always add AIM later without re-configuring your backend.

## Caveats

- When you run `secretless-ai backend set 1password` on a machine where 1Password Desktop integration is enabled, `op` triggers a biometric / unlock prompt (the command runs `op account get` to confirm you are signed in). Cancel or unlock: both are safe. Cancelling exits with `Cannot use 1Password backend` and leaves your current backend as it was. Not triggered when 1Password is not installed or the `op` CLI isn't on `$PATH`.
  Running `secretless-ai backend` on its own only checks whether `op` is on `$PATH`; it does not run `op`.
- Vault tokens on the command line are visible in `ps aux`. Prefer env vars (as shown above) or a token file sourced from a `.envrc`.

## Next steps

- [Run the Broker](run-broker.md): When to run the daemon for multi-agent workflows
- [Team Setup](team-setup.md): Shared backend + CI/CD
- [Secure MCP Configs](secure-mcp-configs.md): Encrypt MCP server credentials using the same backend
