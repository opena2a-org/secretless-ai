# I want to set up secretless for my team

**Time:** 5 minutes
**Prerequisites:** Node.js 20.19+, a shared secret backend (1Password, HashiCorp Vault, or GCP Secret Manager)

When working on a team, each developer needs access to the same secrets without storing them in `.env` files committed to the repo. Secretless connects to a shared backend so every team member resolves secrets from the same source.

## Step 1: Choose a storage backend

| Backend | Best For | Requires |
|---------|----------|----------|
| `1password` | Cross-platform teams | 1Password account + `op` CLI |
| `vault` | Self-hosted, enterprise | HashiCorp Vault instance |
| `gcp-sm` | GCP-native teams | GCP project with Secret Manager API |

`keychain` (macOS Keychain or Linux Secret Service) and `local` are not in this table: each keeps its store on one machine, so teammates cannot resolve secrets from it. To hand a store kept there to another machine, use an encrypted `export`/`import` bundle, described in [Move secrets to another machine](../secrets.md#move-secrets-to-another-machine).

For most teams, 1Password is the simplest starting point. Every developer already has it, and CI/CD uses service account tokens.

> **1Password caveat:** On a machine where the 1Password desktop app is installed and CLI integration is enabled, `secretless-ai backend set 1password` triggers a biometric / master-password prompt (it runs `op account get` to confirm you are signed in). Cancel it if you don't want 1Password. The command exits with `Cannot use 1Password backend` and your current backend stays as it was. If you do want 1Password, unlock once and subsequent calls stay inside the cache window.
> Running `secretless-ai backend` on its own only checks whether `op` is on `$PATH`; it does not run `op`.

## Step 2: Configure the backend

### 1Password

```bash
# Install the 1Password CLI (each developer runs this once)
brew install --cask 1password 1password-cli

# Enable CLI integration:
# 1Password > Settings > Developer > "Integrate with 1Password CLI"

# Set the backend
npx secretless-ai backend set 1password
```

Expected output:

```
  Backend set to: 1password

  Run `npx secretless-ai protect-mcp` to re-protect MCP servers with the new backend.
  Or use `npx secretless-ai migrate` to migrate existing secrets.
```

### HashiCorp Vault

```bash
export VAULT_ADDR=https://vault.yourcompany.com
export VAULT_TOKEN=<your-token>
npx secretless-ai backend set vault
```

### GCP Secret Manager

```bash
gcloud auth application-default login
npx secretless-ai backend set gcp-sm
```

The project comes from the first of: a `gcp.projectId: <project-id>` line in
the repository's `.secretless` (see Step 4), `gcp.projectId` in
`~/.secretless-ai/config.json`, the service account key's `project_id`, and the
Application Default Credentials quota project. A repository that names its own
project never falls back to another, so two repositories on one machine can
resolve from two projects. `npx secretless-ai status` shows which project
applies and where it came from.

## Step 3: Add to your project

Add secretless as a dev dependency:

```bash
npm install --save-dev secretless-ai
```

Then add an explicit setup script that new team members run once:

```json
{
  "scripts": {
    "protect": "secretless-ai init"
  }
}
```

```bash
npm run protect
```

### Why this is not a `postinstall` hook

Earlier versions of this guide wired `secretless-ai init` into `postinstall`. Do not do
that. `init` exits non-zero when it cannot safely configure the project, and anything in
`postinstall` that exits non-zero fails the whole `npm install`.

`init` exits 1 when `.claude/settings.json` exists but cannot be parsed as strict JSON.
Comments and trailing commas are the common cause, and they are what VS Code writes and
what people hand-edit into that file. It refuses rather than replacing a file it could not
read, which is correct on its own terms, but in a `postinstall` hook it means one
developer's editor formatting blocks dependency installation for them entirely.

Exit codes, so you can wire `init` into automation deliberately:

| Situation | Exit |
|---|---|
| No `.claude/settings.json`, or the file is empty | 0: configures normally |
| Valid JSON, including a file with your own keys | 0: merges, your keys preserved |
| Already configured (re-run) | 0: idempotent |
| File is not parseable JSON (comments, trailing commas) | 1: changes nothing, names the parse error |
| File parses but is `null`, an array, a string or a number | 1: changes nothing |

If you do want it automatic, run it in a step whose failure is visible and does not block
installing dependencies: a CI job, or a `prepare` script you are willing to have fail
loudly. Never suppress the exit code with `|| true`: that restores the silent-success
behavior this check exists to remove.

## Step 4: Define required secrets

Create a `.secretless` manifest at the project root listing what secrets the project needs:

```
STRIPE_KEY                  # Stripe API key for payments
DATABASE_URL                # PostgreSQL connection string
SENTRY_DSN        optional  # Error tracking DSN
```

Each line is one secret name. A name is required unless `optional` follows it, and
text after `#` is its description. Any other text after a name is a parse error: the
file lists names only, never values.

On the `gcp-sm` backend, one more line names the GCP project this repository's
secrets live in. It applies to commands run anywhere inside the repository:

```
gcp.projectId: acme-prod
```

Developers run `setup` to interactively provide missing secrets:

```bash
npx secretless-ai setup
```

Expected output:

```
  Secretless Setup

  Store: 1password

  STRIPE_KEY (Stripe API key for payments): sk_live_...
  DATABASE_URL (PostgreSQL connection string): postgres://...
  SENTRY_DSN (Error tracking DSN) [optional, press Enter to skip]:

  Set:      2 secret(s)
  Existing: 0
  Skipped:  1 (optional)
```

`setup` names the backend it writes to before the first prompt, then prompts only for names not yet stored, with the description from the manifest. The prompt does not mask input: a value is shown as you type or paste it.

## Step 5: Set up CI/CD

In CI/CD, secrets come from environment variables. `setup --check` counts a name
from `.secretless` as present when it is in the configured store or set to a
non-empty value in the environment, and lists the names that came from the
environment. It never prompts and never stores those values. Plain `setup` does
not prompt when standard input is not a terminal either: it prints the same
report and exits 1 if a required secret is missing.

### GitHub Actions

```yaml
name: Build
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm ci
      - run: npx secretless-ai setup --check
        env:
          STRIPE_KEY: ${{ secrets.STRIPE_KEY }}
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

The step passes, with `Satisfied: 2 secret(s) (2 from environment)`, when both
values are provided. It fails the build (exit 1) if any required secret from the
`.secretless` manifest is neither stored nor set in the environment. A secret
that is not defined in the repository settings reaches the job as an empty
string, and an empty value counts as missing.

### 1Password in CI/CD

If your team keeps these secrets in 1Password, check 1Password instead of the
store configured on the runner with `--backend 1password`. The job needs the `op`
CLI installed; it authenticates with a service account token:

```yaml
    steps:
      - run: npx secretless-ai setup --check --backend 1password
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
```

The report's `Store:` line reads `1password`, so the log shows which store was
checked. A name set in the job's environment still counts, so the two recipes
can be combined.

## Step 6: Verify team setup

Each developer verifies their local setup:

```bash
npx secretless-ai verify
```

Expected output:

```
  Checking protections...

  Backend:          1password (Secretless vault)
  STRIPE_KEY        hidden from AI, usable via $ENV
  DATABASE_URL      hidden from AI, usable via $ENV

  All secrets protected.
```

## Onboarding checklist

For new team members, the workflow is:

```bash
git clone <repo>
npm install              # dependencies only
npm run protect          # configures AI tool protections
npx secretless-ai setup  # prompts for missing secrets
npx secretless-ai verify # confirms everything works
```

Four commands after cloning. No `.env` files to copy from Slack. No credentials in the repo.

If `npm run protect` exits 1, it names the reason and changes nothing. The usual cause is
a `.claude/settings.json` with comments or a trailing comma. Fix the file and re-run; the
rest of the checklist is unaffected.

## Next steps

- [Protect My Credentials](protect-my-credentials.md): Understand what init does under the hood
- [Secure MCP Configs](secure-mcp-configs.md): Encrypt MCP server credentials with the same backend
- [Migrate from .env](migrate-from-dotenv.md): Move existing .env files into the shared backend
