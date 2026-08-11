# I want to set up secretless for my team

**Time:** 5 minutes
**Prerequisites:** Node.js 20.19+, a shared secret backend (1Password, HashiCorp Vault, or GCP Secret Manager)

When working on a team, each developer needs access to the same secrets without storing them in `.env` files committed to the repo. Secretless connects to a shared backend so every team member resolves secrets from the same source.

## Step 1: Choose a storage backend

| Backend | Best For | Requires |
|---------|----------|----------|
| `keychain` | Small teams, macOS-only | macOS Keychain (built-in) |
| `1password` | Cross-platform teams | 1Password account + `op` CLI |
| `vault` | Self-hosted, enterprise | HashiCorp Vault instance |
| `gcp-sm` | GCP-native teams | GCP project with Secret Manager API |

For most teams, 1Password is the simplest starting point. Every developer already has it, and CI/CD uses service account tokens.

> **1Password caveat:** On a machine where the 1Password desktop app is installed and CLI integration is enabled, the first `secretless-ai backend` run triggers a biometric / master-password prompt (used to confirm `op` availability). Cancel it if you don't want 1Password — the backend probe falls back cleanly. If you do want 1Password, unlock once and subsequent calls stay inside the cache window.

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
  Vault: Secretless (created)
  Ready.
```

### HashiCorp Vault

```bash
export VAULT_ADDR=https://vault.yourcompany.com
export VAULT_TOKEN=<your-token>
npx secretless-ai backend set vault
```

### GCP Secret Manager

```bash
export GOOGLE_CLOUD_PROJECT=your-project-id
npx secretless-ai backend set gcp-sm
```

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

`init` exits 1 when `.claude/settings.json` exists but cannot be parsed as strict JSON —
comments and trailing commas are the common cause, and they are what VS Code writes and
what people hand-edit into that file. It refuses rather than replacing a file it could not
read, which is correct on its own terms, but in a `postinstall` hook it means one
developer's editor formatting blocks dependency installation for them entirely.

Exit codes, so you can wire `init` into automation deliberately:

| Situation | Exit |
|---|---|
| No `.claude/settings.json`, or the file is empty | 0 — configures normally |
| Valid JSON, including a file with your own keys | 0 — merges, your keys preserved |
| Already configured (re-run) | 0 — idempotent |
| File is not parseable JSON (comments, trailing commas) | 1 — changes nothing, names the parse error |
| File parses but is `null`, an array, a string or a number | 1 — changes nothing |

If you do want it automatic, run it in a step whose failure is visible and does not block
installing dependencies — a CI job, or a `prepare` script you are willing to have fail
loudly. Never suppress the exit code with `|| true`: that restores the silent-success
behavior this check exists to remove.

## Step 4: Define required secrets

Create a `.secretless` manifest at the project root listing what secrets the project needs:

```
STRIPE_KEY        required    Stripe API key for payments
DATABASE_URL      required    PostgreSQL connection string
SENTRY_DSN        optional    Error tracking DSN
```

Developers run `setup` to interactively provide missing secrets:

```bash
npx secretless-ai setup
```

Expected output:

```
  Reading .secretless manifest...

  STRIPE_KEY       missing (required)
    Enter value: ****
    Stored in 1password.

  DATABASE_URL     missing (required)
    Enter value: ****
    Stored in 1password.

  SENTRY_DSN       missing (optional)
    Skip? [Y/n]: Y

  2 secrets stored. 1 skipped (optional).
```

## Step 5: Set up CI/CD

In CI/CD, secrets come from environment variables. Secretless detects the CI environment and skips interactive prompts.

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

The `--check` flag fails the build if any required secret from the `.secretless` manifest is missing.

### 1Password in CI/CD

If your team uses 1Password, CI/CD can pull secrets directly using a service account:

```yaml
    steps:
      - run: npx secretless-ai setup --check
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
```

The `op` CLI authenticates via the service account token. Same secrets, no manual env var mapping.

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

If `npm run protect` exits 1, it names the reason and changes nothing — the usual cause is
a `.claude/settings.json` with comments or a trailing comma. Fix the file and re-run; the
rest of the checklist is unaffected.

## Next steps

- [Protect My Credentials](protect-my-credentials.md) -- Understand what init does under the hood
- [Secure MCP Configs](secure-mcp-configs.md) -- Encrypt MCP server credentials with the same backend
- [Migrate from .env](migrate-from-dotenv.md) -- Move existing .env files into the shared backend
