# I want to set up secretless for my team

**Time:** 5 minutes
**Prerequisites:** Node.js 18+, a shared secret backend (1Password, HashiCorp Vault, or GCP Secret Manager)

When working on a team, each developer needs access to the same secrets without storing them in `.env` files committed to the repo. Secretless connects to a shared backend so every team member resolves secrets from the same source.

## Step 1: Choose a storage backend

| Backend | Best For | Requires |
|---------|----------|----------|
| `keychain` | Small teams, macOS-only | macOS Keychain (built-in) |
| `1password` | Cross-platform teams | 1Password account + `op` CLI |
| `vault` | Self-hosted, enterprise | HashiCorp Vault instance |
| `gcp-sm` | GCP-native teams | GCP project with Secret Manager API |

For most teams, 1Password is the simplest starting point. Every developer already has it, and CI/CD uses service account tokens.

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

Add secretless as a dev dependency and configure a `postinstall` hook so new team members get protection automatically:

```bash
npm install --save-dev secretless-ai
```

Add to `package.json`:

```json
{
  "scripts": {
    "postinstall": "npx secretless-ai init --ci"
  }
}
```

Now every `npm install` configures AI tool protections automatically.

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
npm install              # postinstall runs secretless-ai init
npx secretless-ai setup  # prompts for missing secrets
npx secretless-ai verify # confirms everything works
```

Three commands after cloning. No `.env` files to copy from Slack. No credentials in the repo.

## Next steps

- [Protect My Credentials](protect-my-credentials.md) -- Understand what init does under the hood
- [Secure MCP Configs](secure-mcp-configs.md) -- Encrypt MCP server credentials with the same backend
- [Migrate from .env](migrate-from-dotenv.md) -- Move existing .env files into the shared backend
