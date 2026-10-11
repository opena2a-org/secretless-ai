# I want to migrate from .env files

**Time:** 3 minutes
**Prerequisites:** Node.js 20.19+

`.env` files are the most common way to manage secrets locally, but they have two problems: they are plaintext files that AI tools can read, and they get accidentally committed to git. Secretless imports your `.env` contents into encrypted storage and blocks AI tools from reading the files.

## Step 1: Scan for .env files

See which credentials your project's files hold:

```bash
npx secretless-ai scan
```

Expected output for a project whose `.env` holds a Stripe key, a database URL and an OpenAI key, and whose `.env.local` holds a Sentry DSN and a Redis URL:

```
  Secretless Scanner

  4 critical credentials exposed

  ── Findings ────────────────────────────────────────────────
  4 critical

  │ CRITICAL  OpenAI Project Key
  │ .env:3
  │ OPENAI_API_KEY=[OpenAI Project Key REDACTED]
  │ Confidence: high (0.98)
  │ Fix: Move to env var OPENAI_API_KEY. Rotate at platform.openai.com > API Keys.

  │ CRITICAL  PostgreSQL Connection String
  │ .env:2
  │ DATABASE_URL=[PostgreSQL Connection String REDACTED]
  │ Confidence: high (0.97)
  │ Fix: Move to env var DATABASE_URL. Rotate the database password.

  │ CRITICAL  Redis Connection String
  │ .env.local:2
  │ REDIS_URL=[Redis Connection String REDACTED]
  │ Confidence: high (0.96)
  │ Fix: Move to env var REDIS_URL. Rotate the Redis password (requirepass or ACL user).

  │ CRITICAL  Stripe Live Key
  │ .env:1
  │ STRIPE_KEY=[Stripe Live Key REDACTED]
  │ Confidence: high (0.95)
  │ Fix: Move to env var STRIPE_SECRET_KEY. Rotate at dashboard.stripe.com > Developers > API Keys.

  ── Next Steps ──────────────────────────────────────────────
  Protect now:        npx secretless-ai init
  Full security scan: npx hackmyagent secure
```

The scan names each credential's file and line, never its value, and does not modify anything. Findings are listed most severe first, then by confidence, which depends on the value, so the numbers on your project can differ. The Sentry DSN is not reported.

## Step 2: Import secrets into secure storage

Import all detected `.env` files at once:

```bash
npx secretless-ai import --detect
```

Expected output:

```
  Secretless Import

  .env: 3 imported
  .env.local: 2 imported

  Total: 5 secret(s) imported.
```

`import --detect` reads the `.env` files in the current directory and stores every entry, the Sentry DSN included. An entry whose name cannot be stored is counted as skipped.

To import a specific file instead:

```bash
npx secretless-ai import .env
```

Secrets are now stored in your configured backend: `local` (the AES-256-GCM encrypted file), `keychain`, 1Password, Vault or GCP. With no backend configured, they go to the OS keychain where one is available (macOS Keychain, or Linux Secret Service when `secret-tool` is installed), and otherwise to the encrypted file. `npx secretless-ai backend` names the store in use.

## Step 3: Update .gitignore

If `.env` files are not already in your `.gitignore`, add them:

```bash
echo ".env" >> .gitignore
echo ".env.*" >> .gitignore
echo "!.env.example" >> .gitignore
```

Keep a `.env.example` file with placeholder values so new developers know what variables are needed:

```
STRIPE_KEY=sk_test_...
DATABASE_URL=your-database-connection-string
OPENAI_API_KEY=sk-...
```

Or better, use a `.secretless` manifest (see [Team Setup](team-setup.md)).

## Step 4: Verify nothing is exposed

Run `verify` to confirm secrets are hidden from AI tools and still usable:

```bash
npx secretless-ai verify
```

Expected output:

```
  Checking protections...

  .env                     blocked
  .env.local               blocked
  .env.production          blocked
  STRIPE_KEY               hidden from AI, usable via $ENV
  DATABASE_URL             hidden from AI, usable via $ENV
  OPENAI_API_KEY           hidden from AI, usable via $ENV

  All secrets protected.
```

## Using secrets after migration

Your code continues to read `process.env.STRIPE_KEY` as before. Secretless injects secrets as environment variables at runtime.

To run a command with secrets injected:

```bash
npx secretless-ai run -- npm start
npx secretless-ai run -- npm test
npx secretless-ai run --only DATABASE_URL -- npm run migrate
```

To export secrets into your current shell session:

```bash
eval "$(npx secretless-ai env)"
```

## Can I delete the .env files?

After importing and verifying, you can remove the `.env` files from your local machine. The secrets are stored in the backend. If you need to restore them later:

```bash
npx secretless-ai secret list           # See what is stored
npx secretless-ai run -- env | grep KEY  # Verify they resolve
```

Keep `.env` files around during the transition period until your team is confident in the new workflow.

## What happened

The migration did three things:

1. **Scanned** your project for `.env` files and identified credentials
2. **Imported** credential values into your configured backend (with none configured, the OS keychain where one is available, otherwise an AES-256-GCM encrypted file)
3. **Blocked** AI tools from reading `.env` files via deny rules

Your code still reads `process.env.*` variables. The difference is that the values come from encrypted storage instead of a plaintext file.

## Next steps

- [Protect My Credentials](protect-my-credentials.md): Block AI tools from reading all credential file types
- [Team Setup](team-setup.md): Move from local storage to a shared backend like 1Password
- [Secure MCP Configs](secure-mcp-configs.md): Encrypt MCP server credentials the same way
