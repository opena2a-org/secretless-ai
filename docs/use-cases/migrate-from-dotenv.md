# I want to migrate from .env files

**Time:** 3 minutes
**Prerequisites:** Node.js 20.19+

`.env` files are the most common way to manage secrets locally, but they have two problems: they are plaintext files that AI tools can read, and they get accidentally committed to git. Secretless imports your `.env` contents into encrypted storage and blocks AI tools from reading the files.

## Step 1: Scan for .env files

See what `.env` files exist in your project:

```bash
npx secretless-ai scan
```

Expected output:

```
  Scanning for credentials...

  .env                          3 secrets found
  .env.local                    2 secrets found
  config/.env.production        5 secrets found

  10 credentials found in 3 files.
  Run: npx secretless-ai import --detect
```

The scan identifies files containing credentials but does not modify anything.

## Step 2: Import secrets into secure storage

Import all detected `.env` files at once:

```bash
npx secretless-ai import --detect
```

Expected output:

```
  Importing from .env...
    STRIPE_KEY               stored
    DATABASE_URL             stored
    OPENAI_API_KEY           stored

  Importing from .env.local...
    SENTRY_DSN               stored
    REDIS_URL                stored

  5 secrets imported into local backend.
```

To import a specific file instead:

```bash
npx secretless-ai import .env
```

Secrets are now stored in your configured backend (local AES-256-GCM by default, or 1Password/Vault/GCP if configured).

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
2. **Imported** credential values into encrypted storage (AES-256-GCM locally, or your configured backend)
3. **Blocked** AI tools from reading `.env` files via deny rules

Your code still reads `process.env.*` variables. The difference is that the values come from encrypted storage instead of a plaintext file.

## Next steps

- [Protect My Credentials](protect-my-credentials.md) -- Block AI tools from reading all credential file types
- [Team Setup](team-setup.md) -- Move from local storage to a shared backend like 1Password
- [Secure MCP Configs](secure-mcp-configs.md) -- Encrypt MCP server credentials the same way
