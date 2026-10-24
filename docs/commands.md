# Commands

The scan command, MCP server protection, the flags for triaging findings, exit codes, and running Secretless through `opena2a-cli`. Commands for stored secrets are in [Store and use secrets](managing-secrets.md).

## Scan for hardcoded credentials

```bash
npx secretless-ai scan
```

`scan` reads the project's source files, key files and the config files it recognizes by name, and exits 1 when it finds a credential. [What a directory scan opens](scanning.md#what-a-directory-scan-opens) names the files it reads, and [Triage helpers](#triage-helpers) lists the flags that narrow a scan.

## MCP server protection

MCP client configs often hold API keys in plaintext JSON. Any assistant that can read files on your machine can read them. Secretless encrypts them.

```bash
npx secretless-ai protect-mcp
```

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

Scans the configs of Claude Desktop, Cursor, Claude Code, VS Code, and Windsurf in your home directory, and `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.windsurf/mcp.json` and `mcp.json` in the current directory. Secrets move to your configured backend. Non-secret env vars (URLs, regions) stay untouched.

Of the project-level configs, `protect-mcp` rewrites `.mcp.json` only. It writes this machine's wrapper path into each config it rewrites, and a project-level config is usually committed, so it lists the others as not checked and leaves them as they are; `mcp-status` shows their servers. When either command finds no config, it lists every path it looked in.

```bash
npx secretless-ai protect-mcp --backend 1password   # store MCP secrets in 1Password
npx secretless-ai mcp-status                        # show which servers are protected
npx secretless-ai mcp-unprotect                     # restore original configs from backup
```

## Triage helpers

```bash
npx secretless-ai scan --min-confidence 0.85   # high-confidence findings only
npx secretless-ai scan --max-files 20000       # raise the per-walk file cap (default 5000)
npx secretless-ai ignore scripts/seed.js       # stop scan reading a path; it is reported as excluded (exit 1)
npx secretless-ai ignore --pattern 'seed/**/*.ts'
npx secretless-ai diff main                    # audit secretless-managed file changes vs a git ref
npx secretless-ai scan --json                  # machine-readable findings for CI
npx secretless-ai scan --format sarif > secretless.sarif   # the same findings as SARIF 2.1.0, for GitHub code scanning
npx secretless-ai scan --check-validity        # ask each credential's issuer whether it still accepts it (opt-in)
npx secretless-ai status --json                # protection state for CI (gate on summary.verdict)
```

`ignore` narrows what `scan` reads: it appends a gitignore-style line to `.secretlessignore` in the current directory, and `scan` stops reading the paths that line matches. It reports each one it would have read as excluded by `.secretlessignore` and exits 1, because an excluded path is not known to be clean; `npx secretless-ai scan --no-ignore` reads them. `ignore` says after writing a line whether `scan` will exit 1 for it: a line that matches only files `scan` does not open, such as `.txt` files, changes nothing in `scan`. A false positive is handled in the value, not with `ignore`: remove or rewrite it (the finding's own `Fix:`), use `--min-confidence` when its confidence is low, or give a sample value a placeholder word such as `example`, `placeholder` or `fake`, which `scan` hides (the full list is `PLACEHOLDER_INDICATORS` in [`src/patterns.ts`](https://github.com/opena2a-org/secretless-ai/blob/main/src/patterns.ts)); there is no allow-list for a single finding.

`scan` renders a `Confidence: high (0.92)` line under every finding. The score combines pattern specificity, value entropy, value length, and path tier. With `--no-ignore`, findings whose path matches the default-ignore list are tagged `(looks like a test fixture)` so they stay visible without being re-suppressed.

`scan --check-validity` asks the provider that issued each found credential whether it still accepts it, and prints `Validity: live`, `rejected`, `unknown` or `not checked` under the finding (`validity` on each finding and `summary.validity` in `--json`). It is off by default, and without it no credential is sent anywhere. With it, the matched value goes over HTTPS to that provider's own API and to no other host: GitHub (app installation tokens included), GitLab, Anthropic, OpenAI, OpenRouter, Fireworks AI, Groq, Hugging Face, Replicate, Google OAuth access tokens, Slack (tokens and webhook URLs), Discord (bot tokens and webhook URLs), Telegram, SendGrid, npm, DigitalOcean, Heroku, Netlify, Stripe and Linear credentials are checked, and `scan --help` lists the endpoint for each. An AWS key is checked as a pair: the access key ID and the secret access key found with it in one file make one GetCallerIdentity request to sts.amazonaws.com signed with the secret (Signature Version 4), so the key ID and the signature are sent and the secret is not. A file is paired when its findings hold one of each, or several of each that, taken in line order two at a time, are each one key ID and one secret. A key ID and a secret found on one line, which the scan reports as one finding, both count, and are never split between two pairs. A key ID paired with different secrets, or a secret paired with different key IDs, in the scanned files is sent with none of them. A token from a self-managed GitHub or GitLab instance still goes to api.github.com or gitlab.com, which did not issue it, and a key from the AWS China or GovCloud partition still goes to sts.amazonaws.com, whose partition did not issue it. A webhook URL is itself the credential: its path goes to the host that serves it, and nothing else from it. A Discord webhook URL is fetched with GET, the webhook's read-only endpoint, at discord.com whether the URL named discord.com or discordapp.com; a Slack webhook URL is sent a POST whose body is `{}`, a message with no text, which Slack refuses before posting anything. Other types, such as connection strings, private keys and AWS STS temporary keys, read `not checked`, and nothing is sent for them. An OpenAI project key value is not sent either when it is shorter than 132 characters or the scan found a `-` or `_` right after it: the key can hold `-` or `_`, where the pattern stops, so such a value may be only the part before one, and the finding says so. `live` means the host answered 200 (or, for a Slack webhook, that hooks.slack.com refused the empty message with 400 `no_text` rather than refusing the URL), `rejected` that it answered 401 (Slack states a rejection in the body of a 200, Google's tokeninfo in the body of a 400, Discord's webhook endpoint as 404 Unknown Webhook, hooks.slack.com as 403 `invalid_token` or 404 `no_service` or `no_team`, and AWS STS as 403 `InvalidClientTokenId` or `SignatureDoesNotMatch`), and `unknown` any other answer or none, a `SignatureDoesNotMatch` that names the request time among them; the answer changes neither the severity nor the exit code.

### Exit codes and scan coverage

Exit codes: `0` clean, `1` credentials found (or an incomplete scan, or a `scan`, `status` or `verify` target that is missing or cannot be opened, or an `init` that left a tool not configured, or a `verify` that found no API key in the environment to check), `2` the command line was refused and nothing ran, such as an unknown command or subcommand, a command given none of the arguments it needs, an argument `clean`, `doctor` or `init` does not take, a backend type, `backend purge` prefix or cache duration it does not take, a `rules test` pattern it does not take, one backend given to `migrate` as both `--from` and `--to`, or a flag it could not bind. Gate CI on `2` separately: it means the tool did not answer the question, not that the answer was clean.

A scan that stops at the file cap, or cannot open a path, exits 1 and says `No credentials found in the files scanned` rather than `No hardcoded credentials found`; `summary.truncated` and `summary.unreadable` carry the same signal in `--json`. An unrecognised flag, or a flag without a value it can use, is refused with exit 2 before anything runs, rather than partly ignored; `feedback`, `diff` and `mcp-status` instead warn about an unrecognised flag and continue. [Scan coverage and exit codes](scanning.md) says what a directory scan opens, which gaps fail a build and which do not, and shows a sample `--json` summary.

## Using with opena2a-cli

[`opena2a-cli`](https://github.com/opena2a-org/opena2a) is the unified CLI for the OpenA2A security toolchain. `opena2a secrets` runs the secretless-ai release opena2a-cli depends on, which can be older than the one this page describes: opena2a-cli 0.10.13 depends on `secretless-ai@^0.14.1`, so `opena2a secrets` runs 0.14.x, which has no `secret push`, `secret sync`, `git-credential` or `telemetry` command. For those, run `npx secretless-ai` directly. `npm view opena2a-cli dependencies.secretless-ai` prints the range the latest opena2a-cli depends on.

```bash
npm install -g opena2a-cli
opena2a review          # full security dashboard
opena2a secrets init    # initialize secretless protection
```
