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

  MCP servers will start normally — no workflow changes needed.
  Run `npx secretless-ai mcp-status` to check status anytime.
  Run `npx secretless-ai mcp-unprotect` to restore originals.
```

Scans configs across Claude Desktop, Cursor, Claude Code, VS Code, and Windsurf. Secrets move to your configured backend. Non-secret env vars (URLs, regions) stay untouched.

```bash
npx secretless-ai protect-mcp --backend 1password   # store MCP secrets in 1Password
npx secretless-ai mcp-status                        # show which servers are protected
npx secretless-ai mcp-unprotect                     # restore original configs from backup
```

## Triage helpers

```bash
npx secretless-ai scan --min-confidence 0.85   # high-confidence findings only
npx secretless-ai scan --max-files 20000       # raise the per-walk file cap (default 5000)
npx secretless-ai ignore docs/migration.md     # append a path to .secretlessignore
npx secretless-ai ignore --pattern '*.golden.txt'
npx secretless-ai diff main                    # audit secretless-managed file changes vs a git ref
npx secretless-ai scan --json                  # machine-readable findings for CI
npx secretless-ai scan --format sarif > secretless.sarif   # the same findings as SARIF 2.1.0, for GitHub code scanning
npx secretless-ai scan --check-validity        # ask each credential's issuer whether it still accepts it (opt-in)
npx secretless-ai status --json                # protection state for CI (gate on summary.verdict)
```

`scan` renders a `Confidence: high (0.92)` line under every finding. The score combines pattern specificity, value entropy, value length, and path tier. With `--no-ignore`, findings whose path matches the default-ignore list are tagged `(looks like a test fixture)` so they stay visible without being re-suppressed.

`scan --check-validity` asks the provider that issued each found credential whether it still accepts it, and prints `Validity: live`, `rejected`, `unknown` or `not checked` under the finding (`validity` on each finding and `summary.validity` in `--json`). It is off by default, and without it no credential is sent anywhere. With it, the matched value goes over HTTPS to that provider's own API and to no other host: GitHub, Anthropic, OpenAI, Groq, Hugging Face, Replicate, Slack, Discord, Telegram, SendGrid, npm, DigitalOcean, Heroku, Netlify and Stripe credentials are checked, and `scan --help` lists the host for each. Other types, such as connection strings and private keys, read `not checked`, and nothing is sent for them. `live` means the host answered 200, `rejected` that it answered 401, and `unknown` any other answer or none; the answer changes neither the severity nor the exit code.

### Exit codes and scan coverage

Exit codes: `0` clean, `1` credentials found (or an incomplete scan, or a `scan`, `status` or `verify` target that is missing or cannot be opened, or an `init` that left a tool not configured, or a `verify` that found no API key in the environment to check), `2` the command line was refused and nothing ran, such as an unknown command or subcommand, or a flag it could not bind. Gate CI on `2` separately: it means the tool did not answer the question, not that the answer was clean.

A scan that stops at the file cap, or cannot open a path, exits 1 and says `No credentials found in the files scanned` rather than `No hardcoded credentials found`; `summary.truncated` and `summary.unreadable` carry the same signal in `--json`. An unrecognised flag, or a flag without a value it can use, is refused with exit 2 before anything runs, rather than partly ignored; `feedback`, `diff` and `mcp-status` instead warn about an unrecognised flag and continue. [Scan coverage and exit codes](scanning.md) says what a directory scan opens, which gaps fail a build and which do not, and shows a sample `--json` summary.

## Using with opena2a-cli

[`opena2a-cli`](https://github.com/opena2a-org/opena2a) is the unified CLI for the OpenA2A security toolchain. `opena2a secrets` runs the secretless-ai release opena2a-cli depends on, which can be older than the one this page describes: opena2a-cli 0.10.13 depends on `secretless-ai@^0.14.1`, so `opena2a secrets` runs 0.14.x, which has no `secret push`, `secret sync`, `git-credential` or `telemetry` command. For those, run `npx secretless-ai` directly. `npm view opena2a-cli dependencies.secretless-ai` prints the range the latest opena2a-cli depends on.

```bash
npm install -g opena2a-cli
opena2a review          # full security dashboard
opena2a secrets init    # initialize secretless protection
```
