# Run the broker

**Time:** 3 minutes
**Prerequisites:** Node 20+, a storage backend configured ([Bring Your Own Vault](bring-your-own-vault.md))

The broker is a local daemon that mediates credential access for one or more agents. Policy rules gate every resolve: agent ID, credential name, time window, rate limit, optional AIM trust score and capabilities.

## When do I need the broker?

For most workflows you don't — `vault exec` (Tier 2) is enough. Reach for the broker when:

- **Multiple long-lived agents** need credentials in the same session, and you want one policy to govern all of them
- You need **per-agent rate limits** (e.g. "scan-bot gets at most 10 resolves per minute on GITHUB_*")
- You want an **audit log** of every credential access, not just the run
- You plan to wire AIM trust-score policy later

If you're running one short-lived script, skip the daemon — `secretless-ai run --only KEY -- cmd` is simpler.

## Storage: two separate stores

Important architectural note before you start:

- **Identity Vault** (`~/.aim/vault`) — what `vault register` and `vault exec` use. Ed25519 identity-bound, XSalsa20-Poly1305.
- **SecretStore** (your configured backend: local, keychain, 1password, vault, gcp-sm) — what `secret set`, `run --only`, and the broker's `/resolve` endpoint use.

The broker does **not** read from the Identity Vault. `vault exec` does. They're two independent storage paths. Pick the one that fits your use case; most broker users will put credentials in SecretStore.

## Start the broker

```bash
npx secretless-ai broker start
```

```
  Secretless Broker

  Starting credential broker daemon...
  Broker is running.

  PID:          12345
  HTTP port:    19421
  Socket:       /Users/you/.secretless-ai/broker.sock
  AIM:          not configured
  Policy file:  (default)

  Press Ctrl+C to stop.
```

The daemon is foreground by default. In a second terminal:

```bash
npx secretless-ai broker status
```

```
  Secretless Broker Status

  Status:       running
  PID:          12345
  Uptime:       5s
  HTTP port:    19421
  Socket:       /Users/you/.secretless-ai/broker.sock
  AIM:          not configured
  Policies:     0
  Requests:     0
```

Stop the daemon:

```bash
npx secretless-ai broker stop
```

## Authenticate to the broker

The broker generates a random bearer token on start and writes it to `~/.secretless-ai/broker.token` (mode `0600`). Any client resolving a credential must pass it:

```bash
TOK=$(cat ~/.secretless-ai/broker.token)
curl -H "Authorization: Bearer $TOK" http://127.0.0.1:19421/status
```

HTTP routes:

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Health check |
| `GET` | `/status` | Uptime, request count, policy count, AIM state |
| `POST` | `/resolve` | `{agentId, credentialName}` -> `{value}` or 403 |

Both the HTTP port and a Unix socket at `~/.secretless-ai/broker.sock` accept the same routes. The socket is `0600`, same user only.

## Write a policy

Default deny. Without a policy, every `/resolve` returns 403.

Create `~/.secretless-ai/broker-policies.json`:

```json
{
  "version": 1,
  "rules": [
    {
      "id": "scanner-github-readonly",
      "agentSelector": "scan-*",
      "credentialSelector": "GITHUB_TOKEN",
      "constraints": {
        "rateLimit": { "maxPerMinute": 30 },
        "timeWindow": { "start": "09:00", "end": "18:00" }
      },
      "effect": "allow"
    }
  ]
}
```

Supported constraints:

- `timeWindow` — 24h, supports overnight (e.g. `22:00`–`06:00`)
- `rateLimit.maxPerMinute` — per agent + credential pair
- `minTrustScore` — AIM-only, see below
- `requireCapability` — AIM-only, see below

A rule is refused if it names anything else, including a constraint this build
cannot apply and a top-level field it does not read. The refusal names the key
and the legal set. This is deliberate: a constraint that is accepted but not
applied drops the restrictive half of your rule and keeps the permissive half,
while every status surface reports the rule loaded.

That includes documentation keys — a `comment` or `description` beside `id` is
refused today. An `x-` prefixed annotation namespace is planned; until it lands,
keep notes outside the rule objects.

`scopeCheck` was listed here until 0.22.1 and is no longer accepted. It never
denied a request: the check compared an empty current-permission list against
the baseline, so it could not observe an expansion. Enforcing it needs live
permission discovery in the resolve path, which is tracked separately. A rule
naming it is refused rather than silently ignored, so that a policy relying on
it fails visibly instead of appearing enforced.

Reload by restarting the daemon. Or pass `--policy-file <path>` on start to use a non-default location.

## AIM-connected mode

If you run an AIM server and want trust-score / capability policy constraints to work:

```bash
export SECRETLESS_AIM_TOKEN=<bearer-token>
npx secretless-ai broker start --aim-url https://aim.oa2a.org
```

Or on the flag:

```bash
npx secretless-ai broker start --aim-url https://aim.oa2a.org --aim-token <bearer-token>
```

Prefer the env var — CLI tokens are visible in `ps aux`.

Check AIM wiring:

```bash
npx secretless-ai broker status
```

```
  AIM:          configured (reachable)
```

Three possible AIM states:

| Status | Meaning |
|--------|---------|
| `not configured` | `--aim-url` was not passed |
| `configured (reachable)` | AIM responded to `/health` at startup |
| `configured (unreachable)` | `--aim-url` set but AIM did not respond — trust-score / capability constraints will never be satisfied until AIM comes back |

If AIM returns 4xx on agent identity lookups (typically 401 from a missing or bad token), an `aim_auth_error` event lands in `~/.secretless-ai/broker-audit.log` with the status and URL. Check the audit log if your trust-score rules appear to never match.

## Audit log

Every resolve, every auth failure, every startup and shutdown — `~/.secretless-ai/broker-audit.log`, one JSON event per line.

```bash
tail -f ~/.secretless-ai/broker-audit.log
```

```json
{"timestamp":"...","eventType":"resolve","agentId":"scan-01","credentialName":"GITHUB_TOKEN","policyId":"scanner-github-readonly","result":"allowed","reason":"Allowed by rule ...","latencyMs":3}
{"timestamp":"...","eventType":"auth","agentId":"unknown","credentialName":"","policyId":"","result":"denied","reason":"Unauthorized access attempt from 127.0.0.1","latencyMs":0}
```

## Client integration

An agent resolving a credential from the broker makes a POST with its agent ID and the credential name. Example in shell:

```bash
TOK=$(cat ~/.secretless-ai/broker.token)
curl -s -X POST \
  -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d '{"agentId":"scan-01","credentialName":"GITHUB_TOKEN"}' \
  http://127.0.0.1:19421/resolve
```

```json
{"value":"ghp_..."}
```

Denied requests return HTTP 403 with a reason:

```json
{"error":"Access denied","reason":"No matching allow rule (default deny)"}
```

## Stop

```bash
npx secretless-ai broker stop
```

The daemon removes the socket, pid file, and auth token on shutdown.

## Troubleshooting

- **`broker status` shows `Policies: 0` but I have a policy file** — confirm the file is at `~/.secretless-ai/broker-policies.json` or you passed `--policy-file`. Restart the daemon after edits. `broker status` now pulls live values from the running server, so a zero means the daemon really loaded zero rules.
- **All `/resolve` calls return 403 "default deny"** — write an `allow` rule that matches your `agentId` and `credentialSelector`. Check the audit log for the exact input.
- **AIM shows `configured (unreachable)`** — probe the URL yourself: `curl -s -o /dev/null -w "%{http_code}\n" <aim-url>/health`. Common causes: wrong URL, network segmentation, AIM not deployed to that host.

## Next steps

- [Bring Your Own Vault](bring-your-own-vault.md) -- Connect the broker to HashiCorp Vault or 1Password
- [Team Setup](team-setup.md) -- Shared backend + CI/CD
- [Protect My Credentials](protect-my-credentials.md) -- The simpler flow when you don't need the daemon
