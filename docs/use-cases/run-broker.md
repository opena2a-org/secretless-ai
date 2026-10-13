# Run the broker

**Time:** 3 minutes
**Prerequisites:** Node 20+, a storage backend configured ([Bring Your Own Vault](bring-your-own-vault.md))

The broker is a local daemon that mediates credential access for one or more agents. Policy rules gate every resolve: agent ID, credential name, time window, rate limit, optional AIM trust score and capabilities.

## When do I need the broker?

For most workflows you don't: `vault exec` (Tier 2) is enough. Reach for the broker when:

- **Multiple long-lived agents** need credentials in the same session, and you want one policy to govern all of them
- You need **per-agent rate limits** (e.g. "scan-bot gets at most 10 resolves per minute on GITHUB_*")
- You want an **audit log** of every credential access, not just the run
- You plan to wire AIM trust-score policy later

If you're running one short-lived script, skip the daemon: `secretless-ai run --only KEY -- cmd` is simpler.

## Storage: two separate stores

Important architectural note before you start:

- **Identity Vault** (`~/.aim/vault`): what `vault register` and `vault exec` use. Ed25519 identity-bound, XSalsa20-Poly1305.
- **SecretStore** (your configured backend: local, keychain, 1password, vault, gcp-sm): what `secret set`, `run --only`, and the broker's `/resolve` endpoint use.

The broker does **not** read from the Identity Vault. `vault exec` does. They're two independent storage paths. Pick the one that fits your use case; most broker users will put credentials in SecretStore.

## Start the broker

```bash
npx secretless-ai broker start
```

```
  Secretless Broker

  Starting credential broker daemon...
Broker auth token: /Users/you/.secretless-ai/broker.token
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
  Started at:   2026-10-11T09:30:00.000Z
  HTTP port:    19421
  Socket:       /Users/you/.secretless-ai/broker.sock
  AIM:          not configured
  Policies:     0
  Requests:     1
```

`Requests` counts every request the broker has received, this status query included.

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
| `POST` | `/grant` | `{agentId, atx, grant, operation}` -> `{result}` or 403. Answers 404 until a grant file is loaded ([Grants](#grants-run-an-operation-without-handing-over-the-credential)) |

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

- `timeWindow`: 24h, supports overnight (e.g. `22:00`–`06:00`)
- `rateLimit.maxPerMinute`: per agent + credential pair
- `minTrustScore`: AIM-only, see below
- `requireCapability`: AIM-only, see below

A rule is refused if it names anything else, including a constraint this build
cannot apply and a top-level field it does not read. The refusal names the key
and the legal set. This is deliberate: a constraint that is accepted but not
applied drops the restrictive half of your rule and keeps the permissive half,
while every status surface reports the rule loaded.

That includes documentation keys: a bare `comment` or `description` beside `id`
is refused. To keep a note on a rule, put it under a key starting with `x-`:

```json
{
  "id": "scanner-github-readonly",
  "x-comment": "Read-only token for the nightly scanners",
  "agentSelector": "scan-*",
  "credentialSelector": "GITHUB_TOKEN",
  "effect": "allow"
}
```

The broker accepts an `x-` key and does not act on it. It must sit on the rule
itself, beside `id`; it is refused on the file's top level, inside
`constraints` and inside a constraint. Its value must be a string. A name that
resembles a policy field is refused (`x-constraints`, `x-effect`,
`x-timeWindow`), because a note that reads like a restriction would look
applied while restricting nothing. Notes are dropped when the policy loads, so
`broker status`, `/status` and the audit log never show them.

`scopeCheck` was listed here until 0.22.1 and is no longer accepted. It never
denied a request: the check compared an empty current-permission list against
the baseline, so it could not observe an expansion. Enforcing it needs live
permission discovery in the resolve path, which is tracked separately. A rule
naming it is refused rather than silently ignored, so that a policy relying on
it fails visibly instead of appearing enforced.

Reload by restarting the daemon. Or pass `--policy-file <path>` on start to use a non-default location.

## Grants: run an operation without handing over the credential

`/resolve` returns a credential value to the agent. `/grant` does not. The agent names a grant and an operation, the broker exchanges the agent's verified identity for a short-lived scoped token at your identity provider, makes the downstream call itself, and returns only the response. The token stays in the broker.

`/grant` is off until the broker loads a grant file, and answers 404 without one. Create `~/.secretless-ai/broker-grants.json`:

```json
{
  "version": 1,
  "trust": {
    "trustedIssuers": ["did:opena2a:authority:opena2a.org"],
    "publicKeys": [
      { "algorithm": "Ed25519", "publicKeyHex": "<the issuer's public key, 64 hex characters>" }
    ],
    "crl": { "entries": [] }
  },
  "assertion": {
    "issuer": "https://broker.example.com",
    "keyId": "broker-key-1"
  },
  "providers": {
    "orders-idp": { "mode": "exchange", "tokenEndpoint": "https://idp.example.com/oauth2/v1/token" }
  },
  "bindings": [
    {
      "grant": "grant://orders-db",
      "match": { "trustClass": "orders:read", "minTrustLevel": 3, "oasbLevel": ">=L2" },
      "resolve": {
        "mode": "exchange",
        "providerId": "orders-idp",
        "scope": "orders.read",
        "audience": "https://api.orders.example.com",
        "ttlSeconds": 300
      }
    }
  ]
}
```

| Section | What it holds |
|---------|---------------|
| `trust` | The ATX issuers whose agent credentials the broker accepts (`trustedIssuers`), their Ed25519 public keys (`publicKeys`), and the agents whose credentials are revoked (`crl.entries`, each `{"agentId": "...", "reason": "..."}`). When more than one issuer is listed, each key needs a `keyId` of the form `<issuer DID>#<name>`, so one issuer's key cannot sign as another. |
| `assertion` | The identity the broker signs under. `issuer` is the `iss` claim and `keyId` the `kid` of every assertion it sends to an identity provider. Optional `keyFile` moves the signing key; a relative path is resolved against the grant file's directory. |
| `providers` | Identity providers by id. Each is an OAuth token endpoint that accepts an RFC 8693 token exchange with the broker's assertion as the subject token. `exchange` is the only mode with a provider in this version, and the endpoint must be `https` (`http` is accepted for a loopback address). |
| `bindings` | One entry per grant. `match` is what the agent's verified credential must carry; `resolve` names the provider, the scope and lifetime of the token, and the `audience` the operation is sent to. A grant with no binding is denied. |

Start the broker. Two lines report what was loaded:

```bash
npx secretless-ai broker start
```

```
Grant file: /Users/you/.secretless-ai/broker-grants.json (1 binding, 1 provider)
Broker assertion public key: /Users/you/.secretless-ai/broker-assertion.key.pub.json (new key: register it with each identity provider in the grant file)
```

Pass `--grant-file <path>` to load a grant file from another location. A path named on the command line must exist.

The first start creates the signing key at `~/.secretless-ai/broker-assertion.key` (Ed25519, mode `0600`) and writes its public half beside it as a JWK. Register that JWK with each identity provider so it accepts assertions signed by this broker. To rotate the key, stop the broker, delete the key file, start again, and register the new public key. The broker refuses to start on a key file that other users can read.

An agent presents its ATX credential, the grant, and the operation. It sends no host and no credential:

```bash
TOK=$(cat ~/.secretless-ai/broker.token)
curl -s -X POST \
  -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d @grant-request.json \
  http://127.0.0.1:19421/grant
```

where `grant-request.json` is:

```json
{
  "agentId": "orders-reader",
  "atx": { "...": "the agent's signed ATX credential, version 1.1" },
  "grant": "grant://orders-db",
  "operation": { "method": "GET", "path": "/orders", "query": { "customer": "c-123" } }
}
```

The response carries the downstream status and body, and nothing about where it came from:

```json
{"result":{"status":200,"body":{"rows":[{"id":1,"customer":"c-123","total":42}]}}}
```

Before the call is made, the broker checks, in order:

1. The credential's signature, expiry, issuer and revocation against `trust`.
2. With `--aim-url`, that AIM does not report the agent as unverified.
3. The binding's `match` predicates against the verified credential. A version 1.0 credential is denied here: its signature does not cover the capabilities and OASB level that bindings match on.

Every denial is the same `403 {"error":"denied"}`, so an agent learns nothing about the policy from it. The reason is in the audit log as a `grant` event, with the agent id and the grant. A request the broker cannot parse gets a 400 that says what is missing.

Things to know:

- The grant file is read at start. Restart the broker after any edit, including adding an agent to `crl.entries`.
- A file the broker cannot apply as written stops the start with the reason: a key it does not read, a repeated key, a misspelled predicate, an OASB floor it cannot rank. It does not start without the part it could not read.
- A binding whose `providerId` is not under `providers` loads, and every request for that grant is denied. The audit log records `no provider "<id>"`.
- `broker status` does not report grants. The two start lines above are where the loaded counts appear.

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

Prefer the env var: CLI tokens are visible in `ps aux`.

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
| `configured (unreachable)` | `--aim-url` set but AIM did not respond. Trust-score / capability constraints will never be satisfied until AIM comes back |

If AIM returns 4xx on agent identity lookups (typically 401 from a missing or bad token), an `aim_auth_error` event lands in `~/.secretless-ai/broker-audit.log` with the status and URL. Check the audit log if your trust-score rules appear to never match.

## Audit log

Every resolve, every auth failure, every startup and shutdown: `~/.secretless-ai/broker-audit.log`, one JSON event per line.

```bash
tail -f ~/.secretless-ai/broker-audit.log
```

```json
{"timestamp":"...","eventType":"resolve","agentId":"scan-01","credentialName":"GITHUB_TOKEN","policyId":"scanner-github-readonly","result":"allowed","reason":"Allowed by rule ...","latencyMs":3,"prevHash":"...","sig":"..."}
{"timestamp":"...","eventType":"auth","agentId":"unknown","credentialName":"","policyId":"","result":"denied","reason":"Unauthorized access attempt from 127.0.0.1","latencyMs":0,"prevHash":"...","sig":"..."}
```

Every line is signed. `sig` is an Ed25519 signature over the line without `sig`, and `prevHash` is the SHA-256 of the line before it in the same file (all zeros for the first line), so changing, inserting, moving or removing a line makes verification fail at the first line it affects. The broker creates the signing key on its first write: `broker-audit.log.key` (readable by you only) and its public half `broker-audit.log.pub`, both beside the log. Verify a log from Node:

```js
const fs = require('fs');
const { verifyAuditLog } = require('secretless-ai');
const log = `${process.env.HOME}/.secretless-ai/broker-audit.log`;
console.log(verifyAuditLog(log, fs.readFileSync(`${log}.pub`, 'utf-8')));
// { valid: true, records: 2 }
// on failure: { valid: false, records: 2, failedLine: 3, reason: 'record is not signed' }
```

To verify against a key an attacker on this machine cannot replace, copy `broker-audit.log.pub` somewhere else and pass that copy. Verification cannot show that lines were cut from the end of a file, and it does not hold against someone who can read `broker-audit.log.key`. A log written by an earlier version starts with unsigned lines and fails at line 1; move it aside to start a log that verifies. After a rotation each file starts its own chain, so verify `broker-audit.log.1` and the others one file at a time.

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

- **`broker status` shows `Policies: 0` but I have a policy file**: confirm the file is at `~/.secretless-ai/broker-policies.json` or you passed `--policy-file`. Restart the daemon after edits. `broker status` now pulls live values from the running server, so a zero means the daemon really loaded zero rules.
- **All `/resolve` calls return 403 "default deny"**: write an `allow` rule that matches your `agentId` and `credentialSelector`. Check the audit log for the exact input.
- **AIM shows `configured (unreachable)`**: probe the URL yourself: `curl -s -o /dev/null -w "%{http_code}\n" <aim-url>/health`. Common causes: wrong URL, network segmentation, AIM not deployed to that host.

## Next steps

- [Bring Your Own Vault](bring-your-own-vault.md): Connect the broker to HashiCorp Vault or 1Password
- [Team Setup](team-setup.md): Shared backend + CI/CD
- [Protect My Credentials](protect-my-credentials.md): The simpler flow when you don't need the daemon
