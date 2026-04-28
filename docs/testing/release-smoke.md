# secretless-ai release smoke test

**Run before every tag push to `v*`. ~10 minutes by hand.**

Every item came from a real bug or regression. Don't skip without writing down why.

## 0. Build + tests

```bash
cd secretless-ai
git status                 # clean, or only the branch you intend to ship
npm ci                     # lockfile valid
npm run build              # zero output, zero errors
npm test                   # all green (current baseline: ~809 tests)
```

Fail the release if any step is red.

## 1. Help and version

```bash
node dist/cli.js --help     # prints the help block; no telemetry line here
node dist/cli.js --version  # prints two lines: version + telemetry disclosure
```

The `--version` output must be exactly two lines:
```
secretless-ai 0.16.0
Telemetry: on (opt-out: OPENA2A_TELEMETRY=off  •  details: opena2a.org/telemetry)
```

If the second line is missing, the `versionLine()` helper isn't wired or the SDK init failed silently.

## 2. Core commands work end-to-end (3 min)

```bash
TMP=$(mktemp -d) && cd "$TMP"
echo 'OPENAI_API_KEY=sk-fake-deadbeef' > .env
node /path/to/secretless-ai/dist/cli.js init .         # creates .secretless/
node /path/to/secretless-ai/dist/cli.js scan .         # detects fake credential
node /path/to/secretless-ai/dist/cli.js status .       # reports Clean or N findings
node /path/to/secretless-ai/dist/cli.js verify .       # verify pass
```

Fail if any command panics or returns the wrong status.

## 3. Telemetry disclosure surfaces and opt-out (2 min)

**Do NOT point at the production endpoint while smoking** — set `OPENA2A_TELEMETRY_URL=http://127.0.0.1:1/never` so events go to a port that refuses connections (proves fire-and-forget tolerance) instead of polluting prod aggregates.

```bash
export OPENA2A_TELEMETRY_URL=http://127.0.0.1:1/never
unset OPENA2A_TELEMETRY
rm -f ~/.config/opena2a/telemetry.json   # start clean
```

| # | Command | Expected |
|---|---------|----------|
| 3.1 | `secretless-ai --version` | Two lines: `secretless-ai 0.16.0` then `Telemetry: on (opt-out: ...)` |
| 3.2 | `secretless-ai telemetry status` | Prints `state: on`, install_id, config path, policy URL, toggle hint |
| 3.3 | `secretless-ai telemetry off` | Prints `Telemetry disabled for secretless-ai.` Then `--version` shows `Telemetry: off`. `~/.config/opena2a/telemetry.json` has `"enabled": false`. |
| 3.4 | `secretless-ai telemetry on` | Re-enables persistently. |
| 3.5 | `OPENA2A_TELEMETRY=off secretless-ai telemetry status` | Shows `state: off` even though file says `on` (env wins). |
| 3.6 | `OPENA2A_TELEMETRY_DEBUG=print secretless-ai status .` | Stderr contains a `[opena2a:telemetry]` line with the JSON payload (`tool: "secretless-ai"`, `event: "command"`, `name: "status"`, `success: true`, `duration_ms: <int>`, no PII fields). |
| 3.7 | `secretless-ai status .` (with the unreachable URL) | Command completes normally. Telemetry endpoint unreachable must not slow the command perceptibly (≤2s timeout). |

Fail the release if:
- any disclosure line is omitted
- the persisted config file leaks anything beyond `enabled` and `installId`
- the debug-print payload contains scanned secrets, file paths, env-var values, rule contents, or any field outside the locked schema (tool, version, install_id, event, name, success, duration_ms, platform, node_major)
- a command blocks more than 2 seconds when the telemetry endpoint is unreachable

## 4. Cleanup

```bash
unset OPENA2A_TELEMETRY_URL
rm -rf "$TMP"
# Restore your real telemetry config if you had one — the tests above
# overwrite ~/.config/opena2a/telemetry.json.
```
