# Contributing

Apache 2.0. PRs from outside the org welcome.

```bash
git clone https://github.com/opena2a-org/secretless-ai.git
cd secretless-ai && npm install && npm run build && npm test
```

A change to the guard hook that `init` writes (`generateClaudeHookScript` in `src/init.ts`) updates the snapshot of its verdicts with `SECRETLESS_UPDATE_GUARD_SNAPSHOT=1 npx vitest run src/guard-verdict-snapshot.test.ts`, and the diff of `src/fixtures/guard-verdicts.txt` shows every command it now refuses or allows.

Security issues: report privately through [GitHub private vulnerability reporting](https://github.com/opena2a-org/secretless-ai/security/advisories/new) or `info@opena2a.org`. We acknowledge receipt within 48 hours; [SECURITY.md](SECURITY.md) has the full policy.
