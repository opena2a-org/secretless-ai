# Contributing

Apache 2.0. PRs from outside the org welcome.

```bash
git clone https://github.com/opena2a-org/secretless-ai.git
cd secretless-ai && npm install && npm run build && npm test
```

A change to the guard hook that `init` writes (`generateClaudeHookScript` in `src/init.ts`) records the hook's new bytes with `SECRETLESS_UPDATE_GUARD_HOOK_BYTES=1 npx vitest run src/guard-hook.bytes.test.ts` and updates the snapshot of its verdicts with `SECRETLESS_UPDATE_GUARD_SNAPSHOT=1 npx vitest run src/guard-verdict-snapshot.test.ts`. Both run in the default configuration and under the custom rules in `src/fixtures/guard-custom-rules.yaml`. The diff of `src/fixtures/guard-hook-default.txt` and `src/fixtures/guard-hook-custom-rules.txt` is the change to the hook, and the diff of `src/fixtures/guard-verdicts.txt` and `src/fixtures/guard-verdicts-custom-rules.txt` shows every command it now refuses or allows. A change that only moves code leaves all four files as they are.

Security issues: report privately through [GitHub private vulnerability reporting](https://github.com/opena2a-org/secretless-ai/security/advisories/new) or `info@opena2a.org`. We acknowledge receipt within 48 hours; [SECURITY.md](SECURITY.md) has the full policy.
