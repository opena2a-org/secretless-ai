# Contributing

Apache 2.0. PRs from outside the org welcome.

```bash
git clone https://github.com/opena2a-org/secretless-ai.git
cd secretless-ai && npm install && npm run build && npm test
```

A change to the guard hook that `init` writes (`generateClaudeHookScript` in `src/init.ts`) records the hook's new bytes with `SECRETLESS_UPDATE_GUARD_HOOK_BYTES=1 npx vitest run src/guard-hook.bytes.test.ts` and updates the snapshot of its verdicts with `SECRETLESS_UPDATE_GUARD_SNAPSHOT=1 npx vitest run src/guard-verdict-snapshot.test.ts`. Both run in the default configuration and under the custom rules in `src/fixtures/guard-custom-rules.yaml`. The diff of `src/fixtures/guard-hook-default.txt` and `src/fixtures/guard-hook-custom-rules.txt` is the change to the hook, and the diff of `src/fixtures/guard-verdicts.txt` and `src/fixtures/guard-verdicts-custom-rules.txt` shows every command it now refuses or allows. A change that only moves code leaves all four files as they are.

## License of contributions

Contributions are accepted under the repository's license, the Apache License 2.0 (see [LICENSE](LICENSE)). By contributing, you agree that your contributions are licensed under the Apache License 2.0.

## Sign your work

Every commit of a contribution carries a `Signed-off-by: Name <email>` line. `git commit -s` adds it. By signing off, you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org), quoted here as published there:

```text
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

No contributor license agreement is asked for. The Apache License 2.0 does not license the names and logos of the project.

Security issues: report privately through [GitHub private vulnerability reporting](https://github.com/opena2a-org/secretless-ai/security/advisories/new) or `info@opena2a.org`. We acknowledge receipt within 48 hours; [SECURITY.md](SECURITY.md) has the full policy.
