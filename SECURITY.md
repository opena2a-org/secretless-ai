# Security Policy

## Reporting a vulnerability

Report privately. Do not open a public issue for a suspected vulnerability.

**Preferred:** [Report a vulnerability](https://github.com/opena2a-org/secretless-ai/security/advisories/new)
via GitHub private vulnerability reporting. It is enabled on this repository and the report stays
private until an advisory publishes.

**Alternative:** info@opena2a.org

Include what you observed, steps to reproduce with the version you reproduced on, and what you
expected instead. If a report involves a credential, redact it and describe its shape rather than
pasting the value.

We acknowledge receipt within 48 hours and give a remediation timeline in that reply.
## Change control

Changes to the automated review and release configuration (everything under
`.github/`) require an approving review on the pull request's current head
commit from an account listed in the `approvers` line of
`.github/workflows/gate-file-approval.yml`: the GitHub user `thebenignhacker`,
or `lication-reviewer[bot]`, the bot account of the CI reviewer GitHub App.
The gate counts an approval from either account the same way, so automation
can approve those changes as well as propose them. Ordinary pull requests are
gated by status checks alone.
