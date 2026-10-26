# Changelog

## [Unreleased]

**Every broker audit record holds a closed code from `AUDIT_REASONS`
(`src/broker/types.ts`) as its reason, and the `/resolve` record and the
credential event record hold an agent id, a credential name and a policy rule
id only in parsed form or as `unparsed:<length>`.** `AUDIT_REASONS` is the 32
`GRANT_AUDIT_REASONS` codes, unchanged and in their order, then 31 codes for
the broker's other records: an AIM 4xx by status, AIM unreachable at start,
start and stop, a refused bearer token by transport, the duplicate-member
scanner not loading by endpoint, each `/resolve` policy check, a name the
broker found no value for, a store that failed, and each credential event
type. No record carries an AIM URL, an address, a module loader's or a store's
message, a policy's text or text a caller passed. The `auth` record names the
Unix socket or the HTTP port in its code and carries no address. A `resolve`
record holds the `agentId` as sent when it is at most 128 bytes and is a DID or
a name of letters, digits, `.`, `_`, `~` and `-`, and holds the
`credentialName` as sent when the broker returned a value for it or a rule's
`credentialSelector` equals it. The policy decision, the AIM lookup and the
store read still use both as sent, and the 403 body still carries the decision
as text. `AuditLogger.logEvent` takes `reason: AuditReason`, and
`AuditLogger.log` takes a `CodedAuditEntry`, whose `reason` is an
`AuditReason`. Both write any other value, passed through a cast or from
JavaScript, as `unparsed:<length>`, and both now return the entry as written.
Narrowing what a shipped method accepts is a breaking change; on 0.x it rides
a minor release, not a patch. `AuditEntry.reason` stays `string`, and records
written before this change still read and verify. `PolicyEvaluation` gains
`code`, and `PolicyEngine` gains `configures(name)`. `CredentialEventEmitter`
writes the code of the event's type in place of the caller's `reason`,
`leakContext` or `trigger`, which its methods still accept. It writes the agent
id as a `resolve` record does, and writes the secret reference and the policy
rule id as sent only when a new optional third constructor argument,
`{ credentialNames, policyRuleIds }`, lists them. It sends AIM the record it
wrote and nothing else. `AUDIT_REASONS`, `AuditReason`, `CodedAuditEntry`,
`PolicyEvaluationCode` and `CredentialEventAnchor` are exported.
`docs/use-cases/run-broker.md` lists each of the 31 codes for the broker's
other records and where to look for the detail it stands for.

**The broker's grant audit record, the `grant` event, gains two optional
members, `cgtJti` and `operationCommitment`, and names the agent by its
verified ATX DID instead of its AIM agent id. The grant audit record holds a
closed code from `GRANT_AUDIT_REASONS` (`src/broker/types.ts`) as its reason,
and holds an unverified agent id, the grant and `cgtJti` only in parsed form or
as `unparsed:<length>`.** `cgtJti` is the `jti` of the capability grant token
(CGT) minted to obtain the credential. `operationCommitment` is the SHA-256 of
a fresh 32-byte salt followed by the RFC 8785 bytes of the operation as
forwarded. The broker draws the salt only for a downstream caller that
declares, with `deliversSalt: true`, that it delivers the salt to the resource
with the operation. The grant audit record never carries the salt. The grant
audit record carries no `operationCommitment` under a caller that declares no
delivery, such as the built-in `HttpsDownstreamCaller` the broker daemon uses.
`src/broker/grant-resolver.audit-record.test.ts` and
`src/broker/grant-resolver.reason-codes.test.ts` check each member and code.

**The secretless-mcp wrapper starts a server only from the config entry
`protect-mcp` bound its secrets to, with the command they were bound with.**
`protect-mcp` stores a binding beside each client/server pair it stores and
writes its id into the entry's wrapper arguments as `--binding`. Before it
reads a secret, the wrapper checks that the entry carries a binding, that one
is stored for the pair, that the two match, and that the command and
arguments after its `--` are the ones bound. An entry that fails a check exits
1 with one line that names the check, then the fix, and nothing is started.
A server protected by an earlier version does not start until `protect-mcp`
binds it: run `npx secretless-ai protect-mcp` after upgrading. It binds, in a
home config, the one entry that reads a pair, and in the project's
`.mcp.json` an entry whose stored secrets its first backup of the file holds,
and lists the entries it bound, the ones it could not bind with why, and
copies of a bound entry. `mcp-status` says for each protected entry whether
the wrapper starts it, from the check the wrapper runs. `mcp-unprotect`
deletes a pair and its binding from the store only where the restored file
holds every stored name at an equal value, and names the stored names it left
otherwise. A project-level entry starts only in its project's directory or
below it, and no bound entry starts while a project-level config other than
its own, in its start directory or a directory above it, holds its binding:
the refusal names that file. `protect-mcp` replaces a home binding it finds
in a copy of its entry, so the copy no longer starts, and `mcp-status` names
each entry these checks stop. No command prints a binding id.

**A server bound in a project's `.mcp.json` starts only in the project
directory it was bound in.** A copy of the project in another directory does
not start it, and the refusal names the project directory the secrets are
bound to.

**On a backend several machines read, a stored server name belongs to one
config entry.** The store holds one record per client and server name, so a
teammate whose server has that name protects it under another name:
`protect-mcp` leaves the entry, names the entry the name is bound to, and says
to rename the server and run `protect-mcp` again.

**`mcp-unprotect` deletes a pair only where no entry outside the files it
restored can be the one bound to it.** It leaves a pair whose binding names an
entry in a file it did not restore, and names that entry. In a backend shared
between machines (1password, vault, gcp-sm) it leaves a pair with no binding,
since an entry on another machine may read it.

**`protect-mcp` binds a `.mcp.json` entry to a pair with no name stored only
when it stores the entry's values from its env.** Its backup of the file is
evidence only for names stored under the pair, so an entry with no value in its
env is left, and its line says to put the values in its env and run
`protect-mcp`.

**`protect-mcp` binds again a `.mcp.json` entry whose project directory
moved.** Run in the new directory, it binds the entry that carries the old
binding with a new id where the old file no longer exists on this machine, the
backend is this machine's alone (local or keychain), and this machine's backup
of the old file holds every value stored for the server. It files that backup
under the new path first, so `mcp-unprotect` there restores the file, and its
line names the old directory and any change to the command. A copy of a bound
entry whose file no longer exists is reported with that fact.

**`protect-mcp` writes a home entry's binding back into it when the entry,
at the place its binding names, carries no binding or another one**, as after a
home config is restored from an older copy. Where the entry's command changed,
the binding takes the command first. A `.mcp.json` entry in that state is left
unchanged, since its file comes with the repository, and its line says to add
the server again under a new name with its values.

**`protect-mcp` says a bound entry's file no longer exists only when it does
not.** A file it cannot check, such as one in a directory it cannot search, is
named as one whose existence could not be checked, with the error code. In a
backend shared between machines, a file absent here is named as not found on
this machine, with the backend named as read from other machines as well, so
the binding may be in use there, and no entry takes its binding over. In a
backend this machine alone uses, a home binding whose config file
was deleted is taken over by the one home entry that reads its pair. Where a
binding's entry is gone and several entries read its pair, each is left with
the line that names the others.

**Discovery and `protect-mcp`'s rewrite decide by one function which entries
run through a secretless wrapper.** An entry runs through one when its command
is `secretless-mcp`, a path ending `/secretless-mcp`, this build's wrapper, or
a path ending `/mcp-wrapper.js` that contains `secretless`, as another build's
wrapper and an installed copy do. The rewrite leaves the command of every
entry discovery reads as wrapped, and discovery reads this build's wrapper at
its own path.

**`protect-mcp` re-points an entry that runs through another build's wrapper
to the wrapper of the build that runs it**, so the checks the entry runs are
the ones `protect-mcp` and `mcp-status` report. In every config it rewrites,
an entry whose command names a secretless wrapper that is not this build's
file, compared by real path, has its command set to this build's wrapper in
the same write as its binding, whether it is bound, left or a copy. Its
arguments, `env` and key order do not change, so the command it is bound to
does not change. A bare `secretless-mcp` and a wrapper file that no longer
exists are re-pointed; a wrapper that reads a version equal to or above this
build's is left as it is. Each re-pointed entry is listed under its config,
with a count, after the entries bound in the run and before the ones left not
bound. Configs `protect-mcp` does not rewrite are left as they are.

**`mcp-status` reports each entry that runs through the wrapper by where its
pair's binding points, and separately by whether the wrapper starts it from
the directory `mcp-status` runs in.** The state is read from the binding
stored for the pair and the entry's place, for every such entry: no binding,
another entry's place, the entry's own place with no binding id or another
one, its own place and id with a changed command, or bound. An entry at its
binding's own place is never named as another entry, and an entry with no
binding id whose pair is bound elsewhere names that entry. Whether it starts
comes from the checks the wrapper runs before it starts a server, now one
function the wrapper and `mcp-status` both call, so a bound entry whose pair
holds no secret is reported as not started, as the wrapper refuses it. Under
each entry in a config `protect-mcp` rewrites, a line names what
`protect-mcp` then does for its binding, taken from `protect-mcp`'s own plan,
which reads the store and the backups and writes nothing. An entry on a
wrapper older than the first version that checks bindings, or whose version
could not be read, is reported as protected, with no start verdict, and its
line says what `protect-mcp` does about it: in a config it rewrites, the
command that re-points it; in a config it does not rewrite, that it is not
re-pointed; and where this build cannot read its own version to compare with
the wrapper's, that it is not re-pointed for that reason. `mcp-status` writes
nothing, and builds no store where the local store's directory does not
exist.

**Security: the Claude Code guard hook now also judges a Bash command with every backslash-newline pair removed, and refuses the command when it refuses that text, so `cat \` with `.env` on the next line is refused, as `cat .env` is.**
The pairs are removed until none is left, so a pair that forms only when an
inner one is removed is joined too, and the joined text is judged in one more
run of the hook, however many pairs the command holds.

**`protect-mcp` stores a server's secrets only under a client/server name no
other protected server reads, never replaces a stored value, and stores a
value from a project-level config only under a name that holds no stored
secret.** A server whose client/server name a protected server reads by, in
any config `protect-mcp` reads, a project-level one it does not rewrite
included, is listed as `not protected` with the config of that server. The
secrets of a server that does not yet run through the wrapper are stored only
under a name that holds no stored secret, or holds only the server's own
`env` names with the same values. A value from a project-level config, the
project's `.mcp.json` included, is stored only under a name that holds no
stored secret, for a server that runs through the wrapper and for one that
does not. A server left is listed under `secrets not moved`, and in the
`unmoved` list of the result `protectMcp()` returns, with a reason that names
the client/server name and the `env` names stored under it, never a value,
and the count under that list reads
`N server(s) have secrets in plaintext in their env that were not encrypted.`
`src/mcp/protect-pair-sources.test.ts` checks each case and
`src/commands/mcp.test.ts` what `protect-mcp` prints.

**A `scan` finding in a scanned file or directory names the credential its
preview names, where a PyPI token holding a Hugging Face token shape was
reported as a `Hugging Face Token` (#459).** For a line `token=pypi-` followed
by 20 letters and digits, `hf_` and 40 more, `scan --json` reported one
finding with `patternId` `huggingface` and `patternName` `Hugging Face Token`,
while its `preview` read `token=[PyPI API Token REDACTED]`: the finding took
the first pattern in list order that matched the line, and the preview writes
one marker over the token, named for the pattern that starts first on the
line. When the marker over the found value names another pattern that has a
real match under it, the finding now takes that pattern, so this line is
reported as `pypi`, `PyPI API Token`, with the fix that names
`PYPI_API_TOKEN` and the confidence of a PyPI token (0.907, where it was
0.786). Two credentials under markers of their own on one line are reported
as before, for the first pattern in list order. `src/line-mask.test.ts`
checks the line in a source file, in `config.json` and in a file named as the
scan target. `scan --history`, `scan-history` and `scan-staged` still name a
line by the first pattern in list order, so they report this line as
`Hugging Face Token`.

**`clean`, `doctor` and `init` refuse an argument they do not take, with
exit 2 (#471).** An interactive zsh with default options passes the words of
a `# remark` pasted after a command on to it, and each of these commands ran
without them at exit 0: `clean --dry-run # reads the transcripts` scanned the
transcripts, `doctor # checks the shell profiles` ran its checks, and
`init . --no-watch # sets up this project` set up the project. `clean` takes
no argument but the path after `--path`, `doctor` takes none, and `init`
takes one project directory. A command line with another is now refused
before the command runs and exits 2, naming each argument as `clean-history`
names a path it does not take:
`` `doctor` takes no argument; leave the arguments out: '#', checks, the, shell, profiles ``.
`src/followups-471.test.ts` runs each command through the CLI with one
argument and with several, and checks that `clean` and `init` wrote nothing.

**`warm --ttl`, `broker start --port`, `rules test`, `vault exec` and
`protect-mcp --backend` exit 2 for a command line they refuse (#471).**
`warm --ttl 0`, `broker start --port 0`, `rules test 'a;b'`,
`vault exec demo --` with no command after `--`, and
`protect-mcp --backend bogus` each printed the reason and exited 1, the code
`scan` gives for credentials found, where docs/scanning.md gives 2 for a
command line refused before anything ran. Each now exits 2 with the same
reason, apart from `vault exec demo --`, which prints
`Error: a command is required after --` and the usage line in place of
`Error: No command specified. Usage: secretless-ai vault exec <namespace> -- <command>`.
The exit codes in docs/scanning.md and docs/commands.md name an argument
`clean`, `doctor` or `init` does not take, and a `rules test` pattern it does
not take, among the cases of 2.

**`protect-mcp` and the `secretless-mcp` wrapper read and write one store,
`protect-mcp` goes on past a server name the store refuses, and
`mcp-unprotect` restores a config as it was before the first `protect-mcp`
run (#513).** With no backend configured, `protect-mcp` stored `local`
secrets in the OS keychain where one is available (the macOS Keychain, or the
Linux Secret Service when `secret-tool` is installed), while the wrapper gave
its store a key and read `local` from the encrypted file under
`~/.secretless-ai/mcp-vault`, so a server `protect-mcp` rewrote to run through
the wrapper found none of its secrets. On macOS, `mcp-status` printed
`Backend: keychain-macos` and the wrapper
`No secrets are stored for client "cursor", server "github" in the local backend.`
The wrapper now gives its store a key only when its arguments give
`--vault-dir` or `--vault-key`, which keep reading `local` from the encrypted
file, so for the same `--backend` argument, or none, it builds the store
`protect-mcp` builds; that message now names the backend it read
(`keychain-macos` there). With the two building one store, `protect-mcp` now
moves a secret found in the `env` of a server that runs through the wrapper
into the keychain on such a machine, where it left it with the reason
`its wrapper reads from the local encrypted file, and this run stores in keychain-macos`.
It compares the store each backend builds, not the backend names, so the
secret of a server given `--backend keychain` is moved there too, and a
reason for leaving one names the store the run uses, as in
`its --backend argument is "1password", and this run stores in keychain-macos`.
Versions before 0.12.3 stored `local` in the encrypted file with no backend
configured; the wrapper of a server protected by one of them reads it there
when its arguments give `--vault-dir` with the absolute path of
`~/.secretless-ai/mcp-vault`. A client or server name the store refuses, one
that is empty or holds a character other than `A-Z`, `a-z`, `0-9`, `-` or
`_` such as `my.server`, made `protect-mcp` print
`Error: Invalid server name: "my.server". Only alphanumeric, dash, and underscore allowed.`
and exit 1. A server with such a name is now listed as `not protected` with
the reason, one that runs through the wrapper and reads by such a name under
`secrets not moved`, and `protect-mcp` goes on to the next server and
exits 0. Each `protect-mcp` run that rewrote a file replaced its backup, so
after a second run `mcp-unprotect` restored the file as that run found it, with the
server the first run protected still running through the wrapper. A run that
rewrites a file in which a server already runs through the wrapper now keeps
the backup an earlier run wrote, so `mcp-unprotect` restores the file as it
was before the first run. `src/followups-513.test.ts` starts the built
wrapper from the arguments `protect-mcp` writes, runs `protect-mcp` with no
home directory as the command does, and runs `mcp-unprotect` after two
`protect-mcp` runs; on the commit this one starts from, 9 of its 13 tests
fail and the 4 marked CONTROL pass. `src/mcp/protect.test.ts` now expects the
secret moved, where it expected it left, for a wrapper given no `--backend`
or `--backend local` and for a run given `--backend local`.
`docs/use-cases/secure-mcp-configs.md` says which store the wrapper reads,
when a name is refused, and which backup `mcp-unprotect` restores.

**`getOrCreateAgent()` leaves an `identity.json` it cannot use in place and
rejects with the error `vault init` gives, where it wrote a new identity over
it (#505).** `getOrCreateAgent()`, which the package exports, wrote a new
identity over an `~/.opena2a/aim-core/identity.json` it could not read (a file
at mode 000) or that was not valid JSON, so a key in that file was lost, and
returned one that parsed and held no identity (`{}`) as it was, with no
`secretKey`. It now leaves the file as it is and rejects with the error
`vault init` gives in the same state, which names the file and says it
`cannot be read (EACCES)`, `is not valid JSON` or
`holds no agent identity (no agentId, publicKey or secretKey)`, then gives the
restore step and the command that moves the file aside (with the vault in
place, the vault too). With no `identity.json` it creates one as before.
`src/vault-core.test.ts` checks, with no vault, an `identity.json` that is not
JSON, holds `{}` or has no `secretKey`, and, with the vault in place, one at
mode 000: each time the error is the one `vault init` gives and the file is
unchanged.

**`vault init` says that an agent identity carries no name, where it printed
`undefined` (#506).** With an `~/.opena2a/aim-core/identity.json` that holds
`agentId`, `publicKey` and `secretKey` and no `agentName`,
`vault init --name demo` printed
`An agent identity already exists in ~/.opena2a/aim-core (agent undefined); --name demo was not applied.`
and `Agent:       undefined (aim_...)`, and exited 0. That line now says
`(it carries no name)`, and the `Agent:` line shows the `agentId` followed by
`(no name)`, with or without `--name` and before and after the vault exists.
An `agentName` that is empty or `null` is shown the same way. The command
still uses that identity, leaves the file as it is and exits 0. The `Agent:`
line shows an ESC character in a name as `\e`, as the `was not applied` line
already did. `src/vault-core.test.ts` checks these cases and runs
`vault init --name demo` through the CLI.

**`vault test` fails when the identity in `~/.opena2a/aim-core` does not
decrypt the vault's credentials (#507).** With another home's valid
`identity.json` copied over `~/.opena2a/aim-core/identity.json`, `vault test`
printed `[OK]  Vault unlocks with agent identity` and `All checks passed.` and
exited 0, while `vault exec` printed
`Vault resolution denied: Failed to decrypt credential` and exited 1:
unlocking the vault derives a key from the identity and does not check that
key against the vault. The unlock check now decrypts each credential the vault
holds with that key. When one does not decrypt, it prints
`[FAIL]  Agent identity <agent> does not decrypt <n> of <total> credential(s) in the vault:`
followed by the namespaces, then the agent the vault was created for when that
is another agent, then the fix: restore `identity.json` from a backup of the
identity the vault was created with, or store each of those credentials again
with `secretless-ai vault rotate <namespace>`, one line per namespace.
`vault test` then exits 1 and `vaultTest()` resolves to `false`. A namespace
with a space in it is printed quoted (`'two words'`), and one with an ESC
character in it is printed escaped inside `$'...'`, with `<namespace>` in its
command. After either fix step, `vault test` prints
`[OK]  Vault unlocks with agent identity (1 credential(s) decrypted)` and
`All checks passed.` and exits 0, and `vault exec` gives the command the
value. A vault that holds no credential has nothing to decrypt: with an
identity other than the one it was created with, `vault test` prints
`[OK]  Vault unlocks with agent identity (no credentials to decrypt)` and
exits 0, and a credential then stored with that identity reaches `vault exec`.
`src/vault-core.test.ts` checks these states, and the exit codes of
`vault test` and `vault exec` with the other identity in place.

**`mcp-status` reads the `env` of a server that runs through the wrapper, and
`protect-mcp` moves a secret found there into the backend (#508).**
`mcp-status` listed a server whose command is the `secretless-mcp` wrapper as
protected without classifying its `env`, and `protect-mcp` counted it as
protected and left its `env` as it was. The wrapper does not take a value out
of the file, so a key added to the `env` of such a server stayed on disk: for
a `mcp.json` holding a `secretless-mcp` server named `demo` with
`MY_SERVICE_API_KEY` in its `env`, `mcp-status` printed `+ demo: protected`.
It now classifies the `env` of every server and prints
`! demo: EXPOSED (1 plaintext secret(s))`; a wrapped server with an `env`
value it could not read gets the `?` line naming that value and no
`protected` line. `protect-mcp` stores such a secret under the name the
wrapper reads its secrets by (its `--client` and `--server` arguments),
beside the secrets already stored there, and removes it from the server's
`env`, leaving its command and args as they are. It leaves the value in place
and lists the server under `secrets not moved`, with the reason, when another
protected server in a config it reads, a project-level one it does not
rewrite included, reads its secrets by the same name (each server that reads
by a name is given every secret stored under it); when another value is
stored there under the same `env` name (the wrapper gives the server the
stored value in place of the one in its `env`); when the server's arguments
give `--vault-dir` or `--vault-key`; or when its wrapper reads from another
store than the one `protect-mcp` stores in. The wrapper reads from the
backend its `--backend` argument names, or the configured backend when it
gives none (see #513 for the store it builds for `local`).
`docs/use-cases/secure-mcp-configs.md` says what
`+ <name>: protected` means. `src/followups-508.test.ts` runs
`mcp-status` on such servers and starts the built wrapper on a server whose
value `protect-mcp` moved, `src/mcp/protect.test.ts` checks what
`protect-mcp` stores and writes in each case, and `src/commands/mcp.test.ts`
what it prints.

**`clean` gives the reason in place of a `secret set` command for a stored
secret whose name `secret set` refuses (#509).** When `clean` redacted the
value of a secret stored under `_DEMO_TOKEN`, it listed that secret among the
stored secrets it found and printed
`Next:     rotate each one at its provider, then  secretless-ai secret set NAME`,
and `secret set _DEMO_TOKEN` exits 1: the store takes a name that starts with
a digit, `_` or `-`, and `secret set` refuses each of those. When such a name
is listed, the `Next:` line now reads
`rotate each one at its provider, then store its new value`, and under it each
listed name gets a line of its own: `secretless-ai secret set <name>` for a
name `secret set` takes, and for a name it refuses
``"_DEMO_TOKEN" cannot be stored by `secret set`, which takes a letter, then
letters, digits, '_' or '-'; store its new value the way it was first
stored.`` A run that lists only names `secret set` takes prints the `Next:`
line as before. `src/followups-509.test.ts` checks these lines for one name of
each kind under `--dry-run`, for each of `_DEMO_TOKEN`, `1DEMO_TOKEN` and
`-DEMO_TOKEN` alone, for names already marked exposed, for names whose
exposure could not be recorded, and for a name `secret set` takes alone.

**`vault test` prints a `vault rotate` command that runs for a namespace that
begins with `-` (#511).** For a credential the identity in place does not
decrypt, `vault test` printed `secretless-ai vault rotate -x` for the
namespace `-x`. `vault rotate` reads a first argument that begins with `-` as
an option, so that command printed the usage line and exited 2, and
`vault rotate -- -x` was refused the same way. `vault rotate` now takes the
namespace as the one argument after `--`, with `--env <VAR>` before the `--`
when it is given: `vault rotate -- -x` and `vault rotate --env <VAR> -- -x`
rotate `-x`. For such a namespace `vault test` prints
`secretless-ai vault rotate -- -x`, and
`secretless-ai vault rotate -- <namespace>` when the namespace also cannot be
printed as itself. `vault rotate -x` still exits 2, and its usage and
`vault --help` name the second form. `src/vault-core.test.ts` runs the printed
command through the CLI with the value on a pipe, after which `vault test`
exits 0. `src/commands/vault.test.ts` checks these forms, and that
`vault rotate` refuses a missing or empty namespace after `--`, a second
argument after the namespace, and anything before the `--` other than
`--env` or `--value` with its value.

**The recording of `init` and `verify` is paced to be read, and the README
shows it in its Quick start with a caption.** The tape typed 40 ms a
character, ran each command 300 ms after its last character and held the
output of `init` for 5 s, in a 120 by 40 terminal that a README column scales
down to small type. It now types 120 ms a character, waits 800 ms before each
Enter and holds the two steps for 10 s and 9 s, in a 110 by 28 terminal. Each
hold is at least the time its sentence in the new
`docs/vhs/init.narration.json` takes at 150 words a minute plus 0.5 s, so
spoken narration can be added without a new recording. The tape marks its
steps with `# step:` comments and takes a screenshot of each
(`docs/vhs/init-s1.png`, `docs/vhs/init-s2.png`). `docs/vhs/record-init.sh`
moves the MP4's index in front of its media so a web page's `<video>` plays
while it downloads, encodes a VP9 WebM beside it (both stay in the ignored
`docs/vhs/out/`), and writes `docs/vhs/init.json` starting with the keys
`schema`, `surfaceClass`, `tool`, `version`, `prerelease`, `script`,
`scriptSha256`, `recorder`, `commands`, `steps`, `fixture`, `fixtureSha`,
`fixtureUncommittedChanges`, `ranAtUtc`, `durationSeconds`, `outputs`,
`capture`, `narration`, `pace`, `exitCodes` and `meteredCostUsd`; the keys it
wrote before follow them. It then writes the README block between
`<!-- demo:init:start -->` and `<!-- demo:init:end -->`: the GIF, the caption
`Recorded with secretless-ai <version> on <date>`, which ends with
`(pre-release build)` unless the build is the published package or a pack of
the commit the tag `v<version>` names, and links to the text version and the
sidecar. The Documentation list no longer links the recording. The Install
block lists the npm and Homebrew commands without comments, where it also
repeated the Quick start's `npx secretless-ai init` (`docs/install.md` keeps
that line), and the links at the end of the README no longer repeat the
Website and Discord links at its top. The recording was rendered again from
the current source, so it shows `init` creating `.claude/settings.json` with
147 deny patterns and the transcript watcher line that the previous recording
predates. `src/recording-sidecar.test.ts` holds the tape, the narration, the
sidecar and the README block to all of this. No command, flag, exit code or
output changed.

**`vault test` exits 1 when a check fails and gives the step `vault init`
gives, and `vault init` leaves an `identity.json` it cannot use in place
(#502).** `vault test` on an empty home printed
`[FAIL]  No agent identity found` and exited 0, so a script that ran it as a
check saw success. It now exits 1 after a `[FAIL]` line for a missing or
unusable identity or a missing vault, and 0 after `All checks passed.`;
`vaultTest()`, which the package exports, resolves to `false` where it prints
`[FAIL]` and to `true` after `All checks passed.`. With the vault in place and
no identity in `~/.opena2a/aim-core`, `vault test` gave
`Fix: secretless-ai vault init`, which `vault init` refuses in that state with
exit 1. It now gives the restore step and the
`mv ~/.aim/vault ~/.aim/vault.old && secretless-ai vault init` command that
`vault init` prints, and gives `Fix: secretless-ai vault init` only when there
is no vault. With no vault, `vault init` wrote a new identity over an
`~/.opena2a/aim-core/identity.json` it could not read (a file at mode 000)
and exited 0, so the key in that file was lost. An `identity.json` that
parsed and held no identity (`{}`) made `vault init --name demo` print
`(agent undefined)` and a Node `TypeError`, and made `vault list` print the
`TypeError` with the vault in place. `vault init` and the vault commands that
open the vault now leave the file as it is and exit 1 with a line that names
`~/.opena2a/aim-core/identity.json` and says it `cannot be read (EACCES)`,
`is not valid JSON` or
`holds no agent identity (no agentId, publicKey or secretKey)`, then the
restore step and the command that moves the file aside
(`mv ~/.opena2a/aim-core/identity.json ~/.opena2a/aim-core/identity.json.old && secretless-ai vault init`),
or, with the vault in place, moves the vault and the file aside.
`vault test` gives the same step. `src/vault-core.test.ts` checks each of
these states, that the file is unchanged, and the exit codes of `vault test`.

**`vault list` and the other vault commands no longer write an agent identity
before `vault init`, and `vault init --name` says when it keeps the name of an
identity that already exists.** On a home with no vault, `vault list` printed
`Error: Vault not initialized. Run:` / `secretless-ai vault init` and exited 1,
and had first written a new agent identity, its secret key included, to
`~/.opena2a/aim-core/identity.json`. `vault register`, `rotate`, `revoke`,
`exec`, and `migrate` with entries to move, did the same. A later
`vault init --name demo-agent` then used that identity and printed
`Agent:       secretless-agent (aim_...)`, and nothing said that `--name` was
not applied. Each of these commands now checks for the vault before it reads
the identity, and only `vault init` creates one: the same error and exit 1
leave the home as it was. With the vault in place and no identity that can be
read, they and `vault init` exit 1 with
`Error: Vault exists, but no agent identity could be read from ~/.opena2a/aim-core.`,
the restore step, and the command that moves the vault aside and starts a new
one (`mv ~/.aim/vault ~/.aim/vault.old && secretless-ai vault init`), where
they created a new identity, which cannot decrypt the credentials in the
vault. `vault init --name <name>` with an identity of another name that it
can read in `~/.opena2a/aim-core` prints
`An agent identity already exists in ~/.opena2a/aim-core (agent <existing name>); --name <name> was not applied.`
before its result and uses that identity unchanged: other tools that use
`@opena2a/aim-core` can share that directory, so an identity that can be
read is not renamed or replaced. An `identity.json` that is there and cannot
be used is left in place too: see the entry above. With no identity there,
`--name` names the new one as before, and without `--name` nothing new is
printed. `getVaultStore()`, which
the package exports, no longer creates an identity either.
`src/vault-core.test.ts` runs the six commands on an empty home and checks
that the home is still empty afterwards, checks the refusal with the vault in
place and the identity removed, and checks that the `--name` line comes before
`Identity Vault initialized.` and before `Vault already initialized`, with
`identity.json` unchanged.

**`verify` counts the transcript files it found credentials in, where it
printed the number of credentials as a number of files.** With one transcript
holding two GitHub tokens, `verify` printed `GitHub Token in 2 transcript files`,
where `status` printed `2 credentials in the 1 most recent transcript` and
`clean --dry-run` printed `2 credential(s) in 1 file(s)`. A credential type
found more than once now prints the number of values and of distinct files:
`2 in 1 transcript file (~/.claude/projects/<project>/<session>.jsonl: lines 3, 7)`
when every value is in one file, with its line numbers sorted and listed once,
and `3 in 2 transcript files` otherwise. One value still prints its
`file:line`, and the verdict, the exit code and the order of the lines are
unchanged. `src/verify-transcript-count.test.ts` checks each case.

**`secret set` adds no second shell hook line when an empty line separates
the hook's comment line from a working hook line (#498).** With `~/.bashrc`
holding `# secretless-ai: auto-load secrets from vault`, an empty line and
then the hook line `secret set` writes, `secret set` read the empty line as a
missing hook line: it printed `~/.bashrc has the line "# secretless-ai:
auto-load secrets from vault" with no command under it.`, asked `Add a hook
to ~/.bashrc that exports every stored secret in each new shell? [y/N]`, and
after `y` wrote a second hook line under the comment line, so a bash shell
that read the profile ran the hook twice. The check now reads the lines of
the whole profile, not only the line under the comment line, and when one of
them runs the hook `secret set` prints nothing about the hook, asks nothing
and leaves the profile as it is. A line runs the hook when it is the hook
line `secret set` would write, a hook line it wrote earlier whose command is
found, or a line of your own, not a comment, that contains
`secretless-ai env`; spaces around the line are ignored. Such a line above
the comment line, after an empty line or a line of spaces under it, after a
hook line under it whose command was not found, or in a profile with no
comment line now gets no second hook line. When the lines after the empty
line run no hook, as with a commented-out `eval "$(secretless-ai env)"` or a
hook line whose command was not found, the hook line is still written under
the comment line.

**`watch` logs the reason in place of a `secret set` command for a stored
secret whose name `secret set` refuses (#499).** When `watch` redacted a
transcript holding the value of a secret stored under `_DEMO_TOKEN`, it marked
that secret exposed and logged
`Stored secret _DEMO_TOKEN marked exposed. Rotate it at its provider, then: secretless-ai secret set _DEMO_TOKEN`,
and that command exits 1 with `Error: Invalid secret name. Use letters,
numbers, underscores, hyphens. Must start with a letter.`: the store takes a
name that starts with a digit, `_` or `-`, and `secret set` refuses each of
those. For such a name the line now reads
``Stored secret _DEMO_TOKEN marked exposed. Rotate it at its provider, then
store the new value the way this one was first stored. "_DEMO_TOKEN" cannot be
stored by `secret set`, which takes a letter, then letters, digits, '_' or
'-'.`` A name `secret set` takes still gets the `secret set` command, and the
exposure is recorded under either kind of name. `src/followups-499.test.ts`
checks the line for `_DEMO_TOKEN`, `1DEMO_TOKEN` and `-DEMO_TOKEN`, that
`secret set` refuses each of the three without opening the store, and the line
for `DEMO_TOKEN`.

**The README opens with what Secretless does, and its limits have their own
section near the end.** The README's opening paragraph, which `package.json`
repeats as the description `npm search`, `npm view` and the registry listing
show and which top-level `--help` prints, ended on two limits: Cursor, GitHub
Copilot, Windsurf, Cline and Aider get instruction or ignore files that
nothing enforces, and a command that prints its own credential is not
blocked. It now says that Secretless stores API keys outside your project
files and sets up Claude Code, Cursor, GitHub Copilot, Windsurf, Cline and
Aider not to read credential files, and that in Claude Code a hook and deny
rules enforce that. Both limits are unchanged and are stated in a new
"What it does not cover" section near the end of the README and of
docs/how-it-works.md; the paragraph on what the guard cannot see moved there
from the README's usage section. `src/package-description.test.ts` holds the
description to claiming enforcement for Claude Code and no other tool, and
holds the README to that section. The listing changes with the next release.
No command, flag, exit code or output other than the opening of `--help`
changed.

**`git-credential` no longer offers `secret set` for a `--name` that
`secret set` refuses (#494).** `git-credential install --host github.com
--name _GH_TOKEN` printed
`Store:   npx secretless-ai secret set _GH_TOKEN   (if it is not stored yet)`,
and that command exits 1 with `Error: Invalid secret name. Use letters,
numbers, underscores, hyphens. Must start with a letter.`: `--name` takes any
name the store takes, which includes one that starts with a digit, `_` or `-`.
The line `get` prints when no value is stored under the name (`Store it:`),
the line it prints when the stored value holds a line break
(`Store it again as a single line:`) and the line `erase` prints
(`Replace it:`) named the same command. Each of the four lines now gives the
reason and the install command that points git at another name. For `get`
with no value stored it reads ``"_GH_TOKEN" cannot be stored by `secret set`,
which takes a letter, then letters, digits, '_' or '-'; store the token under
a name `secret set` takes, then run: npx secretless-ai git-credential install
--host github.com --name <NAME>``. The install line says
`if it is not stored yet, store the token`, the line-break line
`store the token as a single line` and the `erase` line
`store the new token`, and the command carries the `--username` the helper
was installed with. `install` still writes the helper for such a name and
exits 0, and a name `secret set` takes still gets the `secret set` command in
each of the four places. `src/followups-494.test.ts` checks the four lines for
`_GH_TOKEN`, `1GH_TOKEN` and `-GH_TOKEN`, runs the install command a line
names with `GH_TOKEN` in place of `<NAME>` and checks that the helper entry it
writes names `GH_TOKEN`, and checks each `secret set` command for `GH_TOKEN`.

**`migrate` given one backend as both `--from` and `--to`, and `backend purge`
given a `--prefix` other than `mcp` or `secret`, exit 2, and an empty
`--prefix` is refused where `purge` read it as none (#490).**
`migrate --from local --to local` printed
`Source and destination backends are the same: local` and exited 1, and the
other four backend types given twice exited 1 too. `backend purge --prefix nope`
printed `Unknown prefix: nope. Use 'mcp' or 'secret'.` and exited 1, with
`--yes` as well. 1 is the code for credentials found. Both refusals return
before a backend is built: with one `mcp/` and one `secret/` entry in the
encrypted file, `backend list` listed both after the two had run. They exit 2,
the code for a command line that was refused and ran nothing, as
`backend set nope` and `migrate --from nope --to local` do (#486).
`backend purge --prefix ''` and `backend purge --prefix=` were not refused:
`purge` read the empty prefix as no `--prefix`, so against that file each
printed `To confirm, run: secretless-ai backend purge --yes`, and
`backend purge --prefix '' --yes` printed `Deleted 2 entries from local.` and
exited 0. Each now prints `Unknown prefix: (none). Use 'mcp' or 'secret'.`, as
`backend set ''` names an empty type, exits 2 and deletes nothing. The exit
codes in docs/commands.md and docs/scanning.md name a `backend purge` prefix
the tool does not take, and one backend given to `migrate` as both `--from`
and `--to`, among the cases of 2. `src/followups-490.test.ts` runs the build
with each of the five backend types as both `--from` and `--to`, and with
`backend purge --prefix nope`, `--prefix ''` and `--prefix=`, and expects
exit 2 from each. It calls `runBackend` with `purge --prefix nope --yes` and
`purge --prefix '' --yes` against an encrypted file holding one entry of each
kind and expects both entries to remain.

**The files `init` generates name the version that wrote them, its
instruction block names no credential variable, and `scan` lists a file it
reads through a link out of the scan root with the file's real path (#127).**
The guard hook `.claude/hooks/secretless-guard.sh`, the output check
`.claude/hooks/secretless-output-check.cjs` and the block `init` writes into
`CLAUDE.md` named no version, so nothing told which release wrote the guard a
project runs. They now carry `# Written by secretless-ai <version>`,
`// Written by secretless-ai <version>` and, under the block's heading,
`<!-- Written by secretless-ai <version> -->`, as do the blocks in
`.cursor/rules/secretless.mdc`, `.github/copilot-instructions.md`,
`.windsurfrules` and `.clinerules/secretless.md`. A hook whose line names
another version differs from the one this version writes: `status` reports
`Claude Code guard script differs from the one secretless-ai <version> writes`,
and `init` replaces it and keeps a copy, as it does a hook that differs in any
other way. `.claude/settings.json` is not stamped. The block had an
`Available API keys` table with a row for each of 30 known credential
variables set in the environment `init` ran in, in a file that is usually
committed, which published which services that machine holds keys for. With
all 30 set, the blocks in those five files name none of them; each says that
`npx secretless-ai verify` names the ones it knows that the shell sets,
without their values, a command the guard hook admits. `init` leaves a block
already in a file as it is, so a block an earlier version wrote keeps its
table until it is deleted by hand. With `app.ts -> ../shared/app.ts` in the
scanned directory and a line in `shared/app.ts` that the gcp-service-account
pattern matches, `scan --json` reported the finding on `app.ts` with
`summary.outOfRoot` 0 and `outOfRootLinks` empty, and the text report did not
name `shared/app.ts`: a link to a file outside the scan root is followed, and
only a link to a directory outside it, which is not followed, was listed. Each
file read through a link out of the scan root is now listed with the absolute
real path of the file it was read from, under a new `outOfRootFileLinks` in
`--json`, counted in a new `summary.outOfRootFiles`, and in a
`1 file read through a link out of the scan root:` block in the text report,
which from the scanned directory reads `app.ts -> <real path>` above
`Verify: ls -l app.ts`. A finding in such a file carries that path under a new
`realPath` field in `--json`, and on a
`Links to: <real path> (outside the scan root)` line under its path in the
text report and in `scan --explain`. The `Fix:` of a finding in a `.env` file
read through such a link imported the link by its absolute path; it imports
the file the link leads to. The finding, its severity and confidence, and the
exit code are as before, and the listing does not set the exit code.

**Follow-ups to #485: `ignore ''` exits 2, a finding reached through a
symlink keeps its path under `--min-confidence` and is counted once when the
floor hides it, the `Verify:` line of `scan --explain` scans the path a finding
was scored for, `--version` names what turns telemetry on while it is off, a
backend type or cache duration the tool does not take exits 2, and
docs/scanning.md names the `--max-files` limit (#486).** `ignore ''` and
`ignore --pattern ''` printed the usage of `ignore` and exited 1: an empty path
or pattern counted as given. They exit 2 and write nothing, as `ignore` given
nothing does, and so does `ignore app.js ''`, whose last pattern is empty.
With `config.yaml -> scripts/app.sh` and one line in `scripts/app.sh` that the
gcp-service-account pattern matches, `scan --json` reports the finding as
`critical` (0.864) on `scripts/app.sh` with `"aliases": ["config.yaml"]`, and
so did `--min-confidence 0.8`, but `--min-confidence 0.86` reported it on
`config.yaml` with no `aliases`: the floor dropped the `scripts/app.sh` match
(0.85) before the path to report was chosen. A path whose match scored below
the floor is now among the paths that path is chosen from and `aliases` lists,
so `--min-confidence 0.86` reports it on `scripts/app.sh` with
`"aliases": ["config.yaml"]`. `summary.confidenceSuppressed` counted that one
credential 2 under `--min-confidence 0.9`, which hides it, and 1 under 0.86,
which reports it. It is 1 and 0: a credential is counted once, and only when the
floor hid it, and the text report says
`1 match scored below --min-confidence 0.9 and was hidden.` `scan --explain`
printed `Verify: npx secretless-ai scan scripts/app.sh` under that finding,
which `scan scripts/app.sh` reports as `high` 0.85, and a
`Path: env or config file (1.00)` line that described `config.yaml`. It prints
`Path: env or config file (1.00) for config.yaml: live credentials are usually kept here`
and `Verify: npx secretless-ai scan config.yaml`, which reports the finding on
`scripts/app.sh` as `critical` 0.864. Where the path reported scored the same
as the link path, as `src/app.ts` does with `.alias -> src`, the finding the
scan made for that path is the one reported, and its `Path:` and `Verify:`
lines name no other path. `--version` with a stored `telemetry off`, and
neither CI nor OPENA2A_TELEMETRY set, printed
`Telemetry: off (opt-out: OPENA2A_TELEMETRY=off  •  details: opena2a.org/telemetry)`,
a way to turn off what was off. It prints
`Telemetry: off (turn on: 'secretless-ai telemetry on'  •  details: opena2a.org/telemetry)`.
With OPENA2A_TELEMETRY=off set the hint is `turn on: unset OPENA2A_TELEMETRY`,
followed by `, then 'secretless-ai telemetry on'` when it is stored off as
well, and under CI the line gives the details alone, as the `toggle:` line of
`telemetry status` does. `backend set ''` printed `Unknown backend type: .`; it
prints `Unknown backend type: (none).`, as `backend set` does.
`backend set nope`, `migrate --from nope --to local` and `cache ttl nope`
printed their refusal and exited 1, the code for credentials found. They exit 2,
the code for a command line that was refused and ran nothing, as
`migrate --from local --to nope` does too, and the exit codes in
docs/commands.md and docs/scanning.md name a backend type or cache duration the
tool does not take among its cases. docs/scanning.md gave
`summary.eligibleFiles` as the `--max-files` value that covers every eligible
file, and `scan` refuses `--max-files` above 1000000 with exit 2. It gives it
as that value when it is 1000000 or less, and says to scan a tree with more
eligible files one subdirectory at a time.

**`scan` reports a finding under the path with no symlink in it when a
symlink in the scanned directory leads to the same file, and lists the
symlink's path as an alias (#398).** With `src/app.ts` holding a value the
scan reports and `.alias -> src` in the scanned directory, `scan --json`
reported the one finding as `.alias/app.ts` and none as `src/app.ts`, so a CI
allowlist written for `src/app.ts` did not match it: of the paths that lead to
one file, the finding kept was the one that sorted first. It is now reported
under the path with no symlink in it when the scan found it by that path too,
and the other paths it was found by are listed in code-point order under a new
`aliases` field in `--json`, and on an `Also linked as:` line under the path in
the text report and in `scan --explain`, which names the first three and counts
the rest. The finding keeps the severity, confidence and fix it was reported
with: with `.env -> scripts/env.sh`, `scan --json` reports it as `critical` on
`scripts/env.sh` with `"aliases": [".env"]`, where it reported it as
`critical` on `.env`. A finding the scan found by one path only has no
`aliases` field, and `--format sarif` gives the reported path alone. A
`.secretlessignore` rule is matched against the path the scan reads: with
`src/app.ts` in it, the scan reads that file only as `.alias/app.ts` and
reports the finding there.

**Five fresh-user findings fixed: a command given none of the arguments it
needs exits 2, `scan --max-files` above 1000000 is refused, `scan` of a
missing path names a file or directory, `telemetry status` offers a toggle
that changes the state shown, and `clean` shows its progress and run time
(#127).** A command or subcommand given none of the arguments it needs printed
its usage and exited 0 (`secret`, `scope`, `vault`, `broker`, `watch`) or 1
(`ignore`, `rules test`, `secret set`, `secret get`, `secret rm`, `secret show`,
`scope discover`, `scope check`, `scope reset`, `vault register`,
`vault rotate`, `vault revoke`, `vault exec`, `run`, `import`, `migrate`).
Each now prints the same usage and exits 2, the code for a command line that
was refused and ran nothing, as `hook`, `git-credential` and `export` given
nothing already did; `broker --help`, `watch --help` and `vault --help` exit 0.
`backend set` given no type printed
`Unknown backend type: (none). Use 'local', 'keychain', '1password', 'vault', or 'gcp-sm'.`
and exited 1; it prints the same line and exits 2. `backend set ''` exits 2 as
well.
`scan --max-files 999999999999` ran the scan without a word, and a value above
2^53 - 1 was refused as not "a positive whole number". A value above 1000000 is
now refused with
`--max-files needs a whole number from 1 to 1000000, e.g. --max-files 20000, but was given "999999999999".`,
and `scan --help` gives the range. A scan stopped at the file cap whose
eligible files need a cap above 1000000 suggests scanning one subdirectory at a
time instead of a `--max-files` value it would refuse. `scan nope.js` printed
`Directory not found: .../nope.js`; `scan` takes a file or a directory, and now
prints `File or directory not found: <path>`, while `status` and `verify`,
which take a directory, still print `Directory not found`. `telemetry status`
printed `state: off` above
`toggle: 'secretless-ai telemetry off'  or  OPENA2A_TELEMETRY=off`. The toggle
line now names what changes the state shown: `telemetry off` while it is on,
`telemetry on` while a stored `telemetry off` turns it off,
`unset OPENA2A_TELEMETRY` (then `telemetry on` when it is stored off as well)
while that variable turns it off, and no line under CI or a test runner, where
the `Off for this run` line says why. `clean` printed
`Scanning Claude Code transcripts...` and nothing more until it finished. On a
terminal it now keeps one line up to date on stderr,
`Read <files read> of <files found> files (<percent read>%)`, and blanks it
before the report; a Stop hook, a pipe or a log gets no such line. The report
names the run time, as in `Scanned: 200 files in 4.6s`. The matching is
unchanged, so a run takes as long as before. Scan findings and their exit codes
are unchanged.

**`secret set`, `secret show`, `secret get` and `secret rm` given no NAME exit
2, as `secret exposed` and `secret push` do, and `secret --help` names that
code (#254).** Each printed its usage line and exited 1. The notes of
`secret --help` now end with `A missing NAME, an unknown subcommand and an
unknown option are usage errors: each exits 2.` `src/followups-254.test.ts`
runs the build with no NAME after each of the six subcommands whose usage line
in `secret --help` takes one (`set`, `show`, `exposed`, `get`, `rm` and
`push`), with an unknown subcommand, and with an unknown option after each of
the eight subcommands those lines list, and expects exit 2 from each. A NAME
that `secret set` refuses, such as `9z`, and an empty value, as in
`secret set A=` or `secret set A` given nothing on standard input, still exit 1.

**A `secret://` reference whose path has a `.` or `..` segment is refused as
an invalid reference before a backend is built, where `resolveRef` reported
`Secret not found` for it (#387).** The Vault backend refuses a key with such
a segment before its request (#384), and `resolveRef` read that refusal as an
absent entry: with `VAULT_ADDR` set and `fetch` recorded,
`resolveRef('secret://vault/../../../other-mount/data/prod-db')` sent no
request and threw
`Secret not found: secret://vault/../../../other-mount/data/prod-db`.
`parseSecretRef` now throws
`Invalid secret reference: the path has a ".." segment, which a request URL resolves away and can point outside the backend's store. Got: "secret://vault/../../../other-mount/data/prod-db"`
for that reference, the same with `"."` for a `.` segment, and the same for
each of the five backends: the check is on the path alone. A segment that
holds dots without being `.` or `..`, such as `prod.db`, parses. The catch of
`resolveEnvRefs` took the backend of a failed reference from a second
`parseSecretRef` call, so a reference the parser refuses threw again from
inside the catch and the call rejected as a whole; it now records the refusal
in `errors`, with `backend` undefined, and leaves the reference in `resolved`
as written. `src/phantom/resolver.vault-path.test.ts` resolves the reference
above with `fetch` answering every read with a KV v2 body and asserts the
refusal and no request, and `src/phantom/ref.test.ts` covers the parser.

**The `Scanned N client(s)` line of `protect-mcp` counts clients, where it
counted configs (#484).** Since #470 the server map of each project in
`~/.claude.json` is a config of its own, so a `~/.claude.json` holding a
user-scope server and the local-scope servers of two projects gave
`Scanned 3 client(s)` for Claude Code alone. It now gives `Scanned 1 client(s)`.
`clientsScanned` in the result of `protectMcp`, which the line prints, is the
number of clients with a config checked for secrets, so a client with several
configs or several server maps counts once. `src/mcp/protect.test.ts` checks
that count for that `~/.claude.json`, for `~/.claude/settings.json` with the
project `.mcp.json` (1) and for `~/.claude.json` with `~/.cursor/mcp.json` (2),
and the test of a `~/.claude.json` with a top-level server and one project
expects 1 where it expected 2. `src/mcp-claude-json.test.ts` runs the built
`protect-mcp` on the three-map `~/.claude.json` and reads the line.

**The `purge` command in the `Fix:` block that `secret push --to azure-kv`
prints for an HTTP 409 follows `or,` on its line, so an interactive bash or
zsh given the whole block on standard input does not run it (#481).** The #479
entry below gives that block as four lines, with `--vault kv-demo --as API-KEY`:
`az keyvault secret recover --vault-name kv-demo --name API-KEY`,
`then push again`, `or remove the deleted versions for good:` and
`az keyvault secret purge --vault-name kv-demo --name API-KEY`. The `recover`
command shares its line with the `Fix:` label and the purge had a line of its
own, so given the `Verify:` and `Fix:` lines on standard input,
`bash --norc --noprofile -i` (3.2.57 and 5.3.9) and `zsh -f -i` (5.9) ran the
purge and no other `az` command. The last two lines are now one, as the
access-policy alternative in the `Fix:` for an HTTP 403 is:
`or, to remove the deleted versions for good: az keyvault secret purge --vault-name kv-demo --name API-KEY`.
Given the block, each of the three shells reports `or,` as a command not found
and runs no `az` command. `src/followups-481.test.ts` gives the block printed
before and the block printed now to `bash --norc --noprofile -i`, with `az` a
shell function that prints its words and `PATH` an empty directory, and gives
it each `az` command of the block, from the `az` on its line to the end, which
it runs as printed.

**The remarks after the `Fix:` commands that `secret push --to azure-kv`
prints for a vault name that does not resolve and for an HTTP 409 are lines of
their own, and a check of the source reads the `verify` and `fix` lines of each
`PushError` (#479).** For a vault name that does not resolve, the `Fix:` line
was `az keyvault list --query "[].name" -o tsv   (find the vault name)`. For an
HTTP 409, which `secret push` reports as a deleted secret that Key Vault keeps
for recovery, the `recover` command ended in `(then push again)`, and the
`purge` command on the line under it, which began with `or:`, ended in
`(removes the deleted versions for good)`. bash 5.3 refuses each of the three
lines with ``syntax error near unexpected token `('`` (`bash -n -c`). The
`Fix:` for a vault name that does not resolve is now
`az keyvault list --query "[].name" -o tsv`, with
`find the vault name in its output, then push again with it in --vault` on the
line under it. With `--vault kv-demo --as API-KEY`, the `Fix:` for an HTTP 409
is now four lines: `az keyvault secret recover --vault-name kv-demo --name API-KEY`,
`then push again`, `or remove the deleted versions for good:` and
`az keyvault secret purge --vault-name kv-demo --name API-KEY`. These lines
are the `verify` and `fix` arrays of a `PushError`, which `secret push` prints
under its `Verify:` and `Fix:` labels, so the checks of the source in
`src/followups-471.test.ts` and `src/followups-476.test.ts`, which read a
source line that prints a label or a string that starts ten or more spaces in,
did not match them. `src/followups-479.test.ts` finds the calls of the
`PushError` constructor, `new PushError(...)` and a subclass's `super(...)`,
through the type checker and reads the arguments each passes after the
message, `verify` and `fix`, as arrays of lines. In those it reads a string or
template literal, an array, a spread into one and both branches of a
conditional, and it follows a name to the value it is declared with, to the
values `push` or `unshift` add to it and an `=` assignment gives it, and a
parameter to the argument passed by each call the type checker resolves to
its function, or to its default. It fails on a `#` or parenthesized remark
after the command in a line it reads, and on an expression in one of those
places that is none of these, such as a call. It does not read a line given
to a `PushError` another way, and does not fail on one: for example by an
element assignment (`fix[0] = ...`), through another name for the array, by
`splice`, through a function passed by reference, as to `map`, or in a spread
of all the arguments (`new PushError(...args)`). On the source before this
change it reported the three lines and no other. The same file covers both
messages and runs each `az` command line they print through `bash -n`.

**The remarks that `secret sync`, `scope check`, `init`, the refusal of a
value that cannot be stored and the error for a local store that cannot be
decrypted printed after the command of a `Fix:` or `Verify:` line are lines of
their own (#475).** Each was on the line of its command: in parentheses, as in
`Verify:  secretless-ai mcp-status   (shows the config file for each client)`,
or, for `init` on a missing directory or a symbolic link to a missing path,
as `# run from inside your project` after `npx secretless-ai init`. Pasted,
bash refuses a line with a remark in parentheses with
``syntax error near unexpected token `('``, and an interactive zsh passes the
words of a `#` remark to the command: with `echo` in place of `npx`,
`zsh -f -i` printed `secretless-ai init # run from inside your project`.
Each remark is now a line of its own, above or under its command. With
`--from 1password`, `secret sync` prints `To replace it with 1password's:`
above its `--force` Fix, and `or add it to 1password and sync again` under its
`secret set` Fix. `scope check GCP_SA_KEY`, for a baseline whose credential is
not stored, prints `If the credential is gone, remove the baseline:` above
`Fix:    secretless-ai scope reset GCP_SA_KEY`, and
`If the credential moved, store it again:` above
`Fix:    secretless-ai secret set GCP_SA_KEY`. A value that cannot be stored
gets `Give the value as an argument, not a paste:` above its Fix, and an MCP
server value gets `shows the config file for each client` under
`Verify:  secretless-ai mcp-status`. A local store that cannot be decrypted
gets `the key derives from these` under its `printf` Verify, and
`then re-add your secrets` under `secretless-ai backend set keychain`. `init`
prints `run from inside your project` under `npx secretless-ai init` and, for
a missing directory, `or create this directory first:` above its `mkdir -p`
line. The check of the source in `src/followups-471.test.ts` looked only for
a `#` with whitespace on each side; it now also finds a remark in parentheses
set off from the command by two or more spaces, and either kind inside a style
call such as `c.dim('# ...')`, which is how the `init` remark was written.
`src/followups-475.test.ts`, `src/commands/scope.test.ts` and
`src/followups-272.test.ts` cover each message.

**Under `scan --history`, the did-you-mean for a mistyped flag is chosen from
the flags `--history` takes (#468).** It was chosen from every `scan` flag, so
it could name a flag `--history` refuses: `scan --history --explian` printed
`Unknown option: --explian (did you mean --explain?)`, and
`scan --history --explain` is refused with
`--history does not use --explain, which applies to a directory scan; give it without --history, or leave it out.`
`scan --history --include-test` suggested `--include-tests` in the same way.
The suggestion is now chosen from `--format`, `--help` and `--json`, the
flags the `Supported with --history:` line of the same refusal names, and
names `--format` as that line does: `scan --history --explian` prints
`Unknown option: --explian`, and `scan --history --fromat json` prints
`Unknown option: --fromat (did you mean --format json?)`, where it suggested
`--format <value>`. `scan --explian --history` and
`scan --history=yes --explian` print the same `Unknown option: --explian`
line. Without `--history`, `scan --explian` still suggests `--explain`. Each
still exits 2. `src/scan-history-refusals.test.ts` runs each case through the
built CLI, and `src/argv.test.ts` covers the suggestion `prepareArgv` makes
when its caller names the flags of a form of the verb.

**A check of the source finds a `#` remark after the command on a line
printed under a `Fix:` or `Verify:` label (#476).** The check of the source in
`src/followups-471.test.ts` reads only a line that prints a `Fix:` or
`Verify:` label, so it did not find the `# or create this directory first`
remark that `init` printed after the `mkdir -p` command on the line under its
`Fix:` for a missing directory, which #475 put on a line of its own.
`src/followups-476.test.ts` reads each string in the source that starts ten or
more spaces in, as a line under a label does, and fails on a `#` with
whitespace on each side, or a `#` set off from the command by two or more
spaces, written plainly or as the start of a style call such as
`c.dim('# ...')`.

**A `scan` value flag given another value flag as its value is refused for
that value, where the refusal said a flag was given "undefined" (#469).** In
`scan --min-confidence --format`, `--format` is taken as the value of
`--min-confidence`, but `scan` looked `--format` up by its spelling and read
the token after it, which does not exist, so the refusal read
`--format needs json or sarif, e.g. --format sarif, but was given "undefined".`
and, under `--history`,
`--format needs json with --history, e.g. --format json, but was given "undefined".`
`scan --max-files --min-confidence` and `scan --max-file-size --max-files`
printed "undefined" the same way for `--min-confidence` and `--max-files`.
`scan` now reads `--format`, `--min-confidence`, `--max-files` and
`--max-file-size` from the values the command line bound them to:
`scan --min-confidence --format` reads
`--min-confidence needs a number in [0, 1], e.g. --min-confidence 0.8, but was given "--format".`,
`scan --history --min-confidence --format` reads
`--history does not use --min-confidence, which applies to a directory scan; give it without --history, or leave it out.`,
and `scan --max-files --min-confidence` reads
`--max-files needs a positive whole number, e.g. --max-files 20000, but was given "--min-confidence".`
Each still exits 2. `src/scan-flag-values.test.ts` runs each ordered pair of
these four flags through the built CLI, with and without `--history`.

**`mcp-status`, `protect-mcp` and `mcp-unprotect` read the MCP servers in
`~/.claude.json` (#470).** Claude Code keeps its user-scope MCP servers at the
top level of `~/.claude.json` and its local-scope servers under `projects`,
keyed by the project's path. MCP discovery did not look in that file, which
`scan` reads: for a home directory whose servers were only there, `mcp-status`
printed `No MCP configurations found.` and `protect-mcp` left the values in
the file. The three commands now read the server map at the top level of
`~/.claude.json` and the server map in the entry of each project, each as a
config of its own, and `~/.claude.json` is in the `Looked in:` list.
`mcp-status` lists the servers of a project under a heading that names it,
such as `claude-code (/Users/you/.claude.json, project /Users/you/app)`, and
passes over a project whose server map is empty. `protect-mcp` rewrites the
servers at the top level and in the projects in one write of the file, so its
backup is the file as it was before, and `mcp-unprotect` restores the file
once and prints one `Restored:` line for it. A project's server map that is
not a JSON object is listed as `? not checked`, as a file that could not be
parsed is. `discoverMcpConfigs()` gives the config of a project's server map
the project's path as `projectKey`. `src/mcp-claude-json.test.ts` runs
`mcp-status` and `mcp-unprotect` through the built CLI.

**`protect-mcp` leaves a server as it is when a protected server reads its
secrets by the same client and server name (#470).** Secrets are stored under
the client and server name, and the wrapper of a protected server reads them
back by that name. With `GITHUB_TOKEN` set for a `github` server in
`~/.claude/settings.json` and for another in `.mcp.json`, `protect-mcp`
rewrote both to the wrapper with `--server github --client claude-code`, and
the value stored under that name was the one from `.mcp.json`. A user-scope
and a local-scope server in `~/.claude.json` can have the same name. `protect-mcp` now protects the one it reads first and leaves the other
in its file as it was, listed under its config as
`? github: not protected: its name is taken by a protected server in claude-code (/Users/you/.claude.json)`
and followed by `1 server(s) were not protected, so their secrets are still in plaintext.`
and the step to take. It reads the top level of `~/.claude.json` before its
projects, and the home directory before the project. A server is left the
same way when a server protected in an earlier run reads its secrets by that
name, as its `--client` and `--server` arguments give it. When every server
with secrets was left this way, `protect-mcp` prints
`No plaintext secrets were encrypted.` and does not print `Already clean.`.
`protectMcp()` returns these servers in `sharedName`.

**Hints name the secret, bundle and backends they are about, and the `Fix:`
and `Verify:` lines of `clean --path`, `scan --history` and the two broker
installation faults, and the bundle `import` Fix, end at their
command (#471).** Refused without a terminal,
`secret get STRIPE_SECRET_KEY` offered `secret get <NAME> --force` and
`secret show <NAME>`; it now offers `secret get STRIPE_SECRET_KEY --force` and
`secret show STRIPE_SECRET_KEY`, and `'<name>'` for a name the store cannot
hold. A second `import` of a bundle printed
`Fix:     secretless-ai import <bundle> --force   (replaces those names)`; it
now prints the bundle as given, relative to the working directory or absolute
and quoted, as `Fix:     npx secretless-ai import team.secretless-bundle --force`,
with the remark on the line above it. `backend set` printed a bare
``npx secretless-ai migrate``, which prints only its usage line; it now prints
``npx secretless-ai migrate --from local --to vault`` with the backend used
until now and the new one, and no `migrate` line when the two are the same.
The `Fix:` line of `clean --path` on a missing file, the `Verify:` line of
`scan --history` for lines before the window, and the `Fix:` line of the two
broker installation faults carried a `# remark` after the command; pasted
into `zsh -f -i`, the remark's words were passed to the command, and the
broker line, run with `echo` in place of `npm`, wrote a file named `=`. Each remark is now a line of its own
under the command. `src/followups-471.test.ts` covers each case.

**`verify` gives the `import` step for a key in `.env` (#471).** For a key in
`.env` or `.env.local` the Next Steps block printed
`Protect context:    npx secretless-ai init`, and `init` leaves the line
where it is. It now prints `npx secretless-ai import <file>` for each such
file, the step `scan` gives, then
`then delete those lines, and start the app with npx secretless-ai run -- <command>`.
A key in another file keeps the `init` line. `src/verify-next-steps.test.ts`
runs `verify` on a stand-in result.

**`scan --check-validity` names a proxy's refusal (#471).** Through a local
proxy that answers CONNECT with 403, Node's fetch throws `TypeError` with the
proxy's answer two causes down, and the reason given was the class name:
`no answer from api.sendgrid.com (TypeError)`. It is now
`(the proxy answered 403)`; a network error code anywhere in the chain of
causes is named, and with none the reason is `error`, not the class name.

**`status` puts a missing hook target's path on a line of its own (#471).**
The path in the Stop hook and prompt check rows padded every row with a
command to the width of those rows, in a project whose CLI copy was removed. The path is now printed under its row, the `→` column is set by rows
up to 100 characters, and a wider row prints its command on the line under
it. The prompt check row said `(a credential in a prompt is sent, then
redacted)` while the Stop hook's target was missing and the watcher was not
running; with neither a Stop hook that reaches its target nor the watcher
running it now says `(a credential in a prompt is sent and is not redacted)`.

**`env --help` and `setup --help` use the layout of the other commands'
help (#471).** Each now prints the usage through the CLI prefix, an
`-h, --help` line and ``Run `npx secretless-ai --help` for every command.``;
`env --help` says `env` is refused in an AI agent runtime, and `setup --help`
keeps the manifest format.

**`setup`, `vault register` and `vault rotate` read a typed value with echo
off (#471).** On a terminal each value was shown after its prompt and stayed
in scrollback; it is now read as `secret set` reads one, and `setup` prints
`Input is hidden: a value you type or paste is not shown.` above its prompts.
Ctrl-C at a `setup` prompt, and Ctrl-D at an empty one, answer it and every
later one with nothing, as they did when readline closed on them (#474);
Ctrl-D after a typed value answers the prompt with that value, as Enter does.
The sample in `docs/use-cases/team-setup.md` no longer shows the typed values.

**docs/scanning.md says a SARIF rule carries the highest severity of its
findings (#471),** so a `high` finding of a pattern also found at `critical`
is shown as Critical, and the finding's own severity is
`properties.severity`. The README names the fixture of its quick-start
sample: a project holding an empty `.claude/` directory.

**Under `scan --history`, the refusals made before the history check name
what `--history` takes (#466).** An unknown flag (`--nosuch`), a flag given
no value (`--min-confidence`) or given twice (`--format json --format json`),
a `--format` value other than `json` or `sarif` (`--format xml`), and
`--json` together with `--format sarif` are refused before `scan` reaches the
history check. Under `--history` each of these refusals printed the
`Supported:` line of a directory scan, which offers `--check-validity`,
`--explain`, `--include-config`, `--include-tests`, `--max-file-size`,
`--max-files`, `--min-confidence`, `--no-ignore` and `--show-placeholders`,
and `--history` refuses each of them. These refusals now print
`Supported with --history: --format json, --help, --json`, as the other
`--history` refusals do, and the `--format` refusal reads
`--format needs json with --history, e.g. --format json, but was given "xml".`
where it suggested `--format sarif`, which `--history` refuses. Without
`--history` they are unchanged. Each still exits 2.
`src/scan-history-refusals.test.ts` runs each case through the built CLI.

**`scan --history` and `clean-history` show the history file as
`~/.bash_history` when HOME ends in a slash (#466).** With
`HOME=/path/to/home/`, the file was shown as `~.bash_history`: a
`.bash_history` of mode 000 was reported as
`~.bash_history: could not be read (EACCES)` followed by
`Verify: ls -l ~.bash_history`, a finding as `~.bash_history:1`, and the
`clean-history` backup as `~.bash_history.bak`. A shell does not read
`~.bash_history` as a file in the home directory: `ls -l ~.bash_history`
prints `No such file or directory` in bash, and zsh stops with
`no such user or named directory: .bash_history`. The file is now shown as
`~/.bash_history` in the text report and in `scan --history --json`, the
backup as `~/.bash_history.bak`, and the Verify line reads
`Verify: ls -l ~/.bash_history`, which lists the file.
`src/scan-history-not-read.test.ts` runs such a home through the built CLI
with the file at mode 000 and then readable, and `src/history.test.ts` covers
a HOME ending in one and in two slashes.

**`clean-history` names the history file it did not read and the lines it did
not match (#466).** `clean-history` passed over a history file that is
present and could not be read, and every line longer than 4096 characters,
and then printed `No credentials found in shell history.` at exit 0. With a
`.bash_history` of mode 000 holding
`npx secretless-ai secret set STRIPE_KEY=not-a-real-value`,
`clean-history --dry-run` printed `Files scanned: 0` and
`Lines that would be redacted: 0`. With that command on a line of more than
4096 characters, it printed `Files scanned: 1` and
`Lines that would be redacted: 0`, and the run without `--dry-run` left the
line as it was. On the first home it now prints `No history file was read.`
and lists the file (`~/.bash_history: could not be read (EACCES)`, followed
by `Verify: ls -l ~/.bash_history`); on the second it prints
`No credentials found in the lines that were read.` and lists the line
(`~/.bash_history:1: longer than 4096 characters`), as `scan --history` lists
them, on a dry run and on a real run. A run that redacts a line while
something was not read prints
`History cleaned in the lines that were read. Backups saved with .bak extension.`
in place of `History cleaned. Backups saved with .bak extension.`, followed by
the same lists. The exit code is unchanged, 0, and a line longer than 4096
characters is still left as it is. `cleanHistory()` returns the two lists as
`filesNotRead` and `linesNotRead`, as `scanHistory()` does.
`src/clean-history-not-read.test.ts` runs these homes through the built CLI,
and `src/history.test.ts` covers the lists `cleanHistory` returns.

**`scan-history` and `clean-history` refuse a path (#466).** Neither takes a
path, and a path given to either was accepted and not used: with a
`.bash_history` holding
`npx secretless-ai secret set STRIPE_KEY=not-a-real-value`,
`scan-history ./some-dir` printed the shell history report at exit 1,
`clean-history --dry-run ./some-dir` ran on the shell history at exit 0, and
`clean-history ./some-dir` redacted it and wrote `~/.bash_history.bak`, none
of them naming `./some-dir`. Each is now refused with exit 2 before anything
runs, as `scan --history ./some-dir` is:
`` `scan-history` scans shell history and takes no path; to scan the path, give it to `scan`: ./some-dir ``
and
`` `clean-history` redacts credentials in shell history and takes no path; leave the path out: ./some-dir ``.
Several paths are named in one line. `src/history-verb-refusals.test.ts` runs
each case through the built CLI.

**`scan --history` names the lines and the history files it did not read
(#462).** `scan --history` matches the last 10000 lines of `~/.bash_history`
and `~/.zsh_history`, does not match a line longer than 4096 characters, and
does not read a history file that fails to open. None of the three was
reported: a `.bash_history` holding
`npx secretless-ai secret set STRIPE_KEY=not-a-real-value` on line 1 before
10000 lines of `ls`, on a line of more than 4096 characters, or in a file of
mode 000 printed `No credentials found in shell history.` at exit 0, and
`scan --history --json` wrote the summary `{"total": 0, ...}`; for the file of
mode 000 the document was the one written for a home with no history file.
With no credential found and something not read, the text report now prints
`No credentials found in the lines that were read.`, or
`No history file was read.` when no file was read. It lists a history file
not read with its error code (`~/.bash_history: could not be read (EACCES)`,
followed by `Verify: ls -l ~/.bash_history`), and the runs of lines not read
by line number and reason (`~/.bash_history:1: before the last 10000 lines`,
`~/.bash_history:2: longer than 4096 characters`), ten runs at most followed
by `… and N more`. When lines before the last 10000 are listed it prints
`Verify: npx secretless-ai clean-history --dry-run`, as `clean-history` has no
10000-line limit: on the first home above its dry run reports
`Lines that would be redacted: 1`. A finding is reported as before, followed
by the same lists. The JSON document adds `notRead`, holding `files` (`file`,
`reason`) and `lines` (`file`, `firstLine`, `lastLine`, `count`, `reason`),
written as empty lists when nothing was left unread; `summary` is unchanged.
The exit code is unchanged: 0 with no credential found, 1 with one. The
10000-line window also counted the empty string after the final newline, so
in a 12000-line file of findings ending in a newline the first line reported
was line 2002 and 9999 lines were matched; it is now line 2001, and 10000
lines are matched. `src/scan-history-not-read.test.ts` runs the three homes
above through the built CLI, and `src/history.test.ts` covers the window and
the runs of over-length lines.

**`scan --history` refuses a path and the directory-scan flags (#463).**
`scan --history` returned before the path and these flags were read:
`--include-tests`, `--include-config`, `--explain`, `--no-ignore`,
`--show-placeholders`, `--check-validity`, `--min-confidence`, `--max-files`
and `--max-file-size`. Each was accepted and had no effect, and its value was
not checked: with a `.bash_history` holding
`npx secretless-ai secret set STRIPE_KEY=not-a-real-value`,
`scan --history --min-confidence 7` printed the full report at exit 1 with
nothing on stderr, where `scan . --min-confidence 7` is refused with exit 2,
and `scan --history ./some-dir` and `scan --history --check-validity` printed
the report `scan --history` prints alone. Under `--history`, a path and each
of these flags are now refused with exit 2 and nothing on stdout, as
`--format sarif` is:
`--history does not use --min-confidence, which applies to a directory scan; give it without --history, or leave it out.`
and
`--history scans shell history and takes no path; give the path without --history to scan it: ./some-dir`.
`--format sarif`, a flag and a path given together are refused in one
message, a line for each. The refusals under `--history`, the
`--format sarif` one included, name
`Supported with --history: --format json, --help, --json` where they listed
every `scan` flag. `scan --history`, `scan --history --json` and
`scan --history --format json` are not refused.
`src/scan-history-refusals.test.ts` runs each case through the built CLI.

**`scan --history --json` writes one JSON document (#458).** `scan --history`
returned before `--json` and `--format` were read, so `scan --history --json`
printed the text report and a caller parsing stdout failed on
`Shell History Scanner`. It now writes a document with `tool`, `version`,
`findings` and `summary`. Each finding holds the `file`, `line`, `patternId`,
`patternName` and `preview` the text report prints, and `summary` holds
`total` and `filesScanned`: a `.bash_history` whose one line is
`npx secretless-ai secret set STRIPE_KEY=not-a-real-value` is reported with
`"file": "~/.bash_history"`, `"line": 1`, `"patternId": "cmd-secret-set"`, the
preview
`npx secretless-ai secret set STRIPE_KEY=[Secret in secret set NAME=VALUE REDACTED]`
and the summary `{"total": 1, "filesScanned": 1}`. The exit code is the text
report's, 1 with a credential found and 0 with none, and `--format json`
writes the same document. Under `--history`, `--format sarif` is refused with
exit 2, as `scan --history` has no SARIF form, and a `--format` value the tool
does not write and `--json` beside `--format sarif` are refused with exit 2;
each of the three printed the text report before. `scan --help` shows the form
as `scan --history [--json]`. `src/scan-history-json.test.ts` runs each case
through the built CLI.

**Every preview replaces every credential on the line with its labelled
marker, and `clean-history` redacts every pattern on a line.** The preview
under a `scan` finding, in text and in `--json`, masked the matches of the
pattern the finding reports and printed any other credential on the line as
written. `scan --history` printed the text it matched as its first four
characters, `****` and its last four, so the last four characters of a token
stayed in the preview, or printed `****` for the value of
`secret set NAME=VALUE`; and `clean-history` rewrote the matches of the one
pattern it reported and left any other credential on the line in the file.
Every preview (`scan` text and `--json`, `scan --history` and `diff`) is now
built by one masker, which finds the spans of every credential pattern on the
line as written, each through the credential characters that follow it,
merges spans that overlap, and replaces each with `[<pattern name> REDACTED]`,
the marker `scan` prints, so no character of any value is kept; `scan` cuts
its preview to 80 characters only after masking. A `.env` line holding a
GitHub token and an OpenAI project key, `gh=<token> key=<key>`, is reported
with the preview `gh=[GitHub Token REDACTED] key=[OpenAI Project Key REDACTED]`,
and a credential another pattern matches part of, such as a PyPI token with a
Hugging Face token shape inside it, is replaced whole. `scan --history`
prints the same markers: the `.bash_history` line
`npx secretless-ai secret set STRIPE_KEY=not-a-real-value` is reported with
the preview
`npx secretless-ai secret set STRIPE_KEY=[Secret in secret set NAME=VALUE REDACTED]`
and `export GITHUB_TOKEN=<token>` with
`export GITHUB_TOKEN=[GitHub Token REDACTED]`, the command and the variable
kept and the value's own marker in its place. `clean-history` rewrites each
line it counts through the same masker, with its `[REDACTED:<id>]` markers
and whole-match replacement, so every pattern's matches on the line are
replaced (`export GITHUB_TOKEN=<token>` becomes
`export GITHUB_TOKEN=[REDACTED:github-pat]`); `linesRedacted` still counts
lines. Findings, severity and exit codes do not change.

**`status` and `diff` read the generated hook scripts, and `init` says when
it replaced one that differed.** `status` printed `✓ Claude Code hook
installed` because the guard script was on disk and `.claude/settings.json`
ran it, and it did not read the PostToolUse output check at all, so a guard
edited to allow every read still reported installed and `Protected`. It now
compares `.claude/hooks/secretless-guard.sh` and
`.claude/hooks/secretless-output-check.cjs`, byte for byte, with the text
this version writes (the guard with the project's `.secretless-rules.yaml`),
and prints the ✓ guard row only for a guard that matches. Otherwise it prints
`⚠ Claude Code guard script differs from the one secretless-ai <version>
writes: <path>`, or `⚠ Claude Code guard script could not be compared:
<reason>` when the script or the rules file cannot be read, with
`secretless-ai init` as the fix and the row counted as a warning; in a
repository that tracks the file, `git diff -- <path>` shows the difference
before `init` replaces it, and re-running `status` verifies the fix. The output
check gets a row of its own: `✓ Output check hook installed (PostToolUse)`,
`⚠ Output check hook differs from the one secretless-ai <version> writes (its
credential patterns may be out of date): <path>`, or `⚠ Output check hook not
installed`. `status --json` carries `guardScript` and `outputCheck`, and
`userSettings.guardScript` for the guard the user-level settings file runs,
each `current`, `differs`, `missing` or `unreadable`; `isProtected` and
`enforcement` keep their meaning. `diff` lists the two hook scripts with the
files it already audited. `init` still rewrites a hook that differs, and no
longer labels it `(refreshed to current version)`, a cause it never checked:
it prints `replaced: it differed from the guard secretless-ai <version>
writes`, keeps the replaced bytes in `~/.secretless-ai/replaced/` (directory
0700, file 0600) with the first 12 hex digits of their SHA-256, and names
`git log -p -- <path>` to check for a change you did not make. When the copy
cannot be written it says so and replaces the file anyway. A project set up
with 0.23.0 or earlier has no output check, and its guard reads as differing
where this version writes different text; `npx secretless-ai init` writes
both.

**A hook whose copy of Secretless is gone says so, and `status` no longer
reports it installed.** The pre-commit hook, the Claude Code Stop hook and
the git credential helper name the node binary and CLI file of the copy that
installed them. Once that copy was removed, `status` still printed
`✓ Stop hook installed`, `hook status` printed `Pre-commit hook: installed`,
a commit died with a Node `MODULE_NOT_FOUND` stack trace and the Stop hook
printed `secretless-ai clean --last failed (exit 1)` on every turn. Each of
them now tests that its CLI file is there before running it and, when it is
not, prints one line naming the file and the command that reinstalls it: the
pre-commit hook exits 1 and blocks the commit (`git commit --no-verify`
still bypasses it), the credential helper exits 1 and the Stop hook exits 0.
`status` prints
`⚠ Stop hook installed, target missing: <path> (transcripts unredacted)`
with `npx secretless-ai init` as the fix (`npx secretless-ai init ~` for the
user-level settings file) and counts it as a warning; `status --json`
carries the path as `transcriptProtection.stopHookTargetMissing`, and as
`userSettings.stopHookTargetMissing` for the user-level file; `hook status`
prints `Pre-commit hook: installed, target missing: <path>` with a Verify and
a Fix line. Each names the CLI file, or the node binary when only that is
gone. A copy that runs from the npx cache, a path with an `_npx` directory
on it, is no longer written into a hook: `init`, `hook install` and
`git-credential install` write
`npm_config_offline=true npx --yes secretless-ai@<version>` for it, and
`init` prints a `Hook command:` line that says so. Re-run `init`,
`hook install` or `git-credential install` to rewrite a hook an earlier
version wrote.

**`ignore` says that `scan` keeps exiting 1 for the path it skips.** `scan`
reports a path the scanned directory's own `.secretlessignore` kept it from
reading as excluded, a gap that exits 1 (#414), so ignoring the path a finding
is on never made a scan pass, and `ignore` printed only that it wrote the line
and `Verify: secretless-ai scan`. When the line it wrote keeps `scan` from
reading a path, measured with the walk `scan` runs, it now prints
`Skipped from now on, and listed as excluded: scan keeps exiting 1 for it,
because an excluded path is not known to be clean.` and
`Read it anyway: secretless-ai scan --no-ignore`. A line that keeps `scan`
from reading nothing, such as one matching only `.txt` files, which `scan`
does not open, prints `No path counts as excluded by this line, so scan does
not exit 1 for it.` instead, and a line starting with `!`, which re-includes,
prints neither. The usage text and `ignore --help` say the
scanner skips the path and reports it as excluded (exit 1). When
`.secretlessignore` starts with the header `ignore` writes, the exclusion
block of `scan` reads `Its rules come from the tree being scanned (written by
secretless-ai ignore), not from this scanner.`; the exit code is unchanged.
The Triage helpers section of `docs/commands.md` describes `ignore` as
narrowing what `scan` reads, with examples `scan` reads (its two examples, a
`.md` file and a `*.golden.txt` glob, matched only files `scan` does not
open), and says a false positive is handled in the value: remove or rewrite
it, use `--min-confidence`, or give a sample value a placeholder word such as
`example`; there is no allow-list for a single finding.
`src/commands/ignore.test.ts` checks each message against the `--json` summary
of a scan run after it, and `src/scan-ignore-file-gap.test.ts` the header,
including the one written before #178 and a file with CRLF line endings.

**`mcp-status` reads the project-level MCP configs that `scan` reads, and
names every path it looked in when it finds none.** Before, a project holding
`.cursor/mcp.json` or `.vscode/mcp.json` got `No MCP configurations found.`
from `mcp-status` while `scan` reported a credential in the same file.
Discovery now looks in `.cursor/mcp.json`, `.vscode/mcp.json`,
`.windsurf/mcp.json` and `mcp.json` in the current directory, beside
`.mcp.json` and the home directory configs, and reads a server map under
`servers`, the key the VS Code workspace file carries, when there is none
under `mcpServers` or `mcp-servers`. A file reached both as a home config and
as a project config (`mcp-status` run in the home directory) is read once, as
the home config. `mcp-status` shows a project-level config by its path from
the project (`cursor (.cursor/mcp.json)`), with the same `EXPOSED`,
`protected`, `clean` and `not checked` lines as a home config, and shows a
bare `mcp.json`, whose client is not established, by that path alone. A
server name holding a control character is written as an escape. When
`mcp-status` or `protect-mcp` finds no config, it prints `Looked in:` and each
path, generated from the discovery list (home paths with `~`), before
`No MCP configurations found.`; `protect-mcp` no longer prints its
`Looked for configs from:` and `Supported clients:` lines. `protect-mcp`
still rewrites `.mcp.json` and the home directory configs. It leaves the
other project-level configs as they are and lists each one as
`? not checked: project-level config: see mcp-status`, because it writes this
machine's wrapper path into each config it rewrites and a project-level
config is usually committed. For an exposed server in one of those files,
`mcp-status` says to move each value out of its file and rotate it, not to
run `protect-mcp`, and `mcp-unprotect` does not list them, since nothing was
written to them. `protect-mcp` now rewrites a server map under the key it was
read from: a config whose servers were under `mcp-servers` had its secrets
stored and listed as encrypted while the file kept them in plaintext.

**`init` registers a prompt check that refuses a prompt holding a credential before Claude Code sends it, and offers the transcript watcher (#237).**
Nothing looked at the text a user submits: a key pasted into a prompt was
sent, then redacted from the local transcript afterwards, and nothing said
so. `hook --check-prompt` reads the prompt on stdin (the `prompt` member of
the JSON a Claude Code UserPromptSubmit hook receives, or plain text) and
compares it, in its own process, with the credential catalog and with the
values of the stored secrets, read through the configured backend: a local
read for the local store and the OS keychain; for Vault and GCP Secret Manager
a request to that service, and for 1Password a run of the `op` CLI, on the
first prompt and again whenever the value cache (300 s by default) has
expired, and on every prompt for a GCP project named by a manifest, which has
no cache. On a match it exits 2,
prints `{"decision":"block","reason":...}` on stdout and the reason on stderr;
the reason names the pattern (`GitHub Token`) or the stored secret's name and
the fix (`secret set NAME`, then `$NAME` in the prompt), never the value. A
variable reference such as `$API_KEY`, a documented example key such as the
access key id in the AWS docs, and a value carrying a placeholder word pass; a
stored value shorter than 8 characters is not looked for. A store that cannot
be read leaves the stored-value comparison out and the catalog comparison in.
Measured on a 10 KB prompt against the catalog and 20 stored values: the
check itself takes 0.08 ms (median of 31 runs, in process); a whole
`hook --check-prompt` process takes 113 ms (median of 11 runs) on the
machine where this was measured, of which starting Node takes 47 ms. The hook
sends no usage event. `init` writes the hook into `.claude/settings.json`
under the same pinned prefix as the Stop hook, adds it to an existing install
on re-run and lists the file as modified, and `status` reports it as
`Prompt check installed`, at project or user scope; `status --json` carries
`promptCheckInstalled`, `promptCheckScope` and `watcherDirs` under
`transcriptProtection`. As the Stop hook does, a prompt check that names the
copy by path tests that its CLI file is there before running it: once that
copy is gone it prints
`secretless-ai: prompt check not found at <path>. Reinstall: npx secretless-ai init`
and exits 1, so Claude Code shows that line and sends the prompt unchecked;
`status` prints
`⚠ Prompt check installed, target missing: <path> (a credential in a prompt is sent, then redacted)`
with `npx secretless-ai init` as the fix (`npx secretless-ai init ~` for the
user-level settings file) and counts it as a warning, and `status --json`
carries the path as `transcriptProtection.promptCheckTargetMissing`, and as
`userSettings.promptCheckTargetMissing` for the user-level file. `init` then
offers the transcript watcher: on a
terminal it asks (default yes) and installs it; `init --no-watch` skips the
question; with no terminal to ask on, or no transcript directory yet, it names
`watch install`. `watch install` now starts the watcher in the background and,
on macOS, also writes the login agent; before, it wrote the agent only, and on
Linux it did nothing. `watch start --dir <path>` and `watch install --dir
<path>`, repeatable, watch each directory given besides the default, and the
default is `projects/` under `CLAUDE_CONFIG_DIR` where that variable is set,
for `watch`, `clean`, `status` and `verify` alike. `watch status` and `status`
list the directories the running watcher covers. Each file the watcher redacts
is also shown as a desktop notification (`osascript` on macOS, `notify-send`
on Linux) naming the count, the patterns and the file, never a value. A chat
in a browser is outside the reach of these local hooks; the README says so.

**`scan --check-validity` asks the provider that issued a found credential whether it still accepts it.**
Off by default: without the flag the scanner keeps no matched value, sends no
credential anywhere, and prints what it printed before. With it, each finding
whose type has a probe is sent, over HTTPS, to that provider's own API and to
no other host (`api.github.com/user` for a GitHub token,
`gitlab.com/api/v4/user` for a GitLab token, `api.anthropic.com/v1/models`
for an Anthropic key, `oauth2.googleapis.com/tokeninfo` for a Google OAuth
access token, `slack.com/api/auth.test` for a Slack token; `scan --help`
lists the endpoint for each of the 30 credential types covered, from 21
providers), with redirects left unfollowed and a 10 second bound on each
exchange. A webhook URL is itself the credential: the path of the found URL
goes to the host that serves it, and nothing else from it. A Discord webhook
URL is fetched with GET, the webhook's read-only endpoint, at discord.com
whether the URL named discord.com or discordapp.com; a Slack webhook URL is
sent a POST whose body is `{}`, a message with no text, which Slack refuses
before posting anything. An AWS key is checked as a pair: the access key ID
and the secret access key found with it in one file make one
GetCallerIdentity request to `sts.amazonaws.com` signed with the secret
(Signature Version 4), so the key ID and the signature are sent and the
secret is not. A file is paired when its findings hold one of each, or
several of each that, taken in line order two at a time, are each one key
ID and one secret. A key ID and a secret found on one line, which the scan
reports as one finding, both count, and are never split between two pairs,
so `AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…` on one command line, or
`accessKeyId` and `secretAccessKey` in one object literal, is paired as the
two values on lines of their own are. The answer is printed
under the finding as `Validity: live` when the host answered 200 (or, for a
Slack webhook, when hooks.slack.com refused the empty message with 400
`no_text` rather than refusing the URL), `rejected` when it answered 401
(Slack states a rejection in the body of a 200, Google's tokeninfo in the
body of a 400, Discord's webhook endpoint as 404 Unknown Webhook,
hooks.slack.com as 403 `invalid_token` or 404 `no_service` or `no_team`, and
AWS STS as 403 `InvalidClientTokenId` or `SignatureDoesNotMatch`), and
`unknown` for any other answer or none, a `SignatureDoesNotMatch` that names
the request time among them, with the status or reason named. A token a
self-managed GitHub or GitLab instance issued still goes to api.github.com
or gitlab.com, which did not issue it, and a key from the AWS China or
GovCloud partition still goes to sts.amazonaws.com, whose partition did not
issue it; the answer is that host's. Types without a probe (connection
strings, private keys, AWS STS temporary keys and Stripe webhook signing
secrets among them) read `not checked`, and nothing is sent for them. An
OpenAI project key value is not sent either when it is shorter than 132
characters or the scan found a `-` or `_` right after it: the key can hold
`-` or `_`, where the pattern stops, so such a value may be only the part
before one, and the finding says so. `--json` carries the
same as `validity` on each finding and counts under `summary.validity`,
only when the flag is given; `--format sarif` carries it as
`properties.validity` on each result (#448). The same value, or the
same AWS pair, found in several files is sent once, and an AWS access key ID
paired with different secret access keys, or a secret access key paired with
different access key IDs, in the scanned files is sent with none of them.
Severity, confidence and the exit code do not change with the
answer. For library callers, `probeCredential` and
`checkFindings`, exported from the package, take a `fetchImpl` in place of
the global `fetch` and the bound as `timeoutMs`, 10 seconds by default. An
exchange with no answer within the bound reads `unknown` at the bound
whether or not that `fetchImpl` honours the abort signal it is handed, and
an answer that comes after it is not taken (#449).

**`scan --format sarif` writes the findings as SARIF 2.1.0.** The document
holds one result per finding, with its file, line, pattern name and fix and
its `patternId` as the `ruleId`, and one rule per pattern id, carrying
`security-severity` `9.0` for a `critical` finding and `7.0` for a `high`
one. It is written for `github/codeql-action/upload-sarif`, which sends it to
the repository's Security tab; the Scan in CI section of `docs/scanning.md`
shows the workflow step, and the README's task list links to it. The exit
code is the one `--json` gives, and the `--json` summary is on the run as
`runs[0].properties.summary`. `--format json` is `--json`. A format the tool
does not write, `--format` with no value, and `--json` beside `--format sarif`
are refused with exit 2 before anything runs.

**`secret get --force` is refused inside an AI agent runtime (#445).** `env`
and `export` refuse with exit 1 when one of the variables an AI agent sets in
the commands it runs holds a value: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`,
`CURSOR_TRACE_ID` or `AIDER_MODEL`. `secret get NAME --force`, the override of
the check that blocks `secret get` when stdout is not a terminal, printed the
value with exit 0 under each of them; in an agent with no guard hook for the
command, that output entered the agent's context. It now refuses under the
same check, with exit 1 and before the store is opened, whether stdout is a
pipe or a terminal. The refusal prints the line `env` prints,
`An AI agent runtime is set (CLAUDECODE), so this output would enter the
agent's context.` with the variable found, and offers
`secretless-ai run --only NAME -- <command>`, with the name given in place of
`NAME` when `secret set` would store under it. Inside an agent runtime, the
message that blocks `secret get` without `--force` leaves out its `--force`
line, and `secret --help` and the top-level help say the flag is refused
there. `src/commands/secret-get-agent-runtime.test.ts` covers each variable
with stdout a pipe and a terminal, compares the runtime line with the one
`env` prints, and checks that `--force` prints the value with no variable set.

**`broker start` accepts a socket path as long as the Node it runs under
listens on (#441).** The check from #377 held 104 bytes as the macOS limit.
Node 26.12.0 bundles libuv 1.53.0, which binds a Unix socket path of up to 253
bytes on macOS: measured on macOS 26.6.2 (Darwin 25.6.0) under that Node,
`net.Server.listen` listened on a path of 253 bytes and failed with `EINVAL`
on one of 254. There, `broker start` refused a socket path of 105 to 253
bytes with `a Unix socket path on this platform can be at most 104 bytes`,
and the daemon test that checks the limit against `listen` failed with
`expected [ 'EINVAL', 'shortened' ] to include 'listening'`. The macOS limit
is now 253 bytes under a Node whose libuv (`node -p process.versions.uv`) is
1.53.0 or later and 104 bytes under an earlier one; Linux stays at 108 bytes.
The message keeps its form, with the limit it names and the `HOME` length its
Fix line gives for the default path (226 bytes under libuv 1.53.0) following
the running Node. `src/broker/daemon.test.ts` checks both macOS limits and
the Linux one against the libuv version they apply to, and on a Node that
listens on them starts a broker on a socket path of 200 bytes and on one of
exactly the limit.

**The piped form a `secret set NAME` hint offers reads the value from a file
(#439).** When `secret set NAME` read no value, from an empty pipe or from
Enter alone at the prompt, its `Or:` line offered
`echo "value" | secretless-ai secret set NAME`. Typed with a key in place of
`value`, the key is part of the command line, and an interactive bash records
that line in its history file: the exposure README.md names for
`secret set NAME=VALUE`. The `Or:` line now reads
`cat token.txt | secretless-ai secret set NAME`, and the one printed at a
terminal that cannot turn echo off (#437) reads the same with the given name
in place of NAME, so the key comes from a file and the line typed does not
carry it. `src/commands/secret-set-input.test.ts` covers the three inputs: on
platforms other than Windows it runs the part before the pipe in a shell, in
a directory whose `token.txt` holds a key, passes its output to the
`secret set` words after the pipe, and checks that the key is stored and is
not in the line.

**`secret set NAME` at a terminal that cannot turn echo off reads nothing
(#437).** `secret set NAME` on a terminal reads the value with echo off
through the terminal input's raw mode (#234). A terminal input that reports
`isTTY` and has no `setRawMode` went to the cooked read instead: it printed
`Enter value for NAME: `, read the line in cooked mode, with echo on, so the
value showed on screen and stayed in scrollback, and stored it. That read is
gone. On such a terminal the command now prints `Error: this terminal cannot
hide typed input, so no value was read. Nothing was stored.`, a `Fix:` line
with the `--from-clipboard` form and an `Or:` line with the piped form,
attaches no reader to stdin, stores nothing and exits 1. `process.stdin` on
a terminal is a `tty.ReadStream`, which has `setRawMode`, so a terminal Node
opens itself took the hidden read already. Piped stdin is read until it
closes, as before. `src/commands/secret-set-input.test.ts` covers the
terminal without raw mode.

**A writable telemetry setting file in a directory this user cannot write to
is rewritten again (#431).** Since #429 the new content went to a new file in
the setting file's directory, which needs write permission on the directory:
with `~/.config/opena2a` at mode 0500 and a writable setting file,
`OPENA2A_TELEMETRY=off secretless-ai telemetry off` exited 1 with `EACCES` on
the `.telemetry.json.<pid>.<hex>.tmp` file and left the file unchanged. When
the directory refuses the new file with `EACCES` and the setting file exists
and this user can write it, the file is now rewritten in place. In that
layout, with `OPENA2A_TELEMETRY=off`, `telemetry off`, `telemetry on` and
`--version` exit 0, store `{"enabled": false}`, `{"enabled": true}` and
`{"enabled": false}`, and leave no other file in the directory. The in-place
write keeps the file's mode and does not truncate the file before writing:
under `ulimit -f 0`, `telemetry off` leaves the file as it was and
`telemetry status` prints `state: off`. A setting file this user cannot write
is still not replaced, and with no setting file the `EACCES` is still thrown.
A directory with the macOS immutable flag set (`chflags uchg`) refuses the new
file with `EPERM` instead, and the file is now rewritten in place there too
(#434): before that, with `OPENA2A_TELEMETRY=off`, `telemetry off` and
`telemetry on` exited 1 with `EPERM` on the `.telemetry.json.<pid>.<hex>.tmp`
file and left the file unchanged, and `--version` left the install id in it.
In that directory the three commands now exit 0, store the same settings and
leave no other file, and under `ulimit -f 0` `telemetry off` leaves the file
as it was. A setting file with the immutable flag set is not replaced, and
with no setting file the `EPERM` is thrown.
A directory with the macOS append-only flag set (`chflags uappnd`) takes the
new file but refuses to rename or remove it, with `EPERM` (#436): there, with
`OPENA2A_TELEMETRY=off`, `telemetry off` and `telemetry on` exited 1 with the
`EPERM` of the refused removal, left the setting file unchanged and left two
`.telemetry.json.<pid>.<hex>.tmp` files, and each `--version` run left the
install id and one more such file. Before a new file is made, the setting
file is now renamed to itself: on macOS that rename changes nothing in a
directory that allows it, each of these three directories refuses it, and
that refusal leads to the in-place write. In an append-only directory the
three commands now exit 0, store the same settings and leave no other file,
and under `ulimit -f 0` `telemetry off` leaves the file as it was. A rename
of the new file refused with `EACCES` or `EPERM` leads to the in-place write
as well, and a refused removal of the new file no longer replaces the error
of the write or the rename: with no setting file, an append-only directory
still keeps the new file, and the error is now the refused rename.
`src/telemetry-install-id.test.ts` covers each of these.

**A rewrite of the telemetry setting file that does not finish leaves the
previous content (#429).** The file was rewritten in place, which truncated
it first, so a write that failed part way left it empty. An empty file reads
as absent, and absent is on, so a stored `"enabled": false` was lost: under
`ulimit -f 0`, `OPENA2A_TELEMETRY=off secretless-ai --version` on a file
holding `"enabled": false` and an install id left it at 0 bytes, and the
next `secretless-ai telemetry status` printed `state: on`. The new content
is now written to a new file in the same directory, which is renamed over
the setting file. Under `ulimit -f 0`, `--version`, `telemetry off` and
`telemetry on` with `OPENA2A_TELEMETRY=off` leave the file as it was and no
other file next to it, and the status prints `state: off`. A process killed
before the rename leaves the file as it was and a
`.telemetry.json.<pid>.<hex>.tmp` file next to it. A rewritten file has mode
0600, as the telemetry library writes it; the in-place write kept the mode
the file had. A symlinked setting file stays a link and the file it points
to is rewritten, or created when it does not exist yet (#432): before that,
`OPENA2A_TELEMETRY=off secretless-ai telemetry off` through a link to a
missing file replaced the link with a regular file and left the target
uncreated. A link loop and a file this user cannot write are not replaced.
`src/telemetry-install-id.test.ts` covers each of these.

**An install id left by an earlier run is deleted on a run with telemetry
off (#426).** Since #422 no install id was created while telemetry was off,
but one already in `~/.config/opena2a/telemetry.json`
(`$XDG_CONFIG_HOME/opena2a/telemetry.json` when that is set) was kept, and
`OPENA2A_TELEMETRY=off secretless-ai telemetry on` wrote it back into the
file. On a run with telemetry off (`OPENA2A_TELEMETRY=off`, a stored
`telemetry off`, CI or a test runner) the file is now rewritten without the
install id before the command runs, keeping the stored `enabled` value, so
an explicit `"enabled": false` stays. On such a run `telemetry off` stores
`{"enabled": false}`, and `telemetry on` under `OPENA2A_TELEMETRY=off`, CI
or a test runner stores `{"enabled": true}`, each without an id. Apart from
those two commands, a file with no install id is not written. A
file that cannot be written does not stop the run: `--version` and
`telemetry status` exit 0, and the status still prints the id. A run with
telemetry on keeps and sends the stored id as before. `scan --help` says
when the file is rewritten. `src/telemetry-install-id.test.ts` covers
`--version`, a scan, `telemetry status` and `telemetry on` under
`OPENA2A_TELEMETRY=off`, `CI=true`, a stored `"enabled": false`, a file with
no `enabled` key, `XDG_CONFIG_HOME`, a read-only file, and a control run
with telemetry on.

**No install id is written while telemetry is off (#422).** Under
`OPENA2A_TELEMETRY=off`, `secretless-ai --version` and `secretless-ai scan`
wrote `{"enabled": true, "installId": "..."}` to
`~/.config/opena2a/telemetry.json` (`$XDG_CONFIG_HOME/opena2a/telemetry.json`
when that is set) when the file was absent: the telemetry library's `init`
derived and stored the id whatever the opt-out said, and the opt-out only
stopped sending. `opena2a init` runs `secretless-ai --version`, so a user who
had opted out was given an install id. On a run with telemetry off (that
variable, a stored `telemetry off`, CI or a test runner) the library's `init`
is not called, and its `status` and `setOptOut` are called only by `telemetry
on` with a stored `telemetry off` and none of that variable, CI or a test
runner set: that command turns telemetry on through the library, which stores
an install id. `--version` and a scan write no file, and `telemetry status`
prints `install_id:  none (one is created on the first run with telemetry
on)` when none is stored. Under that variable `telemetry on` and `telemetry
off` store the setting without an install id, and end with
`Off for this run: OPENA2A_TELEMETRY is set to turn it off.`, as `telemetry
status` does. `telemetry off` removes a stored install id. A run with
telemetry on creates and keeps the install id as before. `scan --help` says
the file is created when it is absent and the run has telemetry on.
`src/telemetry-install-id.test.ts` covers `--version`, a scan under each
opt-out value (`off`, `OFF`, `0`, `false`, `no`), `XDG_CONFIG_HOME`,
`telemetry status`, `on` and `off`, `CI=true`, a stored `enabled: false`, and
a control run with telemetry on.

**`doctor` asks the secret store before it says no key is stored (#418).**
With no known API key in the environment or in a shell profile, it printed
`[INFO] No API keys found yet.` and ended with `No keys stored yet. Store
one: npx secretless-ai secret set NAME` without reading the store, so a user
whose keys `secret set` had stored, as that line advises, was told nothing
was stored. The finding now reads `No API keys found in the environment or
in shell profiles.`, and in that state, and only then, `doctor` reads the
store as `secret list` does. When the store holds names, the last line reads,
for example, `No API keys found in the environment or in shell profiles. The
secret store (local backend) holds 1 secret. List them: npx secretless-ai
secret list`, and the `Store one` advice is left out. When the store cannot
be read, the last line says so and points to `secret list` instead of
calling it empty. With an empty store the last line is unchanged. The
`health` value and the exit code, 0, are unchanged. `src/doctor.test.ts`
covers one stored name, two stored names beside a profile that could not be
read, and a local store file that cannot be decrypted.

**`clean --path` refuses a path that is not there or a file that is not a
transcript, and never calls 0 files clean.** `clean --dry-run --path
transcript.log` and `clean --dry-run --path <missing>` printed `Scanned: 0
files` and `No credentials found. Transcripts are clean.` at exit 0, and an
existing file whose name does not end in `.jsonl` or `.md` read the default
`~/.claude/projects` instead, so `--path notes.txt` inside a project directory
reported the session beside it. A missing path now prints `Error: <path> was
not found. Nothing was read.`, a file other than a `.jsonl` or `.md`
transcript prints `Error: <path> is not a transcript (.jsonl or .md). Nothing
was read.`, and a path that cannot be looked up names the error code, each on
stderr at exit 1 with a `Verify:` and a `Fix:` line and before anything is
read. A run that reads no file, such as one on an empty directory, prints
`Scanned: 0 files — nothing to report.` instead of calling the transcripts
clean. `discoverTranscripts` returns no files for such a target rather than
the default directory's. A directory or a `.jsonl` or `.md` file is read as
before. `src/transcript.test.ts` and
`src/commands/transcript.clean-path.test.ts` cover a missing path, a path
under a file, a `.log` file, a `.txt` file beside a session, an empty
directory, and a directory and a file that are still read.

**`doctor` reports a fresh install with no keys as nothing stored yet, not
as BROKEN, and exits 0.** With no known API key in the environment or in a
shell profile, it printed `[ERROR] No API keys found in env vars or shell
profiles` with `Fix: Add export lines to ~/.zshenv` (on Windows, `setx`),
then `BROKEN: Keys are not available to subprocesses.` and exited 1, so the
first run after `verify` pointed at it told a new user to write keys in plain
text into a profile AI tools can read. It now prints `[INFO] No API keys
found in the environment or in shell profiles.` and exits 0; `--fix` is not
offered. With an empty store it adds `Fix: Store one: npx secretless-ai
secret set NAME` and ends with `No keys stored yet. Store one: npx
secretless-ai secret set NAME`; when a profile could not be read, the last
line reads `No keys found in the profiles that were read.` instead. A key
exported only in an interactive-only profile is still `BROKEN` with exit 1.
For library callers, `doctor()` returns the new `health` value `'empty'` for
this state, where it returned `'broken'`. `doctor()` reads the environment
and shell profiles, not the store; the `doctor` command asks the store
before it says nothing is stored (entry above).

**`vault register` refuses an empty value instead of storing it.** With stdin
at end of input, as in `vault register github </dev/null`, it printed
`Credential registered in namespace "github".` and exited 0, having stored a
value of length 0 that `vault exec` then exported as `GITHUB=` and `vault test`
counted as a stored credential. `--value ''` read stdin instead, and an
environment variable that was set but empty was reported as not set. A value
that is empty after trimming, from `--value`, `--env` or stdin, is now refused
with `Error: no value provided. Pipe the value on stdin, or use --env NAME.`
and exit 1, before the namespace is created, the value is stored or the audit
log is written, as `secret set` already refuses one.

**`vault rotate` refuses an empty value instead of storing it (#417).** With
stdin at end of input, as in `vault rotate github </dev/null`, it printed
`Credential rotated for namespace "github".` and `New version: 2` and exited
0, having passed the empty value to the store as the new version of the
credential. A value that is empty after trimming, from `--value`, `--env` or
stdin, is now refused with `Error: no value provided. Pipe the value on stdin,
or use --env NAME.` and exit 1, before the value is stored or the `rotate`
audit event is written, so the previous version stays in place. `--value ''`
and an environment variable that is set but empty are now taken as given
values and reach that check; an unset variable keeps its existing error.
`src/vault-core.test.ts` covers `--value ''`, stdin at end of input, stdin
holding only whitespace, an empty environment variable, a piped value that
still rotates, and the CLI exit code with stdin at end of input.

**`init` counts hardcoded credentials the way `scan` does, so its warning and
the `scan` it points to report the same number.** `init` counted with a
scanner of its own: the fixed config-file list, matched line by line with no
placeholder check and no source or key files. On a copy of a tree whose every
value is marked FAKE it printed
`Warning: 21 hardcoded credentials in config files  → secretless-ai scan`
over a `scan` that printed `No hardcoded credentials found.` and
`21 values looked like a placeholder and were hidden.`, and on a tree whose one
credential is in `src/app.ts` it printed no warning while `scan` printed
`1 credential found`. The count now comes from the same project scan `status`
uses, and the line reads
`Warning: 1 hardcoded credential in this project  → secretless-ai scan`. When
every match is a placeholder it prints nothing; `scan` discloses the hidden
count. The walk stops at the scan's default 5000-file cap; when it stops
there, or a path cannot be read, `init` prints
`Credential scan incomplete: part of this project was not read  → secretless-ai scan`
instead of leaving the count to read as complete. The home-directory files a
bare `scan` also reads, such as `~/.claude/settings.json`, are not part of the
project and are not counted.

**The pre-commit hook, the Claude Code Stop hook and the git credential
helper run the copy of Secretless that wrote them.** `hook install`, `init`
and `git-credential install` write the node binary and CLI file of the
running copy as quoted absolute paths, the form the shell hook already uses,
or `npm_config_offline=true npx --yes secretless-ai@<version>` when those
paths cannot be resolved; none of them writes `npx secretless-ai` without a
version any more. Re-running `init` replaces the Stop hook an earlier
version wrote, and re-running `hook install` or `git-credential install`
replaces the earlier hook or helper entry. The Stop hook still never fails a
turn, and now prints `secretless-ai clean --last failed (exit N)` on its
stderr instead of discarding the cleaner's error output.

**The top-level help lists `telemetry` and `scan-staged` and no entry twice,
an unknown command names the nearest command, and the `vault exec` example
reads the variable it is given (#410).** `--help` listed `warm`, `install`,
`scan --include-tests`, `scan --include-config`, `scan --no-ignore` and
`scan --min-confidence` twice each, and did not list `telemetry` or
`scan-staged`. Every command `cli.ts` registers is now listed, and no entry
below Quick start is listed twice. `secretless-ai scna` printed
`Unknown command: scna` and then the whole help, 173 lines on stdout. It now
prints ``Unknown command: scna (did you mean `scan`?)`` and
``Run `secretless-ai --help` for the list of commands.`` on stderr and
nothing on stdout, with exit 2 as before; `bogus` gets no suggestion. The
next steps `vault init` prints, the help `vault` prints with no subcommand
and the usage `vault exec` prints without `--` showed
`vault exec github -- curl https://api.github.com/user`, which never reads
`$GITHUB`, the variable `vault exec github` sets. They now show
`vault exec github -- sh -c 'printf "Authorization: Bearer %s\n" "$GITHUB" | curl -s -H @- https://api.github.com/user'`,
as `docs/how-it-works.md` now does.

**`scan` and `scan-staged` look for the word "example" only in the comment
text of a line before hiding a value on it as a placeholder, and `scan-staged`
says how many values it hid (#411).** A value was hidden when its line held
"example" anywhere and any of `//`, `#`, `/*`, `<!--`, `-->`, `'''` or `"""`, so
`const token = "<value>"; const docs = "https://example.com";` was not
reported. "Example" now has to sit inside a comment on the line: a `//` or `#`
comment, a block, HTML or docstring comment, or a JSDoc line. A `//` right
after `:` is read as a URL, not a comment. On 13 files each holding one GitHub
token and differing only in the text after it, `scan --json` reported 2 and
hid 11; it now reports 6 and hides 7, the 7 whose text after the token is a
comment that says example (`// Example`, `// https://example.com`,
`# example`, `/* example */`, `<!-- example -->`, `""" example """` and
`''' example '''`). With the same 13 files staged, `scan-staged` named 2 and
printed no count; it now names 6 and prints
`7 values looked like a placeholder and were hidden.` and
`See them: npx secretless-ai scan --show-placeholders`, the lines `scan`
prints. It prints them on a passing check too.

**`secret set` asks before it adds the shell hook to `~/.zshenv` or
`~/.bashrc`, and takes `--no-shell-hook` (#412).** The first `secret set`
appended an `eval "$(... env)"` line, which exports every stored secret into
each new shell, with no question and no way to decline. On a terminal it now
asks `Add a hook to ~/.zshenv that exports every stored secret in each new
shell? [y/N]` and writes the profile only after `y` or `yes`; Enter or `n`
leaves it as it is. Replacing a hook line whose command was not found asks the
same way. `--no-shell-hook` leaves the profile as it is without asking, and
when stdin or stderr is not a terminal, as with a piped value, the profile is
not written. Unless the profile already has a working hook, `secret set` then
prints `secretless-ai run --only NAME -- <command>`, which gives one command
one secret.

**`secret list` on an empty store recommends `secret set MY_KEY` instead of
the form that puts the value in shell history, `secret set NAME=VALUE` says
so, and `scan --history` reports that form (#413).** The empty-store hint read
`Store one:    npx secretless-ai secret set MY_KEY=my_value`; it now reads
`Store one:    npx secretless-ai secret set MY_KEY   (prompts, input hidden)`.
`secret set NAME=VALUE` still stores the value, and now also prints one line
on stderr: `The value was given as an argument (shell history keeps it);`
followed by the `secret set NAME` command, which prompts with input hidden.
On a `.bash_history` holding
`npx secretless-ai secret set STRIPE_KEY=not-a-real-value`, `scan --history`
printed `No credentials found in shell history.` at exit 0; it now reports
the line as `cmd-secret-set` with the preview
`npx secretless-ai secret set STRIPE_KEY=[Secret in secret set NAME=VALUE REDACTED]`
at exit 1, and `clean-history` rewrites it to
`npx secretless-ai [REDACTED:cmd-secret-set]`. A
three-character value such as `PIN=abc` is reported with the whole value
masked, flags before the name such as `--meta app=web` are passed over, and
a line is not reported when it gives no value or the value opens
with `$` or a backtick, as in `STRIPE_KEY="$STRIPE_KEY"` or
`STRIPE_KEY=$(pbpaste)`. A line of many quoted `--meta` or `--description`
arguments is matched in one pass, so `scan --history` and `clean-history`
return on it as fast as on any other line.

**`scan` counts a path the scanned tree's own `.secretlessignore` excluded
as a coverage gap (#414).** On a tree holding `app.js`, `src/index.ts` and a
`.secretlessignore` holding `*`, `scan` printed `No hardcoded credentials
found.` and exited 0, with both paths listed only as declared boundaries. It
now prints `No credentials found in the files scanned.` and
`2 paths excluded by .secretlessignore, so not known to be clean.`, with a
`cat -v` Verify line and a `--no-ignore` Fix line, and exits 1. `--json`
reports the count as `summary.ignoreFileExcluded` and exits 1 as well. A
directory the default-ignore list excludes, such as `examples/`, is still a
declared boundary at exit 0, also when `.secretlessignore` repeats it. A
`.env` file the rule kept from being read was listed as `unsupported file
type`; it is now listed with the ignore rule's reason and counted. A
`.secretlessignore` that excludes a path the default-ignore list does not
now makes a scan that finds nothing exit 1; `--no-ignore` reads those paths.

**`init` writes the same Read, Grep and Bash deny rules for each secret file
extension, and the guard hook refuses `cat server.crt` as it refuses a Read
of `server.crt` (#415).** `.claude/settings.json` had `Read(*.crt)` and
`Grep(*.crt)`, but its Bash rules for secret files named `.env*`, `*.key` and
`*.pem` only, so `.p12`, `.pfx`, `.crt`, `.tfstate` and `.tfvars` had no Bash
rule. One list of
extensions (`.env`, `.key`, `.pem`, `.p12`, `.pfx`, `.crt`, `.tfstate`,
`.tfvars`) now gives each the Read and Grep rules and eight Bash rules (`cat`,
`grep`, `awk`, `sed`, `strings`, `xxd`, and the `python3 -c` and `node -e`
one-liners), and drives the guard hook's file-path rule. On a new project
`init` writes 147 deny patterns, up from 99, and keeps every rule it wrote
before. The guard hook's command rule adds `.crt`: `cat x.crt`,
`cat certs/server.crt`, `head -5 server.CRT`, `grep BEGIN server.crt` and a
`python3 -c` one-liner that opens `server.crt` are refused, and
`openssl x509 -in server.crt -noout -subject` is admitted. The scan that
lets a `printf` or `echo` write name a secret file treats a `.crt` target as
it treats a `.pem` one, so `printf 'cat .env' > notes.crt` is refused, as
`printf 'cat .env' > notes.pem` is. The guard hook's command rule still
admits `cat terraform.tfstate` and `cat prod.tfvars`; for those two `init`
now writes `Bash(cat *.tfstate)` and `Bash(cat *.tfvars)` among the settings
rules.

**`scan` does not offer `.gitattributes`, `.gitkeep` or an ignore file such
as `.secretlessignore` as the `Scan one:` command under the files not read
for credentials (#408).** With `.git` and `.gitignore` passed over (#405),
the line named the next listed file, so on a tree holding a `.git` file,
`.gitignore`, `.secretlessignore` and `src/app.ts` it read
`Scan one: npx secretless-ai scan <tree>/.secretlessignore`, a scan of the
scanner's own ignore file, and with `.gitattributes` in place of
`.secretlessignore` it named `<tree>/.gitattributes`. It now also passes over
`.gitattributes`, `.gitkeep` and a file named `.`, an optional tool name and
`ignore`, such as `.npmignore`, `.dockerignore` or `.eslintignore`, at the
root or in a subdirectory. On both trees the line is now left out.
`.gitmodules` is still offered: a submodule URL can carry a credential.

**`scan` does not offer a `.git` or `.gitignore` file as the `Scan one:`
command under the files not read for credentials (#405).** Both are listed as
an unsupported file type, and the line named the first listed file, so on a
tree holding a `.git` file (as a linked worktree checkout does), `.gitignore`
and `src/app.ts` it read `Scan one: npx secretless-ai scan <tree>/.git`, a scan
of git metadata. It now names the first listed file not named `.git` or
`.gitignore`, and is left out when none is. On that tree the line is now left
out; with `notes.txt` beside them it names `<tree>/notes.txt`.

**The release review reads a dependency with an older npm name such as
`JSONStream` from the registry instead of refusing it (#402).** The
`pinned-first-party-deps` check accepted only lowercase names, so a
non-exact specifier on `JSONStream`, a name the registry serves, failed the
check as `pin not served` with `(not an npm package name)`. npm refuses
capitals and `~'!()*` for new packages only. The check now passes to
`npm view` a name made of the characters `encodeURIComponent` leaves
unchanged, with no leading `.`, `-` or `_`, and a scoped name whose package
part does not start with `.`. A name with a leading hyphen, which the earlier
rule passed to `npm view`, now fails as not an npm package name without being
passed. `src/release-artifact-review-own-pins.test.ts` covers a capitalised
name, a name with `~'!()*`, a capitalised own package and a leading hyphen.

**`scan` does not offer `.git` or a dependency or build directory as the
`Scan one:` command under the directories not entered (#399).** The line named
the first directory in the list, which is sorted by code point, so on a
repository with no hidden cache directory sorting before `.git` it read
`Scan one: npx secretless-ai scan <repo>/.git`, a scan of git metadata. It now
names the first listed directory whose reason is a hidden cache or worktree
directory, a test directory or an ignore rule. It is left out when the list
holds only `.git`, dependency and build directories, and hidden directories
linked outside the scan root or closed to this user. On a tree holding `.git/`,
`node_modules/` and `tests/`, the line named `<tree>/.git` and now names
`<tree>/tests`; without `tests/` the block prints no `Scan one:` line.

**Without python3 the guard hook reads a payload with a space after a colon,
and its secret-file rule reads a long command in less time.** Without python3
the hook read `tool_name`, `file_path`, `path` and `command` with greps that
took no blank on either side of the colon, so a payload with a space after it,
as `JSON.stringify(payload, null, 2)` writes it, left each field empty there:
`{"tool_name": "Bash", "tool_input": {"command": "cat .env"}}` and
`{"tool_name": "Read", "tool_input": {"file_path": ".env"}}` were admitted. The
greps now take spaces or tabs on each side of the colon, and both are refused.
A line break between a key and its colon is still not read without python3.

The secret-file rule matched its reader-verb pattern over the whole of each of
the three texts the hook derives from a command, and once more to quote the
match; with macOS grep that pattern takes seconds per pass over a line of a few
MB. It now matches the pattern only on the lines that name a secret file, and
not again on a text the same as one it already matched. Measured on macOS with
bash 5.3 and python3: for a 4 MB command of `cat x` lines ending in `cat .env`,
the rule took about 26 s of the hook's 31.2 s and takes 0.3 s; for a command of
one 4 MB line ending in `; cat .env`, the hook took 21.5 s and takes 11.7 s,
because the rule still matches that line twice, once to decide and once to
quote it. Without python3 the hook reads the command as one line of JSON, and
the first command took 38.3 s and takes 20.8 s.

The rule also tested each text with `echo` piped into `grep -q`. On a long
command whose secret read came on an early line, grep matched and exited
before echo had written the rest, echo was killed, and under the hook's
`pipefail` the test failed: with python3, `cat .env` followed by 100,000 lines
of `echo x` was admitted. Neither grep of the rule stops early now, and that
command is refused. The 986 commands of `src/fixtures/guard-corpus.txt` keep
their recorded verdicts, with python3 and without.

**`scan` reads source files in dot-directories (#144).** A token in
`.claude/agent.ts` went unreported while its byte-identical copy in
`src/app.ts` was a finding: the source walk entered no directory whose name
starts with `.`, and listed each one as `hidden directory; config and key
files inside are still read`. It now enters them, `.claude/`, `.github/` and
`.vscode/` included, and reports a source file there with severity `high`, as
in any other directory. It still reads no source file in `.git/`, in the
dependency and build directories it skipped before (such as `.next/` and
`.venv/`), or in these hidden cache and worktree directories: `.netlify/`,
`.open-next/`, `.turbo/`, `.playwright-mcp/`, `.yarn/`, `.pnpm-store/`,
`.cache/`, `.terraform/`, `.parcel-cache/`, `.angular/`, `.serverless/` and
`.worktrees/`. Each of those twelve is listed under "not entered for source
files" as `hidden cache or build output; config and key files inside are
still read` or `linked git worktrees; config and key files inside are still
read`, and naming one scans it. `scan --include-config` now reads a
config-format file such as `.claude/values.yaml` in a dot-directory the walk
enters, and without the flag counts it in `unscannedConfig`. A dot-directory
linked outside the scan root is listed only among the links not followed, and
one this user cannot open only among the paths that could not be read. A tree
whose only credential is in `.claude/agent.ts` exited 0 and now exits 1. The
files read in dot-directories count toward `--max-files`. On shallow clones of
`axios/axios` and `psf/requests` the scan reports 0 findings and exits 0
before and after this change, with and without `--include-config`.

**A large dot-directory reaches `scan`'s file cap after the rest of the tree
(#397).** With the source walk entering dot-directories (#144), one whose name
sorted ahead of `src/` had its files collected first, so a large one filled
`--max-files` and the scan dropped a finding the previous release reported. On
a tree with `.foo/` holding 6000 small `.js` files and `zzz/app.ts` holding a
placeholder value, `scan --json --show-placeholders` reported no findings, and
now reports `zzz/app.ts`. The scan still stops at the cap there and says so:
`summary.truncated` is `true`, `summary.eligibleFiles` is 6001, and it exits 1.
The source walk now visits every directory it reaches without passing through
a dot-directory before any directory at or under one, so a stop at the cap
leaves files in dot-directories unscanned before any other file. On a 16-file
tree with source files in and outside dot-directories, the files outside them
that a capped scan reports are the ones the walk before #144 reported, at each
cap from 1 to 16. The key and config walks keep their order. `docs/scanning.md`
and `scan --help` say that the source files in an entered dot-directory count
toward the cap.

**The optional OpenA2A dependencies are pinned to exact versions.**
`package.json` declared `@opena2a/aim-core` at `>=0.2.0` and
`@nanomind/engine` and `@nanomind/guard` at `^0.1.1`, so an install could
resolve each of them to a later release. They are now `0.2.0`, `0.1.1` and
`0.1.1`, the versions those ranges resolved to on 2026-10-15. The release
review's `pinned-first-party-deps` check refused only a caret or tilde range
on an `@opena2a/` name: it passed `*`, `>=0.2.0`, `0.2.x` and `latest` on
`@opena2a/aim-core`, `^0.1.1` on `@nanomind/engine` and `>=0.11.0` on
`hackmyagent`. It now refuses a non-exact specifier on an own package: a name
under `@opena2a/` or `@nanomind/`, or one whose npm maintainers share a
member with `hackmyagent`'s. A name the registry answers E404 for fails as
`pin not served`, and a registry read with no answer is a precondition, so
the review exits non-zero. `src/release-artifact-review-own-pins.test.ts` runs the review
over fixtures for each case.

**The release review accepts an exact version with both a prerelease and a
build suffix (#401).** `pinned-first-party-deps` took a version as exact when
it was `MAJOR.MINOR.PATCH` with one suffix starting `-` or `+`, and that suffix
could not hold a `+`, so `1.0.0-beta+build.1` on `@opena2a/aim-core` failed as
a non-exact specifier. A prerelease suffix may now be followed by a build
suffix, in the order semver 2.0.0 gives: `1.0.0-beta+build.1` on
`@opena2a/aim-core` and `0.33.2-rc.1+build.7` on `hackmyagent` pass with no
registry read, and `1.0.0-beta+build.1+build.2` still fails.

**The release review's `consumer-closure` check reads the deprecation and
advisory state of `@nanomind/` copies in the install closure.** It counted as
own a name on its roster of unscoped names or a name under `@opena2a/`, while
`pinned-first-party-deps` also counts `@nanomind/`: over a fixture closure
holding a deprecated `@nanomind/engine`, the check passed. It now takes the
scopes from `OWN_SCOPES` in `scripts/own-package-pins.mjs`, the list
`pinned-first-party-deps` reads, and that fixture fails the check. Over the
packed 0.23.1 tarball the check now examines `@nanomind/engine@0.1.1` and
`@nanomind/guard@0.1.1`; neither is deprecated or in a vulnerable range. An
unscoped name is still matched against the check's roster, not the npm
maintainers read `pinned-first-party-deps` uses.

**`scan` lists a config file inside a directory this user can list but not
search.** For `t/nosearch/config.json` under a `t/nosearch` of mode `0600`,
`scan t --json` listed the file under neither `findings` nor
`unreadableFiles` and exited 0: an existence check read the permission
failure as absence and dropped the file before the read that lists it. The
check now passes over a file only when `stat` fails with `ENOENT` or
`ENOTDIR`. On that tree `scan t` lists `t/nosearch/config.json: inside a
directory this user cannot search` under "1 path could not be read", with
`Fix: chmod +x t/nosearch`; `--json` carries it in `unreadableFiles` and
`unreadableReasons`, and both exit 1.

**Step 2 of `docs/use-cases/protect-my-credentials.md` shows what `verify`
prints.** Its sample showed lines `verify` does not print: `Checking
protections...`, a `blocked` row for `.env`, `.aws/credentials` and `*.key,
*.pem`, `hidden from AI, usable via $ENV` beside each variable, and `All
secrets protected.` Its prose said `verify` confirms that AI tools cannot read
the credential files; `verify` does not check the deny rules or the guard hook.
The sample is now the output of `verify` in the project from Step 1, in a shell
that sets `ANTHROPIC_API_KEY` and `OPENAI_API_KEY`, and the prose names what
`verify` reads: the credential variables the shell sets, a fixed list of
project files, two files in `~/.claude`, and the five most recent transcript
files under `~/.claude/projects`. `src/docs-sample-output.test.ts` runs `init`
and then `verify` in such a project and compares what `verify` prints with the
sample.

**`scan` reads a config file whose name holds a backslash (#393).** Where the
path separator is `/` (measured on macOS), the config walk opened such a file
under a path with `/` in place of the backslash. That path does not exist, so
a file named `.env.back\slash` was neither read nor listed as unread: `scan
--json` named it under neither `findings` nor `unreadableFiles`. The walk now
hands the config scan the path with only the platform's own separator changed,
which is the path it already lists for an unread file, so the file is read and
a finding from it names `.env.back\slash`. Where the separator is `\`, the path
it hands over is the same as before.

**Every `Fix:` line the `secret` commands print runs as printed.**
`secret set NAME=VALUE --from-clipboard` printed `secret set NAME
--from-clipboard` before it checked the name: for `9z=...` that line was
refused with `Invalid secret name`, for `a b=...` it stored a secret named `a`,
and for `$HOME=...` or `<name>=...` a shell expanded or redirected it. The Fix
of the piped-stdin refusal printed the name the same way, and ran on into the
words `without a pipe or redirect`. A name `secret set` refuses is now printed
as `'<name>'`, each word is quoted for a POSIX shell, and a command inside a
sentence is set apart by two spaces. `secret sync --dry-run` printed its Fix
lines without `--dry-run`, so `--only API_KEY --force` wrote when run as
printed; both sync Fix lines now repeat it. `secret sync` with no manifest
offered `--only NAME1,NAME2`, and `secret list --needs-rotation` offered
`secret set NAME`, which synced or stored secrets of those names; both now
print `'<name>'`. One function, `fixCommand` in `src/fix-command.ts`, builds
every Fix line that gives a `secret` command, and
`src/fix-lines-runnable.test.ts` runs each line printed for a generated set of
inputs through the same entry point: 458 distinct lines. Before this change,
53 of those inputs printed a Fix line that failed (25 of `secret set` and
`secret list`, 28 of `secret sync`, none of `secret push`). What each command
stores, pushes, syncs and exits with is unchanged.

**`scan` prints beside each path it could not read the cause that holds for
that path, and every reason it gives for an unread path is one value of a
closed set.** Each path under "could not be read" now carries one of `this user
cannot read the file`, `this user cannot list the directory`, `inside a
directory this user cannot search`, `symbolic link in a loop, or in a chain too
long to follow`, `symbolic link to a path this user cannot reach` or `opening
it failed with an error other than permissions`, from what `lstat`, `stat` and
`access` report for it. The line "Cause differs by path: permissions, a broken
or looping symlink, or an I/O error." is removed: the scan never lists a broken
link, which has nothing behind it to read. The `Fix:` is `chmod +r` on a file,
`chmod +rx` on a directory or `chmod +x` on the directory above, for the first
listed path a `chmod` can repair; it was `chmod +rx` on the first listed path
whatever its cause, and on a link into a directory that cannot be searched
that `chmod` fails. `--json` adds `unreadableReasons`, a `{ path,
reason }` entry for each path in `unreadableFiles`. A hidden directory the scan
does not enter for source files is listed as `hidden directory; config and key
files inside are still read`, `hidden directory linked outside the scan root;
nothing inside is read` or `hidden directory this user cannot open; nothing
inside is read`, where all three printed `hidden directory`, the first beside
findings from inside it. Two links to one directory outside the scan root
printed "1 symlink points outside the scan root"; the heading now counts the
directories: "1 directory outside the scan root is linked from inside it, so
not followed. One link to each:". The heading over files not searched reads "N
files not read for credentials", where "N files not opened" stood over
`.secretlessignore`, which the scan opens for its rules. No `--json` field is
renamed, and which files are read, every finding and every exit code are as
before.

**A `secret://vault/NAME` reference is not answered by an entry stored under
`secret/NAME/` (#383).** For a `keychain`, `vault` or `1password` reference,
`resolveRef` and `resolveEnvRefs` asked the backend for `secret/NAME` and took
the first entry it returned, and a backend returns the entries stored under
`secret/NAME/` beside `secret/NAME` itself. With a KV v2 mount `secret` holding
`secret/DB/replica` and no `secret/DB`, and a token that may list,
`resolveRef('secret://vault/DB')` read `secret/DB`, got a 404, listed it as a
prefix, and resolved to the value of `secret/DB/replica`. The reference is now
asked as an exact read and answered only by the entry under its own key: that
case sends one GET of `secret/data/secret/DB`, no LIST, and fails with `Secret
not found: secret://vault/DB`. A backend that returns `secret/DB/replica`
before `secret/DB` answers `secret://<backend>/DB` with the value of
`secret/DB`, where it answered with the value of `secret/DB/replica`.

**The recorded walkthrough shows `npx secretless-ai init` and then
`npx secretless-ai verify`, and is rendered from a committed tape.** The
recording the README linked showed `scan`, had last been rendered six months
before its tape was last edited, and nothing said which build it showed. The
new one is `docs/vhs/init.gif`: `docs/vhs/record-init.sh` renders
`docs/vhs/init.tape` in a container, in a new project directory and a new
empty home directory that `docs/vhs/setup-fixture.sh` creates, on a host with
no OS keychain, and writes `docs/vhs/init.json` beside it. That sidecar names
the build shown (the published package by its integrity, or the commit the
package was packed from), the fixture, the typed commands, the terminal size
and the output files; `docs/vhs/init-capture.txt` is the same two commands as
text. The test suite compares the sidecar with the tape, the fixture script
and the version in `package.json`, and checks every command a tape types
against the commands and flags the CLI registers, so a release or a tape edit
that is not followed by a render fails a test. `docs/vhs/record-init.sh
--dry-run` prints the image, its base images, the build, the tape, the fixture
and the files a render writes, and exits 0 without running docker, building or
packing; with `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` set, the script exits 2
before it calls npm or docker. The script packs HEAD only when the registry
answers E404 for the version; when `npm view` fails any other way, for example
because the registry cannot be reached, the script and its dry run exit 1,
name npm's error code and pack nothing. The release smoke test (section 10c of
`docs/testing/release-smoke.md`) renders again after a version bump and
records the sidecar's hash. `docs/demo.tape` is removed.
No command, flag, output or exit code changed.

**`docs/vhs/record-init.sh` counts uncommitted changes to the fixture script
with `git status` and refuses to render when there is one, and the sidecar
drops `scriptSha256`, which held the tape's digest (#379).** The script wrote
`fixtureUncommittedChanges` as the literal `0` and wrote the digest of
`docs/vhs/init.tape` under both `tapeSha256` and `scriptSha256`. It now counts
the lines `git status --porcelain -- docs/vhs/setup-fixture.sh` prints, before
any `docker` call, and exits 1 with a message that starts `record-init.sh: git
status reports uncommitted changes to docs/vhs/setup-fixture.sh` when the count
is not 0, for an unstaged and for a staged edit. The script passes the count to
the container as `FIXTURE_UNCOMMITTED_CHANGES`, and its step inside the
container compares that value with `0` before the render and writes the field
from it. `docs/secretless-ai-demo.gif` is
back in the repository: the README published with 0.23.0 embeds it (line 40 of
`npm view secretless-ai@0.23.0 readme`). No command, flag, output or exit code
of the CLI changed.

**`docs/vhs/record-init.sh` runs `docker build` and `docker run` with a docker
configuration of its own, and ends a render with the sidecar's hash.** The
script ran docker with the caller's configuration, which can name a credential
helper; Docker Desktop's helper keeps registry credentials in the OS keychain.
It now creates a configuration directory that names no credential helper and
holds no registry credentials, only the caller's plugin directory as
`cliPluginsExtraDirs` so that buildx is found, and removes it when the script
ends. It reads the endpoint of the docker context in use with `docker context
inspect`, before that configuration is replaced, and passes it as
`DOCKER_HOST`; a `DOCKER_HOST` the caller set is kept, and when docker names no
endpoint the script exits 1 before `docker build`. A render ends with the line
`sidecar: docs/vhs/init.json sha256 <hash>, version <version>, meteredCostUsd
<cost>, wallClockSeconds <seconds>`, and exits 1 when the render wrote no
sidecar. `--dry-run` names the docker configuration. `docs/vhs/init.gif` and
`docs/vhs/init.json` are rendered again; `docs/vhs/init-capture.txt` is
unchanged. No command, flag, output or exit code of the CLI changed.

**The recording's sidecar names the commit the render started from, for the
published build as well as for a packed one.** `docs/vhs/init.json` named a
commit only when the render packed HEAD (`packedFromCommit`): run with a
stand-in npm that answers with a published integrity, `docs/vhs/record-init.sh`
passed the container `NPM_INTEGRITY` and an empty `PACKED_FROM_COMMIT`, and no
other variable named a commit. The script now reads `git rev-parse HEAD` once,
passes it to the container as `COMMIT` for both builds, and packs a build that
is not on npm from that commit. Its step inside the container compares `COMMIT`
with `^[0-9a-f]{40}$` before the render and exits 1 when it does not match, and
the sidecar writes it as `commit`. `docs/vhs/init.gif` and `docs/vhs/init.json`
are rendered again; `docs/vhs/init-capture.txt` is unchanged. No command, flag,
output or exit code of the CLI changed.

**A `secret://keychain/` reference is not answered by the encrypted file on a
platform with no OS keychain implementation (#376).** With `process.platform`
reported as `win32` or `freebsd`, `createBackend` builds the local encrypted
file for `keychain`, and `resolveRef` and `resolveEnvRefs` read that file as
the keychain: with `win32` reported and `local` configured,
`secret://keychain/STRIPE_KEY` resolved to the file's `STRIPE_KEY` as
`backend: 'keychain'`, with one line on stderr, `secretless: OS keychain not
supported on win32. Falling back to local encrypted backend.` The reference is
now unresolved there, with a `RefResolutionError` that names the URI and the
platform (`Backend "keychain" named by secret://keychain/STRIPE_KEY is not
reachable: OS keychain is not supported on win32. No other store was read in
its place.`), and `resolveEnvRefs` reports it in `errors` and leaves the
reference as the variable's value. With `local` configured,
`secret://local/STRIPE_KEY` reads the file.

**`broker start` checks the length of its socket path before it starts
(#377).** The socket is created at `~/.secretless-ai/broker.sock`. On macOS
under Node 26, a home directory path of 78 bytes made `broker start` fail with
`Error: listen EINVAL: invalid argument <path>` and no Verify or Fix line, and
the failed start left `~/.secretless-ai/broker.token` behind. `broker start`
now refuses a socket path longer than 104 bytes on macOS or 108 bytes on Linux
before it creates `~/.secretless-ai`, a PID file or a token. The message names
the path, its length in bytes and the limit, with a Verify line that counts
the bytes and a Fix line that starts the broker under a `HOME` whose path is
short enough (77 bytes on macOS, 81 on Linux).

**A Vault token that may not list can read one secret name that is not stored
(#375).** A read of one name answered a 404 of `secret/NAME` by listing that
name as a prefix, and since a refused LIST is reported (#372, below) that LIST
failed the read. With a token that may read `secret/data/*` and may not list
`secret/metadata/*`, `secret show MISSING_NAME` printed `Error: Vault:
permission denied listing "secret/MISSING_NAME"`, the broker's credential
lookup threw `permission denied listing` before its environment-variable
fallback, and a sync from Vault recorded the name as failed. A read of one
name now takes the 404 as its answer and sends no LIST: `secret show
MISSING_NAME` prints `Secret not found: MISSING_NAME` and, with `--json`,
`"stored": false`; the broker lookup goes on to the environment variable; and
the sync records the name as not found. Storing a name that has an open
exposure reads its previous value the same way. Reading a prefix, as listing
the stored names does, still reports a refused LIST.

**A Vault key with a `.` or `..` segment is refused before its request, where
a `secret://vault/` reference holding `..` sent the Vault token to paths
outside the KV mount (#384).** The Vault backend placed the key in the request
URL as it was, and the URL resolved its dot segments:
`resolveRef('secret://vault/../../../sys/policies/acl')` sent `GET
/v1/sys/policies/acl` with `X-Vault-Token` set. The same reference written with
`%2e%2e`, with `\` as the separator, or with each `..` split by a tab, a line
feed or a carriage return sent `GET /v1/sys/policies/acl` as well. `resolve`, `store`, `storeVersion`,
`hasEntry` and `delete` now throw `Vault: refused the key "<key>": a "." or
".." segment is resolved away in a request URL and can send the request
outside the "<mount>" KV mount. The request was not sent.` for a key with a
`.` or `..` segment, and `resolveRef` answers such a reference `Secret not
found: <uri>`. Every other segment of a key is percent-encoded in the request
URL: those three references are sent under `/v1/secret/data/secret/` with
`%252e`, `%5C`, `%09`, `%0A` and `%0D` in the path, and a `?` or `#` in a key
is sent as `%3F` or `%23`, where `secret/KEY?list=true` was read from
`/v1/secret/data/secret/KEY` with the query `?list=true`. A key made of
letters, digits, `_`, `-` and `/` is sent as before.

**The unreachable-backend message offers `migrate`, a command that exists
(#372).** When the configured backend could not be reached, the message gave
`secretless-ai backend migrate --from <backend> --to local` as the way to move
to another backend, and `backend` answered that with `Unknown backend command:
migrate` at exit 2. It now gives `secretless-ai migrate --from <backend> --to
local`.

**`migrate --to` is built as the destination (#372).** An unreachable `--to`
was reported as `Configured backend "<backend>" is not reachable`, with a
migration away from it as the way out. It is now reported as the destination,
with the assurance that nothing was copied and the configured backend is
unchanged. On a machine with no backend configured, `--to local` wrote to the
platform keychain while the migration then configured `local`, which once
configured is the encrypted file, so the configured store was left empty;
`--to local` is now the encrypted file. Two names that are one store are
refused before anything is read: with no backend configured,
`migrate --from local --to keychain` read the keychain and wrote it back onto
itself, and now names the store and offers `backend set keychain`.

**`backend set` removes the value cache (#372).** The cache file, keyed by
secret name alone, kept what was read from the previous backend, and until the
cache TTL ran out (5 minutes by default) a read through the new backend was
answered with those entries. `backend set` now removes it, as `migrate` does
(#370).

**A `secret://` reference whose backend cannot be reached is not answered by
the configured backend (#372).** `resolveRef` and `resolveEnvRefs` fell back to
the configured backend when the one a reference names could not be built, and
reported the value as the named backend's: with `local` configured and
`VAULT_ADDR` unset, `secret://vault/STRIPE_KEY` resolved to the encrypted
file's `STRIPE_KEY` as `backend: 'vault'`. The reference is now unresolved,
with a `RefResolutionError` that names the URI and why the backend could not
be reached, and no other store is read in its place.

**A Vault LIST that is refused is reported, not read as an empty store
(#372).** Reading a prefix lists its keys first, and any answer to that LIST
other than success was taken to mean the prefix held nothing, so
`migrate --from vault` printed `No secrets found to migrate.` and exited 0
against a server that refused it. A 403 now throws `Vault: permission denied
listing "<prefix>"` and any other failure `Vault: list failed (HTTP <status>)`,
as a refused read of the same path does. A 404 still means nothing is stored
there.

**A `secret://` reference that names a backend other than the configured one
is resolved without the value cache (#369).**
`resolveRef` and `resolveEnvRefs`, exported from the package, built the backend
a reference names behind the value cache, which is one file keyed by secret
name alone. With `keychain` configured, resolving `secret://vault/STRIPE_KEY`
cached the value Vault held, and for the cache lifetime (300 seconds by
default) a read of `STRIPE_KEY` by name from the configured backend was
answered with Vault's value, also when the keychain held no such secret. The
other way round, a value the configured backend had cached under that name
answered the reference, and Vault was not asked. A reference whose backend is
not the store this machine uses anyway is now read from that backend on every
resolve, and nothing it returns is written to the cache. A reference that names
the configured backend is cached as before, as is one that names `keychain` on
a machine with no backend configured where a keychain is detected (macOS, or
Linux with `secret-tool` on PATH).

**`migrate` copies what `--from` holds, and removes the value cache when it
ends (#370).** `migrate --from <backend>` read its source through the value
cache, one file keyed by secret name alone that answers whichever backend
asks. Until the cache TTL ran out (5 minutes by default) after a command that
read the whole store, such as `secret list`, the migration copied what was
cached instead of what the source held. With `keychain` configured,
`migrate --from vault --to local` copied the keychain's secrets, not Vault's,
to the encrypted file and counted them as migrated; a value rotated in the
source since that read was copied as it was before the rotation; and after a
listing of an empty store, the migration printed `No secrets found to
migrate.` for a source that held secrets. `--from` is now read directly, as
the source of `secret sync` is.
The cache file was also left in place when the migration ended, still holding
the previous backend's entries: after a migration whose writes to `--to` all
failed, a read through the new backend was answered with the previous
backend's entries until the TTL ran out. `migrate` now removes the file when
it ends, whether it migrated, found nothing, failed in part or stopped on an
error, and it copies the `secret/` entries and then the `mcp/` entries instead
of both at once, so nothing is still being written when it does. The next read
asks the backend itself, which on the keychain or 1Password is one more unlock
prompt.
A `--from` backend that cannot be reached is reported as `Source backend
"1password" is not reachable`, with `Nothing was read from it, and nothing on
this machine was changed.`, where it was called the configured backend and
given `backend migrate --from 1password --to local` as the way out.
Who is affected: a migration run within the TTL of such a read whose `--from`
was `keychain`, `1password`, `vault` or `gcp-sm`, the backends the cache is
used for, or `local` on a machine with no backend configured, where `local` is
the platform keychain when one is detected. Running the same `migrate` again
copies what the source holds now and deletes nothing from it;
`npx secretless-ai backend list` then names what `--to` holds. Verify after
any `migrate` with `ls ~/.secretless-ai/cache/.secret-cache` (`No such file or
directory`).

**`--help` opens with the package description.** Top-level help opened with
"Keep secrets out of AI context." The README and the package description are
narrower: a hook and deny rules enforce the read gate in Claude Code, the
other tools get instruction or ignore files that nothing enforces, and a
command that prints its own credential is not blocked. Help now prints that
description in place of the old line, wrapped inside 80 columns, standalone and
under a host CLI that sets `SECRETLESS_CLI_PREFIX`. It is read from
`package.json`, and a test holds the opening of help to it. The name and
release line above it, and every command, flag and exit code, are unchanged.
The line `init` prints under its release line is unchanged too.

**The package description says what the README says.** `npm search`,
`npm view` and the registry listing showed "One command to keep secrets out of
AI. Works with Claude Code, Cursor, Copilot, Windsurf, and any AI coding
tool." The README's opening paragraph is narrower: a hook and deny rules
enforce the read gate in Claude Code, the other tools get instruction or
ignore files that nothing enforces, and a command that prints its own
credential is not blocked. The description in `package.json` is now that
paragraph without its license line, and a test holds the two to the same
sentences, so a change to one fails until the other follows. The listing
changes with the next release. No command, flag, output or exit code changed.

**The README is cut to a short form, and its reference sections are pages
under `docs/`.** The README was 4376 words in 16 sections, and a reader had to
scroll past the architecture, the supported-tools table and the backends to
reach Telemetry. It is now under 900 words in 7 sections: the first command and
its output, a task list that links to the section for each task, storing and
using a secret, install, telemetry, documentation and license. The other
sections moved as written: `docs/install.md` (from source, verifying a release,
when Secretless reads a stored value), `docs/how-it-works.md` (how it works,
architecture, supported tools, storage backends, NanoMind),
`docs/managing-secrets.md` (every `secret` workflow, git credentials, what the guard
cannot see, pushing to a cloud secret store), `docs/commands.md` (MCP server
protection, triage helpers, exit codes, use through opena2a-cli) and
`CONTRIBUTING.md`. The description now says where the read gate is enforced
and where it is an instruction file, and that a command that prints its own
credential is not blocked. The sample `init` output starts below the version
banner, so the README carries no release number or date; the whole output is
in `docs/captures/quick-start.txt`, which the test suite compares with what
the build prints. Guide links that pointed at README sections point at the new
pages. No command, flag, output or exit code changed.

**The broker audit log is signed, and `verifyAuditLog` checks it (#259).**
The AAP broker profile requires every verification, decision, resolution and
denial to be written to a signed audit log, and the reference test for it
passed on an append-only log with no signature: it checked only that the
grant event was there and the scoped token was not. Each line of
`broker-audit.log` now carries `prevHash`, the SHA-256 of the line before it,
and `sig`, an Ed25519 signature over the line without `sig`. The key is created
on the first write as `broker-audit.log.key` (mode 0600), with its public half
in `broker-audit.log.pub`. `verifyAuditLog(logPath, publicKey)`, exported from
the package, returns `{ valid, records }` and, on failure, the first line that
failed and why: an unsigned line, a line changed after signing, a line that is
not in the exact form the broker wrote, or a line removed, inserted or moved.
The conformance test now verifies the log and requires an unsigned or altered
decision record to be refused. Lines cut from the end of a file are not
detected. A log written by an earlier version fails at its first line; move it
aside to start one that verifies.

**`run`, `env`, `secret sync`, `secret show` and `secret exposed` no longer
offer `secret set` for a name `secret set` refuses (#325).** The store holds
names that start with a digit, `_` or `-` (a sync or an import writes them),
and `secret set` takes a name that starts with a letter. On a store without
`9z`, `run --only 9z -- <command>` printed `Fix: secretless-ai secret set 9Z`,
and running that line was refused with `Invalid secret name. ... Must start
with a letter.` The same unusable line was printed by `env --only`, by
`secret sync` for a name in neither store, by `secret exposed` as its `Fix:`
for a name that is not stored and as its `Next:` step for one that is, by
`secret show` as `Record one:`, and by `run` for a stored value that holds a
null byte. Each such name now gets a line that begins ``"9Z" cannot be stored
by `secret set`, which takes a letter, then letters, digits, '_' or '-'`` and
ends with what to do instead, and a `Fix:` names the first name `secret set`
takes. When no name is one it takes, no `secret set` line is printed. A name
`secret set` takes is offered as before.

**`diff` ignores an unknown flag instead of reading it as the git ref (#336).**
`secretless-ai diff --bogusflag` printed `Warning: ignoring unknown flag
--bogusflag.` and then `Invalid git ref: "--bogusflag"` at exit 1, because the
flag it had just warned about was the first argument it read. The flag is now
dropped before the ref is chosen, so `diff --bogusflag` runs against `HEAD` and
`diff --bogusflag main` runs against `main`, as the README and
`docs/scanning.md` already said. A ref that starts with a single `-` is still
refused as an invalid ref.

**An unknown command or subcommand exits 2 (#335).**
`secretless-ai scna`, `backend purg`, `cache bogus`, and an unrecognised
subcommand of `secret`, `scope`, `broker`, `vault`, `install`, `watch`, `hook`
or `rules` exited 1, the code that also means credentials were found, so a CI
gate read a mistyped command as a finding. They now exit 2, the code for a
command line that was refused before anything ran, as `telemetry` and
`git-credential` already did; a bare `hook` exits 2 as well. A bare `cache` or
`backend` still prints its status at exit 0. `verify` still exits 1 when no
API key is set in the environment, since there is then nothing to verify; the
exit-code table in the README and `docs/scanning.md`, and `verify --help`, now
say so.

**`scan --explain` prints a detailed view of each finding (#332).**
Without a ready NanoMind engine, `--explain` printed the plain `scan` view and
said to install `@nanomind/engine`, a package that installs as an optional
dependency but reports ready only when its model file and runtime exist. Each
finding now shows the pattern that matched, the confidence score's inputs
(pattern, entropy, length and path, and whether a fixed-structure pattern
raised it to high), the path rule that applied, the Fix, and a Verify command
that re-scans the file from the current directory (`ls -l` for a file flagged
for existing). None of it uses the engine. With
`SECRETLESS_NANOMIND_EXPLAIN=1` and no ready engine, the notice now says
whether the package or its model is missing and names the model files it did
not find. `scan --json` output is unchanged.

**The vault guide no longer shows a `vault exec` example that sends an empty
bearer header (#329).** `docs/use-cases/bring-your-own-vault.md` showed
`vault exec github -- curl -H "Authorization: Bearer $GITHUB" ...`. The
calling shell expands `$GITHUB` before `vault exec` starts, and `vault exec`
starts its command without a shell, so the request went out with an empty
bearer token; the same line would also have put the token on curl's command
line. That example is gone: the guide's `run --only` example (#328) stands in
its place, and it reads the value inside a single-quoted `sh -c` script and
passes the header to curl on stdin. A test reads every documented `run` and
`vault exec` child command and fails on a variable the calling shell expands,
one the child receives as literal text, or one a script passes to another
program as an argument.

**The 1Password caveat in the team setup and bring-your-own-vault guides names
`backend set 1password` as the command that raises the unlock prompt (#338).**
Both guides said the first `secretless-ai backend` run triggered a biometric or
master-password prompt. `backend` with no subcommand only checks whether `op`
is on PATH and prints `auth not probed`; `backend set 1password` runs
`op account get`, which is what makes the 1Password app ask. The caveat now
sits on that command and says that cancelling leaves the current backend
unchanged. Verify with `npx secretless-ai backend | grep 1Password`
(`auth not probed`, no prompt).

**The shell hook `secret set` installs exports secrets without a global
install (#333).** The hook ran the bare `secretless-ai env` and discarded
errors, so after `npx secretless-ai secret set` new terminals exported nothing
unless `secretless-ai` was on PATH, which a copy run through npx never is, and
which a new macOS terminal has not set up yet when it reads `~/.zshenv`. The
hook now runs node and the CLI script by their full paths, using a `node` on
PATH that resolves to the same binary so a Homebrew upgrade does not break it.
When `secretless-ai` is not on PATH, `secret set` prints the path the hook runs
and how to keep that copy installed. A hook line this tool wrote earlier whose
command is no longer found is replaced on the next `secret set`; a line the
user wrote is left alone. Verify with
`npx secretless-ai secret set DEMO_KEY`, then
`env -i HOME="$HOME" PATH=/usr/bin:/bin zsh -c '[ -n "$DEMO_KEY" ] && echo set || echo unset'`
(`set`; on Linux use `bash -c '. ~/.bashrc; ...'`).

**`setup --check` counts secrets passed as environment variables, and `setup`
without a terminal no longer reports success (#330).** The CI recipes in
`docs/use-cases/team-setup.md` pass secrets to the job as `env:` and run
`setup --check`, which counted only names in the configured store, so the step
failed with every value present. A name set to a non-empty value in the
environment now counts as present and is listed under `From environment (not
stored):`; an empty value, which is what an undefined GitHub Actions secret
becomes, still counts as missing. `setup --backend <type>` checks or stores in
the named backend instead of the configured one, so the 1Password recipe runs
`setup --check --backend 1password`, and the report names the store it checked.
`--backend local` is the AES-256-GCM encrypted file, also on a machine with no
backend configured, where `local` otherwise means the platform keychain when
one is detected (macOS, or Linux with `secret-tool` on PATH). A `1password`,
`vault` or `gcp-sm` backend named with `--backend` that cannot be reached is
reported as named for this run, with no `backend migrate` line, because the
configured backend is unchanged. `keychain` is not checked when it is named:
under `SECRETLESS_OS_KEYCHAIN=off`, `setup --check --backend keychain` reports
the names as missing, and a value typed into `setup --backend keychain` fails
with the keychain's own error. A backend named with `--backend` that is not
the one this machine uses anyway is read and written without the value cache,
which is one file keyed by secret name alone, so a secret it holds is not then
counted as held by the configured backend: with `keychain` configured,
`setup --check --backend vault` followed by `setup --check` reports a secret
only Vault holds as missing. In a terminal, `setup` names the store before its
first prompt.
Plain `setup` with standard input that is not a terminal took its answers from
that input: a piped value was stored as the secret it was prompted for, and
when the input ended with a prompt unanswered, `setup` exited 0 without a
summary, whatever was still missing. It now reads nothing from a pipe: it
prompts for nothing, prints the same report as `--check`, and exits 1 when a
required secret is missing. To store a value from a script, pipe it to
`secret set NAME`, which reads the value from standard input. In a terminal, a
required secret left blank, or input ended with Ctrl-D, is reported as still
missing with exit 1 instead of a successful summary. `runSetup`, exported from
the package, changed the same way: called without `check` from a process whose
standard input is not a terminal, it returns the report with
`promptsSkipped: true` instead of prompting (pass `interactive: true` and an
`input` stream to prompt); it counts a name set to a non-empty value in
`process.env` as present unless `env` is passed (`env: {}` counts the store
alone); `SetupResult` has a new required field, `fromEnvironmentNames`, that
lists those names; and `backendNamed: true` treats `backendType` as named for
this run, as `--backend` does. Two other exports take the same choice:
`SecretStoreOptions` has `backendNamed`, which `new SecretStore(options)`
reads, and `createBackend` takes `{ role: 'named' }` as its fourth argument.
Verify with
`printf 'STRIPE_KEY\n' > .secretless; STRIPE_KEY=x npx secretless-ai setup --check`
(`PASS`, exit 0) and `npx secretless-ai setup </dev/null` (exit 1).

**`backend set local` stores secrets in the AES-256-GCM encrypted file
(#327).** On macOS, and on Linux with `secret-tool` installed, `local` was
replaced by the OS keychain even when the user chose it, so `backend set
local` was followed by `Current: keychain-macos (configured: local, upgraded
because a platform keychain is available)` and there was no way to select the
encrypted file the docs describe. Only the unconfigured default upgrades now:
with no backend configured, secrets still go to the platform keychain where
one is available, and `backend` prints ``Current: keychain-macos (default,
because a platform keychain is available; `secretless-ai backend set local`
selects the encrypted file)``. Once any backend is configured, `local` is the
file, including as the source of `migrate --from local`. Who is affected: a
machine that ran `backend set local` with a platform keychain available stored
its secrets in that keychain, and now reads the encrypted file instead, which
starts empty. Verify with `npx secretless-ai backend` (`Current: local`) and
`npx secretless-ai secret list`; move the stored secrets with
`npx secretless-ai migrate --from keychain --to local`. A machine that never
ran `backend set` keeps its secrets in the platform keychain where one is
available: after `backend set <name>`, `migrate --from local` reads the
encrypted file and does not move them, and `migrate --from keychain --to
<name>` does. The README's backend example showed `--from local` and now shows
`--from keychain`.

**The sample outputs in the guides and the README now show what the commands
print (#337).** The blocks showed lines the tool no longer prints: `status` as
`Backend:`, `File rules:` and `Secrets:` rows instead of its Observations and
Verdict, `mcp-status` with secret counts and a line for a client with no
servers, `protect-mcp` without its header and closing lines,
`backend set 1password` with `Vault: Secretless (created)` and `Ready.`,
`setup` with `Enter value: ****` and `Skip? [Y/n]` prompts, `scan` with
per-file counts, `import --detect` with a line per name, and `broker start`
and `broker status` without the auth token path and start time. Each block is
now the command's output on a fixture, and a test runs those commands and
compares what they print with the blocks, so a change to the output fails it
until the guide shows the change. The MCP and `.env` guides also say that
secrets go to the OS keychain by default where one is available, not to the
local encrypted file, and the Team Setup guide says `setup` shows a value as it
is typed.

**`run` now refuses a stored value on the command line in any URL encoding
(#334).** It compared arguments with the value and with its
`encodeURIComponent` form only, so with `FAKE/pa ss@word+1` stored,
`run -- echo "x?p=FAKE%2fpa%20ss%40word%2b1"` (lowercase hex) and
`run -- echo "x?p=FAKE%2Fpa+ss%40word%2B1"` (`+` for a space) started the
command with the value readable in `ps`. Each argument is now also compared
percent-decoded, with upper- or lowercase hex and with and without `+` read as
a space, so those forms and a partly encoded value are refused as well.

**The Team Setup guide's `.secretless` example now parses (#331).** Step 4
showed lines such as `STRIPE_KEY        required    Stripe API key for payments`,
and the parser refuses any text after a name other than `optional` and a `#`
comment, so a manifest copied from the guide made `setup --check` print
`.secretless could not be parsed` and `Nothing was checked`, and exit 1. The
example now reads `STRIPE_KEY  # Stripe API key for payments` and
`SENTRY_DSN  optional  # Error tracking DSN`, and the guide states the line
format. The parser is unchanged: refusing other trailing text keeps a value
from sitting in a description column.

**The README and the bring-your-own-vault guide no longer say `vault exec`
reads the configured storage backend (#328).** `vault exec` resolves only from
the Identity Vault (`~/.aim/vault`) that `vault register` fills, so a secret
stored with `secret set` in any of the five backends gave
`Vault resolution denied: Namespace "<name>" not found`, while the README said
each tier "works against any supported backend" and the guide showed
`vault exec` as the way to use the backend it had just connected. Both now say
`vault exec` reads the Identity Vault only, and show
`run --only NAME -- <command>` for a secret in the backend.

**The README says when Secretless reads a stored value and where it sends one
(#339).** It said Secretless "never reads or transmits credential values it
manages" and that values "never enter AI context, transcripts, or shell
history". `run`, `env` and the shell hook read values to inject them, `clean`
and `watch` read them to find them in transcripts, `secret set` compares them,
and `secret push` sends them in an HTTPS request body to Azure Key Vault,
HashiCorp Vault or GCP Secret Manager; `secret set NAME=VALUE` puts a value in
shell history. The README now says no value is sent to OpenA2A, names the
commands that read a value and why, and names the two ways a value still
reaches shell history or AI context.

**The README and SECURITY.md give one response time for security reports
(#345).** The README promised a response within 24 hours; SECURITY.md says
receipt is acknowledged within 48 hours. The README now states the 48-hour
acknowledgement, names GitHub private vulnerability reporting beside
`info@opena2a.org`, and points to SECURITY.md.

**The README says `status` points to `doctor` for plaintext git credentials
(#342).** It said `doctor` and `status` each print Verify and Fix lines for a
`~/.git-credentials` or `~/.netrc` file and a `store` helper. `status` prints
one row for each that ends in `→ secretless-ai doctor`; `doctor` prints the
Verify and Fix lines, and `status --json` carries them in
`gitCredentials.findings`. The README now says so.

**The MCP docs no longer say every config holds plaintext keys that the model
sees (#340).** The README's "MCP server protection" section, the MCP guide and
the use-case index said every MCP server config has plaintext API keys and
that the LLM sees them. Many configs hold no key (`protect-mcp` reports
`No plaintext secrets found in MCP configs. Already clean.` for them), and the
client application reads a config to start its servers; the model sees a key
only when an assistant reads the file. The pages now say MCP client configs
often hold API keys in plaintext JSON, and that any assistant that can read
files on your machine can read them.

**The README says which secretless-ai release `opena2a secrets` runs
(#346).** It said only that Secretless powers `opena2a secrets`, while
opena2a-cli 0.10.13 depends on `secretless-ai@^0.14.1`, a release with no
`secret push`, `secret sync`, `git-credential` or `telemetry` command. The
"Using with opena2a-cli" section now names that range and those commands, says
to run them through `npx secretless-ai`, and gives
`npm view opena2a-cli dependencies.secretless-ai` to print the range the latest
opena2a-cli depends on.

**The "I already have a vault" guide no longer says Azure Key Vault is not
part of the CLI (#343).** It said AWS Secrets Manager and Azure Key Vault were
both missing, while `secret push --to azure-kv` writes to Azure Key Vault. The
guide now says Azure Key Vault is a push target, not a storage backend
(`backend set` does not accept it), and links the README's new "Push secrets
to a cloud secret store" heading; AWS Secrets Manager is still the one it names
as missing.

**`scan` no longer lists a key file it reported as a file it did not open
(#341).** In a directory holding `t.secretless-bundle`, `scan --json` reported
the bundle as a high finding and also counted it in `skippedUnsupported`, and
the human report listed it under `1 file not opened: ... unsupported file
type` with a `Scan one:` line that reported it again. A `.pem`, `.key`,
`.crt`, `.p12` or `.pfx` file got the same listing, though the scan reads each
of them for a private key or flags it by its presence. A key file is now
listed as not opened only when a test-file or ignore rule kept the scan from
reading it, with that rule as the reason; the same directory now reports
`"high": 1` and `"skippedUnsupported": 0`.

**The team setup guide no longer lists `keychain` as a shared team backend
(#344).** The table under "Choose a storage backend" in
`docs/use-cases/team-setup.md` offered `keychain` for "Small teams,
macOS-only", on a page whose premise is a backend every team member resolves
from. The OS keychain keeps its store on one machine, on macOS Keychain and on
Linux Secret Service alike, as the table in
`docs/use-cases/bring-your-own-vault.md` already said ("Shared across
machines? No"). The team table now lists `1password`, `vault` and `gcp-sm`
only, and a line under it says `keychain` and `local` are per machine and
points to the encrypted `export`/`import` bundle for moving such a store to
another machine. A test fails when the team table lists a backend the other
table says is not shared across machines.

**`secret push` no longer offers `secret set` for a name `secret set`
refuses (#323).** `secret push A,-x --to vault --dry-run`, with `A` stored and
`-x` not, printed `Fix: npx secretless-ai secret set -x`, and running that line
was refused with `Invalid secret name. ... Must start with a letter.`; a later
name that starts with a digit or `_` got the same unusable `Fix:`. Each such
name now gets its own line, ``"-x" cannot be stored by `secret set`, which
takes a name that starts with a letter; give the name the secret is stored
under.``, and the `Fix:` names the first missing name `secret set` takes. When
no missing name is one it takes, the `Verify: npx secretless-ai secret list`
line stands alone and no `Fix:` is printed.

**No usage event is sent from CI or a test runner (#320).** A CI job or a
test run starts in a fresh home directory, and each fresh home was given a new
install id, so every job and every test run that started the CLI was counted
as a new user. Nothing is sent now while `CI`, a CI service's own variable
(`GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `TF_BUILD` and others),
`VITEST`, `JEST_WORKER_ID` or `NODE_TEST_CONTEXT` is set. `--version` shows
`Telemetry: off` for such a run, and `telemetry status` shows `state: off`
with a line naming the variable. A value that is empty or only spaces, or is
`false` or `0` in any letter case with surrounding spaces ignored, counts as
unset, so `CI=false` and `CI=` leave telemetry as the user configured it. This
repository's test suite runs with `OPENA2A_TELEMETRY=off`, and a test that
starts the CLI with telemetry on fails before the CLI starts.

**`secret push` refuses a first name, or a first `--as` name, that starts
with `-` behind whitespace (#316).** `secret push A,B --to vault --as ' -x,a.b'`
printed `Fix: npx secretless-ai secret push A,B --to vault --as -x,a_b`, and
running that line was refused with `--as needs a value, but none was given.`;
`secret push ' -x' --to vault --as a.b` printed a `Fix:` that began
`secret push -x`, refused with `-x is not read by secret push`. Whitespace
around a name is dropped, so ` -x` is read as `-x` is: the push now stops
before anything is read with `"-x" cannot be the first --as name: ...
Choose another name for A.` or `"-x" cannot be the first name: ... Give
another name before it.` An empty name before it (`,-x`) is dropped as well
and refused the same way. A name that starts with `-` later in the list is
read as before, and a `Fix:` gives it back where it stands.

**The `<name>` a `secret push` refusal leaves in its `Fix:` is quoted
(#316).** `secret push A,B --to vault --as '<2fa>,a.b'` printed
`Fix: ... --as <name>,a_b`, which a shell, pasted unedited, read as input from
a file `name` and output to a file `,a_b`, creating or truncating that file
when `name` existed. It now prints `--as '<name>',a_b`; run unedited, the
line is refused for naming a placeholder and nothing is written or created.
A placeholder given in `--as`, such as `<names>`, is quoted the same way.

**`secret push --to azure-kv` no longer offers an `--as` name that starts
with `-` (#314).** Key Vault names allow letters, digits and `-`, so a refused
name was offered with `-` in place of each other character:
`secret push A --to azure-kv --vault kv-demo --as .x` printed
`Fix: ... --as -x`, and running that line was refused with
`--as needs a value, but none was given.` (`_x` gave `-x` too, and `.` gave
`-`). The `Fix:` now leaves such a name as `<name>`, and its
"cannot name a secret" line ends with `; choose another name for A.`

**`secret push` quotes both names when two `--as` names differ only in case
(#312).** `secret push A,B --to azure-kv --vault kv-demo --as a-b,A-B`
printed `A and B would both be pushed as "A-B".`, which reads as if A had been
given `A-B`. It now prints
`A and B would both be pushed as "a-b", since "A-B" differs from it only in case.`
The earlier secret's name comes first, as in the "is taken by" line. Two
equal names print one name, as before.

**A `secret push --as` value in angle brackets that is not a placeholder is
left as `<name>` in the `Fix:` (#312).** `secret push A --to vault --as
'<2fa>'` offered `Fix: ... --as _2fa_`, a name made from the characters of a
value meant to be filled in; `'<_name>'` gave `__name_` and `'<>'` gave `__`.
Vault accepts each of these if the `Fix:` is run as printed. The `Fix:` now
leaves `<name>`, and the line for the value ends with
`; choose another name for A.` The value gets that line wherever it stands in
`--as`: `secret push A,B --to vault --as 'a.b,<2fa>'` printed a
"cannot name a secret" line for `a.b` only, and now prints one for `<2fa>`
too. A `<word>` whose word starts with a letter a-z or A-Z and holds only
those letters, digits, `-` and `_` after it is still a placeholder and stays
in the `Fix:` as given.

**The `Fix:` of a `secret push --dry-run` refusal keeps `--dry-run` (#312).**
`secret push A --to vault --as a.b --dry-run` printed
`Fix: npx secretless-ai secret push A --to vault --as a_b`, which writes to
Vault when run as printed. The `Fix:` now keeps `--dry-run`, and so does
the one for two secrets that would be pushed as one name. `--dry-run` stands
before `--as` (#314): a `Fix:` that ended `--as <name> --dry-run` was read by
a shell, pasted unedited, as input from a file `name` and output to a file
`--dry-run`. It now ends with `--as '<name>'` (#316), which a shell passes
as given; run unedited, it is refused for naming a placeholder and writes
nothing.

**A `secret push` refusal says which secret needs another name for each
refused `--as` name its `Fix:` cannot spell as a command word (#307).** A
refused name that holds a character the refusal prints escaped, such as a tab
or a zero-width space, is left as `<name>` in the `Fix:`, and only the first
refused name got a "cannot name a secret" line.
`secret push A,B --to vault --as $'a.b,c\td'` printed that line for `a.b`
only, and its `Fix:` left B as `<name>` with no line saying why. Each such
name now gets the line, and the line ends by naming the secret the name was
given for: `; choose another name for B.` This holds for one that is the
first or the only refused name too; its line did not name the secret. A
refused name with no such character gets the line only when it is the first
refused name other than a placeholder, as before, unless it is a value in
angle brackets that is not a placeholder (#312) or one whose replacement would
start with `-` (#314), which gets the line wherever it stands.

**A `secret push` refusal names every secret its `Fix:` leaves as `<name>`
(#307).** `secret push A,B --to vault --as '<name>,<name>'` said only that
A's `<name>` was a placeholder; it now prints one placeholder line per
secret. `secret push A,B,C --to azure-kv --vault kv-demo --as a-b,A-B,a.b`
left B as `<name>` with no line saying why; it now prints
`A and B would both be pushed as "a-b", since "A-B" differs from it only in case.`
beside the line for C, as it already did when no name was refused. A `<word>` counts as a placeholder when the
word starts with a letter a-z or A-Z and holds only those letters, digits,
`-` and `_` after it; the `<names>` the usage line prints is one.

**`secret push` prints a `Fix:` when two secrets would be pushed as one name
(#303).** `secret push A,B --to vault --as x,x` printed
`A and B would both be pushed as "x".` and the usage line, with no command to
run next. It now prints `Fix: ... --as x,'<name>'`: the first secret keeps the
name, and each later secret the store would push as the same name is left as
`<name>` and named in its own line. This covers Azure Key Vault, which does not
tell names apart by case, so `secret push ab,AB --to azure-kv --vault kv-demo`
offers `--as ab,'<name>'`.

**A `secret push` run with the `<name>` of an earlier `Fix:` left unfilled
says `<name>` is a placeholder to replace (#302).** `secret push A,B --to
vault --as '<name>,a_b'` printed `"<name>" cannot name a secret in Vault` and
offered `--as _name_,a_b` as its `Fix:` (`-name-` for Azure Key Vault), a
name made from the placeholder's letters. It now prints `"<name>" in --as is
a placeholder: replace it with the name A should have in` the store, with the
characters that store allows, and the `Fix:` keeps `<name>` where it stands.
Each refused `--as` name in the same line that is not a placeholder is still
replaced as before, and the first of them gets the "cannot name a secret"
line. The `Fix:` leaves a name as `<name>` instead when it holds a character
the refusal prints escaped, is in angle brackets, or would be replaced by a
name that starts with `-`, and each of those gets its own line wherever it
stands (#307, #312, #314).

**A refused `secret push --as` name says why its `Fix:` leaves `<name>` when
the replacement is already taken (#295).** `secret push A,B --to vault --as
a.b,a_b` printed `--as <name>,a_b` with only the character-class reason for
`a.b`, so nothing said that `a_b` was not offered because `B` already uses it.
The refusal now prints one line per such name, before the `Fix:`:
`"a_b" is taken by B; choose another name for A.` The line names the secret
given that name or offered it earlier in the `Fix:`, and for Azure Key Vault,
which does not tell names apart by case, the spelling that holds it:
`"A-B" is taken by B as "a-b", which differs only in case; ...`.

**The `Fix:` under a refused `secret push --as` name no longer keeps two given
names the store would merge (#294).** Given names the store accepts were kept
as they were, so `secret push A,B,C --to vault --as x,x,c.d` printed
`--as x,x,c_d`, and running that line was refused with `A and B would both be
pushed as "x"`. An accepted name that the store would push as the same name
as an earlier one is now left as `<name>` for the user to fill in, so that
line prints `--as x,'<name>',c_d`; for Azure Key Vault, which does not tell
names apart by case, `--as x,X,c.d` gives `--as x,'<name>',c-d`.

**The `Fix:` under a refused `secret push --as` name no longer offers two
secrets the same name (#289).** Each refused name was replaced on its own, so
`secret push A,B --to vault --as a.b,a_b` printed `--as a_b,a_b`, and running
that line was refused with `A and B would both be pushed as "a_b"`. A
replacement that would push as the same name as another `--as` name, one
given or one offered earlier in the line, is now left as `<name>` for the
user to fill in; for Azure Key Vault, which does not tell names apart by case,
`--as A.B,a-b` gives `--as '<name>',a-b`. Replacements that stay distinct are
offered as before.

**The `Fix:` under a refused `secret push --as` name offers a name the store
accepts, `git-credential` prints a `--host`, `--name` or `--username` value it
refuses escaped, and `init` exits 1 when it left a tool not configured
(#285).** `secret push NAME --to vault --as a.b`, and the same with `--to
gcp-sm`, printed as its `Fix:` the command it had just refused, because those
two stores offered the refused name back. The `Fix:` now names one the store
accepts: each character outside letters, digits, `-` and `_` becomes `_`, and
a Secret Manager name is cut to 255 characters, so `--as a.b` gives `--as
a_b`. A refused name that holds a control character gets `<name>` for every
store; for Azure Key Vault the `Fix:` used to print that name with every
character Key Vault does not allow replaced by `-`. `git-credential install`,
`uninstall` and `get` printed a `--host`, `--name` or `--username` value they
refused as given, so a line feed in it started a new line that read like one
of the tool's own. Each is now printed with its control characters escaped,
such as `\n`, and a URL given as `--host` is answered with `use --host <host>`
when what is left of it holds one. A value that holds none prints as before.
`init` exited 0 after its "Not configured" block, printed for a tool whose
instruction path it refused to write through (a symbolic link, a file with
more than one hard link, an entry of the wrong kind, or a path outside the
project). It now exits 1, as it does when `.claude/settings.json` cannot be
updated, whether or not another tool was configured in the same run, so a
script that runs `init` on such a project sees a failure until the path is
changed as the printed `Fix:` says. Its output is unchanged, and the README
and docs/scanning.md list this case under exit code 1.

**`status --json` adds `ignoreFileTools` and `detectedTools`.**
`configuredTools` lists Aider, which `init` configures through `.aiderignore`,
beside the tools configured through an instruction file. The text output lists
the two apart, as `Ignore file:` and `Tool instructions:`, but a JSON consumer
could tell them apart only through `enforcement`. `ignoreFileTools` lists the
configured tools whose file is an ignore file, and `detectedTools` lists the AI
tools found in the project, configured or not. Every existing key is unchanged.
The type documentation of `StatusResult.enforcement` no longer says `none` is
reported exactly when `isProtected` is false; it also names the one case where
`none` is reported while `isProtected` is true.

**A command's own refusal of a subcommand or value prints the value escaped,
and the Fix under `init`'s "Not configured" block re-runs `init` on the
directory it was given (#280).** `backend`, `cache`, `secret`, `scope`,
`broker`, `vault`, `install`, `watch`, `hook`, `rules` and `git-credential`
given a subcommand or action they do not know, `diff` given a ref it refuses,
and a value refused by `backend set`, `backend purge --prefix`, `cache ttl`,
`rules test`, `secret show`, `secret rm`, `secret list`, `secret sync`,
`secret push` (its `--to` target and its `--as` name), `scope discover`,
`scope check`, `broker start --port`, `warm --ttl` or `protect-mcp --backend`
printed that value as given, and so did `scope reset`; a line feed in it
started a new line that read like one of the tool's own. Each is now printed
with its control characters escaped, such as `\n`, as the command line's own
refusals are. The `Fix:` under a refused `secret push --as` name leaves
`<name>` where that name cannot be spelled as a command word. Text that holds
none prints as before. The `Fix:` under `init`'s "Not configured" block ended with `re-run:
secretless-ai init`, which sets up the working directory, not the one given to
`init`; it now ends with `npx secretless-ai init` and that directory, as the
`Fix:` under `init`'s "Not a directory" message spells the command. The README
and docs/scanning.md say that exit code 1 also covers a `scan`, `status` or
`verify` target that is missing or cannot be opened, docs/scanning.md names
`mcp-status` with `feedback` and `diff` as the commands that warn about an
unrecognised flag, and the README's telemetry section gives `scan` and `init`
as example command names and says a first argument that is not a command is
sent as `unknown`. Detection, exit codes and the `--json` document are
unchanged.

**The usage event sends `unknown` in place of a first argument that is not a
command, and records that run as a failure.** The event's `name` field carries
the command that ran. `secretless-ai ./some/dir`, a mistyped command such as
`scna`, or another first argument that is not a command was sent there as
typed, so a path reached the telemetry endpoint, and the run, which printed
"Unknown command" and did nothing, was recorded as a success. Such a run now
sends `unknown` with `success: false`. A command that ran is sent by its name
as before. `OPENA2A_TELEMETRY_DEBUG=print` prints each event to stderr.

**`runInit` sets up the directory it checked when a path has `..` after a
symlink (#274).** This affects callers of the programmatic API only; the
command line resolves its argument first and is unchanged. The check that the
directory exists reads `..` after a symbolic link as the parent of the
directory the link points at, as the file system does. `init` then built every
path it writes by dropping `..` together with the name before it, so
`runInit('link/../proj')`, with `link` pointing into another directory, passed
the check on the `proj` beside the link's target and wrote to a `proj` beside
`link`, creating it when it did not exist. `init` now sets up the directory the
check found, and the paths it lists as created and under "Not configured" are
in that directory. A path whose `..` names the same directory either way, such
as one with no symbolic link before the `..`, is set up and printed as before.

**`scan`, `status` and `verify` say why a directory that is there cannot be
reached, `init` escapes a path in its "Not configured" block, and an argument
the command line refuses is printed escaped (#276).** `scan locked/inner`,
where `locked` is a directory this user cannot search, said "Directory not
found" and "Check the path and try again"; `scan`, `status` and `verify` now
say "Permission denied", name the directory that cannot be searched, and print
a `Verify:` line and a `Fix:` line. When the path runs through a symbolic link
into that directory, they name the link as well. A path through a symbolic
link that points back at itself gets "Too many levels of symbolic links" and
names the link,
and any other failure of the lookup is named by its error code. `scan --json`
prints the same lines to stderr and no document. `init` printed a path as
given in the list under "Not configured" and in the `Verify:` and `Fix:` lines
under that list, so a line feed in a directory name started a new line; the
list now prints each control character as an escape such as `\n`, and those
commands name `<path>` in place of a path that cannot be printed as itself.
`scan` given two paths, `init` or `status` given an argument that starts with
`-`, a command given an option it refuses or warns about, such as `--bogus`
or `--json=` with a value, and an unknown command or `telemetry` action
printed the argument as given; it is now escaped the same way, and the `scan`
command the two-path message suggests quotes the first path for pasting, or
names `<path>`. A command's own message for a subcommand or value it does not
accept, such as `secret` given an unknown subcommand or `diff` given a ref it
refuses, still prints it as given.
On Windows, the "Directory not found" and "Not a
directory" messages of `init`, `scan`, `status` and `verify` print a path with
`/` between its parts, as a finding's path is printed, while the `Verify:` and
`Fix:` commands under them kept `\`; the commands now spell the path with `/`
as well, and so do the list and the commands under "Not configured". `scan
--help` said a directory scan "opens nothing else" beyond the files it lists,
while every command also reads the telemetry setting and creates its file when
that is absent; the help now limits that sentence to the files a scan opens
for secrets or for its rules, and names the file:
`~/.config/opena2a/telemetry.json`, or
`$XDG_CONFIG_HOME/opena2a/telemetry.json` when that variable is set. For a
caller of `runInit`, a file path that ends in `/.`, such as `notes.txt/.`, got
a `Fix:` that ran `init` on the file; it now names the directory that holds
the file. `IGNORE_FILENAME` in `dist/secretlessignore`, exported for this
package's own help text, is left out of the published type declarations, as
the four exports named under #273 are. Detection, exit codes and the `--json`
document are unchanged.

**`scan`, `status` and `verify` name the file a path runs through, `init`
escapes the path in its "Directory not found" and "Not a directory" messages,
and `scan --help` names the ignore file
(#273).** `scan notes.txt/sub`, where `notes.txt` is a file, said "Directory not
found" and "Check the path and try again"; `scan`, `status` and `verify` now say
"Not a directory", name the file, and print a `Verify:` line and a `Fix:` line:
`scan` on the file, `status` and `verify` on the directory that holds it.
`scan --json` prints the same lines to stderr and no document. `init` printed
a path in its messages as given, so a line feed in a directory name started a
new line that read like one of its own. Its "Directory not found" and "Not a
directory" messages, and those of `scan`, `status` and `verify`, now print
each control character in a path as an escape such as `\n` or `\e`, as `scan`
does for a file name, and a `Verify:` or `Fix:` command under them names
`<path>` in place of a path that cannot be printed as itself. `init` still
prints a path as given in an error from the file system, such as `EACCES:
permission denied`, and in its "Created:" and "Modified:" lists. `init` on a
symbolic link whose target does not exist, or
on a path under one, suggested a `mkdir -p` that fails on that link; it now
names the link and leaves that suggestion out. For a caller of `runInit`, a
path with `..` after a symbolic link named a file in the link's own parent
directory; it now names the file the lookup stopped at. `scan --help` said a
directory scan opens nothing beyond the files it lists, while it also reads
`.secretlessignore` at the top of the scanned directory for its rules; the
help now names it. An option description too long for its line in any
command's `--help` now continues on the next line, so `scan --help` fits an
80-column terminal. The published type declarations no longer include four
exports that exist for this package's own tests and help text:
`withDirsVisitedBudget` and `GLOBAL_CONFIG_LABELS` in `dist/scan`, and
`nearMissCellsEvaluated` and `resetNearMissCellsEvaluated` in
`dist/near-miss`. Detection, exit codes and `--json` output are unchanged.

**`init` lists a `.claude/settings.json` it created under `Created:`, where it
listed the file under `Modified:`.** In a project with no settings file, `init`
printed `Modified:` and `~ .claude/settings.json (added 99 deny patterns)`
about a file that was not there before the run. The list is what a reader uses
to decide what to commit and what a revert costs, and it said a file of theirs
had been edited. The row now reads `+ .claude/settings.json (99 deny patterns)`
under `Created:`, after the two hook scripts and before `CLAUDE.md`, with the
count worded as `status` words it, and the run prints no `Modified:` section. A
settings file that was there before the run, an empty one included, stays under
`Modified:` as `~ .claude/settings.json (added 99 deny patterns)`. For library
callers, the value `init()` returns keeps its keys and types, and one path
moves: on a project with no settings file `.claude/settings.json` is now in
`filesCreated` and no longer in `filesModified`, so code that reads
`filesModified` to learn whether the settings were written should read both
lists. The README quick start and the `docs/use-cases/protect-my-credentials.md`
sample are regenerated from this build. Unchanged: what `init` writes, its exit
codes, and the output of `status` and `verify`.

**`broker start` now serves `POST /grant` when it has a grant file; until now
the endpoint answered 404 on every broker the command could start.** The grant
flow has been in the package as a library: the broker verifies the agent's ATX
credential, matches it against a binding, exchanges it for a short-lived scoped
token at an identity provider, makes the downstream call itself and returns
only the response. The daemon never built it, so `/grant` answered
`404 {"error":"Not found"}` beside a healthy `/health`, and only code that
constructed `BrokerServer` by hand could reach it. `broker start` now loads
`~/.secretless-ai/broker-grants.json` when that file exists, or the file named
by the new `--grant-file <path>` (which must exist). The file has four
sections: `trust` (the ATX issuers accepted, their Ed25519 public keys, and
revoked agents), `assertion` (the issuer and key id the broker signs under),
`providers` (identity providers by id, each an OAuth token endpoint for an
RFC 8693 token exchange) and `bindings` (one per grant, read by the same code
that validates a binding passed in memory). A file the broker cannot apply as
written stops the start and says why: a key it does not read, a repeated key, a
misspelled predicate, a public key the verifier would drop, a token endpoint
over plain `http` off the loopback address. The first start creates the
broker's Ed25519 signing key at `~/.secretless-ai/broker-assertion.key` (mode
`0600`) and writes its public half beside it as a JWK for you to register with
each identity provider; a later start signs with the same key, and a key file
other users can read is refused with the `chmod` that fixes it. A start that
loaded a grant file prints the file, the number of bindings and providers, and
the path of the public key. Grant decisions go to the broker's audit log as
`grant` events, and a broker started with `--aim-url` denies an agent AIM
reports as unverified on `/grant` as well. The grant file is read at start, so
an edit, including a revocation, takes effect on restart. Unchanged: with no
grant file `/grant` still answers 404, and `/resolve`, `/health`, `/status` and
the policy file behave as before. `broker status` does not report grants yet.
For library callers, `startDaemon` accepts `grantFile` and `tokenFile`.
`docs/use-cases/run-broker.md` has a new Grants section with the file format
and a request.

**`scan` no longer tells you to move a key in a `.env` file to an env var, and
no longer prints `Protect now: npx secretless-ai init` in a project `status`
reports protected.** A key found in a real `.env` file (`.env`, `.env.local`,
`.env.production` and the other names `scan` reads) got the same Fix as a key
in source code, `Move to env var STRIPE_SECRET_KEY`, where it already is. Its
Fix now reads `Store it with npx secretless-ai import .env, delete the line,
and start the app with npx secretless-ai run -- <command>.`, followed by the
same rotation text as before. The path is the one that works from the
directory you ran `scan` in, quoted for the shell when it needs to be, and
`<file>` when the name holds a terminal control character. A key in any other
file keeps its Fix as it was. `scan --json` and the library's `scan()` carry
the same text in `fix`. The Next Steps block printed `Protect now: npx
secretless-ai init` after every scan with findings, including in a project
where `init` had run; `scan --explain` did the same with `Run \`npx
secretless-ai init\` to add protections.` Both lines now follow the rule
`status` uses for its own `init` advice: they appear where nothing is set up,
where the guard script is on disk and no settings file runs it, and where only
instruction files are set up in a project `init` sets up Claude Code in. A
project where the Claude Code hook enforces protection no longer gets them, nor
does one `init` set up through instruction or ignore files for Cursor, GitHub
Copilot, Windsurf, Cline or Aider alone. A scan of a single file reads the
directory holding it. What `scan` detects, its severities and its exit codes
are unchanged. The sample `scan` output in the guide for migrating from `.env`
files (`docs/use-cases/migrate-from-dotenv.md`) shows the new Fix, and the
guide says that Step 2 imports every `.env` file at once.

**`mcp-status` and `protect-mcp` no longer report a server as clean when a part
of its entry could not be read.** A config that is valid JSON can still hold a
server entry these commands cannot read: an `env` written as one string or as
an array, an env value that is a number or a nested object, or a server that is
not a JSON object. Each such part was passed over without a word, so
`mcp-status` printed `clean (no secrets in env)` and `protect-mcp` printed
`Already clean.` over a value neither had looked at. `mcp-status` now lists the
server under its config as `? <server>: env not checked: not a JSON object`,
`? <server>: env value API_TOKEN not checked: not a string` or
`? <server>: entry not checked: not a JSON object`, and prints no `clean` line
for it. A plaintext secret found in the rest of the entry is still reported as
`EXPOSED`, and `protect-mcp` still encrypts it. Both commands then print the
number of servers with an unread part, the shape that can be read (a server is
a JSON object, and its env is a JSON object of string values) and a Fix line,
and `protect-mcp` prints `No plaintext secrets found in the parts of the MCP
configs that were read.` in place of `Already clean.` The lines name the server
and the env entry and never quote a value. An entry, `env` or env value that is
`null` holds nothing and is not listed. What these commands detect as a secret
is unchanged, and so are their exit codes. In the library, each config from
`discoverMcpConfigs()` carries the list as `unchecked`, and the `protectMcp()`
result carries it per config as `unchecked`.

**`status` no longer prints `Protected` for a project configured only through
instruction files, and `status --json` adds `enforcement`.** `status` reported
a project as `Protected` once any AI tool carried the Secretless instruction
block. For Cursor, GitHub Copilot, Windsurf and Cline that block is an
instruction file: nothing enforces it, and it has no effect unless the tool
loads that file. A project whose only configuration was such a file printed
the same `Protected` verdict as a project with the Claude Code guard hook. Its
verdict line now reads
`Advisory only: instructions for Windsurf, which nothing enforces`, and its
instruction row reads `Tool instructions: Windsurf (advisory, not enforced)`.
This corrects what `status` reports and is not a regression in protection: a
project that printed `Protected` on instruction files alone has the same files
and the same protection after upgrading as before, and it did not have an
enforced control then either. `Protected` is now printed only where Claude
Code applies a guard hook or deny patterns, from the project's settings or
from user-level settings that reach the project.

`status --json` gains `enforcement`, one of `hook`, `ignore-file`, `advisory`
or `none`: the strongest mechanism `isProtected` rests on. It is `none`
whenever `isProtected` is false, and also for the case in the next entry.
`isProtected` and `summary.verdict` keep their meaning, so a CI job that gates
on them behaves as before: a project with instruction files alone still
reports `isProtected: true` and `protected-warnings`. To require an enforced
control, gate on `enforcement` being `hook`.

**`status` no longer reports a guard script that nothing runs as the Claude
Code hook, and `status --json` adds `hookWired`.** `status` treated
`.claude/hooks/secretless-guard.sh` existing on disk as the hook being in
place. Claude Code runs the guard only when a settings file wires it into
PreToolUse, so a project whose `.claude/settings.json` lost that entry (another
tool rewrote the file, or it was edited by hand), or whose settings file is
gone, printed `✓ Claude Code hook installed`, `enforcement: hook` and
`Protected` while nothing ran the guard. The hook row now reads
`Claude Code guard script not run: .claude/settings.json does not run it` as a
warning that names `secretless-ai init`, which adds the entry back. `enforcement`
is `hook` only where a settings file that reaches the project runs the guard
or carries deny patterns; with neither, it is `advisory` when the `CLAUDE.md`
block is present and `none` otherwise, and the verdict line reads
`Not enforced: the guard script is on disk and no settings file runs it`
instead of `Protected`. `hookInstalled` keeps its meaning, the script is on
disk, and the new `hookWired` is true when `.claude/settings.json` runs it.
`isProtected` is unchanged for these projects. The new warning row means such a
project reports `protected-warnings` where every other row was clean, which is
the value it should have reported.

**`init` and `status` agree about an Aider project.** `init` configures Aider
by writing patterns to `.aiderignore` and printed `Configured: Aider`. `status`
looked for an instruction block in `.aider.conf.yml`, which `init` does not
write, and printed `Not protected` for the same directory. `status` now reads
the `.aiderignore` block `init` writes: the project is listed as
`Ignore file: Aider (.aiderignore, no hook enforces it)`, `enforcement` is
`ignore-file`, and the verdict line reads
`Ignore file only: .aiderignore for Aider, which no hook enforces`. For this
layout `isProtected` changes from `false` to `true` and `summary.verdict` from
`not-protected` to `protected-warnings`, the values the instruction-file tools
already report. `.aiderignore` is a list of paths for Aider to leave out; no
hook enforces it, and Secretless does not check that Aider applies it.

**`init` states the mode of each tool it configures.** Under the `Configured:`
line `init` prints one line per mode: `Enforced: Claude Code (guard hook and
deny patterns)`, `Ignore file: Aider (.aiderignore, no hook enforces it)` and
`Advisory: Cursor (instruction file, nothing enforces it)`. `Configured: Cursor`
on its own read as protection in place. The README quick start and the
`docs/use-cases/protect-my-credentials.md` sample show the new lines, and the
README's supported tools section says what `status` prints for each mode.

**`status` no longer names `secretless-ai init` as the fix for a hook `init`
does not install.** In a project set up for another tool and not for Claude
Code, `init` configures that tool and installs no hook, so the
`Claude Code hook not installed` and `Stop hook not installed` rows, which
ended in `→ secretless-ai init`, sent the user to a command that left both
rows as they were. Those rows now end in
`for Claude Code: mkdir -p .claude && secretless-ai init`, which installs
both. The `Not protected` line for such a project said to run `init` "to
install hooks"; it now says that `init` configures the tools it detected and
that hooks are installed for Claude Code only.

**Scan coverage and exit-code detail moved from the README to
`docs/scanning.md`.** The README had grown to 417 lines. What a directory scan
opens, which gaps fail a build, how a command line the tool cannot bind is
refused, and the sample `--json` summary are on that page, with the text
unchanged. The README keeps the exit codes, a short summary and a link, and
How it works step 1 links to the page's "What a directory scan opens" section.
A test holds the README under 400 lines and checks that every relative link
and anchor in the README and `docs/` resolves.

**The Claude Code guard hook refuses a command that prints the environment
through `set`, `env`, `printenv`, `export`, `declare`, `compgen`, an
interpreter one-liner, `docker`, `kubectl`, `tmux`, `launchctl`, `systemctl`
or `npm`, and a command it cannot parse.** The
hook refused a few spellings of an environment dump by matching command text
(a bare `printenv`, a bare `env`, a process listing that shows environments
or full command lines, a `node -e` one-liner naming `process.env`) and let
the other shapes through: a bare `set`,
`set -x`, `export -p`, `declare -p`, `typeset`, `compgen -v`,
`printenv NAME`, a python, ruby or perl one-liner printing `os.environ`,
`ENV` or `%ENV`, `node -p process.env`, `docker inspect`,
`docker exec <container> env`, `tmux show-environment`, and any of these
behind `bash -c`, `eval`,
`sudo`, `xargs`, a subshell, a pipe or a command substitution. Under `python3`
the hook now parses the whole command into the simple commands the shell runs
and judges each by what it runs. `set` passes only with a literal option that
turns on no tracing or allexport (`set -e`, `set -euo pipefail`,
`set -o pipefail`), and zsh `setopt` never with `xtrace`, `verbose` or
`allexport`; `env` only as a prefix that runs a program
(`env -u NAME cmd`); `printenv` and `compgen` never; `export`, `readonly`,
`declare`, `typeset` and `local` only as assignments (with a bare name and no
option, `declare`, `typeset` and `local` print the variable in zsh, so they
need `NAME=value` or an option); an interpreter one-liner is refused when its
program names the whole environment (`os.environ` with no subscript or
`.get`, `process.env` with no property, ruby `ENV`, perl `%ENV`, php
`getenv()`, awk `ENVIRON`) and allowed when it reads a variable by name
(`os.environ.get("HOME")`, or `process.env.HOME`, which was refused before
and is now allowed); `docker inspect` only with a `--format`
that names no `Env` field. A command the parser cannot read, such as one with
an unclosed quote or a program name or `bash -c` or `eval` string that comes
from an expansion, is refused with the reason it could not be read and a
rewrite. For an expansion the reason quotes the command. For a construct that
is never closed it quotes up to 60 characters from the point where the parser
stopped, and that is nothing when the parser stopped at the end of the command
(an unclosed double quote, `(`, `$(`, `[[`, `case`, `$'` or array assignment).
A process substitution in an argument, as in `diff <(sort a) <(sort b)`, is
read like the rest of the command and judged by what runs inside it, so
`cat <(env)` is refused. The hook does not read the command after `eval --`
or `sudo -k`, a process substitution inside `[[ ]]`, a script that bash reads
from a process substitution (`bash <(echo env)`), a named coprocess or
`${ cmd; }`, so an environment print there is not refused unless an older
text rule matches it, as for a bare `env`.
Without `python3` nothing parses the command and the hook matches its text
instead. A command is refused when `set`, `env`, `printenv`, `export`,
`declare`, `typeset`, `local`, `readonly`, `compgen`, `ps`, `pgrep`, `tmux` or
`docker inspect` stands at the start of a line, after `;`, `&`, `|`, `(`, `{`,
a backquote or `!`, after `eval` or a shell's `-c`, or behind `sudo`, `doas`,
`command`, `builtin`, `exec`, `nohup`, `time`, `nice`, `xargs` or `watch`, and
the reason says to install `python3` unless an older rule refuses the command
first with its own reason, as for a bare `env`, a bare `printenv` or `ps e`.
The name is not matched after `then`, `do` or `else`, after an assignment or a
redirection, in a `case` arm, behind `timeout` or a wrapper option whose
value is a separate word (`sudo -uroot set` is refused, `sudo -u root set`
is not), or when it is quoted or backslash-escaped: `if true; then set; fi`,
`X=1 env`, `sudo -u root set` and `"printenv"` are allowed. Deny
reasons that named `printenv NAME` as the safe path now name
`[ -n "$NAME" ]`. Re-run `secretless-ai init` to refresh an installed hook.

**`scan --help` names the home-directory files a scan reads, `--json` carries
the count a `--max-files` cap needs, and `init` under a file names that file
(#263).** `scan --help` said a directory scan opens nothing beyond the files it
lists, while every directory scan also reads `~/.claude/CLAUDE.md`,
`~/.claude/settings.json`, `~/.claude.json` and `~/.cursor/mcp.json`; the help
now lists them. The `--json` summary adds `eligibleFiles`, the count the human
report's `--max-files` Fix is sized from (0 when no cap dropped a file), and
`walkBudgetExceeded`, set when the walk's directory limit stopped it, which no
file cap clears. `init notes.txt/sub`, where `notes.txt` is a file, said
"Directory not found" and suggested a `mkdir -p` that fails on that file; it
now names the file and suggests `init` on the directory that holds it.
Detection, the report's "files not opened" list and exit codes are unchanged.

**The grant resolver holds the life any provider reports for a scoped credential to the binding's TTL.**
`ExchangeProvider` caps the life it reports at the binding's `ttlSeconds`, but
the provider registry takes any `CredentialProvider`, and `GrantResolver`
handed the worker whatever a provider returned. Under a 300 second binding, a
provider that reported `43200`, `1e21`, `NaN`, the string `"300"` or no life at
all reached the downstream caller with that value as `expiresInSeconds`. The
resolver now applies the rule the exchange site applies, from one shared
function: a stated life can shorten the binding's TTL and cannot extend it, a
value that is not a number reports the TTL, and a negative one reports 0. The
worker receives a copy of the credential, so the object a provider returned is
not changed, and own members a provider adds beside `token`, `tokenType` and
`expiresInSeconds` are kept. A provider that returns no credential object is
now denied before the downstream caller runs. This bounds the life the broker
reports; it does not shorten the credential the provider issued.

**The broker's assertion mint functions refuse an issue time that is not a clock reading in seconds.**
`mintBrokerAssertion`, `mintBrokerAssertionMlDsa65` and
`mintHybridBrokerAssertion` take the issue time as an argument, `nowSeconds`,
so tests and fixture generation can fix the clock, and `exp` is that value
plus the binding's TTL. Nothing checked it: `NaN` or `Infinity` minted
`"iat": null, "exp": null`, the string `"1780315200"` minted a thirteen-digit
string `exp`, and a `Date.now()` reading, which is in milliseconds, minted an
`exp` more than fifty thousand years out (the year 58385 for a reading taken
on 2026-06-01). Each now throws, naming the value, unless `nowSeconds` is a
number from 0 to 253402300799 (9999-12-31T23:59:59Z, the last second a
four-digit year can state). Every millisecond reading after 11 January 1978
lies outside that range, and the error for one says to pass
`Math.floor(Date.now() / 1000)`. The default clock is unchanged, so every
assertion `ExchangeProvider` mints is unchanged.

**In Exchange mode the life reported for a scoped credential is capped by the TTL its assertion was minted with.**
`ExchangeProvider.resolve` checked the binding's TTL when it minted the broker
assertion, then read `ttlSeconds` from the caller's binding object a second
time, after the authorization server answered, to cap the reported life. A
binding object changed while the token exchange was in flight (a configuration
reload that edits bindings in place, for example) was reported with the later
value: an assertion minted with 300 seconds came back as a credential life of
`1e21`, of one year when the server stated one, or of `NaN`. The provider now
reads each member of the binding once, before it mints, and uses that copy for
the assertion, the token-exchange request and the reported life, so the
`scope` and `audience` it requests are also the ones the assertion carries.

**The broker's assertion mint functions refuse a binding TTL outside 1 to 43200 seconds.**
`mintBrokerAssertion`, `mintBrokerAssertionMlDsa65` and
`mintHybridBrokerAssertion` take a resource binding directly, and a binding
built in code never passes `GrantPolicy`. They added whatever `ttlSeconds`
held to the issue time: an absent TTL or `NaN` minted `"exp": null`, the
string `"300"` minted a thirteen-digit `exp`, and `1e21` minted one trillions
of years out. Each now throws, naming the value, unless `ttlSeconds` is a
whole number from 1 to 43200, the same range `GrantPolicy` loads.
`ExchangeProvider.resolve` mints before it calls the authorization server, so
a refused binding sends no token-exchange request.

**A grant binding's `resolve.ttlSeconds` may be at most twelve hours.**
`GrantPolicy` required a whole number of seconds greater than zero and set no
upper bound, so `ttlSeconds: 1e21` loaded and minted a broker assertion whose
`exp` lay trillions of years out, which a verifier reads as no expiry at all.
A binding above 43200 seconds is now refused at load, and the error names the
ceiling and the value. In Exchange mode the binding's TTL also caps the life
reported for the scoped credential:
an `expires_in` from the authorization server can shorten it but not extend
it, a `NaN` falls back to the binding's TTL, and a negative value is reported
as 0 seconds.

**`scope discover` and `scope check` profile an AWS credential's own access key.**
For an AWS credential, both commands signed their requests with the key pair
in the environment instead of the credential's stored access key ID, so the
permissions of whichever principal the environment held were reported as that
credential's, and `scope discover` saved them as its baseline. Requests are
now signed with the stored access key ID, using the secret key and session
token from the environment, so AWS answers for that key or rejects the
signature. When `AWS_ACCESS_KEY_ID` in the environment names a different key,
both commands stop before sending a request and save no baseline.
`AWSScopeProvider.discover(credential)` refuses a credential other than the
access key it signs with. A baseline an earlier version saved for an AWS
credential while the environment held a different key pair holds that key's
permissions: `scope reset <name>` and then `scope discover <name>` rebuilds it.

**`scope discover` and `scope check` sign their AWS requests for `us-east-1`.**
Both commands send their AWS requests to the global STS and IAM endpoints,
`sts.amazonaws.com` and `iam.amazonaws.com`, for which AWS scopes a signature
to `us-east-1`. They signed them for the region named by `AWS_REGION` or
`AWS_DEFAULT_REGION` instead, so with either set to another region the
signature did not carry the scope AWS checks for those hosts. The IAM steps
read a 403 as a permission the key does not hold, so `scope discover` could
save a refused IAM request as a baseline with no permissions. Every request is
now signed for `us-east-1` whatever region the environment names, and the
`region` argument of the `AWSScopeProvider` constructor no longer changes the
signature. A baseline saved while either variable named another region may
list no permissions: `scope reset <name>` and then `scope discover <name>`
rebuilds it.

**`scope discover` and `scope check` profile an IAM user created with a path.**
Both commands took the user name they send to IAM from everything after
`:user/` in the caller's ARN. An IAM user created with a path has an ARN of
the form `arn:aws:iam::123456789012:user/division/team/JaneDoe`, and IAM takes
`UserName` as the friendly name alone, so for such a user the request carried
`division/team/JaneDoe`, IAM refused it with HTTP 400, and both commands
stopped with `IAM ListAttachedUserPolicies failed (HTTP 400)`. The name sent
is now the last segment of the ARN. A user created without a path is
unchanged.

**`scan` prints a control character in a file name or an excerpt as a visible escape.**
The report printed names and excerpts from the scanned files as they were,
so a line feed in a file name started a new report line that read like the
scanner's own, and an escape character reached the terminal as a control
sequence. The human report now prints each control character (U+0000 to
U+001F and U+007F to U+009F), each Unicode format character, and each
character that prints as nothing or as a blank, such as U+034F, U+2800 and the
variation selectors, in every name and excerpt it shows as an escape such as
`\n`, `\t`, `\e`, `\x07` or `\u2800`, written as `hackmyagent` writes them. In
a finding's path, a literal backslash that could be read as one of these
escapes is doubled, so `dir\nx` and a name holding a line feed print apart. In
a list of paths the scan skipped or could not read, such a name is printed
inside `$'...'` with every backslash doubled and a single quote written `\'`,
so a `: ` inside the name cannot pass for the separator before its reason. A
`Verify:` or `Fix:` command names the first listed path that prints as itself,
or for symlinks outside the scan root the first target that does, and `<path>`
when none does; a `Scan one:` line names such a path or is left out. On
Windows a finding's path prints with `/` between its parts. Each name in those
lists, whether it prints as itself or escaped, and the path in each `Verify:`,
`Fix:` or `Scan one:` command, the `Verify:` under a finding with `--explain`
included, now go through the same conversion; a listed name that printed as
itself did not, so one list could hold both separators.
`scan --explain` prints generated context line by line under its own indent,
and `vault scan` prints each finding's path escaped. Escaping happens after
detection and masking, and the escaping changes no `--json` output.

**`scan` lists a file whose name holds a backslash under that name, and
matches its rules against that name.** On Linux and macOS a backslash is a
character a file name can hold, and the lists of skipped, unread and
unfollowed paths turned it into `/`: a file named `n\x.txt` in `dir` was
listed as `dir/n/x.txt`, and `Scan one:` offered that path, which does not
exist. A symlink named `l\nk` that points outside the scan root stopped the
report with `ENOENT` while it built that link's `Fix:` line. Those lists,
their `Scan one:` and `Fix:` lines and the same paths in `--json` now keep the
backslash. The `.secretlessignore` rules, the default-ignore list and the
built-in config list were matched against the name with its backslash turned
into `/` too, and now match the name as it is. A rule for `n\x.js` now applies
to that file, which is listed as `ignore rule (--no-ignore)` and counted in
`ignoreFileExcluded`, so the scan exits 1 as for any path the tree's own
ignore file excludes. The default rule `test/` no longer keeps a file named
`test\y.js` at the root of the scan from being read. A file named
`.mcp\config.json` at the root is no longer read as the `config.json` of a
`.mcp` directory; it is listed as a config file not on the built-in list, as
`secrets.json` is. Under `--no-ignore`, a finding in a file named
`docs\vhs\y.js` no longer has `looksLikeFixture` set. A file named on the
command line, such as `n\x.txt` scanned from its own directory, is reported in
`--json` as `n\x.txt`, where it was `n/x.txt`. On Windows, where `\`
separates the parts of a path, the lists and their paths in `--json` print `/`
between them as before, and the path of a file named on the command line
outside the current directory now goes through the same conversion, so
`C:\other\x.env` is reported as `C:/other/x.env`.

**`scan` lists a key file that an ignore or test-file rule covers with that
rule.** The source walk listed each `.pem`, `.key`, `.crt`, `.p12`, `.pfx` or
`.secretless-bundle` file it skipped as `unsupported file type`, because the
key walk reads those. The key walk applies the ignore and test-file rules as
well, so a key file named in `.secretlessignore` was read by no walk while its
reason named a type the scan reads. Such a file is now listed with
`ignore rule (--no-ignore)` or `test file (--include-tests)`, the flag that
reads it, in the report and in `skippedUnsupportedFiles` in `--json`. Findings
and exit codes are unchanged.

**`scan` lists a config file that is not on the built-in list once.** A
config-format file such as `secrets.json` was named under
`1 config file not scanned: ..., so not known to be clean.` and again under
`1 file not opened: declared boundaries, not findings.`, each with its own
`Scan one:` line. It is now listed only under the first heading, and the count
in the second leaves it out. `skippedUnsupported` and `skippedUnsupportedFiles`
in `--json` still include it, as `unscannedConfig` does. The sample behind
`skippedUnsupportedFiles` keeps up to twenty such config files and, apart from
them, up to twenty other files, so it can hold forty entries, and the second
heading lists up to eight of its own files and can offer one as `Scan one:`
however many config files sort ahead of them.

**`scan` words its coverage lines with the separators `vault scan` uses.**
The coverage section joined each heading to its explanation with a dash, and
each directory not entered and each file not opened to its reason the same
way. It now prints
`Scan incomplete: stopped at the 5000-file cap, so files were left unscanned.`,
`1 path could not be read, so not known to be clean.`,
`1 symlink points outside the scan root, so not followed.`,
`1 file skipped for size, so not known to be clean.`,
`1 config file not scanned: its name is not on the built-in config list, so not known to be clean.`,
`1 directory not entered for source files: declared boundaries, not findings.`,
`1 file not opened: declared boundaries, not findings.` and one
`<path>: <reason>` line per directory or file, such as
`node_modules: dependency or build output`. The line under an unreadable path
reads `Cause differs by path: permissions, ...`. Detection, exit codes and
`--json` output are unchanged.

**Five fresh-user findings fixed: a `--max-files` suggestion that clears the
truncation, `-V`, and three messages that now end in a next step (#127).**
A scan stopped at the file cap suggested four times the cap, so 30 eligible
files scanned with `--max-files 2` were told to use 8 and stayed truncated. The
walk now counts eligible files past the cap without opening them, and the Fix
line suggests that count, which clears the cap in one run. When a directory
limit rather than the file cap stopped the walk, the report says raising
`--max-files` will not help. `-V` prints the version, as `-v` and `--version`
do. `init` on a path that does not exist, or is a file, says so and gives
Verify and Fix lines instead of a raw `ENOENT: ... mkdir` error; nothing is
written. `diff` in a repository with no commits says there is no commit to
compare against and suggests a first commit, instead of `git fetch`. `scope
check` for a name with a stored baseline but no stored credential calls the
baseline stale and offers `scope reset` or `secret set`. Scan findings, verdicts
and exit codes are unchanged.

**`scan --help` says what a directory scan does not open.** The help named
only dependency and build output as unread, while a directory scan prints one
of eight reasons beside each path it skipped and explains none of them before
the run. `scan --help` now lists the source extensions, config file names and
key file extensions a directory scan opens; each reason the scan reports for a
path it skipped (`unsupported file type`, `config file not on the built-in
list`, `test file`, `test directory`, `ignore rule`, `hidden directory`,
`dependency or build output`, `git metadata`), with what it covers and the
flag that opens it where one does; and that naming a file scans it whatever
its type. `--include-config` now has a description in the options list. What
the scan opens, its findings and its exit code are unchanged.

**`status --json` and `vault scan` count a file skipped for size as
unscanned.** `status --json` read `scanIncomplete: false` over a tree holding a
file skipped for size, and `vault scan` printed `No hardcoded credentials
found.` over one. Both built their own coverage counters without the size
list, so `status` reported a complete scan where `scan --json` on the same tree
reported `oversize: 1` and exited 1. `status --json` now reads
`scanIncomplete: true` there, and `vault scan` says how many files were skipped
for size. A test finds every call to the scanner in the shipped code and fails
when one leaves out a coverage counter.

**The README's `clean` example runs (#240).** Under "A flag never widens
scope" the README showed `npx secretless-ai clean --dryrun --path ./transcripts`
as a bare command to illustrate the refusal, so a reader who copied it got exit
2 and nothing else. It now shows `clean --dry-run --path ./transcripts`, and the
refusal a mistyped `--dryrun` produces is shown as output. `src/docs-commands.test.ts`
now passes every `secretless-ai` invocation in the README and `docs/` to the
CLI's argument parser and fails on any flag it would refuse or ignore.

**The gcp-sm backend reads a repository's GCP project from its `.secretless`
(#177).** A `gcp.projectId: <project-id>` line in a repository's `.secretless`
names the GCP project that repository's names are read from and stored in, for
commands run in the repository or any directory below it. It wins over
`gcp.projectId` in `~/.secretless-ai/config.json`, the service account key's
`project_id` and the ADC quota project; a machine with no such line resolves
exactly as before. Outside a repository only the current directory's
`.secretless` is read. A `gcp.projectId` line that is empty, appears twice, or
is not a project id or project number is a manifest error, and the backend then
refuses instead of using another project. `status` shows the project and the
file or setting it came from (`gcpProject` in `--json`); `verify` names the
project for each manifest name, with a `gcloud secrets list` command that checks
access; `secret list` says when its list belongs to one repository. A permission
error names the project and the manifest line that chose it, and a
manifest-named project these credentials cannot list is an error instead of an
empty list. Reads from a manifest-named project skip the value cache, which is
keyed by name alone and would otherwise hand one repository's value to another.
`backend:` and `gcp:` lines written as YAML are reported with the supported
form. Project ids and file paths appear in output; values never do.

**Every write to a project a repository named says so before it writes
(#177).** A repository's `.secretless` arrives with the clone, so a value
written there can land in a GCP project other than this machine's. Each command
that writes to such a project prints `In GCP project <id>, named by <file> line
<n>` before its first write: `secret set`; `secret sync`, under its `To:` line;
`import` of a bundle, after every refusal has passed, and the line reporting
the import and the line listing names that do not read back both name the
project; `import <file>` and `import --detect` for `.env` files, once; and
`setup`, on stderr before its first prompt. In a repository whose `.secretless`
names no GCP project, these commands print as before.

**`export` and `import` move a secret store to another machine (#175).**
`secretless-ai export --out <file>.secretless-bundle [--only K1,K2]` writes the
selected names and values, with the `required` flag and description the current
directory's `.secretless` gives them, into one file encrypted under a passphrase
(scrypt, AES-256-GCM). Nothing about the source machine is written. The file is
created owner-only and an existing file is never replaced. `secretless-ai import
<bundle>` on the other machine decrypts it and stores the entries in that
machine's backend. A wrong passphrase, a changed file, or a name that already
exists (without `--force`) is refused before anything is written. After writing,
each name is read back from the store and compared with the bundle. The
passphrase is read from the terminal without echo, or from
`SECRETLESS_EXPORT_PASSPHRASE`, never from an argument, and neither command
prints a value. `export` refuses inside an AI agent runtime, as `env` does,
because a caller that picks the passphrase can decrypt the bundle. Importing a
`.env` file is unchanged; `--force` is refused there, since that path already
replaces names.

**`export` refuses a bad `--out` file name before it asks for a passphrase
(#242).** An `--out` path that does not end in `.secretless-bundle`, or one that
already exists, was checked only after the passphrase was read: in a terminal
the passphrase was typed twice and then refused, and with no terminal and no
`SECRETLESS_EXPORT_PASSPHRASE` the command printed `No passphrase` instead of
the file name error. Both refusals, with their `Fix:` lines, now come first.
The exit code is unchanged.

**`scan`, `scan-staged`, `clean` and `verify` treat a bundle as a secret
(#175).** A bundle holds every secret it was given behind one passphrase that
can be guessed at offline, so these commands now report one where they said
nothing before:
- `scan` reports a `*.secretless-bundle` file by its presence, without reading
  it, as a high-severity `secretless-bundle` finding (Secretless Encrypted
  Bundle), so a tree holding one now exits 1.
- `scan-staged` blocks a commit that stages a file ending in
  `.secretless-bundle`, as it blocks a private key file.
- `clean`, the Stop hook and `watch` redact a bundle printed into a transcript
  as `[REDACTED:secretless-bundle]`.
- `verify` counts such a bundle in one of the five most recent transcripts as a
  credential exposed in a transcript, so it prints `FAIL` and exits 1 where it
  passed, and `status` counts it among the transcript secrets it reports.

**`clean`, `watch` and the Stop hook redact a secret printed as `NAME=value`
when the value has no vendor prefix (#185).** Process listings and environment
dumps print `JIRA_TOKEN=<hex>` or `MY_SERVICE_TOKEN=<hex>`; no vendor pattern
matches such a value, so it stayed in the transcript. A value of 8 or more
characters assigned to an uppercase name that ends in `TOKEN`, `SECRET`,
`SECRET_KEY`, `PASSWORD`, `PASSWD`, `API_KEY`, `APIKEY`, `ACCESS_KEY`,
`PRIVATE_KEY` or `CREDENTIAL` is now redacted as
`[REDACTED:secret-assignment]`, and the name stays visible. A name that only
contains one of those words (`TOKEN_COUNT=3`, `MAX_TOKENS=4096`,
`GOOGLE_APPLICATION_CREDENTIALS=<path>`) is left alone, as is a value that is a
reference (`$VAR`, `${VAR}`, `$(cmd)`, `<placeholder>`, `process.env.X`) or a
marker an earlier run wrote. A vendor-shaped value is still reported once,
under its vendor pattern. `verify` reads the five most recent transcripts with
the same rule, so it can now fail on such a line: where it printed `PASS` and
exited 0, a recent transcript holding `JIRA_TOKEN=<hex>` makes it print `FAIL`
and exit 1, with `npx secretless-ai clean` as the next step. `status` counts
these values in the transcript secrets it reports, so its count can rise.
`scan` is unchanged.

**`status` reads `~/.claude/settings.json` as well as the project's own
settings, and says which one protects the project (#188).** From a project
with no install of its own, `status` printed "Not protected" even after `init`
had been run from the home directory, whose deny patterns and Stop hook Claude
Code applies in every project. It now reads both files. When only the
user-level file covers the project, the verdict reads `Protected by user-level
settings in ~/.claude/settings.json`, and the deny patterns and Stop hook it
contributes are listed with that path. "Not protected" is printed only when
neither file has the hooks. The guard hook is still reported as not installed
in such a project: `init` wires it as
`"$CLAUDE_PROJECT_DIR"/.claude/hooks/secretless-guard.sh`, which from the
user-level file points at the project's own hooks directory, so it runs there
only after `secretless-ai init` in the project. A user-level file that does not
parse, or that repeats a key, gets a warning and does not count, and deny rules
in a user-level file that wires no Secretless hook do not count either.
`status --json` adds `protectionScope`, `userSettings` and
`transcriptProtection.stopHookScope`.

**`secret push` writes stored secrets to a cloud secret store without the
value on a command line (#235).** `secret push NAME[,NAME2...] --to azure-kv
--vault <name>` writes each named secret from this machine's store to Azure
Key Vault; `--to vault` and `--to gcp-sm` write to HashiCorp Vault and GCP
Secret Manager at the names `secret sync --from` reads. Before this, getting a
stored key into a deployment meant `secret get NAME` passed to a cloud CLI,
which put the value in process listings and shell history. Each value now goes
from the store into an HTTPS request body inside the process. The output names
each entry with the identifier and version written, followed by the command
that references it next (for Key Vault, `az containerapp secret set` with a
`keyvaultref:` URI); a value, a token and the service's response text are never
printed. The Key Vault token comes from the standard Azure credential chain:
`AZURE_TENANT_ID` and `AZURE_CLIENT_ID` with a client secret or federated token
file, then a managed identity, then the signed-in Azure CLI. `--as` gives the
names to use in the target, since Key Vault names allow letters, digits and
`-` only; a name the target cannot hold is refused with the `--as` that fixes
it. A name that is not stored on this machine and a target that cannot
authenticate both stop the push before anything is written, and the first
write that fails stops the rest. A refused token, a vault that does not exist
and a missing role or access policy each exit 1 with `Verify:` and `Fix:` lines
naming the role or command, and nothing is written to another store.
`--dry-run` reports, per name, "would create" or "would add a version" from
metadata alone and writes nothing. A target or store that cannot be opened is
reported in the same layout as the other `secret` subcommands (#247): a blank
line, `Error:` before the first line, and every further line at two spaces.

**`protect-mcp` prints a control character in an MCP env key name as an
escape (#229).** An env key name comes from the client's config file, and
`protect-mcp` wrote it to the terminal as it was in three places: the `Fix:`
line of a refused value, the list of encrypted keys, and a prompt injection
warning. A key such as `X<ESC>[2J_TOKEN` cleared the screen instead of
being shown. A key holding a control character, DEL, a C1 control, U+2028 or
U+2029, a quote or a backslash is now printed quoted, with each such character
written as a `\u` escape, for example `"X\u001b[2J_TOKEN" (encrypted)`. The
first line of a refusal already quoted the key and now escapes DEL, C1
controls, U+2028 and U+2029 as well. An ordinary key such as `GITHUB_TOKEN`
prints as before.

**`secret set`, `import` and `protect-mcp` refuse a value holding a C1
control character (U+0080 to U+009F) (#230).** The stored-value check refused
the escape character 0x1B but accepted U+009B, the one-character form of the
same `ESC [` sequence, so a value ending in an 8-bit `CSI 2 J` was stored. C1
characters are now refused like the other control characters, with the
refusal naming the character (for example `a C1 control character (U+009B)`)
and its position, never the value. U+00A0 and above, including accented and
non-Latin letters, are still accepted.

**Exposed secrets are tracked until they are rotated (#236).** `secret
exposed NAME --where "<note>" [--at <date>]` records `exposedAt` and
`exposedWhere` in the secret's metadata, beside the store and never with the
value. `secret list --needs-rotation` lists every open exposure with its date,
note and recorded provider, and exits 1 while any is open; `--json` gives
`name`, `exposedAt`, `exposedWhere` and `provider` for each. `secret set` with a
value that differs from the stored one, whether typed, piped or read with
`--from-clipboard`, closes the exposure and records `rotatedAt`; the same
value leaves it open and says so, with a Fix line that repeats the form used.
The two values are compared in memory, and no hash of either is kept. When
`clean` or `watch` redacts a value equal to a stored secret, it marks that
secret exposed and prints its name and the next step; the store is read only
when something was redacted, on a `clean --dry-run` too, which `clean --help`
says. A value written by `secret sync`, `import` or `setup` closes or leaves an
exposure the same way without printing which, as `secret --help` says. Every
`secret exposed` usage error exits 2. `status` shows the number of open
exposures with the command that lists them.

**`git-credential` serves a stored token to git over HTTPS, and `doctor` and
`status` report plaintext git credential files (#238).** `git-credential
install --host <host> --name <NAME> [--username <user>]` adds two entries to
`credential.https://<host>.helper` in the global git config: an empty entry,
which stops git asking any helper configured before it (such as `store`) for
that host or handing it the token, and a helper that answers from the secret
store. A port outside 1-65535 is refused: no HTTPS request can reach that
port, so the helper is never asked. No value
is written to any config file, and `git-credential uninstall --host <host>`
removes those two entries, for any host `install` could have written, and
leaves any other helper for the host as it was. Git runs the helper as `git-credential get`, which answers
only HTTPS requests for its host, never for a different user than
`--username` or for a requested username holding a line break or NUL (which a
`url=` username can after decoding), never for a request whose `url=` does not
parse or holds a username whose percent-escapes do not decode (#254), refuses when stdin or stdout is a terminal
without opening the store, and refuses a stored value holding a line break rather than trimming
it; `store` and `erase` write nothing. These protocol calls are not counted by
telemetry. `doctor` now has a Git credentials block, and `status` a row per
finding: `~/.git-credentials`, `~/.config/git/credentials`, `~/.netrc` and a
`store` helper's `--file` with lines that hold a credential (count, line
numbers and hosts, never a user or value; a `.netrc` `default` entry is not
named as a host or provider), and a `credential.helper` set to
`store`, each with Verify and Fix lines. `doctor`'s verdict and exit code
still reflect the shell profile check alone, and `--fix` does not touch these
files. `status --json` carries them as `gitCredentials`, with the Verify and
Fix lines in `gitCredentials.findings`; its `files[].hosts` leaves out a
`.netrc` `default` entry as well, whose password line is still in `lines` (#254). The guard hook and
the deny rules `init` writes now refuse `git-credential get` and `git
credential fill`, which print the token, so `init` adds three deny patterns.

**`scan` names the config files it did not read, and `scan --include-config`
reads them (#190).** `scan` picks config files by name (`config.json`,
`docker-compose.yml`) and source files by extension, so a config-format file
whose name is not on the built-in list, such as `secrets.json`,
`appsettings.json`, `values.yaml`, `app.toml`, `.npmrc` or a `Dockerfile`, was
read by neither. A tree whose only key sat in `secrets.json` scanned to
`total: 0`, exit 0 and `No hardcoded credentials found.`, with no line about
the file. These files are now a declared boundary: the `--json` summary
carries `unscannedConfig` (the count) and `unscannedConfigFiles` lists a sample
of their paths, and the text report names up to ten of them with a `Fix:` line
that runs `scan <dir> --include-config` and a `Scan one:` line for the first.
Like `skippedUnsupported` and `notEntered`, the count does not change the exit
code, because `tsconfig.json` alone would otherwise fail every clean scan; a CI
job that wants it to gate can test it with
`jq -e '.summary.unscannedConfig == 0'`. `scan --include-config` scans these
files with the source-file rules, so a credential in one is a finding and the
scan exits 1. The test-file and ignore rules apply to them as to source files,
and generated lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`
and others) are not counted.

**`summary.skippedUnsupported` no longer counts files `scan` read (#190).** A
config file on the built-in list, such as `config.json`, was read by the config
walk and also counted by the source walk as a file it did not open. It is now
left out of `skippedUnsupported` and `skippedUnsupportedFiles`, so the same
tree can report a lower count than before. A config file off the list is still
counted there, with the reason `config file not on the built-in list
(--include-config)`, as well as in `unscannedConfig`.

**`protect-mcp` refuses an MCP server value that holds terminal escapes or
U+FFFD, the same rule `secret set` applies (#104).** A value in a server's
`env` block containing an escape or other control character, a null byte, or
U+FFFD used to be stored in the vault and the config rewritten to point at it,
so the corruption surfaced only at the server's first request. Every value for
a server is now checked before any is stored. A refusal names the key, the
server, the character and its position, never the value; nothing is stored for
that server, its config file is left as it was, and `protect-mcp` exits 1. Tab,
newline and carriage return are still accepted, so multi-line keys store as
before.

**`init` writes Cursor's and Cline's instructions where those tools document
their rule files.** `init` used to write the Secretless block to `.cursorrules`
for Cursor and to a single `.clinerules` file for Cline. Cursor documents
project rules as `.cursor/rules/*.mdc` files and Cline documents a
`.clinerules/` directory, so in a project with no rule file yet `init` now
creates `.cursor/rules/secretless.mdc` (an always-applied rule) and
`.clinerules/secretless.md`, and it never creates a `.cursorrules` file or a
single-file `.clinerules`. A project that already has one keeps it and the
block is appended there; a Cursor project whose rules live only in
`.cursorrules` gets no `.mdc` file, so in a project an earlier version set up,
re-running `init` leaves the existing file as it is. A Cline project with a
`.cline/rules/` directory and no `.clinerules` gets
`.cline/rules/secretless.md`, and a `.clinerules` directory no longer makes
`init` fail with `EISDIR`. When a path `init` would write through for Cursor
or Cline is a symbolic link or resolves outside the project, nothing is
written for that tool and it is left off the `Configured:` line. `status` now
reads the files `init` writes: an initialised Cursor project used to be
reported as not protected. These are instruction files: nothing enforces
them, and they have no effect unless the tool loads that file. The README's
supported tools table named `.cursorrules` and `.clinerules` and now names the
files `init` creates. The use case `docs/use-cases/protect-my-credentials.md`
said `init` creates `.cursorrules` and showed output `init` does not print; it
now shows the output of a run in a project that Claude Code and Cursor both
use, names the files that run writes, and says which of them is enforced.

**`init` checks Windsurf's rules file the way it checks Cursor's and Cline's.**
`init` wrote Windsurf's instructions straight to `.windsurfrules`: when that
path was a symbolic link, the block was appended to the file the link pointed
at, and a dangling link had its target created, even outside the project. A
`.windsurfrules` directory made `init` fail with `EISDIR`, and Cline and
Aider, which `init` configures after Windsurf, were left unconfigured. When
`.windsurfrules` is a symbolic link or is not a regular file, nothing is
written for Windsurf, it is left off the `Configured:` line, and the tools
after it are still configured. `init` still writes Windsurf's instructions to
`.windsurfrules`.

**`init` names every path it refused, with the reason, a Verify and a Fix
line.** A tool whose rule file path `init` refused just dropped off the
`Configured:` line: in a project whose only rule file was a `.cursorrules`
link to `AGENTS.md`, `init` printed `Configured: none` and
`Already up to date. No files changed.` and said nothing about the link. It
now prints a `Not configured:` block with one line per refused path and its
reason (for example `.cursorrules is a symbolic link (Cursor)`), then
`Verify: ls -ld -- <paths>` and a Fix line for each path, and no longer says the
project is up to date. The exit code is unchanged. The rule file writer now
opens the file without following a symbolic link and checks again, after
opening, that it is the regular file the path names inside the project. A link
put in place of the rule file itself between `init`'s path checks and its write
is refused instead of followed. A link put in place of a directory on the way
can still leave an empty file or directory where it leads; the path is then
refused, and the Secretless block is never written through either. When such a
link leads somewhere `init` cannot write, the path is refused the same way;
`init` used to fail there with `EACCES` without naming it.

**`init` refuses a rule file with more than one hard link, as it refuses a
symbolic link.** A hard link is another name for the same file, and that name
can be outside the project: when `.windsurfrules` was a hard link to
`../outside.md`, `init` appended the Secretless block to `../outside.md`. When
a rule file `init` would append to has a link count above 1, nothing is written
for that tool, and the `Not configured:` block names the path with the reason
`has more than one hard link` and a Fix line that replaces the file with a copy
of itself. The copy goes to a new file that `mktemp` creates beside the rule
file, never to an existing name, and that file is removed again when the copy
fails, as it does for a file the user cannot read. The Verify and Fix commands
put `--` before their paths, so they run as printed for a path that starts with
`-`. `ls -ld`, the Verify line, shows the link count in its second column.
The count is checked on the path before the write and again on the opened
file, so a hard link put in place of the rule file between the two is refused
too. Which links are covered: symbolic links are refused on the rule
files `init` writes for Cursor (`.cursor/rules/secretless.mdc`,
`.cursorrules`), Cline (`.clinerules`, `.clinerules/secretless.md`,
`.cline/rules/secretless.md`) and Windsurf (`.windsurfrules`) and on every
directory on the way to them, and hard links on those rule files. The other
files `init` writes in the project, `CLAUDE.md`,
`.github/copilot-instructions.md`, `.aiderignore`, `.claude/settings.json` and
the hook scripts `.claude/hooks/secretless-guard.sh` and
`.claude/hooks/secretless-output-check.cjs`, are not checked for either kind of
link and are still written through one. The hook scripts are rewritten whole,
not appended to: through a link, the file it leads to ends up holding only the
script. The shell profile in the home directory that `init` copies `export`
lines to, when its output has a `Shell profile fix:` line, is not checked for
links either.

**Output longer than 8192 bytes reaches a Node 20 caller on macOS whole.** The
CLI called `process.exit()` while the end of a long write could still be
queued. On macOS, a Node 20 program that ran `secretless-ai` through
`child_process` then received only the first 8192 bytes: `secretless-ai --help`,
now longer than that, stopped mid-line in its Options section, without the
Supports line or the docs link. The CLI now exits once stdout and stderr have
written everything queued on them; a run with nothing left to write exits at
once, as before. The exit code is unchanged, also when the reader closes the
pipe early.

**`scan` names the same skipped entries and the same `Scan one:` target on
every platform.** The sample of files not opened and directories not entered,
and the `Scan one:` command under each, are the first entries the walk meets,
and the walk took each directory in whatever order the listing came back. Node
returns byte order on macOS and Linux only because its I/O layer sorts; the
order is not documented, and the filesystems themselves return hash order. The
walk now sorts each directory's entries by code point, the byte order of the
UTF-8 name, before visiting them. Output on macOS and Linux is unchanged; it no
longer depends on the listing order, and neither does which files a scan that
reaches the file cap opens.

**`vault scan` and the `vault` help no longer tell you to put a credential on
the command line.** For every finding, `vault scan` printed
`Migrate:  secretless-ai vault register <namespace> --value <value>`, and the
`vault` help example, the `vault init` next steps and the empty `vault list`
hint showed `--value` too. An argument stays in shell history and shows in the
process list. `vault register` and `vault rotate` already read the value from a
prompt, from a pipe or from `--env <VAR>`, so the printed commands now use
those: `secretless-ai vault register openai-proj` prompts for the value, and
`gh auth token | secretless-ai vault register github` reads it from the pipe.
The `--value` entry in the help now says that shell history keeps it, and the
`vault rotate` usage line no longer lists it. `--value` still works.

**The Claude Code guard hook no longer refuses a command because a grep pattern
or a heredoc mentions a secret file.** The hook's Bash arms match command text,
so `grep -c '/\.env(\.local)?$/' src/init.ts`, `grep -c 'eval
"$(secretless-ai env)"' src/setup.ts` and a `cat > notes.md <<'EOF'` that
writes a note mentioning `~/.zshrc` and `.env` were refused as secret reads,
though none of them opens a secret file. The hook now drops the pattern of a
plain grep and the body of a heredoc before it matches, and only when it
understands the whole command: no `$` expansion, backtick, subshell or brace
expansion; only programs that neither run a command nor read file names from
their input (`grep`, `cat`, `head`, `tail`, `wc`, `cut`, `tr`, `tee`, `sort`,
`uniq`, `mkdir`, `echo`, `printf`); and grep options that GNU and BSD grep
parse the same way. File operands are never dropped, so `grep -c x .env`,
`grep -c x < .env` and `cat .env.example` are refused as before. So is any
command that could turn the dropped text back into a filename, such as
`grep -o '\.env' notes.md | xargs cat` or a heredoc that writes `x.sh` followed
by `sh x.sh`. Without `python3` nothing is dropped. The arm for the
secretless data directory still reads the whole command, so
`grep -rn "\.secretless-ai" src` is still refused, as are a `git grep` for
a secret-file token and the `node -e` and `python3 -c` one-liners. Run
`npx secretless-ai@latest init` again to refresh an installed hook.

**The instruction block no longer says that credentials in the conversation are
redacted.** The block `init` writes ended with the line "Credentials in this
conversation are automatically redacted by Secretless AI". That line was wrong.
For Claude Code, a hook runs `secretless-ai clean --last` after each turn; it
rewrites the newest session file in each project directory under
`~/.claude/projects` and replaces values that match known credential patterns.
It does not stop a value from reaching the model or its provider, and no
cleanup is installed for any other tool. The block now says so, under the
heading "Credentials in the conversation". A file written by an earlier version
keeps the old line, because `init` leaves a file that already holds the
`<!-- secretless:managed -->` marker unchanged. To refresh one, delete the
block from the marker line through the end of the "Transcript Protection" list,
then run `npx secretless-ai@latest init`. If a credential value appeared in a
conversation while the old line was in place, rotate it.

**The guard hook lets only `secretless-ai` itself name the data directory.**
The hook's data-directory rule listed reading commands (`cat`, `head`, `awk`
and others), so any reader it did not list passed: a `python3`, `node`, `ruby`
or `perl` one-liner, or a shell redirect such as
`< ~/.secretless-ai/config.json`, read the store's files through it. A Bash
command that names `~/.secretless-ai` or `~/.opena2a/secretless-ai` is now
refused unless the whole command is one `secretless-ai` or `npx secretless-ai`
invocation made of plain words. A command that chains, pipes, redirects or
substitutes, that quotes or escapes a word, or that uses `run` or `vault exec`
to start another program is refused. So is a command that only mentions the
directory, such as `cd ~/.secretless-ai`; the deny reason says so and points
at the Read and Grep tools for source searches. The rule still reads command
text, so it sees the directory only where the command names it, and the
native deny rules are unchanged.

**The Claude Code guard hook refuses process listings that print environments
or full command lines, and a bare `env`, as it already refused `printenv`
(#187).** `pgrep` with `-l` or `-a` (`pgrep -fl`, `pgrep -a`,
`--list-name`, `--list-full`), `ps` asking for the environment (`-E`, or `e`
in a BSD-style first argument such as `ps eww <pid>`), for unlimited width
(`ww`, as in `ps auxww`) or for the command column by name (`-o command`,
`args` or `cmd`), and a command that names `/proc/<pid>/environ` are now
denied, with `pgrep -f <pattern>` (process IDs only) named as the safe form.
`env` followed only by its own options and `NAME=value` assignments, which
runs no command and prints the environment, is denied; `env` as a prefix that
runs a command (`env -u NAME cmd`, `/usr/bin/env node`) is still allowed. A
plain `ps aux` or `ps -ef` is not matched, although it prints the same command
column. The rule reads command text, so it sees `/proc/<pid>/environ` only
where the command names it: a path the shell builds when the command runs,
such as `/proc/self/envi*`, is not matched. Re-run `secretless-ai init` to
refresh an installed hook.

**The broker refuses a repeated JSON member name on `/resolve`, in the AIM
identity response and in its own status reads, as it already did on `/grant`
and in the policy file (#147).** A `/resolve` body that repeats a member name,
at any depth and including a case variant or an escaped spelling, is now
answered `400` with `Duplicate member "<name>"`; before, `JSON.parse` kept the
last copy and the credential was served. If the duplicate-member scanner cannot
be loaded, `/resolve` answers `503` and writes the cause to the broker audit
log instead of parsing without it. An AIM agent response that repeats a member
is read as no agent identity, so a `minTrustScore` or `requireCapability`
constraint denies the request. `broker status` reads a `/status` reply that
repeats a member as unreadable and prints the PID-file status. A PID file that
does not re-serialize to the text the daemon writes, which includes one that
repeats a member, is read as no running daemon, so `broker stop` signals no
process from it.

**`secret set` records what a credential is for, and `secret show` reads it
back without the value (#172).** `secret set NAME --description "..." --meta
key=value` stores a description and any number of metadata fields beside the
value; `--meta` is repeatable, `--meta key=` removes a field, and `set` without
either flag keeps what was recorded, so rotating a value does not erase it.
`secret show NAME` prints the description, the metadata and whether the value
is stored, never the value. `secret list --long` adds descriptions and metadata
to the listing, `secret list --app <name>` lists the entries recorded with
`--meta app=<name>`, and `secret list --json` and `secret show --json` carry the
same fields. Keys are free-form: `app`, `provider`, `scopes`, `tokenTtl`,
`redirectUri` and `expiresAt` are conventions, not a schema. Descriptions and
metadata are kept in plain text in `~/.secretless-ai/secret-annotations.json`,
and `set` refuses one that contains the value or matches a credential pattern,
before anything is stored. `secret rm` removes them with the value. A plain
`secret list` does not read the file and is unchanged. The new flags belong to
one subcommand each, and another subcommand refuses them with exit 2 rather
than ignoring them.

**The OS keychain refusal reaches the user whole, in one layout (#205).**
Under `SECRETLESS_OS_KEYCHAIN=off`, `backend set keychain` printed "Cannot use
keychain backend: macOS Keychain is not accessible" (on Linux, "secret-tool
not found"), so the variable and its Verify and Fix lines never showed; it now
gives the refusal as the reason. `secret list` and `run` printed the same
refusal in two layouts. They, the other `secret` subcommands, and any error a
command does not handle itself now print through one printer: a blank line,
`Error:` before the first line, and every further line at two spaces, where
`run` had pushed the Verify and Fix lines to four. The README now states that
the switch's value is exactly `off`, in lowercase. The release artifact
review's install smoke passes `SECRETLESS_OS_KEYCHAIN` through to the CLI
starts it makes, so the switch holds for any command added to that list.

**The guard hook no longer refuses prose or a template field as a secret
read.** The Bash rule that refuses reading a secret file matched a reader verb
anywhere in a line, even as the end of a longer word, so `sed` was found in
`used ` and `refused `: a heredoc writing notes to a Markdown file, or a commit
message, that went on to name `.env` or `server.key` was refused. It also took
the Go template field `{{.Config.Env}}` for a `.env` file whenever a reader
verb came earlier on the line, as in
`docker ps -q | head -1 | xargs docker inspect --format '{{.Config.Env}}'`.
A reader verb now has to be a whole word, and a secret extension has to end a
path component, which a closing `}}` never does. Real reads are still refused
wherever the shell runs the verb from: `cat .env`, `sudo cat .env`,
`ssh host cat .env`, `if [ -f .env ]; then cat .env; fi`, `/bin/cat .env`, a
`cat .env` line in a heredoc fed to bash, and the compressed, alternative and
suffix-named flavours of the readers: the compressor front ends (`zcat`,
`gzcat`, `bzcat`, `xzcat`, `lzcat`, `lz4cat`, `zstdcat` and their `less`,
`more` and `grep` forms), the grep variants (`egrep`, `fgrep`, `rgrep`,
`ugrep`, `pcregrep`, `pcre2grep`), the awk variants (`gawk`, `mawk`, `nawk`),
and the GNU names Homebrew installs beside the system tools (`gcat`, `ghead`,
`gtail`, `gless`, `ggrep`, `gsed`, `gstrings`), as well as the other
installable programs whose name ends in a reader verb and that print or
transmit a plain file: `lolcat`, `ccat`, `mdcat`, `socat` and `netcat`,
`multitail`, `colortail`, `logtail`, `xtail`, `mdless`, `jless`, `agrep`,
`hgrep`, `cgrep`, `sgrep`, `vgrep`, `pdfgrep` and `zipgrep`. The list is
closed: a reader program the rule does not name is admitted by it, and the
Bash deny rules `init` writes do not name it either. A `\n` or `\t` escape also
starts a word: on a host without `python3` the hook reads the command from the
raw JSON payload, where a line break arrives as `\n`, so a reader verb at the
start of a heredoc line or of a later command line is still refused there, and
`printf 'x\ncat .env' | sh` is
refused too. In the rules for a secret file and `python3 -c`/`node -e`, a `\t`
escape also counts as the space after the verb: without `python3` a tab arrives
as `\t`, so `cat<TAB>.env` and `node<TAB>-e` reading `.env` are refused there,
and `printf 'cat\t.env' | sh` is refused on every host. A tab-separated
`printf` or `awk -F'\t'` that names no secret file is still admitted. The
`python3 -c`/`node -e` rule takes the same path-component ending. Re-running
`npx secretless-ai init` refreshes the hook in an existing project.

**The guard hook admits a write of text that names a secret file, and its
refusal quotes what it matched.** A whole-word reader verb followed by a
secret-file name was refused as a read even inside text being written to a
file: `printf '%s\n' '... the head of process.env.PATH ...' >> notes.md` was
refused because `head` came before `process.env.` on the line. Three write
forms are admitted when they are the whole command: `printf` or `echo` of
single-quoted text redirected with `>` or `>>`, which nothing admitted before,
and `cat > FILE` or `cat >> FILE` fed a heredoc whose delimiter is
single-quoted (`<<'EOF'`), which the command analyzer also admits. The shell
neither expands nor runs that text; it copies it to the file. The target
must be a plain path that is not itself a `.env`, `.key`, `.pem`, `.p12` or
`.pfx` file, `cat` must have no file operand, and the command must hold
nothing else: no pipe, no second command on the first line or after the
heredoc's first terminator line, and no `$`, double quote or second redirect
outside the single quotes. Any other program given the same heredoc,
including `bash`, `zsh`, `command bash` and a name the hook does not know, has
every line checked as before. The hook's other rules still read the whole
command, so a note holding `echo $API_KEY` is refused as before, and without
`python3` the hook checks the whole command as before. A refusal from either
secret-file-read rule now quotes the text it matched, as in
``Matched `cat .env` ``, and stays one JSON document when that text holds a
quote, a backslash or `$(`. Re-running `npx secretless-ai init` refreshes the
hook in an existing project.

**The guard hook refuses printing a secret variable however the command is
spaced.** The rule for `echo` or `printenv` of a secret variable judged only
the text up to the first backslash or letter `n` after the verb, so
`echo -n $GITHUB_TOKEN` and `echo "token: $GITHUB_TOKEN"` were admitted on
every host; it now reads to the end of the command, which still ends at `;`,
`&` or `|`. The rules for `echo` or `printenv` of a secret variable, `eval
echo`, `python3 -c` or `node -e` reading a secret variable, and the
`secretless-ai secret get --force`, `run -- env`, `vault exec -- env` and
`env` commands took only whitespace between their words. Without `python3`
the hook reads the command from the raw JSON payload, where a tab arrives as
`\t`, so `echo<TAB>$GITHUB_TOKEN`, `printenv<TAB>GITHUB_TOKEN` and
`secretless-ai<TAB>env` were admitted there, and `printf 'echo\t$GITHUB_TOKEN'
| sh` was admitted on every host. A `\t` escape now counts as that space. Bare
`printenv` is refused when another command follows it after `;` or `&`, as in
`printenv; echo done`, and without `python3` when it starts or ends a line of
a longer command. `printenv | wc -l`, `echo<TAB>$HOME` and
`secretless-ai run -- envsubst` are still admitted. Re-running
`npx secretless-ai init` refreshes the hook in an existing project.

**The guard hook reads the whole command without `python3`.** Without
`python3` the hook takes the command from the raw JSON payload, and it stopped
at the first double quote there, which is the escaped quote inside the
command. `echo "$GITHUB_TOKEN"`, `python3 -c "import os;
print(os.environ['GITHUB_TOKEN'])"`, `x=""; cat .env` and
`eval "$(secretless-ai env)"` reached its rules as `echo \`, `python3 -c \`,
`x=\` and `eval \`, and were admitted. It now reads the string to its closing
quote, so these commands are refused as they are with `python3`; a refusal
that quotes the matched text shows a double quote as the payload carries it,
`\"`. On every host, bare `printenv` is also refused when a quote follows it
directly, because `printf 'x\nprintenv' | sh` and `sh -c 'cd /tmp;printenv'`
run it, and a quoted name, `printenv "GITHUB_TOKEN"`, is refused like the
unquoted one. A quote after a space opens an argument, so `printenv "PATH"` is
still admitted, and so is a search such as `grep -n 'printenv' src`. Every
decision this changes goes from allow to refuse. Re-running
`npx secretless-ai init` refreshes the hook in an existing project.

**The guard hook refuses a `node -e` read of `process.env` for reading the
environment, not a secret file.** Node names the environment `process.env`,
which ends in `.env`, so the rule for a python or node one-liner that names a
secret file refused `node -e` reading a variable and said it named a secret
file: `node -e 'console.log(process.env.GITHUB_TOKEN)'` was told "reads secret
files", where the same read written in python was told "reads secret
environment variables". With each `process.env` set aside, a one-liner that
still names a `.env`, `.key`, `.pem`, `.p12` or `.pfx` file keeps the
secret-file reason, and one that names a secret variable gets the
secret-variable reason. Any other, such as
`node -e 'console.log(process.env.HOME)'` or one that prints all of
`process.env`, is refused for reading environment variables, and the reason
names `printenv NAME` for a variable that holds no secret. Both
environment-variable reasons now quote the text they matched, as the
secret-file reasons do. No decision changes: each of these commands was
refused before and is refused now. Re-running `npx secretless-ai init`
refreshes the hook in an existing project.

**The guard hook judges a symlinked path by the file it reaches.** The hook's
file rules read only the name a tool was given, so a link named like a
template (`config.env.example -> .env`) was allowed as a template while the
Read, Grep or Edit went through to the real `.env`, and a link with a plain
name (`notes.txt -> ~/.aws/credentials`) matched no rule at all. A repository
can ship such a link. The hook now follows every symlink in the path, in the
parent directories as well as the file itself, and applies the same rules to
the resolved path, template exemption first: a link to a secret file is
refused, and a template-named link to another template is still allowed. A
link that cannot be resolved (its target is missing, or it loops) is refused,
because what it reaches is unknown. A file that does not exist yet, such as
the target of a Write, is still checked under its resolved parent directory.
A path that passes through no link is judged by the name it was given alone,
as before: the resolved path is absolute, and the path-fragment rules
(`secrets/`, `.ssh/`, `credentials/`, a custom `files:` pattern) match
anywhere in it, so a relative path is not judged by the working directory it
is joined to, and a project kept under a directory named `secrets/` still
reads its own `src/app.js` by relative path. A link in such a project is
judged by the absolute path it resolves to, and that path names `secrets/`,
so the link is refused even when it reaches a plain file in the project:
`docs.md -> README.md` is now refused, as the absolute path to `README.md`
always was, while `README.md` by relative path is still read. Read the file
the link points to by its own relative path.
Re-running `npx secretless-ai init` refreshes the hook in an existing project.

**An absolute file pattern in `.secretless-rules.yaml` is enforced, in either
way it can be written.** A `files:` pattern naming an absolute path
(`/srv/app/creds/*.json`) produced a `.claude/settings.json` deny rule with one
leading slash, and a rule path with one leading slash resolves under the
project root: the rule matched `<project>/srv/app/creds/*.json` and never the
file the operator named, so the Read went through. The Read rule is now written
with the `//` root prefix, which names the absolute path. The pattern may also
be written `//srv/app/creds/*.json` directly, and that form used to carry the
second slash into everything that matches a real path — the `cat`, `grep`,
`awk`, `sed`, `strings` and `xxd` command rules, and the generated guard hook's
path globs — where it matched nothing that can exist, leaving the hook, the
layer that refuses the read, silent for exactly the file the rule names. Both
spellings now generate the same Read and command rules: the root prefix in the
Read rule, a single slash everywhere a path or a typed command is matched. The
Grep rule is left as written, so it still carries the second slash for the
`//` spelling. Re-running
`npx secretless-ai init` installs the working rules over an existing project
config and refreshes the hook; the single-slash rule an older version wrote is
left in place, where it matches only a path of that name under the project.

**`run` refuses to start a command whose arguments carry a stored value.**
`secretless-ai run --only DB_URL -- psql "$DB_URL"` used to start psql with
the connection URL as its argument, because the calling shell expands the
reference before `run` starts; a process's arguments are readable by every
local process (`ps`, process monitors, crash reports) for as long as it runs.
`run` now compares the command and its arguments against each injected value
of eight or more characters, verbatim and URL-encoded, and when one matches it
exits 1 without starting the command. The message names the variable, never
the value, and gives the environment shape for the program: `PGPASSWORD` with
host, user and database as arguments (or a `service=` entry) for psql and the
other libpq tools, a header read from stdin with `-H @-` for curl. The new
`--allow-argv` flag, given before `--`, starts the command anyway and prints a
warning that the value is visible in process listings. Values shorter than
eight characters are not checked. The vault guide's curl example now passes
the header on stdin.

**`status` says which files its credential row covers.** The row read `No
credentials in config files` when the project scan found nothing, but the
scan does not read every config file: a project with a key in `values.yaml`
and another in `main.tf` printed that line. It now reads `No credentials
detected in scanned files`, and a finding reads `N credential(s) detected in
project files` instead of `in config files`. The count, the `--json` output
and the exit code are unchanged.

**The Vault Exec description no longer says the agent never sees the
secret.** The README, the `vault` help text and the `vaultExec` type
declaration in 0.23.0 and earlier releases said that the agent, the AI
tool's context and any process listing never see a credential injected by
`vault exec`. That was wrong. `vault exec` sets the value in the child
command's environment and does not mask the child's output, so a wrapped
command that prints its environment or the credential returns the value to
whoever ran it, an AI assistant included; and while the child runs, another
process running as the same user can read its environment. What `vault exec`
does is unchanged in this release; the three texts now describe it. If you
relied on the earlier wording, wrap only commands that do not print the
credential.

**The Vault and GCP Secret Manager backends bound the whole HTTP exchange,
and a request that times out says what to do.** Each request's 10-second
bound used to end when the response headers arrived, so a server that sent
its headers and then stalled the body left `resolve`, `store` and `delete`
waiting for as long as the connection stayed open. The bound now covers the
response body as well, and the request is abandoned and its connection closed
when it passes. A timed-out request used to fail with `This operation was
aborted`; it now names the backend, the method and path (never the address's
userinfo, the token or the value), notes that a timed-out write may still
have been applied, and prints a Verify and a Fix line. A health check that
times out after 5 seconds reports the same on one line.

**`clean` names the transcript lines it did not read.** A transcript line
longer than 51200 characters is skipped whole, so a credential on it is
neither reported nor redacted. `clean` used to print `No credentials found.
Transcripts are clean.` over such a line; it now prints `No credentials found
in the lines that were read.` and, after any findings, a `Not read:` block
that states how many such lines there are and in how many files, names up to
ten files and up to ten line numbers per file and counts the rest, and ends
with one Verify line, for the first file named, that lists its over-length
lines and their lengths. The exit code is unchanged. `cleanTranscripts`
returns every such line to library callers as `linesNotRead` and
`totalLinesNotRead`.

**The guard hook no longer reads an environment accessor in a search pattern
as a secret file (#119).** `grep -c "process\.env" app.ts`, and the same
search for `import.meta.env` or `Deno.env`, was refused as a secret-file read
because the accessor contains the `.env` token. An accessor is now exempt
from the Bash file-read check only as the pattern of `grep`, `egrep`, `fgrep`
or `git grep`: the first word after options that take no argument, or the
word after `-e`. A file called `process.env` is a `name.env` file, so the same
text as a file argument or under another command (`grep API_KEY process.env`,
`grep -f process.env src`, `cat process.env`) still blocks, as does a real env
file in the same command (`grep -rn "process.env" .env.local`). The exemption
is withheld from any command carrying `;`, `&`, `>`, `<`, `$` or a backtick,
from one that pipes into anything but `head`, `wc`, `sort` or `uniq` with
options only (`grep -o "process.env" README.md | cut -c8- | xargs cat`
rebuilds `.env` from grep's output), and from one with options or quoted
words after the pattern. The committed-template over-block
(`grep API .env.example`) is unchanged, for the reason given in the hook's
note on template files.

**`secret sync --from <backend>` seeds this machine's store from a shared
backend by name (#176).** `secret sync --from 1password` (or `vault`,
`gcp-sm`, `keychain`, `local`) copies the required names of `./.secretless`,
the names given with `--only K1,K2`, or the required names of
`--manifest <file>`, into the configured store. Each name is read from the
source by its own key, so a source token that can read entries but not list
them still syncs. A local value that differs is left as it is and reported as
a conflict unless `--force` is given; a name in neither store, a conflict and
a read or write failure each exit 1 and are named. `--dry-run` reports what
would be created, updated or left alone and writes nothing; like the real run,
it exits 1 for a name in neither store, a conflict or a read failure, but a
write that would fail is found only by the real run. The source is checked for
health before any entry is
read, an unreachable source is reported as the source rather than as the
configured backend, values are never printed, and the source is read without
the cache layer,
whose file is keyed by name alone and would otherwise serve the shared value as
the local one. `setup --check` now names `secret sync` when required names are
missing. The sync flags are refused on the other `secret` subcommands, so
`secret set --dry-run` cannot store the value it was asked to preview. Its
errors print in the same layout as the other `secret` subcommands (#233): a
blank line, `Error:` before the first line, every further line at two spaces,
and for an unreachable source the Verify line inside that block.

**`mcp-status`, `protect-mcp`, `mcp-unprotect` and `doctor` name every file
they could not read or parse instead of reporting it as clean.** `mcp-status`
skipped an MCP config it could not parse, so a Cursor config holding a
plaintext token behind one trailing comma printed "No MCP configurations
found." Each such config is now listed under its client and path as `? not
checked:` with the reason (`not valid JSON (line 4, column 3)`, `could not be
read (EACCES)`, `not a JSON object`), followed by a count and a Fix line. The
reason gives a position only and never quotes the file, because the JSON
parser's own message can quote the text around the error. `protect-mcp` and
`mcp-unprotect` passed over such a config without naming it, so `protect-mcp`
could print "Already clean." beside a config it never read; they now list it as
`? not checked:` and `? not restored:` with the same reason, count and Fix
line, and the `protectMcp()` result carries the list as `unparsed`. A config
whose top level is `null` no longer makes `mcp-status`, `protect-mcp` or
`mcp-unprotect` fail with a TypeError: each of them exited 1 on such a config
and now exits 0. `doctor` listed a shell profile it could not read as "no keys"
and could still print "HEALTHY: All keys correctly configured"; the profile is
now marked `could not be read (<code>), not checked`, the verdict says it
covers only the profiles that were read, and a `Not checked:` line names each
file with a Fix line. The `doctor` health value is unchanged, and so are the
exit codes of these commands outside that `null` case; a profile in the library
`doctor()` result carries `readError` when it could not be read.

**`scan` no longer calls a directory it reported a finding from "not entered"
(#254).** The block listing directories the scan did not descend into named
`.github` as "not entered" beside a finding from
`.github/workflows/config.yml`. That block lists where source files were not
read, so it is now headed "directories not entered for source files". Of the
directories it gave the reason "hidden directory", one an ignore rule covers,
such as `.golden/` on the default list, is entered by no walk, and its reason
is now "ignore rule (--no-ignore)", in `notEnteredDirs` under `--json` too; the
others keep the reason "hidden directory". Which files are read is unchanged.

**`scan` names every file it did not open, even when no directory was
skipped.** The count of files not opened was printed only inside the
"directories not entered" block, so a directory whose only boundary was a file
of an unsupported type printed "No hardcoded credentials found." with nothing
beside it: an AWS access key id in `notes.txt` was never read, and the report
did not say so. Files not opened now have their own block, listed with the
reason each was not opened, followed by a `Scan one:` command that names a
file, because naming a file scans it whatever its type. A control character
in a listed name is shown as a visible escape, and such a name is never
offered as the command. What the scan detects, the exit code and the `--json`
output are unchanged. `--help` lists scanning a single file under Scan
Coverage.

**`SECRETLESS_OS_KEYCHAIN=off` refuses every call to the OS credential-store
CLIs.** Set `SECRETLESS_OS_KEYCHAIN=off` to refuse every call to the macOS
Keychain and Linux Secret Service CLIs; reads and writes through those backends
then fail with an error instead of prompting, and nothing is read from or
written to another store. The value is compared exactly: any value other than
`off` changes nothing. The refusal is made in the one module that starts the
`security` and `secret-tool` children and the availability probes, so
`/usr/bin/security`, `secret-tool` and the `which secret-tool` probe are
never started, and the error names the variable with a Verify and a Fix line.
The test suite sets it in every worker; a CLI child started from a copy of
the worker's environment inherits it.

**The docs URL the tool prints now points at the page that exists.**
`--help` and the header written into a new `.secretlessignore` cited
`https://opena2a.org/secretless-ai`, which is a 404; both now cite
`https://opena2a.org/secretless`, the live docs page the README already
links. No other output changes; the GitHub repository links
(`github.com/opena2a-org/secretless-ai`) are the repository's real name
and are unchanged.

**The macOS Keychain backend hands the value to `security` on stdin, runs
`/usr/bin/security` by absolute path, and every backend child call is bounded
in time.** `secret set` on the keychain backend now writes one
`add-generic-password` line to the stdin of `/usr/bin/security -i`, with the
value carried as `-X` hex, so the child's argument list is the constant `-i`
whatever the value is; it used to pass the value as `-w <value>` on the command
line. Each store is followed by a read-back compare, and a write that reported
success without landing is a thrown failure. A name holding a line break, an
empty value, and a value too long for one `security` line are refused by name
before any process starts. `security` is run by its absolute path from the
backend and from the factory's availability probe, so a program of that name
earlier on PATH never runs. Every child the keychain, Secret Service and
1Password backends and the factory start now has a 30-second bound; a child
that does not return in time is ended and the call fails with a Verify and a
Fix line, where it used to wait for as long as the child did. A failure
message from `security` carries neither the value nor its hex form, and a
value read back from the keychain keeps its own trailing whitespace. The
`keychain-macos` and `keychain-linux` backends' tests now run their real child
process path against a recorder program on Linux.

**`broker start`, `watch start` and `warm` no longer report a service running
that has already stopped (#132).** `broker start` and `watch start` run the
broker or the watcher in the foreground, as their help says, until Ctrl+C or
SIGTERM. Before, both printed that the service was running, and printed its
PID, then exited, which ended the service. `broker status` and `watch status`
then said it was not running. `watch start` now exits 1 and says the watcher
did not start when there is no transcript directory to watch, instead of
printing "Press Ctrl+C to stop" and exiting 0. `warm` now starts the broker in
a separate background process and reports `Broker: started` only after that
process answers on its port. Before, it started the broker inside its own
process, which ended when `warm` exited.

**Three commands no longer report a clean result over work they did not do
(#125).** `status <dir>` and `verify <dir>` on a directory that does not exist
now print `Directory not found: <dir>` on stderr and exit 1, the same as
`scan`. Before, both printed a clean verdict (`verify` printed PASS) and
exited 0, so a typo in a CI path produced a green check over nothing.
`scan-staged` outside a git repository now says `Not a git repository` and
exits 2, the same as `diff`; before, it printed nothing and exited 0, which
reads the same as "staged files scanned, nothing found". An empty index inside
a repository still exits 0. `scan --min-confidence <n>` now reports what the
filter removed: the `--json` summary carries `minConfidence` and
`confidenceSuppressed`, and the human report says how many matches scored
below the threshold and prints the command that shows them. When the filter
hid every match, the report reads `No credentials found at or above confidence
<n>.` instead of `No hardcoded credentials found.` The filter still does not
set the exit code, the same as placeholder suppression, because the user asked
for it.

**`secretless-mcp` reports its version, and refuses a server name it has no
secrets for (#138).** `secretless-mcp --version` (or `-v`) prints
`secretless-mcp <version>` and exits 0; it printed the usage line and exited
1. `protect-mcp` runs MCP servers through a copy of the wrapper under
`~/.secretless-ai/bin`, which does not update when the package does, so the
copy now records the version it was copied from and reports that one. A
`--client`/`--server` pair with no secrets in the vault now exits 1 without
starting the server, names the pair and the backend it read, and lists the
pairs that are stored (names only). It started the server with none of its
credentials and printed nothing. `protect-mcp` wraps only servers it moved a
secret out of, so a pair it wrapped always has secrets. Arguments after `--`
now always reach the server: a server started with `-h` or `--help` among its
own arguments got the wrapper's usage line and exit 0 instead of starting.
The new `--version` and `-v` are read the same way, before `--` only.

**The credentials rule is keyed on the credential store, not on the word
`credentials` anywhere in a path.** The generated guard hook matched the bare
fragment `credentials`, so it denied any file that merely NAMES the subject —
including this project's own use-case page,
`docs/use-cases/protect-my-credentials.md`, which was the single tracked file in
the repository the hook we generate would refuse to open, and which holds no
credential. It is now `credentials/`, the store form `SECRET_FILE_PATTERNS` in
`patterns.ts` already used and that the hook's list had drifted from by one
slash. The native `.claude/settings.json` deny rule had the same shape and is
narrowed the same way: `Grep(credentials*)`, a prefix glob that denied a
project-root `credentials-guide.md` to the Grep tool, is now
`Grep(credentials/*)`. Nothing that protects a real store moves —
`credentials/prod.json`, `~/.aws/credentials`, `.aws/credentials` and
`.git-credentials` are all still blocked, the last by the unchanged
exact-basename dotfile rule. Note for existing projects: an older
`.claude/settings.json` keeps its previously written `Grep(credentials*)` line,
since `init` prunes only the rules listed in `DEPRECATED_DENY_RULES`; remove
that line by hand to pick the narrowed rule up.

**Two Bash deny messages that can fire on a search pattern now say so and name
the way forward.** `Secretless: blocked script command that reads secret files`
and `Secretless: blocked access to secretless data directory` were single-clause
refusals, but both arms match command TEXT and so also fire on commands that
only DESCRIBE the shape they search for — `node -e "re = new RegExp('\.env')"`,
`python3 -c "import re; re.compile(r'\.pem')"`, `grep -rn "\.secretless-ai" src`
— none of which opens a secret. Those commands are still denied (exempting the
token is a credential bypass; see NOTE ON TEMPLATE FILES in `init.ts`), but each
reason now states that the guard cannot tell a filename from a search pattern
and names the Read tool and the Grep tool as the sanctioned route, matching the
secret-file arm that already did.

**A broker policy rule can carry notes under `x-` keys (#143).** Since 0.22.1 a
`comment` or `description` on a rule stops the broker from starting; that
refusal stands, and it now names the spelling that loads. A rule key that
starts with `x-` and holds a string, such as `"x-comment": "nightly scanners"`,
is accepted and does not affect the rule. It is accepted on a rule only: on the
file's top level, inside `constraints` or inside a constraint it is refused. An
`x-` name that resembles a rule field or a constraint (`x-constraints`,
`x-effect`, `x-agent-selector`, `x-timeWindow`) is refused and the error names
the field, because a note that reads like a restriction would look applied
while restricting nothing. Notes are dropped at load and do not appear in
`getRules()`, `/status`, `broker status` or the audit log.

**The session-check PreToolUse hook (`secretless-ai hook --check-only`) now
denies instead of advising.** This hook is registered by hand in the Claude
Code hooks config; `init` installs only `secretless-guard.sh`, which is
unchanged. On an expired or tampered session the command exits 2 and prints
the PreToolUse deny JSON
(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}`)
on stdout with the reason on stderr, so Claude Code blocks the tool call
instead of letting it proceed past a warning. Previously the hook exited 1
with a message on stderr only, which the hook contract does not treat as
blocking: the session gate could not gate. A session file whose HMAC is
missing or does not match its content (tampered) now also denies. Before, a
mismatch was treated as "never installed" and passed silently, and a file with
the HMAC field removed was accepted as a valid session. On an expired session
with the broker daemon not running, the deny reason names
`secretless-ai broker start` before `secretless-ai warm`; a tampered session
names `secretless-ai warm` only. When no session file exists at all the hook
still passes with exit 0 and no output: users who never set Secretless up are
not blocked. This hook is a gate on the assistant's tool path, not a security
boundary.

**`secretless-mcp --help` prints its usage and exits 0.** Previously `--help`
and `-h` were treated as bad arguments and exited 1, which the new release
artifact review's install smoke (every bin must answer `--help`) caught.

**A `.secretless-rules.yaml` line the parser cannot read is now reported, and
`rules list` and `init` exit 1 over it.** Previously a top-level key the parser
did not recognise — `file:` instead of `files:`, `Files:`, `envs:` — silently
discarded every pattern under it, flow syntax (`env: [ACME_*]`) and zero-indent
list items vanished the same way, and the loader still reported the file as
loaded (or empty) with no diagnostic. The deny rules were generated without
those patterns and `init` exited 0: a restriction you wrote, reported as
loaded, that did not restrict. Unknown keys now get a nearest-match hint
("did you mean \"files\"?") but are never auto-corrected, every dropped pattern
is named with its line number, and the sections that were read still load. Two
adjacent holes closed with it: a section line the parser cannot read — inline
content, stray spacing like `files :`, an invisible character — no longer lets
the items below it attach to the previous section (a file pattern misread as an
env pattern generated deny rules you did not write), a rules file refused for
unsafe pattern characters no longer configures nothing while `init` exits 0,
and the problem is reported even when Claude Code is not among the configured
tools.

### Security

- On the gcp-sm backend a read for one MCP server returns only that server's
  secrets, and a server with none stored gets none; an MCP secret is stored
  under a name derived from its client, server and env name, so two servers
  with the same env name never share or overwrite a secret. Servers protected
  on gcp-sm before this release must be protected again: run mcp-unprotect,
  then protect-mcp.
- gcp-sm: a store, delete or read by a plain key refuses when the secret
  carries the store-key label, so it never reaches a secret held for an MCP
  server.
- gcp-sm: a plain read, a store to an existing secret and a plain delete first
  read the secret's labels. That read needs `secretmanager.secrets.get`
  (Secret Manager Viewer, grantable on the one secret) besides Secret
  Accessor; a principal with Secret Accessor alone is refused with the Viewer
  hint, and no value is read.
- gcp-sm: an MCP key whose segment starts with U+FEFF decodes back to itself
  and keeps its server binding.

### Fixed

- The size `scan` prints for a file skipped for size reads as larger than the
  cap. Both figures were rounded, so a 1,052,708-byte file over the 1 MB
  source cap printed `(1.0 MB, cap 1.0 MB)`. When the rounded figures would
  not show the file as larger, both are now exact byte counts:
  `(1,052,708 bytes, cap 1,048,576 bytes)`.
- `scan` opens source files whose extension is upper case (`Legacy.JS`,
  `main.PY`). The source matcher compared extensions exactly, unlike the key-file
  and config matchers, so those files were never read (#120).
- `scan` recognises a real env file whatever the case of its name
  (`.ENV.STAGING`, `.Env.Production`). Only the template marker was compared
  case-insensitively, so templates were rejected in any case while real files
  were recognised only in lower case (#120).
- `scan` reports `truncated` only when a candidate file was dropped at the file
  cap. A tree of exactly `--max-files` files plus an empty directory reported
  "Scan incomplete" and exited 1 with nothing unscanned (#120).
- A value flag given twice (`scan --max-files 10 --max-files 20000`,
  `run --only A --only B`) is refused with both values named. The first value
  used to win and the second was dropped silently (#120).
- `scan` run from the filesystem root prints absolute paths in its coverage
  warnings and their `Verify:` and `Fix:` commands. The path relative to `/`
  dropped the leading slash (`private/tmp/app/big.js`), which runs only from
  `/` and reads as a path under the current directory (#120).
- `--help` names the third layer that keeps a directory out of a scan. The
  `--no-ignore` entry now says dependency and build output (`node_modules/`,
  `dist/`, `build/`, ...) is still not entered and can be scanned by its path,
  and Scan Coverage lists `scan dist`. It described only `.secretlessignore`
  and the default-ignore list, so `--no-ignore --include-tests` read as full
  coverage (#136).
- The broker's policy selector matcher (`matchGlob`) no longer backtracks
  exponentially on a failing match. It compiled `*` to a regex quantifier, so a
  selector with several wildcards let a requester-supplied value stall the deny
  loop (`"*a" x 10` against forty characters took seconds; `x 14` did not
  return). It now matches with two cursors, bounded by selector length times
  value length, with the same `*` and `?` semantics (#141).
- The broker's `PolicyEngine.getRules()` returns rules that share no object
  with the engine. It copied each rule shallowly, so the returned `constraints`
  was the object `evaluate()` reads, and deleting `minTrustScore` from it turned
  a denying policy into an allowing one (#145).
- The Linux Secret Service backend no longer reads a locked or unreachable
  keyring as an empty one. Every `secret-tool lookup` failure was taken as
  "not found", so a locked collection, a dismissed unlock dialog, a timed-out
  lookup or a session with no Secret Service made `resolve` return nothing and
  `run` inject nothing, with exit 0. `secret-tool` exits 1 and prints nothing
  both for an absent entry and for an entry in a locked collection, so a silent
  miss is now checked with `secret-tool search` on the same attributes, which
  lists a locked entry without opening an unlock dialog. Only a miss that the
  search confirms is absence; anything else is an error that names the secret,
  never its value, and gives a read-only command that shows whether the
  default collection is locked (#130).
- `<command> --help` and `<command> -h` print that command's usage and the
  options it accepts. Every command used to answer with the full global help,
  so `migrate --help` named neither `--from` nor `--to`, the two flags the
  `migrate` error for an unknown option lists before it says
  "Run `secretless-ai migrate --help` for usage." A subcommand asks its
  command, so `broker start --help` prints the `broker` help. Bare `--help`,
  no argument, and an unknown command still print the global help, `setup`
  and `env` still print their own, and `--help` still runs nothing.
- `doctor` lists every export of a secret-looking name in each shell profile
  (`JIRA_TOKEN`, `DB_PASSWORD`, `CLIENT_SECRET`), with its name and line number
  and never its value. It only looked for a fixed list of provider key names, so
  a profile exporting any other secret read as "no keys" and the verdict was
  HEALTHY. A secret written out in plain text under such a name is now a
  warning, with `secretless-ai secret set NAME`, the line to remove and a
  `Verify:` command that prints the line number and never the value, and the
  verdict is DEGRADED (exit 1). A value fetched when the shell starts
  (`$(gh auth token)`, `"$OTHER"`) or a file path (`~/keys/signing`, and a
  path starting with `/`, `./` or `../`, quoted or not) is listed but not
  reported, and it is not an API key: when the profiles hold only such exports
  and no known key is set or exported, `doctor` still reports "No API keys
  found in env vars or shell profiles" and BROKEN (exit 1). `--fix` still
  copies only the known key names (#186).
- The README and the `scan` line of `--help` said a scan covers config files
  and source code. A directory scan checks source files by extension, key
  files, and the config files it recognizes by name; it does not open other
  files, such as `values.yaml`, `main.tf`, `.ipynb` notebooks, GitHub Actions
  workflows other than one whose file name is a recognized config name (such
  as `.github/workflows/config.yml`), or most `.md` files. Both now say so. No
  release through 0.23.0 opened these files either, so a clean result from one
  did not cover them.
  `scan --include-config` reads config-format files outside dot-directories,
  such as `values.yaml` and `main.tf`. From 0.21.1 on, naming a file scans it:
  `npx secretless-ai scan deploy/values.yaml`. Through 0.21.0, `scan` did not
  read a file named on the command line, so a clean result did not cover that
  file either (fixed in 0.21.1).

### Changed

- `resolve(path, { exact: true })` returns `{ [path]: value }` when an entry
  is stored under exactly `path`, and `{}` otherwise, on every backend. The
  macOS and Linux keychains, 1Password, Vault and GCP Secret Manager read no
  other entry's value for it; the local store is one encrypted file and is
  decrypted whole for any read.
- `broker start` serves `POST /resolve` only when it loads a policy file: the
  one `--policy-file` names, or `~/.secretless-ai/broker-policies.json` when
  that file exists. A broker that loads no policy file builds no credential
  resolver and answers 404 on `/resolve`, where it answered 403 to every
  request. A `--policy-file` that names a missing file refuses the start,
  where it started a broker with zero rules. The new `--no-resolve` keeps
  `/resolve` off when the default policy file exists, and is refused together
  with `--policy-file`. `broker start` prints a `Grants:` line and a `Resolve:`
  line in place of `Policy file:`, each saying whether the route is on and what
  decided it.
  `broker start` prints the token file, the grant file and the assertion
  public key as rows of the block under `Broker is running.` (`Token file:`,
  `Grants:` and `Public key:`), where it printed them as lines above the
  block.

- `startDaemon` no longer prints the token file, grant file and public key
  lines. A library caller reads the grant file path, the two counts, the public
  key path and the new-key flag from `getStatus().routes.grant.source`. The
  token file path is the caller's `tokenFile`, or, without one, the new
  `BROKER_TOKEN_FILE` export.

- `PolicyEngine` and `BrokerServer` no longer accept a caller-supplied
  enforcement path. `new PolicyEngine({ rateLimiter })` and
  `new BrokerServer(config, { policy })` now throw a `TypeError`: the engine
  always enforces the `rateLimit` constraint with its own limiter, and the
  server always builds its engine from `config.policyFile`. The supplied
  limiter or engine replaced the decision itself, so one that always allowed
  removed the policy's limits while the policy still reported as loaded. The
  CLI never passed either option. Library callers remove the option, and set
  `config.policyFile` to choose the server's policy (#146).
- The instructions `init` writes into `CLAUDE.md` and the other tools' rule
  files state that command output is not guarded. A command that returns
  credential values (`aws secretsmanager get-secret-value`,
  `kubectl get secret -o yaml`, a provider API) puts them into the
  conversation, and no layer checks it. The README says the same under
  "What the guard cannot see". Existing installs keep their block until it is
  removed and `init` is run again (#129).
- `KNOWN_CONSTRAINT_KEYS`, `KNOWN_RULE_KEYS` and `KNOWN_ENVELOPE_KEYS` from
  `secretless-ai/dist/broker/policy` are read-only views, not `Set` instances.
  They were the sets the policy loader consults, so
  `KNOWN_CONSTRAINT_KEYS.add('minTrustScoree')` loaded that typo as an
  unconstrained allow in every `PolicyEngine` in the process, and the same call
  on the other two let a misspelled `constraints` container load unconstrained
  and a file's `denyRules` be dropped. The loader now reads private sets.
  `has`, `size`, `forEach`, `keys`, `values`, `entries` and iteration behave as
  before; `add`, `delete` and `clear` are gone, `Set.prototype.add.call` on a
  view throws a `TypeError`, and `instanceof Set` is now false (#148).

### Added

- `BrokerServer` accepts `resolver: null` and then serves no `POST /resolve`:
  it builds no credential resolver, reads no policy file, and refuses
  `config.policyFile` with a `TypeError`. `/health` gains `grantServed` and
  `resolveServed`; `/status` gains `routes`, one entry per capability route
  with what turned it on (`source` for `/grant`, `policyFile` for `/resolve`)
  or why it is off (`reason`: `noPolicyFile` or `disabled`). The dependencies
  `resolveOff` and `grantSource` carry those facts to the server, and each is
  refused with a `TypeError` beside a dependency it contradicts.

- `init` installs a PostToolUse hook for Claude Code,
  `.claude/hooks/secretless-output-check.cjs`, wired to Bash. It reads a
  command's output after the command runs and, when the output matches the
  credential catalog, warns the user and tells the assistant to treat the value
  as exposed. It names the pattern and never repeats the value. The PreToolUse
  guard decides on the command text, so a command that fetches credentials
  (`curl -H "Authorization: Bearer $TOKEN"` against a config endpoint) passed
  it and its output reached context unread. This is detection after exposure,
  not prevention: the value is already in context when the hook sees it, and a
  format outside the catalog passes unflagged. Run `init` again to add it to an
  existing install (#129).
- `secret set NAME --from-clipboard` stores a key copied from a web page
  without it reaching the command line, the screen or shell history. The value
  is read through `pbpaste`, `wl-paste`, `xclip`, `xsel` or `Get-Clipboard`
  over a pipe and only its length and character classes are printed. After the
  value is stored the clipboard is cleared, unless it changed since it was read
  or `--keep-clipboard` is given. An empty clipboard or a missing clipboard tool
  stores nothing and exits 1 with a `Fix:` line. The flag is refused together
  with `NAME=VALUE` or piped stdin (exit 2). `secret set NAME` on a terminal
  now prompts with input hidden, drops bracketed-paste markers and handles
  Backspace, and Ctrl-C at the prompt stores nothing and exits 130 (#234).

## [0.23.0] - 2026-08-19

The tool does what it says. Every change here is a case where a command accepted
something, did something narrower or different, and reported success.

**Read these three before you upgrade.**

**1. `--json` on a command that does not implement it now exits 2.** It is
implemented by `scan` and `status`. The other 30 commands accepted it and
ignored it: 15 did nothing with it, 11 mistook it for a subcommand, and 4
mistook it for a path. The last group is why this is not a tidy-up — `verify
--json` resolved `--json` as the project directory and printed `AI context:
clean (no credentials found)` for a directory whose `CLAUDE.md` held a live key.
If you pass `--json` to anything other than `scan` or `status`, that call now
fails instead of returning human text at exit 0.

**2. `scan`, `scan-staged` and `scan-history` now refuse an unrecognised flag
instead of warning and continuing.** `scan --nosuchflag` on a clean tree changes
from exit 0 to exit 2; on a tree with findings, from 1 to 2. `scan` is the most
used command in this tool and this is a CI-visible change to it. The reason is
that warn-and-continue produced `No hardcoded credentials found.` — the
strongest clean claim the tool makes — over a scan whose scope you asked to
change and did not get. `scan-staged` is the pre-commit gate and had no
machine-readable channel at all, so an exit code was the only signal it had.
`feedback` and `diff` still warn, since they report no verdict.

**3. `PolicyEngine.loadPolicies()` is now `async`.** Only relevant if you use
this package as a library rather than a CLI. `const n = engine.loadPolicies()`
becomes `const n = await engine.loadPolicies()`. An un-awaited call leaves the
engine holding zero rules, which is default-deny.

**In the same area:** `PolicyEngine.loadRules()` now validates what it is handed,
the same way rules read from the policy file are validated. It used to validate
nothing, so a caller that parsed its own rules skipped every check the file
loader performs. It now throws on an unknown or misspelled constraint key
(`timeWindoww`), on a constraint this build does not enforce (`scopeCheck`), and
on a rule carrying any key outside the five a rule may hold — annotation keys
such as `description` are deliberately not tolerated, for the same reason they
are refused in a policy file. It also no longer keeps a reference to the object
you passed: mutating your own rule after the call used to change the engine's
decision. Narrowing what a shipped method accepts is a breaking change; on 0.x
it rides this minor.

### Security

- **A duplicated key in a broker policy file no longer decides the rule.**
  `JSON.parse` keeps the last of a repeated member name and resolves it before
  the loader is given anything to inspect, so a rule whose text read
  `"effect": "deny"` then `"effect": "allow"` loaded as an allow — and the rule
  count, `getRules()` and `/health` all reported the operator's rule as loaded.
  The restrictive half was gone and nothing said so. The same shape applied one
  level out: a file carrying two `rules` arrays loaded only the second, so
  appending a deny block below an existing one produced a policy containing
  neither the deny rules nor any indication they had been dropped.

  Duplicating a key that the loader *does* know also defeated the checks added
  in 0.22.1, because the instance that would have been refused is the instance
  that disappears: a duplicated `constraints` hid an unknown-constraint
  refusal, a duplicated `rateLimit` hid the sub-key refusal, a duplicated
  `requireCapability` hid the empty-capability refusal, and a duplicated
  `effect` hid effect validation.

  A duplicated member is now refused at every level of the file, on the raw text
  before parsing. Names are compared after JSON escape decoding and case
  folding, so a colliding member spelled as an escape sequence or a case variant
  is caught too — worth knowing, because such a spelling survives a `grep` and
  a diff review while `JSON.parse` still collapses it. Tracked as #140; the
  limitation was disclosed in GHSA-4x65-2hwf-fwpm and is now closed.

  This statement is scoped to duplicated member names and to nothing else.

- **`status` no longer reports zero deny patterns for a settings file whose keys
  collide.** `.claude/settings.json` is read by Claude Code, and Claude Code keeps
  the last copy of a repeated key. A file whose `permissions` block appears twice
  therefore has every deny pattern in the first copy dropped -- in the editor, not
  here -- for as long as the duplicate has existed. `status` reported that as
  `denyRuleCount: 0` with nothing else set, byte-identical to a project that
  configured none, and printed a green check beside it. It now names the repeated
  key and says the patterns cannot be read as configured.

  **Contract change:** `denyRuleCount` is now `number | null`. It is `null`
  whenever the count was not measured -- a settings file that would not parse, and
  one whose keys collide. A number implies a measurement, and `0` over a file we
  could not read is a parse artifact. A consumer testing `denyRuleCount > 0` is
  unaffected; one testing `=== 0` is not. The two unknown states are
  distinguishable in the JSON: `settingsUnreadable` and `settingsAmbiguous`.

  Scanned on the raw text with the same check the broker policy loader uses, so a
  collision spelled as a JSON escape or a case variant is caught too. Measured
  against 36 real-world config files with no false positives.

- **A `/grant` request no longer reports a broker-side fault as your mistake.**
  One `catch` covered both the load of the duplicate-member scanner and the scan
  itself, while its comment named only the parse — so a scanner that failed to
  load returned `400 Invalid JSON` to every caller, blaming each request for a
  security module that was silently absent. The two are now separate, and a
  scanner that will not load is reported as a broker fault, logged, with grant
  requests refused rather than answered.

### Fixed

- **`cache` and `backend` refuse a subcommand they do not recognise** instead of
  printing their status page at exit 0. `backend purg` — a near miss of the
  destructive `purge` — exited 0 with a normal-looking report, and nothing in
  the output or the exit code separated "purged" from "never ran". `telemetry`
  had the same shape with a message: it printed `Unknown action` to stdout and
  returned 0. Running any of these with no subcommand is still an exploration
  and still exits 0.
- **`secret list` refuses an argument** rather than accepting a filter token and
  listing every stored name anyway, byte-identically to the unfiltered run.
- **A near miss of `--json` is no longer suggested by a command that does not
  implement it.** The refusal hid `--json` from its own "Supported:" line while
  suggesting it two lines earlier, and taking the suggestion produced the
  silent mistarget above.

### Added

- **`scan` reports what it did not look at.** Two new non-gating fields in the
  `--json` summary, each with a sample carrying the reason:
  `skippedUnsupported` (files enumerated but not opened) and `notEntered`
  (directories not descended into). Neither changes the exit code — a boundary
  the scanner declared is not a claim it broke, and every repository contains at
  least one, so gating on them would fail every build.

  The case that made this necessary: source files inside dot-directories are not
  scanned, while config and key files inside them are. So a scan could report a
  finding inside `.claude/` while a byte-identical credential in
  `.claude/agent.ts` went unreported, with every coverage counter reading 0 —
  the summary did not merely omit the gap, it corroborated the conclusion that
  there wasn't one. Tracked as #144. This release discloses the gap; changing
  what is scanned is separate work.

## [0.22.1] - 2026-08-12

A security patch. Three defects where the tool did something other than what it
was asked, and reported success: a broker policy that authorized more than the
operator wrote, a credential selector that injected the whole store when it was
spelled with an equals sign, and a redaction that reported a completed removal
over material still on disk.

**Behavior change worth reading before you upgrade.** A command line the tool
cannot bind is now refused with exit 2 instead of being partly ignored. This
affects three shapes: an unrecognised flag on a command that WRITES (`clean`,
`clean-history`, `run`, `backend`, `migrate`, `vault`, `init`, and the rest),
a flag given a value it cannot use (`scan --max-files abc`), and a value-taking
flag given no value at all. Read-only `scan` still warns and continues on an
unknown flag, as it has since #81. If you have automation passing a flag this
tool does not implement, it will now stop rather than run with a scope you did
not choose.

**`--json` is unchanged in this release.** It is still accepted and ignored by
the commands that do not implement it. Making that an error is a consumer-
visible change and belongs to its own release.

**A broker policy file with an unrecognised field now refuses to load, and the
daemon will not start.** This includes documentation keys: a `comment` or
`description` sitting beside `id` in a rule is refused. That is not
hypothetical — it is what one hand-annotated policy file on our own machine
carried, and it is how we found this. The remedy is to delete the key; the
error names it and lists the five fields a rule may carry. An `x-` prefixed
annotation namespace is planned so that notes have a supported home, and it is
deliberately not being designed inside a security patch. The refusal is the
strict direction on purpose: a field we do not read is a field whose meaning we
would be dropping.

### Security

- **The broker authorized more than the policy said.** The policy engine
  silently dropped any constraint it could not type-match, so the restrictive
  half of an operator's rule evaporated and the permissive half survived, while
  `loadPolicies()`, `getRules()` and `/health` all reported the rule loaded.
  A `timeWindow` written with numeric hours instead of `"HH:MM"` strings, or
  `rateLimit.maxPerMinute` as the string `"1"`, produced no constraints at all
  and an unconditional allow. A numeric string is not a hypothetical: it is what
  a YAML-to-JSON conversion, a templating layer or an env-var substitution
  produces. The sharpest case is `minTrustScore: "80"`, where the trust floor
  disappears and any agent matching the selector is served. A constraint this
  build cannot apply is now refused rather than ignored, and a policy file that
  exists but will not validate is a startup failure rather than a warning — a
  daemon warning is a silent failure with extra steps. Affects 0.9.2 through
  0.22.0.

- **The same fail-open was reachable one level up, through a typo.** The check
  above refuses a constraint it cannot apply, but nothing validated a rule's
  top-level fields — so misspelling the container (`contraints`, `constraint`)
  discarded the whole constraint block, and the rule loaded as an unconstrained
  allow with every surface reporting it loaded. Measured with a control: the
  correct spelling plus a closed time window denies; the typo allows. A rule may
  now carry only `id`, `agentSelector`, `credentialSelector`, `constraints` and
  `effect`, and anything else refuses the file.

- **The same silent drop existed at three further levels of the policy file.**
  A pre-tag pass asked one question at every level of operator-authored input
  rather than at the level the last defect turned up, and found: a sibling of
  `rules` in the file envelope (`{"rules": [allow], "denyRules": [deny-all]}`
  loaded the allow set, ignored the deny set, and served the credential); a
  sub-key inside a structured constraint (`rateLimit` read `maxPerMinute` and
  dropped `maxPerHour`, so a cap of 1/hour permitted 3600/hour, and a mistyped
  `End` left a time window open); and an empty value that deletes the
  restriction (`requireCapability: ""` skipped the capability check entirely,
  including its fail-closed no-identity branch, because that branch tested
  truthiness while its sibling tests `!== undefined`). An empty `agentSelector`
  or `credentialSelector` matches nothing, so a deny rule carrying one never
  fired. All refuse now.

- **`scopeCheck` was documented as a deny and could not deny.** It was listed as
  "deny if credential permissions expanded since last baseline", counted among
  the loaded constraints, and advertised in the broker guide — while the
  enforcement path compared an *empty* current-permission list against the
  baseline, so expansion was false for every baseline and the deny branch was
  unreachable. Measured: the same comparison reports an expansion when handed
  real permissions, so the call site was what disabled it. An operator's
  scope-drift gate was inert while every surface reported it enforced. The
  constraint is removed rather than left accepted-and-unapplied: a rule naming
  it is now refused with an error saying this build does not enforce it, so a
  policy that depended on it fails visibly instead of appearing to hold. Real
  enforcement needs live permission discovery in the resolve path and is
  tracked separately.

- **`run --only=NAME` injected every credential in the store.** The parser
  compared `args[i] === '--only'` by exact equality, so the GNU equals spelling
  was an unrecognised argument, silently discarded — and with no selector, the
  child process receives everything. Nothing was printed on stdout or stderr and
  the exit code was the child's. The refusal `env` prints when it detects an AI
  agent runtime recommends `secretless-ai run --only NAME -- <command>` as the
  safe alternative, so the tool's own recommended remedy was defeated by a
  one-character difference in how it was typed. `env --only=NAME`, and `env
  --only` with no value, exported the whole store the same way.

### Fixed

- **`clean --dryrun` performed the irreversible write it was asked to preview.**
  `clean` is destructive by default and `--dry-run` is the only thing that makes
  it a preview; the flag was read with `args.includes('--dry-run')` and nothing
  validated the rest of the command line, so any misspelling silently degraded
  to the destructive path and exited 0. The only signal was a missing "Mode:
  dry-run" line, printed after the file had already been rewritten — and unlike
  `clean-history`, this path writes no `.bak`. `clean-history --dryrun` had the
  identical shape and targets your real shell history, which has no path flag at
  all.

- **`clean --path=DIR` cleaned every transcript on the machine.** The equals
  spelling was unparsed, and the fallback for a missing scope is the maximum
  scope. Measured: a target holding one file, against 9,119 files discovered and
  205 that would have been rewritten in place. The header printed the unscoped
  "Scanning Claude Code transcripts..." with no mention that the `--path` given
  had been discarded. `--path` with no value did the same.

- **`scan --max-files <path>` scanned the working directory instead.** The flag
  consumed the path as its value, leaving no positional, so the scan silently
  retargeted and printed "No hardcoded credentials found." over a tree it never
  opened, with exit 0 and every coverage counter reading zero. The warning named
  the invalid value; nothing said the path had been eaten or named the directory
  actually scanned. A rejected flag value now refuses the run rather than
  falling back to a default you did not ask for.

- **`--min-confidence=`, `--max-files=` and `--max-file-size=` were dropped.**
  Each was warned about as an unknown flag and the scan ran at the default, so
  a raised cap was not raised and a confidence threshold was not applied.

- **Redaction left the tail of a credential longer than its pattern's fixed
  length ([#133](https://github.com/opena2a-org/secretless-ai/issues/133)).**
  The redactors replaced what the DETECTOR matched, and the detector's patterns
  carry fixed quantifiers, so a value longer than the canonical shape kept its
  overshoot — while the output read as fully redacted. This is a remediation
  defect, not a preview defect: `clean` wrote the residue back into the
  transcript and reported the redaction complete, `clean-history` did the same
  to your shell history, and `diff` printed it to stdout under a "REDACTED"
  label with no length cap. The replacement span is now derived from the
  credential rather than from the pattern match, and every write and display
  path routes through the same primitive. Vendors document GitHub, AWS and Slack
  token lengths as variable, so a fixed quantifier is wrong regardless of
  today's value. Listed in 0.22.0 as a known issue fixed in 0.23.0; it is fixed
  here instead.

- **`secretless-mcp` read credentials from the wrong place.** The second
  published bin carried the same parse idiom and had never been swept:
  `--vault-dir=` fell back to the default vault and `--backend=` to the
  configured backend, so the wrapper loaded credentials from somewhere other
  than where it was told to. An empty `--server` or `--client` now refuses
  rather than starting an MCP server with none of the credentials the wrapper
  exists to inject.

  **Migration consequence, if you hand-edited an MCP config.** A wrapper line
  carrying `--vault-dir=/path` was reading the DEFAULT vault and will now read
  the directory you named — which may be empty, in which case the server starts
  without its secrets. The same applies to `--backend=`: it now uses the backend
  named rather than the configured default. Configs written by `protect-mcp`
  use the spaced form and are unaffected.

- **`verify --alll` answered a narrower question than the one asked.** Any
  misspelling of `--all` was resolved as the project directory, so every project
  context file was skipped and the short report was printed as though it were
  the full one.

### Known issues

Found by this release's own walkthrough, each reproduced against published 0.22.0
and carried rather than fixed. First carry for both. Named here because this
release is about the tool telling the truth about what it did, and both of these
are cases where it does not.

- **`scan` has three ignore layers and one of them is unreachable by any flag
  ([#136](https://github.com/opena2a-org/secretless-ai/issues/136)).** A tree whose
  only credential sits in `dist/`, `build/`, `node_modules/`, `coverage/` or
  `vendor/` reports `No hardcoded credentials found.` with exit 0 under every
  documented flag combination. Worse, `--no-ignore` and `--include-tests` each
  widen coverage on their own and, given together, narrow it back to the no-flag
  baseline. `--help` describes the two layers that flags do reach and is silent
  about the third. Fixed in **0.24.0**, with the rest of the selection work.

- **A typo in a `scan` coverage flag yields a confident clean
  ([#137](https://github.com/opena2a-org/secretless-ai/issues/137)).**
  `scan --include-testss` warns on stderr, names the flag you meant, and then exits
  0 with `No hardcoded credentials found.` over a tree it narrowed. The `--json`
  summary carries no trace of the dropped flag, so a CI job gating on
  `summary.total` cannot see it. `scan` warns rather than refuses by design — see
  the behaviour note above — and the case that survives that design is the
  coverage flags specifically. Fixed in **0.23.0**.

### Corrections to the 0.22.0 notes

Found while re-checking the issues that release closed. Neither is fixed here —
0.22.1 is deliberately narrow — but a release note that claims more than the
code does is the same defect class this release is about.

- **"Values are validated at the store boundary, so `set`, `import` and the MCP
  write path are all covered" is wider than the code.** The MCP write path does
  not end at `setSecret`: `src/mcp/vault.ts` calls the backend directly and
  bypasses the check, as does the backend migration path. Measured by storing a
  value carrying bracketed-paste escape bytes through `McpVault` and reading it
  back unchanged. The source comment asserting the same coverage is wrong in the
  same way. Tracked on [#104](https://github.com/opena2a-org/secretless-ai/issues/104).

- **"Every successful write now prints the shape" is only true of `secret set`.**
  `setup` prompts for values interactively and prints no shape line; `import`
  prints names only.

## [0.22.0] - 2026-08-12

Credential disclosure and integrity. Three defects a credential manager should
not carry, plus what sweeping their shape across the code turned up.

**Behavior change worth reading before you upgrade.** Reads that used to return
"nothing" on failure now fail closed. If the local store cannot be decrypted, if
the keychain will not answer, or if the name index is malformed, the command
exits non-zero and says so instead of reporting an empty store. If you have
automation that treats "no secrets" as a normal outcome, it will now see an
error in the cases where the tool never actually read anything.

**`secret set` now refuses a mangled value.** Null bytes, U+FFFD and control
characters other than tab, newline and carriage return are rejected rather than
stored. Multi-line secrets (PEM keys, service-account JSON) are unaffected.

**Your cache is invalidated once on upgrade.** Cached values are now tied to the
build that read them, so the first resolve after upgrading re-reads from the
backend. Expect one extra unlock prompt.

### Fixed

- **The on-disk cache served values written by a previous build ([#118](https://github.com/opena2a-org/secretless-ai/issues/118)).** Upgrading specifically to fix a corrupted credential returned the corrupted credential for another five minutes, because the cache had no idea which build wrote what. The TTL bounds how stale a value may be and says nothing about how it was read; #107 fixed a read path that corrupted most 32-hex secrets and changed no file format, so nothing invalidated what the broken build had cached. A fix the user cannot observe is indistinguishable from no fix, and this one actively taught them the tool was broken. Entries now carry the identity of the build that wrote them and are dropped unless it matches. Version alone is not the build — a working tree, a global install and an `npx` unpack can report the same version while running different code — so the install location is folded in.

- **`cache clear` cleared a directory the cache stopped using in 0.12.3.** It deleted the abandoned file, printed `Cache cleared`, and left every live entry in place. It is also the workaround #118 documents, so the one published remedy for a stale cached credential was a no-op that reported success. Both locations are cleared now, off the same default the backend writes to. Clearing the pre-0.12.3 file matters on its own: it is an encrypted file of credential values that nothing reads and nothing expires.

- **A cache marker that outlived its entries reported a successful resolve of nothing.** The marker asserts "this prefix is fully resolved" and was guarded by a condition that is true for every possible value, so `run` could inject no secrets at all and exit 0. Measured on 0.21.3. The marker now carries the count it was written with.

- **An unreadable local store was read as an empty one ([#104](https://github.com/opena2a-org/secretless-ai/issues/104)).** `resolve` caught every failure and returned nothing, so `run`, `status`, `verify` and manifest checks all reported success over a credential set they never saw, with exit 0 and empty stderr. Empty and unreadable are different states and the code cannot tell them apart by guessing. A store that is absent is still empty — that is a real first-run state — but one that is present and will not decrypt now fails closed, naming the store, the reason, and the two inputs its key derives from.

- **`secret set` destroyed the store when it could not read it.** The read failure was swallowed with "start fresh" and a one-entry store was written over the top. Measured: three secrets stored, then one `set` from an account that could not decrypt the store, and all three are gone — while the command printed `Stored: NAME` and exited 0. The original account's key still worked right up to that write, so the data was recoverable until the tool destroyed it.

- **The store format version was written on every save and checked nowhere.** A store written in a format this build does not understand would be decrypted, parsed as whatever it parsed as, and served. It is now checked before the decrypt, and a store with no version file is still read — that is a store from a build that never wrote one, not a mismatch.

- **`doctor` and `verify` called the local store healthy because the file existed.** Presence was the entire check, so the one state it exists to catch — a store that is there and unreadable — was the state it called healthy. `secret rm` likewise reported "no such secret" against a store it could not read.

- **A locked keychain made every secret read as missing.** `security` exits 44 for "the specified item could not be found"; every other failure, including a locked login keychain and a dismissed approval dialog, was read the same way. Only 44 means absent now.

- **A malformed name index reported an empty keychain.** The index is how the backends answer "what secrets exist", since the OS keychain has no such query. Any failure reading it returned an empty list, so `secret list` printed nothing and `run` injected nothing over a keychain that still held every secret. Only a missing file means "no secrets yet".

- **A keychain read that could not establish the encoding returned the raw value.** macOS hex-encodes binary passwords, and `-w` output alone cannot say whether it did. When the check that settles it does not complete, returning the raw value hands back the hex transcript of the credential rather than the credential — silently, exit 0. There are three answers to that question, not two, and the third is now a refusal.

- **`run` printed a secret value to stderr ([#117](https://github.com/opena2a-org/secretless-ai/issues/117)).** Node rejects an environment value containing a null byte and puts the value in the message. The throw is synchronous, so the handler meant to catch spawn failures never saw it, and the message went to stderr unredacted — which is what CI logs capture. Such a value is not exotic: macOS returns binary passwords hex-encoded, and they decode to bytes containing a null. Values are now checked before the spawn, so the error names every unusable secret and only its name, and the spawn is wrapped for anything a different Node version rejects that we did not anticipate.

- **The redaction backstop missed escaped and truncated values.** It compared whole values and whole lines, and runtimes embed neither: Node escapes control bytes and truncates long values, `JSON.parse` quotes the first ten characters. Measured against all three throws this tool actually hits, whole-value containment reports no leak over a message displaying most of the credential. Detection now works on runs of the value, in any escaping, and the macOS Keychain write path uses the same detector.

- **`diff` printed credential values verbatim.** It renders the git diff of secretless-managed files — which is exactly where a credential gets added, and exactly the output someone pastes into a chat to ask whether the change is safe — while `scan` redacted the same bytes in the same file. Found by this release's own walkthrough. It uses `scan`'s redactor and `scan`'s pattern list now, so the two cannot drift apart.

- **A mangled paste was stored without comment ([#104](https://github.com/opena2a-org/secretless-ai/issues/104)).** A 40-character hex token pasted at the interactive prompt was stored as 19 bytes of control characters and U+FFFD — the terminal's own bracketed-paste sequences captured into the value — and surfaced much later as a type error inside an unrelated consumer. Values are validated at the store boundary, so `set`, `import` and the MCP write path are all covered. Every successful write now prints the shape: length and character class, never content.

### Known issues

Found by this release's own walkthrough, each reproduced against published 0.21.3 and carried rather than fixed. First carry for all three, and all three are fixed in **0.23.0**.

- **Redaction leaves the tail of a token longer than its pattern's fixed length ([#133](https://github.com/opena2a-org/secretless-ai/issues/133)).** A correctly-shaped classic GitHub PAT redacts cleanly; a value one character longer prints that character, and the residue grows with the overshoot. This is the same detector/redactor gap this release fixes for error messages, still present in the scan preview path, so it is named here rather than left for a reader to discover in a release about disclosure.
- **`broker start` reports success for a daemon that is not running ([#132](https://github.com/opena2a-org/secretless-ai/issues/132)).** It prints "Broker is running" and a PID; `broker status` immediately reports it is not, and the PID does not exist. `warm` auto-starts the broker, so this is on a default path.
- **On Linux, `secret-tool` failures are still read as "not found" ([#130](https://github.com/opena2a-org/secretless-ai/issues/130)).** Separating that from "could not read" needs exit codes that could not be measured on the machine this was fixed on, and a guessed mapping is worse than a recorded gap. The macOS path is fixed.

## [0.21.3] - 2026-08-11

Closes the `init` data-loss defect disclosed as a known issue in 0.21.2, plus
three more places where the same shape appeared: a file we could not parse or
could not open was treated as a file with nothing in it.

**Behavior change worth reading before you upgrade:** `init` now exits 1 and
changes nothing when `.claude/settings.json` cannot be merged into, instead of
replacing it. `scan` now exits 1 when a file was skipped for exceeding the
per-file size cap, the same way it already does for the file-count cap and for
unreadable paths. Both were previously exit 0.

**If you run `init` from a `postinstall` hook, move it before you upgrade.** Our
own team-setup guide recommended that wiring until this release. Because `init`
now exits 1 on a `.claude/settings.json` it cannot parse, and `npm` fails the
whole install when `postinstall` exits non-zero, a single developer's JSONC
settings file will stop `npm install` from completing for them. Run it as an
explicit script instead (`"protect": "secretless-ai init"`, then `npm run
protect`), so the failure is visible and actionable without blocking dependency
installation. Do not paper over it with `|| true` — that restores exactly the
silent success this release removes. `docs/use-cases/team-setup.md` is updated
with the exit-code table.

### Fixed

- **`init` destroyed `.claude/settings.json` when it did not parse as strict JSON, and reported the merge as successful ([#122](https://github.com/opena2a-org/secretless-ai/issues/122)).** The read helper collapsed "file absent" and "file present but unparseable" into the same `null`; the caller turned that into `{}` and wrote it back, so every user key was replaced by a Secretless-only document with no backup — while the run printed `added 96 deny patterns` and exited 0. The trigger is JSONC (`//` comments, trailing commas), which is what VS Code writes and what people hand-edit into that file, so the failure landed on files that looked normal to their owner.

  `init` now leaves such a file byte-identical, names the parse error, states that no deny patterns and no hook wiring were installed, and exits 1. The `Verify:` and `Fix:` lines are specific to which of the three failures occurred — a syntax error, valid JSON that is not an object, or a file that could not be opened at all. They have to be: a settings file whose top level is `null`, an array or a string is *valid JSON*, so a `JSON.parse` check exits 0 on it, and printing that as the verify step for every refusal would tell the user their file was fine while `init` refused it, under advice to remove comments the file does not contain. Each printed command is now executed by the test suite against the shape it is printed for, and against a healthy file, rather than asserted as a string. It does not list Claude Code as configured, because the guard script on disk is inert until settings.json references it — reporting it as configured would have been the same false success one line further down.

  Three neighbouring shapes reached the same write path and are fixed with it. A settings file containing valid JSON `null` took the overwrite branch. An **array** was worse than data loss: properties assigned to an array are dropped by `JSON.stringify`, so `init` wrote the array back unchanged while reporting 96 deny patterns added — a project left completely unprotected with a success message and nothing destroyed to prompt a second look. A **string** or number threw a raw `Cannot create property 'hooks' on string` at the user with no file named and no fix. A file that is empty or whitespace-only is still configured normally: it provably holds no user content.

- **`status` reported an unparseable `.claude/settings.json` as zero deny patterns.** "No rules configured" and "could not read the rules" rendered identically, so a project whose protection was never wired up looked exactly like a healthy one — and the ✓ next to `Claude Code hook installed` was keyed on the guard script merely existing on disk, not on anything having wired it in. `status` now reports the parse failure as a warning with a verify command, exposes `settingsUnreadable` in `--json`, and does not claim `isProtected`.

- **Setting the backend or the cache TTL silently reset the other one when `~/.secretless-ai/config.json` did not parse.** Same collapse as #122 in a smaller file: the read-modify-write started from `{}` on a parse failure, so `backend set` dropped `cacheTtl` and `cache set` reverted the backend to `local`. For a tool that decides where credentials get written, quietly resetting that choice is the defect, not the recovery. Both writers now refuse, name the file and the parse error, and leave it unchanged.

- **Files over the per-file size cap were skipped with no warning ([#120](https://github.com/opena2a-org/secretless-ai/issues/120)).** A config file over 10 MB or a source file over 1 MB was dropped with no `truncated`, no `unreadable` and no output of any kind. Measured: an 11 MB `config.json` with a live-shaped Google key on line 1 scanned to `total: 0`, `truncated: false`, exit 0. The cap bounds memory use and says nothing about the contents — the same bytes under it produce a finding — so this closes the size-cap gap in the class 0.21.2 was working through. It is not the last one: see the `status` transcript fix below, and the open scope gap in `Known issues`. Skipped files are now listed with their size and the cap, counted in `summary.oversize` and `oversizeFiles` in `--json`, and set exit 1.

- **`status` reported every discovered transcript as scanned, turning a three-file sample into a clean verdict.** It printed `Transcripts clean (8850 files scanned)` while having read three of them — `transcriptFiles` was a discovery count rendered as a scanned count. Measured on a real machine during this release's testing: that line printed while `clean --dry-run`, over the same 8850 files, found 882 credentials in 168 of them. Sampling is deliberate and stays (a full pass takes tens of seconds; `status` answers immediately), but the scope is now stated: `No credentials in the 3 most recent transcripts (8850 found; the rest were not read)`, with `clean --dry-run` offered as the full check. `--json` gains `transcriptFilesScanned` alongside `transcriptFiles`. Present in 0.21.2 and earlier; it is the same confident-zero-over-unread-content defect as the rest of this release, on the headline verdict surface.

- **The MCP wrapper told users to run a command that does not exist.** When the vault directory was missing, `secretless-mcp` printed `Run 'npx secretless-ai mcp-protect' to set up MCP secret protection` and exited 1. The command is `protect-mcp`, so following the instruction printed `Unknown command: mcp-protect` and exited 1 again — a dead end on an error path, where the user is already stuck. Present in 0.21.2 and every earlier version. Fixed, and the class is now covered: a test cross-references every command the tool suggests in its own output against the commands `cli.ts` actually dispatches. Markdown was already checked this way; the tool's own output strings were not, which is why this survived.

### Added

- **`scan --max-file-size <size>`** raises the per-file cap (`20mb`, `500kb`, or a byte count), so a reported skip has a fix and not only a name. One value applies to config and source files alike. An unparseable value is refused with a warning rather than silently falling back — `--max-files` had shown that `parseInt` turns `1e6` into a cap of 1 while the user believes it was raised.
- **The scan triage flags are now listed in `--help`.** `--max-files`, `--max-file-size`, `--min-confidence`, `--show-placeholders`, `--no-ignore` and `--include-tests` were all absent, including the two that coverage warnings tell the user to run.

### Documentation

- **Three stale numbers in the README, all corrected and pinned.** A number in a sample output is read as the tool's actual behavior, so a stale one misdescribes the build the reader just installed. The sample `init` output claimed 86 deny patterns where the build writes 96; the feature list claimed 21 blocked file patterns where the hook layer enforces 18; and the test badge was a hardcoded `1333 passing` that had to be edited by hand to stay true, so it is now the live CI badge instead. The two counts and the sample version banner are pinned by tests that read the README and compare it against what the code actually produces, both sides derived at run time so neither can drift silently.
- **`docs/use-cases/team-setup.md` no longer wires `init` into a `postinstall` hook.** See the upgrade note above; the guide now uses an explicit `npm run protect` script and documents `init`'s exit codes.

### Known issues

- **`scan <dir>` skips every config file whose name is not on a 33-entry allowlist, and reports the result as clean ([#124](https://github.com/opena2a-org/secretless-ai/issues/124)).** Found by this release's own testing, in the same defect class the release is about, so it is called out here rather than left silent. 14 files in one directory each holding the identical key produced `total: 4` with `truncated: false` and no exclusion notice; `secrets.json`, `settings.json`, `creds.json`, `appsettings.json`, `.npmrc`, `Dockerfile`, `serverless.yml`, `values.yaml`, `app.toml` and `app.ini` were never read, while `config.json` and `config.yaml` were. Each missed file is detected correctly when named directly (`secretless-ai scan secrets.json` finds it), so this is file selection, not detection. Reproduces identically on 0.21.2 and earlier — not a regression in this release.

  Until it is fixed, `secretless-ai scan <file>` on a specific config file is reliable, and a directory scan should not be read as covering config formats beyond the allowlist. **This blocks 1.0.0**: the version will not ship with it open, per the v1 burndown, and widening the file set has to be measured in both directions because a noisier scan is its own failure mode.

### Internal

- The finding-dedup key in `src/scan.ts` held two raw NUL bytes written directly into the source rather than as escapes. The compiled string is unchanged; the source is no longer classified as binary by `grep`, `rg` and every diff viewer.

## [0.21.2] - 2026-08-06

Three defects that shipped in 0.21.1, two of them regressions introduced by that
release's own fixes. All three are cases where the scanner reported a clean or
complete result for work it had not done, so upgrade promptly.

**Behavior change worth reading before you upgrade:** a scan that could not read
everything no longer exits 0. If the file walk stops at the cap, or any file
cannot be opened, `scan` exits 1 and says `No credentials found in the files
scanned` instead of `No hardcoded credentials found`. A CI job over a tree larger
than the 5000-file cap that was passing will now fail until you raise
`--max-files` or narrow the path. Those passes were not earned: the walk stopped
early and the result was reported as clean.

### Known issues

- **`init` destroys `.claude/settings.json` when it does not parse as strict JSON, and reports the merge as successful ([#122](https://github.com/opena2a-org/secretless-ai/issues/122)).** Not introduced here — it reproduces identically on 0.21.1 — but disclosed rather than left silent, because it is the same defect class this release is about: a tool reporting success for work it did not do. The trigger is JSONC (`//` comments, trailing commas), which is what VS Code writes and what people hand-edit. A valid JSON settings file merges correctly and preserves every user key; only a parse failure clobbers, and no backup is written. If you keep comments in that file, back it up before running `init`. Fix targeted at 0.21.3.

### Fixed

- **A symlinked config file or directory was silently skipped (regression in 0.21.1).** `walkConfigFiles` classified entries with `Dirent.isDirectory()` / `isFile()`, which are `lstat`-based — a symlink is neither, so it fell through both branches and was dropped. 0.21.0 reached config files through `existsSync`/`statSync`, which follow links; making the config walk recursive removed symlink support without anything noticing.

  ```
  repo/.claude -> shared-claude/          # settings.json holds a live key
  0.21.0   exit 1   1 critical credential exposed
  0.21.1   exit 0   No hardcoded credentials found.
  ```

  This affected every `CONFIG_FILES` entry at any depth — `.env`, `.mcp.json`, `docker-compose.yml`, `terraform.tfvars` — and a symlinked `.claude/` is exactly what a dotfile manager or a shared monorepo config produces. Entries are now classified by following the link, and the three near-identical tree walks were collapsed onto one shared traversal: they had drifted apart, which is how the config copy gained recursion while losing the symlink handling, and sharing the walk means link handling, cycle safety and coverage reporting cannot diverge again.

  Three bounds come with it, because a repository is an untrusted input to a scanner.

  A directory is treated as a cycle only when it appears in its **own ancestor chain**. A global visited-realpath set also terminates, but it drops a directory reachable by a second path once the first is seen — which silently re-broke this very case whenever the link's target was itself in the tree, and which of the two paths won depended on readdir order.

  A **directory** link resolving outside the scan root is not followed, because otherwise a repo containing `link -> $HOME` makes `scan .` traverse the whole home directory; these are listed with the command to scan the target directly, so declining is never silent. A **file** link is still followed wherever it points: reading one file the repository explicitly names is bounded work, and `pkg/.env -> ../../shared/.env` is what stow, chezmoi and monorepo-root env files actually produce.

  Finally, the number of distinct paths through a lattice of links is exponential — a 15-level fixture reaches one directory 32,767 ways — so the number of routes followed to any one directory is capped, and crossing that cap reports the scan as incomplete rather than passing silently. Sockets, FIFOs and device files are never opened.

  Findings are deduplicated on the resolved file, so a credential reachable by several paths is one finding rather than one per path.

- **A scan that hit the file cap reported clean.** The walkers stopped at `maxSourceFiles` (default 5000) and returned quietly, so an incomplete scan was indistinguishable from a complete one — fewer findings, no signal, exit 0. Truncation is now reported through `ScanStats.truncated`, surfaced in the human output and in `--json` as `summary.truncated` alongside `summary.maxFiles`, and exits 1. Adds `--max-files <n>` so the warning has a runnable fix.

- **`.secretless` parse errors echoed credential values to stderr, twice.** The manifest is documented safe to commit, and `setup --check` stderr is exactly what lands in CI logs. A `NAME=VALUE` line echoed the whole line; a `NAME VALUE` line echoed it again interpolated into the error reason, which was also unbounded — so a 200 KB token flooded stderr through a field the 120-char line limit did not cover.

  Redaction is an allowlist by position rather than a character test. Secret names allow `[a-zA-Z0-9_-]`, so a live token is itself a valid name and no charset rule can tell the two apart; only position can. The reason now names the shape it saw (dotenv, YAML, JSON), which is more actionable than the echo it replaces:

  ```
  line 1: [redacted]
          looks like dotenv (NAME=VALUE) — .secretless declares names only, never values
  ```

  The first token is echoed only when the WHOLE token is a valid secret name. An earlier form of this fix split a `NAME=VALUE` paste and printed the left side, on the reasoning that in dotenv the left of `=` is the name — but `=` is also base64 padding, so for a secret from `openssl rand -base64 32` the "name" is the entire secret, and it was printed in full.

- **An unreadable file or directory was reported as clean, exit 0 (#116).** The same content, readable, produces a finding. A directory scan dropped the file from the count and a named target printed `No hardcoded credentials found`; a directory whose listing failed vanished with nothing recorded at all. Unreadable paths are now listed with a runnable `chmod` fix, counted in `--json` as `summary.unreadable`, and exit 1. A broken symlink still counts as nothing to scan, but `EACCES`/`ELOOP` on a link target is reported rather than skipped.

- **`status` and `vault scan` discarded the coverage signal.** Both call the same scanner and neither asked for it, so `vault scan` printed the unqualified `No hardcoded credentials found` over a tree it could not fully read — the exact string `scan` was fixed to stop printing — and `status --json` reported `secretsFound: 0` as though it were a verdict. `status --json` gains `scanIncomplete`.

- **`--max-files` accepted a value it then ignored.** `parseInt` stops at the first non-digit, so `--max-files 20abc` silently became a cap of 20 and `--max-files 1e6` a cap of 1: the user believed the cap was raised while the scan covered a fraction of the tree and exited 0. The value must now be all digits.

- **`.env` variants were mostly missed (#116).** `.env` and `.env.local` were detected; `.env.development`, `.env.production`, `.env.staging`, `.env.test` and `.env.prod` were not — the exact set named in the CLAUDE.md block Secretless itself installs. Any unrecognised `.env.*` is now scanned and only known template suffixes (`.example`, `.sample`, `.template`, `.dist`) are skipped, so the unknown case fails closed.

- **Config filenames were matched case-sensitively.** On macOS and Windows `Claude.md` and `CLAUDE.md` are the same file to the OS but not to an exact-match lookup, so a file the user could plainly see was skipped.

### Security

- **The `Verify:` and `Fix:` lines quote the paths they print.** Those paths are filenames from the scanned repository — attacker-controlled by definition — and the lines exist to be copy-pasted into a terminal. A symlink named `a"; id; echo "b` previously produced a command that closed the quote and ran `id`.

### Internal

- Two tests asserted nothing and were rewritten. One asserted a pattern that accepted the unfixed value it claimed to guard against; the other computed its expectation by calling the same function as the code under test, so a wrong answer was wrong identically on both sides. Both are now pinned against independent oracles and verified to fail on a mutant.

## [0.21.1] - 2026-08-06

Four defects that shipped in 0.21.0, plus issues #110, #111 and #112. Two of
these let a command report success while doing less than it said: `--include-tests`
reported clean on a tree it never scanned, and `run --only` ran commands with
credentials missing. Both are reasons to upgrade promptly.

### Fixed

- **`scan <file>` reported a clean result for a file containing a credential.** A file path was accepted, checked for existence, then walked as if it were a directory — which found nothing:

  ```
  $ secretless-ai scan single.js
    No hardcoded credentials found.          # exit 0
  $ secretless-ai scan .                     # the same file, via its directory
    1 credential found                       # exit 1
  ```

  `secretless-ai scan src/config.ts` in a CI step was therefore a green pass over a live credential. A named file is now scanned as that file. Because naming a path is an explicit instruction rather than a directory walk, neither the ignore list nor the test-file heuristics apply to it: those exist to keep a walk from being noisy, and there is no walk.

- **Config files were only found at the scan root.** Source files recursed; `config.json`, `docker-compose.yml`, `.mcp.json`, `terraform.tfvars` and the rest were matched only against the top directory. A monorepo, or anything under `deploy/` or `infra/`, reported clean at exactly the invocation everyone runs first, while the same scan from inside the subdirectory found the credential immediately.

  Config files are now found at any depth, including in the hidden directories where tool configs actually live (`.cursor/`, `.claude/`, `.vscode/`). Generated trees (`node_modules/`, `dist/`, `build/`) are still never walked, and `.secretlessignore` still applies.

- **`scan <a> <b>` silently scanned only the first path.** The second was dropped with no warning, and because the first path's findings still set exit 1, the run looked complete while an entire file went unscanned. It now exits 2 naming the paths it was given, rather than answering for input it ignored.

- **A single-file finding reported a path that did not resolve.** `scan deploy/prod/app.js --json` reported `file: "app.js"`, so a CI job annotating `file:line` from the JSON pointed at the wrong file or at nothing. It now reports the same path a directory scan does.

- **`status`, `cache` and `mcp-status` reported the configured backend rather than the one in use.** The same defect as #111, in the three surfaces that were not swept when `backend` was fixed. `cache` drew a wrong conclusion from it — `Status: Not needed (local backend has no auth prompts)` on a machine whose secrets go to the Keychain, which does prompt. All four surfaces now name the effective backend and agree; `status --json` gains a `configuredBackend` field alongside it.

- **`run --only ''` ran the command and exited 0.** An empty value read as "flag not supplied", so the filter vanished — while the semantically identical `--only ,,` correctly refused. Same input, opposite fail direction. A CI step computing `--only "$KEYS"` with an empty `$KEYS` ran unprotected and reported success. Both forms now fail closed.

- **`run --only` never checked that the names it was given were found (#110).** One root cause, three failure modes, and only the least harmful was loud.

  | store | `--only` matches | before |
  |---|---|---|
  | non-empty | nothing | exit 1, blamed the backend |
  | non-empty | some, not all | exit 0, ran a credential short, silently |
  | empty | anything | exit 0, ran with nothing injected |

  `loadSecrets` filtered what the backend *returned* and never iterated what it was *asked for*, so an unmatched name left no trace and was indistinguishable downstream from a name nobody requested. `run` then saw only a count of zero and reached for the one explanation it had — the backend — which was reachable the whole time.

  The third mode needs no user error at all: on a fresh machine or a CI runner whose store was never populated, `run --only DEPLOY_TOKEN -- ./deploy.sh` ran the deploy with no token and exited 0. The warning said "No secrets found", which reads as informational next to a command that then appears to work.

  Requested is now compared against resolved inside `loadSecrets`, the only place both are in scope. Any name that resolved to nothing is an error naming the unmatched names — whether it is one of five or five of five — with `Verify:`/`Fix:` lines and a near-miss hint drawn from names actually in the store, since the whole class is typos. An empty `--only` list (`--only ,,`) refuses too. The count-based guard in `run` is scoped to the no-`--only` case, where it is the correct diagnosis. `env --only` shares `loadSecrets` and gets the same fix.

- **`backend` reported the configured value, not the backend actually in use (#111).** On a default machine `backend` printed `Current: local` while `secret list` printed `keychain-macos`. Both were describing the same store and disagreeing about it.

  `createBackend` deliberately upgrades `local` to the platform keychain (#34); the defect was that `backend` read the config value while everything else reported the constructed object. The two stores differ in ways a user acts on — the keychain is shared across every project on the machine and can prompt for authorization, the local encrypted file does neither — and "where does my value physically go" is the question this command exists to answer.

  `Current:` now names the backend that will actually be constructed, and says why when it differs: `keychain-macos  (configured: local, upgraded because a platform keychain is available)`. The effective name is derived from the same factory the store uses, so the two cannot drift apart again, and it is computed without any probe that could trigger an auth prompt.

- **`setup --check` misread an unrecognised manifest into names that do not exist (#112).** A YAML-shaped `.secretless` — a reasonable first guess, since the sibling rules manifest is YAML — was not rejected. It was parsed into `required:` and two bare `-` characters and reported as `Missing: 3 required`, none of which appear in the file as names. In CI, the documented use for `--check`, that is a red build whose message sends you to look at your store instead of at your file.

  Each line is now validated with the same rule the store uses for secret names, rather than a second copy of it. A line that cannot be a name is a manifest error reported with its line number and the offending character, followed by the expected format; nothing is counted, because the file did not say what to count. A trailing token that is neither `optional` nor a comment is rejected too, so the defect cannot simply move one token to the right.

  The format was also documented nowhere. `setup --help` now shows it. That help block — and `env`'s — existed but was unreachable, because `--help` was intercepted for every subcommand before dispatch; the interception stays for runners that would otherwise perform their action (`init --help` once created a literal `--help/` directory), with an explicit exception list for the two that answer help first.

- **`scan --explain` printed model output instead of the fix, not alongside it.** When the local NanoMind engine happened to return text, that text *replaced* the deterministic `Fix:` line, so a HIGH finding arrived with no remediation at all. One run produced `Also, provide a solution to the security risk of a hardcoded OpenAI Project Key found in src/client.js.` — the model echoing its own prompt back, presented as the tool's own guidance. Other runs produced a `require('openai-project-key')` (no such npm package) and a repetition loop.

  The trigger looked intermittent because the engine usually returns an empty string and the fallback branch then printed the real fix. The defect itself was not intermittent: *any* non-null explanation replaced the remediation.

  The `Fix:` line now always prints. Generated text may only appear beside it, labelled `Context (generated, unverified):`, and is dropped when it fails validation — prompt echo (measured against the actual prompt, so it survives rewording), install or import directives, host references, degenerate repetition, and length. The prompt no longer asks the model for "the immediate action to take"; remediation belongs to the verified fix, and soliciting it is what invited an invented package name. A security tool must not emit a package name or a rotation URL it made up: an invented URL points at a domain an attacker is free to register.

- **`--explain` no longer prints generated context at all by default.** Measuring the local engine over 30 runs while fixing the above: 30 produced text and **none produced a usable explanation**. Validation caught 27. The three that passed were instruction-tuning noise ("Your answer must contain exactly 3 bullet points"). Among those correctly rejected were confident and *wrong* security claims — a leaked OpenAI key described as "vulnerable to brute-force attacks", and as letting an attacker "inject malicious code into the client". Neither is true of an API key.

  A wrong security claim from a security tool is worse than no claim, and a label does not make it true, so the generated line is now off unless `SECRETLESS_NANOMIND_EXPLAIN=1` is set. `--explain` still gives the detailed per-finding view with verified remediation, which is the part that was worth having. The help text no longer promises "rich context explanations" it could not deliver.

- **`--include-tests` did not include test files.** A credential in `test/fixture.test.js` was reported clean with the flag set — a silent false all-clear on exactly the tree the user asked to check.

  Two independent gates suppress test paths: the walker's `TEST_DIRS` check and the default-ignore list's `test/` entry. The flag opened only the first, so anything inside a test *directory* stayed hidden; a test-*named* file outside one (`src/fixture.test.js`) was found, which is why the flag looked like it worked. It now opens both, and reaches `tests/`, `__tests__/`, `__fixtures__/`, `test-server/` and `e2e/` as well.

  Deliberately unchanged: `node_modules/`, `dist/` and `build/` stay suppressed — asking for tests is not asking to scan dependency trees — and an explicit entry in your own `.secretlessignore` still wins, with `--no-ignore` remaining the way to override that.

- **40 of 57 credential patterns produced findings with no fix.** `aws-secret` was the one a release-test fixture happened to exercise; the missing guidance covered most of the catalog, including every GitHub token variant, `npm`, `gitlab`, `sendgrid`, `digitalocean`, `sentry` and `stripe-webhook`. Each rendered a HIGH or CRITICAL finding and then stopped, with nothing to act on.

  `fix` is now non-optional. Patterns without a hand-written entry derive one from data the pattern already carries — the exact env var name, plus revoke-and-reissue — so a newly added pattern cannot ship a dead end. Derived text names no console URL, because we have not verified one for those providers and inventing it is the same failure as inventing a package name.

- **An AWS secret-key preview hid which variable was exposed.** The name-gated pattern's match spans the variable name, so redacting the whole match rendered `AWS_SECRET_ACCESS_KEY = "…"` as a bare `"`. Patterns that capture their value now redact only the value: the preview reads `const AWS_SECRET_ACCESS_KEY = "[AWS Secret Access Key REDACTED]";`. The secret itself is still never shown.

- **The `--explain` footer claimed "147+ checks" for `hackmyagent secure`.** The real figure is over 300 and moves every release. The claim is gone rather than restated — a number in user-facing output has to trace to something measured.

## [0.21.0] - 2026-08-05

### Fixed

- **A configured backend that could not be reached was silently replaced by the local store.** With `backend set 1password` and the 1Password desktop app disconnected, `secret set NAME=value` wrote to the *local* store and printed `Stored: NAME`. `secret get NAME` then read 1Password and reported nothing. `run` executed the command with no credentials injected at all. Each of those reports success at the point of use, and the failure only surfaces later as an authentication error that never mentions secretless.

  `createBackend()` took a `strict` flag that defaulted to false, and `SecretStore` — the code behind `secret set`, `secret get`, `secret list` and `run` — never passed it. Only `backend migrate` did. On the default path an unavailable backend printed two lines to stderr and returned a `LocalBackend`.

  The state that triggers it is ordinary. With the `op` binary installed and an account configured but the desktop app not running, `op --version` and `op account list` both exit 0 (the latter answers from local config), while `op account get` exits 1. Quitting the app, rebooting, or a reset CLI-integration toggle is enough.

  Substituting a store is not a safe degradation for a credential manager, so it no longer happens. An unreachable configured backend now fails closed with an error that names the backend you chose, states that nothing was read from or written to anywhere else, and carries the `Verify:` and `Fix:` commands plus the deliberate `backend migrate` path. The permissive path remains for read-only diagnostics, and now says plainly that it is listing a different store.

  **Behaviour change.** Commands that previously appeared to succeed against the wrong store now exit non-zero. That is the point: if `secret set` was quietly writing somewhere you did not choose, it was never succeeding. If a script depended on the old fallback, switch it deliberately with `secretless-ai backend set local`.

- **Overwriting a 1Password secret could destroy it.** `store()` deleted the existing item before creating the replacement. If `op item create` then failed for any reason — app disconnected mid-command, vault permissions, network — the old value was already gone and the new one was never written. The replacement is now created first and the superseded item retired afterwards, by ID rather than by title, because the two legitimately share a title in the window between the calls.

- **1Password items could land untagged and become invisible to every later read.** The tag was set only inside the JSON template, while `listItems()` filters on it, so an item that did not pick the tag up could never be resolved again. Title and tag are now passed as explicit `--title` and `--tags` flags as well, which take precedence in `op item create`.

- **A pending 1Password approval hung the entire command.** `op` was invoked with no timeout, so an approval dialog waiting on someone who is not at the machine blocked the caller indefinitely with no output. Calls are now bounded (30s default, `SECRETLESS_OP_TIMEOUT_MS` to change it) and report what to check.

- **The team-setup guide published a `postinstall` hook that fails every `npm install`.** `docs/use-cases/team-setup.md` told teams to add `"postinstall": "npx secretless-ai init --ci"`, directly under the line "Now every `npm install` configures AI tool protections automatically." `init` takes an optional directory path and no flags, so it exits 2 with `Unknown option: --ci` and npm fails the install for every developer who followed the guide.

  The guide was correct when it was written. Making `init` reject unknown flags (#62 — before that, `init --dry-run` created a literal `--dry-run/` directory) is what turned a silently-wrong documented command into a loudly-broken one. A release that tightens a parser has to re-check every command its own docs publish. `src/docs-commands.test.ts` now derives the command list from the dispatch sites in `cli.ts` and fails if any documented command does not exist, or if any doc puts a flag on `init`.

- **Errors were buried under a stack trace.** The top-level handler printed the raw error object, so messages carrying `Verify:` and `Fix:` lines arrived underneath our own file paths and read as a crash. It now prints the message; set `SECRETLESS_DEBUG=1` when the stack is what you need.

- **Overwriting a macOS Keychain secret could destroy it.** `store()` deleted the existing entry before adding the replacement, so a write that failed afterwards — a locked Keychain, a dismissed approval — left nothing behind. The entry is now updated in place with `security add-generic-password -U`, and the legacy-named duplicate is swept only after the new value is committed. Same defect and same fix as the 1Password backend above.

- **Most 32-hex-character secrets were silently corrupted on read (macOS Keychain).** A HIBP Pro API key stored with `secret set` came back from `secret get` as 16 bytes of binary, and the same corrupted value was injected by `secret run`, so every consumer of that credential authenticated with garbage. The key in the Keychain was never wrong; only the read path was, which is why nothing looked broken until an API rejected the request.

  `security find-generic-password -w` hex-encodes a password it will not print literally (an embedded newline, for example), and the value has to be decoded back. But its output is genuinely ambiguous — the text `d259cc9961fbd259cc9961fbd259cc99` and the bytes `line1\nline2` both come back as an even-length run of hex digits, and nothing in the output distinguishes them. The old code decided from content: decode when the decoded bytes contain a control character, a rule meant to spare hex-looking passwords such as `deadbeef`.

  A 32-hex-character key is 16 random bytes, and the control ranges that rule tested cover 32 of 256 values, so `1 - (224/256)^16` = **88%** of such keys tripped it. That shape is ordinary: HIBP keys, MD5-form tokens, and many other API keys are exactly 32 hex characters. The remaining 12% round-tripped fine, which is what made the failure look intermittent.

  Content cannot answer the question, so the decision no longer comes from content. `security ... -g` states the encoding explicitly — `password: "…"` for text, `password: 0x…` for encoded bytes — and that marker is now what decides. The exact bytes still come from `-w`; `-g` is consulted only when the value is ambiguously shaped, so the common case still costs one `security` call. Anything unclear (probe fails, Keychain locked, no `0x` marker) returns the raw value undecoded: handing back a secret verbatim is always safe, decoding one that was never encoded is the bug.

  No re-entry is needed. Values already in the Keychain were stored correctly and read back intact once this is in — confirmed against a real affected key, which read back byte-identical to what `security` reports.

  One upgrade note: resolved values are cached for five minutes in `~/.secretless-ai/store/.secret-cache`, so a corrupted value read by the previous version can still be served briefly after upgrading. It expires on its own; the cache is keyed on write time, not on access, so it cannot be held alive by reads. If a credential still looks wrong immediately after upgrading, wait out the TTL rather than re-entering the secret. This is also worth knowing when diagnosing: while the old CLI is still installed alongside a new build, running either one repopulates the shared cache for the other.

### Security

- **`secret set` printed the secret value in its own error message (macOS).** When the Keychain refused a write, the failure surfaced as:

  ```
  Error: Command failed: security add-generic-password -s Secretless: NUTEST -a secret/NUTEST -w hello-world-123
  ```

  `security add-generic-password` takes the password as `-w <value>`, and Node's `execFileSync` puts the whole argv into the error it throws. So the credential landed in the terminal at the exact moment a user is most likely to copy the output and paste it somewhere to ask what went wrong — including into the AI assistant this tool exists to keep it away from. Found in a fresh-user walkthrough, not in the test suite.

  The argv echo is our own command line and tells the user nothing, so it is now dropped entirely, the value is scrubbed from what remains, and a final unconditional check discards the detail altogether if the value can still be found in it. A vaguer error is always better than a leaked one. The message that replaces it names the key, explains that the Keychain declined the write, and carries `Verify:` and `Fix:` lines including the fallback to the encrypted file store.

  The other backends were checked for the same shape: Linux passes the value on stdin, 1Password writes it to a mode-0600 temp file specifically to keep it out of argv, and Vault and GCP send it over HTTP. macOS was the only one, and it is the default there.

  Not fixed in this release: the value is still in `argv` while `security` runs, so it is briefly visible to `ps`. macOS documents this itself ("Use of the -p or -w options is insecure"). The obvious fix — `-w` with no argument, reading the password from stdin — reads a single line and would silently truncate multi-line secrets such as private keys, which this backend supports. Tracked separately rather than traded for data loss.

- **The guard hook no longer fails open on a pretty-printed payload.** `tool_name` and `file_path` were extracted with greps that match only compact JSON (`"tool_name":"Bash"`, no space after the colon). A client that pretty-prints its hook payload left both empty, which skipped the entire Bash-command branch and the file-path guard, so every guard silently permitted the call. This is the same dead-branch class as the 2026-07-16 `FILE_PATH` regression, reached through payload formatting rather than through `set -euo pipefail`. Both fields are now parsed with `python3`'s JSON module (as the `command` field already was), with the greps kept as the fallback for hosts without python3 — where python3 is absent, the pretty-printed payload still fails open, so this closes the hole only on hosts that have it.

  Only non-empty strings are accepted from the parser. `str()` of a number, boolean, or object produced a non-empty WRONG value (`'123'`, `'True'`), which suppressed the grep fallback and left the guard reading a field that was not there.

- **Custom `env:` or `bash:` rules no longer generate a broken hook.** `customRulesToHookBlocks` returned its blocks without a trailing newline, and the caller interpolates that directly ahead of `  exit 0`, so the last block's `fi` collided with it (`  fi  exit 0`). The generated script was not valid bash, and the hook exited 2 on every tool call, for every tool, in any project defining those rules. It failed closed, but a guard that blocks `ls -la` gets uninstalled. `files:`-only rules produce an empty block string and never hit it, which is why the existing `bash -n` coverage — written against a `files:` rule — never caught it. The new test asserts the rules actually reach the generated hook before checking it parses, so a fixture rejected by the pattern validator cannot report a false pass.

- **The file guard now checks every candidate path in the payload, not just the first.** The structured parse reads the documented top-level fields, so on its own it would have narrowed the older whole-payload grep: a secret path nested below the top level (MultiEdit-style edit lists, MCP tool payloads) was no longer seen once a benign top-level path satisfied the extraction. Candidates from the structured walk and from the greps are now unioned and each one is checked, so a benign `path` cannot mask a nested secret `file_path`.

### Known limitation (deliberate, documented in the hook)

- **The command guard still refuses to read committed template files**, while the file-path guard allows them. The two layers disagree on purpose.

  The obvious fix — subtracting template-suffixed path tokens from the command before matching — was implemented, tested against a 50-command corpus, and then reverted, because it is a credential bypass. The guard is a denylist over command TEXT whose only evidence is the literal secret path appearing after a verb; removing that literal hands the attacker the deletion. `cat "$(basename <name>.env.example .example)"` reconstructs the real path from the very token the scrub erased, needs no preconditions, and was measured reading a real secret file that the previous hook blocked. Requiring the extension match at the end of the token fails identically, because the template token still never matches.

  Closing the disagreement safely requires resolving the path a command would actually open rather than pattern-matching its text. Until then, over-blocking a placeholder file is the correct trade against leaking a real one.

All notable changes to [secretless-ai](https://www.npmjs.com/package/secretless-ai) are documented in this file.

```bash
npm install -g secretless-ai
```

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.20.1] - 2026-07-28

### Fixed
- **The guard hook missed every prefixed secret variable.** The `echo`/`printenv`
  arm anchored the secret word immediately after the `$`, so it matched only the
  bare `$API_KEY`, `$SECRET`, `$TOKEN` forms. Real variables carry a prefix, and
  `echo $ANTHROPIC_API_KEY`, `echo $OPENAI_API_KEY`, `echo $GITHUB_TOKEN`,
  `echo $AWS_SECRET_ACCESS_KEY` and `echo $DATABASE_URL` all walked past it. The
  native `permissions.deny` globs (`Bash(echo $*API_KEY*)`) already allowed the
  prefix, so the two layers disagreed and the hook was the weaker one. The
  variable name may now carry any prefix, and `${BRACED}` form is matched too.
- **`printenv NAME` was never checked.** `printenv` takes a bare variable name
  with no `$`, which the `$`-based arm could not see, so `printenv ANTHROPIC_API_KEY`
  was allowed. Bare `printenv`, which prints the whole environment, is now blocked
  as well. `env` is deliberately left alone: it is overwhelmingly used as a prefix
  (`env -u VAR cmd`), and its dump form is covered by the deny rules.
- Deny rules gained the matching entries: `echo $*PRIVATE_KEY*`, `echo $*ACCESS_KEY*`,
  `echo $*DATABASE_URL*`, `printenv *PASSWORD*`, `printenv *CREDENTIAL*`,
  `printenv *VAULT*`, `printenv *DATABASE_URL*`, and bare `printenv`.

- **The guard blocked ordinary work in two ways, so it trained people to work
  around it.** A guard that refuses the day job gets switched off, which is the
  real security cost.
  - The echo/printenv arm matched a secret variable anywhere on the line, so a
    line that began with echo and later passed a key to curl was refused, even
    though passing a secret to curl is the intended way to use one. The span now
    stops at a command separator; a separate echo of a secret later on still
    matches by itself.
  - A secret file extension matched mid-word, so the key extension also caught
    the keys() method call and keychain filenames, and an inline interpreter
    one-liner listing manifest fields was refused as if it read a private key.
    The extension must now end there. The dotted local env file still matches,
    because the next character is a dot.
- **Locale-dependent matching allowed an evasion.** In a UTF-8 locale grep
  decodes each line as characters, and a line carrying an invalid byte sequence
  cannot be decoded, so patterns using a bracket expression stopped matching on
  that line while plain literal patterns still matched. Appending one invalid
  byte to a secret-reading command made the bracket-expression guards fall
  silent. The generated hook now sets LC_ALL=C, so matching is bytewise and no
  longer varies with the developer's locale. Caught by the existing
  lone-surrogate fail-closed test when the extension boundary was added.

### Note for existing installs
A hook generated by an older version stays on disk until `secretless-ai init` is
run again. Two behaviours worth re-checking on an old hook: it blocks committed
template files (`.env.example`, `.env.sample`) that were never meant to be
blocked, and it allows real secret files in the `name.key` / `name.pem` suffix
form. Both were fixed earlier; re-running `init` picks them up.

## [0.20.0] - 2026-07-22

### Added
- **Post-quantum broker assertions (AAP-SPEC 0.4 §8.2/§9.3/§9.4/§9.5, RFC 9964).**
  The broker now mints ML-DSA-65 (FIPS 204) assertions on two new paths:
  `mintBrokerAssertionMlDsa65` (compact `ML-DSA-65` JWT, the PQ-interop lane)
  and `mintHybridBrokerAssertion` (hybrid Ed25519 + ML-DSA-65 as JWS General
  JSON Serialization — one signature entry per suite over the same payload; a
  conformant verifier accepts only if every declared entry verifies and both
  suite families are present). New key surface: `generateBrokerPqcSigningKey`
  (seed-injectable, the FIPS 204 xi / RFC 9964 AKP `priv` form) and
  `brokerPublicAkpJwk` (RFC 9964 `AKP` public JWK for the discovery document).
  Signing is hedged by default and deterministic on request
  (`PqcMintOptions.deterministic`, required for byte-exact fixtures); tests
  prove sha256 byte-parity with the AAP spec repo's published fixtures across
  three independent FIPS 204 implementations. The existing compact EdDSA path
  is byte-for-byte unchanged. Serialization-profile decision:
  agent-authorization-protocol `decisions/2026-07-16-mldsa65-serialization-profile.md`.

### Changed
- **Node engine floor raised from `>=18.0.0` to `>=20.19.0`** — the ML-DSA-65
  suite loads the ESM-only `@noble/post-quantum` via `require(esm)`, supported
  since Node 20.19; Node 18 and 20 are both end-of-life. The dependency loads
  lazily: classical EdDSA minting never touches it, and requesting a PQ mint on
  an older runtime fails with an actionable error instead of `ERR_REQUIRE_ESM`.
- New dependency: `@noble/post-quantum` 0.6.1 (exact pin).

### Security
- **`scan`, `verify`, `status`, and `mcp-status` now cover the Claude Code
  project-scope MCP config `.mcp.json` (release-test P1).** The file sits at the
  project root and is committed to repos, yet none of the four surfaces read it:
  a planted Anthropic key inside `mcpServers.*.env` survived `scan` (exit 0),
  `mcp-status` ("No MCP configurations found"), and `verify` (PASS). The scan
  and verify file lists gain `.mcp.json` (via `@opena2a/credential-patterns`
  0.1.3, lockstep-asserted), and MCP discovery now enumerates the project-scope
  `.mcp.json` alongside the five per-user client configs, so `mcp-status`
  reports its servers and `protect-mcp` can wrap them.
- **`.cursor/mcp.json` is now actually scanned** — the config-file list carried
  a `.curse/mcp.json` typo since the entry was introduced, so Cursor's
  project-scope MCP config never matched (fixed in
  `@opena2a/credential-patterns` 0.1.3).
- **The scan list also gains `.mcp/config.json`, `.claude/settings.local.json`,
  and `.windsurf/mcp.json`**, and the global scan (`scan` without
  `--no-global`) now reads `~/.claude.json` (the store `claude mcp add` writes
  user-scope MCP `env` into) and `~/.cursor/mcp.json`. Known limit, disclosed:
  individual lines over 4096 chars are skipped by the ReDoS guard, so a fully
  minified config can pass unscanned — structural JSON parsing for config
  files is tracked as follow-up work.

### Fixed
- **Database connection-string patterns no longer flag credential-free URIs.**
  `postgresql://localhost:5432/mydb` — the canonical Postgres MCP server
  layout — produced `CRITICAL PostgreSQL Connection String` with nothing
  secret in it. The `mongodb`/`postgres`/`mysql`/`redis` patterns (via
  `@opena2a/credential-patterns` 0.1.3) now require an embedded secret: a
  userinfo password (`user:pass@`, `:pass@`), a
  `password=`/`pwd=`/`sslpassword=` query param (case-insensitive), or —
  redis only — any single userinfo token (`redis://your-password@host`; pre-ACL
  Redis has no usernames; the literal Redis 6+ ACL username `default@` is
  carved out). Plain `mongodb://` URIs are now covered (the old pattern
  matched only `mongodb+srv://`). Env-var-interpolated passwords
  (`postgres://app:${POSTGRES_PASSWORD}@db` — the shape this tool tells you
  to use) are no longer flagged, while a real password next to an
  interpolated host still is; matches cannot cross JSON string boundaries on
  minified content (no false positives, no destructive over-masking in
  `clean-history`); and every run is length-bounded so scheme-stuffed
  one-line files scan in linear time. Also fixes a quick-check derivation bug
  that silently skipped plain `redis://` lines containing a `${VAR}` — a real
  redis password on such a line was never scanned. Deliberate narrowing:
  username-only URIs for postgres/mysql/mongodb (`postgres://user@host`) no
  longer match — a username without a password is not a credential.
- **`redis` and `mysql` findings now carry a `Fix:` line** — both ids were
  missing from the per-pattern fix-guidance map, so their findings were dead
  ends; a regression test asserts every database connection-string finding
  has one. Also fixes the `status` verdict grammar ("1 unblocked credential
  needs review").

## [0.19.1] - 2026-07-16

### Security
- **The generated guard hook now inspects the full command instead of truncating at the first quote (#99).** The hook extracted the Bash command with `grep -o '"command":"[^"]*"'`, which stops at the first `"`. Any command containing a quote — `x="" ; cat .env`, `eval "$(secretless-ai env)"`, `echo ""; secretless-ai secret get X --force` — was truncated before the dangerous part and slipped past every hook guard. The hook now parses the command with `python3`'s JSON reader when available, and **fails closed**: on any extraction failure or empty output it falls back to the grep extraction rather than skipping guards. The `env` subcommand match also gained a proper word boundary, so it catches `$(secretless-ai env)` (terminated by `)`), `env;`, and `env|` while still ignoring the word `environment`. The native `permissions.deny` rules already enforced these at the Claude Code layer; this restores the guard hook as a real second layer rather than one a single quote walks through.
- **`secretless-ai vault exec <ns> -- env` / `-- printenv` is now blocked (#99).** `vault exec` injects an identity-vault namespace credential into the child process, which `env`/`printenv` would then print — the same shape as the already-denied `run -- env`, but it had no deny rule or hook arm. Added `Bash(*secretless-ai vault exec*-- env*)` / `-- printenv*` deny rules and a matching hook arm, with a word boundary so `-- envsubst` (a legit templating program) is not over-blocked.

These harden the best-effort Claude Code layers that back the primary tool-level `env` gate shipped in 0.19.0. Re-run `secretless-ai init` to regenerate the hook and deny rules. Two honest, adversarially-reviewed notes on the heuristic hook layer: (1) now that the full command is inspected, a benign command that merely *mentions* a secret-file path inside a quoted string (e.g. `git commit -m "fix cat .env parsing"`) is also flagged — safe-direction (it blocks, never leaks), recoverable by rephrasing, and the deliberate trade-off of not truncating; (2) command-string matching stays heuristic (e.g. a path-prefixed `-- /usr/bin/env` is not matched). The tool-level agent-runtime gate on `env` is the enforcing layer; the hook is defense-in-depth.

## [0.19.0] - 2026-07-16

### Security
- **`secretless-ai env` now refuses to print secrets when it runs inside an AI-agent runtime.** `env` dumps every stored secret as plaintext `export` statements — it exists only for the user's shell-profile `eval` hook, which runs in the user's own shell. `secret get` was TTY-guarded and `run -- env` was denied, but the bare `env` command was unguarded, so an agent in a "protected" project could exfiltrate the entire machine-global store with one documented command. The primary, spelling-independent fix is in the tool: `env` checks for a known agent-runtime marker (`CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CURSOR_TRACE_ID`, `AIDER_MODEL`) and, if set, emits nothing and points to `secretless-ai run --only NAME -- <cmd>` instead. Because the check is on the runtime, not the command text, it holds however the agent spells the invocation (`npx …@latest env`, quoted `env`, a shell variable, a tab) — every one of which slips past a deny-glob or a grep in the guard hook. The shell-profile hook is unaffected (no marker set in a normal shell); inside an agent shell, secrets no longer auto-load into the environment, so use `run --only` for the specific secret a command needs. Enumeration-limited by nature (it can only name agents that set a marker), so it is backed by two best-effort Claude Code layers below.
- **Best-effort Claude Code layers for the naive form: a `Bash(*secretless-ai env*)` deny rule and a guard-hook arm.** These block the literal `secretless-ai env` before it runs. They are heuristic, not airtight — a deny glob and a grep over the command string can be evaded by re-spelling — so they back the runtime gate above rather than standing alone. Known limits, tracked for follow-up: the deny glob also blocks benign strings containing `secretless-ai env` (e.g. `env --help`, a commit message), and the guard hook's grep-based JSON parsing is defeated by an embedded quote.
- **The generated guard hook's entire Bash-command branch was dead code; it now runs.** Every Bash tool call died at the `FILE_PATH` extraction under `set -euo pipefail` (a `grep` with no match returns non-zero) before reaching any command guard, so none of the hook's Bash protections (`cat .env`, `run -- env`, `secret get --force`, ...) ever fired. The JSON-field extractions now tolerate a no-match (`|| true`), reviving the branch. Native `permissions.deny` rules already enforced these at the Claude Code layer, so this restores the hook as a (best-effort) second layer rather than closing an open hole. Found by release-test 2026-07-16. Re-run `secretless-ai init` to regenerate the hook and deny rules.

### Fixed
- **`setup --check` prints a coherent report when no `.secretless` manifest exists (#97).** It used to render "Missing: 0 required", an empty "Missing secrets:" block, and a FAIL telling the user to configure secrets the same output said don't exist. The no-manifest path now stops after the create-a-manifest hint with a single `FAIL: No .secretless manifest to check against.` line. Exit codes unchanged (still 1, so CI gates keep failing on a missing manifest). Library surface: `SetupResult` gains `manifestFound`.
- **The broker assertion's `trust_class` claim now carries the abstract ATX trust class (e.g. `orders:read`) from the matched policy clause instead of duplicating the downstream `scope` (e.g. `orders.read`).** The two were conflated at minting, against the AAP broker profile §11 federation semantics — a v2 peer broker verifying the assertion needs the portable capability, not a deployment-local scope name. The grant resolver now injects the matched trust class into the resource binding (`ResourceBinding.trustClass`, resolver-populated, never authored in configuration); `mintBrokerAssertion` now throws if the field is missing rather than silently minting a token the pinned claim schema rejects (breaking only for direct library callers; the wired daemon path always injects). Regression-tested at the unit and end-to-end (conformance) layers. Pinned normatively by AAP-SPEC 0.3 §4.2.

### Added
- **`status --json` emits a machine-readable status document (#63).** Same envelope convention as `scan --json` (`{tool, version, ...facts, summary}`, camelCase); `summary.verdict` is one of `not-protected | protected-clean | protected-warnings` and `summary.warnings` always matches the human view's warning count (both derive from the same rows). Exit code stays 0; CI consumers gate on `summary.verdict`. `--help` now mentions `--json` on both `scan` and `status`.
- **`secret list` and `verify` disclose their scope (#89).** `secret list` names the backend and states the store is machine-global (shared across all projects); `verify` states it spans the project, global AI config (`~/.claude`), and current-shell env vars — so a green PASS is never mistaken for "this project only".
- **The broker strict-parses grant request bodies (#93).** `JSON.parse` is last-wins on duplicate members, so a duplicate-member smuggle inside the signed ATX credential was collapsed before the verifier could see it. `handleGrant` now runs atx-verify's fold-aware `firstDuplicateMember` over the raw body before any `JSON.parse` and refuses the request on the first colliding member at any depth (reject-side only; legitimate grants resolve unchanged). `@opena2a/atx-verify` bumped to 0.3.0, which also brings the declaredPurpose v1.1 TBS coverage fix into the broker's verify path.
- `mintBrokerAssertion` accepts an injectable `jti` (defaults to the existing 16-random-bytes-hex behavior) so conformance fixtures can be minted deterministically (AAP-SPEC §9.7).

### Docs
- **README now documents the secret workflow**: `secret set` / `import` / `run --only`, `secret get` TTY-gating, and how to ask an AI assistant to use a stored key without exposing its value. `docs/testing/release-smoke.md` expanded to full command-surface parity (#60), with every expected output verified against the built CLI.

### Changed
- **The ATX (Agent Trust eXtension) verifier now comes from `@opena2a/atx-verify` instead of a copy bundled in the broker.** The verifier was previously maintained as `src/broker/atx.ts` here *and* in the AIM SDK — two copies of byte-sensitive canonicalization (RFC 8785 JCS) that had to stay in lockstep with the Go/Python reference verifiers. It is now the single, separately-tested, SLSA-attested `@opena2a/atx-verify` package (consumed by both), closing that drift window. The broker's behavior is unchanged: the same Ed25519 verification over the same v1.0/v1.1 canonical payloads, proven by the AAP conformance test running against the package.

### Removed (breaking — library surface only; CLI unaffected)
- **`secretless-ai` no longer re-exports the ATX verifier *values* `LocalAtxVerifier`, `canonicalPayload`, `normalizeRfc3339`, and `SUPPORTED_ATX_VERSION`.** Import them from `@opena2a/atx-verify` directly (a CommonJS package cannot statically re-export the ESM-only verifier's values). The ATX *types* (`Atx`, `AtxVerifier`, `ResolutionContext`, `AtxTrustAnchors`, etc.) are still re-exported, since they appear in secretless's own public broker types. No CLI command or behavior changes.

## [0.18.2] - 2026-06-01

### Fixed
- **`init` now migrates an existing config instead of only appending to it.** Older `init` was additive-only: it appended new deny rules and wrote the guard hook only when absent, so upgrading the CLI did **not** propagate template/hook fixes to an already-initialized project — the broad `Read(.env*)` / `Grep(*.env*)` globs and a stale `secretless-guard.sh` survived, re-blocking `.env.example` while `init` reported "Already up to date". `init` now (1) prunes a known deprecated-rule list (`DEPRECATED_DENY_RULES`) after re-adding the current enumerated rules, so a real env file is never left unprotected, and (2) regenerates the managed guard hook and rewrites it in place when its content is stale. Output reports `removed N deprecated patterns` and `~ .claude/hooks/secretless-guard.sh (refreshed to current version)`; an already-current config is still a clean no-op (no churn on re-run).
- **`secretless-ai env` skips secret names that aren't valid shell variables instead of breaking the whole shell.** Stored secret names allow `-` (e.g. `vault-name`), but a shell identifier cannot — so `export vault-name='…'` made the shell reject the entire `eval "$(secretless-ai env)"`, printing `export: not valid in this context` on **every** command in profiles that use the eval hook, and silently dropping all the other secrets too. `env` now skips names that aren't valid POSIX shell identifiers (matching the validation `import` already applies), exports the rest normally, and reports the skipped names as a leading shell comment (a no-op inside `eval`, visible on direct invocation) that names them and how to fix — no secret value is exposed. Public API: `isValidShellIdentifier`.

## [0.18.1] - 2026-06-01

### Fixed
- **`scope` with no subcommand prints usage cleanly instead of an error.** Bare `secretless-ai scope` showed `Unknown scope command: (none)` and exited 1 (reads like an error for an empty invocation); it now prints the usage block and exits 0, mirroring the `secret` fix in #80. A real unrecognized subcommand (`scope bogus`) still errors with `Unknown scope command: bogus` and exits 1.
- **`scan` warns on an unrecognized flag instead of silently ignoring it (#81).** A typo like `--show-placeholder` (for `--show-placeholders`) used to no-op with no feedback. `scan` now prints `Warning: ignoring unknown flag --x` plus the supported-flag list. The warning is non-fatal — the exit code still reflects findings.
- **`secret` with no subcommand prints usage cleanly instead of an error (#80).** Bare `secretless-ai secret` showed `Unknown secret command: (none)` (which reads like an error for an empty invocation) and now prints the usage block and exits 0. A real unrecognized subcommand (`secret bogus`) still errors with `Unknown secret command: bogus` and exits 1.
- **`init` no longer blocks committed env template files (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`).** These hold placeholders, not real secrets, and are meant to be read/edited/committed, but the generated config blocked them three ways: the `Read(.env*)` / `Grep(*.env*)` deny globs, the guard hook's `.env.*` dotfile arm, and the `.aiderignore` `.env.*` entry. Deny rules now enumerate real env files (`.env`, `.env.local`, `.env.*.local`, `.env.{development,production,staging,test}`, `*.env`) instead of a broad `.env*` glob — Claude Code deny rules can't negate and `deny` beats `allow`, so enumeration is the only way to let templates fall through. The guard hook exempts `*.example` / `*.sample` / `*.template` / `*.dist` basenames before any block logic, and the generated `.aiderignore` un-ignores them. Real env files and other secrets stay blocked. Matches the env-file policy shipped to the user's global config.

## [0.18.0] - 2026-06-01

### Added
- **`scan --json` emits a single valid JSON document (issue #63).** Previously the flag printed the human report. Output is `{ tool, version, findings[], summary: { total, critical, high, placeholdersSuppressed } }` on stdout only (errors go to stderr); the exit code still signals findings (1) vs clean (0) for CI gating.
- **`scan --show-placeholders` and a "N values hidden" hint.** When the scanner suppresses values that look like known examples / placeholders (`AKIA…EXAMPLE`, `sk-…FAKE…`, `your_api_key`, an `example.com` connection string), it now reports how many were hidden and how to reveal them, instead of a silent "No hardcoded credentials found." This fixes the new-user trap of testing with obvious placeholder values and concluding the scanner is broken, and surfaces the over-suppression case where a real-looking value sits behind a documentation host.

### Fixed
- **`scan` and `verify` now use the same detection predicate, and `verify` no longer hides values silently (issue #64).** `verify` detected credentials in AI-context files with a raw `pattern.regex.test(line)` that applied no known-example / placeholder suppression, while `scan` routed through `findRealMatch` (which applies `isKnownExample`). A placeholder like `sk-ant-api03-FAKE…` in `.env` was suppressed by `scan` but flagged by `verify` — the two disagreed on the same file. `verify` now shares `scan`'s detection path. Because `verify` answers a higher-stakes question ("is a real key exposed right now?"), it also **counts and surfaces** suppressed values (`N values looked like a placeholder and were not counted — confirm with scan --show-placeholders`), so it never reports a green PASS while silently hiding a value whose random body happens to contain a token like `sample`/`xxx` or that sits on a `# example` line.
- **Guard hook now blocks secret files by extension suffix, not only literal dotfiles (security).** The generated `.claude/hooks/secretless-guard.sh` matched secret extensions with an anchored `^\.key`-style regex, so it blocked `.key`/`.env` but silently **allowed** the far more common `server.key`, `client.pem`, `id_rsa.pem`, and `prod.env` forms, and was case-sensitive, so `.KEY`/`server.PEM` bypassed it on case-insensitive filesystems. Matching is now a case-insensitive suffix check against the lowercased basename, with `.env` families and credential dotfiles handled explicitly. Added `Read(*.env)` / `Read(*.crt)` (and `Grep` equivalents) to the deny-rule backstop, closing the `prod.env` double-gap. Regression test feeds `server.key`/`prod.env`/`.KEY` to the generated hook and asserts deny.
- **Scanner now reads standalone private-key files (`*.pem`, `*.key`, `*.p12`, `*.pfx`).** These extensions were in the block list but were never fed to the scanner, so a private key in `server.key` or `id_rsa.pem`, the most common on-disk layout, reported clean. Text key files are scanned for a PEM `PRIVATE KEY` block (public certs in `.crt`/`.pem` do not match, so no false positive); binary PKCS#12 keystores are flagged by existence.
- **Confidence scoring no longer under-rates fixed-structure keys.** A real AWS access-key ID (`AKIA...`) displayed as `low (0.58)` because pattern specificity counted only the literal prefix, making the `high` tier unreachable for AWS / Stripe / Slack / GitHub keys. Specificity now also credits a fixed/bounded length quantifier over a restricted character class, and structurally-definitive patterns are floored at the `high` tier in real source/config locations (fixture and docs paths are left unfloored so demo creds don't outrank production ones). A fixed-structure AWS key in a source file now scores `high (0.85)`.
- **`diff` outside a git repository no longer dead-ends.** The "Not a git repository" message now explains what `diff` does and gives a next step (`git init`), satisfying the no-dead-ends rule.

## [0.17.0] - 2026-04-30

### Added
- **Per-finding confidence score on `ScanFinding`.** Every finding now carries a deterministic composite score in `[0, 1]` plus a tier label (`high` / `medium` / `low`). Inputs are pattern specificity (length of literal regex prefix), value entropy (Shannon over the matched value), value length tier, and path tier (live source / config files outrank docs and fixture paths). Renders inline as `Confidence: high (0.92)` so users can prioritise on noisy repos. Findings within the same severity are now sorted by descending confidence. Public API: `scoreFinding`, `formatConfidence`, `patternSpecificity`, `valueEntropy`, `lengthTier`, `pathTier`, `ConfidenceTier`, `ConfidenceBreakdown`. New CLI flag `scan --min-confidence <n>` (`n` in `[0, 1]`) drops findings below the threshold.
- **`secretless-ai ignore <path>` subcommand.** Convenience wrapper that appends a gitignore-style glob to `.secretlessignore`. Idempotent — re-running with the same pattern is a no-op. Creates the file with a header comment if it doesn't exist; otherwise appends and ensures a trailing newline. Validates input against path traversal (`..`), absolute paths, and symlinks at the target. Accepts an explicit `--pattern` form for non-path globs (`*.golden.txt`, `**/__fixtures__/**`).
- **`secretless-ai diff <ref>` subcommand.** Concrete change-set audit of secretless-managed files (`.claude/settings.json`, `.secretlessignore`, `.secretless-rules.yaml`) versus a git ref. Default ref is `HEAD`. Output is a unified-diff-like report with per-file `INTRODUCED` / `MODIFIED` / `REMOVED` / `UNCHANGED` tags. Missing or invalid refs return distinct exit codes (1 for malformed input, 2 for git errors). Refs are validated against `[A-Za-z0-9._/^@~+-]` only — shell metacharacters and refs starting with `-` are rejected; `execFileSync` is invoked with an argv array, never a shell string.
- **"Looks like a test fixture" inline hint** on `scan --no-ignore` findings whose path matches the default-ignore list. Helps users distinguish real-vs-fake findings without re-suppressing them. The hint is also exposed on the public `ScanFinding` interface as `looksLikeFixture: boolean`.

### Changed
- `ScanFinding` interface gained three required fields: `confidence: number`, `confidenceTier: 'high' | 'medium' | 'low'`, `looksLikeFixture: boolean`. Library consumers that destructure `ScanFinding` will need to handle the new fields (additive, not breaking — JSON consumers see strictly more keys).
- `printFindings` (CLI) renders the confidence tier under each finding. Tier colour mirrors the severity ramp — `high` green, `medium` yellow, `low` dim — so a low-confidence high-severity finding visually de-emphasises without disappearing.

### Security

- **The `Verify:` and `Fix:` lines quote the paths they print.** Those paths are filenames from the scanned repository — attacker-controlled by definition — and the lines exist to be copy-pasted into a terminal. A symlink named `a"; id; echo "b` previously produced a command that closed the quote and ran `id`.

### Internal
- New `src/confidence.ts` module + 32-test `confidence.test.ts` covering pattern-specificity escape handling, entropy noise floor, length-tier monotonicity, path-tier classification (Windows path normalisation, mixed-case, `*.test.ts` suffix), composite determinism, monotonicity-on-every-axis, and tier-rendering.
- New `src/commands/ignore.ts` + 20-test `ignore.test.ts` covering file creation, append behaviour, idempotence (whitespace and `./` normalisation), traversal rejection (Unix absolute, Windows drive prefix, parent traversal, nested `..`), symlink rejection, 1MB size cap, and non-file refusal.
- New `src/commands/diff.ts` + 14-test `diff.test.ts` exercising real `git init` repos in tmpdirs: clean diff, additions-only (synthesised diff for untracked files), mixed adds/mods, missing ref, malformed ref (shell metacharacter rejection, `-` prefix rejection, `..` rejection, length cap), not-a-git-repo handling.
- Test count: 915 → 988 (+73 new). Build is `tsc` clean. No public API removals.

## [0.16.4] - 2026-04-29

### Added
- `.secretlessignore` — gitignore-style file at the project root that suppresses scan findings for paths the user has marked as fixtures or examples. The default-ignore list is applied automatically on top of the user file and covers `__tests__/`, `__fixtures__/`, `test/`, `tests/`, `test-server/`, `docs/vhs/`, `examples/`, `e2e/`, `.golden/`, `node_modules/`, `dist/`, `build/`. Each default path is justified by a real-world false positive observed during dogfooding (e.g. `docs/vhs/setup-lab.sh` fixture credentials, `test-server/agents.js` adversarial system prompts). Negative patterns (`!docs/vhs/`) re-enable scanning for a default-ignored path. New CLI flag `--no-ignore` on `scan` and `scan-staged` disables both the user file and the defaults. Public API: `loadSecretlessIgnore`, `buildMatcher`, `DEFAULT_IGNORE_PATTERNS`, `IgnoreMatcher`.
- `secretless-ai feedback` — opt-in subcommand that prints the star/issue/discussion links. Replaces the unconditional "Helpful? Star the project" line that previously trailed every `init` invocation.

### Changed
- **`init` output redesigned** per CISO Rule 11. Collapsed the redundant Detected + Configured pair into one line (`Configured: Claude Code (1 of 1 detected)`); the previous `+` / `*` glyph distinction was confusing. The `Modified:` line now says exactly what changed (`.claude/settings.json (added 21 deny patterns)`) instead of just naming the file. Dropped the misleading `Done. Secrets are now blocked from AI context.` line — `init` configures hooks, the actual blocking happens at AI-tool invocation. Added a `Next steps:` block (Verify / Scan / Status) so every run ends in a runnable verb. Removed the unconditional star-prompt line from `init` output (now lives in `secretless-ai feedback`). `init` re-runs over an already-configured project now print `Already up to date. No files changed.` instead of an empty Created/Modified pair.
- **`status` output redesigned** per CISO Rule 11. The previous five sub-blocks (top-level metrics, Session, Broker, Transcript Protection, transcript line counts) collapsed into one Observations table. Every warning row ends in `→ <runnable command>` so the user has no dead end. Glyphs differentiate satisfied (`✓`) from needs-action (`⚠`). The Verdict line now reflects the warning count instead of a bare `Protected: Yes` — `Protected — Clean`, `Protected (4 unblocked credentials need review)`, `Not protected. Run secretless-ai init to install hooks.`
- **Catalog re-pin to `@opena2a/credential-patterns@0.1.1`** with three new false-positive suppression branches (mirrored locally to keep the lockstep test green): block-comment marker recognition for line-level `'''`/`"""`/`<!--`/`-->`/`*` (JSDoc continuation lines now allowlisted when paired with the substring `example`), bare `'fake'` in `PLACEHOLDER_INDICATORS` (replaces `'fake_'` and `'fake-'` — case-insensitive substring match accepts `sk-proj-fake1234567890abcdefghijklmnop`), and a localhost-bound demo-password allowlist for connection strings (`postgres://admin:password123@localhost`/`@127.0.0.1`/`@[::1]` recognized as tutorial fixtures).
- `init` `InitResult` interface gained `denyRulesAdded` (delta this run) and `denyRulesTotal` (full count after merge). The existing `denyRuleCount` on `StatusResult` is unchanged.

### Security

- **The `Verify:` and `Fix:` lines quote the paths they print.** Those paths are filenames from the scanned repository — attacker-controlled by definition — and the lines exist to be copy-pasted into a terminal. A symlink named `a"; id; echo "b` previously produced a command that closed the quote and ran `id`.

### Internal
- New `src/secretlessignore.ts` parser (gitignore-subset glob → regex) plus 18-test `secretlessignore.test.ts` covering defaults, user file, negation, glob semantics, anchor rules, Windows path normalization, and path-traversal rejection. New `scan()` integration tests assert default-ignore suppression of fixture paths and `--no-ignore` round-trip.
- `walkSourceFiles` now consults the ignore matcher at directory level (prunes whole subtrees) and again at file level (file-name globs).

## [0.16.3] - 2026-04-29

### Added
- Runtime dependency on `@opena2a/credential-patterns@0.1.0` (exact pin). PR 1 of the credential-pattern consolidation lifted the local pattern catalog into a shared, SLSA-attested package so secretless-ai and hackmyagent stop maintaining duplicate regex copies. This release brings the package in as a peer of the local catalog and asserts they stay in lockstep.
- `src/lockstep.test.ts` — equivalence test that fails CI on any drift between local `src/patterns.ts` and the package: pattern count, per-pattern (`id`, `name`, `regex.source`, `regex.flags`, `envPrefix`, `category`), `CREDENTIAL_PREFIX_QUICK_CHECK`, `KNOWN_EXAMPLE_KEYS`, `PLACEHOLDER_INDICATORS`, `SECRET_FILE_PATTERNS`, `CONFIG_FILES`, `SOURCE_FILE_EXTENSIONS`, `SOURCE_SKIP_DIRS`, plus functional parity of `isKnownExample` / `findRealMatch` on a panel of allowlist-branch oracle inputs. Mutation-tested: a regex change or allowlist addition on either side fails this test with a precise per-pattern diagnostic.

### Changed
- No behavior change. No public API change. `import { CREDENTIAL_PATTERNS } from 'secretless-ai'` still resolves to the local CommonJS-friendly catalog. `scan` / `verify` / `init` / `transcript` / `mcp` / `doctor` / `history` / `scan-staged` paths continue to read from `src/patterns.ts`. The full migration that moves consumer code onto the package directly requires converting secretless-ai from CommonJS to ESM (the package is ESM-only) and is tracked separately for a future major version.

## [0.16.2] - 2026-04-28

### Fixed
- **Read-only commands no longer trigger Touch ID or "1Password Access Requested" dialogs.** `secretless-ai backend` (no subcommand) and the local→keychain upgrade in `createBackend` were calling `isKeychainAvailable()` (`security default-keychain` — can fire Touch ID on Macs with biometric-locked keychains) and `isOnePasswordAvailable()` (`op account get` — fires the "Allow Terminal to get CLI access" dialog on Macs with the 1Password desktop app). A first-time user running `npx secretless-ai backend` to inspect available backends would see these prompts and reasonably uninstall. Split each probe into a `*Likely()` variant (cheap PATH/platform check, never spawns a process) and the existing `*Available()` variant (active probe, kept for genuine pre-flight on `backend set <type>` and `migrate`). Read-only display paths now use `*Likely()`. Regression test in `src/commands/backend.silence.test.ts` asserts `runBackend([])`, `runStatus`, and `createBackend('local')` never invoke `security` or `op` via `child_process`. Public API gains `isKeychainLikely` and `isOnePasswordLikely` exports.

## [0.16.1] - 2026-04-28

### Fixed
- **Telemetry exit-path coverage** (#61). Every command now emits exactly one telemetry event regardless of which exit path it takes. Previously, ~50 `process.exit()` calls in `src/commands/*.ts` bypassed the `try/finally` in `src/cli.ts`, so failure paths (`scan` with findings, `verify` FAIL/WARN, `doctor` unhealthy, every command's error branch) emitted no telemetry. Adoption metrics were biased toward "everything always works." All command handlers now return their exit code; `process.exit()` lives only in `main().then()` at `src/cli.ts:178`. Exit codes preserved across the surface (including `vault exec` upstream-process exit, `run` child-process exit). The `hook --check-only` fast path retains its silent-and-fast contract intentionally and is excluded from telemetry by design.

## [0.16.0] - 2026-04-27

### Added
- Tier-1 anonymous usage telemetry via `@opena2a/telemetry@0.1.2` and `@opena2a/cli-ui@0.4.0`. `secretless-ai --version` now prints the disclosure line; `secretless-ai telemetry [on|off|status]` inspects/toggles. Disable per-invocation with `OPENA2A_TELEMETRY=off`, persistently with `secretless-ai telemetry off`, audit payloads with `OPENA2A_TELEMETRY_DEBUG=print`. README §Telemetry documents the schema and links to [opena2a.org/telemetry](https://opena2a.org/telemetry). Default ON; opt-out is one env var or one subcommand.
- `docs/testing/release-smoke.md` — first release-smoke for this repo, covering build/help/version + the seven telemetry checks.

### Changed
- `src/cli.ts` `main()` is now async to support `await tele.flush()` before `process.exit()` (prevents subcommand telemetry events from being lost on exit). The dispatcher logic moved into a sync `dispatch()` helper to keep the case statement compact.
- First runtime dependency: `@opena2a/telemetry` + `@opena2a/cli-ui`. Previously the package had only devDependencies.

## [0.15.1] - 2026-04-22

### Changed
- **Release pipeline**: secretless now publishes via npm Trusted Publishing with SLSA v1 provenance. GitHub Actions exchanges an OIDC token with the npm registry at publish time — no long-lived `NPM_TOKEN` in the repo or workflow. Consumers verify provenance via `npm view secretless-ai dist.attestations --json`.
- **Lockfile sync**: `package-lock.json` realigned with `package.json` after a prior drift where the lockfile stayed at 0.14.1 during the 0.15.0 bump.

## [0.15.0] - 2026-04-14

### Added
- **Broker AIM auth**: `broker start --aim-token <token>` (or `SECRETLESS_AIM_TOKEN` env var) sends `Authorization: Bearer` on AIM requests. Without it, AIM returns 401 and trust-score / capability policy constraints cannot be satisfied.
- **Broker AIM reachability probe**: on startup, the broker pings AIM `/health` once and reports the result via `aimReachable` in `/status` and `broker status` output.
- **Audit log for AIM 4xx responses**: AIM 4xx failures now emit an `aim_auth_error` audit event (was silently swallowed). Helps diagnose auth misconfiguration.

### Changed
- `broker status` now displays `AIM: not configured` / `AIM: configured (reachable)` / `AIM: configured (unreachable)` instead of the misleading `AIM: connected`. **BREAKING**: the `aimConnected` field in `BrokerStatus` is split into `aimConfigured` (was `--aim-url` passed) + `aimReachable` (actually responded). Downstream TypeScript consumers of `BrokerStatus` will need to update.
- `broker status` CLI queries the running daemon over its HTTP `/status` endpoint to report live `Policies`, `Requests`, `aimConfigured`, `aimReachable` counts. Previously reported cached zeros from the PID file.

### Fixed
- `broker status` no longer reports `Policies: 0 / Requests: 0 / AIM: not connected` regardless of live state.
- `scan-staged` (pre-commit hook) now applies the same known-example-key allowlist as `scan`. Previously, docs or CHANGELOG entries that referenced public example keys like `AKIAIOSFODNN7EXAMPLE` could trigger false-positive commit blocks.
- `isKnownExample` operator precedence: the comment-marker check used `A && B || C` which bound as `(A && B) || C`, causing any line containing `#` to enter the inner block regardless of 'example' context. Fixed to `A && (B || C)` (#50).
- Known-example keys no longer shadow real credentials on the same line. Both the cross-pattern case (e.g. `AKIAIOSFODNN7EXAMPLE` + real `ghp_…` on one line) and the within-pattern case (two AWS keys, first example second real) are now detected. Scanner iterates every match via `matchAll` instead of breaking at the first (#51).
- `scan --help`, `init --help`, `broker start --help` and every other `<subcommand> --help` now print help instead of running the subcommand. Previously `init --help` created a literal `--help/` directory in the user's cwd and `broker start --help` launched the daemon.

### Documentation
- New README "Architecture" section names the three tiers (SDK, Vault Exec, Broker) and states that AIM is optional — Tiers 1 and 2 work against any supported backend.
- New guide `docs/use-cases/bring-your-own-vault.md` — connect Secretless to an existing HashiCorp Vault / 1Password / GCP Secret Manager with round-trip verification using stock vault tooling.
- New guide `docs/use-cases/run-broker.md` — when to run the broker daemon, how to write policies, AIM-connected mode, audit log.
- `team-setup.md` now flags the 1Password desktop biometric prompt on first `backend` run.

## [0.14.0] - 2026-04-01

### Added
- **NanoMind guard integration**: MCP protection now screens env var values for prompt injection patterns (role-switching, instruction override). Warns during `protect-mcp` when suspicious values are detected.
- **NanoMind engine integration**: `scan --explain` generates rich context-aware explanations for each finding using NanoMind's local inference engine.
- Both integrations are optional. NanoMind packages are optional dependencies with graceful fallback when not installed.

## [0.13.0] - 2026-04-01

### Added
- **False positive reduction**: Known example keys (AWS `AKIAIOSFODNN7EXAMPLE`, Stripe test keys, etc.) and placeholder patterns (`your_`, `example`, `fake_`) are now excluded from scan results
- **Scan fix guidance**: Each finding includes actionable fix text with rotation URLs (e.g., "Move to env var ANTHROPIC_API_KEY. Rotate at console.anthropic.com")

### Changed
- Split `commands/secrets.ts` (409 lines) into `secrets.ts` (234) + `env-run.ts` (177)
- TypeScript upgraded to 6.0.2, vitest to 4.1.2
- tsconfig: `module` and `moduleResolution` set to `Node16`

### Fixed
- All 5 npm audit vulnerabilities resolved (esbuild/vite chain via vitest 4.x)

## [0.12.7] - 2026-04-01

### Added
- Source code scanning: `scan` now detects hardcoded credentials in `.js`, `.ts`, `.py`, `.go`, `.java`, `.rb`, and 10+ more file types by walking the project tree
- Test files (`.test.*`, `.spec.*`, `__tests__/`) are excluded by default -- use `--include-tests` to opt in
- `rules test` auto-detects bash command patterns when starting with known commands (`curl`, `wget`, `ssh`, `aws`, `docker`, etc.)

### Changed
- Split `cli.ts` (2336 lines) into 12 focused modules under `src/commands/` for maintainability
- `watch` with no subcommand now shows usage help instead of silently starting
- `setup --check` with no `.secretless` manifest now returns failure instead of misleading PASS

### Updated
- typescript: ^5.3.0 -> ^5.9.3
- vitest: ^1.2.0 -> ^2.1.9
- @types/node: ^25.2.3 -> ^25.5.0

## [0.12.5] - 2026-03-18

### Changed
- `verify` hides unset env vars by default — shows count with `--all` flag to list them
- Transcript findings collapsed by credential type (e.g., "found in 16 transcript files")

### Added
- Quick start section in `--help` output (scan -> init -> verify)

## [0.12.4] - 2026-03-14

### Fixed

- Fix `--only` flag case-insensitive matching in `run` command -- `--only shodan_key` now correctly matches secrets stored as `SHODAN_KEY`

## [0.12.3] - 2026-03-12

### Security

- Replace SHA-256 key derivation with scrypt + random salt for MCP backup encryption
- Add bearer token authentication to credential broker HTTP transport
- Add HMAC-SHA256 integrity protection to session state files
- Fix Windows shell injection in `doctor --fix` (execFileSync instead of execSync)
- Add XML escaping for LaunchAgent plist generation to prevent injection
- Add symlink traversal protection in transcript directory walker
- Add response size limits (1 MB) to AIM client to prevent memory exhaustion
- Restrict file permissions on wrapper installation (0o700 dirs, 0o600 files)
- Add security headers (X-Content-Type-Options, Cache-Control) to broker responses
- Move rate limiter evaluation after other policy checks to prevent slot exhaustion
- Add secret name validation regex to prevent injection via malformed names

## [0.12.2] - 2026-03-11

### Fixed

- YAML parser key regex now handles underscores, hyphens, and numbers in section names
- Improved error messages for `secret set` and `scan` when given invalid paths

### Changed

- Documentation updates for custom deny rules

## [0.12.1] - 2026-03-11

### Fixed

- `rules import` command ENOENT error when importing rules files
- Distinguish between empty and missing rules files in validation

### Added

- `--env`, `--file`, and `--bash` flags to `rules test` for targeted rule testing

## [0.12.0] - 2026-03-11

### Added

- Custom deny rules via `.secretless-rules.yaml` configuration files
- User-defined patterns for blocking env vars, files, and bash commands
- `rules` CLI command with `init`, `list`, and `test` subcommands

## [0.11.7] - 2026-03-11

### Security

- Block `python3`/`node` env var extraction in hooks
- Block `eval`-based credential extraction attempts

## [0.11.6] - 2026-03-11

### Security

- Encrypt MCP backup files with AES-256-GCM

## [0.11.5] - 2026-03-11

### Fixed

- `--force` flag parsing order in `secret get` CLI command

## [0.11.4] - 2026-03-10

### Added

- GCP Secret Manager backend (`gcp-sm`)
- Graceful fallback when configured backend (1Password, Vault) is unavailable

### Fixed

- `migrate` command failing to find secrets from keychain/1Password backends
- Vault env var validation before migration
- Vault status display in `backend` command

### Security

- Harden against adversarial bypass attempts

## [0.11.0] - 2026-03-04

### Added

- v2 session management with phantom refs for automatic cleanup
- Structured audit events for secret access tracking
- Cache preloading to eliminate 1Password Touch ID popups
- AWS scope discovery and shell history scanning
- Per-key service names in keychain backends

### Fixed

- Touch ID authentication using LAContext via compiled Swift binary
- Dead-end CLI outputs now include actionable hints
- Duplicate vault creation in 1Password backend
- 1Password approval dialog now shows "Secretless" instead of "terminal"

### Changed

- Hardened `.gitignore` with additional secret and environment patterns

## [0.10.0] - 2026-03-02

### Added

- Credential scope discovery (detect where each secret is used)
- HashiCorp Vault backend for secret storage
- `scope` CLI command for viewing credential usage

## [0.9.2] - 2026-03-02

### Added

- `broker start`, `broker stop`, `broker status` CLI commands
- TTL-based encrypted cache for keychain/1Password backends to reduce OS auth prompts

## [0.9.0] - 2026-03-02

### Added

- `env` command for loading vault secrets into shell sessions
- Auto shell hook for transparent secret injection
- Broker service for identity-aware credential mediation

## [0.8.2] - 2026-02-27

### Fixed

- `secret set` hanging in interactive TTY mode

## [0.8.1] - 2026-02-26

### Changed

- Add star prompt and link to meta repository

## [0.8.0] - 2026-02-23

### Added

- OS keychain backend (macOS Keychain, Linux Secret Service)
- 1Password backend for secret storage and retrieval
- `secret get`, `secret set`, `secret list`, `secret delete` commands
- `backend` command for switching between storage backends
- MCP configuration protection (backup and sanitize MCP config files)

## [0.7.1] - 2026-02-18

### Added

- Shell profile doctor command (`doctor`) for diagnosing profile issues
- Cross-platform shell profile detection and auto-fix during `init`

## [0.7.0] - 2026-02-18

### Added

- `doctor` command for shell profile diagnostics

## [0.6.2] - 2026-02-17

### Fixed

- Use global regex in `transcript clean` to redact all occurrences of a credential

### Changed

- Ecosystem header banner with cross-links to related tools

## [0.6.0] - 2026-02-10

### Added

- MCP secret protection: detect and block credential exposure in MCP tool calls

## [0.5.0] - 2026-02-10

### Added

- Expanded credential pattern library from 12 to 49 patterns
- Coverage for AWS, Azure, GCP, Stripe, Twilio, SendGrid, and more

## [0.4.0] - 2026-02-10

### Added

- Transcript credential scanning and redaction (`transcript scan`, `transcript clean`)

### Fixed

- Complete redaction of partial credential matches
- Tightened Azure credential pattern to reduce false positives

## [0.3.1] - 2026-02-09

### Fixed

- Security findings: complete redaction and tighter Azure pattern matching

## [0.2.0] - 2026-02-09

### Added

- Global config scanning (`.env`, shell profiles, git configs)
- `verify` command for checking environment protection status
- Environment variable hints in scan output

### Changed

- Renamed package from `secretless` to `secretless-ai`

## [0.1.1] - 2026-02-09

### Fixed

- Homepage URL in package.json
- CLI package name references

### Added

- README documentation

## [0.1.0] - 2026-02-09

### Added

- Initial release: one-command AI secret protection
- Shell hook (`secretless-guard.sh`) for intercepting credential access
- Credential pattern matching for common API key formats
- `init` command for automated setup
- `scan` command for detecting exposed credentials

[0.12.2]: https://github.com/opena2a-org/secretless/compare/v0.12.0...HEAD
[0.12.1]: https://github.com/opena2a-org/secretless/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/opena2a-org/secretless/compare/v0.11.7...v0.12.0
[0.11.7]: https://github.com/opena2a-org/secretless/compare/v0.11.6...v0.11.7
[0.11.6]: https://github.com/opena2a-org/secretless/compare/v0.11.5...v0.11.6
[0.11.5]: https://github.com/opena2a-org/secretless/compare/v0.11.0...v0.11.5
[0.11.4]: https://github.com/opena2a-org/secretless/compare/v0.11.0...v0.11.5
[0.11.0]: https://github.com/opena2a-org/secretless/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/opena2a-org/secretless/compare/v0.9.2...v0.10.0
[0.9.2]: https://github.com/opena2a-org/secretless/compare/v0.8.2...v0.9.2
[0.9.0]: https://github.com/opena2a-org/secretless/compare/v0.8.2...v0.9.2
[0.8.2]: https://github.com/opena2a-org/secretless/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/opena2a-org/secretless/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/opena2a-org/secretless/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/opena2a-org/secretless/compare/v0.6.2...v0.7.1
[0.7.0]: https://github.com/opena2a-org/secretless/compare/v0.6.2...v0.7.1
[0.6.2]: https://github.com/opena2a-org/secretless/compare/v0.6.0...v0.6.2
[0.6.0]: https://github.com/opena2a-org/secretless/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/opena2a-org/secretless/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/opena2a-org/secretless/compare/v0.2.0...v0.4.0
[0.3.1]: https://github.com/opena2a-org/secretless/compare/v0.2.0...v0.4.0
[0.2.0]: https://github.com/opena2a-org/secretless/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/opena2a-org/secretless/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/opena2a-org/secretless/releases/tag/v0.1.0
