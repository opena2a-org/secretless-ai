# Install

Run Secretless with `npx`, install it from npm or Homebrew, or build it from source. The last section says how to check what a release installed and when Secretless reads a value it stores.

## npm

```bash
npx secretless-ai init          # run once, no install
npm install -g secretless-ai    # install globally
```

Requires Node.js 20.19 or later.

## Homebrew

```bash
brew install opena2a-org/tap/secretless-ai
```

## From source

```bash
git clone https://github.com/opena2a-org/secretless-ai.git
cd secretless-ai
npm install
npm run build && npm test
node dist/cli.js verify
```

## Upgrading

```bash
npm install -g secretless-ai      # or: brew upgrade opena2a-org/tap/secretless-ai
secretless-ai --version
```

If `protect-mcp` protects your MCP servers, run it once after upgrading to 0.24.0 or later:

```bash
npx secretless-ai protect-mcp
```

From 0.24.0 the `secretless-mcp` wrapper starts a server only from a config entry that `protect-mcp` has bound to the server's stored secrets. An entry runs the wrapper build its command names, so this check is made where that build is 0.24.0 or later. `protect-mcp` binds the entries it protected and lists each one it cannot bind, with what to change. In the configs it rewrites, it also moves each entry that runs through an earlier build's wrapper, or one whose version it cannot read, onto its own build's wrapper. Until it runs, the wrapper does not start a server from an unbound entry, and it prints this command. `mcp-status` names each entry that runs through a wrapper that does not check its binding, or one whose version it cannot read.

## Verifying what was installed

Every release publishes via npm Trusted Publishing with SLSA v1 provenance. No long-lived `NPM_TOKEN`. GitHub Actions exchanges its OIDC token with npm at publish time.

```bash
npm view secretless-ai dist.attestations --json
# Expects non-empty result with predicateType "https://slsa.dev/provenance/v1"
```

Secretless sends no credential value to OpenA2A: [telemetry](../README.md#telemetry) carries no values. It reads a value it manages when a command you run needs it: to give it to a process (`run`, the `env` shell hook, an MCP server set up by `protect-mcp`, git through `git-credential`, a process that asks the `broker`), to compare it with one you are storing (`secret set`), to find and redact it in transcripts (`clean`, `watch`), to print it in an interactive terminal (`secret get`), to ask the service it belongs to what it can reach (`scope discover`), or to write it to a store or file you name (`migrate`, `secret sync`, `export`, and `secret push`, which sends it in an HTTPS request body to Azure Key Vault, HashiCorp Vault or GCP Secret Manager). Backends (OS keychain, 1Password, HashiCorp Vault, GCP Secret Manager, AES-256-GCM encrypted file) decrypt a value when one of these commands asks for it. `secretless-ai verify` runs an integrity check of your local install.
