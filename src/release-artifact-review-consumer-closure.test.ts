import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import {
  BLIND_SCANNER,
  OWN_PACKAGE_PINS_MODULE,
  SCRIPT,
  buildTarball,
  closedPort,
  expectDeprecatedDependencyCaught,
  fetchHonoursProxy,
  fixturePackageJson,
  healthyFiles,
  relocatedScript,
  runReview,
  tmpRoot,
} from "./release-artifact-review.test-support";

/**
 * consumer-closure keeps a finding it has already made when a later read
 * fails: a deprecated own copy found before the GitHub advisories read fails
 * the check whether or not that read succeeds, as Results.precondition says a
 * precondition never masks a finding. With no finding yet, the failed read is
 * still a precondition.
 *
 * Each run is offline. npm is a stand-in that answers the registry reads, and
 * the advisories read is sent through a proxy address nothing listens on, so
 * it fails before it leaves the machine.
 */

type OwnCopy = { name: string; version: string; repo: string };

const OWN_COPY: OwnCopy = {
  name: "hackmyagent",
  version: "0.0.1-fixture",
  repo: "opena2a-org/hackmyagent",
};
const OWN_SPEC = `${OWN_COPY.name}@${OWN_COPY.version}`;
const REPO = OWN_COPY.repo;

/**
 * The scopes pinned-first-party-deps counts as own, from its source so the
 * two cannot drift. Read when the tests are collected, so it throws rather
 * than asserts.
 */
function ownScopes(): string[] {
  const match = /export const OWN_SCOPES = \[([^\]]*)\]/.exec(
    fs.readFileSync(OWN_PACKAGE_PINS_MODULE, "utf-8"),
  );
  if (match === null) throw new Error("OWN_SCOPES not found in own-package-pins.mjs");
  const scopes = [...match[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
  if (!scopes.includes("@nanomind/")) {
    throw new Error(`OWN_SCOPES no longer lists @nanomind/: ${JSON.stringify(scopes)}`);
  }
  return scopes;
}

/** The version the script's deprecation probe reads, from its source so the two cannot drift. */
function knownDeprecatedSpec(): string {
  const match =
    /KNOWN_DEPRECATED = \{ name: '([^']+)', version: '([^']+)' \}/.exec(
      fs.readFileSync(SCRIPT, "utf-8"),
    );
  expect(match, "KNOWN_DEPRECATED not found in the script").not.toBeNull();
  const [, name, version] = match as RegExpExecArray;
  return `${name}@${version}`;
}

/**
 * A stand-in npm in a new directory: the closure resolves to one copy of
 * `copy`, its packument names `copy.repo`, and `view <spec> deprecated`
 * prints a notice for each spec in `deprecated`. Every other call exits 0.
 */
function npmStandIn(deprecated: string[], copy: OwnCopy): string {
  const dir = fs.mkdtempSync(path.join(tmpRoot, "npm-stand-in-"));
  const lock = {
    lockfileVersion: 3,
    packages: {
      "": { name: "closure-scratch" },
      [`node_modules/${copy.name}`]: { version: copy.version },
    },
  };
  const packument = {
    versions: [copy.version],
    "repository.url": `git+https://github.com/${copy.repo}.git`,
  };
  const source = [
    `#!${process.execPath}`,
    "const argv = process.argv.slice(2);",
    "if (argv[0] === 'install' && argv.includes('--package-lock-only')) {",
    `  require('fs').writeFileSync('package-lock.json', ${JSON.stringify(JSON.stringify(lock))});`,
    `} else if (argv[0] === 'view' && argv[1] === ${JSON.stringify(copy.name)}) {`,
    `  console.log(${JSON.stringify(JSON.stringify(packument))});`,
    "} else if (argv[0] === 'view' && argv[2] === 'deprecated') {",
    `  if (${JSON.stringify(deprecated)}.includes(argv[1])) console.log('fixture deprecation notice');`,
    "}",
    "process.exit(0);",
    "",
  ].join("\n");
  fs.writeFileSync(path.join(dir, "npm"), source);
  fs.chmodSync(path.join(dir, "npm"), 0o755);
  return dir;
}

async function offlineReview(name: string, deprecated: string[], copy: OwnCopy = OWN_COPY) {
  const proxy = `http://127.0.0.1:${await closedPort()}`;
  if (!fetchHonoursProxy(proxy)) return null;
  const { script, env } = relocatedScript({ source: BLIND_SCANNER });
  const files = {
    ...healthyFiles(),
    "package/package.json": fixturePackageJson({
      dependencies: { [copy.name]: copy.version },
    }),
  };
  return runReview(["--tarball", buildTarball(`${name}.tgz`, files)], {
    script,
    env: {
      PATH: `${npmStandIn(deprecated, copy)}${path.delimiter}${env.PATH}`,
      HTTPS_PROXY: proxy,
      https_proxy: proxy,
      NO_PROXY: "",
      no_proxy: "",
    },
    unset: ["GH_TOKEN"],
  });
}

const SKIP_NOTE =
  "not measured: this node's fetch ignores HTTPS_PROXY, so the advisories read would leave the machine";

describe("consumer-closure keeps a deprecation it found when the advisories read then fails", () => {
  it(
    "a deprecated own copy fails the check, and the detail names the advisories read that failed",
    { timeout: 300_000 },
    async (ctx) => {
      const run = await offlineReview("deprecated-then-unreadable", [
        knownDeprecatedSpec(),
        OWN_SPEC,
      ]);
      if (run === null) return ctx.skip(SKIP_NOTE);

      expectDeprecatedDependencyCaught(run, OWN_SPEC);
      expect(run.stdout).toMatch(
        new RegExp(
          `^check consumer-closure: fail: .*advisories endpoint unreadable for ${REPO} \\(states: all\\): fetch failed`,
          "m",
        ),
      );
    },
  );

  it(
    "with no deprecated own copy, the failed advisories read is a precondition",
    { timeout: 300_000 },
    async (ctx) => {
      const run = await offlineReview("unreadable", [knownDeprecatedSpec()]);
      if (run === null) return ctx.skip(SKIP_NOTE);

      expect(run.status).not.toBe(0);
      expect(run.census["consumer-closure"]).toBe("precondition");
      expect(run.stdout).toMatch(
        new RegExp(
          `^check consumer-closure: precondition: advisories endpoint unreadable for ${REPO} \\(states: all\\): fetch failed`,
          "m",
        ),
      );
      expect(run.stdout).not.toContain(`${OWN_SPEC} is deprecated`);
    },
  );
});

/**
 * consumer-closure and pinned-first-party-deps read the own scopes from one
 * list, OWN_SCOPES in own-package-pins.mjs: a deprecated copy under each of
 * them, @nanomind/engine included, is examined and fails the check.
 */
describe("consumer-closure examines a copy under every scope pinned-first-party-deps counts as own", () => {
  it.for(ownScopes())(
    "a deprecated %sengine copy fails the check",
    { timeout: 300_000 },
    async (scope, ctx) => {
      const copy: OwnCopy = {
        name: `${scope}engine`,
        version: "0.0.1-fixture",
        repo: "opena2a-org/scope-fixture",
      };
      const spec = `${copy.name}@${copy.version}`;
      const run = await offlineReview(
        `scope-${scope.replace(/[^a-z0-9]/g, "")}`,
        [knownDeprecatedSpec(), spec],
        copy,
      );
      if (run === null) return ctx.skip(SKIP_NOTE);

      expectDeprecatedDependencyCaught(run, spec);
      expect(run.stdout).toMatch(
        new RegExp(
          `^check consumer-closure: fail: .*advisories endpoint unreadable for ${copy.repo} \\(states: all\\): fetch failed`,
          "m",
        ),
      );
    },
  );
});
