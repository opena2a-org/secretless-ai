import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import {
  BLIND_SCANNER,
  REPO_ROOT,
  buildTarball,
  expectSingleFailure,
  fixturePackageJson,
  healthyFiles,
  preconditionsOf,
  relocatedScript,
  runReview,
  tmpRoot,
  type Run,
} from "./release-artifact-review.test-support";

/**
 * pinned-first-party-deps refuses a non-exact specifier on an own-package
 * dependency, in any of the four dependency sections. An own package is a
 * name under @opena2a/ or @nanomind/, or one whose npm maintainers share a
 * member with hackmyagent's; the second half is read from the registry, so
 * an unscoped own name needs no roster entry. A name the registry answers
 * E404 for is `pin not served`, and a read that gets no answer is a
 * precondition, never a pass.
 *
 * Each run is offline. npm is a stand-in first on PATH: it answers
 * `npm view <name> maintainers --json` from REGISTRY (a name not listed there
 * is maintained by OTHER alone) and fails every other call, `npm ping` among
 * them, so no check reaches the network. The scanner is BLIND_SCANNER.
 */

const OWNER = "fixture-owner";
const OTHER = "fixture-other";

type Answer = string[] | "E404" | "ECONNREFUSED";

const REGISTRY: Record<string, Answer> = {
  hackmyagent: [OWNER],
  "arp-guard": [OTHER, OWNER],
  "Legacy-Own-Fixture": [OWNER],
  "not-served-fixture": "E404",
  "unreachable-fixture": "ECONNREFUSED",
};

const LOOSE = "non-exact specifier on an own-package dependency";

type Sections = Partial<
  Record<
    "dependencies" | "devDependencies" | "optionalDependencies" | "peerDependencies",
    Record<string, string>
  >
>;

interface OwnPinsRun extends Run {
  /** The argv of every npm call the review made. */
  calls: string[][];
}

function npmStandIn(registry: Record<string, Answer>): {
  dir: string;
  log: string;
} {
  const dir = fs.mkdtempSync(path.join(tmpRoot, "npm-maintainers-"));
  const log = path.join(dir, "calls.jsonl");
  const source = [
    `#!${process.execPath}`,
    "const fs = require('fs');",
    "const argv = process.argv.slice(2);",
    `fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify(argv) + '\\n');`,
    `const registry = ${JSON.stringify(registry)};`,
    "if (argv[0] === 'view' && argv[2] === 'maintainers' && argv[3] === '--json') {",
    `  const answer = Object.prototype.hasOwnProperty.call(registry, argv[1]) ? registry[argv[1]] : [${JSON.stringify(OTHER)}];`,
    "  if (answer === 'E404') {",
    "    console.log(JSON.stringify({ error: { code: 'E404', summary: 'Not Found' } }));",
    "    console.error('npm error code E404');",
    "    process.exit(1);",
    "  }",
    "  if (answer === 'ECONNREFUSED') {",
    "    console.error('npm error code ECONNREFUSED');",
    "    process.exit(1);",
    "  }",
    "  console.log(JSON.stringify(answer.map((user) => `${user} <${user}@example.invalid>`)));",
    "  process.exit(0);",
    "}",
    "process.exit(1);",
    "",
  ].join("\n");
  fs.writeFileSync(path.join(dir, "npm"), source);
  fs.chmodSync(path.join(dir, "npm"), 0o755);
  return { dir, log };
}

let tarballs = 0;

function review(sections: Sections, registry: Record<string, Answer> = REGISTRY): OwnPinsRun {
  const { script, env } = relocatedScript({ source: BLIND_SCANNER });
  const npm = npmStandIn(registry);
  const files = {
    ...healthyFiles(),
    "package/package.json": fixturePackageJson(sections),
  };
  tarballs += 1;
  const run = runReview(["--tarball", buildTarball(`own-pins-${tarballs}.tgz`, files)], {
    script,
    env: { PATH: `${npm.dir}${path.delimiter}${env.PATH}` },
    unset: ["GH_TOKEN"],
  });
  const calls = fs.existsSync(npm.log)
    ? fs
        .readFileSync(npm.log, "utf-8")
        .split("\n")
        .filter((line) => line.length > 0)
        .map((line) => JSON.parse(line) as string[])
    : [];
  // Maintainer names are compared, never printed.
  expect(run.stdout + run.stderr).not.toContain(OWNER);
  expect(run.stdout + run.stderr).not.toContain(OTHER);
  return { ...run, calls };
}

function viewedNames(run: OwnPinsRun): string[] {
  return run.calls.filter((argv) => argv[0] === "view").map((argv) => argv[1]);
}

describe("pinned-first-party-deps refuses a non-exact specifier on an own package", () => {
  it.each([
    ["@opena2a/aim-core", "^0.2.0"],
    ["@opena2a/aim-core", "*"],
    ["@opena2a/aim-core", ">=0.2.0"],
    ["@opena2a/aim-core", "0.2.x"],
    ["@opena2a/aim-core", "latest"],
    ["@nanomind/engine", "^0.1.1"],
    ["hackmyagent", ">=0.11.0"],
    ["arp-guard", "~0.3.0"],
    ["@opena2a/aim-core", "1.0.0-beta+build.1+build.2"],
    ["Legacy-Own-Fixture", "^1.0.0"],
  ])("%s %s fails the check, named", { timeout: 120_000 }, (name, spec) => {
    const run = review({ dependencies: { [name]: spec } });
    expectSingleFailure(run, "pinned-first-party-deps");
    expect(run.stdout).toContain(`${LOOSE}: dependencies.${name}=${spec}`);
  });

  it("a declaration in each of the four sections is named", { timeout: 120_000 }, () => {
    const run = review({
      dependencies: { hackmyagent: ">=0.11.0" },
      devDependencies: { "@opena2a/cli-ui": "~0.4.0" },
      optionalDependencies: { "@nanomind/guard": "^0.1.1" },
      peerDependencies: { "arp-guard": ">=0.3.0" },
    });
    expectSingleFailure(run, "pinned-first-party-deps");
    for (const label of [
      "dependencies.hackmyagent=>=0.11.0",
      "devDependencies.@opena2a/cli-ui=~0.4.0",
      "optionalDependencies.@nanomind/guard=^0.1.1",
      "peerDependencies.arp-guard=>=0.3.0",
    ]) {
      expect(run.stdout).toContain(label);
    }
  });

  it("an npm: alias is judged by the package it installs", { timeout: 120_000 }, () => {
    const run = review({ dependencies: { "left-pad": "npm:hackmyagent@*" } });
    expectSingleFailure(run, "pinned-first-party-deps");
    expect(run.stdout).toContain(`${LOOSE}: dependencies.left-pad=npm:hackmyagent@*`);
    expect(viewedNames(run)).toContain("hackmyagent");
    expect(viewedNames(run)).not.toContain("left-pad");
  });

  it("a name the registry answers E404 for fails as pin not served", { timeout: 120_000 }, () => {
    const run = review({ dependencies: { "not-served-fixture": "^1.0.0" } });
    expectSingleFailure(run, "pinned-first-party-deps");
    expect(run.stdout).toContain("pin not served: dependencies.not-served-fixture=^1.0.0");
  });

  it("a name npm cannot look up fails, and is never passed to npm", { timeout: 120_000 }, () => {
    const name = "--registry=http://127.0.0.1:9/";
    const run = review({ dependencies: { [name]: "^1.0.0" } });
    expectSingleFailure(run, "pinned-first-party-deps");
    expect(run.stdout).toContain(`dependencies.${name}=^1.0.0 (not an npm package name)`);
    expect(run.calls.flat()).not.toContain(name);
  });

  it("a name with a leading hyphen fails, and is never passed to npm", { timeout: 120_000 }, () => {
    const name = "-leading-hyphen-fixture";
    const run = review({ dependencies: { [name]: "^1.0.0" } });
    expectSingleFailure(run, "pinned-first-party-deps");
    expect(run.stdout).toContain(`dependencies.${name}=^1.0.0 (not an npm package name)`);
    expect(run.calls.flat()).not.toContain(name);
  });
});

describe("pinned-first-party-deps passes exact pins and packages other publishers own", () => {
  it(
    "exact pins pass with no registry read",
    { timeout: 120_000 },
    () => {
      const run = review({
        dependencies: { "@opena2a/aim-core": "0.2.0", hackmyagent: "0.33.2" },
        optionalDependencies: {
          "@nanomind/engine": "0.1.1",
          "x-fixture": "npm:@opena2a/aim-core@0.2.0",
        },
        devDependencies: { "arp-guard": "0.0.1-fixture" },
      });
      expect(run.census["pinned-first-party-deps"]).toBe("pass");
      expect(viewedNames(run)).toEqual([]);
    },
  );

  it(
    "an exact pin with a prerelease and then a build suffix passes with no registry read",
    { timeout: 120_000 },
    () => {
      const run = review({
        dependencies: { "@opena2a/aim-core": "1.0.0-beta+build.1", hackmyagent: "0.33.2-rc.1+build.7" },
      });
      expect(run.census["pinned-first-party-deps"]).toBe("pass");
      expect(viewedNames(run)).toEqual([]);
    },
  );

  it(
    "a non-exact specifier on a package hackmyagent's maintainers do not publish passes, after both reads",
    { timeout: 120_000 },
    () => {
      const run = review({ devDependencies: { typescript: "^6.0.2" } });
      expect(run.census["pinned-first-party-deps"]).toBe("pass");
      expect(viewedNames(run).sort()).toEqual(["hackmyagent", "typescript"]);
    },
  );

  it(
    "a legacy name with capitals or ~'!()* is read from the registry, not refused as a name",
    { timeout: 120_000 },
    () => {
      const run = review({
        dependencies: { JSONStream: "^1.3.5" },
        devDependencies: { "~legacy'name!(x)*": "^1.0.0" },
      });
      expect(run.census["pinned-first-party-deps"]).toBe("pass");
      expect(viewedNames(run).sort()).toEqual(["JSONStream", "hackmyagent", "~legacy'name!(x)*"]);
    },
  );
});

describe("pinned-first-party-deps without a registry answer is a precondition, never a pass", () => {
  it("the dependency's own read fails", { timeout: 120_000 }, () => {
    const run = review({ dependencies: { "unreachable-fixture": "^1.0.0" } });
    expect(run.status).not.toBe(0);
    expect(run.census["pinned-first-party-deps"]).toBe("precondition");
    const pinned = preconditionsOf(run).find((p) => p.check === "pinned-first-party-deps");
    expect(pinned?.detail).toContain("dependencies.unreachable-fixture=^1.0.0 (npm view exited 1, ECONNREFUSED)");
  });

  it("hackmyagent's maintainers read fails", { timeout: 120_000 }, () => {
    const run = review(
      { devDependencies: { typescript: "^6.0.2" } },
      { ...REGISTRY, hackmyagent: "ECONNREFUSED" },
    );
    expect(run.status).not.toBe(0);
    expect(run.census["pinned-first-party-deps"]).toBe("precondition");
    const pinned = preconditionsOf(run).find((p) => p.check === "pinned-first-party-deps");
    expect(pinned?.detail).toContain("devDependencies.typescript=^6.0.2 (hackmyagent maintainers unread:");
  });
});

describe("the delivered package.json pins every own package exactly", () => {
  const delivered = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf-8"));
  const sections: Sections = {
    dependencies: delivered.dependencies ?? {},
    devDependencies: delivered.devDependencies ?? {},
    optionalDependencies: delivered.optionalDependencies ?? {},
    peerDependencies: delivered.peerDependencies ?? {},
  };

  it("its four dependency sections pass the check", { timeout: 120_000 }, () => {
    const run = review(sections);
    expect(run.census["pinned-first-party-deps"]).toBe("pass");
  });

  it("the same sections with a planted hackmyagent >=0.11.0 fail, naming only the planted cell", { timeout: 120_000 }, () => {
    const run = review({
      ...sections,
      dependencies: { ...sections.dependencies, hackmyagent: ">=0.11.0" },
    });
    expectSingleFailure(run, "pinned-first-party-deps");
    const detail = /^check pinned-first-party-deps: fail: (.*)$/m.exec(run.stdout)?.[1];
    expect(detail).toBe(`${LOOSE}: dependencies.hackmyagent=>=0.11.0`);
  });
});
