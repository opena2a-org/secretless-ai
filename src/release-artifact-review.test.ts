import { describe, it, expect } from "vitest";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import {
  BLIND_SCANNER,
  CHECKS,
  POISONED_DIST_FILE,
  REPO_ROOT,
  SCRIPT,
  buildTarball,
  buildUstarTgz,
  expectSingleFailure,
  fixturePackageJson,
  healthyFiles,
  relocatedScript,
  runReview,
  tmpRoot,
  type Run,
} from "./release-artifact-review.test-support";

/**
 * scripts/release-artifact-review.mjs, exercised as the release `review` job
 * runs it: spawned on a tarball, judged by its exit code and its census.
 *
 * Red first, per check: each blocking class gets a poisoned tarball built in a
 * temp directory, and the assertion is that the script exits non-zero naming
 * exactly that class — one `=fail` in the census, the right one. Then green: a
 * clean fixture passes every check, and the tarball packed from this delivered
 * tree passes every check whose verdict needs no network reading.
 *
 * The credential scanner is the real, exact-pinned hackmyagent from this
 * repository's node_modules/.bin — the same resolution the release `review`
 * job gets from `npm ci --ignore-scripts`. The two scanner-degradation cases
 * (unresolvable scanner, a scanner that misses the planted control) run a
 * copy of the script whose repo root is a scratch directory, so what its
 * node_modules/.bin holds is under the test's control.
 *
 * Deliberately absent here: any read of `CI` or `GITHUB_ACTIONS`. The tag
 * push that publishes is made on a machine where those variables are unset,
 * so a tolerance conditioned on them would exempt the publish path itself. A
 * precondition on the own-tarball run is a test failure in every environment.
 */

/** The checks whose verdict needs no network reading. */
const NO_NETWORK_CHECKS = [
  "entry-allowlist",
  "no-dotfiles",
  "no-test-material",
  "no-install-scripts",
  "pinned-first-party-deps",
  "no-retracted-claims",
  "global-install-smoke",
  "credential-scan",
];

/** What satisfies each check's precondition, for the failure message. */
const PRECONDITION_REMEDY: Record<string, string> = {
  "npm-audit":
    "registry access (there is no command; restore network to the npm registry)",
  "global-install-smoke":
    "registry access (there is no command; restore network to the npm registry)",
  "credential-scan": "npm ci --ignore-scripts",
  "consumer-closure":
    "registry and GitHub API access (set GH_TOKEN for authenticated advisory reads)",
};

const BROKEN_CLI = [
  "#!/usr/bin/env node",
  "if (process.argv[2] === '--version') { process.exit(1); }",
  "console.log('usage: fixture'); process.exit(0);",
  "",
].join("\n");

/** One review per scenario, shared across assertions. */
const memo = new Map<string, Run>();
function reviewOf(name: string, make: () => Run): Run {
  if (!memo.has(name)) memo.set(name, make());
  return memo.get(name)!;
}

const healthyRun = () =>
  reviewOf("healthy", () =>
    runReview(["--tarball", buildTarball("healthy.tgz", healthyFiles())]),
  );

// ---------------------------------------------------------------------------
// What the script refuses, and how it reports
// ---------------------------------------------------------------------------

describe("release-artifact-review.mjs reviews the packed bytes and reports every check", () => {
  it("the script refuses to run without a --tarball path", () => {
    const bare = runReview([]);
    expect(bare.status).toBe(2);
    expect(bare.stderr).toContain("usage:");

    const missing = runReview([
      "--tarball",
      path.join(tmpRoot, "does-not-exist.tgz"),
    ]);
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain("no such tarball");
  });

  it(
    "--advisory-states takes published or all and the states read are printed",
    { timeout: 300_000 },
    () => {
      const bad = runReview([
        "--tarball",
        buildTarball("states-bad.tgz", healthyFiles()),
        "--advisory-states",
        "draft",
      ]);
      expect(bad.status).toBe(2);
      expect(bad.stderr).toContain(
        "--advisory-states must be published or all",
      );

      const healthy = healthyRun();
      expect(healthy.stdout).toContain("advisory states: all");

      const published = reviewOf("states-published", () =>
        runReview([
          "--tarball",
          buildTarball("states-published.tgz", healthyFiles()),
          "--advisory-states",
          "published",
        ]),
      );
      expect(published.stdout).toContain("advisory states: published");
    },
  );

  it(
    "every check appears in the census whether it passed, failed or hit a precondition",
    { timeout: 300_000 },
    () => {
      const healthy = healthyRun();
      for (const check of CHECKS) {
        expect(
          Object.keys(healthy.census),
          `census is missing ${check}`,
        ).toContain(check);
        expect(["pass", "fail", "precondition"]).toContain(
          healthy.census[check],
        );
      }

      // On a failing run too: the census is not a success-path artifact.
      const poisoned = reviewOf("poison-dotfile", () =>
        runReview([
          "--tarball",
          buildTarball("poison-dotfile.tgz", {
            ...healthyFiles(),
            "package/dist/.env": "X=1\n",
          }),
        ]),
      );
      for (const check of CHECKS) {
        expect(
          Object.keys(poisoned.census),
          `census is missing ${check}`,
        ).toContain(check);
      }
    },
  );

  it(
    "an entry outside dist/, README, LICENSE and package.json fails the entry allowlist",
    { timeout: 300_000 },
    () => {
      const run = reviewOf("stray-entry", () =>
        runReview([
          "--tarball",
          buildTarball("stray.tgz", {
            ...healthyFiles(),
            "package/extra.js": "module.exports = 1;\n",
          }),
        ]),
      );
      expectSingleFailure(run, "entry-allowlist");
      expect(run.stdout).toContain("package/extra.js");
    },
  );

  it(
    "both bins are exercised: version, help, init help and the mcp wrapper",
    { timeout: 300_000 },
    () => {
      const healthy = healthyRun();
      expect(healthy.stdout).toContain("secretless-ai --version");
      expect(healthy.stdout).toContain("secretless-ai --help");
      expect(healthy.stdout).toContain("secretless-ai init --help");
      expect(healthy.stdout).toContain("secretless-mcp --help");
    },
  );

  it("the exact-pinned hackmyagent resolves from node_modules/.bin under npm ci --ignore-scripts", () => {
    // The pin is what makes the release review job's scanner resolution
    // deterministic: `npm ci --ignore-scripts` reifies node_modules/.bin.
    const manifest = JSON.parse(
      fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf-8"),
    );
    const pin = manifest.devDependencies?.hackmyagent;
    expect(pin, "hackmyagent is not a devDependency").toBeDefined();
    expect(pin).toMatch(/^\d+\.\d+\.\d+$/);
    expect(
      fs.existsSync(
        path.join(REPO_ROOT, "node_modules", ".bin", "hackmyagent"),
      ),
    ).toBe(true);
  });

  it(
    "the scanner row prints the scanner version and PATH is the fallback, never the first choice",
    { timeout: 300_000 },
    () => {
      const healthy = healthyRun();
      expect(healthy.stdout).toMatch(
        /check credential-scan: pass: hackmyagent@\d+\.\d+\.\d+/,
      );

      // A blind scanner planted FIRST on PATH must lose to node_modules/.bin:
      // if PATH won, the control would go unflagged and this run would report a
      // precondition instead of a pass.
      const blindDir = fs.mkdtempSync(path.join(tmpRoot, "path-blind-"));
      fs.writeFileSync(path.join(blindDir, "hackmyagent"), BLIND_SCANNER);
      fs.chmodSync(path.join(blindDir, "hackmyagent"), 0o755);
      const run = reviewOf("path-is-fallback", () =>
        runReview(
          ["--tarball", buildTarball("path-fallback.tgz", healthyFiles())],
          {
            env: {
              PATH: `${blindDir}${path.delimiter}${process.env.PATH ?? ""}`,
            },
          },
        ),
      );
      expect(run.census["credential-scan"]).toBe("pass");
    },
  );

  it(
    "an unresolvable hackmyagent is a precondition and a non-zero exit, never a pass",
    { timeout: 300_000 },
    () => {
      const { script, env } = relocatedScript();
      const run = reviewOf("no-scanner", () =>
        runReview(
          ["--tarball", buildTarball("no-scanner.tgz", healthyFiles())],
          { script, env },
        ),
      );
      expect(run.status).not.toBe(0);
      expect(run.census["credential-scan"]).toBe("precondition");
      expect(run.stdout).toMatch(
        /check credential-scan: precondition: hackmyagent not resolvable/,
      );
      expect(run.stdout).toContain("preconditions not met: credential-scan");
    },
  );

  it(
    "a scanner that misses the planted control is a precondition naming the scanner version",
    { timeout: 300_000 },
    () => {
      const { script, env } = relocatedScript({ source: BLIND_SCANNER });
      const run = reviewOf("blind-scanner", () =>
        runReview(
          ["--tarball", buildTarball("blind-scanner.tgz", healthyFiles())],
          { script, env },
        ),
      );
      expect(run.status).not.toBe(0);
      expect(run.census["credential-scan"]).toBe("precondition");
      expect(run.stdout).toContain("control not flagged by hackmyagent@9.9.9");
    },
  );
});

// ---------------------------------------------------------------------------
// Each blocking class caught by name; then the clean and delivered tarballs passing
// ---------------------------------------------------------------------------

describe("each blocking class is caught by name, and the delivered tree passes", () => {
  it(
    "a dotfile entry is caught by no-dotfiles",
    { timeout: 300_000 },
    () => {
      const run = reviewOf("poison-dotfile", () =>
        runReview([
          "--tarball",
          buildTarball("poison-dotfile.tgz", {
            ...healthyFiles(),
            "package/dist/.env": "X=1\n",
          }),
        ]),
      );
      expectSingleFailure(run, "no-dotfiles");
      expect(run.stdout).toContain("package/dist/.env");
    },
  );

  it(
    "a fixtures/ entry is caught by no-test-material",
    { timeout: 300_000 },
    () => {
      const run = reviewOf("poison-fixtures", () =>
        runReview([
          "--tarball",
          buildTarball("poison-fixtures.tgz", {
            ...healthyFiles(),
            "package/dist/fixtures/sample.js": "1;\n",
          }),
        ]),
      );
      expectSingleFailure(run, "no-test-material");
      expect(run.stdout).toContain("package/dist/fixtures/sample.js");
    },
  );

  it(
    "a postinstall script is caught by no-install-scripts",
    { timeout: 300_000 },
    () => {
      const files = {
        ...healthyFiles(),
        "package/package.json": fixturePackageJson({
          scripts: { postinstall: 'node -e "1"' },
        }),
      };
      const run = reviewOf("poison-postinstall", () =>
        runReview(["--tarball", buildTarball("poison-postinstall.tgz", files)]),
      );
      expectSingleFailure(run, "no-install-scripts");
      expect(run.stdout).toContain("postinstall");
    },
  );

  it(
    "a caret range on an @opena2a/ dependency is caught by pinned-first-party-deps",
    { timeout: 300_000 },
    () => {
      const files = {
        ...healthyFiles(),
        "package/package.json": fixturePackageJson({
          dependencies: { "@opena2a/cli-ui": "^0.4.0" },
        }),
      };
      const run = reviewOf("poison-caret", () =>
        runReview(["--tarball", buildTarball("poison-caret.tgz", files)]),
      );
      expectSingleFailure(run, "pinned-first-party-deps");
      expect(run.stdout).toContain("@opena2a/cli-ui=^0.4.0");
    },
  );

  it(
    "a dist/cli.js that exits 1 on --version is caught by global-install-smoke",
    { timeout: 300_000 },
    () => {
      const files = { ...healthyFiles(), "package/dist/cli.js": BROKEN_CLI };
      const run = reviewOf("poison-cli", () =>
        runReview(["--tarball", buildTarball("poison-cli.tgz", files)]),
      );
      expectSingleFailure(run, "global-install-smoke");
      expect(run.stdout).toContain("secretless-ai --version: exited 1");
    },
  );

  it(
    "a dist/ file carrying a value of the control class is caught by credential-scan, without echoing the value",
    { timeout: 300_000 },
    () => {
      const files = {
        ...healthyFiles(),
        "package/dist/config.js": POISONED_DIST_FILE,
      };
      const run = reviewOf("poison-credential", () =>
        runReview(["--tarball", buildTarball("poison-credential.tgz", files)]),
      );
      expectSingleFailure(run, "credential-scan");
      // The failure names checkId and file:line, never the matched text.
      expect(run.stdout).toMatch(
        /check credential-scan: fail: .*config\.js:\d+/,
      );
      expect(run.stdout).not.toContain("sk-" + "proj-" + "B".repeat(48));
    },
  );

  it(
    "a dependency on a deprecated hackmyagent version is caught by consumer-closure",
    { timeout: 600_000 },
    () => {
      // Named at test time from the registry's own answer: the version the script
      // probes (KNOWN_DEPRECATED, read from its source so the two cannot drift) must
      // read as deprecated via `npm view` right now, or this test cannot run.
      const source = fs.readFileSync(SCRIPT, "utf-8");
      const match =
        /KNOWN_DEPRECATED = \{ name: 'hackmyagent', version: '([^']+)' \}/.exec(
          source,
        );
      expect(match, "KNOWN_DEPRECATED not found in the script").not.toBeNull();
      const version = (match as RegExpExecArray)[1];
      const view = spawnSync(
        "npm",
        ["view", `hackmyagent@${version}`, "deprecated"],
        { encoding: "utf-8", timeout: 120_000 },
      );
      expect(view.status, view.stderr).toBe(0);
      expect(
        (view.stdout ?? "").trim().length,
        `hackmyagent@${version} does not read as deprecated on the registry`,
      ).toBeGreaterThan(0);
      console.log(
        `deprecated hackmyagent version used by this test: ${version}`,
      );

      const files = {
        ...healthyFiles(),
        "package/package.json": fixturePackageJson({
          dependencies: { hackmyagent: version },
        }),
      };
      const run = reviewOf("poison-deprecated", () =>
        runReview(["--tarball", buildTarball("poison-deprecated.tgz", files)]),
      );
      expect(run.census["consumer-closure"]).toBe("fail");
      expect(run.status).not.toBe(0);
      expect(run.stdout).toContain(`hackmyagent@${version} is deprecated`);
      expect(run.stdout).toMatch(/failing: .*consumer-closure/);
    },
  );

  it(
    "a statically bad tarball is not installed: its dynamic checks are preconditions, not passes",
    { timeout: 300_000 },
    () => {
      const poisoned = reviewOf("poison-dotfile", () =>
        runReview([
          "--tarball",
          buildTarball("poison-dotfile.tgz", {
            ...healthyFiles(),
            "package/dist/.env": "X=1\n",
          }),
        ]),
      );
      expect(poisoned.census["global-install-smoke"]).toBe("precondition");
      expect(poisoned.census["credential-scan"]).toBe("precondition");
      expect(poisoned.census["npm-audit"]).toBe("precondition");
      expect(poisoned.census["consumer-closure"]).toBe("precondition");
    },
  );

  it(
    "a clean fixture tarball exits 0 with every check pass",
    { timeout: 300_000 },
    () => {
      const healthy = healthyRun();
      expect(healthy.stdout).toContain("result: pass");
      expect(healthy.status).toBe(0);
      for (const check of CHECKS) {
        expect(
          healthy.census[check],
          `${check} is ${healthy.census[check]}`,
        ).toBe("pass");
      }
    },
  );

  it(
    "the tarball packed from the delivered tree passes every no-network check, with no precondition anywhere",
    { timeout: 600_000 },
    () => {
      const packDir = fs.mkdtempSync(path.join(tmpRoot, "pack-"));
      const pack = spawnSync(
        "npm",
        ["pack", "--ignore-scripts", "--pack-destination", packDir],
        {
          cwd: REPO_ROOT,
          encoding: "utf-8",
          timeout: 300_000,
        },
      );
      expect(pack.status, pack.stderr).toBe(0);
      const tarball = path.join(
        packDir,
        pack.stdout.trim().split("\n").pop()!,
      );

      const run = runReview(["--tarball", tarball]);

      // A check that could not run here is a test failure: the publish path
      // itself runs outside CI, so an unrunnable check must surface loudly.
      for (const check of CHECKS) {
        if (run.census[check] === "precondition") {
          const detail =
            new RegExp(`^check ${check}: precondition: (.*)$`, "m").exec(
              run.stdout,
            )?.[1] ?? "<no detail>";
          expect.fail(
            `check ${check} hit a precondition on the delivered tarball: ${detail}. ` +
              `Satisfy it with: ${PRECONDITION_REMEDY[check] ?? "see the check output above"}`,
          );
        }
      }

      for (const check of NO_NETWORK_CHECKS) {
        expect(run.census[check], `${check} is ${run.census[check]}`).toBe(
          "pass",
        );
      }

      // consumer-closure may pass or fail — a fail names a nested own copy that
      // blocks the release job until it is replaced; it is not a defect of this
      // script.
      expect(
        ["pass", "fail"],
        `consumer-closure is ${run.census["consumer-closure"]}`,
      ).toContain(run.census["consumer-closure"]);
      expect(
        ["pass", "fail"],
        `npm-audit is ${run.census["npm-audit"]}`,
      ).toContain(run.census["npm-audit"]);
      if (
        run.census["consumer-closure"] === "fail" ||
        run.census["npm-audit"] === "fail"
      ) {
        console.log(
          "delivered-tarball verbatim:",
        );
        for (const line of run.stdout.split("\n")) {
          if (/^(check (npm-audit|consumer-closure)|census|result)/.test(line))
            console.log(`  ${line}`);
        }
      }

      // Exit code 0 exactly when no check is fail or precondition.
      const anyBlocked = CHECKS.some((check) => run.census[check] !== "pass");
      expect(run.status === 0).toBe(!anyBlocked);
    },
  );

  it(
    "a tarball with no dist/ exits non-zero with precondition in its output",
    { timeout: 300_000 },
    () => {
      const files = {
        "package/package.json": fixturePackageJson(),
        "package/README.md": "# fixture\n",
      };
      const run = reviewOf("no-dist", () =>
        runReview(["--tarball", buildTarball("no-dist.tgz", files)]),
      );
      expect(run.status).not.toBe(0);
      expect(run.stdout).toContain("precondition");
      expect(run.census["global-install-smoke"]).toBe("precondition");
      expect(run.census["credential-scan"]).toBe("precondition");
      expect(run.stdout).toContain("dist/ absent from the tarball");
    },
  );
});

// ---------------------------------------------------------------------------
// A tarball entry under package/dist/ whose path carries a `..` segment must
// fail a check BY NAME. `tar` cannot create such a member (it strips `..` on
// create), so the fixture is a hand-built ustar archive. The check has to fire from
// the LISTING, before extraction: bsdtar and GNU tar both refuse the member at
// extraction, which today turns every check into a precondition and reports
// nothing about the traversal itself. Asserting `status != 0` alone would pass
// on tar's refusal — the assertion that let a reverted fix look green.
// ---------------------------------------------------------------------------

const TRAVERSAL_ENTRY = "package/dist/../../../evil-marker.js";

describe("an entry under package/dist/ that escapes it fails dist-containment by name", () => {
  it("names the traversal entry from the listing, whether or not tar agrees to extract it", () => {
    const run = reviewOf("traversal", () =>
      runReview([
        "--tarball",
        buildUstarTgz("traversal.tgz", {
          ...healthyFiles(),
          [TRAVERSAL_ENTRY]: "module.exports = 'escaped';\n",
        }),
      ]),
    );
    expect(run.status).not.toBe(0);
    expect(run.census["dist-containment"]).toBe("fail");
    expect(run.stdout).toContain("check dist-containment: fail");
    expect(run.stdout).toContain(TRAVERSAL_ENTRY);
  }, 600_000);

  it("control: the same hand-built archive without the escaping member passes dist-containment", () => {
    const run = reviewOf("ustar-healthy", () =>
      runReview(["--tarball", buildUstarTgz("ustar-healthy.tgz", healthyFiles())]),
    );
    expect(run.census["dist-containment"]).toBe("pass");
  }, 600_000);
});
