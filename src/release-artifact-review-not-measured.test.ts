import { describe, it, expect } from "vitest";
import * as fs from "fs";
import {
  SCRIPT,
  expectDeprecatedDependencyCaught,
  notMeasuredReason,
  preconditionsOf,
  type Run,
} from "./release-artifact-review.test-support";

/**
 * The delivered-tarball case of src/release-artifact-review.test.ts fails on
 * every precondition but one: the GitHub advisories read, on a run that sends
 * no GH_TOKEN, refused or held on this machine by advisoryReadOf.
 * Unauthenticated reads share a per-address rate limit, so a shared CI runner
 * hit it on a change that touched nothing near the review, and the required
 * check failed. That one precondition is reported as not measured. The
 * script's verdict is unchanged, so the release `review` job, which sends
 * GH_TOKEN, still blocks on it.
 *
 * These cases spawn nothing: each run is built from lines in the script's
 * output format, as the delivered-tarball case reads them.
 */

function runOf(lines: string[], status: number | null = 1): Run {
  const census: Record<string, string> = {};
  for (const line of lines) {
    const match = /^check ([a-z-]+): (pass|fail|precondition)/.exec(line);
    if (match) census[match[1]] = match[2];
  }
  return { status, stdout: `${lines.join("\n")}\n`, stderr: "", census };
}

const RATE_LIMITED_403 =
  "check consumer-closure: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: all): rate-limited or forbidden (HTTP 403)";
const RATE_LIMITED_429 =
  "check consumer-closure: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: published): rate-limited or forbidden (HTTP 429)";
const HELD =
  "check consumer-closure: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: all): fetch failed:   } | } |  | Node.js v26.7.0";

describe("a refused advisories read with no GH_TOKEN is not measured; every other precondition fails the delivered-tarball case", () => {
  it("reads each precondition and its detail from the script's output", () => {
    const run = runOf([
      "check entry-allowlist: pass",
      RATE_LIMITED_403,
      "check npm-audit: precondition: registry unreachable (npm ping failed)",
    ]);
    expect(preconditionsOf(run)).toEqual([
      {
        check: "npm-audit",
        detail: "registry unreachable (npm ping failed)",
      },
      {
        check: "consumer-closure",
        detail:
          "advisories endpoint unreadable for opena2a-org/opena2a (states: all): rate-limited or forbidden (HTTP 403)",
      },
    ]);
  });

  it("the advisories read refused with HTTP 403 or 429 and no GH_TOKEN is not measured, and the reason names GH_TOKEN", () => {
    for (const line of [RATE_LIMITED_403, RATE_LIMITED_429]) {
      const [precondition] = preconditionsOf(runOf([line]));
      const reason = notMeasuredReason(precondition, {});
      expect(reason, line).not.toBeNull();
      expect(reason).toContain("GH_TOKEN");
      expect(reason).toContain("opena2a-org/opena2a");
    }
  });

  it("an empty GH_TOKEN sends no authorization, so it counts as no token", () => {
    const [precondition] = preconditionsOf(runOf([RATE_LIMITED_403]));
    expect(notMeasuredReason(precondition, { GH_TOKEN: "" })).not.toBeNull();
  });

  it("with GH_TOKEN set, a refused advisories read fails the case", () => {
    const [precondition] = preconditionsOf(runOf([RATE_LIMITED_403]));
    expect(
      notMeasuredReason(precondition, { GH_TOKEN: "fixture-token-not-a-secret" }),
    ).toBeNull();
  });

  it("every other consumer-closure precondition fails the case, with or without GH_TOKEN", () => {
    const others = [
      "check consumer-closure: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: all): HTTP 500",
      "check consumer-closure: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: all): fetch failed: getaddrinfo ENOTFOUND api.github.com",
      "check consumer-closure: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: all): not an advisory list",
      "check consumer-closure: precondition: the advisory feed returned zero advisories across 1 roster repositories (states: all); an empty feed cannot be told apart from a broken read",
      "check consumer-closure: precondition: deprecation probe errored on fixture-package@1.0.0: rate-limited or forbidden (HTTP 403)",
      "check consumer-closure: precondition: registry unreachable (npm ping failed)",
    ];
    for (const line of others) {
      const [precondition] = preconditionsOf(runOf([line]));
      expect(notMeasuredReason(precondition, {}), line).toBeNull();
    }
  });

  it("with no GH_TOKEN and the read held on this machine, the read that failed to fetch is not measured, and the reason names GH_TOKEN", () => {
    const [precondition] = preconditionsOf(runOf([HELD]));
    const reason = notMeasuredReason(precondition, {}, true);
    expect(reason).not.toBeNull();
    expect(reason).toContain("GH_TOKEN");
    expect(reason).toContain("held");
    expect(reason).toContain("opena2a-org/opena2a");
  });

  it("a read that failed to fetch fails the case when it was not held, or when GH_TOKEN is set", () => {
    const [precondition] = preconditionsOf(runOf([HELD]));
    expect(notMeasuredReason(precondition, {}, false)).toBeNull();
    expect(notMeasuredReason(precondition, {})).toBeNull();
    expect(
      notMeasuredReason(
        precondition,
        { GH_TOKEN: "fixture-token-not-a-secret" },
        true,
      ),
    ).toBeNull();
  });

  it("a held read excuses no other precondition", () => {
    const others = [
      "check consumer-closure: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: all): HTTP 500",
      "check consumer-closure: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: all): not an advisory list",
      "check consumer-closure: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: all): unparseable response",
      "check consumer-closure: precondition: the advisory feed returned zero advisories across 1 roster repositories (states: all); an empty feed cannot be told apart from a broken read",
      "check consumer-closure: precondition: npm view hackmyagent@0.0.0-fixture deprecated errored: fetch failed: E404",
      "check consumer-closure: precondition: registry unreachable (npm ping failed)",
      "check npm-audit: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: all): fetch failed: TypeError: fetch failed",
    ];
    for (const line of others) {
      const [precondition] = preconditionsOf(runOf([line]));
      expect(notMeasuredReason(precondition, {}, true), line).toBeNull();
    }
  });

  it("the script still words a refused advisories read the way notMeasuredReason reads it", () => {
    // Reworded, the exception would stop matching and a rate limit would fail
    // the gate on unrelated changes again.
    const source = fs.readFileSync(SCRIPT, "utf-8");
    expect(source).toContain(
      "`advisories endpoint unreadable for ${repo} (states: ${advisoryStates}): ${response.error ?? 'not an advisory list'}`",
    );
    expect(source).toContain(
      "if (status === 403 || status === 429) return { body: null, error: `rate-limited or forbidden (HTTP ${status})` };",
    );
    expect(source).toContain(
      "if (child.status !== 0) return { body: null, error: `fetch failed: ${tailOf(child)}` };",
    );
  });

  it("a refused read reported by any check other than consumer-closure fails the case", () => {
    const [precondition] = preconditionsOf(
      runOf([
        "check npm-audit: precondition: advisories endpoint unreadable for opena2a-org/opena2a (states: all): rate-limited or forbidden (HTTP 403)",
      ]),
    );
    expect(notMeasuredReason(precondition, {})).toBeNull();
  });
});

/**
 * The judgment of the deprecated-dependency case of
 * src/release-artifact-review.test.ts. The script keeps a deprecation it
 * found when the advisories read after it is refused
 * (src/release-artifact-review-consumer-closure.test.ts), so that case takes
 * no not-measured exception. Each run below breaks one thing the case holds,
 * and the error names the assertion that caught it.
 */
describe("the deprecated-dependency case accepts only a non-zero exit, a consumer-closure fail naming the deprecated version, and consumer-closure listed as failing", () => {
  const DEPRECATED = "hackmyagent@0.0.0-fixture";
  const NAMED =
    'check consumer-closure: fail: hackmyagent@0.0.0-fixture is deprecated: "fixture notice"';
  const FAILING = "result: fail — failing: consumer-closure";

  it("a run that exits non-zero, fails consumer-closure naming the deprecated version and lists it as failing is caught", () => {
    expect(() =>
      expectDeprecatedDependencyCaught(runOf([NAMED, FAILING]), DEPRECATED),
    ).not.toThrow();
  });

  it("a run that exits 0 fails the case", () => {
    expect(() =>
      expectDeprecatedDependencyCaught(runOf([NAMED, FAILING], 0), DEPRECATED),
    ).toThrow(/^exit status: expected \+0 not to be \+0/);
  });

  it("a consumer-closure that is not a fail fails the case, a refused advisories read with no GH_TOKEN included", () => {
    for (const lines of [
      [
        'check consumer-closure: pass: hackmyagent@0.0.0-fixture is deprecated: "fixture notice"',
        FAILING,
      ],
      [RATE_LIMITED_403],
      [RATE_LIMITED_429],
      [
        "check consumer-closure: precondition: npm view hackmyagent@0.0.0-fixture deprecated errored: E404",
      ],
    ]) {
      expect(
        () => expectDeprecatedDependencyCaught(runOf(lines), DEPRECATED),
        lines[0],
      ).toThrow(/^consumer-closure.*: expected '(pass|precondition)' to be 'fail'/);
    }
  });

  it("a consumer-closure fail that does not name the deprecated version fails the case", () => {
    expect(() =>
      expectDeprecatedDependencyCaught(
        runOf([
          'check consumer-closure: fail: hackmyagent@0.0.1-fixture is deprecated: "fixture notice"',
          FAILING,
        ]),
        DEPRECATED,
      ),
    ).toThrow(/^deprecated version named: /);
  });

  it("output that names the deprecated version with no failing: line fails the case", () => {
    expect(() =>
      expectDeprecatedDependencyCaught(runOf([NAMED]), DEPRECATED),
    ).toThrow(/^consumer-closure listed as failing: /);
  });
});
