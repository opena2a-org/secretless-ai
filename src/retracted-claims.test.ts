import { describe, it, expect } from "vitest";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { pathToFileURL } from "url";
import {
  REPO_ROOT,
  RETRACTED_CLAIMS_MODULE,
  buildTarball,
  expectSingleFailure,
  healthyFiles,
  runReview,
  tmpRoot,
} from "./release-artifact-review.test-support";

/**
 * A security claim an earlier release shipped and the source withdrew
 * reaches no user until a release ships the correction: until then every
 * install carries the old text. scripts/retracted-claims.mjs lists each such
 * sentence. These tests hold the source and the tarball packed from it to
 * none of them, and the release review's `no-retracted-claims` check refuses
 * a tarball that carries one, naming the file and line.
 *
 * No sentence is written out in this file: each is read from the list, so
 * the walk of src/ below does not find this file.
 */

interface RetractedClaimsModule {
  RETRACTED_CLAIMS: { text: string; shipped: string }[];
  retractedClaimsIn(content: string): { claim: string; line: number }[];
}

function loadRetractedClaims(): Promise<RetractedClaimsModule> {
  return import(pathToFileURL(RETRACTED_CLAIMS_MODULE).href);
}

/** Every regular file under `dir`, as paths relative to it. */
function regularFilesUnder(dir: string): string[] {
  const out: string[] = [];
  const walk = (rel: string) => {
    for (const entry of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const child = rel === "" ? entry.name : path.join(rel, entry.name);
      if (entry.isDirectory()) walk(child);
      else if (entry.isFile()) out.push(child);
    }
  };
  walk("");
  return out.sort();
}

/** Each retracted claim the regular files under `dir` carry, as `file:line "claim"`. */
function claimsUnder(mod: RetractedClaimsModule, dir: string, label: string): string[] {
  const hits: string[] = [];
  for (const rel of regularFilesUnder(dir)) {
    const content = fs.readFileSync(path.join(dir, rel), "utf-8");
    for (const { claim, line } of mod.retractedClaimsIn(content)) {
      hits.push(`${label}/${rel}:${line} "${claim}"`);
    }
  }
  return hits;
}

/** The documentation 0.23.0 shipped on a GrantPolicy field, carrying `claim`. */
function grantPolicyDts(claim: string): string {
  return [
    "export interface GrantPolicyMatch {",
    "    /** Minimum ATX trust level. " + claim + " */",
    "    minTrustLevel?: number;",
    "}",
    "",
  ].join("\n");
}

describe("the retracted-claims list finds each sentence where a shipped file carries it", () => {
  it("lists at least the GrantPolicy field documentation 0.23.0 shipped", async () => {
    const mod = await loadRetractedClaims();
    expect(mod.RETRACTED_CLAIMS.length).toBeGreaterThan(0);
    expect(mod.RETRACTED_CLAIMS.map((c) => c.shipped).join("\n")).toContain(
      "dist/broker/grant-policy.d.ts",
    );
  });

  it("finds a claim on the line it starts on, also when a comment wraps it", async () => {
    const mod = await loadRetractedClaims();
    for (const { text } of mod.RETRACTED_CLAIMS) {
      expect(mod.retractedClaimsIn(grantPolicyDts(text))).toEqual([
        { claim: text, line: 2 },
      ]);

      const [first, ...rest] = text.split(" ");
      const wrapped = [
        "export interface GrantPolicyMatch {",
        "    /**",
        "     * Minimum ATX trust level. " + first,
        "     * " + rest.join(" "),
        "     */",
        "    minTrustLevel?: number;",
        "}",
      ].join("\n");
      expect(mod.retractedClaimsIn(wrapped)).toEqual([{ claim: text, line: 3 }]);
    }
  });

  it("control: a sentence that says the opposite, or another one, is not a hit", async () => {
    const mod = await loadRetractedClaims();
    for (const { text } of mod.RETRACTED_CLAIMS) {
      const lowered = text.charAt(0).toLowerCase() + text.slice(1);
      expect(mod.retractedClaimsIn(`/** Not ${lowered} */`)).toEqual([]);
      expect(mod.retractedClaimsIn(`/** Not${text} */`)).toEqual([]);
    }
    expect(mod.retractedClaimsIn("// Enforced predicates (v1).\n")).toEqual([]);
  });
});

describe("neither the source nor the tarball packed from it carries a retracted claim", () => {
  it("no file under src/ and not the README carries one", async () => {
    const mod = await loadRetractedClaims();
    const hits = claimsUnder(mod, path.join(REPO_ROOT, "src"), "src");
    for (const { claim, line } of mod.retractedClaimsIn(
      fs.readFileSync(path.join(REPO_ROOT, "README.md"), "utf-8"),
    )) {
      hits.push(`README.md:${line} "${claim}"`);
    }
    expect(hits).toEqual([]);
  });

  it(
    "the tarball npm packs from the delivered tree, dist/ included, carries none",
    { timeout: 300_000 },
    async () => {
      const mod = await loadRetractedClaims();
      const packDir = fs.mkdtempSync(path.join(tmpRoot, "pack-claims-"));
      const pack = spawnSync(
        "npm",
        ["pack", "--ignore-scripts", "--pack-destination", packDir],
        { cwd: REPO_ROOT, encoding: "utf-8", timeout: 300_000 },
      );
      expect(pack.status, pack.stderr).toBe(0);
      const tarball = path.join(packDir, pack.stdout.trim().split("\n").pop()!);
      const extractDir = path.join(packDir, "extract");
      fs.mkdirSync(extractDir);
      const tar = spawnSync("tar", ["-xzf", tarball, "-C", extractDir], {
        encoding: "utf-8",
      });
      expect(tar.status, tar.stderr).toBe(0);
      const packageDir = path.join(extractDir, "package");

      // The file 0.23.0 carried the claim in must be packed, or a tarball
      // without a built dist/ would pass by carrying nothing.
      expect(
        fs.existsSync(path.join(packageDir, "dist", "broker", "grant-policy.d.ts")),
        "dist/broker/grant-policy.d.ts is not in the packed tarball; run `npm run build` first",
      ).toBe(true);
      expect(claimsUnder(mod, packageDir, "package")).toEqual([]);
    },
  );
});

describe("the release review refuses a tarball that carries a retracted claim", () => {
  it(
    "a shipped .d.ts carrying one fails no-retracted-claims, naming the file and line",
    { timeout: 300_000 },
    async () => {
      const mod = await loadRetractedClaims();
      const claim = mod.RETRACTED_CLAIMS[0].text;
      const run = runReview([
        "--tarball",
        buildTarball("retracted-claim.tgz", {
          ...healthyFiles(),
          "package/dist/broker/grant-policy.d.ts": grantPolicyDts(claim),
        }),
      ]);
      expectSingleFailure(run, "no-retracted-claims");
      expect(run.stdout).toContain(
        `check no-retracted-claims: fail: retracted claims in shipped files: "${claim}" at package/dist/broker/grant-policy.d.ts:2`,
      );
    },
  );

  it(
    "a README carrying one fails no-retracted-claims too",
    { timeout: 300_000 },
    async () => {
      const mod = await loadRetractedClaims();
      const claim = mod.RETRACTED_CLAIMS[0].text;
      const run = runReview([
        "--tarball",
        buildTarball("retracted-claim-readme.tgz", {
          ...healthyFiles(),
          "package/README.md": `# fixture\n\nThe trust level is checked. ${claim}\n`,
        }),
      ]);
      expectSingleFailure(run, "no-retracted-claims");
      expect(run.stdout).toContain(`"${claim}" at package/README.md:3`);
    },
  );

  it(
    "control: the same tarball without the claim passes no-retracted-claims",
    { timeout: 300_000 },
    () => {
      const run = runReview([
        "--tarball",
        buildTarball("retracted-claim-control.tgz", {
          ...healthyFiles(),
          "package/dist/broker/grant-policy.d.ts": grantPolicyDts(""),
        }),
      ]);
      expect(run.census["no-retracted-claims"]).toBe("pass");
      expect(run.stdout).toMatch(
        /^check no-retracted-claims: pass: 6 files read, none carries any of the \d+ retracted claims$/m,
      );
    },
  );
});
