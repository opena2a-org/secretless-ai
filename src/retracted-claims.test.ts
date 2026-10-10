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

/**
 * `content` as a string that counts the characters read from it. A method
 * call is charged what it scans or copies (`indexOf` up to its match, `slice`
 * and its kin their result, a one-character read one) and any other method a
 * whole pass. An index read is charged one character. The count depends on
 * the code, not the machine.
 *
 * The count follows the content where a method takes it: a string a method
 * returns, alone or held by an array, a match or an iterator, is a counting
 * string on the same counter, charged by its own length. Reads of a plain
 * string cannot be counted, so `plainStrings` names what handed one out: a
 * conversion to a primitive string, and a function given to a method, which
 * the method calls with plain strings. A string of one character stays
 * plain, so it still equals the character it is: it was charged when it was
 * read. A copy put together from such characters is read uncounted.
 */
function countingString(content: string): {
  text: string;
  charsRead: () => number;
  plainStrings: () => string[];
} {
  let charsRead = 0;
  const plainStrings = new Set<string>();
  const charge = (length: number, method: string, args: unknown[], result: unknown): number => {
    switch (method) {
      case "indexOf": {
        const from = Math.min(Math.max(Math.trunc(Number(args[1])) || 0, 0), length);
        const end = result === -1 ? length : (result as number) + String(args[0]).length;
        return end - from;
      }
      case "slice":
      case "substring":
      case "substr":
        return (result as string).length;
      case "at":
      case "charAt":
      case "charCodeAt":
      case "codePointAt":
        return 1;
      default:
        return length;
    }
  };
  // `value` as the code under test gets it: each string it holds, at any
  // depth, a counting one. An array or a match wraps a string when it is read
  // from it, so taking only its length wraps none.
  const counted = (value: unknown): unknown => {
    if (typeof value === "string") return value.length > 1 ? counting(value) : value;
    if (typeof value !== "object" || value === null) return value;
    if (!Array.isArray(value) && Symbol.iterator in value) {
      const items = value as Iterable<unknown>;
      return (function* () {
        for (const item of items) yield counted(item);
      })();
    }
    return new Proxy(value, {
      get: (target, key, receiver) => counted(Reflect.get(target, key, receiver)),
    });
  };
  const counting = (plain: string): string => {
    const length = plain.length;
    const text = new Proxy(new String(plain), {
      get(target, key) {
        if (key === Symbol.toPrimitive) {
          return () => {
            plainStrings.add("a conversion to a primitive string");
            return plain;
          };
        }
        const value: unknown = Reflect.get(target, key);
        if (typeof key === "string" && /^\d+$/.test(key)) charsRead += 1;
        if (typeof value !== "function" || key === "constructor") return value;
        return (...args: unknown[]) => {
          if (args.some((arg) => typeof arg === "function")) {
            plainStrings.add(`${String(key)} given a function`);
          }
          const result: unknown = value.apply(plain, args);
          charsRead += charge(length, String(key), args, result);
          return counted(result);
        };
      },
    });
    return text as unknown as string;
  };
  return {
    text: counting(content),
    charsRead: () => charsRead,
    plainStrings: () => [...plainStrings],
  };
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

  it("gives each of several hits its own line, two on one line included", async () => {
    const mod = await loadRetractedClaims();
    for (const { text } of mod.RETRACTED_CLAIMS) {
      const content = ["/**", ` * ${text} ${text}`, " */", "", `// ${text}`].join("\n");
      expect(mod.retractedClaimsIn(content)).toEqual([
        { claim: text, line: 2 },
        { claim: text, line: 2 },
        { claim: text, line: 5 },
      ]);
    }
  });

  it("reads a file with many hits in one pass, not once per hit", async () => {
    const mod = await loadRetractedClaims();
    const { text } = mod.RETRACTED_CLAIMS[0];
    const count = 25_000;
    const content = countingString(`${text}\n`.repeat(count));

    const hits = mod.retractedClaimsIn(content.text);

    expect(hits.length).toBe(count);
    expect(hits.every((hit, i) => hit.line === i + 1)).toBe(true);
    // Reads of a plain string are in no count, so none may be handed out.
    expect(content.plainStrings()).toEqual([]);
    // Counting each hit's line from the start of the file read it about
    // count / 2 times over; one pass per listed claim, plus one to count
    // lines, reads it a few times.
    const passes = content.charsRead() / content.text.length;
    expect(passes).toBeGreaterThan(0);
    expect(passes).toBeLessThanOrEqual(2 * mod.RETRACTED_CLAIMS.length + 1);
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

describe("the counting string counts a copy's reads and names a plain string it hands out", () => {
  const count = 400;
  const file = "hit\n".repeat(count);
  const everyLine = Array.from({ length: count }, (_, i) => i + 1);

  /** The line of each hit in `whole`, counted from the start of `whole` for every hit. */
  const linesCountedPerHit = (whole: string): number[] =>
    Array.from(whole.matchAll(/hit/g), (match) => whole.slice(0, match.index).split("\n").length);

  /**
   * The lines `scan` found in `file`, the passes it made over it, and what
   * handed it a plain string.
   */
  const readsOf = (scan: (content: string) => number[]) => {
    const content = countingString(file);
    const lines = scan(content.text);
    return {
      lines,
      passes: content.charsRead() / file.length,
      plainStrings: content.plainStrings(),
    };
  };

  it.each<[string, (content: string) => string]>([
    ["replace", (content) => content.replace(/\r\n/g, "\n")],
    ["toString", (content) => content.toString()],
    ["valueOf", (content) => content.valueOf()],
    ["slice", (content) => content.slice(0)],
    ["concat", (content) => content.concat("")],
    ["normalize", (content) => content.normalize()],
  ])("counts a line count made once per hit on the string %s returns", (_method, copyOf) => {
    const { lines, passes, plainStrings } = readsOf((content) =>
      linesCountedPerHit(copyOf(content)),
    );
    expect(lines).toEqual(everyLine);
    expect(plainStrings).toEqual([]);
    expect(passes).toBeGreaterThan(count / 2);
  });

  it.each<[string, (content: string) => string]>([
    ["String()", (content) => String(content)],
    ["a template literal", (content) => `${content}`],
    ["a concatenation", (content) => content + ""],
  ])("names %s, whose plain string a line count made once per hit reads", (_how, plainOf) => {
    const { lines, plainStrings } = readsOf((content) => linesCountedPerHit(plainOf(content)));
    expect(lines).toEqual(everyLine);
    expect(plainStrings).toEqual(["a conversion to a primitive string"]);
  });

  it("names a regular expression run on the content, which converts it", () => {
    const { lines, plainStrings } = readsOf((content) => {
      const lines: number[] = [];
      const pattern = /hit/g;
      for (let match = pattern.exec(content); match; match = pattern.exec(content)) {
        lines.push(match.input.slice(0, match.index).split("\n").length);
      }
      return lines;
    });
    expect(lines).toEqual(everyLine);
    expect(plainStrings).toEqual(["a conversion to a primitive string"]);
  });

  it("counts a line count made once per hit on the input a match carries", () => {
    const { lines, passes, plainStrings } = readsOf((content) =>
      Array.from(
        content.matchAll(/hit/g),
        (match) => (match.input ?? "").slice(0, match.index).split("\n").length,
      ),
    );
    expect(lines).toEqual(everyLine);
    expect(plainStrings).toEqual([]);
    expect(passes).toBeGreaterThan(count / 2);
  });

  it("counts a read of a string in an array a method returns", () => {
    const content = countingString(file);
    const pieces = content.text.split("\n");
    const before = content.charsRead();
    expect(pieces.length).toBe(count + 1);
    expect(pieces[1].indexOf("t")).toBe(2);
    expect(content.charsRead() - before).toBe(3);
    expect(content.plainStrings()).toEqual([]);
  });

  it("names a function given to a method, which the method calls with plain strings", () => {
    const { lines, plainStrings } = readsOf((content) => {
      const lines: number[] = [];
      content.replace(/hit/g, (hit: string, index: number, whole: string) => {
        lines.push(whole.slice(0, index).split("\n").length);
        return hit;
      });
      return lines;
    });
    expect(lines).toEqual(everyLine);
    expect(plainStrings).toEqual(["replace given a function"]);
  });

  it("control: a single character read from the content equals that character", () => {
    const content = countingString(file);
    expect(content.text[3] === "\n").toBe(true);
    expect(content.text.charAt(3) === "\n").toBe(true);
    expect(content.charsRead()).toBe(2);
    expect(content.plainStrings()).toEqual([]);
  });

  it("control: the scan of a copy with other line endings stays within a few passes", async () => {
    const mod = await loadRetractedClaims();
    const { text } = mod.RETRACTED_CLAIMS[0];
    const content = countingString(`${text}\r\n`.repeat(count));

    const hits = mod.retractedClaimsIn(content.text.replace(/\r\n/g, "\n"));

    expect(hits.map((hit) => hit.line)).toEqual(everyLine);
    expect(content.plainStrings()).toEqual([]);
    // More than the pass the copy took: the scan's reads of the copy count.
    const passes = content.charsRead() / content.text.length;
    expect(passes).toBeGreaterThan(1);
    expect(passes).toBeLessThanOrEqual(2 * mod.RETRACTED_CLAIMS.length + 1);
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
