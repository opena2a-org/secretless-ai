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
 * What a scan returns when `read` can count all of it: `T`, but no promise
 * or other thenable, whose scan goes on after it has returned.
 */
type SyncResult<T> = T extends PromiseLike<unknown> ? never : T;

/** Whether `value` is a promise or another thenable, which an `await` waits on. */
function isThenable(value: unknown): boolean {
  return typeof (value as { then?: unknown } | null | undefined)?.then === "function";
}

/**
 * `content` as a string that counts the characters read from it. A method
 * call is charged what it scans or copies (`indexOf` up to its match, `slice`
 * and its kin their result, a one-character read one) and any other method a
 * whole pass. An index read is charged one character. The count depends on
 * the code, not the machine.
 *
 * The count follows the content where a method takes it: a string a method
 * returns or an index read gives, alone or held by an array, a match or an
 * iterator, is a counting string on the same counter, charged by its own
 * length, and so is a string `String.fromCharCode` or `String.fromCodePoint`
 * makes while `read` runs a scan. A single character is one too, so a copy
 * put together from the characters a scan reads, or from their codes, is put
 * together from counting strings. Reads of a plain string cannot be counted,
 * so `plainStrings` names what handed one out: a conversion to a primitive
 * string, which putting such a copy together makes, and a function given to
 * a method, which the method calls with plain strings. A scan must therefore
 * read the content through String.prototype methods called on it, or by
 * index, `content.matchAll(pattern)` and not `pattern.exec(content)`: a
 * RegExp method given the content converts it, so even a linear `exec` loop
 * is named. A counting string is an object, so a character never `===` the
 * character it is: compare it by its code. `characters` counts the single
 * characters handed out, so a wrong line can be put down to such a compare.
 *
 * `read` counts a scan until it returns: from then on the two `String`
 * functions make plain strings again. A copy a scan that returns a promise
 * makes from character codes after its first `await` is therefore a plain
 * string, which nothing names. `read` takes no such scan: the type of a scan
 * leaves one out, and `read` fails when a scan returns a thenable all the
 * same.
 */
function countingString(content: string): {
  text: string;
  read: <T>(scan: (text: string) => SyncResult<T>) => T;
  charsRead: () => number;
  characters: () => number;
  plainStrings: () => string[];
} {
  let charsRead = 0;
  let characters = 0;
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
  // depth, a counting one, but the empty string, which has nothing to read.
  // An array or a match wraps a string when it is read from it, so taking
  // only its length wraps none.
  const counted = (value: unknown): unknown => {
    if (typeof value === "string") {
      if (value.length === 1) characters += 1;
      return value.length > 0 ? counting(value) : value;
    }
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
    const boxed = new String(plain);
    // A String object holds each character as a fixed property, which a
    // proxy of it must hand out as it is: the target holds none of them, so
    // an index read can hand out a counting string.
    const target: object = Object.create(String.prototype, { length: { value: length } });
    const text = new Proxy(target, {
      has: (_target, key) => Reflect.has(boxed, key),
      get(_target, key) {
        if (key === Symbol.toPrimitive) {
          return () => {
            plainStrings.add("a conversion to a primitive string");
            return plain;
          };
        }
        const value: unknown = Reflect.get(boxed, key);
        if (typeof key === "string" && /^\d+$/.test(key)) {
          charsRead += 1;
          return counted(value);
        }
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
  const text = counting(content);
  // A number stays a number, so a string made from the codes a scan reads is
  // a counting string only because these two make one while the scan runs.
  const read = <T>(scan: (text: string) => SyncResult<T>): T => {
    const { fromCharCode, fromCodePoint } = String;
    String.fromCharCode = (...codes: number[]) => counted(fromCharCode(...codes)) as string;
    String.fromCodePoint = (...codes: number[]) => counted(fromCodePoint(...codes)) as string;
    let result: T;
    try {
      result = scan(text);
    } finally {
      String.fromCharCode = fromCharCode;
      String.fromCodePoint = fromCodePoint;
    }
    // The type leaves a promise out, but a scan typed as returning its result
    // can return one all the same, as a function read from a module can.
    if (isThenable(result)) {
      throw new Error(
        "the scan returned a promise: read has String.fromCharCode and String.fromCodePoint make " +
          "counting strings only until the scan returns, so a copy the scan makes from character " +
          "codes after its first await is a plain string, whose reads no count sees and nothing " +
          "names. Give read a scan that returns its result, not a promise of it",
      );
    }
    return result;
  };
  return {
    text,
    read,
    charsRead: () => charsRead,
    characters: () => characters,
    plainStrings: () => [...plainStrings],
  };
}

/** What makes each thing `plainStrings` names hand out a plain string, and what a scan does instead. */
function becauseOf(handedOut: string): string {
  if (handedOut === "a conversion to a primitive string") {
    return (
      "which a RegExp method given the content (pattern.exec(content)), String(content), a template " +
      "literal, a concatenation and a copy put together from its characters or their codes each make: " +
      "call String.prototype methods on the content instead (content.matchAll(pattern))"
    );
  }
  return (
    "which the method calls with plain strings: read each match from content.matchAll(pattern) " +
    "instead of giving a method a function"
  );
}

/**
 * Fails when a counting string handed out a plain string, whose reads are
 * in no count, naming what handed it out and how a scan reads the content
 * instead.
 */
function expectNoPlainStrings(plainStrings: string[]): void {
  expect(
    plainStrings,
    "the scan read the content as a plain string, which no count sees, handed out by " +
      plainStrings.map((handedOut) => `${handedOut}, ${becauseOf(handedOut)}`).join("; and by "),
  ).toEqual([]);
}

/**
 * Fails when `lines` is not 1, 2, 3 and on, naming the first hit on another
 * line. When the scan read single characters, each a counting string that
 * never `===` the character it is, the failure says to compare their codes.
 */
function expectEveryLine(lines: number[], characters: number): void {
  const wrong = lines.findIndex((line, i) => line !== i + 1);
  const compare =
    characters === 0
      ? ""
      : `: the scan read ${characters} single characters from the content, each a counting ` +
        "string, an object that never === the character it is, so compare its code " +
        '(content.charCodeAt(pos) === 10, not content[pos] === "\\n")';
  expect(wrong, `hit ${wrong + 1} is on line ${lines[wrong]}, not ${wrong + 1}${compare}`).toBe(-1);
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

    const hits = content.read((text) => mod.retractedClaimsIn(text));

    expect(hits.length).toBe(count);
    expectEveryLine(
      hits.map((hit) => hit.line),
      content.characters(),
    );
    // Reads of a plain string are in no count, so none may be handed out.
    expectNoPlainStrings(content.plainStrings());
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
    const lines = content.read(scan);
    return {
      lines,
      passes: content.charsRead() / file.length,
      characters: content.characters(),
      plainStrings: content.plainStrings(),
    };
  };

  /**
   * The line of each hit in `content`, from a count of the newlines before it
   * made one character at a time, each looked at with `isNewline`.
   */
  const linesCountedByCharacter =
    (isNewline: (content: string, pos: number) => boolean) =>
    (content: string): number[] => {
      const lines: number[] = [];
      let line = 1;
      let pos = 0;
      for (const match of content.matchAll(/hit/g)) {
        while (pos < (match.index ?? 0)) {
          if (isNewline(content, pos)) line += 1;
          pos += 1;
        }
        lines.push(line);
      }
      return lines;
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

  it.each<[string, (content: string) => string]>([
    ["Array.from", (content) => Array.from(content).join("")],
    ["a spread", (content) => [...content].join("")],
    ["split('')", (content) => content.split("").join("")],
    [
      "an index read",
      (content) => {
        let copy = "";
        for (let i = 0; i < content.length; i += 1) copy += content[i];
        return copy;
      },
    ],
    [
      "charAt",
      (content) => {
        let copy = "";
        for (let i = 0; i < content.length; i += 1) copy += content.charAt(i);
        return copy;
      },
    ],
  ])(
    "names a copy put together from the characters %s hands out, which a line count made once per hit reads",
    (_how, copyOf) => {
      const { lines, plainStrings } = readsOf((content) => linesCountedPerHit(copyOf(content)));
      expect(lines).toEqual(everyLine);
      expect(plainStrings).toEqual(["a conversion to a primitive string"]);
    },
  );

  it.each<[string, (content: string) => string]>([
    [
      "String.fromCharCode",
      (content) => {
        let copy = "";
        for (let i = 0; i < content.length; i += 1) copy += String.fromCharCode(content.charCodeAt(i));
        return copy;
      },
    ],
    [
      "String.fromCodePoint",
      (content) => {
        let copy = "";
        for (let i = 0; i < content.length; i += 1) {
          copy += String.fromCodePoint(content.codePointAt(i) ?? 0);
        }
        return copy;
      },
    ],
  ])(
    "names a copy put together from the strings %s makes of the character codes, which a line count made once per hit reads",
    (_how, copyOf) => {
      const { lines, plainStrings } = readsOf((content) => linesCountedPerHit(copyOf(content)));
      expect(lines).toEqual(everyLine);
      expect(plainStrings).toEqual(["a conversion to a primitive string"]);
      expect(() => expectNoPlainStrings(plainStrings)).toThrow(
        /a copy put together from its characters or their codes/,
      );
    },
  );

  it("counts a line count made once per hit on the copy String.fromCharCode makes of every character code at once", () => {
    const { lines, passes, plainStrings } = readsOf((content) => {
      const codes: number[] = [];
      for (let i = 0; i < content.length; i += 1) codes.push(content.charCodeAt(i));
      return linesCountedPerHit(String.fromCharCode(...codes));
    });
    expect(lines).toEqual(everyLine);
    expect(plainStrings).toEqual([]);
    expect(passes).toBeGreaterThan(count / 2);
  });

  it("control: String.fromCharCode makes a plain string again once the scan is over", () => {
    const content = countingString(file);
    expect(content.read(() => typeof String.fromCharCode(104))).toBe("object");
    expect(String.fromCharCode(104)).toBe("h");
    expect(String.fromCodePoint(104)).toBe("h");
  });

  it("fails a scan that returns a promise, whose copy made from character codes after an await is a plain string", async () => {
    const content = countingString(file);
    const made: string[] = [];
    const scan = async (): Promise<void> => {
      made.push(typeof String.fromCharCode(104));
      await 0;
      made.push(typeof String.fromCharCode(104));
    };
    let scanned = Promise.resolve();
    expect(() =>
      // @ts-expect-error the type of a scan leaves out one that returns a promise
      content.read(() => (scanned = scan())),
    ).toThrow(
      /^the scan returned a promise: .* makes from character codes after its first await is a plain string, whose reads no count sees and nothing names\. Give read a scan that returns its result, not a promise of it$/,
    );
    // What the failure is for: the scan was over for read at its first await.
    await scanned;
    expect(made).toEqual(["object", "string"]);
    expect(String.fromCharCode(104)).toBe("h");
    expect(String.fromCodePoint(104)).toBe("h");
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

  it("fails a linear exec loop, naming the conversion and saying to call String.prototype methods on the content", () => {
    const { lines, passes, plainStrings } = readsOf((content) => {
      const lines: number[] = [];
      const pattern = /hit/g;
      let line = 1;
      let newline = content.indexOf("\n");
      for (let match = pattern.exec(content); match; match = pattern.exec(content)) {
        while (newline !== -1 && newline < match.index) {
          line += 1;
          newline = content.indexOf("\n", newline + 1);
        }
        lines.push(line);
      }
      return lines;
    });
    expect(lines).toEqual(everyLine);
    // The loop's own reads, its indexOf calls, are the one pass counted: the
    // regular expression read a plain string, so its pass is in no count.
    expect(passes).toBe(1);
    expect(plainStrings).toEqual(["a conversion to a primitive string"]);
    expect(() => expectNoPlainStrings(plainStrings)).toThrow(
      /handed out by a conversion to a primitive string, which a RegExp method given the content \(pattern\.exec\(content\)\).*: call String\.prototype methods on the content instead \(content\.matchAll\(pattern\)\)/,
    );
  });

  it.each<[string, (content: string) => unknown, string]>([
    [
      "a copy put together from Array.from",
      (content) => Array.from(content).join(""),
      "handed out by a conversion to a primitive string, which a RegExp method given the content " +
        "(pattern.exec(content)), String(content), a template literal, a concatenation and a copy " +
        "put together from its characters or their codes each make",
    ],
    [
      "replace given a function",
      (content) => content.replace(/(?!)/g, () => ""),
      "handed out by replace given a function, which the method calls with plain strings: read " +
        "each match from content.matchAll(pattern) instead of giving a method a function",
    ],
  ])("fails a scan that reads %s, naming what handed out the plain string", (_how, scan, says) => {
    const { plainStrings } = readsOf((content) => {
      scan(content);
      return [];
    });
    let failure = "";
    try {
      expectNoPlainStrings(plainStrings);
    } catch (error) {
      failure = (error as Error).message;
    }
    expect(failure).toContain(says);
    // Only the conversion is put down to a RegExp method.
    if (!says.includes("conversion")) expect(failure).not.toContain("pattern.exec(content)");
  });

  it("fails a linear scan that compares the characters it reads with ===, saying to compare their codes", () => {
    const { lines, characters, plainStrings } = readsOf(
      linesCountedByCharacter((content, pos) => content[pos] === "\n"),
    );
    expect(plainStrings).toEqual([]);
    expect(characters).toBeGreaterThan(0);
    expect(() => expectEveryLine(lines, characters)).toThrow(
      /^hit 2 is on line 1, not 2: the scan read \d+ single characters from the content, each a counting string, an object that never === the character it is, so compare its code \(content\.charCodeAt\(pos\) === 10, not content\[pos\] === "\\n"\)/,
    );
  });

  it("control: the same scan comparing the codes of the characters it reads passes, in about two passes", () => {
    const { lines, passes, characters, plainStrings } = readsOf(
      linesCountedByCharacter((content, pos) => content.charCodeAt(pos) === 10),
    );
    expect(characters).toBe(0);
    expectEveryLine(lines, characters);
    expectNoPlainStrings(plainStrings);
    // The match iteration is a pass, and the codes read up to the last hit
    // nearly another.
    expect(passes).toBeGreaterThan(1);
    expect(passes).toBeLessThanOrEqual(2);
  });

  it("control: a wrong line from a scan that read no single character says only which hit", () => {
    expect(() => expectEveryLine([1, 1, 3], 0)).toThrow(/^hit 2 is on line 1, not 2: expected 1 to be -1/);
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

  it("control: a single character read from the content is that character, read on the same counter", () => {
    const content = countingString(file);
    const byIndex = content.text[3];
    const byCharAt = content.text.charAt(3);
    expect(content.charsRead()).toBe(2);
    // A counting string is an object, so each is compared by its code.
    expect(byIndex.length).toBe(1);
    expect(byIndex.charCodeAt(0)).toBe("\n".charCodeAt(0));
    expect(byCharAt.length).toBe(1);
    expect(byCharAt.charCodeAt(0)).toBe("\n".charCodeAt(0));
    expect(content.charsRead()).toBe(4);
    expect(content.plainStrings()).toEqual([]);
  });

  it("control: the counting string has each of its indexes and its own length, as a String object does", () => {
    const content = countingString(file);
    const text = content.text as unknown as object;
    expect(3 in text).toBe(true);
    expect(file.length in text).toBe(false);
    expect(Object.getOwnPropertyDescriptor(text, "length")).toEqual(
      Object.getOwnPropertyDescriptor(new String(file), "length"),
    );
    // An array method given the string visits each index it has, reading each once.
    let newlines = 0;
    const visited = Array.prototype.map.call(text, (character: string) => {
      if (character.charCodeAt(0) === 10) newlines += 1;
      return character;
    });
    expect(Object.keys(visited).length).toBe(file.length);
    expect(newlines).toBe(count);
    expect(content.plainStrings()).toEqual([]);
  });

  it("control: an empty string a method returns is the plain empty string, false as a condition", () => {
    const content = countingString(file);
    const pieces = content.text.split("\n");
    expect(pieces[count]).toBe("");
    expect(content.text.slice(0, 0)).toBe("");
    expect(pieces.filter((piece) => piece).length).toBe(count);
    expect(content.plainStrings()).toEqual([]);
  });

  it("control: the scan of a copy with other line endings stays within a few passes", async () => {
    const mod = await loadRetractedClaims();
    const { text } = mod.RETRACTED_CLAIMS[0];
    const content = countingString(`${text}\r\n`.repeat(count));

    const hits = content.read((crlf) => mod.retractedClaimsIn(crlf.replace(/\r\n/g, "\n")));

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
