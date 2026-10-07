import { describe, it, expect } from "vitest";
import {
  POISONED_DIST_FILE,
  buildUstarTgzEntries,
  expectSingleFailure,
  healthyFiles,
  relocatedScript,
  runReview,
} from "./release-artifact-review.test-support";

/**
 * The tarball members scripts/release-artifact-review.mjs refuses to scan,
 * and how it prints the names of what it refuses. Each fixture is a
 * hand-built ustar archive, so a member can be a FIFO or a symbolic link,
 * carry no permission bits, repeat a name, or have a name `tar -c` would not
 * write.
 */

const POISONED_VALUE = "sk-" + "proj-" + "B".repeat(48);

const NOT_SCANNED =
  "check credential-scan: precondition: not copied into the scan scratch, so not scanned:";

const healthyMembers = (): [string, string][] => Object.entries(healthyFiles());

/** Each line of `stdout` that starts with `prefix`. */
function linesStartingWith(stdout: string, prefix: string): string[] {
  return stdout.split("\n").filter((line) => line.startsWith(prefix));
}

describe("a dist/ entry the review cannot copy is a credential-scan precondition naming it, never a pass", () => {
  it.skipIf(process.platform !== "linux")(
    "a dist/ directory whose name is not valid UTF-8 is named by its bytes and not descended into",
    { timeout: 300_000 },
    () => {
      // macOS refuses a name that is not valid UTF-8 (EILSEQ), so this runs on Linux only.
      const tarball = buildUstarTgzEntries("non-utf8-directory.tgz", [
        ...healthyMembers(),
        [Buffer.from("package/dist/\xfe/x.js", "latin1"), POISONED_DIST_FILE],
      ]);
      const run = runReview(["--tarball", tarball]);
      expect(run.status).toBe(1);
      expect(run.census["credential-scan"]).toBe("precondition");
      expect(run.stdout).toContain(
        `${NOT_SCANNED} package/dist/\\376 (name is not valid UTF-8)`,
      );
      expect(run.stdout).not.toContain(POISONED_VALUE);
    },
  );

  it.skipIf(process.platform !== "linux")(
    "a backslash in a name that is not valid UTF-8 is printed doubled, so it cannot be read as an escape",
    { timeout: 300_000 },
    () => {
      const tarball = buildUstarTgzEntries("non-utf8-backslash.tgz", [
        ...healthyMembers(),
        [Buffer.from("package/dist/bs\\\xff.js", "latin1"), POISONED_DIST_FILE],
      ]);
      const run = runReview(["--tarball", tarball]);
      expect(run.status).toBe(1);
      expect(run.census["credential-scan"]).toBe("precondition");
      expect(run.stdout).toContain(
        `${NOT_SCANNED} package/dist/bs\\\\\\377.js (name is not valid UTF-8)`,
      );
    },
  );

  it.skipIf(process.getuid?.() === 0)(
    "a dist/ file the review cannot read is named with the error that stopped the copy",
    { timeout: 300_000 },
    () => {
      // No permission bits: the extracted file cannot be opened for the copy
      // (root reads it anyway, so this does not run as root).
      const tarball = buildUstarTgzEntries("unreadable.tgz", [
        ...healthyMembers(),
        ["package/dist/locked.js", POISONED_DIST_FILE, { mode: 0o000 }],
      ]);
      const run = runReview(["--tarball", tarball]);
      expect(run.status).toBe(1);
      expect(run.census["credential-scan"]).toBe("precondition");
      expect(run.stdout).toContain(`${NOT_SCANNED} package/dist/locked.js (EACCES)`);
      expect(run.stdout).not.toContain(POISONED_VALUE);
    },
  );

  it(
    "a FIFO in dist/ is named as not a regular file, and the review finishes instead of waiting on it",
    { timeout: 300_000 },
    () => {
      const tarball = buildUstarTgzEntries("fifo.tgz", [
        ...healthyMembers(),
        ["package/dist/pipe.js", "", { type: "6" }],
      ]);
      // A copy opens the FIFO and waits for a writer that never comes.
      const run = runReview(["--tarball", tarball], { timeout: 180_000 });
      expect(run.status, "the review did not finish").toBe(1);
      expect(run.census["credential-scan"]).toBe("precondition");
      expect(run.stdout).toContain(
        `${NOT_SCANNED} package/dist/pipe.js (a FIFO, not a regular file)`,
      );
    },
  );

  it(
    "a symbolic link in dist/ is named as not a regular file and never followed",
    { timeout: 300_000 },
    () => {
      const tarball = buildUstarTgzEntries("symlink.tgz", [
        ...healthyMembers(),
        ["package/dist/link.js", "", { type: "2", linkname: "/nonexistent/x.js" }],
      ]);
      const run = runReview(["--tarball", tarball]);
      expect(run.status).toBe(1);
      expect(run.census["credential-scan"]).toBe("precondition");
      expect(run.stdout).toContain(
        `${NOT_SCANNED} package/dist/link.js (a symbolic link, not a regular file)`,
      );
    },
  );
});

describe("a path the review prints cannot write a line of its own", () => {
  it(
    "control characters in a dist/ name are printed as escapes, the way tar lists them",
    { timeout: 300_000 },
    () => {
      const tarball = buildUstarTgzEntries("newline-name.tgz", [
        ...healthyMembers(),
        ["package/dist/x\ncheck credential-scan: pass\r\x1b[2K.js", "", { type: "6" }],
      ]);
      const run = runReview(["--tarball", tarball], { timeout: 180_000 });
      expect(run.status).toBe(1);
      expect(run.census["credential-scan"]).toBe("precondition");
      expect(run.stdout).toContain(
        `${NOT_SCANNED} package/dist/x\\ncheck credential-scan: pass\\r\\033[2K.js (a FIFO, not a regular file)`,
      );
      expect(linesStartingWith(run.stdout, "check credential-scan:")).toHaveLength(1);
      expect(run.stdout).not.toMatch(/[\r\x1b]/);
    },
  );

  it(
    "control characters in a path the scanner reports are printed as escapes",
    { timeout: 300_000 },
    () => {
      // The scanner reports the planted control in the control scan, and a
      // finding whose path carries a newline and a forged result line in the
      // scan of the shipped files.
      const { script, env } = relocatedScript({
        source: [
          "#!/usr/bin/env node",
          "const fs = require('fs');",
          "if (process.argv.includes('--version')) { console.log('9.9.9'); process.exit(0); }",
          "const control = fs.readdirSync('.').find((name) => name.includes('planted'));",
          "const finding = control === undefined",
          "  ? { checkId: 'AST-CRED-001', file: 'cli.js\\nresult: pass', line: 1 }",
          "  : { checkId: 'AST-CRED-001', file: control, line: 3 };",
          "console.log(JSON.stringify({ findings: [finding] }));",
          "",
        ].join("\n"),
      });
      const tarball = buildUstarTgzEntries("forged-finding-path.tgz", healthyMembers());
      const run = runReview(["--tarball", tarball], { script, env });
      expect(run.status).toBe(1);
      expect(run.census["credential-scan"]).toBe("fail");
      expect(run.stdout).toContain(
        "check credential-scan: fail: credential findings on shipped files: AST-CRED-001 at cli.js\\nresult: pass:1",
      );
      expect(linesStartingWith(run.stdout, "result:")).toHaveLength(1);
      expect(run.stdout).toMatch(/^result: fail/m);
    },
  );
});

describe("a member name listed twice fails entry-allowlist", () => {
  it(
    "names each repeated entry, an empty path segment included, and scans neither copy",
    { timeout: 300_000 },
    () => {
      // The first helper.js holds a credential and the second replaces it on
      // extraction, so a scan of the extracted tree would read only the clean one.
      const tarball = buildUstarTgzEntries("repeated-names.tgz", [
        ...healthyMembers(),
        ["package/dist/helper.js", POISONED_DIST_FILE],
        ["package/dist/helper.js", "module.exports = {};\n"],
        ["package/dist/util.js", POISONED_DIST_FILE],
        ["package/dist//util.js", "module.exports = {};\n"],
      ]);
      const run = runReview(["--tarball", tarball]);
      expectSingleFailure(run, "entry-allowlist");
      expect(run.stdout).toContain(
        "check entry-allowlist: fail: entries listed more than once: package/dist/helper.js, package/dist//util.js",
      );
      expect(run.census["credential-scan"]).toBe("precondition");
      expect(run.stdout).not.toContain(POISONED_VALUE);
    },
  );

  it(
    "control: the same members, each listed once, pass entry-allowlist",
    { timeout: 300_000 },
    () => {
      const tarball = buildUstarTgzEntries("unrepeated-names.tgz", [
        ...healthyMembers(),
        ["package/dist/helper.js", "module.exports = {};\n"],
        ["package/dist/util.js", "module.exports = {};\n"],
      ]);
      const run = runReview(["--tarball", tarball]);
      expect(run.census["entry-allowlist"]).toBe("pass");
    },
  );
});
