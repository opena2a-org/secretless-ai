import { afterAll, expect } from "vitest";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as net from "net";
import * as path from "path";
import * as zlib from "zlib";

/**
 * Fixtures and runners shared by the tests of
 * scripts/release-artifact-review.mjs: tarballs built file-by-file, the
 * script spawned on one and its census parsed, and a copy of the script whose
 * scanner resolution the test controls.
 *
 * Excluded from the build (tsconfig: `*.test-support.ts`) and from the test
 * glob (`*.test.ts`), so it ships in neither.
 */

export const REPO_ROOT = path.resolve(__dirname, "..");
export const SCRIPT = path.join(REPO_ROOT, "scripts", "release-artifact-review.mjs");
export const CHILD_ENV_MODULE = path.join(REPO_ROOT, "scripts", "child-env.mjs");
export const RETRACTED_CLAIMS_MODULE = path.join(REPO_ROOT, "scripts", "retracted-claims.mjs");

export const CHECKS = [
  "entry-allowlist",
  "no-dotfiles",
  "no-test-material",
  "dist-containment",
  "no-install-scripts",
  "pinned-first-party-deps",
  "no-retracted-claims",
  "npm-audit",
  "global-install-smoke",
  "credential-scan",
  "consumer-closure",
];

// ---------------------------------------------------------------------------
// Fixtures: tarballs built file-by-file
// ---------------------------------------------------------------------------

// Everything below executes files it just wrote — installed bins, stub
// scanners — so the scratch space must live on an exec-mounted filesystem.
// /tmp is noexec in some sandboxes; node_modules/.cache (gitignored,
// guaranteed present once vitest itself is installed) is not. The script's
// own work dir follows via TMPDIR.
const scratchBase = path.join(
  REPO_ROOT,
  "node_modules",
  ".cache",
  "release-review-tests",
);
fs.mkdirSync(scratchBase, { recursive: true });
export const tmpRoot = fs.mkdtempSync(path.join(scratchBase, "run-"));
afterAll(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));

export const FIXTURE_CLI = [
  "#!/usr/bin/env node",
  "if (process.argv[2] === '--version') { console.log('0.0.0-fixture'); process.exit(0); }",
  "console.log('usage: fixture'); process.exit(0);",
  "",
].join("\n");

// A shipped file carrying a value of the planted control's class: a
// credential-named const assembled at runtime from parts, same shape the
// script plants (sk- + proj- + 48 repeated characters), so no
// credential-shaped literal exists in this repository either.
export const POISONED_DIST_FILE = [
  `const OPENAI_API_KEY = ${JSON.stringify("sk-" + "proj-" + "B".repeat(48))};`,
  "module.exports = { OPENAI_API_KEY };",
  "",
].join("\n");

export function fixturePackageJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify(
    {
      // Not an own-package name: the clean fixture's consumer closure must
      // hold zero own copies, so its consumer-closure check passes vacuously
      // with no advisory feed to read.
      name: "release-review-fixture",
      version: "0.0.0-fixture",
      license: "Apache-2.0",
      bin: {
        "secretless-ai": "dist/cli.js",
        "secretless-mcp": "dist/mcp-wrapper.js",
      },
      files: ["dist"],
      ...overrides,
    },
    null,
    2,
  );
}

export function healthyFiles(): Record<string, string> {
  return {
    "package/package.json": fixturePackageJson(),
    "package/README.md": "# fixture\n",
    "package/LICENSE": "Apache-2.0\n",
    "package/dist/cli.js": FIXTURE_CLI,
    "package/dist/mcp-wrapper.js": FIXTURE_CLI,
  };
}

/** A gzipped tarball with exactly these file entries, no directory entries. */
export function buildTarball(name: string, files: Record<string, string>): string {
  const stage = fs.mkdtempSync(path.join(tmpRoot, "stage-"));
  for (const [entry, content] of Object.entries(files)) {
    const target = path.join(stage, entry);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
    fs.chmodSync(target, 0o755);
  }
  const tarball = path.join(tmpRoot, name);
  const tar = spawnSync(
    "tar",
    ["-czf", tarball, "-C", stage, ...Object.keys(files)],
    { encoding: "utf-8" },
  );
  expect(tar.status, tar.stderr).toBe(0);
  return tarball;
}

export interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  census: Record<string, string>;
}

function parseCensus(stdout: string): Record<string, string> {
  const censusLine = /^census: (.+)$/m.exec(stdout);
  const census: Record<string, string> = {};
  if (censusLine) {
    for (const pair of censusLine[1].split(" ")) {
      const [check, status] = pair.split("=");
      census[check] = status;
    }
  }
  return census;
}

export function runReview(
  args: string[],
  options: {
    script?: string;
    env?: Record<string, string>;
    unset?: string[];
    timeout?: number;
  } = {},
): Run {
  const env: Record<string, string | undefined> = {
    ...process.env,
    TMPDIR: tmpRoot,
    ...(options.env ?? {}),
  };
  for (const name of options.unset ?? []) delete env[name];
  const run = spawnSync(process.execPath, [options.script ?? SCRIPT, ...args], {
    encoding: "utf-8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: options.timeout ?? 600_000,
    env,
  });
  return {
    status: run.status,
    stdout: run.stdout ?? "",
    stderr: run.stderr ?? "",
    census: parseCensus(run.stdout ?? ""),
  };
}

export interface Precondition {
  check: string;
  detail: string;
}

/** Every check the run reports as precondition, in census order, with its detail. */
export function preconditionsOf(run: Run): Precondition[] {
  return CHECKS.filter((check) => run.census[check] === "precondition").map(
    (check) => ({
      check,
      detail:
        new RegExp(`^check ${check}: precondition: (.*)$`, "m").exec(
          run.stdout,
        )?.[1] ?? "<no detail>",
    }),
  );
}

const UNSENT_ADVISORY_READ =
  /^advisories endpoint unreadable for (\S+) \(states: [a-z]+\): fetch failed: /;

/**
 * Why a precondition on the delivered tarball is reported as not measured, or
 * null when it fails the test. One precondition qualifies, on a run that
 * sends no GH_TOKEN and whose read advisoryReadOf held on this machine
 * (`readHeld`): consumer-closure's GitHub advisories read failing to fetch.
 * With no GH_TOKEN the read is held or the case is skipped, never sent, so a
 * read refused with HTTP 403 or 429 fails the test like any other
 * precondition. The script's verdict is unchanged: the check is still a
 * precondition and the script still exits non-zero, so the release `review`
 * job, which sends GH_TOKEN, still blocks on it.
 */
export function notMeasuredReason(
  precondition: Precondition,
  env: Record<string, string | undefined>,
  readHeld = false,
): string | null {
  if (precondition.check !== "consumer-closure") return null;
  // The advisory fetch sends authorization only for a non-empty GH_TOKEN.
  if (env.GH_TOKEN) return null;
  const unsent = readHeld ? UNSENT_ADVISORY_READ.exec(precondition.detail) : null;
  if (unsent !== null) {
    return `with no GH_TOKEN the advisories read for ${unsent[1]} was held on this machine; set GH_TOKEN to measure it`;
  }
  return null;
}

/** A local port nothing listens on: bound, read and closed again. */
export function closedPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as net.AddressInfo;
      server.close(() => resolve(port));
    });
  });
}

/**
 * Whether this node's fetch sends a request through `proxy` when started with
 * NODE_USE_ENV_PROXY=1, as the script's advisories read is. A node that
 * ignores it (Node 20) would send the read to api.github.com.
 */
export function fetchHonoursProxy(proxy: string): boolean {
  const probe = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      "try { await fetch('https://proxy-probe.invalid/'); } catch (e) { console.log(e.cause?.code ?? ''); }",
    ],
    {
      env: { PATH: process.env.PATH ?? "", NODE_USE_ENV_PROXY: "1", HTTPS_PROXY: proxy },
      encoding: "utf-8",
      timeout: 30_000,
    },
  );
  return (probe.stdout ?? "").trim() === "ECONNREFUSED";
}

/**
 * How a review run sends its GitHub advisories read, and the variables
 * runReview adds for it. With GH_TOKEN set the read is sent with the token.
 * With none, the read is held on this machine: HTTPS_PROXY names a closed
 * local port, which the script's fetch child honours (it starts with
 * NODE_USE_ENV_PROXY=1), and NO_PROXY names the npm registry host, so npm
 * still reaches the registry. Unauthenticated reads share one per-address
 * rate limit, which repeated runs of these tests used up. Where the read can
 * be neither sent with a token nor held, it is not sent: the case that would
 * send it skips with `note`, which says why and names GH_TOKEN. That mode
 * carries no variables for runReview, so a case cannot run the review with it.
 * `honoursProxy` is the probe of this node's fetch.
 */
export type AdvisoryRead =
  | { mode: "authenticated"; env: Record<string, string> }
  | { mode: "held"; env: Record<string, string> }
  | { mode: "skip"; note: string };

const PROXY_VARIABLES = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];

export async function advisoryReadOf(
  env: Record<string, string | undefined> = process.env,
  honoursProxy: (proxy: string) => boolean = fetchHonoursProxy,
): Promise<AdvisoryRead> {
  if (env.GH_TOKEN) return { mode: "authenticated", env: {} };
  const unheld = (reason: string): AdvisoryRead => ({
    mode: "skip",
    note: `not measured: ${reason}; with no GH_TOKEN the advisories read could only be sent without a token, so it is not sent; set GH_TOKEN to measure it`,
  });

  // A configured proxy is how npm reaches the registry here; exempting the
  // registry from a closed proxy would take that route away.
  const proxyVariable = PROXY_VARIABLES.find((name) => env[name]);
  if (proxyVariable !== undefined) {
    return unheld(`${proxyVariable} is set, and holding the read would route npm around that proxy`);
  }
  const config = spawnSync(
    "npm",
    ["config", "get", "registry", "proxy", "https-proxy"],
    { env, encoding: "utf-8", timeout: 60_000 },
  );
  if (config.status !== 0) {
    return unheld(`npm config get exited ${config.status}, so the registry host is unknown`);
  }
  const settings = new Map<string, string>();
  for (const line of (config.stdout ?? "").split("\n")) {
    const at = line.indexOf("=");
    if (at > 0) settings.set(line.slice(0, at), line.slice(at + 1).trim());
  }
  for (const key of ["proxy", "https-proxy"]) {
    const value = settings.get(key);
    if (value !== undefined && value !== "null" && value !== "") {
      return unheld(`npm config sets ${key}, and holding the read would route npm around that proxy`);
    }
  }
  let registryHost: string;
  try {
    registryHost = new URL(settings.get("registry") ?? "").hostname;
  } catch {
    return unheld("npm config get printed no registry URL");
  }

  const proxy = `http://127.0.0.1:${await closedPort()}`;
  if (!honoursProxy(proxy)) {
    return unheld("this node's fetch ignores HTTPS_PROXY");
  }
  return {
    mode: "held",
    env: {
      HTTPS_PROXY: proxy,
      https_proxy: proxy,
      NO_PROXY: registryHost,
      no_proxy: registryHost,
    },
  };
}

/**
 * The deprecated-dependency case's judgment of its run: the script exits
 * non-zero, consumer-closure is a fail, the output names `dependency`
 * ("name@version") as deprecated, and the result line lists consumer-closure
 * as failing. The script keeps a deprecation it found when the advisories
 * read after it fails, so no precondition is accepted here, with or without
 * GH_TOKEN.
 */
export function expectDeprecatedDependencyCaught(
  run: Run,
  dependency: string,
): void {
  expect(run.status, "exit status").not.toBe(0);
  const precondition = preconditionsOf(run).find(
    ({ check }) => check === "consumer-closure",
  );
  expect(
    run.census["consumer-closure"],
    precondition === undefined
      ? "consumer-closure"
      : `consumer-closure precondition: ${precondition.detail}`,
  ).toBe("fail");
  expect(run.stdout, "deprecated version named").toContain(
    `${dependency} is deprecated`,
  );
  expect(run.stdout, "consumer-closure listed as failing").toMatch(
    /failing: .*consumer-closure/,
  );
}

export function expectSingleFailure(run: Run, check: string) {
  expect(run.status).not.toBe(0);
  const failing = CHECKS.filter((name) => run.census[name] === "fail");
  expect(failing).toEqual([check]);
  expect(run.stdout).toContain(`failing: ${check}`);
}

/**
 * A copy of the script rooted in a scratch directory, so its
 * node_modules/.bin scanner resolution is under the test's control. `env`
 * strips every node_modules/.bin entry off PATH (npm run puts this repo's on
 * PATH, which would hand the copy the real scanner as a fallback) while
 * keeping the system directories tar and npm live in.
 */
export function relocatedScript(binStub?: { source: string }): {
  script: string;
  env: Record<string, string>;
} {
  const root = fs.mkdtempSync(path.join(tmpRoot, "relocated-"));
  fs.mkdirSync(path.join(root, "scripts"));
  fs.copyFileSync(
    SCRIPT,
    path.join(root, "scripts", "release-artifact-review.mjs"),
  );
  fs.copyFileSync(CHILD_ENV_MODULE, path.join(root, "scripts", "child-env.mjs"));
  fs.copyFileSync(
    RETRACTED_CLAIMS_MODULE,
    path.join(root, "scripts", "retracted-claims.mjs"),
  );
  if (binStub) {
    const binDir = path.join(root, "node_modules", ".bin");
    fs.mkdirSync(binDir, { recursive: true });
    const stub = path.join(binDir, "hackmyagent");
    fs.writeFileSync(stub, binStub.source);
    fs.chmodSync(stub, 0o755);
  }
  // Also drop any directory that holds a scanner executable (a global install on a
  // developer machine): the relocated copy must see NO scanner unless the test plants one.
  // node and npm stay reachable through a private bin dir placed first: the
  // directory that holds a global scanner is often the one that holds node.
  const toolBin = path.join(root, "tool-bin");
  fs.mkdirSync(toolBin);
  fs.symlinkSync(process.execPath, path.join(toolBin, "node"));
  const npmPath = spawnSync("which", ["npm"], {
    encoding: "utf-8",
  }).stdout?.trim();
  if (npmPath) fs.symlinkSync(npmPath, path.join(toolBin, "npm"));
  const systemPath = [
    toolBin,
    ...(process.env.PATH ?? "")
      .split(path.delimiter)
      .filter(
        (dir) =>
          !dir.includes("node_modules") &&
          !fs.existsSync(path.join(dir, "hackmyagent")),
      ),
  ].join(path.delimiter);
  return {
    script: path.join(root, "scripts", "release-artifact-review.mjs"),
    env: { PATH: systemPath },
  };
}

/** A stub scanner that honours `secure --format json` but reports nothing. */
export const BLIND_SCANNER = [
  "#!/usr/bin/env node",
  "if (process.argv.includes('--version')) { console.log('9.9.9'); process.exit(0); }",
  "console.log(JSON.stringify({ findings: [] }));",
  "process.exit(0);",
  "",
].join("\n");

/**
 * How a ustar member is written: its type flag ("0" a regular file, "2" a
 * symbolic link, "6" a FIFO), its permission bits and, for a link, its target.
 */
export interface UstarMember {
  type?: string;
  mode?: number;
  linkname?: string;
}

function ustarHeader(name: string | Buffer, size: number, member: UstarMember = {}): Buffer {
  const header = Buffer.alloc(512, 0);
  if (typeof name === "string") header.write(name, 0, 100, "utf-8");
  else name.copy(header, 0, 0, 100);
  header.write((member.mode ?? 0o755).toString(8).padStart(7, "0") + "\0", 100, 8, "ascii");
  header.write("0000000\0", 108, 8, "ascii");
  header.write("0000000\0", 116, 8, "ascii");
  header.write(size.toString(8).padStart(11, "0") + "\0", 124, 12, "ascii");
  header.write("00000000000\0", 136, 12, "ascii");
  header.write("        ", 148, 8, "ascii"); // checksum field counted as spaces
  header.write(member.type ?? "0", 156, 1, "ascii");
  if (member.linkname !== undefined) header.write(member.linkname, 157, 100, "utf-8");
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "ascii");
  return header;
}

/** A ustar .tgz whose member names are written verbatim — `..` included. */
export function buildUstarTgz(name: string, files: Record<string, string>): string {
  return buildUstarTgzEntries(name, Object.entries(files));
}

/**
 * buildUstarTgz with each member name given as text or as raw bytes, so a name
 * need not be valid UTF-8, and optionally how the member is written.
 */
export function buildUstarTgzEntries(
  name: string,
  members: [string | Buffer, string, UstarMember?][],
): string {
  const blocks: Buffer[] = [];
  for (const [entry, content, member] of members) {
    const body = Buffer.from(content, "utf-8");
    blocks.push(ustarHeader(entry, body.length, member), body);
    const pad = (512 - (body.length % 512)) % 512;
    if (pad) blocks.push(Buffer.alloc(pad, 0));
  }
  blocks.push(Buffer.alloc(1024, 0));
  const tarball = path.join(tmpRoot, name);
  fs.writeFileSync(tarball, zlib.gzipSync(Buffer.concat(blocks)));
  return tarball;
}
