import { describe, it, expect } from "vitest";
import { spawn, spawnSync } from "child_process";
import * as fs from "fs";
import * as http from "http";
import type { AddressInfo } from "net";
import * as path from "path";
import { pathToFileURL } from "url";
import {
  CHILD_ENV_MODULE,
  POISONED_DIST_FILE,
  SCRIPT,
  buildTarball,
  buildUstarTgz,
  expectSingleFailure,
  fixturePackageJson,
  healthyFiles,
  relocatedScript,
  runReview,
  tmpRoot,
} from "./release-artifact-review.test-support";

/**
 * The environment scripts/release-artifact-review.mjs starts each child with
 * (scripts/child-env.mjs), and the dist/ file names its credential scan reads.
 *
 * Every child starts from an allowlist. npm's configuration reaches npm and
 * no other child, and GH_TOKEN reaches the advisory fetch and no other child.
 * Where a child is a program on PATH (npm, tar, the scanner) the review is run
 * with a recorder in its place, and the assertions read what each child was
 * given.
 */

interface ChildEnvModule {
  childEnv(
    extra?: Record<string, string>,
    env?: Record<string, string | undefined>,
  ): Record<string, string>;
  npmChildEnv(
    extra?: Record<string, string>,
    env?: Record<string, string | undefined>,
  ): Record<string, string>;
  fetchChildEnv(
    url: string,
    env?: Record<string, string | undefined>,
  ): Record<string, string>;
  fetchChild(
    url: string,
    env?: Record<string, string | undefined>,
  ): { command: string; args: string[]; env: Record<string, string> };
}

function loadChildEnv(): Promise<ChildEnvModule> {
  return import(pathToFileURL(CHILD_ENV_MODULE).href);
}

/**
 * A program that appends one line per call to `log` — its argv, its
 * environment's variable names and the few values the assertions need, never
 * a whole environment — and then runs `body`.
 */
function recorderSource(name: string, log: string, body: string[]): string {
  return [
    `#!${process.execPath}`,
    "const fs = require('fs');",
    "const argv = process.argv.slice(2);",
    "const env = process.env;",
    `fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ program: ${JSON.stringify(name)}, argv, names: Object.keys(env), home: env.HOME, npmConfig: env.npm_config_review_probe, noProxy: env.no_proxy, configHome: env.XDG_CONFIG_HOME }) + '\\n');`,
    ...body,
    "",
  ].join("\n");
}

/** The recorder written as the executable `name` in `dir`. */
function recordingProgram(dir: string, name: string, log: string, body: string[]): void {
  fs.writeFileSync(path.join(dir, name), recorderSource(name, log, body));
  fs.chmodSync(path.join(dir, name), 0o755);
}

/** Answers just enough for the review to start its ping, closure, audit and global install children. */
const NPM_BODY = [
  "if (argv[0] === 'install' && argv.includes('--package-lock-only')) {",
  "  fs.writeFileSync('package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'closure-scratch' } } }));",
  "}",
  "process.exit(0);",
];

/** Hands the call to the real tar, so listing and extraction still work. */
function tarBody(realTar: string): string[] {
  return [
    "const run = require('child_process').spawnSync(" +
      `${JSON.stringify(realTar)}, argv, { stdio: 'inherit' });`,
    "process.exit(run.status === null ? 1 : run.status);",
  ];
}

/** Honours `--version` and `secure --format json`, and reports nothing. */
const SCANNER_BODY = [
  "if (argv.includes('--version')) { console.log('9.9.9'); process.exit(0); }",
  "console.log(JSON.stringify({ findings: [] }));",
  "process.exit(0);",
];

interface ChildCall {
  program: string;
  argv: string[];
  names: string[];
  home?: string;
  npmConfig?: string;
  noProxy?: string;
  configHome?: string;
}

/** A UTF-8 locale this host offers, or undefined when `locale -a` lists none of these. */
const UTF8_LOCALE = (spawnSync("locale", ["-a"], { encoding: "utf-8" }).stdout ?? "")
  .split("\n")
  .map((name) => name.trim())
  .find((name) => /^(C|en_US)\.utf-?8$/i.test(name));

const NON_ASCII_FILES = {
  ...healthyFiles(),
  "package/dist/café.js": POISONED_DIST_FILE,
};

function expectNonAsciiCredentialCaught(run: ReturnType<typeof runReview>): void {
  expectSingleFailure(run, "credential-scan");
  expect(run.stdout.normalize("NFC")).toMatch(
    /check credential-scan: fail: .*café\.js:\d+/,
  );
  expect(run.stdout).not.toContain("sk-" + "proj-" + "B".repeat(48));
}

describe("each child of the review starts from an allowlist; npm configuration reaches only npm, GH_TOKEN only the advisory fetch", () => {
  const kept = {
    PATH: "/usr/bin:/bin",
    HOME: "/home/runner",
    TMPDIR: "/tmp/runner",
    LANG: "C.UTF-8",
    LC_ALL: "en_US.UTF-8",
    LC_CTYPE: "en_US.UTF-8",
    XDG_CONFIG_HOME: "/home/runner/.config-elsewhere",
    HTTPS_PROXY: "http://proxy.example:3128",
    http_proxy: "http://proxy.example:3128",
    NO_PROXY: "localhost",
    NODE_EXTRA_CA_CERTS: "/etc/ssl/proxy-ca.pem",
  };
  const npmConfig = {
    npm_config_registry: "https://registry.example",
    NPM_CONFIG_USERCONFIG: "/home/runner/.npmrc",
  };
  const env = {
    ...kept,
    ...npmConfig,
    GH_TOKEN: "gh-token-probe",
    GITHUB_TOKEN: "github-token-probe",
    NODE_AUTH_TOKEN: "node-auth-probe",
    NODE_OPTIONS: "--require /tmp/hook.js",
    TARBALL: "tarball/secretless-ai.tgz",
    REVIEW_UNLISTED_PROBE: "unlisted",
  };

  it("childEnv keeps PATH, HOME, temp, locale, XDG_CONFIG_HOME, proxy and CA variables, and no npm configuration", async () => {
    const { childEnv } = await loadChildEnv();
    expect(childEnv({}, env)).toEqual(kept);
    expect(childEnv({ HOME: "/scratch/home" }, env)).toEqual({
      ...kept,
      HOME: "/scratch/home",
    });
  });

  it("npmChildEnv adds npm configuration in either case, and nothing else", async () => {
    const { npmChildEnv } = await loadChildEnv();
    expect(npmChildEnv({}, env)).toEqual({ ...kept, ...npmConfig });
    expect(npmChildEnv({ HOME: "/scratch/home" }, env)).toEqual({
      ...kept,
      ...npmConfig,
      HOME: "/scratch/home",
    });
  });

  it("fetchChildEnv adds GH_TOKEN when the job has one, and no npm configuration", async () => {
    const { fetchChildEnv } = await loadChildEnv();
    expect(fetchChildEnv("https://api.example/advisories", env)).toEqual({
      ...kept,
      GH_TOKEN: "gh-token-probe",
      NODE_USE_ENV_PROXY: "1",
      REVIEW_GET_URL: "https://api.example/advisories",
    });
    const { GH_TOKEN: _token, ...withoutToken } = env;
    expect(
      fetchChildEnv("https://api.example/advisories", withoutToken),
    ).not.toHaveProperty("GH_TOKEN");
  });

  it("the advisory fetch child sends GH_TOKEN as a bearer token, and no authorization without one", async () => {
    const { fetchChild } = await loadChildEnv();
    const seen: (string | undefined)[] = [];
    const server = http.createServer((req, res) => {
      seen.push(req.headers.authorization);
      res.setHeader("content-type", "application/json");
      res.end("[]");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/advisories`;
    const fetchWith = (jobEnv: Record<string, string>) =>
      new Promise<{ status: number | null; stdout: string }>((resolve) => {
        const { command, args, env: childEnv } = fetchChild(url, jobEnv);
        const child = spawn(command, args, { env: childEnv });
        let stdout = "";
        child.stdout.on("data", (chunk) => (stdout += chunk));
        child.on("close", (status) => resolve({ status, stdout }));
      });
    try {
      const withToken = await fetchWith({
        PATH: process.env.PATH ?? "",
        GH_TOKEN: "gh-token-probe",
      });
      expect(withToken.status).toBe(0);
      expect(JSON.parse(withToken.stdout)).toEqual({ status: 200, text: "[]" });
      const withoutToken = await fetchWith({ PATH: process.env.PATH ?? "" });
      expect(withoutToken.status).toBe(0);
      expect(seen).toEqual(["Bearer gh-token-probe", undefined]);
    } finally {
      server.close();
    }
  });

  it(
    "outside a UTF-8 locale, a credential in a dist/ file with a non-ASCII name is caught by credential-scan",
    { timeout: 300_000 },
    () => {
      // With LANG, LC_ALL and LC_CTYPE unset, tar lists café.js with octal
      // escapes (caf\303\251.js); the scan reads names from the extracted
      // tree, so the file is still copied and scanned.
      const run = runReview(
        ["--tarball", buildUstarTgz("non-ascii-name-c-locale.tgz", NON_ASCII_FILES)],
        { unset: ["LANG", "LC_ALL", "LC_CTYPE"] },
      );
      expectNonAsciiCredentialCaught(run);
    },
  );

  it.skipIf(UTF8_LOCALE === undefined)(
    "under a UTF-8 locale, a credential in a dist/ file with a non-ASCII name is caught by credential-scan",
    { timeout: 300_000 },
    () => {
      const run = runReview(
        ["--tarball", buildUstarTgz("non-ascii-name.tgz", NON_ASCII_FILES)],
        { env: { LANG: UTF8_LOCALE as string, LC_ALL: "", LC_CTYPE: "" } },
      );
      expectNonAsciiCredentialCaught(run);
    },
  );

  it("every child starts through run(), and none is handed the whole environment", () => {
    // run() applies the allowlist to any call that names no environment, so a
    // second spawn site, or a call that passes process.env, would bypass it.
    // The review below records what each child was actually given.
    const source = fs.readFileSync(SCRIPT, "utf-8");
    expect(source.match(/\bspawnSync\(/g)).toHaveLength(1);
    expect(source).not.toMatch(/\.\.\.process\.env\b/);
    expect(source).not.toMatch(/\benv:\s*process\.env(?![.\w])/);
  });

  it(
    "npm, tar and the scanner see no GH_TOKEN and no unlisted variable; npm alone sees npm configuration",
    { timeout: 300_000 },
    () => {
      const realTar = spawnSync("which", ["tar"], { encoding: "utf-8" }).stdout?.trim() ?? "";
      expect(realTar, "no tar on PATH").not.toBe("");
      const stubDir = fs.mkdtempSync(path.join(tmpRoot, "child-recorder-"));
      const log = path.join(stubDir, "calls.jsonl");
      recordingProgram(stubDir, "npm", log, NPM_BODY);
      recordingProgram(stubDir, "tar", log, tarBody(realTar));
      const { script, env } = relocatedScript({
        source: recorderSource("hackmyagent", log, SCANNER_BODY),
      });
      const files = {
        ...healthyFiles(),
        "package/package.json": fixturePackageJson({
          dependencies: { "left-pad": "1.3.0" },
        }),
      };
      const review = runReview(["--tarball", buildTarball("child-env.tgz", files)], {
        script,
        env: {
          PATH: `${stubDir}${path.delimiter}${env.PATH}`,
          GH_TOKEN: "gh-token-probe",
          REVIEW_UNLISTED_PROBE: "unlisted",
          npm_config_review_probe: "kept",
          no_proxy: "review-probe.invalid",
          XDG_CONFIG_HOME: "/review-probe/config",
        },
      });

      const calls: ChildCall[] = fs.existsSync(log)
        ? fs
            .readFileSync(log, "utf-8")
            .split("\n")
            .filter((line) => line.length > 0)
            .map((line) => JSON.parse(line))
        : [];
      const has = (program: string, first: string, flag?: string) =>
        calls.some(
          (c) =>
            c.program === program &&
            c.argv[0] === first &&
            (flag === undefined || c.argv.includes(flag)),
        );
      // Reachability: the review started each kind of child.
      const seen = `calls seen: ${calls.map((c) => `${c.program} ${c.argv.join(" ")}`).join("; ")}\n${review.stdout}`;
      expect(has("npm", "ping"), seen).toBe(true);
      expect(has("npm", "install", "--package-lock-only"), seen).toBe(true);
      expect(has("npm", "audit"), seen).toBe(true);
      expect(has("npm", "install", "-g"), seen).toBe(true);
      expect(has("tar", "-tzf"), seen).toBe(true);
      expect(has("tar", "-xzf"), seen).toBe(true);
      expect(has("hackmyagent", "--version"), seen).toBe(true);
      expect(has("hackmyagent", "secure"), seen).toBe(true);

      for (const call of calls) {
        const label = `${call.program} ${call.argv.join(" ")}`;
        expect(call.names, label).not.toContain("GH_TOKEN");
        expect(call.names, label).not.toContain("REVIEW_UNLISTED_PROBE");
        expect(call.names, label).toContain("PATH");
        expect(call.home, label).toBeTruthy();
        expect(call.noProxy, label).toBe("review-probe.invalid");
        expect(call.configHome, label).toBe("/review-probe/config");
        if (call.program === "npm") {
          expect(call.npmConfig, label).toBe("kept");
        } else {
          expect(
            call.names.filter((name) => /^npm_config_/i.test(name)),
            label,
          ).toEqual([]);
        }
      }
      // The two installs keep their scratch HOME.
      const homeOf = (flag: string) =>
        calls.find((c) => c.program === "npm" && c.argv[0] === "install" && c.argv.includes(flag))?.home;
      expect(path.basename(homeOf("--package-lock-only") ?? "")).toBe("closure-home");
      expect(path.basename(homeOf("-g") ?? "")).toBe("install-home");
    },
  );
});
