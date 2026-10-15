import { describe, it, expect } from "vitest";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { pathToFileURL } from "url";
import {
  CHILD_ENV_MODULE,
  advisoryReadOf,
  closedPort,
  fetchHonoursProxy,
  tmpRoot,
} from "./release-artifact-review.test-support";

/**
 * advisoryReadOf decides how the review tests that reach consumer-closure's
 * GitHub advisories read send it. With no GH_TOKEN the read is held on this
 * machine, so repeated runs spend none of the per-address rate limit
 * unauthenticated reads share; npm keeps its route to the registry.
 *
 * Each environment below starts from PATH and an empty HOME, so no user npm
 * configuration or proxy variable of the machine running the tests decides
 * the mode.
 */

interface ChildEnvModule {
  fetchChild(
    url: string,
    env?: Record<string, string | undefined>,
  ): { command: string; args: string[]; env: Record<string, string> };
}

function loadChildEnv(): Promise<ChildEnvModule> {
  return import(pathToFileURL(CHILD_ENV_MODULE).href);
}

function bareEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    PATH: process.env.PATH ?? "",
    HOME: fs.mkdtempSync(path.join(tmpRoot, "advisory-read-home-")),
    ...extra,
  };
}

const ADVISORIES_URL =
  "https://api.github.com/repos/opena2a-org/secretless-ai/security-advisories?per_page=100";

describe("advisoryReadOf holds the advisories read on this machine when no GH_TOKEN is set", () => {
  it("with GH_TOKEN set, the read is sent with it and runReview gets no added variable", async () => {
    expect(
      await advisoryReadOf(bareEnv({ GH_TOKEN: "fixture-token-not-a-secret" })),
    ).toEqual({ mode: "authenticated", env: {} });
  });

  it(
    "with no GH_TOKEN, the script's fetch child is refused at a closed local port, and NO_PROXY names the npm registry host",
    { timeout: 120_000 },
    async (ctx) => {
      const probe = `http://127.0.0.1:${await closedPort()}`;
      if (!fetchHonoursProxy(probe)) {
        return ctx.skip(
          "not measured: this node's fetch ignores HTTPS_PROXY, so the read cannot be held",
        );
      }
      const env = bareEnv();
      const read = await advisoryReadOf(env);
      expect(read.mode, JSON.stringify(read)).toBe("held");

      const proxy = /^http:\/\/127\.0\.0\.1:(\d+)$/.exec(read.env.HTTPS_PROXY);
      expect(proxy, read.env.HTTPS_PROXY).not.toBeNull();
      expect(read.env.https_proxy).toBe(read.env.HTTPS_PROXY);

      const registry = spawnSync("npm", ["config", "get", "registry"], {
        env,
        encoding: "utf-8",
        timeout: 60_000,
      });
      expect(registry.status, registry.stderr).toBe(0);
      const host = new URL(registry.stdout.trim()).hostname;
      expect(read.env.NO_PROXY).toBe(host);
      expect(read.env.no_proxy).toBe(host);

      // The fetch child exactly as the script starts it, in the environment
      // runReview gives the script.
      const { fetchChild } = await loadChildEnv();
      const { command, args, env: childEnv } = fetchChild(ADVISORIES_URL, {
        ...env,
        ...read.env,
      });
      const child = spawnSync(command, args, {
        env: childEnv,
        encoding: "utf-8",
        timeout: 60_000,
      });
      expect(child.status).not.toBe(0);
      expect(child.stdout).toBe("");
      expect(child.stderr).toContain(
        `ECONNREFUSED 127.0.0.1:${(proxy as RegExpExecArray)[1]}`,
      );
    },
  );

  it("a proxy variable already set is kept: the read is sent without a token, and the reason names the variable", async () => {
    for (const name of ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]) {
      const read = await advisoryReadOf(
        bareEnv({ [name]: "http://127.0.0.1:9" }),
      );
      expect(read.mode, name).toBe("unauthenticated");
      expect(read.env, name).toEqual({});
      expect(read.mode === "unauthenticated" && read.reason, name).toContain(
        `${name} is set`,
      );
    }
  });

  it(
    "a proxy npm is configured with is kept the same way, and the reason names the setting, not its value",
    { timeout: 120_000 },
    async () => {
      for (const [variable, key] of [
        ["npm_config_https_proxy", "https-proxy"],
        ["npm_config_proxy", "proxy"],
      ]) {
        const read = await advisoryReadOf(
          bareEnv({ [variable]: "http://127.0.0.1:9" }),
        );
        expect(read.mode, variable).toBe("unauthenticated");
        expect(read.env, variable).toEqual({});
        const reason = read.mode === "unauthenticated" ? read.reason : "";
        expect(reason, variable).toContain(`npm config sets ${key},`);
        expect(reason, variable).not.toContain("127.0.0.1");
      }
    },
  );
});
