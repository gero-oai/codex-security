import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

const packageRoot = join(import.meta.dir, "..");
const cli = join(packageRoot, "src", "cli.ts");

for (const [name, args] of [
  ["CLI", [cli, "serve"]],
  ["standalone entrypoint", [join(packageRoot, "src", "server", "index.ts")]],
] as const) {
  test(`${name} serves findings with isolated state and shuts down`, async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-serve-"));
    const state = join(root, "state with spaces");
    const child = spawn(process.execPath, [...args], {
      env: {
        ...process.env,
        CODEX_SECURITY_STATE_DIR: state,
        HOST: "127.0.0.1",
        PORT: "0",
        OPENAI_API_KEY: "",
        CODEX_API_KEY: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 20_000,
    });
    const exited = once(child, "exit");
    let stderr = "";
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    try {
      let base: string | undefined;
      for await (const line of createInterface({ input: child.stdout })) {
        const match = /^Findings service listening on (127\.0\.0\.1:\d+)$/.exec(
          line,
        );
        if (match) {
          base = `http://${match[1]}`;
          break;
        }
      }
      expect(base, stderr).toBeDefined();
      const response = await fetch(`${base}/v1/findings`);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ findings: [], total: 0 });
      expect((await stat(join(state, "workbench.sqlite3"))).isFile()).toBe(
        true,
      );
      child.kill("SIGTERM");
      const [code] = await exited;
      // Windows terminates child processes instead of delivering SIGTERM.
      if (process.platform !== "win32") expect(code).toBe(0);
      expect(stderr).toBe("");
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
      await exited;
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);
}

test("serve reports startup failures with a nonzero exit", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-security-serve-failure-"));
  try {
    const state = join(root, "not-a-directory");
    await writeFile(state, "synthetic file");
    const child = spawnSync(process.execPath, [cli, "serve"], {
      env: { ...process.env, CODEX_SECURITY_STATE_DIR: state },
      encoding: "utf8",
      timeout: 20_000,
    });
    expect(child.error).toBeUndefined();
    expect(child.status).toBe(1);
    expect(child.stdout).toBe("");
    expect(child.stderr).toContain("Could not access the findings database");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("serve exposes help and schema without starting the service", async () => {
  for (const args of [
    ["--help"],
    ["serve", "--help"],
    ["serve", "--schema", "--json"],
  ]) {
    const stdout = capture();
    const stderr = capture();
    expect(await main(args, stdout.stream, stderr.stream, dependencies())).toBe(
      0,
    );
    if (args.includes("--schema")) {
      expect(JSON.parse(stdout.text())).toEqual({});
    } else {
      expect(stdout.text()).toContain("serve");
    }
    expect(stderr.text()).toBe("");
  }
});

test("serve rejects positional arguments and JSON output", async () => {
  for (const args of [
    ["serve", "repository"],
    ["serve", "--json"],
  ]) {
    const stdout = capture();
    const stderr = capture();
    expect(await main(args, stdout.stream, stderr.stream, dependencies())).toBe(
      2,
    );
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("serve");
  }
});
