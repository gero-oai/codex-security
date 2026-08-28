import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { CodexReviewRunner } from "../src/deduplication/codex-review.js";
import { environmentEntry } from "../src/scan-comparison.js";

const fixture = fileURLToPath(
  new URL("fixtures/codex-review.mjs", import.meta.url),
);

const transportCases: {
  scenario: string;
  name?: string;
  environmentNames?: readonly [string, string, string];
  windowsOnly?: boolean;
  windowsSandbox?: "elevated";
}[] = [
  ...["correction", "text-only", "failed-turn", "exit", "cancel"].map(
    (scenario) => ({ scenario }),
  ),
  {
    scenario: "correction",
    name: "lowercase Windows environment",
    environmentNames: ["codex_home", "openai_api_key", "gh_config_dir"],
    windowsOnly: true,
  },
  {
    scenario: "correction",
    name: "mixed-case Windows environment",
    environmentNames: ["Codex_Home", "Codex_Api_Key", "Gh_Config_Dir"],
    windowsOnly: true,
  },
  {
    scenario: "correction",
    name: "configured Windows sandbox",
    windowsSandbox: "elevated",
  },
];

for (const {
  scenario,
  name = scenario,
  environmentNames = ["CODEX_HOME", "OPENAI_API_KEY", "GH_CONFIG_DIR"],
  windowsOnly = false,
  windowsSandbox,
} of transportCases) {
  const runCase = test.skipIf(windowsOnly && process.platform !== "win32");
  runCase(`Codex review transport: ${name}`, async () => {
    const modelHome = await mkdtemp(join(tmpdir(), "codex-review-test-"));
    const checkout = await mkdtemp(join(tmpdir(), "codex-review-source-"));
    const ghConfig = await mkdtemp(join(tmpdir(), "codex-review-gh-"));
    const transcript = join(modelHome, "messages.jsonl");
    let child: ChildProcessWithoutNullStreams | undefined;
    let directory: string | undefined;
    let args: readonly string[] = [];
    const controller = new AbortController();
    try {
      const configuration =
        (windowsSandbox === undefined
          ? ""
          : `[windows]\nsandbox = "${windowsSandbox}"\n\n`) +
        '[mcp_servers.synthetic]\ncommand = "synthetic-unused-command"\n';
      await writeFile(join(modelHome, "config.toml"), configuration);
      const [homeName, keyName, ghName] = environmentNames;
      const runner = new CodexReviewRunner(
        {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          TEMP: process.env["TEMP"],
          TMP: process.env["TMP"],
          [homeName]: modelHome,
          [keyName]: "synthetic-review-key",
          [ghName]: ghConfig,
        },
        (_command, commandArgs, options) => {
          args = commandArgs;
          directory = options.env!["CODEX_SQLITE_HOME"];
          expect(options.cwd).toBe(checkout);
          child = spawn(
            process.execPath,
            [fixture, scenario, transcript],
            options,
          );
          if (scenario === "cancel")
            child.once("spawn", () =>
              controller.abort("synthetic cancellation"),
            );
          return child;
        },
        controller.signal,
        checkout,
      );
      let validations = 0;
      const result = runner.run({
        model: "gpt-5.6-sol",
        effort: "ultra",
        prompt: "Review the supplied synthetic reports.",
        schema: {
          type: "object",
          properties: { decision: { enum: ["SAME", "DISTINCT"] } },
          required: ["decision"],
          additionalProperties: false,
        },
        validate(value: unknown) {
          validations++;
          if (
            typeof value !== "object" ||
            value === null ||
            !("decision" in value) ||
            value.decision !== "SAME"
          )
            throw new Error("Invalid decision");
          return { decision: value.decision };
        },
      });
      if (scenario === "correction") {
        expect(await result).toEqual({ decision: "SAME" });
        expect(validations).toBe(2);
      } else if (scenario === "cancel") {
        await expect(result).rejects.toBe("synthetic cancellation");
      } else {
        await expect(result).rejects.toMatchObject({
          message:
            "Codex did not complete a validated deduplication review. Findings are unchanged; retry the command.",
        });
        expect(validations).toBe(scenario === "failed-turn" ? 1 : 0);
      }
      expect(args).toContain('cli_auth_credentials_store="ephemeral"');
      expect(args.join(" ")).not.toContain("synthetic-review-key");
      const permissions = args.find((argument) =>
        argument.startsWith("permissions.codex_security_review="),
      );
      expect(permissions).toContain(
        `${JSON.stringify(resolve(modelHome))}="deny"`,
      );
      expect(permissions).toContain(
        `${JSON.stringify(resolve(ghConfig))}="deny"`,
      );
      if (windowsSandbox !== undefined) {
        expect(
          args.some((argument) => /^windows\.sandbox\s*=/u.test(argument)),
        ).toBe(false);
        expect(await readFile(join(modelHome, "config.toml"), "utf8")).toBe(
          configuration,
        );
      }
      if (scenario !== "cancel")
        expect(await readFile(transcript, "utf8")).toContain(
          '"method":"account/login/start"',
        );
      expect(existsSync(join(modelHome, "auth.json"))).toBe(false);
      expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true);
      expect(existsSync(directory!)).toBe(false);
      expect(existsSync(checkout)).toBe(true);
    } finally {
      await rm(modelHome, { recursive: true, force: true });
      await rm(checkout, { recursive: true, force: true });
      await rm(ghConfig, { recursive: true, force: true });
    }
  });
}

test("environment lookups preserve platform case rules and exact-key precedence", () => {
  const aliases = { codex_home: "synthetic-alias" };
  expect(environmentEntry(aliases, "CODEX_HOME")).toBe(
    process.platform === "win32" ? "synthetic-alias" : undefined,
  );
  expect(
    environmentEntry(
      { ...aliases, CODEX_HOME: "synthetic-exact" },
      "CODEX_HOME",
    ),
  ).toBe("synthetic-exact");
  expect(environmentEntry({ ...aliases, CODEX_HOME: "" }, "CODEX_HOME")).toBe(
    "",
  );
});
