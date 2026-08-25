import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { CodexOptions, ThreadOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { CodexSecurity } from "../src/index.js";
import { mockWorkbench } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const fixtures = createApiTestFixtures();
const InternalCodexSecurity = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
  runtimeOptions?: { surface: "cli" | "sdk" },
) => CodexSecurity;

afterEach(fixtures.cleanup);

async function scanResponseSurface(runtimeOptions?: {
  surface: "cli" | "sdk";
}): Promise<string | undefined> {
  const root = await fixtures.temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  let surface: string | undefined;

  const client = new InternalCodexSecurity(
    {},
    {
      environment: {},
      prepareRuntime: async () => preparedRuntime(codexHome),
      resolvePluginPython: async () => "/managed/python",
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      runWorkbench: async (
        _options: unknown,
        args: readonly string[],
        input?: string,
      ) => mockWorkbench(args, input),
      createCodex: (options: CodexOptions) => {
        surface = (
          options.config?.["responses_api_metadata"] as
            | Record<string, string>
            | undefined
        )?.["codex_security_surface"];
        return {
          startThread: (threadOptions: ThreadOptions) => ({
            id: null,
            async runStreamed() {
              expect(threadOptions.threadSource).toBe(
                `codex_security_${runtimeOptions?.surface ?? "sdk"}`,
              );
              await fixtures.copyCompletedScan(root);
              return { events: completedEvents() };
            },
          }),
        };
      },
    },
    runtimeOptions,
  );

  await client.run(repository);
  await client.close();
  return surface;
}

describe("CodexSecurity request attribution", () => {
  test("SDK runtime scans use SDK attribution", async () => {
    expect(await scanResponseSurface()).toBe("sdk");
  });

  test("CLI runtime scans use CLI attribution", async () => {
    expect(await scanResponseSurface({ surface: "cli" })).toBe("cli");
  });
});
