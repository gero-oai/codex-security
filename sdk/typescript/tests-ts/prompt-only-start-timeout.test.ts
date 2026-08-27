import { expect, test } from "bun:test";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

test("gives long workbench operations the five-minute timeout", async () => {
  const runtime = await loadBundledRuntime();
  const source =
    /async function executeWorkbench\([^\n]*\) \{[\s\S]*?\n\}/u.exec(
      runtime,
    )?.[0];
  expect(source).toBeDefined();
  const execFileHelper = /\b(execFileAsync\d*)\(/u.exec(source ?? "")?.[1];
  expect(execFileHelper).toBeDefined();

  const executeWorkbench = new Function(
    execFileHelper!,
    "workbenchScriptPath",
    "PLUGIN_ROOT",
    "isJsonObject2",
    `${source}\nreturn executeWorkbench;`,
  )(
    async (
      _command: string,
      _args: string[],
      options: { timeout: number },
    ) => ({ stdout: JSON.stringify({ timeout: options.timeout }) }),
    () => "workbench.py",
    PLUGIN_ROOT,
    () => true,
  ) as (command: string, args: string[]) => Promise<{ timeout: number }>;

  expect(await executeWorkbench("python", ["start-prompt-only-scan"])).toEqual({
    timeout: 300_000,
  });
  expect(await executeWorkbench("python", ["start-scan"])).toEqual({
    timeout: 300_000,
  });
  expect(await executeWorkbench("python", ["create-workspace"])).toEqual({
    timeout: 300_000,
  });
  expect(await executeWorkbench("python", ["prepare-scan-completion"])).toEqual(
    { timeout: 300_000 },
  );
  expect(await executeWorkbench("python", ["other-operation"])).toEqual({
    timeout: 30_000,
  });
});

test("state-free inspection reuses but does not create a fallback", async () => {
  const runtime = await loadBundledRuntime();
  const source =
    /async function executeWorkbenchWithStateSelection\([^\n]*\) \{[\s\S]*?\n\}/u.exec(
      runtime,
    )?.[0];
  expect(source).toBeDefined();

  function selector(fallback: Promise<string> | undefined) {
    let pinCalls = 0;
    const executeWorkbenchWithStateSelection = new Function(
      "WORKBENCH_COMMANDS_WITHOUT_DATABASE",
      "CONFIGURED_WORKBENCH_STATE_DIR",
      "fallbackWorkbenchStateDir",
      "persistentWorkbenchStateSucceeded",
      "withWorkbenchStateSelectionLock",
      "executeWorkbench",
      "isUnwritableSqliteOpenError",
      "pinFallbackWorkbenchStateDir",
      "logWorkbenchStateFallback",
      `${source}\nreturn executeWorkbenchWithStateSelection;`,
    )(
      new Set(["inspect-target", "inspect-setup"]),
      undefined,
      fallback,
      false,
      async (operation: () => Promise<unknown>) => await operation(),
      async (_command: string, _args: string[], stateDir?: string) => ({
        stateDir,
      }),
      () => false,
      async () => {
        pinCalls += 1;
        return "/new-fallback";
      },
      () => undefined,
    ) as (command: string, args: string[]) => Promise<{ stateDir?: string }>;
    return { executeWorkbenchWithStateSelection, pinCalls: () => pinCalls };
  }

  const withoutFallback = selector(undefined);
  expect(
    await withoutFallback.executeWorkbenchWithStateSelection("python", [
      "inspect-setup",
    ]),
  ).toEqual({ stateDir: undefined });
  expect(withoutFallback.pinCalls()).toBe(0);

  const withFallback = selector(Promise.resolve("/pinned-fallback"));
  expect(
    await withFallback.executeWorkbenchWithStateSelection("python", [
      "inspect-setup",
    ]),
  ).toEqual({ stateDir: "/pinned-fallback" });
  expect(withFallback.pinCalls()).toBe(0);
});

test("a rejected pending fallback pin does not fail state-free inspection", async () => {
  const runtime = await loadBundledRuntime();
  const pinSource =
    /async function pinFallbackWorkbenchStateDir\(\) \{[\s\S]*?\n\}/u.exec(
      runtime,
    )?.[0];
  const selectionSource =
    /async function executeWorkbenchWithStateSelection\([^\n]*\) \{[\s\S]*?\n\}/u.exec(
      runtime,
    )?.[0];
  expect(pinSource).toBeDefined();
  expect(selectionSource).toBeDefined();
  const pathModule = /\b(import_node_path\d+)\.join\b/u.exec(
    pinSource ?? "",
  )?.[1];
  const fsModule = /\b(import_node_fs\d+)\.promises\b/u.exec(
    pinSource ?? "",
  )?.[1];
  expect(pathModule).toBeDefined();
  expect(fsModule).toBeDefined();

  let mkdirCalls = 0;
  const firstMkdir = Promise.withResolvers<void>();
  const mkdirStarted = Promise.withResolvers<void>();
  const bundled = new Function(
    pathModule!,
    fsModule!,
    "scanRoot",
    "WORKBENCH_COMMANDS_WITHOUT_DATABASE",
    "CONFIGURED_WORKBENCH_STATE_DIR",
    "fallbackWorkbenchStateDir",
    "persistentWorkbenchStateSucceeded",
    "withWorkbenchStateSelectionLock",
    "executeWorkbench",
    "isUnwritableSqliteOpenError",
    "logWorkbenchStateFallback",
    `${pinSource}\n${selectionSource}\nreturn { pinFallbackWorkbenchStateDir, executeWorkbenchWithStateSelection };`,
  )(
    { join: (left: string, right: string) => `${left}/${right}` },
    {
      promises: {
        mkdir: async () => {
          mkdirCalls += 1;
          if (mkdirCalls === 1) {
            mkdirStarted.resolve();
            await firstMkdir.promise;
          }
        },
      },
    },
    async () => "/fallback",
    new Set(["inspect-target", "inspect-setup"]),
    undefined,
    undefined,
    false,
    async (operation: () => Promise<unknown>) => await operation(),
    async (_command: string, _args: string[], stateDir?: string) => ({
      stateDir,
    }),
    () => false,
    () => undefined,
  ) as {
    executeWorkbenchWithStateSelection: (
      command: string,
      args: string[],
    ) => Promise<{ stateDir?: string }>;
    pinFallbackWorkbenchStateDir: () => Promise<string>;
  };

  const pin = bundled.pinFallbackWorkbenchStateDir();
  await mkdirStarted.promise;
  const inspection = bundled.executeWorkbenchWithStateSelection("python", [
    "inspect-setup",
  ]);
  const outcomes = Promise.allSettled([pin, inspection]);
  firstMkdir.reject(new Error("synthetic fallback failure"));
  const [pinOutcome, inspectionOutcome] = await outcomes;
  expect(pinOutcome).toMatchObject({
    status: "rejected",
    reason: expect.objectContaining({
      message: "synthetic fallback failure",
    }),
  });
  expect(inspectionOutcome).toEqual({
    status: "fulfilled",
    value: { stateDir: undefined },
  });
  expect(mkdirCalls).toBe(1);

  await expect(bundled.pinFallbackWorkbenchStateDir()).resolves.toBe(
    "/fallback/workbench-state",
  );
  expect(mkdirCalls).toBe(2);
  expect(
    await bundled.executeWorkbenchWithStateSelection("python", [
      "inspect-setup",
    ]),
  ).toEqual({ stateDir: "/fallback/workbench-state" });
});
