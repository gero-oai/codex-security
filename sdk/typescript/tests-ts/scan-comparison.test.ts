import {
  appendFile,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import {
  Codex,
  type CodexOptions,
  type ThreadOptions,
  type TurnOptions,
} from "@openai/codex-sdk";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { resolveCodexCommand, runCodexCommand } from "../src/runtime.js";
import {
  comparisonEnvironment,
  matchCompletedScan,
  matchScanFindings,
  matchScanFindingsInternal,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function finding(occurrenceId: string): ScanComparisonInput["before"][number] {
  return { occurrenceId };
}

function fakeCodex(response: unknown) {
  const calls: {
    prompt?: string;
    threadOptions?: ThreadOptions;
    turnOptions?: TurnOptions;
  } = {};
  const codex: NonNullable<ScanComparisonOptions["codex"]> = {
    startThread(options) {
      calls.threadOptions = options;
      return {
        async run(prompt, turnOptions) {
          calls.prompt = prompt;
          calls.turnOptions = turnOptions;
          return {
            finalResponse:
              typeof response === "string"
                ? response
                : JSON.stringify(response),
          };
        },
      };
    },
  };
  return { codex, calls };
}

describe("semantic scan comparison", () => {
  test("uses comparison attribution for CLI comparison turns", async () => {
    const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
    await matchScanFindingsInternal(
      { before: [], after: [] },
      { codex },
      { surface: "cli" },
    );
    expect(calls.threadOptions?.threadSource).toBe("security_scan_comparison");
  });

  test("disables explicit and inherited MCP servers for read-only helper turns", async () => {
    const home = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(home);
    await writeFile(
      join(home, "config.toml"),
      '[mcp_servers.inherited]\ncommand = "synthetic-inherited"\n',
    );
    const executable = join(
      home,
      process.platform === "win32" ? "custom-codex.exe" : "custom-codex",
    );
    await copyFile(resolveCodexCommand({}).command, executable);
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: home,
      CODEX_CLI_PATH: executable,
      OPENAI_API_KEY: "synthetic-key",
    };
    const { codex } = fakeCodex({ matches: [], uncertain: [] });
    let config: CodexOptions["config"];
    let codexPath: string | undefined;
    const startThread = spyOn(
      Codex.prototype,
      "startThread",
    ).mockImplementation(function (this: Codex, options) {
      config = (this as unknown as { options: CodexOptions }).options.config;
      codexPath = (this as unknown as { options: CodexOptions }).options
        .codexPathOverride;
      return codex.startThread(options!) as ReturnType<Codex["startThread"]>;
    });
    try {
      await matchScanFindings(
        { before: [], after: [] },
        {
          environment,
          workingDirectory: relative(process.cwd(), home),
          config: {
            codexOverrides: {
              mcp_servers: {
                synthetic: { command: "synthetic-integration", enabled: true },
              },
            },
          },
        },
      );
      expect(config?.["mcp_servers"]).toEqual({
        synthetic: { command: "synthetic-integration", enabled: false },
        inherited: { enabled: false },
      });
      expect(codexPath).toBe(executable);
      const effective = await runCodexCommand(
        resolveCodexCommand(environment),
        [
          "-C",
          home,
          "-c",
          'mcp_servers.synthetic.command="synthetic-integration"',
          ...Object.keys(config!["mcp_servers"]!).flatMap((name) => [
            "-c",
            `mcp_servers.${name}.enabled=false`,
          ]),
          "mcp",
          "list",
          "--json",
        ],
        environment,
      );
      expect(effective.success).toBe(true);
      expect(
        JSON.parse(effective.stdout).map(
          (server: { name: string; enabled: boolean }) => ({
            name: server.name,
            enabled: server.enabled,
          }),
        ),
      ).toEqual([
        { name: "inherited", enabled: false },
        { name: "synthetic", enabled: false },
      ]);
    } finally {
      startThread.mockRestore();
    }
  });

  test("preserves environment API-key precedence over managed credentials", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    let statusProbed = false;
    const account = async () => {
      statusProbed = true;
      return { authenticated: true, details: "Logged in using ChatGPT" };
    };

    const environment = await comparisonEnvironment(
      {
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        OPENAI_API_KEY: "synthetic-key-must-not-be-used",
        CODEX_API_KEY: "synthetic-secondary-must-not-be-used",
      },
      account,
    );

    expect(environment["CODEX_SECURITY_STATE_DIR"]).toBe(stateDirectory);
    expect(environment["OPENAI_API_KEY"]).toBe(
      "synthetic-key-must-not-be-used",
    );
    expect(environment["CODEX_API_KEY"]).toBe(
      "synthetic-secondary-must-not-be-used",
    );
    expect(environment["CODEX_HOME"]).toBeUndefined();
    const provider = {
      CODEX_SECURITY_STATE_DIR: stateDirectory,
      CODEX_SECURITY_SCAN_ID: "scan",
      CODEX_HOME: "/provider-home",
      CODEX_CLI_PATH: "/compatible-codex",
      CODEX_SAFETY_IDENTIFIER: "synthetic-user",
      FIREWORKS_API_KEY: "provider-key",
    };
    expect(await comparisonEnvironment(provider, account)).toEqual(provider);
    expect(statusProbed).toBe(false);
  });

  test.skipIf(process.platform !== "win32")(
    "recognizes provider scan variables regardless of Windows casing",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const stateDirectory = join(root, "state");
      const providerHome = join(root, "provider-home");
      await mkdir(join(stateDirectory, "codex-home"), {
        recursive: true,
        mode: 0o700,
      });
      let statusProbed = false;
      const provider = {
        codex_security_scan_id: "scan",
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        codex_home: providerHome,
        FIREWORKS_API_KEY: "synthetic-provider-key",
      };

      const environment = await comparisonEnvironment(provider, async () => {
        statusProbed = true;
        return { authenticated: true, details: "Logged in using ChatGPT" };
      });

      expect(environment).toEqual(provider);
      expect(statusProbed).toBe(false);
    },
  );

  test.skipIf(process.platform !== "win32")(
    "replaces differently cased Windows CODEX_HOME variables",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const stateDirectory = join(root, "state");
      const credentialHome = join(stateDirectory, "codex-home");
      await mkdir(credentialHome, { recursive: true, mode: 0o700 });

      const environment = await comparisonEnvironment(
        {
          CODEX_SECURITY_STATE_DIR: stateDirectory,
          codex_home: join(root, "ambient-home"),
        },
        async () => ({
          authenticated: true,
          details: "Logged in using ChatGPT",
        }),
        undefined,
        async () => await realpath(credentialHome),
      );

      expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
      expect(environment["codex_home"]).toBeUndefined();
    },
  );

  test("reuses managed keyring credentials when no environment key is present", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    let probedHome: string | undefined;

    const environment = await comparisonEnvironment(
      { CODEX_SECURITY_STATE_DIR: stateDirectory },
      async (_command, storedEnvironment) => {
        probedHome = storedEnvironment["CODEX_HOME"];
        return { authenticated: true, details: "Logged in using ChatGPT" };
      },
    );

    expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
    expect(probedHome).toBe(await realpath(credentialHome));
  });

  test.skipIf(process.platform === "win32")(
    "uses the canonical keyring identity when the state parent is symlinked",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const actualState = join(root, "actual-state");
      const linkedState = join(root, "linked-state");
      const credentialHome = join(actualState, "codex-home");
      await mkdir(credentialHome, { recursive: true, mode: 0o700 });
      await symlink(actualState, linkedState, "dir");
      let probedHome: string | undefined;

      const environment = await comparisonEnvironment(
        { CODEX_SECURITY_STATE_DIR: linkedState },
        async (_command, storedEnvironment) => {
          probedHome = storedEnvironment["CODEX_HOME"];
          return { authenticated: true, details: "Logged in using ChatGPT" };
        },
      );

      expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
      expect(probedHome).toBe(await realpath(credentialHome));
    },
  );

  test("forwards cancellation to managed credential-status checks", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    await mkdir(join(stateDirectory, "codex-home"), {
      recursive: true,
      mode: 0o700,
    });
    const controller = new AbortController();
    let observedSignal: AbortSignal | undefined;
    let statusStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      statusStarted = resolve;
    });

    const waiting = comparisonEnvironment(
      { CODEX_SECURITY_STATE_DIR: stateDirectory },
      async (_command, _environment, signal) => {
        observedSignal = signal;
        statusStarted();
        return await new Promise((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          });
        });
      },
      controller.signal,
    );
    await started;
    controller.abort(new DOMException("canceled", "AbortError"));

    await expect(waiting).rejects.toMatchObject({ name: "AbortError" });
    expect(observedSignal).toBe(controller.signal);
  });

  test("retains API-key authentication when the managed home is not signed in", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    const ambientHome = join(root, "ambient-codex-home");
    await mkdir(ambientHome, { mode: 0o700 });
    await mkdir(join(stateDirectory, "codex-home"), {
      recursive: true,
      mode: 0o700,
    });

    const environment = await comparisonEnvironment(
      {
        CODEX_HOME: ambientHome,
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        OPENAI_API_KEY: "synthetic-comparison-key",
      },
      async () => ({ authenticated: false, details: "Not logged in" }),
    );

    expect(environment["OPENAI_API_KEY"]).toBe("synthetic-comparison-key");
    expect(environment["CODEX_HOME"]).toBe(ambientHome);
  });

  test.skipIf(process.platform !== "win32")(
    "recognizes stored credentials under a backslash home-relative path",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const ambientHome = join(root, "ambient-codex-home");
      await mkdir(ambientHome);
      await writeFile(join(ambientHome, "auth.json"), "{}");
      const environment = await comparisonEnvironment({
        CODEX_HOME: "~\\ambient-codex-home",
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        OPENAI_API_KEY: "",
        USERPROFILE: root,
      });

      expect(environment["OPENAI_API_KEY"]).toBeUndefined();
    },
  );

  test("compares all findings with one restricted structured-output turn", async () => {
    const input: ScanComparisonInput = {
      before: [finding("before-1"), finding("before-2")],
      after: [finding("after-1"), finding("after-2"), finding("after-3")],
    };
    const result = {
      matches: [
        {
          beforeOccurrenceIds: ["before-1"],
          afterOccurrenceIds: ["after-1", "after-2"],
          confidence: "high",
          reason: "The later scan split the same vulnerable extractor.",
        },
      ],
      uncertain: [
        {
          beforeOccurrenceId: "before-2",
          afterOccurrenceId: "after-3",
          reason: "A second entry point might be independently exploitable.",
        },
      ],
    } satisfies ScanComparisonResult;
    const { codex, calls } = fakeCodex(result);
    const controller = new AbortController();

    expect(
      await matchScanFindings(input, {
        codex,
        model: "comparison-model",
        reasoningEffort: "high",
        signal: controller.signal,
        workingDirectory: "/tmp/comparison",
      }),
    ).toEqual(result);
    expect(calls.threadOptions).toEqual({
      threadSource: "security_scan_comparison",
      model: "comparison-model",
      modelReasoningEffort: "high",
      sandboxMode: "read-only",
      approvalPolicy: "never",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      workingDirectory: "/tmp/comparison",
      skipGitRepoCheck: true,
    });
    expect(calls.turnOptions).toMatchObject({ signal: controller.signal });
    expect(calls.turnOptions?.outputSchema).toMatchObject({
      required: ["matches", "uncertain"],
    });
    expect(calls.prompt).toContain(
      "same underlying root cause and remediation",
    );
    expect(calls.prompt).toContain(
      "same vulnerable helper share one root cause",
    );
    expect(calls.prompt).toContain("every earlier occurrence in one group");
    expect(calls.prompt).toContain("untrusted data");
    expect(calls.prompt).toContain(JSON.stringify(input));
  });

  test("disables inherited MCP servers in the real comparison session", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-comparison-")),
    );
    temporaryDirectories.push(root);
    const codexHome = join(root, "codex-home");
    const markerDirectory = join(root, "mcp-started");
    const projectConfig = join(root, ".codex");
    const mcpServer = join(root, "synthetic-mcp.mjs");
    await Promise.all(
      [codexHome, markerDirectory, projectConfig].map((path) => mkdir(path)),
    );
    const node = Bun.which("node");
    expect(node).not.toBeNull();
    const homeServers = ["synthetic", "contains space", "café", "__proto__"];
    const projectServer = "project_local";
    const servers = [...homeServers, projectServer];
    const startedServers = ["synthetic", "__proto__", projectServer];
    const serverConfiguration = (name: string) =>
      [
        `[mcp_servers.${JSON.stringify(name)}]`,
        `command = ${JSON.stringify(node)}`,
        `args = [${JSON.stringify(mcpServer)}, ${JSON.stringify(join(markerDirectory, name))}]`,
        "startup_timeout_sec = 5",
      ].join("\n");
    await writeFile(
      mcpServer,
      [
        'import { writeFileSync } from "node:fs";',
        'import { createInterface } from "node:readline";',
        'writeFileSync(process.argv[2], "started");',
        "for await (const line of createInterface({ input: process.stdin })) {",
        "  const request = JSON.parse(line);",
        "  if (request.id === undefined) continue;",
        '  const result = request.method === "initialize"',
        '    ? { protocolVersion: "2025-11-25", capabilities: { tools: {} },',
        '        serverInfo: { name: "synthetic", version: "1.0.0" } }',
        '    : request.method === "tools/list" ? { tools: [] } : {};',
        '  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }) + "\\n");',
        "}",
      ].join("\n"),
    );
    const requests: Record<string, unknown>[] = [];
    const mcpRequests: Array<{
      path: string;
      providerKey: string | null;
    }> = [];
    const response = { matches: [], uncertain: [] };
    const service = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(request) {
        const path = new URL(request.url).pathname;
        if (path !== "/v1/responses") {
          mcpRequests.push({
            path,
            providerKey: request.headers.get("X-Provider-Key"),
          });
          return new Response(null, { status: 404 });
        }
        if (request.method !== "POST") {
          return new Response(null, { status: 404 });
        }
        requests.push((await request.json()) as Record<string, unknown>);
        const events = [
          { type: "response.created", response: { id: "synthetic-response" } },
          {
            type: "response.output_item.done",
            item: {
              type: "message",
              role: "assistant",
              id: "synthetic-message",
              content: [
                { type: "output_text", text: JSON.stringify(response) },
              ],
            },
          },
          {
            type: "response.completed",
            response: {
              id: "synthetic-response",
              usage: {
                input_tokens: 0,
                input_tokens_details: null,
                output_tokens: 0,
                output_tokens_details: null,
                total_tokens: 0,
              },
            },
          },
        ];
        return new Response(
          events
            .map(
              (event) =>
                `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`,
            )
            .join(""),
          { headers: { "content-type": "text/event-stream" } },
        );
      },
    });
    await writeFile(
      join(codexHome, "config.toml"),
      [
        `openai_base_url = ${JSON.stringify(`${service.url}v1`)}`,
        `[projects.${JSON.stringify(root)}]`,
        'trust_level = "trusted"',
        ...homeServers.map(serverConfiguration),
      ].join("\n"),
    );
    await writeFile(
      join(projectConfig, "config.toml"),
      serverConfiguration(projectServer),
    );
    const environment: NodeJS.ProcessEnv = {
      ...Object.fromEntries(
        Object.entries(process.env).filter(([name]) =>
          [
            "COMSPEC",
            "HOME",
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "USERPROFILE",
          ].includes(name.toUpperCase()),
        ),
      ),
      CODEX_HOME: codexHome,
      OPENAI_API_KEY: "synthetic-comparison-key",
    };
    try {
      const unrestricted = Bun.spawnSync(
        [
          resolveCodexCommand(environment).command,
          "--cd",
          root,
          "--config",
          "features.apps=false",
          "--config",
          "features.plugins=false",
          "--config",
          "features.shell_tool=false",
          "--config",
          "features.unified_exec=false",
          "debug",
          "prompt-input",
          "synthetic comparison",
        ],
        { env: environment, stdout: "ignore", stderr: "pipe" },
      );
      expect(
        unrestricted.exitCode,
        new TextDecoder().decode(unrestricted.stderr),
      ).toBe(0);
      for (const server of startedServers) {
        expect(
          await readFile(join(markerDirectory, server), "utf8"),
          `${server}: ${new TextDecoder().decode(unrestricted.stderr)}`,
        ).toBe("started");
      }
      await Promise.all(
        startedServers.map((server) => rm(join(markerDirectory, server))),
      );
      await appendFile(
        join(projectConfig, "config.toml"),
        [
          "",
          "[mcp_servers.synthetic_http]",
          `url = ${JSON.stringify(`${service.url}mcp`)}`,
          'env_http_headers = { "X-Provider-Key" = "OPENAI_API_KEY" }',
        ].join("\n"),
      );

      expect(
        await matchScanFindings(
          { before: [], after: [] },
          { environment, model: "gpt-5.6-sol", workingDirectory: root },
        ),
      ).toEqual(response);
      expect(requests).toHaveLength(1);
      expect(mcpRequests).toEqual([]);
      expect(JSON.stringify(requests[0]?.["tools"] ?? [])).not.toContain(
        "synthetic",
      );
      for (const server of servers) {
        await expect(
          readFile(join(markerDirectory, server)),
        ).rejects.toMatchObject({ code: "ENOENT" });
      }
    } finally {
      service.stop(true);
    }
  });

  test("fails closed when configured MCP servers cannot be inspected", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-comparison-")),
    );
    temporaryDirectories.push(root);
    const executable = join(root, "app-server");
    const scenario = join(root, "scenario.json");
    await writeFile(
      executable,
      [
        'const { readFileSync } = require("node:fs");',
        'const { dirname } = require("node:path");',
        'const { createInterface } = require("node:readline");',
        'if (process.argv.slice(2).join(" ") !== "-c features.plugins=false") process.exit(2);',
        "if (process.cwd() !== dirname(process.argv[1])) process.exit(3);",
        'if (["OPENAI_API_KEY", "CODEX_API_KEY", "AUTHORIZATION", "SYNTHETIC_SECRET", "HTTP_PROXY"].some((name) => process.env[name] !== undefined)) process.exit(4);',
        'const scenario = JSON.parse(readFileSync("scenario.json", "utf8"));',
        "if (scenario.exitCode !== undefined) process.exit(scenario.exitCode);",
        'createInterface({ input: process.stdin }).on("line", (line) => {',
        "  const request = JSON.parse(line);",
        '  if (request.method === "initialize") {',
        '    const response = scenario.initializationError ? { error: { code: -32601, message: "unsupported" } } : { result: {} };',
        '    process.stdout.write(JSON.stringify({ id: request.id, ...response }) + "\\n");',
        '  } else if (request.method === "config/read") {',
        "    const output = scenario.raw ?? JSON.stringify({ id: request.id, ...scenario.response });",
        '    process.stdout.write(output + "\\n", () => process.exit(0));',
        "  }",
        "});",
      ].join("\n"),
    );
    const node = Bun.which("node");
    expect(node).not.toBeNull();

    for (const response of [
      { exitCode: 1 },
      { raw: "not-json" },
      { raw: "{}" },
      { initializationError: true },
      { response: { error: { code: -32601, message: "unsupported" } } },
      { response: { result: null } },
      { response: { result: {} } },
      { response: { result: { config: null } } },
      { response: { result: { config: [] } } },
      { response: { result: { config: { mcp_servers: null } } } },
      { response: { result: { config: { mcp_servers: [] } } } },
      {
        response: {
          result: { config: { mcp_servers: { "unsafe.name": {} } } },
        },
      },
      {
        response: {
          result: { config: { mcp_servers: { "unsafe=name": {} } } },
        },
      },
    ]) {
      await writeFile(scenario, JSON.stringify(response));
      await expect(
        matchScanFindings(
          { before: [], after: [] },
          {
            environment: {
              ...process.env,
              CODEX_CLI_PATH: node!,
              OPENAI_API_KEY: "synthetic-comparison-key",
              CODEX_API_KEY: "synthetic-secondary-key",
              AUTHORIZATION: "synthetic-authorization",
              SYNTHETIC_SECRET: "synthetic-secret",
              HTTP_PROXY: "http://synthetic.invalid",
            },
            workingDirectory: root,
          },
        ),
      ).rejects.toThrow(/Could not (read MCP configuration|safely disable)/u);
    }
  });

  test("uses the requested scan model and effort for component matching", async () => {
    const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
    const config = {
      codexOverrides: {
        model: "configured-model",
        model_reasoning_effort: "high",
        model_provider: "synthetic-provider",
      },
    };
    await matchScanFindings({ before: [], after: [] }, { config, codex });
    expect(calls.threadOptions).toMatchObject({
      model: "configured-model",
      modelReasoningEffort: "high",
      sandboxMode: "read-only",
      networkAccessEnabled: false,
    });
    await matchScanFindings(
      { before: [], after: [] },
      { config, codex, model: "explicit-model", reasoningEffort: "low" },
    );
    expect(calls.threadOptions).toMatchObject({
      model: "explicit-model",
      modelReasoningEffort: "low",
    });
  });

  test("matches open and dismissed findings from the same target", async () => {
    const open = { findingId: "open", occurrenceId: "old-open" };
    const dismissed = { findingId: "dismissed", occurrenceId: "old-dismissed" };
    const after = { findingId: "renamed", occurrenceId: "new-renamed" };
    const commands: Array<{ args: readonly string[]; input?: string }> = [];
    let input: ScanComparisonInput | undefined;
    await matchCompletedScan({
      scanId: "current",
      repository: "/repository",
      previousFindings: [open],
      falsePositives: [{ findingId: "dismissed", sourceScanId: "prior" }],
      findings: [after],
      environment: {
        CODEX_HOME: "/provider-home",
        CODEX_SECURITY_SCAN_ID: "current",
        FIREWORKS_API_KEY: "synthetic-provider-key",
      },
      async workbench(args, commandInput) {
        commands.push({ args, input: commandInput });
        return args[0] === "list-unmatched-scan-pairs"
          ? {
              batches: [
                {
                  afterScanId: "current",
                  afterFindings: [after],
                  beforeScans: [
                    {
                      scanId: "another-target",
                      findings: [{ ...dismissed, occurrenceId: "foreign" }],
                    },
                    { scanId: "prior", findings: [open, dismissed] },
                  ],
                },
              ],
            }
          : {};
      },
      async matchFindings(value, options) {
        input = value;
        expect(options).toMatchObject({
          environment: {
            CODEX_HOME: "/provider-home",
            CODEX_SECURITY_SCAN_ID: "current",
          },
        });
        return {
          matches: [
            {
              beforeOccurrenceIds: ["old-dismissed"],
              afterOccurrenceIds: ["new-renamed"],
              confidence: "high",
              reason: "Same dismissed root cause.",
            },
          ],
          uncertain: [
            {
              beforeOccurrenceId: "old-open",
              afterOccurrenceId: "new-renamed",
              reason: "Possible match.",
            },
          ],
        };
      },
    });
    expect(input).toEqual({ before: [open, dismissed], after: [after] });
    expect(commands.map(({ args: [command] }) => command)).toEqual([
      "list-unmatched-scan-pairs",
      "save-scan-comparison",
    ]);
    expect(commands[1]!.args.at(-1)).toBe("--matches-json-stdin");
    const saved = JSON.parse(commands[1]!.input!) as ScanComparisonResult;
    expect(
      saved.matches.map(({ beforeOccurrenceIds }) => beforeOccurrenceIds),
    ).toEqual([["old-dismissed"]]);
    expect(saved.uncertain).toEqual([]);
  });

  test.each([
    ["no history", false, false, false, 0, false],
    ["a stable identity", true, false, true, 2, false],
    ["a renamed dismissed identity", false, true, false, 2, true],
  ] as const)(
    "only starts a model turn when needed for %s",
    async (
      _scenario,
      open,
      dismissed,
      stable,
      expectedCalls,
      expectedModel,
    ) => {
      const before = { findingId: "previous", occurrenceId: "old" };
      const after = {
        findingId: stable ? "previous" : "new",
        occurrenceId: "new",
      };
      let calls = 0;
      let modelCalled = false;
      await matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: open ? [before] : [],
        falsePositives: dismissed
          ? [{ findingId: "previous", sourceScanId: "prior" }]
          : [],
        findings: [after],
        async workbench(args) {
          calls += 1;
          return args[0] === "list-unmatched-scan-pairs"
            ? {
                batches: [
                  {
                    afterScanId: "current",
                    afterFindings: [after],
                    beforeScans: [{ scanId: "prior", findings: [before] }],
                  },
                ],
              }
            : {};
        },
        async matchFindings() {
          modelCalled = true;
          return { matches: [], uncertain: [] };
        },
      });
      expect(calls).toBe(expectedCalls);
      expect(modelCalled).toBe(expectedModel);
    },
  );

  test("rejects malformed model JSON", async () => {
    const { codex } = fakeCodex("not-json");
    await expect(
      matchScanFindings({ before: [], after: [] }, { codex }),
    ).rejects.toThrow("invalid JSON");
  });

  test("allows cross-history uncertainty without relaxing two-scan matching", async () => {
    const input: ScanComparisonInput = {
      before: [finding("before-confirmed"), finding("before-uncertain")],
      after: [finding("after-shared")],
    };
    const response = {
      matches: [
        {
          beforeOccurrenceIds: ["before-confirmed"],
          afterOccurrenceIds: ["after-shared"],
          confidence: "high",
          reason: "Confirmed in one historical scan.",
        },
      ],
      uncertain: [
        {
          beforeOccurrenceId: "before-uncertain",
          afterOccurrenceId: "after-shared",
          reason: "Uncertain in another historical scan.",
        },
      ],
    } satisfies ScanComparisonResult;

    await expect(
      matchScanFindings(input, { codex: fakeCodex(response).codex }),
    ).rejects.toThrow("invalid uncertain pair");
    expect(
      await matchScanFindings(input, {
        codex: fakeCodex(response).codex,
        allowHistoricalUncertainty: true,
      }),
    ).toEqual(response);
  });

  const match = (beforeOccurrenceIds = ["before-1"]) => ({
    beforeOccurrenceIds,
    afterOccurrenceIds: ["after-1"],
    confidence: "high" as const,
    reason: "Same root cause.",
  });
  const uncertain = (afterOccurrenceId = "after-1") => ({
    beforeOccurrenceId: "before-1",
    afterOccurrenceId,
    reason: "Possible root cause.",
  });

  test.each([
    {
      label: "missing arrays",
      result: {},
      error: "invalid match result",
    },
    {
      label: "low confidence",
      result: { matches: [{ ...match(), confidence: "low" }], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "empty groups",
      result: { matches: [match([])], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "invented occurrences",
      result: { matches: [match(["invented"])], uncertain: [] },
      error: "unknown before occurrence",
    },
    {
      label: "repeated occurrences",
      result: { matches: [match(), match()], uncertain: [] },
      error: "before occurrence more than once",
    },
    {
      label: "invented uncertain occurrences",
      result: { matches: [], uncertain: [uncertain("invented")] },
      error: "invalid uncertain pair",
    },
    {
      label: "uncertainty already matched with confidence",
      result: { matches: [match()], uncertain: [uncertain()] },
      error: "invalid uncertain pair",
    },
    {
      label: "duplicate uncertain pairs",
      result: { matches: [], uncertain: [uncertain(), uncertain()] },
      error: "duplicate uncertain pair",
    },
  ])("rejects $label", async ({ result, error }) => {
    const { codex } = fakeCodex(result);
    await expect(
      matchScanFindings(
        { before: [finding("before-1")], after: [finding("after-1")] },
        { codex },
      ),
    ).rejects.toThrow(error);
  });
});
