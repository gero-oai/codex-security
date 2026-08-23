import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  appendFile,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  publishScanInternal,
  type PublicationCodexResult,
  type PublishScanDependencies,
  type PublishScanOptions,
  type PublishScanProgress,
  type PublishScanResult,
} from "../src/publish.js";
import type {
  PreparedPublicationIssue,
  PreparedScanPublication,
} from "../src/publication.js";

const OPTIONS: PublishScanOptions = {
  destination: "linear",
  teamId: "team-example",
  projectId: "project-example",
};
const CLAIM_COLLISION_ERROR =
  "Codex wrote a Linear publication that reused or relabeled a claim across incompatible publication evidence.";
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function preparedPublication(
  count = 1,
  scanId = "scan-example",
): PreparedScanPublication {
  return {
    scanId,
    uploadId: scanId,
    scanDirectory: join(tmpdir(), "completed-scan"),
    destination: {
      type: "linear",
      teamId: OPTIONS.teamId,
      projectId: OPTIONS.projectId,
    },
    issues: Array.from({ length: count }, (_, index) => ({
      findingId: `finding-${index + 1}`,
      occurrenceId: `occurrence-${index + 1}`,
      title: `[Codex Security][HIGH] Synthetic finding ${index + 1}`,
      description: [
        `**Finding ID:** finding-${index + 1}`,
        `**Occurrence ID:** occurrence-${index + 1}`,
        "",
        `Finding ${index + 1}`,
        "",
        "```ts",
        "unsafe(input)",
        "```",
      ].join("\n"),
      priority: 2,
    })),
  };
}

function issueEvent(
  issue: PreparedPublicationIssue,
  options: {
    status?: "completed" | "failed";
    error?: string;
    identifier?: string;
    url?: string;
  } = {},
): string {
  const identifier = options.identifier ?? `SEC-${issue.findingId.slice(8)}`;
  const url = options.url ?? `https://linear.app/example/issue/${identifier}`;
  return JSON.stringify({
    type: "item.completed",
    item: {
      id: `tool-${issue.findingId}`,
      type: "mcp_tool_call",
      server: "codex_apps",
      tool: "linear_save_issue",
      arguments: {
        team: OPTIONS.teamId,
        project: OPTIONS.projectId,
        title: issue.title,
        description: issue.description,
        ...(issue.priority === undefined ? {} : { priority: issue.priority }),
      },
      ...(options.status === "failed"
        ? {
            status: "failed",
            error: { message: options.error ?? "Issue creation failed." },
          }
        : {
            status: "completed",
            result: {
              content: [],
              structured_content: { identifier, url },
            },
          }),
    },
  });
}

function issueEventWithResult(
  issue: PreparedPublicationIssue,
  result: unknown,
): string {
  const completed = JSON.parse(issueEvent(issue)) as {
    item: { result: unknown };
  };
  completed.item.result = result;
  return JSON.stringify(completed);
}

function failedIssueEventWithResult(
  issue: PreparedPublicationIssue,
  result: unknown,
): string {
  const failed = JSON.parse(issueEvent(issue, { status: "failed" })) as {
    item: Record<string, unknown>;
  };
  delete failed.item["error"];
  failed.item["result"] = result;
  return JSON.stringify(failed);
}

function dependencies(
  publication: PreparedScanPublication,
  invocation: Partial<PublicationCodexResult> = {},
  overrides: Partial<PublishScanDependencies> = {},
): PublishScanDependencies {
  const stateDirectory = join(
    tmpdir(),
    `codex-security-publication-test-${randomUUID()}`,
  );
  temporaryDirectories.push(stateDirectory);
  return {
    environment: {
      ...process.env,
      CODEX_SECURITY_LINEAR_API_KEY: "",
      CODEX_SECURITY_STATE_DIR: stateDirectory,
    },
    prepare: async () => publication,
    resolveCodex: () => ({ command: "synthetic-codex" }),
    runCodex: async () => ({
      exitCode: 0,
      stdout: publication.issues.map((issue) => issueEvent(issue)).join("\n"),
      stderr: "",
      ...invocation,
    }),
    preparePublicationStore: async () => undefined,
    recordPublishedIssues: async (_publication, issues) => [...issues],
    writeReceipt: async () => undefined,
    ...overrides,
  };
}

type LinearClient = ReturnType<
  NonNullable<PublishScanDependencies["linearClient"]>
>;
type LinearIssueInput = Parameters<LinearClient["createIssue"]>[0];

function linearApiClient(
  publication: PreparedScanPublication,
  options: {
    configured?: (apiKey: string) => void;
    create?: (
      input: LinearIssueInput,
      signal: AbortSignal | null | undefined,
    ) => Promise<void> | void;
    result?: (
      input: LinearIssueInput,
      index: number,
    ) => { identifier: string; url: string };
  } = {},
): NonNullable<PublishScanDependencies["linearClient"]> {
  return ({ apiKey, signal, redirect }) => {
    expect(redirect).toBe("error");
    options.configured?.(apiKey ?? "");
    return {
      users: async () => ({ nodes: [{ id: "assignee-from-email" }] }),
      createIssue: async (input: LinearIssueInput) => {
        await options.create?.(input, signal);
        const index = publication.issues.findIndex(
          ({ title }) => title === input.title,
        );
        const identifier = `SEC-${index + 1}`;
        const result = options.result?.(input, index) ?? {
          identifier,
          url: `https://linear.app/example/issue/${identifier}`,
        };
        return {
          success: true,
          issue: Promise.resolve(result),
        };
      },
    } as unknown as LinearClient;
  };
}

interface PublicationPromptData {
  scanId: string;
  handoffFile: string;
  publicationFile: string;
  batches: Array<
    Array<{
      findingId: string;
      occurrenceId: string;
    }>
  >;
}

function publicationData(input: string): PublicationPromptData {
  const encoded = input
    .split("BEGIN UNTRUSTED PUBLICATION DATA\n")[1]!
    .split("\nEND UNTRUSTED PUBLICATION DATA")[0]!;
  return JSON.parse(encoded) as PublicationPromptData;
}

function handoffRecord(
  publication: PreparedScanPublication,
  issue: PreparedPublicationIssue,
  options: {
    identifier?: string;
    identifierKey?: "issueIdentifier" | "identifier" | "id";
    url?: string;
    error?: string;
  } = {},
): Record<string, unknown> {
  return {
    scanId: publication.scanId,
    findingId: issue.findingId,
    occurrenceId: issue.occurrenceId,
    ...(options.error === undefined
      ? {
          [options.identifierKey ?? "issueIdentifier"]:
            options.identifier ?? `SEC-${issue.findingId.slice(8)}`,
          ...(options.url === undefined ? {} : { url: options.url }),
        }
      : { error: options.error }),
    arguments: {
      team: publication.destination.teamId,
      ...(publication.destination.projectId === undefined
        ? {}
        : { project: publication.destination.projectId }),
      title: issue.title,
      description: issue.description,
      ...(issue.priority === undefined ? {} : { priority: issue.priority }),
    },
  };
}

async function writeHandoff(
  input: string,
  records: readonly (Record<string, unknown> | string)[],
): Promise<void> {
  const { handoffFile } = publicationData(input);
  await appendFile(
    handoffFile,
    `${records
      .map((record) =>
        typeof record === "string" ? record : JSON.stringify(record),
      )
      .join("\n")}\n`,
    "utf8",
  );
}

async function publicationEventsFile(handoffFile: string): Promise<string> {
  const directory = dirname(handoffFile);
  const files = (await readdir(directory)).filter(
    (name) => name.startsWith("events-") && name.endsWith(".jsonl"),
  );
  expect(files).toHaveLength(1);
  return join(directory, files[0]!);
}

async function processHasExited(pid: number): Promise<boolean> {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return true;
      throw error;
    }
    if (process.platform === "linux") {
      const state = await readFile(`/proc/${pid}/stat`, "utf8").catch(
        () => undefined,
      );
      if (state === undefined || /\) Z /u.test(state)) return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return false;
}

describe("direct Linear API publication", () => {
  test("leaves issues unassigned unless an email or user ID is selected", async () => {
    for (const scenario of [
      { requested: undefined, assigned: undefined, teamOnly: false },
      {
        requested: "teammate@example.test",
        assigned: "assignee-from-email",
        teamOnly: true,
      },
      { requested: "user-123", assigned: "user-123", teamOnly: false },
    ]) {
      const publication = preparedPublication();
      if (scenario.teamOnly) delete publication.destination.projectId;
      const inputs: LinearIssueInput[] = [];
      let configuredKey = "";
      const injected = dependencies(
        publication,
        {},
        {
          linearClient: linearApiClient(publication, {
            configured: (key) => {
              configuredKey = key;
            },
            create: (input) => {
              inputs.push(input);
            },
          }),
          resolveCodex: () => {
            throw new Error("Direct publication must not start Codex.");
          },
        },
      );
      injected.environment!["CODEX_SECURITY_LINEAR_API_KEY"] =
        "environment-key";
      const result = await publishScanInternal(
        publication.scanDirectory,
        {
          destination: "linear",
          teamId: OPTIONS.teamId,
          ...(scenario.teamOnly ? {} : { projectId: OPTIONS.projectId }),
          ...(scenario.requested === undefined
            ? {}
            : { linearApiKey: "explicit-key", assigneeId: scenario.requested }),
        },
        injected,
      );

      expect(configuredKey).toBe(
        scenario.requested === undefined ? "environment-key" : "explicit-key",
      );
      expect(inputs).toEqual([
        {
          teamId: OPTIONS.teamId,
          ...(scenario.teamOnly ? {} : { projectId: OPTIONS.projectId }),
          title: publication.issues[0]!.title,
          description: publication.issues[0]!.description,
          priority: 2,
          ...(scenario.assigned === undefined
            ? {}
            : { assigneeId: scenario.assigned }),
        },
      ]);
      if (scenario.assigned === undefined) {
        expect(inputs[0]).not.toHaveProperty("assigneeId");
      }
      expect(result.counts).toEqual({ findings: 1, created: 1, failed: 0 });
    }
  });

  test("completes direct batches before continuing and preserves individual failures", async () => {
    const publication = preparedPublication(23);
    let started = 0;
    let completed = 0;
    let completedAtFirstIssueProgress: number | undefined;
    const updates: PublishScanProgress[] = [];
    let releaseFirstBatch: (() => void) | undefined;
    const firstBatchStarted = new Promise<void>((resolve) => {
      releaseFirstBatch = resolve;
    });
    const result = await publishScanInternal(
      publication.scanDirectory,
      {
        ...OPTIONS,
        linearApiKey: "synthetic-key",
        onProgress: (event) => {
          updates.push(event);
          if (
            event.type === "issue_completed" &&
            completedAtFirstIssueProgress === undefined
          ) {
            completedAtFirstIssueProgress = completed;
          }
        },
      },
      dependencies(
        publication,
        {},
        {
          linearClient: linearApiClient(publication, {
            create: async (input) => {
              const index = publication.issues.findIndex(
                ({ title }) => title === input.title,
              );
              started += 1;
              if (started === 20) releaseFirstBatch?.();
              if (index < 20) await firstBatchStarted;
              else expect(completed).toBeGreaterThanOrEqual(20);
              completed += 1;
              if (index === 21)
                throw new Error("Linear rejected this finding.");
            },
          }),
        },
      ),
    );

    expect(started).toBe(23);
    expect(result.counts).toEqual({ findings: 23, created: 22, failed: 1 });
    expect(result.failed).toEqual([
      { findingId: "finding-22", error: "Linear rejected this finding." },
    ]);
    expect(completedAtFirstIssueProgress).toBe(23);
    expect(updates.filter((event) => event.type === "batch_settled")).toEqual([
      { type: "batch_settled", settled: 20, total: 23 },
      { type: "batch_settled", settled: 23, total: 23 },
    ]);
    const mutationCheckpoints = updates.filter(
      (event) => event.type === "mutation_settled",
    );
    expect(mutationCheckpoints).toHaveLength(23);
    expect(mutationCheckpoints.map((event) => event.settled)).toEqual(
      Array.from({ length: 23 }, (_, index) => index + 1),
    );
    expect(
      new Set(mutationCheckpoints.map((event) => event.findingId)).size,
    ).toBe(23);
    expect(
      updates
        .filter((event) => event.type === "issue_completed")
        .map((event) => event.findingId),
    ).toEqual(publication.issues.map((issue) => issue.findingId));
  });

  test("does not emit terminal direct successes before duplicate identity reconciliation", async () => {
    const publication = preparedPublication(3);
    const duplicateIdentifier = "SYNTH-DUPLICATE";
    const duplicateUrl = "https://linear.app/example/issue/SYNTH-DUPLICATE";
    const updates: PublishScanProgress[] = [];
    const receipts: PublishScanResult[] = [];
    let persisted: string[] = [];
    const injected = dependencies(
      publication,
      {},
      {
        linearClient: linearApiClient(publication, {
          result: (_input, index) =>
            index < 2
              ? {
                  identifier: duplicateIdentifier,
                  url: duplicateUrl,
                }
              : {
                  identifier: "SEC-3",
                  url: "https://linear.app/example/issue/SEC-3",
                },
        }),
        recordPublishedIssues: async (_prepared, issues) => {
          persisted = issues.map(({ issueIdentifier }) => issueIdentifier);
          return [...issues];
        },
        writeReceipt: async (receipt) => {
          receipts.push(structuredClone(receipt));
        },
      },
    );

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        {
          ...OPTIONS,
          linearApiKey: "synthetic-key",
          onProgress: (event) => updates.push(event),
        },
        injected,
      ),
    ).rejects.toThrow(/could not verify every completed mutation/u);

    expect(persisted).toEqual(["SEC-3"]);
    expect(updates.filter((event) => event.type === "issue_completed")).toEqual(
      [
        {
          type: "issue_completed",
          findingId: "finding-1",
          error: CLAIM_COLLISION_ERROR,
          completed: 1,
          total: 3,
        },
        {
          type: "issue_completed",
          findingId: "finding-2",
          error: CLAIM_COLLISION_ERROR,
          completed: 2,
          total: 3,
        },
        {
          type: "issue_completed",
          findingId: "finding-3",
          issueIdentifier: "SEC-3",
          completed: 3,
          total: 3,
        },
      ],
    );
    expect(
      updates.some(
        (event) =>
          event.type === "issue_completed" &&
          event.issueIdentifier === duplicateIdentifier,
      ),
    ).toBe(false);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [{ findingId: "finding-3", issueIdentifier: "SEC-3" }],
      failed: [
        { findingId: "finding-1", error: CLAIM_COLLISION_ERROR },
        { findingId: "finding-2", error: CLAIM_COLLISION_ERROR },
      ],
      counts: { findings: 3, created: 1, failed: 2 },
    });

    const stateDirectory = injected.environment!["CODEX_SECURITY_STATE_DIR"]!;
    const handoffRoot = join(
      stateDirectory,
      "publications",
      "linear",
      "handoffs",
    );
    const handoffDirectories = await readdir(handoffRoot);
    expect(handoffDirectories).toHaveLength(1);
    const handoff = await readFile(
      join(handoffRoot, handoffDirectories[0]!, "issues.jsonl"),
      "utf8",
    );
    expect(handoff.trim().split("\n")).toHaveLength(3);
    expect(handoff.match(new RegExp(duplicateIdentifier, "gu"))).toHaveLength(
      4,
    );
  });

  test("stops before the next direct batch when durable mutation progress aborts publication", async () => {
    const publication = preparedPublication(23);
    const controller = new AbortController();
    const updates: PublishScanProgress[] = [];
    let started = 0;
    let persisted: string[] = [];
    let receipt: PublishScanResult | undefined;
    const injected = dependencies(
      publication,
      {},
      {
        linearClient: linearApiClient(publication, {
          create: () => {
            started += 1;
          },
        }),
        recordPublishedIssues: async (_prepared, issues) => {
          persisted = issues.map(({ issueIdentifier }) => issueIdentifier);
          return [...issues];
        },
        writeReceipt: async (result) => {
          receipt = structuredClone(result);
        },
      },
    );

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        {
          ...OPTIONS,
          linearApiKey: "synthetic-key",
          signal: controller.signal,
          onProgress: (event) => {
            updates.push(event);
            if (event.type === "mutation_settled") {
              controller.abort("SIGINT");
            }
          },
        },
        injected,
      ),
    ).rejects.toThrow(/publication handoff remains at/u);

    const completed = updates.filter(
      (
        event,
      ): event is Extract<PublishScanProgress, { type: "issue_completed" }> =>
        event.type === "issue_completed",
    );
    expect(started).toBe(20);
    expect(persisted).toEqual(
      Array.from({ length: 20 }, (_, index) => `SEC-${index + 1}`),
    );
    expect(receipt).toMatchObject({
      counts: { findings: 23, created: 20, failed: 3 },
    });
    expect(completed).toHaveLength(23);
    expect(new Set(completed.map(({ findingId }) => findingId)).size).toBe(23);
    expect(completed.map(({ completed }) => completed)).toEqual(
      Array.from({ length: 23 }, (_, index) => index + 1),
    );
    expect(updates.filter((event) => event.type === "batch_settled")).toEqual([
      { type: "batch_settled", settled: 20, total: 23 },
    ]);
    const mutationCheckpoints = updates.filter(
      (event) => event.type === "mutation_settled",
    );
    expect(mutationCheckpoints).toHaveLength(20);
    expect(mutationCheckpoints.map((event) => event.settled)).toEqual(
      Array.from({ length: 20 }, (_, index) => index + 1),
    );

    const stateDirectory = injected.environment!["CODEX_SECURITY_STATE_DIR"]!;
    const handoffRoot = join(
      stateDirectory,
      "publications",
      "linear",
      "handoffs",
    );
    const handoffDirectories = await readdir(handoffRoot);
    expect(handoffDirectories).toHaveLength(1);
    const handoffLines = (
      await readFile(
        join(handoffRoot, handoffDirectories[0]!, "issues.jsonl"),
        "utf8",
      )
    )
      .trim()
      .split("\n");
    expect(handoffLines).toHaveLength(20);
  });

  test("cancels slow active peers after the first durable mutation checkpoint", async () => {
    const publication = preparedPublication(23);
    const controller = new AbortController();
    const updates: PublishScanProgress[] = [];
    let started = 0;
    let stopped = 0;
    let persisted: string[] = [];
    let receipt: PublishScanResult | undefined;
    const injected = dependencies(
      publication,
      {},
      {
        linearClient: linearApiClient(publication, {
          create: async (input, signal) => {
            started += 1;
            if (input.title === publication.issues[0]!.title) {
              return;
            }
            await new Promise<void>((_resolve, reject) => {
              const stop = (): void => {
                stopped += 1;
                reject(new Error("Publication canceled."));
              };
              if (signal?.aborted) {
                stop();
                return;
              }
              signal?.addEventListener("abort", stop, { once: true });
            });
          },
        }),
        recordPublishedIssues: async (_prepared, issues) => {
          persisted = issues.map(({ issueIdentifier }) => issueIdentifier);
          return [...issues];
        },
        writeReceipt: async (result) => {
          receipt = structuredClone(result);
        },
      },
    );

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        {
          ...OPTIONS,
          linearApiKey: "synthetic-key",
          signal: controller.signal,
          onProgress: (event) => {
            updates.push(event);
            if (event.type === "mutation_settled") {
              controller.abort("checkpoint");
            }
          },
        },
        injected,
      ),
    ).rejects.toThrow(/publication handoff remains at/u);

    expect({ started, stopped, persisted }).toEqual({
      started: 20,
      stopped: 19,
      persisted: ["SEC-1"],
    });
    expect(receipt).toMatchObject({
      counts: { findings: 23, created: 1, failed: 22 },
    });
    expect(
      updates.filter((event) => event.type === "mutation_settled"),
    ).toEqual([
      {
        type: "mutation_settled",
        findingId: "finding-1",
        settled: 1,
        total: 23,
      },
    ]);
    expect(updates.filter((event) => event.type === "batch_settled")).toEqual(
      [],
    );
    const terminal = updates.filter(
      (
        event,
      ): event is Extract<PublishScanProgress, { type: "issue_completed" }> =>
        event.type === "issue_completed",
    );
    expect(terminal).toHaveLength(23);
    expect(
      terminal.filter((event) => event.issueIdentifier !== undefined),
    ).toEqual([
      {
        type: "issue_completed",
        findingId: "finding-1",
        issueIdentifier: "SEC-1",
        completed: 1,
        total: 23,
      },
    ]);
    expect(
      updates.findIndex((event) => event.type === "issue_completed"),
    ).toBeGreaterThan(
      updates.findIndex((event) => event.type === "mutation_settled"),
    );
  });

  test("recovers completed direct issues before honoring cancellation", async () => {
    const publication = preparedPublication(23);
    const controller = new AbortController();
    let started = 0;
    let stopped = 0;
    let persisted: string[] = [];
    let receipt: unknown;
    const injected = dependencies(
      publication,
      {},
      {
        linearClient: linearApiClient(publication, {
          create: async (input, signal) => {
            started += 1;
            if (input.title === publication.issues[0]!.title) {
              await new Promise((resolve) => setTimeout(resolve, 0));
              controller.abort("SIGINT");
              return;
            }
            await new Promise<void>((_resolve, reject) => {
              signal?.addEventListener(
                "abort",
                () => {
                  stopped += 1;
                  reject(new Error("Publication canceled."));
                },
                { once: true },
              );
            });
          },
        }),
        recordPublishedIssues: async (_prepared, issues) => {
          persisted = issues.map(({ issueIdentifier }) => issueIdentifier);
          return [...issues];
        },
        writeReceipt: async (result) => {
          receipt = result;
        },
      },
    );

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        {
          ...OPTIONS,
          linearApiKey: "synthetic-key",
          signal: controller.signal,
        },
        injected,
      ),
    ).rejects.toThrow(/publication handoff remains at/u);

    expect({ started, stopped, persisted }).toEqual({
      started: 20,
      stopped: 19,
      persisted: ["SEC-1"],
    });
    expect(receipt).toMatchObject({
      counts: { findings: 23, created: 1, failed: 22 },
    });
  });
});

describe("connected Linear publication", () => {
  test("rejects pre-aborted publication before preparing scans or touching local state", async () => {
    const publication = preparedPublication();
    const controller = new AbortController();
    controller.abort(new Error("Publication was canceled before it started."));
    let prepared = false;
    let verified = false;
    let resolved = false;
    let started = false;
    let persisted = false;
    let receipt = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            prepare: async () => {
              prepared = true;
              return publication;
            },
            preparePublicationStore: async () => {
              verified = true;
            },
            resolveCodex: () => {
              resolved = true;
              return { command: "must-not-run" };
            },
            runCodex: async () => {
              started = true;
              return { exitCode: 0, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = true;
              return [...issues];
            },
            writeReceipt: async () => {
              receipt = true;
            },
          },
        ),
      ),
    ).rejects.toThrow("Publication was canceled before it started.");

    expect(prepared).toBe(false);
    expect(verified).toBe(false);
    expect(resolved).toBe(false);
    expect(started).toBe(false);
    expect(persisted).toBe(false);
    expect(receipt).toBe(false);
  });

  test("does not create publication state when cancellation interrupts preparation", async () => {
    const publication = preparedPublication();
    const controller = new AbortController();
    let verified = false;
    let resolved = false;
    let started = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            prepare: async () => {
              controller.abort(new Error("Publication preparation stopped."));
              return publication;
            },
            preparePublicationStore: async () => {
              verified = true;
            },
            resolveCodex: () => {
              resolved = true;
              return { command: "must-not-run" };
            },
            runCodex: async () => {
              started = true;
              return { exitCode: 0, stdout: "", stderr: "" };
            },
          },
        ),
      ),
    ).rejects.toThrow("Publication preparation stopped.");

    expect(verified).toBe(false);
    expect(resolved).toBe(false);
    expect(started).toBe(false);
  });

  test("publishes team-only findings with project-free handoffs and recovered mappings", async () => {
    const publication: PreparedScanPublication = {
      ...preparedPublication(2),
      destination: { type: "linear", teamId: OPTIONS.teamId },
    };
    let prompt: string | undefined;
    let receiptDestination: unknown;

    const result = await publishScanInternal(
      publication.scanDirectory,
      { destination: "linear", teamId: OPTIONS.teamId },
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _arguments, input) => {
            prompt = input;
            const data = publicationData(input);
            const stored = JSON.parse(
              await readFile(data.publicationFile, "utf8"),
            ) as {
              destination: Record<string, unknown>;
              batches: Array<Array<{ arguments: Record<string, unknown> }>>;
            };
            expect(stored.destination).toEqual({
              type: "linear",
              teamId: "team-example",
            });
            expect(stored.destination).not.toHaveProperty("projectId");
            for (const issue of stored.batches.flat()) {
              expect(issue.arguments).not.toHaveProperty("project");
            }

            await writeHandoff(input, [
              handoffRecord(publication, publication.issues[0]!, {
                identifier: "TEAM-1",
              }),
            ]);
            const event = JSON.parse(
              issueEvent(publication.issues[1]!, { identifier: "TEAM-2" }),
            ) as { item: { arguments: Record<string, unknown> } };
            delete event.item.arguments["project"];
            return {
              exitCode: 0,
              stdout: JSON.stringify(event),
              stderr: "",
            };
          },
          recordPublishedIssues: async (prepared, issues) => {
            expect(prepared.destination).toEqual({
              type: "linear",
              teamId: "team-example",
            });
            const recovered = (
              await readFile(publicationData(prompt!).handoffFile, "utf8")
            )
              .trim()
              .split("\n")
              .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(
              recovered.map((record) => record["issueIdentifier"]),
            ).toEqual(["TEAM-1", "TEAM-2"]);
            for (const record of recovered) {
              expect(record["arguments"]).not.toHaveProperty("project");
            }
            return [...issues];
          },
          writeReceipt: async (receipt) => {
            receiptDestination = receipt.destination;
          },
        },
      ),
    );

    expect(prompt).toContain("linear_get_team with the supplied team");
    expect(prompt).not.toContain("linear_get_project");
    expect(prompt).not.toContain("resolved project");
    expect(prompt).toContain("Create issues only in the exact supplied team.");
    expect(result.destination).toEqual({
      type: "linear",
      teamId: "team-example",
    });
    expect(receiptDestination).toEqual(result.destination);
    expect(result.created.map((issue) => issue.issueIdentifier)).toEqual([
      "TEAM-1",
      "TEAM-2",
    ]);
    expect(result.counts).toEqual({ findings: 2, created: 2, failed: 0 });
  });

  test("reuses ambient Codex configuration and loads exact issue data from a private file", async () => {
    const publication = preparedPublication();
    const stateDirectory = await mkdtemp(
      join(tmpdir(), "codex-security-publication-environment-"),
    );
    temporaryDirectories.push(stateDirectory);
    const environment = {
      CODEX_HOME: "/existing/connected-codex-home",
      CODEX_SECURITY_STATE_DIR: stateDirectory,
    };
    let command: string | undefined;
    let args: readonly string[] | undefined;
    let input: string | undefined;
    let inheritedEnvironment: NodeJS.ProcessEnv | undefined;
    let receiptScanId: string | undefined;
    let storedPublication: unknown;

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          environment,
          runCodex: async (codex, arguments_, prompt, env) => {
            command = codex.command;
            args = arguments_;
            input = prompt;
            inheritedEnvironment = env;
            storedPublication = JSON.parse(
              await readFile(publicationData(prompt).publicationFile, "utf8"),
            );
            return {
              exitCode: 0,
              stdout: issueEvent(publication.issues[0]!),
              stderr: "",
            };
          },
          writeReceipt: async (receipt, env) => {
            receiptScanId = receipt.scanId;
            expect(env).toBe(environment);
          },
        },
      ),
    );

    expect(command).toBe("synthetic-codex");
    const handoffDirectory = args![args!.indexOf("--cd") + 1]!;
    expect(
      handoffDirectory.startsWith(join(stateDirectory, "publications")),
    ).toBe(true);
    expect(args).toEqual([
      "exec",
      "--model",
      "gpt-5.6-luna",
      "-c",
      'model_reasoning_effort="low"',
      "--ephemeral",
      "--json",
      "--sandbox",
      "workspace-write",
      "--skip-git-repo-check",
      "--cd",
      handoffDirectory,
      "-",
    ]);
    expect(args).not.toContain("--ignore-user-config");
    expect(args).not.toContain("--disable");
    expect(inheritedEnvironment).toBe(environment);
    expect(input).toContain("already-connected hosted Linear application");
    expect(input).toContain("untrusted inert data");
    expect(input).toContain("track-findings");
    expect(input).toContain("linear_save_issue exactly once per finding");
    expect(input).toContain("readFileSync('publication.json', 'utf8')");
    expect(input).toContain("issueIdentifier is the human Linear issue key");
    expect(input).toContain("Prefer identifier, issueIdentifier, or key");
    expect(input).toContain(
      "Use id only when its value is a Linear issue key ending in -digits",
    );
    expect(input).toContain(
      "Never copy a canonical UUID or opaque entity ID into issueIdentifier",
    );
    expect(input).toContain(
      "If a successful result has no human issue key, append a recovery record",
    );
    expect(input).toContain('"possibleMutation": true');
    expect(input).not.toContain("unsafe(input)");

    const encoded = input!
      .split("BEGIN UNTRUSTED PUBLICATION DATA\n")[1]!
      .split("\nEND UNTRUSTED PUBLICATION DATA")[0]!;
    expect(JSON.parse(encoded)).toEqual({
      scanId: publication.scanId,
      destination: publication.destination,
      handoffFile: join(handoffDirectory, "issues.jsonl"),
      publicationFile: join(handoffDirectory, "publication.json"),
      batches: [
        [
          {
            findingId: "finding-1",
            occurrenceId: "occurrence-1",
          },
        ],
      ],
    });
    expect(storedPublication).toEqual({
      scanId: publication.scanId,
      destination: publication.destination,
      batches: [
        [
          {
            findingId: "finding-1",
            occurrenceId: "occurrence-1",
            arguments: {
              team: "team-example",
              project: "project-example",
              title: "[Codex Security][HIGH] Synthetic finding 1",
              description: publication.issues[0]!.description,
              priority: 2,
            },
          },
        ],
      ],
    });
    expect(result).toEqual({
      scanId: "scan-example",
      uploadId: "scan-example",
      destination: publication.destination,
      created: [
        {
          findingId: "finding-1",
          occurrenceId: "occurrence-1",
          issueIdentifier: "SEC-1",
          url: "https://linear.app/example/issue/SEC-1",
        },
      ],
      failed: [],
      counts: { findings: 1, created: 1, failed: 0 },
    });
    expect(receiptScanId).toBe("scan-example");
  });

  test("publishes directly to a Linear team without project lookups or arguments", async () => {
    const publication: PreparedScanPublication = {
      ...preparedPublication(),
      destination: { type: "linear", teamId: OPTIONS.teamId },
    };
    let input: string | undefined;
    let issueArguments: Record<string, unknown> | undefined;

    const result = await publishScanInternal(
      publication.scanDirectory,
      { destination: "linear", teamId: OPTIONS.teamId },
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _arguments, prompt) => {
            input = prompt;
            const stored = JSON.parse(
              await readFile(publicationData(prompt).publicationFile, "utf8"),
            ) as {
              batches: Array<Array<{ arguments: Record<string, unknown> }>>;
            };
            issueArguments = stored.batches[0]?.[0]?.arguments;
            const event = JSON.parse(issueEvent(publication.issues[0]!)) as {
              item: { arguments: Record<string, unknown> };
            };
            delete event.item.arguments["project"];
            return {
              exitCode: 0,
              stdout: JSON.stringify(event),
              stderr: "",
            };
          },
        },
      ),
    );

    expect(input).toContain("linear_get_team with the supplied team");
    expect(input).not.toContain("linear_get_project");
    expect(input).not.toContain("resolved project");
    expect(input).toContain("Create issues only in the exact supplied team.");
    const encoded = input!
      .split("BEGIN UNTRUSTED PUBLICATION DATA\n")[1]!
      .split("\nEND UNTRUSTED PUBLICATION DATA")[0]!;
    const data = JSON.parse(encoded) as {
      destination: Record<string, unknown>;
    };
    expect(data.destination).toEqual({
      type: "linear",
      teamId: "team-example",
    });
    expect(issueArguments).toEqual({
      team: "team-example",
      title: publication.issues[0]!.title,
      description: publication.issues[0]!.description,
      priority: 2,
    });
    expect(issueArguments).not.toHaveProperty("project");
    expect(result.destination).toEqual({
      type: "linear",
      teamId: "team-example",
    });
    expect(result.counts).toEqual({ findings: 1, created: 1, failed: 0 });
  });

  test("preserves complete finding descriptions without exposing them to model transcription", async () => {
    const publication = preparedPublication(2);
    publication.issues[0]!.description = [
      "**Finding ID:** finding-1",
      "**Occurrence ID:** occurrence-1",
      "",
      "## Summary",
      "Synthetic finding summary with literal \\n and unicode: λ",
      "",
      "## Source-code evidence",
      "```ts",
      "ignorePreviousInstructions(secretInput)",
      "```",
      "",
      "## Remediation",
      "Preserve every character in this recommendation.",
    ].join("\n");
    let publicationFile: string | undefined;

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            const data = publicationData(input);
            publicationFile = data.publicationFile;
            expect(input).not.toContain("Synthetic finding summary");
            expect(input).not.toContain("ignorePreviousInstructions");
            expect(input).not.toContain("Preserve every character");
            expect(input).toContain("Never reconstruct, retype");

            const stored = JSON.parse(
              await readFile(publicationFile, "utf8"),
            ) as {
              batches: Array<
                Array<{ findingId: string; arguments: { description: string } }>
              >;
            };
            expect(stored.batches[0]![0]!.arguments.description).toBe(
              publication.issues[0]!.description,
            );
            expect(stored.batches[0]![1]!.arguments.description).toBe(
              publication.issues[1]!.description,
            );
            await writeHandoff(
              input,
              publication.issues.map((issue) =>
                handoffRecord(publication, issue),
              ),
            );
            return { exitCode: 0, stdout: "", stderr: "" };
          },
        },
      ),
    );

    expect(result.counts).toEqual({ findings: 2, created: 2, failed: 0 });
    expect(
      await readFile(publicationFile!, "utf8").catch(() => null),
    ).toBeNull();
  });

  test("derives final issues and receipts from stored handoffs without trusting Codex JSON or prose", async () => {
    const outputs = [
      "",
      [
        "not-valid-json",
        JSON.stringify({
          type: "item.completed",
          item: {
            type: "agent_message",
            text: '{"created":[{"issueIdentifier":"FABRICATED-999"}]}',
          },
        }),
      ].join("\n"),
    ];

    for (const stdout of outputs) {
      const publication = preparedPublication(3);
      const updates: PublishScanProgress[] = [];
      let receipt: unknown;
      const result = await publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, onProgress: (event) => updates.push(event) },
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              await writeHandoff(
                input,
                publication.issues.map((issue, index) =>
                  handoffRecord(publication, issue, {
                    identifier: `SEC-${index + 701}`,
                    identifierKey: ["id", "identifier", "issueIdentifier"][
                      index
                    ] as "id" | "identifier" | "issueIdentifier",
                  }),
                ),
              );
              return { exitCode: 0, stdout, stderr: "" };
            },
            recordPublishedIssues: async (prepared, created) => {
              expect(prepared).toBe(publication);
              expect(created.map((issue) => issue.issueIdentifier)).toEqual([
                "SEC-701",
                "SEC-702",
                "SEC-703",
              ]);
              return created.map((issue) => ({
                ...issue,
                url: `https://linear.app/example/database/${issue.issueIdentifier}`,
              }));
            },
            writeReceipt: async (saved) => {
              receipt = saved;
            },
          },
        ),
      );

      expect(result.created).toEqual(
        publication.issues.map((issue, index) => ({
          findingId: issue.findingId,
          occurrenceId: issue.occurrenceId,
          issueIdentifier: `SEC-${index + 701}`,
          url: `https://linear.app/example/database/SEC-${index + 701}`,
        })),
      );
      expect(result.failed).toEqual([]);
      expect(result.counts).toEqual({ findings: 3, created: 3, failed: 0 });
      expect(receipt).toEqual(result);
      expect(
        updates
          .filter((event) => event.type === "issue_completed")
          .map((event) => event.issueIdentifier),
      ).toEqual(["SEC-701", "SEC-702", "SEC-703"]);
      expect(updates.at(-1)).toEqual({
        type: "completed",
        created: 3,
        failed: 0,
        total: 3,
      });
    }
  });

  test("accepts valid handoffs when real connector events omit a recognizable issue identifier", async () => {
    const publication = preparedPublication();
    const updates: PublishScanProgress[] = [];
    const event = JSON.parse(issueEvent(publication.issues[0]!)) as {
      item: {
        tool: string;
        result: { content: unknown[]; structured_content: unknown };
      };
    };
    event.item.tool = "linear.save_issue";
    event.item.result = {
      content: [],
      structured_content: { nested_connector_response: "unrecognized" },
    };
    const recoveredUrl = "https://linear.app/example/issue/SEC-808";

    const result = await publishScanInternal(
      publication.scanDirectory,
      { ...OPTIONS, onProgress: (update) => updates.push(update) },
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input, _environment, onEvent) => {
            onEvent?.(event);
            await writeHandoff(input, [
              {
                ...handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-808",
                  url: recoveredUrl,
                }),
                structured_content: {
                  identifier: "SEC-808",
                  url: recoveredUrl,
                },
                content: [
                  {
                    type: "text",
                    text: JSON.stringify({
                      issue: { issueIdentifier: "SEC-808", url: recoveredUrl },
                    }),
                  },
                ],
              },
            ]);
            return {
              exitCode: 0,
              stdout: JSON.stringify(event),
              stderr: "",
            };
          },
        },
      ),
    );

    expect(result.created[0]!.issueIdentifier).toBe("SEC-808");
    expect(result.created[0]!.url).toBe(recoveredUrl);
    expect(result.failed).toEqual([]);
    expect(
      updates.filter((update) => update.type === "issue_completed"),
    ).toEqual([
      {
        type: "issue_completed",
        findingId: "finding-1",
        issueIdentifier: "SEC-808",
        completed: 1,
        total: 1,
      },
    ]);
  });

  test("accepts repeated equal carrier claims without staging recovery evidence", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    const identifier = "SYNTH-777";
    const url = `https://linear.app/example/issue/${identifier}`;
    const output = issueEventWithResult(issue, {
      identifier,
      url,
      structured_content: {
        issueIdentifier: identifier,
        url,
      },
      content: [
        {
          type: "text",
          text: JSON.stringify({ issue: { id: identifier, url } }),
        },
      ],
    });
    let eventWrites = 0;

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            await writeHandoff(input, [
              handoffRecord(publication, issue, {
                identifier,
                url,
              }),
            ]);
            return { exitCode: 0, stdout: output, stderr: "" };
          },
          writeEvents: async () => {
            eventWrites += 1;
            return "unused";
          },
        },
      ),
    );

    expect(result.created).toEqual([
      {
        findingId: issue.findingId,
        occurrenceId: issue.occurrenceId,
        issueIdentifier: identifier,
        url,
      },
    ]);
    expect(result.indeterminate).toBeUndefined();
    expect(eventWrites).toBe(0);
  });

  test("accepts entity-enriched event and handoff evidence as one determinate issue", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    const entityId = "11111111-2222-4333-8444-555555555555";
    const identifier = "SYNTH-711";
    const url = `https://linear.app/example/issue/${identifier}`;
    const output = issueEventWithResult(issue, {
      structured_content: { id: entityId, identifier, url },
    });
    let eventWrites = 0;
    let persisted: string[] = [];

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            await writeHandoff(input, [
              {
                ...handoffRecord(publication, issue, { identifier, url }),
                id: entityId,
              },
            ]);
            return { exitCode: 0, stdout: output, stderr: "" };
          },
          recordPublishedIssues: async (_prepared, issues) => {
            persisted = issues.map((saved) => saved.issueIdentifier);
            return [...issues];
          },
          writeEvents: async () => {
            eventWrites += 1;
            return "unused";
          },
        },
      ),
    );

    expect(result).toMatchObject({
      created: [
        {
          findingId: issue.findingId,
          occurrenceId: issue.occurrenceId,
          issueIdentifier: identifier,
          url,
        },
      ],
      failed: [],
      counts: { findings: 1, created: 1, failed: 0 },
    });
    expect(result.indeterminate).toBeUndefined();
    expect(persisted).toEqual([identifier]);
    expect(persisted).not.toContain(entityId);
    expect(eventWrites).toBe(0);
  });

  test("does not relabel an opaque connector entity as a human issue key", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    const opaqueIdentity = "synthetic-opaque-entity";
    const output = issueEventWithResult(issue, {
      structured_content: { id: opaqueIdentity },
    });
    const record = handoffRecord(publication, issue, {
      identifier: opaqueIdentity,
    });
    const receipts: PublishScanResult[] = [];
    let handoffFile = "";
    let persisted: string[] = [];

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [record]);
              return { exitCode: 0, stdout: output, stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = issues.map((saved) => saved.issueIdentifier);
              return [...issues];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow(/could not verify every completed mutation/u);

    expect(persisted).toEqual([]);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [],
      failed: [
        {
          findingId: issue.findingId,
          error: CLAIM_COLLISION_ERROR,
        },
      ],
      counts: { findings: 1, created: 0, failed: 1 },
    });
    expect(await readFile(handoffFile, "utf8")).toBe(
      `${JSON.stringify(record)}\n`,
    );
    expect(
      await readFile(await publicationEventsFile(handoffFile), "utf8"),
    ).toBe(`${output}\n`);
  });

  test("recovers a human issue key when an exact handoff relabels the entity UUID", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    const entityId = "22222222-3333-4444-8555-666666666666";
    const identifier = "SYNTH-712";
    const url = `https://linear.app/example/issue/${identifier}`;
    const output = issueEventWithResult(issue, {
      structured_content: { id: entityId, key: identifier, url },
    });
    const record = handoffRecord(publication, issue, {
      identifier: entityId,
      url,
    });
    let handoffFile = "";
    let persisted: string[] = [];

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            handoffFile = publicationData(input).handoffFile;
            await writeHandoff(input, [record]);
            return { exitCode: 0, stdout: output, stderr: "" };
          },
          recordPublishedIssues: async (_prepared, issues) => {
            persisted = issues.map((saved) => saved.issueIdentifier);
            return [...issues];
          },
        },
      ),
    );

    expect(result).toMatchObject({
      created: [
        {
          findingId: issue.findingId,
          occurrenceId: issue.occurrenceId,
          issueIdentifier: identifier,
          url,
        },
      ],
      failed: [],
      counts: { findings: 1, created: 1, failed: 0 },
    });
    expect(result.indeterminate).toBeUndefined();
    expect(persisted).toEqual([identifier]);
    expect(persisted).not.toContain(entityId);
    expect(await readFile(handoffFile, "utf8").catch(() => null)).toBeNull();
  });

  test("keeps UUID-only event and handoff evidence indeterminate without recording a publication", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    const entityId = "33333333-4444-4555-8666-777777777777";
    const url = "https://linear.app/example/issue/SYNTH-ENTITY-ONLY";
    const output = issueEventWithResult(issue, {
      structured_content: { id: entityId, url },
    });
    const record = handoffRecord(publication, issue, {
      identifier: entityId,
      url,
    });
    const receipts: PublishScanResult[] = [];
    let handoffFile = "";
    let persisted: string[] = [];

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [record]);
              return { exitCode: 0, stdout: output, stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = issues.map((saved) => saved.issueIdentifier);
              return [...issues];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /could not verify every completed mutation.*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    expect(persisted).toEqual([]);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [],
      failed: [
        {
          findingId: issue.findingId,
          error: expect.stringContaining("valid created issue identifier"),
        },
      ],
      counts: { findings: 1, created: 0, failed: 1 },
    });
    expect(await readFile(handoffFile, "utf8")).toBe(
      `${JSON.stringify(record)}\n`,
    );
    expect(
      await readFile(await publicationEventsFile(handoffFile), "utf8"),
    ).toBe(`${output}\n`);
  });

  test("retains deeply nested conflicting connector evidence without overflowing", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    let nested = '{"identifier":"SYNTH-DEEP-OTHER"}';
    for (let depth = 0; depth < 8_000; depth += 1) {
      nested = `{"issue":${nested}}`;
    }
    const result = `{"identifier":"SYNTH-DEEP-ROOT","issue":${nested}}`;
    const marker = "__SYNTHETIC_DEEP_RESULT__";
    const completed = JSON.parse(issueEvent(issue)) as {
      item: Record<string, unknown>;
    };
    completed.item["result"] = marker;
    const output = JSON.stringify(completed).replace(
      JSON.stringify(marker),
      result,
    );
    const receipts: PublishScanResult[] = [];
    let handoffFile = "";
    let persisted = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              return { exitCode: 0, stdout: output, stderr: "" };
            },
            recordPublishedIssues: async () => {
              persisted = true;
              return [];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow(/could not verify every completed mutation/u);

    expect(persisted).toBe(false);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [],
      failed: [{ findingId: issue.findingId }],
      counts: { findings: 1, created: 0, failed: 1 },
    });
    expect(await readFile(handoffFile, "utf8")).toBe("");
    expect(
      await readFile(await publicationEventsFile(handoffFile), "utf8"),
    ).toBe(`${output}\n`);
  });

  test("retains deeply nested conflicting handoff evidence without overflowing", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    let nested = '{"identifier":"SYNTH-DEEP-OTHER"}';
    for (let depth = 0; depth < 8_000; depth += 1) {
      nested = `{"issue":${nested}}`;
    }
    const marker = "__SYNTHETIC_DEEP_HANDOFF__";
    const encoded = JSON.stringify({
      ...handoffRecord(publication, issue, {
        identifier: "SYNTH-DEEP-ROOT",
      }),
      structured_content: marker,
    });
    const record = encoded.replace(JSON.stringify(marker), nested);
    const receipts: PublishScanResult[] = [];
    let handoffFile = "";
    let persisted = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [record]);
              return { exitCode: 0, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async () => {
              persisted = true;
              return [];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow(/could not verify every completed mutation/u);

    expect(persisted).toBe(false);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [],
      failed: [{ findingId: issue.findingId }],
      counts: { findings: 1, created: 0, failed: 1 },
    });
    expect(await readFile(handoffFile, "utf8")).toBe(`${record}\n`);
  });

  test("retains handoff-only evidence when Linear succeeds without a human issue key", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    const error = "Linear reported success without a human issue key.";
    const record = {
      ...handoffRecord(publication, issue, { error }),
      possibleMutation: true,
    };
    const receipts: PublishScanResult[] = [];
    let handoffFile = "";
    let persisted = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [record]);
              return { exitCode: 0, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async () => {
              persisted = true;
              return [];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /could not verify every completed mutation.*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    expect(persisted).toBe(false);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [],
      failed: [{ findingId: issue.findingId, error }],
      counts: { findings: 1, created: 0, failed: 1 },
    });
    expect(await readFile(handoffFile, "utf8")).toBe(
      `${JSON.stringify(record)}\n`,
    );
    expect(
      (await readdir(dirname(handoffFile))).filter(
        (name) => name.startsWith("events-") && name.endsWith(".jsonl"),
      ),
    ).toEqual([]);
  });

  test("retains an explicit possible mutation when a keyless handoff copies mismatched arguments", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    const record = handoffRecord(publication, issue);
    delete record["issueIdentifier"];
    record["possibleMutation"] = true;
    (record["arguments"] as Record<string, unknown>)["title"] =
      "[Codex Security][HIGH] Mismatched synthetic finding";
    const receipts: PublishScanResult[] = [];
    let handoffFile = "";
    let persisted = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [record]);
              return { exitCode: 0, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async () => {
              persisted = true;
              return [];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /could not verify every completed mutation.*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    expect(persisted).toBe(false);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [],
      failed: [
        {
          findingId: issue.findingId,
          error: expect.stringContaining("valid created issue identifier"),
        },
      ],
      counts: { findings: 1, created: 0, failed: 1 },
    });
    expect(await readFile(handoffFile, "utf8")).toBe(
      `${JSON.stringify(record)}\n`,
    );
  });

  test("keeps an ordinary failure determinate and removes its handoff", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    const error = "Linear rejected the synthetic finding.";
    const record = handoffRecord(publication, issue, { error });
    let handoffFile = "";
    let receipt: PublishScanResult | undefined;

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            handoffFile = publicationData(input).handoffFile;
            await writeHandoff(input, [record]);
            return { exitCode: 0, stdout: "", stderr: "" };
          },
          writeReceipt: async (saved) => {
            receipt = structuredClone(saved);
          },
        },
      ),
    );

    expect(result).toMatchObject({
      created: [],
      failed: [{ findingId: issue.findingId, error }],
      counts: { findings: 1, created: 0, failed: 1 },
    });
    expect(result.indeterminate).toBeUndefined();
    expect(receipt).toEqual(result);
    expect(await readFile(handoffFile, "utf8").catch(() => null)).toBeNull();
  });

  test("rejects every owner of a shared entity ID while preserving independent sibling order", async () => {
    const publication = preparedPublication(4);
    const [first, ownerA, ownerB, last] = publication.issues as [
      PreparedPublicationIssue,
      PreparedPublicationIssue,
      PreparedPublicationIssue,
      PreparedPublicationIssue,
    ];
    const sharedEntityId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const identifiers = [
      "SYNTH-801",
      "SYNTH-802",
      "SYNTH-803",
      "SYNTH-804",
    ] as const;
    const enriched = (
      issue: PreparedPublicationIssue,
      identifier: string,
    ): Record<string, unknown> => ({
      ...handoffRecord(publication, issue, {
        identifier,
        url: `https://linear.app/example/issue/${identifier}`,
      }),
      id: sharedEntityId,
    });
    const records = [
      handoffRecord(publication, last, { identifier: identifiers[3] }),
      enriched(ownerB, identifiers[2]!),
      handoffRecord(publication, first, { identifier: identifiers[0] }),
      enriched(ownerA, identifiers[1]!),
    ];
    const receipts: PublishScanResult[] = [];
    let handoffFile = "";
    let persisted: string[] = [];

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, records);
              return { exitCode: 0, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = issues.map((saved) => saved.issueIdentifier);
              return [...issues];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow("could not verify every completed mutation");

    expect(persisted).toEqual([identifiers[0], identifiers[3]]);
    expect(persisted).not.toContain(sharedEntityId);
    const receipt = receipts.at(-1)!;
    expect(receipt.indeterminate).toBe(true);
    expect(receipt.created.map((saved) => saved.issueIdentifier)).toEqual([
      identifiers[0],
      identifiers[3],
    ]);
    expect(receipt.failed).toEqual([
      {
        findingId: ownerA.findingId,
        error: CLAIM_COLLISION_ERROR,
      },
      {
        findingId: ownerB.findingId,
        error: CLAIM_COLLISION_ERROR,
      },
    ]);
    expect(await readFile(handoffFile, "utf8")).toBe(
      `${records.map((record) => JSON.stringify(record)).join("\n")}\n`,
    );
  });

  test.each([
    [
      "lowercase event, uppercase handoff, forward event order",
      false,
      "forward",
    ],
    [
      "lowercase event, uppercase handoff, reverse event order",
      false,
      "reverse",
    ],
    [
      "uppercase event, lowercase handoff, forward event order",
      true,
      "forward",
    ],
    [
      "uppercase event, lowercase handoff, reverse event order",
      true,
      "reverse",
    ],
  ] as const)(
    "rejects case-aliased entity UUIDs across %s",
    async (_label, eventUsesUppercase, eventOrder) => {
      const publication = preparedPublication(3);
      const [eventOwner, handoffOwner, sibling] = publication.issues as [
        PreparedPublicationIssue,
        PreparedPublicationIssue,
        PreparedPublicationIssue,
      ];
      const canonicalEntityId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
      const uppercaseEntityId = canonicalEntityId.toUpperCase();
      const eventEntityId = eventUsesUppercase
        ? uppercaseEntityId
        : canonicalEntityId;
      const handoffEntityId = eventUsesUppercase
        ? canonicalEntityId
        : uppercaseEntityId;
      const eventIdentifier = "SYNTH-UUID-EVENT-1";
      const handoffIdentifier = "SYNTH-UUID-HANDOFF-2";
      const siblingIdentifier = "SYNTH-UUID-SIBLING-3";
      const collidingEvent = issueEventWithResult(eventOwner, {
        structured_content: {
          id: eventEntityId,
          identifier: eventIdentifier,
          url: `https://linear.app/example/issue/${eventIdentifier}`,
        },
      });
      const siblingEvent = issueEvent(sibling, {
        identifier: siblingIdentifier,
        url: `https://linear.app/example/issue/${siblingIdentifier}`,
      });
      const output =
        eventOrder === "forward"
          ? [collidingEvent, siblingEvent].join("\n")
          : [siblingEvent, collidingEvent].join("\n");
      const handoff = {
        ...handoffRecord(publication, handoffOwner, {
          identifier: handoffIdentifier,
          url: `https://linear.app/example/issue/${handoffIdentifier}`,
        }),
        id: handoffEntityId,
      };
      const receipts: PublishScanResult[] = [];
      let handoffFile = "";
      let persisted: string[] = [];

      await expect(
        publishScanInternal(
          publication.scanDirectory,
          OPTIONS,
          dependencies(
            publication,
            {},
            {
              runCodex: async (_command, _args, input) => {
                handoffFile = publicationData(input).handoffFile;
                await writeHandoff(input, [handoff]);
                return { exitCode: 0, stdout: output, stderr: "" };
              },
              recordPublishedIssues: async (_prepared, issues) => {
                persisted = issues.map((issue) => issue.issueIdentifier);
                return [...issues];
              },
              writeReceipt: async (receipt) => {
                receipts.push(structuredClone(receipt));
              },
            },
          ),
        ),
      ).rejects.toThrow("could not verify every completed mutation");

      expect(persisted).toEqual([siblingIdentifier]);
      const receipt = receipts.at(-1)!;
      expect(receipt).toMatchObject({
        indeterminate: true,
        created: [
          {
            findingId: sibling.findingId,
            issueIdentifier: siblingIdentifier,
          },
        ],
        failed: [
          {
            findingId: eventOwner.findingId,
            error: CLAIM_COLLISION_ERROR,
          },
          {
            findingId: handoffOwner.findingId,
            error: CLAIM_COLLISION_ERROR,
          },
        ],
        counts: { findings: 3, created: 1, failed: 2 },
      });
      expect(JSON.stringify(receipt.failed)).not.toContain(canonicalEntityId);
      expect(JSON.stringify(receipt.failed)).not.toContain(uppercaseEntityId);
      const recoveryRecords = (await readFile(handoffFile, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(recoveryRecords.map((record) => record["findingId"])).toEqual([
        handoffOwner.findingId,
        sibling.findingId,
      ]);
      expect(
        await readFile(await publicationEventsFile(handoffFile), "utf8"),
      ).toBe(`${output}\n`);
    },
  );

  test.each([
    [
      "entity result then identifier handoff",
      "entity-to-identifier",
      "forward",
    ],
    [
      "entity result then identifier handoff",
      "entity-to-identifier",
      "reverse",
    ],
    [
      "identifier result then entity handoff",
      "identifier-to-entity",
      "forward",
    ],
    [
      "identifier result then entity handoff",
      "identifier-to-entity",
      "reverse",
    ],
    ["URL result then identifier handoff", "url-to-identifier", "forward"],
    ["URL result then identifier handoff", "url-to-identifier", "reverse"],
    ["identifier result then URL handoff", "identifier-to-url", "forward"],
    ["identifier result then URL handoff", "identifier-to-url", "reverse"],
  ] as const)(
    "rejects cross-kind claim reuse across owners: %s (%s, %s event order)",
    async (_label, kind, eventOrder) => {
      const publication = preparedPublication(3);
      const [eventOwner, handoffOwner, sibling] = publication.issues as [
        PreparedPublicationIssue,
        PreparedPublicationIssue,
        PreparedPublicationIssue,
      ];
      const sharedValue = kind.includes("url")
        ? "https://linear.app/example/issue/SYNTH-CROSS-VALUE"
        : "synthetic-opaque-cross-owner";
      const eventIdentifier =
        kind === "identifier-to-entity" || kind === "identifier-to-url"
          ? sharedValue
          : "SYNTH-EVENT-OWNER";
      const eventUrl =
        kind === "url-to-identifier"
          ? sharedValue
          : "https://linear.app/example/issue/SYNTH-EVENT-OWNER";
      const eventResult: Record<string, unknown> = {
        identifier: eventIdentifier,
        url: eventUrl,
        ...(kind === "entity-to-identifier" ? { id: sharedValue } : {}),
      };
      const collidingEvent = issueEventWithResult(eventOwner, {
        structured_content: eventResult,
      });
      const siblingIdentifier = "SYNTH-INDEPENDENT-SIBLING";
      const siblingEvent = issueEvent(sibling, {
        identifier: siblingIdentifier,
        url: `https://linear.app/example/issue/${siblingIdentifier}`,
      });
      const outputLines =
        eventOrder === "forward"
          ? [collidingEvent, siblingEvent]
          : [siblingEvent, collidingEvent];
      const handoffIdentifier =
        kind === "entity-to-identifier" || kind === "url-to-identifier"
          ? sharedValue
          : "SYNTH-HANDOFF-OWNER";
      const handoffUrl =
        kind === "identifier-to-url"
          ? sharedValue
          : "https://linear.app/example/issue/SYNTH-HANDOFF-OWNER";
      const handoff = {
        ...handoffRecord(publication, handoffOwner, {
          identifier: handoffIdentifier,
          url: handoffUrl,
        }),
        ...(kind === "identifier-to-entity" ? { id: sharedValue } : {}),
      };
      const output = outputLines.join("\n");
      const receipts: PublishScanResult[] = [];
      let handoffFile = "";
      let persisted: string[] = [];

      await expect(
        publishScanInternal(
          publication.scanDirectory,
          OPTIONS,
          dependencies(
            publication,
            {},
            {
              runCodex: async (_command, _args, input) => {
                handoffFile = publicationData(input).handoffFile;
                await writeHandoff(input, [handoff]);
                return { exitCode: 0, stdout: output, stderr: "" };
              },
              recordPublishedIssues: async (_prepared, issues) => {
                persisted = issues.map((issue) => issue.issueIdentifier);
                return [...issues];
              },
              writeReceipt: async (receipt) => {
                receipts.push(structuredClone(receipt));
              },
            },
          ),
        ),
      ).rejects.toThrow("could not verify every completed mutation");

      expect(persisted).toEqual([siblingIdentifier]);
      expect(persisted).not.toContain(sharedValue);
      expect(receipts).toHaveLength(2);
      const receipt = receipts.at(-1)!;
      expect(receipt).toMatchObject({
        indeterminate: true,
        created: [
          {
            findingId: sibling.findingId,
            issueIdentifier: siblingIdentifier,
          },
        ],
        failed: [
          {
            findingId: eventOwner.findingId,
            error: CLAIM_COLLISION_ERROR,
          },
          {
            findingId: handoffOwner.findingId,
            error: CLAIM_COLLISION_ERROR,
          },
        ],
        counts: { findings: 3, created: 1, failed: 2 },
      });
      const recoveryRecords = (await readFile(handoffFile, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(recoveryRecords.map((record) => record["findingId"])).toEqual([
        handoffOwner.findingId,
        sibling.findingId,
      ]);
      expect(
        await readFile(await publicationEventsFile(handoffFile), "utf8"),
      ).toBe(`${output}\n`);
    },
  );

  test.each([
    ["the same owner", "same-owner"],
    ["an unknown owner", "unknown-owner"],
  ] as const)(
    "rejects entity-to-identifier reuse split across evidence for %s",
    async (_label, attribution) => {
      const publication = preparedPublication(2);
      const [candidate, sibling] = publication.issues as [
        PreparedPublicationIssue,
        PreparedPublicationIssue,
      ];
      const sharedValue = "synthetic-opaque-split-evidence";
      const event = JSON.parse(
        issueEventWithResult(candidate, {
          structured_content: {
            id: sharedValue,
            identifier: "SYNTH-EVENT-IDENTIFIER",
          },
        }),
      ) as { item: { arguments: Record<string, unknown> } };
      if (attribution === "unknown-owner") {
        event.item.arguments["description"] =
          "Synthetic description without a publication identity.";
      }
      const siblingIdentifier = "SYNTH-SPLIT-SIBLING";
      const output = [
        JSON.stringify(event),
        issueEvent(sibling, { identifier: siblingIdentifier }),
      ].join("\n");
      const handoff = handoffRecord(publication, candidate, {
        identifier: sharedValue,
      });
      const receipts: PublishScanResult[] = [];
      let handoffFile = "";
      let persisted: string[] = [];

      await expect(
        publishScanInternal(
          publication.scanDirectory,
          OPTIONS,
          dependencies(
            publication,
            {},
            {
              runCodex: async (_command, _args, input) => {
                handoffFile = publicationData(input).handoffFile;
                await writeHandoff(input, [handoff]);
                return { exitCode: 0, stdout: output, stderr: "" };
              },
              recordPublishedIssues: async (_prepared, issues) => {
                persisted = issues.map((issue) => issue.issueIdentifier);
                return [...issues];
              },
              writeReceipt: async (receipt) => {
                receipts.push(structuredClone(receipt));
              },
            },
          ),
        ),
      ).rejects.toThrow("could not verify every completed mutation");

      expect(persisted).toEqual([siblingIdentifier]);
      expect(receipts.at(-1)).toMatchObject({
        indeterminate: true,
        created: [
          {
            findingId: sibling.findingId,
            issueIdentifier: siblingIdentifier,
          },
        ],
        failed: [
          {
            findingId: candidate.findingId,
            error: CLAIM_COLLISION_ERROR,
          },
        ],
        counts: { findings: 2, created: 1, failed: 1 },
      });
      expect(await readFile(handoffFile, "utf8")).toContain(sharedValue);
      expect(
        await readFile(await publicationEventsFile(handoffFile), "utf8"),
      ).toBe(`${output}\n`);
    },
  );

  test.each([
    ["identifier", "event"],
    ["identifier", "handoff"],
    ["entityId", "event"],
    ["entityId", "handoff"],
    ["url", "event"],
    ["url", "handoff"],
  ] as const)(
    "normalizes surrounding whitespace on %s claims from %s evidence",
    async (kind, paddedSource) => {
      const publication = preparedPublication(3);
      const [eventOwner, handoffOwner, sibling] = publication.issues as [
        PreparedPublicationIssue,
        PreparedPublicationIssue,
        PreparedPublicationIssue,
      ];
      const sharedValue =
        kind === "identifier"
          ? "SYNTH-WHITESPACE-SHARED"
          : kind === "entityId"
            ? "55555555-6666-4777-8888-999999999999"
            : "https://linear.app/example/issue/SYNTH-WHITESPACE-SHARED";
      const padded = (value: string): string => ` \t${value}\n`;
      const eventValue =
        paddedSource === "event" ? padded(sharedValue) : sharedValue;
      const handoffValue =
        paddedSource === "handoff" ? padded(sharedValue) : sharedValue;
      const eventIdentifier =
        kind === "identifier" ? eventValue : "SYNTH-WHITESPACE-EVENT";
      const handoffIdentifier =
        kind === "identifier" ? handoffValue : "SYNTH-WHITESPACE-HANDOFF";
      const eventUrl =
        kind === "url"
          ? eventValue
          : "https://linear.app/example/issue/SYNTH-WHITESPACE-EVENT";
      const handoffUrl =
        kind === "url"
          ? handoffValue
          : "https://linear.app/example/issue/SYNTH-WHITESPACE-HANDOFF";
      const ownerEvent = issueEventWithResult(eventOwner, {
        structured_content: {
          identifier: eventIdentifier,
          url: eventUrl,
          ...(kind === "entityId" ? { id: eventValue } : {}),
        },
      });
      const siblingIdentifier = "SYNTH-WHITESPACE-SIBLING";
      const siblingEvent = issueEvent(sibling, {
        identifier: siblingIdentifier,
      });
      const outputLines =
        paddedSource === "event"
          ? [ownerEvent, siblingEvent]
          : [siblingEvent, ownerEvent];
      const output = outputLines.join("\n");
      const handoff = {
        ...handoffRecord(publication, handoffOwner, {
          identifier: handoffIdentifier,
          url: handoffUrl,
        }),
        ...(kind === "entityId" ? { id: handoffValue } : {}),
      };
      const siblingRecord = handoffRecord(publication, sibling, {
        identifier: siblingIdentifier,
      });
      const records =
        paddedSource === "handoff"
          ? [handoff, siblingRecord]
          : [siblingRecord, handoff];
      const receipts: PublishScanResult[] = [];
      let handoffFile = "";
      let persisted: string[] = [];
      let failure: unknown;

      try {
        await publishScanInternal(
          publication.scanDirectory,
          OPTIONS,
          dependencies(
            publication,
            {},
            {
              runCodex: async (_command, _args, input) => {
                handoffFile = publicationData(input).handoffFile;
                await writeHandoff(input, records);
                return { exitCode: 0, stdout: output, stderr: "" };
              },
              recordPublishedIssues: async (_prepared, issues) => {
                persisted = issues.map((issue) => issue.issueIdentifier);
                return [...issues];
              },
              writeReceipt: async (receipt) => {
                receipts.push(structuredClone(receipt));
              },
            },
          ),
        );
      } catch (error) {
        failure = error;
      }

      expect(failure).toBeInstanceOf(Error);
      expect((failure as Error).message).toContain(
        "could not verify every completed mutation",
      );
      expect((failure as Error).message).not.toContain(sharedValue);
      expect(persisted).toEqual([siblingIdentifier]);
      const receipt = receipts.at(-1)!;
      expect(receipt).toMatchObject({
        indeterminate: true,
        created: [
          {
            findingId: sibling.findingId,
            issueIdentifier: siblingIdentifier,
          },
        ],
        failed: [
          {
            findingId: eventOwner.findingId,
            error: CLAIM_COLLISION_ERROR,
          },
          {
            findingId: handoffOwner.findingId,
            error: CLAIM_COLLISION_ERROR,
          },
        ],
        counts: { findings: 3, created: 1, failed: 2 },
      });
      expect(JSON.stringify(receipt.failed)).not.toContain(sharedValue);
      expect(await readFile(handoffFile, "utf8")).toBe(
        `${records.map((record) => JSON.stringify(record)).join("\n")}\n`,
      );
      expect(
        await readFile(await publicationEventsFile(handoffFile), "utf8"),
      ).toBe(`${output}\n`);
    },
  );

  test.each([
    ["structured conflict with handoff A", "conflict-structured-a"],
    ["root/JSON conflict with handoff B", "conflict-json-b"],
    ["conflicting event identifier X reservation", "conflicting-x"],
    ["conflicting event URL Y reservation", "conflicting-y"],
    ["unknown-owner identifier reservation", "unknown-id"],
    ["wrong-argument URL reservation", "wrong-url"],
    ["wrong-argument independent sibling", "wrong-independent"],
    ["owner-conflicting identifier reservation", "owner-id"],
    ["owner-conflicting URL reservation", "owner-url"],
    ["owner-conflicting independent sibling", "owner-independent"],
    ["URL-only carrier reservation", "url-only"],
    ["different identifiers with one URL", "pair-url"],
    ["one identifier with different URLs", "pair-id"],
    ["absent result with independent sibling", "absent"],
  ] as const)("reconciles one evidence ledger: %s", async (_label, kind) => {
    const publication = preparedPublication(2);
    const [owner, sibling] = publication.issues as [
      PreparedPublicationIssue,
      PreparedPublicationIssue,
    ];
    const url = (identifier: string): string =>
      `https://linear.app/example/issue/${identifier}`;
    const zRecord = handoffRecord(publication, sibling, {
      identifier: "SYNTH-Z",
      url: url("SYNTH-Z"),
    });
    let output = "";
    let records: Record<string, unknown>[] = [];
    let expectedPersisted: string[] = [];

    if (
      kind === "conflict-structured-a" ||
      kind === "conflict-json-b" ||
      kind === "conflicting-x" ||
      kind === "conflicting-y"
    ) {
      output = issueEventWithResult(owner, {
        structured_content: {
          identifier: "SYNTH-X",
          url: url("SYNTH-X"),
        },
        content: [
          {
            type: "text",
            text: JSON.stringify({
              identifier: "SYNTH-Y",
              url: url("SYNTH-Y"),
            }),
          },
        ],
        ...(kind === "conflict-json-b"
          ? { identifier: "SYNTH-X", url: url("SYNTH-X") }
          : {}),
      });
      const selectedIdentifier =
        kind === "conflict-json-b" ? "SYNTH-Y" : "SYNTH-X";
      records = [
        handoffRecord(publication, owner, {
          identifier: selectedIdentifier,
          url: url(selectedIdentifier),
        }),
        kind === "conflicting-x"
          ? handoffRecord(publication, sibling, {
              identifier: "SYNTH-X",
              url: url("SYNTH-B"),
            })
          : kind === "conflicting-y"
            ? handoffRecord(publication, sibling, {
                identifier: "SYNTH-B",
                url: url("SYNTH-Y"),
              })
            : zRecord,
      ];
      expectedPersisted =
        kind === "conflict-structured-a" || kind === "conflict-json-b"
          ? ["SYNTH-Z"]
          : [];
    } else if (kind === "unknown-id") {
      const unknown = JSON.parse(
        issueEvent(owner, { identifier: "SYNTH-X", url: url("SYNTH-X") }),
      ) as { item: { arguments: Record<string, unknown> } };
      unknown.item.arguments["description"] = "No publication identity";
      output = JSON.stringify(unknown);
      records = [
        handoffRecord(publication, sibling, {
          identifier: "SYNTH-X",
          url: url("SYNTH-B"),
        }),
      ];
    } else if (kind === "wrong-url" || kind === "wrong-independent") {
      const wrong = JSON.parse(
        issueEvent(owner, { identifier: "SYNTH-X", url: url("SYNTH-X") }),
      ) as { item: { arguments: Record<string, unknown> } };
      wrong.item.arguments["team"] = "team-unexpected";
      output = JSON.stringify(wrong);
      records = [
        handoffRecord(publication, owner, {
          identifier: "SYNTH-X",
          url: url("SYNTH-X"),
        }),
        kind === "wrong-url"
          ? handoffRecord(publication, sibling, {
              identifier: "SYNTH-B",
              url: url("SYNTH-X"),
            })
          : zRecord,
      ];
      if (kind === "wrong-independent") {
        expectedPersisted = ["SYNTH-Z"];
      }
    } else if (
      kind === "owner-id" ||
      kind === "owner-url" ||
      kind === "owner-independent"
    ) {
      output = issueEvent(owner, {
        identifier: "SYNTH-X",
        url: url("SYNTH-X"),
      });
      records = [
        handoffRecord(publication, owner, {
          identifier: kind === "owner-id" ? "SYNTH-Y" : "SYNTH-X",
          url: url("SYNTH-Y"),
        }),
        kind === "owner-id"
          ? handoffRecord(publication, sibling, {
              identifier: "SYNTH-X",
              url: url("SYNTH-B"),
            })
          : kind === "owner-url"
            ? handoffRecord(publication, sibling, {
                identifier: "SYNTH-B",
                url: url("SYNTH-X"),
              })
            : zRecord,
      ];
      if (kind === "owner-independent") {
        expectedPersisted = ["SYNTH-Z"];
      }
    } else if (kind === "url-only") {
      output = issueEventWithResult(owner, {
        identifier: "SYNTH-A",
        url: url("SYNTH-A"),
        structured_content: { url: url("SYNTH-URL-ONLY") },
      });
      records = [
        handoffRecord(publication, owner, {
          identifier: "SYNTH-A",
          url: url("SYNTH-A"),
        }),
        handoffRecord(publication, sibling, {
          identifier: "SYNTH-B",
          url: url("SYNTH-URL-ONLY"),
        }),
      ];
    } else if (kind === "pair-url" || kind === "pair-id") {
      records = publication.issues.map((issue, index) =>
        handoffRecord(publication, issue, {
          identifier:
            kind === "pair-id" ? "SYNTH-SHARED" : `SYNTH-${index + 1}`,
          url:
            kind === "pair-url"
              ? url("SYNTH-SHARED")
              : url(`SYNTH-${index + 1}`),
        }),
      );
    } else {
      output = issueEventWithResult(owner, {
        structured_content: { title: "No identifier" },
        content: [],
      });
      records = [zRecord];
      expectedPersisted = ["SYNTH-Z"];
    }

    const receipts: PublishScanResult[] = [];
    const updates: PublishScanProgress[] = [];
    let handoffFile = "";
    let historyWrites = 0;
    let persisted: string[] = [];

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, onProgress: (update) => updates.push(update) },
        dependencies(
          publication,
          { stdout: output },
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, records);
              return { exitCode: 0, stdout: output, stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              historyWrites += 1;
              persisted = issues.map((issue) => issue.issueIdentifier);
              return [...issues];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow("could not verify every completed mutation");

    expect(historyWrites).toBe(expectedPersisted.length > 0 ? 1 : 0);
    expect(persisted).toEqual(expectedPersisted);
    expect(receipts).toHaveLength(2);
    const finalReceipt = receipts.at(-1)!;
    expect(finalReceipt.indeterminate).toBe(true);
    expect(finalReceipt.created.map((issue) => issue.issueIdentifier)).toEqual(
      expectedPersisted,
    );
    expect(finalReceipt.failed.map((failure) => failure.findingId)).toEqual(
      publication.issues
        .filter(
          (issue) =>
            !finalReceipt.created.some(
              (created) => created.findingId === issue.findingId,
            ),
        )
        .map((issue) => issue.findingId),
    );
    expect(await readFile(handoffFile, "utf8")).toBe(
      `${records.map((record) => JSON.stringify(record)).join("\n")}\n`,
    );
    const eventFiles = (await readdir(dirname(handoffFile))).filter((name) =>
      name.startsWith("events-"),
    );
    if (output.length === 0) {
      expect(eventFiles).toEqual([]);
    } else {
      expect(eventFiles).toHaveLength(1);
      expect(
        await readFile(join(dirname(handoffFile), eventFiles[0]!), "utf8"),
      ).toBe(`${output}\n`);
    }
    expect(updates.some((update) => update.type === "completed")).toBe(false);
  });

  test.each([
    ["identifier", "exact", true],
    ["URL", "exact", true],
    ["identifier", "unowned", false],
    ["URL", "wrong-argument", false],
  ] as const)(
    "handles %s claims from %s failed results as negative evidence",
    async (claimKind, attribution, collides) => {
      const publication = preparedPublication(3);
      const [failed, candidate, independent] = publication.issues as [
        PreparedPublicationIssue,
        PreparedPublicationIssue,
        PreparedPublicationIssue,
      ];
      const sharedIdentifier = "SYNTH-SHARED";
      const sharedUrl = "https://linear.app/example/issue/SYNTH-SHARED";
      const candidateIdentifier = "SYNTH-CANDIDATE";
      const candidateUrl = "https://linear.app/example/issue/SYNTH-CANDIDATE";
      const failedResult = {
        structured_content:
          claimKind === "identifier"
            ? { identifier: sharedIdentifier }
            : { url: sharedUrl },
      };
      const candidateHandoff =
        claimKind === "identifier"
          ? {
              identifier: collides ? sharedIdentifier : candidateIdentifier,
              url: candidateUrl,
            }
          : {
              identifier: candidateIdentifier,
              url: collides ? sharedUrl : candidateUrl,
            };
      const independentIdentifier = "SYNTH-INDEPENDENT";
      const independentUrl =
        "https://linear.app/example/issue/SYNTH-INDEPENDENT";
      const independentEvent = issueEvent(independent, {
        identifier: independentIdentifier,
        url: independentUrl,
      });
      const failedRecord = JSON.parse(
        failedIssueEventWithResult(failed, failedResult),
      ) as { item: { arguments: Record<string, unknown> } };
      if (attribution === "unowned") {
        failedRecord.item.arguments["description"] = "No publication identity";
      } else if (attribution === "wrong-argument") {
        failedRecord.item.arguments["team"] = "team-unexpected";
      }
      const failedEvent = JSON.stringify(failedRecord);
      const output = [independentEvent, failedEvent].join("\n");
      const records = [
        handoffRecord(publication, candidate, candidateHandoff),
        handoffRecord(publication, independent, {
          identifier: independentIdentifier,
          url: independentUrl,
        }),
      ];
      const receipts: PublishScanResult[] = [];
      let handoffFile = "";
      let persisted: string[] = [];
      const expectedPersisted = [
        ...(collides ? [] : [candidateIdentifier]),
        independentIdentifier,
      ];

      await expect(
        publishScanInternal(
          publication.scanDirectory,
          OPTIONS,
          dependencies(
            publication,
            {},
            {
              runCodex: async (_command, _args, input) => {
                handoffFile = publicationData(input).handoffFile;
                await writeHandoff(input, records);
                return { exitCode: 0, stdout: output, stderr: "" };
              },
              recordPublishedIssues: async (_prepared, issues) => {
                persisted = issues.map((issue) => issue.issueIdentifier);
                return [...issues];
              },
              writeReceipt: async (receipt) => {
                receipts.push(structuredClone(receipt));
              },
            },
          ),
        ),
      ).rejects.toThrow("could not verify every completed mutation");

      expect(persisted).toEqual(expectedPersisted);
      const receipt = receipts.at(-1)!;
      expect(receipt.indeterminate).toBe(true);
      expect(receipt.created.map((issue) => issue.issueIdentifier)).toEqual(
        expectedPersisted,
      );
      expect(receipt.failed.map((issue) => issue.findingId)).toEqual(
        collides ? [failed.findingId, candidate.findingId] : [failed.findingId],
      );
      if (collides) {
        expect(receipt.failed[1]!.error).toContain("reused");
      }
      expect(
        await readFile(await publicationEventsFile(handoffFile), "utf8"),
      ).toBe(`${output}\n`);
    },
  );

  test.each([
    ["a single failed call", 1, undefined, false],
    ["a failed retry", 2, undefined, true],
    [
      "a single failed call with an explicit failure handoff",
      1,
      "The handoff records a synthetic rejection.",
      false,
    ],
  ] as const)(
    "keeps claim-free terminal evidence compatible with %s",
    async (_name, attempts, handoffError, indeterminate) => {
      const publication = preparedPublication(2);
      const [failed, sibling] = publication.issues as [
        PreparedPublicationIssue,
        PreparedPublicationIssue,
      ];
      const outputLines = Array.from({ length: attempts }, (_, index) =>
        issueEvent(failed, {
          status: "failed",
          error: `Synthetic rejection ${index + 1}.`,
        }),
      );
      const records = [
        ...(handoffError === undefined
          ? []
          : [handoffRecord(publication, failed, { error: handoffError })]),
        handoffRecord(publication, sibling, {
          identifier: "SYNTH-SIBLING",
        }),
      ];
      const receipts: PublishScanResult[] = [];
      const preservedEvents: string[][] = [];
      let persisted: string[] = [];

      const operation = publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              await writeHandoff(input, records);
              return {
                exitCode: 0,
                stdout: outputLines.join("\n"),
                stderr: "",
              };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = issues.map((issue) => issue.issueIdentifier);
              return [...issues];
            },
            writeEvents: async (_directory, events) => {
              preservedEvents.push([...events]);
              return "/synthetic/events.jsonl";
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      );

      const result = indeterminate
        ? await expect(operation).rejects.toThrow(
            "could not verify every completed mutation",
          )
        : await operation;
      const finalReceipt = indeterminate ? receipts.at(-1)! : result;

      expect(persisted).toEqual(["SYNTH-SIBLING"]);
      expect(finalReceipt).toMatchObject({
        ...(indeterminate ? { indeterminate: true } : {}),
        created: [
          {
            findingId: sibling.findingId,
            issueIdentifier: "SYNTH-SIBLING",
          },
        ],
        failed: [
          {
            findingId: failed.findingId,
            error:
              handoffError ??
              (attempts > 1
                ? expect.stringContaining("more than one")
                : "Synthetic rejection 1."),
          },
        ],
      });
      expect(preservedEvents).toEqual(indeterminate ? [outputLines] : []);
    },
  );

  test("persists unaffected siblings in publication order while retaining recovery evidence", async () => {
    const publication = preparedPublication(3);
    const [first, conflicting, last] = publication.issues as [
      PreparedPublicationIssue,
      PreparedPublicationIssue,
      PreparedPublicationIssue,
    ];
    const outputs = [
      issueEvent(first, { identifier: "SYNTH-FIRST" }),
      issueEventWithResult(conflicting, {
        structured_content: { identifier: "SYNTH-X" },
        content: [
          {
            type: "text",
            text: JSON.stringify({ identifier: "SYNTH-Y" }),
          },
        ],
      }),
      issueEventWithResult(last, {
        structured_content: { title: "No identifier" },
        content: [],
      }),
    ];
    const records = [
      handoffRecord(publication, first, { identifier: "SYNTH-FIRST" }),
      handoffRecord(publication, conflicting, { identifier: "SYNTH-X" }),
      handoffRecord(publication, last, { identifier: "SYNTH-LAST" }),
    ];
    const receipts: PublishScanResult[] = [];
    const phases: string[] = [];
    let handoffFile = "";
    let persisted: string[] = [];

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeFile(
                join(dirname(handoffFile), "events.jsonl"),
                "Existing event log\n",
                { flag: "wx", mode: 0o600 },
              );
              await writeHandoff(input, records);
              return {
                exitCode: 0,
                stdout: outputs.join("\n"),
                stderr: "",
              };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              phases.push("history");
              persisted = issues.map((issue) => issue.issueIdentifier);
              return [...issues];
            },
            writeReceipt: async (receipt) => {
              phases.push(receipt.created.length === 0 ? "initial" : "final");
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow("could not verify every completed mutation");

    expect(phases).toEqual(["initial", "history", "final"]);
    expect(persisted).toEqual(["SYNTH-FIRST", "SYNTH-LAST"]);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [
        { findingId: first.findingId, issueIdentifier: "SYNTH-FIRST" },
        { findingId: last.findingId, issueIdentifier: "SYNTH-LAST" },
      ],
      failed: [
        {
          findingId: conflicting.findingId,
          error: expect.stringContaining("conflicting"),
        },
      ],
    });
    expect(await readFile(handoffFile, "utf8")).toBe(
      `${records.map((record) => JSON.stringify(record)).join("\n")}\n`,
    );
    expect(
      await readFile(await publicationEventsFile(handoffFile), "utf8"),
    ).toBe(`${outputs.join("\n")}\n`);
    expect(
      await readFile(join(dirname(handoffFile), "events.jsonl"), "utf8"),
    ).toBe("Existing event log\n");
  });

  test("creates deterministic concurrent batches of at most 20 and persists every settled batch", async () => {
    const publication = preparedPublication(41);
    let linearFindAccesses = 0;
    publication.issues = new Proxy(publication.issues, {
      get: (target, property, receiver) => {
        if (property === "find") linearFindAccesses += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    let batchSizes: number[] = [];
    let handoffFile: string | undefined;
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            expect(input).toContain("concurrently with Promise.allSettled");
            expect(input).toContain("Do not search, deduplicate");
            expect(input).toContain("invoke the track-findings skill");
            expect(input.toLowerCase()).not.toContain("sequential");
            const data = publicationData(input);
            batchSizes = data.batches.map((batch) => batch.length);
            handoffFile = data.handoffFile;
            const issues = new Map(
              publication.issues.map((issue) => [issue.findingId, issue]),
            );
            for (const batch of data.batches) {
              await writeHandoff(
                input,
                [...batch]
                  .reverse()
                  .map((entry) =>
                    handoffRecord(publication, issues.get(entry.findingId)!),
                  ),
              );
            }
            return { exitCode: 0, stdout: "", stderr: "" };
          },
        },
      ),
    );

    expect(batchSizes).toEqual([20, 20, 1]);
    expect(result.created.map((issue) => issue.findingId)).toEqual(
      publication.issues.map((issue) => issue.findingId),
    );
    expect(result.counts).toEqual({ findings: 41, created: 41, failed: 0 });
    expect(linearFindAccesses).toBe(0);
    expect(await readFile(handoffFile!, "utf8").catch(() => null)).toBeNull();
  });

  test("preserves valid handoffs while reporting failed, missing, and malformed finding records", async () => {
    const publication = preparedPublication(4);
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            await writeHandoff(input, [
              handoffRecord(publication, publication.issues[0]!),
              handoffRecord(publication, publication.issues[1]!, {
                error: "The connected project rejected this finding.",
              }),
              "{malformed-json",
              handoffRecord(publication, publication.issues[3]!),
            ]);
            return { exitCode: 0, stdout: "invalid", stderr: "" };
          },
        },
      ),
    );

    expect(result.created.map((issue) => issue.findingId)).toEqual([
      "finding-1",
      "finding-4",
    ]);
    expect(result.failed).toEqual([
      {
        findingId: "finding-2",
        error: "The connected project rejected this finding.",
      },
      {
        findingId: "finding-3",
        error: "Codex wrote an invalid Linear publication handoff.",
      },
    ]);
    expect(result.counts).toEqual({ findings: 4, created: 2, failed: 2 });
  });

  test("never discards valid created issues because of unrelated trailing handoff noise", async () => {
    const publication = preparedPublication(2);
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            await writeHandoff(input, [
              ...publication.issues.map((issue) =>
                handoffRecord(publication, issue),
              ),
              "{truncated-trailing-line",
              { findingId: "unrelated-finding" },
            ]);
            return { exitCode: 0, stdout: "", stderr: "" };
          },
        },
      ),
    );

    expect(result.created.map((issue) => issue.issueIdentifier)).toEqual([
      "SEC-1",
      "SEC-2",
    ]);
    expect(result.failed).toEqual([]);
  });

  test("retains an exact no-error handoff without a usable issue identifier", async () => {
    const publication = preparedPublication();
    const record = handoffRecord(publication, publication.issues[0]!, {
      identifier: "",
    });
    const receipts: PublishScanResult[] = [];
    let handoffFile = "";
    let publicationFile = "";
    let historyWrites = 0;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              ({ handoffFile, publicationFile } = publicationData(input));
              await writeHandoff(input, [record]);
              return { exitCode: 0, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              historyWrites += 1;
              return [...issues];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /could not verify every completed mutation.*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    expect(historyWrites).toBe(0);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [],
      failed: [
        {
          findingId: publication.issues[0]!.findingId,
          error: expect.stringContaining("valid created issue identifier"),
        },
      ],
      counts: { findings: 1, created: 0, failed: 1 },
    });
    expect(await readFile(handoffFile, "utf8")).toBe(
      `${JSON.stringify(record)}\n`,
    );
    expect(await readFile(publicationFile, "utf8")).toContain(
      publication.issues[0]!.findingId,
    );
  });

  test("prefers verified issue events over missing handoffs and model-authored failures", async () => {
    const publication = preparedPublication(3);
    let recovered: string | undefined;
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            const first = publication.issues[0]!;
            const second = publication.issues[1]!;
            const third = publication.issues[2]!;
            await writeHandoff(input, [
              handoffRecord(publication, first),
              handoffRecord(publication, third, {
                error: "The handoff explicitly rejected this finding.",
              }),
            ]);
            recovered = publicationData(input).handoffFile;
            return {
              exitCode: 0,
              stdout: [issueEvent(second), issueEvent(third)].join("\n"),
              stderr: "",
            };
          },
          recordPublishedIssues: async (_prepared, created) => {
            const records = (await readFile(recovered!, "utf8"))
              .trim()
              .split("\n")
              .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(records.map((record) => record["findingId"])).toEqual([
              "finding-1",
              "finding-3",
              "finding-2",
              "finding-3",
            ]);
            expect(records[2]!["issueIdentifier"]).toBe("SEC-2");
            expect(records[3]!["issueIdentifier"]).toBe("SEC-3");
            return [...created];
          },
        },
      ),
    );

    expect(result.created.map((issue) => issue.findingId)).toEqual([
      "finding-1",
      "finding-2",
      "finding-3",
    ]);
    expect(result.failed).toEqual([]);
    expect(result.counts).toEqual({ findings: 3, created: 3, failed: 0 });
  });

  test("retains verified issue mappings after model-authored failures if the publication database fails", async () => {
    const publication = preparedPublication(2);
    let handoffFile: string | undefined;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-RECOVERABLE",
                }),
                handoffRecord(publication, publication.issues[1]!, {
                  error: "The model could not write the created issue.",
                }),
              ]);
              return {
                exitCode: 0,
                stdout: issueEvent(publication.issues[1]!),
                stderr: "",
              };
            },
            recordPublishedIssues: async () => {
              throw new Error(
                "Synthetic local history token=diagnostic-only is unavailable.",
              );
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /Could not persist created Linear issues: Synthetic local history token=diagnostic-only is unavailable\..*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    const records = (await readFile(handoffFile!, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(
      records.map((record) => [record["findingId"], record["issueIdentifier"]]),
    ).toEqual([
      ["finding-1", "SEC-RECOVERABLE"],
      ["finding-2", undefined],
      ["finding-2", "SEC-2"],
    ]);
    expect(records[1]!["error"]).toBe(
      "The model could not write the created issue.",
    );
  });

  test("recovers validated partial mappings after cancellation before preserving its private handoff", async () => {
    const publication = preparedPublication(3);
    const controller = new AbortController();
    const updates: PublishScanProgress[] = [];
    let handoffFile: string | undefined;
    let publicationFile: string | undefined;
    let childStopped = false;
    let recorded: string[] = [];
    let receipt: unknown;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        {
          ...OPTIONS,
          signal: controller.signal,
          onProgress: (event) => updates.push(event),
        },
        dependencies(
          publication,
          {},
          {
            runCodex: async (
              _command,
              _args,
              input,
              _environment,
              onEvent,
              signal,
            ) => {
              expect(signal).toBe(controller.signal);
              ({ handoffFile, publicationFile } = publicationData(input));
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-WRITTEN",
                }),
                {
                  ...handoffRecord(publication, publication.issues[2]!, {
                    identifier: "SEC-UNVERIFIED",
                  }),
                  scanId: "another-scan",
                },
              ]);
              const observed = issueEvent(publication.issues[1]!, {
                identifier: "SEC-SALVAGED",
              });
              onEvent?.(JSON.parse(observed) as unknown);
              controller.abort("SIGINT");
              await Promise.resolve();
              childStopped = true;
              return {
                exitCode: 130,
                stdout: observed,
                stderr: "Publication was interrupted.",
              };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              expect(childStopped).toBe(true);
              recorded = issues.map((issue) => issue.issueIdentifier);
              return [...issues];
            },
            writeReceipt: async (result) => {
              expect(childStopped).toBe(true);
              receipt = result;
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /Linear publication was interrupted.*indeterminate.*publication handoff remains at .*; recover it before retrying to avoid creating duplicate issues\./u,
    );

    expect(recorded).toEqual(["SEC-WRITTEN", "SEC-SALVAGED"]);
    expect(receipt).toMatchObject({
      scanId: publication.scanId,
      created: [
        { findingId: "finding-1", issueIdentifier: "SEC-WRITTEN" },
        { findingId: "finding-2", issueIdentifier: "SEC-SALVAGED" },
      ],
      failed: [{ findingId: "finding-3" }],
      counts: { findings: 3, created: 2, failed: 1 },
    });
    expect(JSON.stringify(receipt)).not.toContain("SEC-UNVERIFIED");
    expect(updates.some((event) => event.type === "completed")).toBe(false);

    const recovery = (await readFile(handoffFile!, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(
      recovery.map((record) => [
        record["findingId"],
        record["issueIdentifier"],
      ]),
    ).toEqual([
      ["finding-1", "SEC-WRITTEN"],
      ["finding-3", "SEC-UNVERIFIED"],
      ["finding-2", "SEC-SALVAGED"],
    ]);
    expect(await readFile(publicationFile!, "utf8")).toContain("unsafe(input)");
    if (process.platform !== "win32") {
      expect((await stat(dirname(handoffFile!))).mode & 0o077).toBe(0);
      expect((await stat(handoffFile!)).mode & 0o077).toBe(0);
      expect((await stat(publicationFile!)).mode & 0o077).toBe(0);
    }
  });

  test("retains every verified recovery mapping when cancellation and database failure overlap", async () => {
    const publication = preparedPublication(2);
    const controller = new AbortController();
    let handoffFile: string | undefined;
    let receipt = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-WRITTEN",
                }),
              ]);
              controller.abort("SIGTERM");
              return {
                exitCode: 143,
                stdout: issueEvent(publication.issues[1]!, {
                  identifier: "SEC-SALVAGED",
                }),
                stderr: "",
              };
            },
            recordPublishedIssues: async () => {
              throw new Error("The publication database is unavailable.");
            },
            writeReceipt: async () => {
              receipt = true;
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /database is unavailable.*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    expect(receipt).toBe(false);
    const recovery = (await readFile(handoffFile!, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(
      recovery.map((record) => [
        record["findingId"],
        record["issueIdentifier"],
      ]),
    ).toEqual([
      ["finding-1", "SEC-WRITTEN"],
      ["finding-2", "SEC-SALVAGED"],
    ]);
  });

  test("preserves an ordinary local diagnostic when a cancellation receipt cannot be written", async () => {
    const publication = preparedPublication();
    const controller = new AbortController();
    const diagnostic = "Synthetic token cache unavailable";
    let handoffFile: string | undefined;
    let persisted = false;
    let failure: unknown;

    try {
      await publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-SAVED",
                }),
              ]);
              controller.abort("SIGINT");
              return { exitCode: 130, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = true;
              return [...issues];
            },
            writeReceipt: async () => {
              throw new Error(diagnostic);
            },
          },
        ),
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toMatch(
      /partial receipt could not be saved: Synthetic token cache unavailable\..*publication handoff remains at.*avoid creating duplicate issues/u,
    );
    expect(persisted).toBe(true);
    expect(await readFile(handoffFile!, "utf8")).toContain("SEC-SAVED");
  });

  test("retains rejected success-shaped handoffs for recovery", async () => {
    const scenarios: Array<{
      name: string;
      mutate: (record: Record<string, unknown>) => Record<string, unknown>[];
    }> = [
      {
        name: "another scan",
        mutate: (record) => [{ ...record, scanId: "another-scan" }],
      },
      {
        name: "another occurrence",
        mutate: (record) => [{ ...record, occurrenceId: "another-occurrence" }],
      },
      {
        name: "duplicate finding records",
        mutate: (record) => [record, record],
      },
      {
        name: "an unexpected finding",
        mutate: (record) => [{ ...record, findingId: "another-finding" }],
      },
      {
        name: "an invalid URL",
        mutate: (record) => [{ ...record, url: "" }],
      },
      {
        name: "conflicting identity aliases",
        mutate: (record) => [{ ...record, identifier: "" }],
      },
      {
        name: "conflicting nested identity",
        mutate: (record) => {
          const changed: Record<string, unknown> = {
            ...record,
            id: record["issueIdentifier"],
            issue: { identifier: "SEC-OTHER" },
          };
          delete changed["issueIdentifier"];
          delete changed["arguments"];
          return [changed];
        },
      },
      {
        name: "a nested success result",
        mutate: (record) => {
          const { issueIdentifier, ...rest } = record;
          return [{ ...rest, issue: { identifier: issueIdentifier } }];
        },
      },
      {
        name: "a structured success result",
        mutate: (record) => {
          const { issueIdentifier, ...rest } = record;
          return [
            {
              ...rest,
              structured_content: { issue: { identifier: issueIdentifier } },
            },
          ];
        },
      },
    ];

    for (const scenario of scenarios) {
      const publication = preparedPublication();
      let persisted = false;
      let handoffFile = "";
      let receipt: unknown;
      const operation = publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(
                input,
                scenario.mutate(
                  handoffRecord(publication, publication.issues[0]!),
                ),
              );
              return { exitCode: 0, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async (_prepared, created) => {
              persisted = true;
              return [...created];
            },
            writeReceipt: async (result) => {
              receipt = result;
            },
          },
        ),
      );

      await expect(operation).rejects.toThrow(
        "could not verify every completed mutation",
      );
      expect(receipt, scenario.name).toMatchObject({
        created: [],
        failed: [{ findingId: "finding-1" }],
        counts: { findings: 1, created: 0, failed: 1 },
      });
      expect(await readFile(handoffFile, "utf8"), scenario.name).toContain(
        "SEC-1",
      );
      expect(persisted, scenario.name).toBe(false);
    }
  });

  test("retains duplicate identifier-less success-shaped handoffs as indeterminate evidence", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    const base = handoffRecord(publication, issue);
    delete base["issueIdentifier"];
    const records = [
      { ...base, structured_content: { status: "created" } },
      { ...base, content: [{ type: "text", text: '{"status":"created"}' }] },
    ];
    const receipts: PublishScanResult[] = [];
    let handoffFile = "";
    let historyWrites = 0;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, records);
              return { exitCode: 0, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              historyWrites += 1;
              return [...issues];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /could not verify every completed mutation.*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    expect(historyWrites).toBe(0);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [],
      failed: [
        {
          findingId: issue.findingId,
          error: expect.stringContaining("more than one"),
        },
      ],
      counts: { findings: 1, created: 0, failed: 1 },
    });
    expect(await readFile(handoffFile, "utf8")).toBe(
      `${records.map((record) => JSON.stringify(record)).join("\n")}\n`,
    );
  });

  test("retains distinct duplicate Linear issue IDs for indeterminate recovery", async () => {
    const publication = preparedPublication(2);
    const issue = publication.issues[0]!;
    const first = issueEvent(issue, { identifier: "SYNTH-DUPLICATE-A" });
    const unverified = JSON.parse(
      issueEvent(issue, { identifier: "SYNTH-DUPLICATE-B" }),
    );
    unverified.item.arguments.title = "Changed title";
    const output = [
      first,
      JSON.stringify(unverified),
      issueEvent(publication.issues[1]!),
    ].join("\n");
    let handoffFile: string | undefined;
    let persisted: string[] = [];
    let receipt: unknown;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [
                handoffRecord(publication, issue, {
                  identifier: "SYNTH-DUPLICATE-A",
                }),
                handoffRecord(publication, issue, {
                  identifier: "SYNTH-DUPLICATE-B",
                }),
                handoffRecord(publication, publication.issues[1]!),
              ]);
              return {
                exitCode: 0,
                stdout: output,
                stderr: "",
              };
            },
            recordPublishedIssues: async (_prepared, created) => {
              persisted = created.map((issue) => issue.issueIdentifier);
              return [...created];
            },
            writeReceipt: async (result) => {
              receipt = result;
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /could not verify every completed mutation.*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    expect(persisted).toEqual(["SEC-2"]);
    expect(receipt).toMatchObject({
      counts: { findings: 2, created: 1, failed: 1 },
      failed: [
        {
          findingId: "finding-1",
          error: expect.stringContaining("more than one"),
        },
      ],
    });
    const records = (await readFile(handoffFile!, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(records.map((record) => record["issueIdentifier"])).toEqual([
      "SYNTH-DUPLICATE-A",
      "SYNTH-DUPLICATE-B",
      "SEC-2",
    ]);
    expect(
      await readFile(await publicationEventsFile(handoffFile!), "utf8"),
    ).toBe(`${output}\n`);
  });

  test("does not let an absent first completion hide a later duplicate", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    const absent = issueEventWithResult(issue, {
      structured_content: { title: "No identifier" },
      content: [],
    });
    const resolved = issueEvent(issue, { identifier: "SYNTH-DUPLICATE" });
    const output = `${absent}\n${resolved}`;
    const record = handoffRecord(publication, issue, {
      identifier: "SYNTH-DUPLICATE",
    });
    const receipts: PublishScanResult[] = [];
    const updates: PublishScanProgress[] = [];
    let handoffFile = "";
    let historyWrites = 0;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, onProgress: (update) => updates.push(update) },
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [record]);
              return { exitCode: 0, stdout: output, stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              historyWrites += 1;
              return [...issues];
            },
            writeReceipt: async (receipt) => {
              receipts.push(structuredClone(receipt));
            },
          },
        ),
      ),
    ).rejects.toThrow("could not verify every completed mutation");

    expect(historyWrites).toBe(0);
    expect(receipts).toHaveLength(2);
    expect(receipts.at(-1)).toMatchObject({
      indeterminate: true,
      created: [],
      failed: [
        {
          findingId: issue.findingId,
          error: expect.stringContaining("more than one"),
        },
      ],
      counts: { findings: 1, created: 0, failed: 1 },
    });
    expect(await readFile(handoffFile, "utf8")).toBe(
      `${JSON.stringify(record)}\n`,
    );
    expect(
      await readFile(await publicationEventsFile(handoffFile), "utf8"),
    ).toBe(`${output}\n`);
    expect(updates.some((update) => update.type === "completed")).toBe(false);
  });

  test("recovers incomplete handoff arguments from an exact observed mutation", async () => {
    const publication = preparedPublication(2);
    let handoffFile: string | undefined;
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            handoffFile = publicationData(input).handoffFile;
            const records = publication.issues.map((issue) => {
              const record = handoffRecord(publication, issue);
              delete record["arguments"];
              return record;
            });
            await writeHandoff(input, records);
            return {
              exitCode: 0,
              stdout: publication.issues
                .map((issue) => issueEvent(issue))
                .join("\n"),
              stderr: "",
            };
          },
          recordPublishedIssues: async (_prepared, issues) => {
            const records = (await readFile(handoffFile!, "utf8"))
              .trim()
              .split("\n")
              .map((line) => JSON.parse(line));
            expect(records.slice(2)).toEqual(
              publication.issues.map((issue) => ({
                ...handoffRecord(publication, issue),
                url: `https://linear.app/example/issue/SEC-${issue.findingId.slice(8)}`,
              })),
            );
            return [...issues];
          },
        },
      ),
    );

    expect(result.counts).toEqual({ findings: 2, created: 2, failed: 0 });
  });

  test("keeps recovery-write failures from blocking verified history persistence", async () => {
    const publication = preparedPublication(2);
    const changed = JSON.parse(issueEvent(publication.issues[1]!));
    changed.item.arguments.team = "different-team";
    const phases: string[] = [];
    let receipt: PublishScanResult | undefined;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {
            stdout: [
              issueEvent(publication.issues[0]!),
              JSON.stringify(changed),
            ].join("\n"),
          },
          {
            recordPublishedIssues: async (_prepared, issues) => {
              phases.push("history");
              return [...issues];
            },
            writeEvents: async () => {
              phases.push("events");
              throw new Error("Synthetic event writer unavailable.");
            },
            writeReceipt: async (result) => {
              phases.push(result.created.length === 0 ? "initial" : "final");
              receipt = structuredClone(result);
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /could not verify every completed mutation.*Could not preserve Linear connector-event evidence/u,
    );

    expect(phases).toEqual(["events", "initial", "history", "final"]);
    expect(receipt).toMatchObject({
      indeterminate: true,
      created: [{ findingId: "finding-1", issueIdentifier: "SEC-1" }],
      counts: { findings: 2, created: 1, failed: 1 },
      warnings: expect.arrayContaining([
        expect.stringContaining("Synthetic event writer unavailable"),
      ]),
    });
  });

  test("rejects handoffs contradicted by observed trusted Linear mutations", async () => {
    const scenarios: Array<{
      name: string;
      events: (publication: PreparedScanPublication) => string[];
    }> = [
      {
        name: "different created issue",
        events: (publication) => [
          issueEvent(publication.issues[0]!, { identifier: "SEC-OTHER" }),
        ],
      },
      {
        name: "failed connector call",
        events: (publication) => [
          issueEvent(publication.issues[0]!, {
            status: "failed",
            error: "The connected Linear project denied this request.",
          }),
        ],
      },
      {
        name: "duplicate connector calls",
        events: (publication) => [
          issueEvent(publication.issues[0]!),
          issueEvent(publication.issues[0]!),
        ],
      },
      {
        name: "failed retry after an absent completion",
        events: (publication) => [
          issueEventWithResult(publication.issues[0]!, {
            structured_content: { title: "No identifier" },
          }),
          issueEvent(publication.issues[0]!, {
            status: "failed",
            error: "The connected Linear project denied the retry.",
          }),
        ],
      },
    ];

    for (const scenario of scenarios) {
      const publication = preparedPublication();
      let receipt: unknown;
      const operation = publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!),
              ]);
              return {
                exitCode: 0,
                stdout: scenario.events(publication).join("\n"),
                stderr: "",
              };
            },
            writeReceipt: async (result) => {
              receipt = result;
            },
          },
        ),
      );

      await expect(operation).rejects.toThrow(
        "could not verify every completed mutation",
      );
      expect(receipt, scenario.name).toMatchObject({
        created: [],
        failed: [{ findingId: "finding-1" }],
      });
    }
  });

  test("does not create source-bearing handoffs when the Codex command cannot be resolved", async () => {
    const publication = preparedPublication();
    const injected = dependencies(
      publication,
      {},
      {
        resolveCodex: () => {
          throw new Error("The Codex executable could not be resolved.");
        },
        runCodex: undefined,
      },
    );

    await expect(
      publishScanInternal(publication.scanDirectory, OPTIONS, injected),
    ).rejects.toThrow("The Codex executable could not be resolved.");

    const handoffRoot = join(
      injected.environment!["CODEX_SECURITY_STATE_DIR"]!,
      "publications",
      "linear",
      "handoffs",
    );
    expect(
      await stat(handoffRoot).then(
        () => false,
        (error: NodeJS.ErrnoException) => error.code === "ENOENT",
      ),
    ).toBe(true);
  });

  test("removes source-bearing handoffs when the Codex executable cannot be spawned", async () => {
    const publication = preparedPublication();
    let persisted = false;
    const missingExecutable = join(
      tmpdir(),
      `codex-security-missing-executable-${randomUUID()}`,
    );
    const injected = dependencies(
      publication,
      {},
      {
        resolveCodex: () => ({ command: missingExecutable }),
        runCodex: undefined,
        recordPublishedIssues: async (_publication, issues) => {
          persisted = true;
          return [...issues];
        },
      },
    );

    await expect(
      publishScanInternal(publication.scanDirectory, OPTIONS, injected),
    ).rejects.toThrow("Could not start Codex for Linear publication.");

    const handoffRoot = join(
      injected.environment!["CODEX_SECURITY_STATE_DIR"]!,
      "publications",
      "linear",
      "handoffs",
    );
    expect(await readdir(handoffRoot)).toEqual([]);
    expect(persisted).toBe(false);
  });

  test("retains handoffs when an injected publisher rejects after a possible mutation", async () => {
    const publication = preparedPublication();
    let handoffFile: string | undefined;
    const injected = dependencies(
      publication,
      {},
      {
        runCodex: async (_command, _args, input) => {
          handoffFile = publicationData(input).handoffFile;
          await writeHandoff(input, [
            handoffRecord(publication, publication.issues[0]!, {
              identifier: "SEC-RECOVERABLE",
            }),
          ]);
          throw new Error("The publisher failed after a possible mutation.");
        },
      },
    );

    await expect(
      publishScanInternal(publication.scanDirectory, OPTIONS, injected),
    ).rejects.toThrow("The publisher failed after a possible mutation.");

    expect(await readFile(handoffFile!, "utf8")).toContain("SEC-RECOVERABLE");
    expect(
      await readFile(join(dirname(handoffFile!), "publication.json"), "utf8"),
    ).toContain("unsafe(input)");
  });

  test("verifies the existing publication database before starting Codex or creating issues", async () => {
    const publication = preparedPublication();
    let resolved = false;
    let started = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            preparePublicationStore: async () => {
              throw new Error(
                "The local scan history does not contain this finding.",
              );
            },
            resolveCodex: () => {
              resolved = true;
              return { command: "must-not-run" };
            },
            runCodex: async () => {
              started = true;
              return { exitCode: 0, stdout: "", stderr: "" };
            },
          },
        ),
      ),
    ).rejects.toThrow("local scan history does not contain this finding");

    expect(resolved).toBe(false);
    expect(started).toBe(false);
  });

  test("previews every finding without starting Codex or writing a receipt", async () => {
    const publication = preparedPublication(2);
    const result = await publishScanInternal(
      publication.scanDirectory,
      { ...OPTIONS, dryRun: true },
      dependencies(
        publication,
        {},
        {
          resolveCodex: () => {
            throw new Error("dry runs must not resolve Codex");
          },
          runCodex: async () => {
            throw new Error("dry runs must not start Codex");
          },
          writeReceipt: async () => {
            throw new Error("dry runs must not write receipts");
          },
        },
      ),
    );

    expect(result).toEqual({
      scanId: "scan-example",
      uploadId: "scan-example",
      destination: publication.destination,
      created: [],
      failed: [],
      counts: { findings: 2, created: 0, failed: 0 },
      dryRun: true,
      issues: publication.issues,
    });
  });

  test("rejects an already-aborted publication before preparing or starting Codex", async () => {
    const publication = preparedPublication();
    const controller = new AbortController();
    const reason = new Error("Publication was canceled before startup.");
    controller.abort(reason);
    let prepared = false;
    let started = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            prepare: async () => {
              prepared = true;
              return publication;
            },
            runCodex: async () => {
              started = true;
              return { exitCode: 0, stdout: "", stderr: "" };
            },
          },
        ),
      ),
    ).rejects.toBe(reason);
    expect(prepared).toBe(false);
    expect(started).toBe(false);
  });

  test("forwards cancellation and saves verified issues before reporting interruption", async () => {
    const publication = preparedPublication(2);
    const controller = new AbortController();
    const reason = new Error("Publication was interrupted.");
    let saved: PublicationCodexResult | undefined;
    let savedIssueIdentifiers: string[] | undefined;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            runCodex: async (
              _command,
              _args,
              _input,
              _environment,
              _onEvent,
              signal,
            ) => {
              expect(signal).toBe(controller.signal);
              controller.abort(reason);
              saved = {
                exitCode: 1,
                stdout: issueEvent(publication.issues[0]!),
                stderr: "",
              };
              return saved;
            },
            writeReceipt: async (receipt) => {
              savedIssueIdentifiers = receipt.created.map(
                (issue) => issue.issueIdentifier,
              );
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /Linear publication was interrupted\. The publication handoff remains at .*; recover it before retrying to avoid creating duplicate issues\./u,
    );

    expect(saved?.exitCode).toBe(1);
    expect(savedIssueIdentifiers).toEqual(["SEC-1"]);
  });

  test.each([
    ["a promptly exiting parent", false, "SIGTERM"],
    ["a parent that ignores termination", true, "SIGTERM"],
    ["a Ctrl-C-interrupted parent", false, "SIGINT"],
  ] as const)(
    "cancellation stops %s and its signal-resistant Codex descendants",
    async (_description, ignoreTermination, terminationSignal) => {
      const directory = await mkdtemp(
        join(tmpdir(), "codex-security-publication-cancel-"),
      );
      temporaryDirectories.push(directory);
      const publication = preparedPublication(2);
      const parentPath = join(directory, "parent.pid");
      const descendantPath = join(directory, "descendant.pid");
      const preload = join(directory, "codex-preload.cjs");
      await writeFile(
        preload,
        [
          'const fs = require("node:fs");',
          'const { spawn } = require("node:child_process");',
          'fs.readFileSync(0, "utf8");',
          "fs.writeFileSync(process.env.CODEX_PUBLICATION_PARENT_PID, String(process.pid));",
          "const environment = { ...process.env };",
          "delete environment.NODE_OPTIONS;",
          "const descendant = [",
          '  "const fs = require(\\"node:fs\\");",',
          '  "process.on(\\"SIGTERM\\", () => {});",',
          '  "process.on(\\"SIGINT\\", () => {});",',
          '  "fs.writeFileSync(process.env.CODEX_PUBLICATION_DESCENDANT_PID, String(process.pid));",',
          '  "setInterval(() => {}, 1000);",',
          '].join("");',
          'spawn(process.execPath, ["-e", descendant], { env: environment, stdio: "ignore" });',
          "const waiter = new Int32Array(new SharedArrayBuffer(4));",
          "for (let attempts = 0; !fs.existsSync(process.env.CODEX_PUBLICATION_DESCENDANT_PID); attempts += 1) {",
          "  if (attempts === 1000) process.exit(3);",
          "  Atomics.wait(waiter, 0, 0, 10);",
          "}",
          'if (process.env.CODEX_PUBLICATION_IGNORE_TERMINATION === "1") {',
          '  process.on("SIGTERM", () => {});',
          "}",
          "fs.writeSync(1, `${process.env.CODEX_PUBLICATION_EVENT}\\n`);",
          "for (;;) Atomics.wait(waiter, 0, 0, 1000);",
        ].join("\n"),
        "utf8",
      );
      const controller = new AbortController();
      const reason =
        terminationSignal === "SIGINT"
          ? "SIGINT"
          : new Error("Publication was interrupted.");
      const injected = dependencies(
        publication,
        {},
        {
          environment: {
            ...process.env,
            CODEX_SECURITY_STATE_DIR: join(directory, "state"),
            NODE_OPTIONS: `--require=${JSON.stringify(preload)}`,
            CODEX_PUBLICATION_PARENT_PID: parentPath,
            CODEX_PUBLICATION_DESCENDANT_PID: descendantPath,
            CODEX_PUBLICATION_IGNORE_TERMINATION: ignoreTermination ? "1" : "0",
            CODEX_PUBLICATION_EVENT: issueEvent(publication.issues[0]!),
          },
          resolveCodex: () => ({
            command: execFileSync("node", ["-p", "process.execPath"], {
              encoding: "utf8",
            }).trim(),
          }),
        },
      );
      delete injected.runCodex;
      delete injected.writeReceipt;

      await expect(
        publishScanInternal(
          publication.scanDirectory,
          {
            ...OPTIONS,
            signal: controller.signal,
            onProgress: (event) => {
              if (event.type === "codex_event") controller.abort(reason);
            },
          },
          injected,
        ),
      ).rejects.toThrow(
        /Linear publication was interrupted\. The publication handoff remains at .*; recover it before retrying to avoid creating duplicate issues\./u,
      );

      const parent = Number(await readFile(parentPath, "utf8"));
      const descendant = Number(await readFile(descendantPath, "utf8"));
      expect(await processHasExited(parent)).toBe(true);
      expect(await processHasExited(descendant)).toBe(true);
      const receipt = join(
        directory,
        "state",
        "publications",
        "linear",
        `${createHash("sha256").update(publication.scanId).digest("hex")}.json`,
      );
      const persisted = JSON.parse(await readFile(receipt, "utf8")) as {
        created: Array<{ issueIdentifier: string }>;
        counts: { findings: number; created: number; failed: number };
      };
      expect(persisted.created.map((issue) => issue.issueIdentifier)).toEqual([
        "SEC-1",
      ]);
      expect(persisted.counts).toEqual({ findings: 2, created: 1, failed: 1 });
    },
    30_000,
  );

  test("streams dotted Linear events, ordered progress, and a partial-publication receipt", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "codex-security-publication-stream-"),
    );
    temporaryDirectories.push(directory);
    const publication = preparedPublication(3);
    const preload = join(directory, "codex-preload.cjs");
    await writeFile(
      preload,
      [
        'const fs = require("node:fs");',
        'const prompt = fs.readFileSync(0, "utf8");',
        'if (!prompt.includes("BEGIN UNTRUSTED PUBLICATION DATA")) process.exit(2);',
        "const lines = JSON.parse(process.env.CODEX_PUBLICATION_TEST_EVENTS);",
        'fs.writeSync(1, "not-json\\n");',
        "const first = JSON.stringify(lines[0]);",
        "const boundary = Math.floor(first.length / 2);",
        "fs.writeSync(1, first.slice(0, boundary));",
        "fs.writeSync(1, `${first.slice(boundary)}\\r\\n`);",
        "fs.writeSync(1, `${JSON.stringify(lines[1])}\\n`);",
        "fs.writeSync(1, `${JSON.stringify(lines[2])}\\n`);",
        "fs.writeSync(1, JSON.stringify(lines[3]));",
        "process.exit(0);",
      ].join("\n"),
      "utf8",
    );
    const reasoning = {
      type: "item.completed",
      item: { type: "reasoning", text: "Creating the requested issue." },
    };
    const issues = publication.issues.slice(0, 2).map((finding, index) => {
      const issue = JSON.parse(issueEvent(finding)) as {
        item: {
          tool: string;
          result: {
            content: unknown[];
            structured_content: { id: string; url: string };
          };
        };
      };
      const identifier = `SEC-${index + 901}`;
      issue.item.tool = "linear.save_issue";
      issue.item.result = {
        content: [],
        structured_content: {
          id: identifier,
          url: `https://linear.app/example/issue/${identifier}`,
        },
      };
      return issue;
    });
    const failure = JSON.parse(
      issueEvent(publication.issues[2]!, {
        status: "failed",
        error: "The connected Linear project rejected this finding.",
      }),
    ) as { item: { tool: string } };
    failure.item.tool = "linear.save_issue";
    const updates: PublishScanProgress[] = [];
    const injected = dependencies(
      publication,
      {},
      {
        environment: {
          ...process.env,
          CODEX_SECURITY_STATE_DIR: join(directory, "state"),
          NODE_OPTIONS: `--require=${JSON.stringify(preload)}`,
          CODEX_PUBLICATION_TEST_EVENTS: JSON.stringify([
            reasoning,
            ...issues,
            failure,
          ]),
        },
        resolveCodex: () => ({
          command: execFileSync("node", ["-p", "process.execPath"], {
            encoding: "utf8",
          }).trim(),
        }),
      },
    );
    delete injected.runCodex;
    delete injected.writeReceipt;

    const result = await publishScanInternal(
      publication.scanDirectory,
      { ...OPTIONS, onProgress: (event) => updates.push(event) },
      injected,
    );

    expect(result.created).toEqual([
      {
        findingId: "finding-1",
        occurrenceId: "occurrence-1",
        issueIdentifier: "SEC-901",
        url: "https://linear.app/example/issue/SEC-901",
      },
      {
        findingId: "finding-2",
        occurrenceId: "occurrence-2",
        issueIdentifier: "SEC-902",
        url: "https://linear.app/example/issue/SEC-902",
      },
    ]);
    expect(result.failed).toEqual([
      {
        findingId: "finding-3",
        error: "The connected Linear project rejected this finding.",
      },
    ]);
    expect(result.counts).toEqual({ findings: 3, created: 2, failed: 1 });
    expect(updates).toEqual([
      { type: "started", scanId: "scan-example", total: 3 },
      { type: "codex_event", event: reasoning },
      { type: "codex_event", event: issues[0] },
      { type: "codex_event", event: issues[1] },
      { type: "codex_event", event: failure },
      {
        type: "issue_completed",
        findingId: "finding-1",
        issueIdentifier: "SEC-901",
        completed: 1,
        total: 3,
      },
      {
        type: "issue_completed",
        findingId: "finding-2",
        issueIdentifier: "SEC-902",
        completed: 2,
        total: 3,
      },
      {
        type: "issue_completed",
        findingId: "finding-3",
        error: "The connected Linear project rejected this finding.",
        completed: 3,
        total: 3,
      },
      { type: "completed", created: 2, failed: 1, total: 3 },
    ]);
    const receipt = join(
      directory,
      "state",
      "publications",
      "linear",
      `${createHash("sha256").update(publication.scanId).digest("hex")}.json`,
    );
    expect(JSON.parse(await readFile(receipt, "utf8"))).toEqual(result);
  });

  test("never reports an issue for unknown finding IDs or repeated tool events", async () => {
    const publication = preparedPublication();
    const updates: PublishScanProgress[] = [];
    const unexpected = JSON.parse(issueEvent(publication.issues[0]!)) as Record<
      string,
      unknown
    >;
    const item = unexpected["item"] as Record<string, unknown>;
    const args = item["arguments"] as Record<string, unknown>;
    args["description"] = "**Finding ID:** unknown\n**Occurrence ID:** unknown";
    const valid = JSON.parse(issueEvent(publication.issues[0]!)) as unknown;

    await publishScanInternal(
      publication.scanDirectory,
      { ...OPTIONS, onProgress: (event) => updates.push(event) },
      dependencies(
        publication,
        {},
        {
          runCodex: async (_codex, _args, _input, _environment, onEvent) => {
            onEvent!(unexpected);
            expect(updates.at(-1)).toEqual({
              type: "codex_event",
              event: unexpected,
            });
            onEvent!(valid);
            onEvent!(valid);
            return {
              exitCode: 0,
              stdout: JSON.stringify(valid),
              stderr: "",
            };
          },
        },
      ),
    );

    expect(updates.filter((event) => event.type === "issue_completed")).toEqual(
      [
        {
          type: "issue_completed",
          findingId: "finding-1",
          issueIdentifier: "SEC-1",
          completed: 1,
          total: 1,
        },
      ],
    );
  });

  test("reports final failures when the evidence ledger invalidates streamed successes", async () => {
    const publication = preparedPublication(2);
    const sharedUrl = "https://linear.app/example/issue/SYNTH-SHARED";
    const rawEvents = publication.issues.map((issue, index) =>
      issueEvent(issue, {
        identifier: `SYNTH-STREAM-${index + 1}`,
        url: sharedUrl,
      }),
    );
    const events = rawEvents.map((event) => JSON.parse(event) as unknown);
    const updates: PublishScanProgress[] = [];

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, onProgress: (event) => updates.push(event) },
        dependencies(
          publication,
          {},
          {
            runCodex: async (
              _command,
              _args,
              _input,
              _environment,
              onEvent,
            ) => {
              for (const event of events) onEvent!(event);
              return {
                exitCode: 0,
                stdout: rawEvents.join("\n"),
                stderr: "",
              };
            },
          },
        ),
      ),
    ).rejects.toThrow(/could not verify every completed mutation/u);

    expect(
      updates
        .filter((event) => event.type === "codex_event")
        .map((event) => event.event),
    ).toEqual(events);
    expect(updates.filter((event) => event.type === "issue_completed")).toEqual(
      publication.issues.map((issue, index) => ({
        type: "issue_completed",
        findingId: issue.findingId,
        error: CLAIM_COLLISION_ERROR,
        completed: index + 1,
        total: 2,
      })),
    );
  });

  test("does not allow a failing progress observer to stop issue publication", async () => {
    const publication = preparedPublication();
    let observations = 0;
    const result = await publishScanInternal(
      publication.scanDirectory,
      {
        ...OPTIONS,
        onProgress: () => {
          observations += 1;
          throw new Error("The optional progress display failed.");
        },
      },
      dependencies(
        publication,
        {},
        {
          runCodex: async (_codex, _args, _input, _environment, onEvent) => {
            const event = JSON.parse(
              issueEvent(publication.issues[0]!),
            ) as unknown;
            onEvent!(event);
            return {
              exitCode: 0,
              stdout: JSON.stringify(event),
              stderr: "",
            };
          },
        },
      ),
    );

    expect(result.counts).toEqual({ findings: 1, created: 1, failed: 0 });
    expect(observations).toBe(4);
  });

  test("does not start Codex or write a receipt when the scan has no findings", async () => {
    const publication = preparedPublication(0);
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          resolveCodex: () => {
            throw new Error("empty scans must not resolve Codex");
          },
          writeReceipt: async () => {
            throw new Error("empty scans must not write receipts");
          },
        },
      ),
    );

    expect(result.counts).toEqual({ findings: 0, created: 0, failed: 0 });
  });

  test("returns persisted successes and partial failures when an optional receipt cannot be saved", async () => {
    for (const partialFailure of [false, true]) {
      const publication = preparedPublication(2);
      const progress: PublishScanProgress[] = [];
      let invocations = 0;
      let persisted: string[] = [];
      let handoffFile: string | undefined;

      const result = await publishScanInternal(
        publication.scanDirectory,
        {
          ...OPTIONS,
          onProgress: (event) => progress.push(event),
        },
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              invocations += 1;
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-PERSISTED",
                }),
                handoffRecord(
                  publication,
                  publication.issues[1]!,
                  partialFailure
                    ? { error: "The destination rejected this finding." }
                    : { identifier: "SEC-ALSO-PERSISTED" },
                ),
              ]);
              return {
                exitCode: 0,
                stdout: "not trusted agent prose",
                stderr: "",
              };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = issues.map((issue) => issue.issueIdentifier);
              return [...issues];
            },
            writeReceipt: async () => {
              throw new Error(
                "OPENAI_API_KEY=sk-proj-SYNTHETIC_RECEIPT_SECRET_123",
              );
            },
          },
        ),
      );

      const expectedCreated = partialFailure
        ? ["SEC-PERSISTED"]
        : ["SEC-PERSISTED", "SEC-ALSO-PERSISTED"];
      expect(invocations).toBe(1);
      expect(persisted).toEqual(expectedCreated);
      expect(result.created.map((issue) => issue.issueIdentifier)).toEqual(
        expectedCreated,
      );
      expect(result.failed).toEqual(
        partialFailure
          ? [
              {
                findingId: "finding-2",
                error: "The destination rejected this finding.",
              },
            ]
          : [],
      );
      expect(result.counts).toEqual({
        findings: 2,
        created: expectedCreated.length,
        failed: partialFailure ? 1 : 0,
      });
      expect(result.warnings).toEqual([
        "Could not save the publication receipt: [redacted]. Linear issues were already created; do not retry publication.",
      ]);
      expect(JSON.stringify(result)).not.toContain("SYNTHETIC_RECEIPT_SECRET");
      expect(progress.at(-1)).toEqual({
        type: "completed",
        created: expectedCreated.length,
        failed: partialFailure ? 1 : 0,
        total: 2,
      });
      expect(
        await stat(handoffFile!).then(
          () => false,
          (error: NodeJS.ErrnoException) => error.code === "ENOENT",
        ),
      ).toBe(true);
    }
  });

  test("keeps receipt failures fatal when no Linear issues were created", async () => {
    const publication = preparedPublication();
    let persisted = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          { stdout: "" },
          {
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = true;
              return [...issues];
            },
            writeReceipt: async () => {
              throw new Error("The receipt disk is unavailable.");
            },
          },
        ),
      ),
    ).rejects.toThrow("The receipt disk is unavailable.");

    expect(persisted).toBe(false);
  });

  test("preserves successful issues when another creation fails", async () => {
    const publication = preparedPublication(3);
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(publication, {
        stdout: [
          issueEvent(publication.issues[0]!),
          issueEvent(publication.issues[1]!, {
            status: "failed",
            error: "The destination rejected this issue.",
          }),
        ].join("\n"),
      }),
    );

    expect(result.created).toHaveLength(1);
    expect(result.failed).toEqual([
      {
        findingId: "finding-2",
        error: "The destination rejected this issue.",
      },
      {
        findingId: "finding-3",
        error: "Codex did not create a Linear issue for this finding.",
      },
    ]);
    expect(result.counts).toEqual({ findings: 3, created: 1, failed: 2 });
  });

  test("reports Codex and connected-app failures without invented issue creation", async () => {
    const publication = preparedPublication();
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(publication, {
        exitCode: 1,
        stdout: "",
        stderr: "Linear is not connected.",
      }),
    );

    expect(result.created).toEqual([]);
    expect(result.failed).toEqual([
      {
        findingId: "finding-1",
        error:
          "Codex could not publish through the connected Linear app: Linear is not connected.",
      },
    ]);
  });

  test("creates a fresh issue on every publication without deduplicating", async () => {
    const publication = preparedPublication();
    let calls = 0;
    const injected = dependencies(
      publication,
      {},
      {
        runCodex: async () => {
          calls += 1;
          return {
            exitCode: 0,
            stdout: issueEvent(publication.issues[0]!, {
              identifier: `SEC-${calls}`,
            }),
            stderr: "",
          };
        },
      },
    );

    const first = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      injected,
    );
    const second = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      injected,
    );

    expect(calls).toBe(2);
    expect(first.uploadId).toBe(second.uploadId);
    expect(first.created[0]!.issueIdentifier).toBe("SEC-1");
    expect(second.created[0]!.issueIdentifier).toBe("SEC-2");
  });

  test("preserves both private receipts when the same scan is published concurrently", async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), "codex-security-concurrent-publication-receipts-"),
    );
    temporaryDirectories.push(stateDirectory);
    const publication = preparedPublication();
    let calls = 0;
    const injected = dependencies(
      publication,
      {},
      {
        environment: { CODEX_SECURITY_STATE_DIR: stateDirectory },
        runCodex: async () => {
          calls += 1;
          return {
            exitCode: 0,
            stdout: issueEvent(publication.issues[0]!, {
              identifier: `SEC-CONCURRENT-${calls}`,
            }),
            stderr: "",
          };
        },
      },
    );
    delete injected.writeReceipt;

    const results = await Promise.all([
      publishScanInternal(publication.scanDirectory, OPTIONS, injected),
      publishScanInternal(publication.scanDirectory, OPTIONS, injected),
    ]);
    const directory = join(stateDirectory, "publications", "linear");
    const digest = createHash("sha256")
      .update(publication.scanId)
      .digest("hex");
    const attempts = (await readdir(directory)).filter(
      (name) => name.startsWith(`${digest}-`) && name.endsWith(".json"),
    );

    expect(attempts).toHaveLength(2);
    const receipts = await Promise.all(
      attempts.map(async (name) => {
        const path = join(directory, name);
        if (process.platform !== "win32") {
          expect((await stat(path)).mode & 0o077).toBe(0);
        }
        return JSON.parse(await readFile(path, "utf8")) as {
          created: Array<{ issueIdentifier: string }>;
        };
      }),
    );
    expect(
      receipts
        .flatMap((receipt) =>
          receipt.created.map((issue) => issue.issueIdentifier),
        )
        .sort(),
    ).toEqual(["SEC-CONCURRENT-1", "SEC-CONCURRENT-2"]);
    const latest = JSON.parse(
      await readFile(join(directory, `${digest}.json`), "utf8"),
    ) as (typeof results)[number];
    expect(results).toContainEqual(latest);
    expect(
      results.map((result) => result.created[0]!.issueIdentifier).sort(),
    ).toEqual(["SEC-CONCURRENT-1", "SEC-CONCURRENT-2"]);
  });

  test("keeps publication receipts outside sealed scans and hashes unsafe scan IDs", async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), "codex-security-publication-receipt-"),
    );
    temporaryDirectories.push(stateDirectory);
    const publication = preparedPublication(1, "../../outside/scan");
    const injected = dependencies(
      publication,
      {},
      {
        environment: { CODEX_SECURITY_STATE_DIR: stateDirectory },
      },
    );
    delete injected.writeReceipt;

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      injected,
    );
    const digest = createHash("sha256")
      .update("../../outside/scan")
      .digest("hex");
    const receipt = join(
      stateDirectory,
      "publications",
      "linear",
      `${digest}.json`,
    );

    expect(JSON.parse(await readFile(receipt, "utf8"))).toEqual(result);
  });

  test("requires an exact team and rejects a blank supplied project before reading a scan", async () => {
    const publication = preparedPublication();
    for (const options of [
      { ...OPTIONS, destination: "azure" } as unknown as PublishScanOptions,
      { ...OPTIONS, teamId: "  " },
      { ...OPTIONS, projectId: "  " },
    ]) {
      await expect(
        publishScanInternal(
          publication.scanDirectory,
          options,
          dependencies(
            publication,
            {},
            {
              prepare: async () => {
                throw new Error("invalid destinations must not load scans");
              },
            },
          ),
        ),
      ).rejects.toThrow();
    }
  });
});
