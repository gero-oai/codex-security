import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Finding, JsonObject, SeverityLevel } from "../src/index.js";
import { main } from "../src/cli.js";
import {
  capture,
  dependencies as fixtureDependencies,
  FakeSignals,
  fakeResult,
} from "./cli-fixtures.js";

const CURRENT_REPOSITORY = resolve("/current/repository");
const SAVED_REPOSITORY = resolve("/saved/repository");
const STATE_DIRECTORY = resolve("/tmp/codex-security-state");

type FixtureOptions = Exclude<
  Parameters<typeof fixtureDependencies>[0],
  undefined
>;

function dependencies(
  options: FixtureOptions & {
    onPatchReviewSnapshot?: NonNullable<
      ReturnType<typeof fixtureDependencies>["snapshotPatchReviewWorktree"]
    >;
    patchReviewDeltas?: readonly {
      paths: string[];
      diff: string;
      publicationUnsafePaths?: string[];
    }[];
  } = {},
) {
  const { onPatchReviewSnapshot, patchReviewDeltas, ...fixtureOptions } =
    options;
  const current = fixtureDependencies(fixtureOptions);
  let patchReviewDelta = 0;
  current.snapshotPatchReviewWorktree =
    onPatchReviewSnapshot ??
    (async (directory) => ({
      directory,
      candidate: async () => {
        const deltas = patchReviewDeltas ?? [
          {
            paths: ["src/finding-1.ts"],
            diff: "diff --git a/src/finding-1.ts b/src/finding-1.ts\n",
          },
        ];
        const selected = deltas[
          Math.min(patchReviewDelta, deltas.length - 1)
        ] ?? { paths: [], diff: "" };
        patchReviewDelta += 1;
        return {
          paths: [...selected.paths],
          diff: selected.diff,
          publicationUnsafePaths: [...(selected.publicationUnsafePaths ?? [])],
        };
      },
      dispose: async () => {},
    }));
  return current;
}

function resultWithFindings(severities: readonly SeverityLevel[]) {
  const result = fakeResult(severities);
  result.findings.findings.forEach((finding, index) => {
    Object.assign(finding, {
      findingId: `csf_${index + 1}`,
      occurrenceId: `occ_${index + 1}`,
      title: `Finding ${index + 1}`,
      summary: `Summary ${index + 1}`,
      locations: [
        { path: `src/finding-${index + 1}.ts`, startLine: index + 1 },
      ],
    });
  });
  return result;
}

function savedScan(
  result: ReturnType<typeof resultWithFindings>,
  scanId = "scan-1",
): JsonObject {
  return {
    scan: {
      scanId,
      targetPath: SAVED_REPOSITORY,
      findings: result.findings.findings as unknown as JsonObject[],
    },
  };
}

function completePatches(
  args: readonly string[],
  output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
  status: "verified" | "blocked" = "verified",
): Finding[] {
  const prompt = output?.appServer?.prompt ?? args.at(-1)!;
  const findings = JSON.parse(prompt.split("\n").at(-1)!) as Finding[];
  output?.stdout.write(
    JSON.stringify({
      patches: findings.map((finding) => ({
        occurrenceId: finding.occurrenceId,
        status,
        files: status === "verified" ? [finding.locations[0]!.path] : [],
        ...(status === "verified"
          ? { verification: "The exploit fails and focused tests pass." }
          : { reason: "The required service is unavailable." }),
      })),
    }),
  );
  return findings;
}

async function runWorkflow(
  arguments_: string[],
  fixtures: Parameters<typeof dependencies>[0] = {},
  options: {
    interactive?: boolean;
    review?: boolean;
    configure?: (value: ReturnType<typeof dependencies>) => void;
  } = {},
) {
  const stdout = capture();
  const stderr = capture(options.interactive);
  const current = dependencies({
    currentDirectory: CURRENT_REPOSITORY,
    onCodex: (args, output) => {
      completePatches(args, output);
      return 0;
    },
    ...fixtures,
  });
  if (options.interactive) {
    current.confirmPatchReview = async (question) => {
      stderr.stream.write(`\n${question} (y/N)\n`);
      return options.review ?? true;
    };
  }
  options.configure?.(current);
  return {
    exitCode: await main(arguments_, stdout.stream, stderr.stream, current),
    stdout: stdout.text(),
    stderr: stderr.text(),
  };
}

describe("scan and patch workflow", () => {
  test("patches selected scan findings in the scanned repository and returns JSON", async () => {
    const result = resultWithFindings(["critical", "high", "medium", "low"]);
    const invocations: Array<{
      args: readonly string[];
      directory: string | undefined;
      prompt: string | undefined;
    }> = [];
    const patched: Finding[] = [];
    const outcome = await runWorkflow(
      [
        "scan",
        "../other/repository",
        "--patch",
        "--patch-severity",
        "high",
        "--fail-on-severity",
        "high",
        "--json",
      ],
      {
        result,
        onCodex: (args, output) => {
          invocations.push({
            args,
            directory: output?.appServer?.directory,
            prompt: output?.appServer?.prompt,
          });
          patched.push(...completePatches(args, output));
          return 0;
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
      "occ_1",
      "occ_2",
    ]);
    expect(invocations).toHaveLength(2);
    for (const invocation of invocations) {
      expect(invocation.args[0]).toBe("app-server");
      expect(invocation.directory).toBe(
        resolve(CURRENT_REPOSITORY, "../other/repository"),
      );
      expect(invocation.prompt).toContain("Return exactly one JSON object");
    }
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      manifest: result.manifest,
      findings: result.findings,
      patchSeverity: "high",
      patches: [
        { occurrenceId: "occ_1", status: "verified" },
        { occurrenceId: "occ_2", status: "verified" },
      ],
    });
    expect(outcome.stderr).toContain("Patching 2 confirmed findings...");
  });

  test("runs independent review stages for scan and saved-finding patching", async () => {
    for (const arguments_ of [
      ["scan", "--patch"],
      ["patch", "--scan", "scan-1"],
    ]) {
      const result = resultWithFindings(["high"]);
      const stages: string[] = [];
      const outcome = await runWorkflow(
        [...arguments_, "--review-style", "--review-minimality"],
        {
          result,
          onWorkbench: () => savedScan(result),
          onCodex: (args, output) => {
            const { prompt, sandbox } = output!.appServer!;
            if (sandbox === "read-only") {
              expect(prompt).toContain(JSON.stringify(["src/finding-1.ts"]));
              const stage = ["minimality", "local-coding-style"].find((value) =>
                prompt.includes(`only the ${value} review`),
              )!;
              stages.push(stage);
              output!.stdout.write(
                JSON.stringify({
                  status: "approved",
                  findings: [],
                }),
              );
            } else {
              stages.push("author");
              completePatches(args, output);
            }
            return 0;
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(stages).toEqual(["author", "minimality", "local-coding-style"]);
    }
  });

  test("passes the configured revision budget to scan and saved-finding patching", async () => {
    for (const arguments_ of [
      ["scan", "--patch"],
      ["patch", "--scan", "scan-1"],
    ]) {
      const result = resultWithFindings(["high"]);
      let reviews = 0;
      const outcome = await runWorkflow(
        [...arguments_, "--review-minimality", "--max-review-revisions", "2"],
        {
          result,
          onWorkbench: () => savedScan(result),
          onCodex: (args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              reviews += 1;
              output!.stdout.write(
                JSON.stringify(
                  reviews < 3
                    ? {
                        status: "revise",
                        findings: [`Remove unrelated change ${reviews}.`],
                      }
                    : { status: "approved", findings: [] },
                ),
              );
            } else {
              completePatches(args, output);
            }
            return 0;
          },
        },
      );

      expect({
        arguments_,
        exitCode: outcome.exitCode,
        stderr: outcome.stderr,
      }).toMatchObject({ exitCode: 0 });
      expect(reviews).toBe(3);
    }
  });

  test("updates the independent review scope after an author revision", async () => {
    const result = resultWithFindings(["high"]);
    const scopes: string[][] = [];
    let reviews = 0;
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--review-minimality", "--review-style"],
      {
        result,
        onWorkbench: () => savedScan(result),
        patchReviewDeltas: [
          {
            paths: ["src/finding-1.ts"],
            diff: "diff --git a/src/finding-1.ts b/src/finding-1.ts\n",
          },
          {
            paths: ["src/existing-helper.ts"],
            diff: "diff --git a/src/existing-helper.ts b/src/existing-helper.ts\n",
          },
        ],
        onCodex: (args, output) => {
          const { prompt, sandbox } = output!.appServer!;
          if (sandbox === "read-only") {
            const lines = prompt.split("\n");
            const scope = lines.findIndex((line) =>
              line.startsWith("Review scope is exactly"),
            );
            scopes.push(JSON.parse(lines[scope + 1]!).paths);
            reviews += 1;
            output!.stdout.write(
              JSON.stringify(
                reviews === 1
                  ? { status: "revise", findings: ["Use the existing helper."] }
                  : { status: "approved", findings: [] },
              ),
            );
          } else if (reviews === 0) {
            completePatches(args, output);
          } else {
            output!.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: ["src/reported-only.ts"],
                    verification: "The exploit fails and focused tests pass.",
                  },
                ],
              }),
            );
          }
          return 0;
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(scopes).toEqual([
      ["src/finding-1.ts"],
      ["src/existing-helper.ts"],
      ["src/existing-helper.ts"],
    ]);
  });

  test("rejects a verified patch without an observed candidate delta", async () => {
    const result = resultWithFindings(["high"]);
    let reviews = 0;
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--review-minimality", "--json"],
      {
        result,
        onWorkbench: () => savedScan(result),
        patchReviewDeltas: [{ paths: [], diff: "" }],
        onCodex: (args, output) => {
          if (output!.appServer!.sandbox === "read-only") reviews += 1;
          else completePatches(args, output);
          return 0;
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(reviews).toBe(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [
        {
          occurrenceId: "occ_1",
          status: "failed",
          files: [],
          reason:
            "The patch reported a verified result without any observed candidate changes.",
        },
      ],
    });
  });

  test("preserves a direct no-change patch result without running reviews", async () => {
    let reviews = 0;
    const outcome = await runWorkflow(
      ["patch", "Already-safe synthetic issue", "--review-minimality"],
      {
        patchReviewDeltas: [{ paths: [], diff: "" }],
        onCodex: (_args, output) => {
          if (output!.appServer!.sandbox === "read-only") reviews += 1;
          else output!.stdout.write("No change was needed.\n");
          return 0;
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(outcome.stdout).toBe("No change was needed.\n");
    expect(reviews).toBe(0);
  });

  test("preserves reviewer SIGINT and SIGTERM exits for structured patches", async () => {
    for (const arguments_ of [
      ["scan", "--patch"],
      ["patch", "--scan", "scan-1"],
    ]) {
      for (const signalExit of [130, 143] as const) {
        const result = resultWithFindings(["high"]);
        const outcome = await runWorkflow(
          [...arguments_, "--review-minimality", "--json"],
          {
            result,
            onWorkbench: () => savedScan(result),
            onCodex: (args, output) => {
              if (output!.appServer!.sandbox === "read-only") {
                return signalExit;
              }
              completePatches(args, output);
              return 0;
            },
          },
        );

        expect(outcome.exitCode).toBe(signalExit);
        expect(JSON.parse(outcome.stdout)).toMatchObject({ patches: [] });
        expect(outcome.stdout).not.toContain('"status":"failed"');
        expect(outcome.stderr).toContain(
          `minimality review exited with status ${signalExit}`,
        );
      }
    }
  });

  test("stops and cleans interrupted baseline and candidate capture", async () => {
    for (const entrypoint of ["scan", "patch"] as const) {
      for (const phase of ["baseline", "candidate"] as const) {
        for (const signalName of ["SIGINT", "SIGTERM"] as const) {
          const temporaryRoot = await realpath(
            await mkdtemp(join(tmpdir(), "codex-security-aborted-snapshot-")),
          );
          const snapshotDirectory = join(temporaryRoot, "snapshot");
          const signals = new FakeSignals();
          const result = resultWithFindings(["high", "high"]);
          let authors = 0;
          let reviews = 0;
          let disposals = 0;
          const repositoryCommands: string[] = [];
          try {
            const outcome = await runWorkflow(
              [
                ...(entrypoint === "scan"
                  ? ["scan", "--patch"]
                  : ["patch", "--scan", "scan-1"]),
                "--review-minimality",
                "--create-pr",
                "--json",
              ],
              {
                signals,
                result,
                onWorkbench: () => savedScan(result),
                onPatchReviewSnapshot: async (directory, signal) => {
                  expect(signal).toBeDefined();
                  await mkdir(snapshotDirectory);
                  let disposed = false;
                  const dispose = async () => {
                    if (disposed) return;
                    disposed = true;
                    disposals += 1;
                    await rm(snapshotDirectory, {
                      recursive: true,
                      force: true,
                    });
                  };
                  if (phase === "baseline") {
                    signals.emit(signalName);
                    expect(signal!.reason).toBe(signalName);
                    await dispose();
                    signal!.throwIfAborted();
                  }
                  return {
                    directory,
                    candidate: async () => {
                      signals.emit(signalName);
                      expect(signal!.reason).toBe(signalName);
                      signal!.throwIfAborted();
                      return { paths: [], diff: "" };
                    },
                    dispose,
                  };
                },
                onCodex: (args, output) => {
                  if (output!.appServer!.sandbox === "read-only") {
                    reviews += 1;
                    output!.stdout.write(
                      JSON.stringify({ status: "approved", findings: [] }),
                    );
                  } else {
                    authors += 1;
                    completePatches(args, output);
                  }
                  return 0;
                },
                onRepositoryCommand: (command) => {
                  repositoryCommands.push(command);
                  return "";
                },
              },
            );

            expect(outcome.exitCode).toBe(signalName === "SIGINT" ? 130 : 143);
            expect(JSON.parse(outcome.stdout)).toMatchObject({ patches: [] });
            expect(authors).toBe(phase === "baseline" ? 0 : 1);
            expect(reviews).toBe(0);
            expect(repositoryCommands).toEqual([]);
            expect(disposals).toBe(1);
            expect(
              await realpath(snapshotDirectory).catch(() => undefined),
            ).toBeUndefined();
            expect(signals.listeners.get("SIGINT")?.size ?? 0).toBe(0);
            expect(signals.listeners.get("SIGTERM")?.size ?? 0).toBe(0);
          } finally {
            await rm(temporaryRoot, { recursive: true, force: true });
          }
        }
      }
    }
  });

  test("propagates a legitimate no_change result after a revision", async () => {
    const result = resultWithFindings(["high"]);
    let authors = 0;
    let reviews = 0;
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--review-minimality", "--json"],
      {
        result,
        onWorkbench: () => savedScan(result),
        patchReviewDeltas: [
          {
            paths: ["src/finding-1.ts"],
            diff: "diff --git a/src/finding-1.ts b/src/finding-1.ts\n",
          },
          { paths: [], diff: "" },
        ],
        onCodex: (args, output) => {
          if (output!.appServer!.sandbox === "read-only") {
            reviews += 1;
            output!.stdout.write(
              JSON.stringify({
                status: "revise",
                findings: ["Verify whether the finding is already fixed."],
              }),
            );
          } else if ((authors += 1) === 1) {
            completePatches(args, output);
          } else {
            output!.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "no_change",
                    files: ["../model-reported-path.ts"],
                    verification: "The vulnerable behavior no longer exists.",
                  },
                ],
              }),
            );
          }
          return 0;
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect({ authors, reviews }).toEqual({ authors: 2, reviews: 1 });
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [{ occurrenceId: "occ_1", status: "no_change", files: [] }],
    });
  });

  test("preserves terminal revision status, reason, and observed paths", async () => {
    for (const [status, expectedExit] of [
      ["blocked", 1],
      ["failed", 2],
    ] as const) {
      const result = resultWithFindings(["high"]);
      let authors = 0;
      const reason = `Synthetic ${status} reason.`;
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--review-minimality", "--json"],
        {
          result,
          onWorkbench: () => savedScan(result),
          patchReviewDeltas: [
            {
              paths: ["src/finding-1.ts"],
              diff: "diff --git a/src/finding-1.ts b/src/finding-1.ts\n",
            },
            {
              paths: ["src/observed-revision.ts"],
              diff: "diff --git a/src/observed-revision.ts b/src/observed-revision.ts\n",
            },
          ],
          onCodex: (args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              output!.stdout.write(
                JSON.stringify({
                  status: "revise",
                  findings: ["Recheck the affected boundary."],
                }),
              );
            } else if ((authors += 1) === 1) {
              completePatches(args, output);
            } else {
              output!.stdout.write(
                JSON.stringify({
                  patches: [
                    {
                      occurrenceId: "occ_1",
                      status,
                      files: ["/model/reported/path.ts"],
                      reason,
                    },
                  ],
                }),
              );
            }
            return 0;
          },
        },
      );

      expect(outcome.exitCode).toBe(expectedExit);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        patches: [
          {
            occurrenceId: "occ_1",
            status,
            files: ["src/observed-revision.ts"],
            reason,
          },
        ],
      });
    }
  });

  test("reviews sibling edits from a nested invocation at the Git root", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-nested-patch-")),
    );
    const selected = join(repository, "packages", "selected");
    const sibling = join(repository, "packages", "sibling");
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let observed: { paths: string[]; diff: string } | undefined;
    let authorDirectory: string | undefined;
    let reviewerDirectory: string | undefined;
    const issueInputs: string[][] = [];
    try {
      await mkdir(selected, { recursive: true });
      await mkdir(sibling, { recursive: true });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(selected, "entry.ts"), "selected\n");
      await writeFile(join(selected, "issue.txt"), "nested issue\n");
      await writeFile(join(repository, "issue.txt"), "root issue\n");
      await writeFile(join(sibling, "value.ts"), "unsafe\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        ["patch", "issue.txt", "--review-minimality"],
        {
          currentDirectory: selected,
          onCodex: async (_args, output) => {
            const server = output!.appServer!;
            issueInputs.push(JSON.parse(server.prompt.split("\n").at(-1)!));
            if (server.sandbox === "read-only") {
              reviewerDirectory = server.directory;
              const lines = server.prompt.split("\n");
              const marker = lines.findIndex((line) =>
                line.startsWith("Review scope is exactly"),
              );
              observed = JSON.parse(lines[marker + 1]!);
              output!.stdout.write(
                JSON.stringify({ status: "approved", findings: [] }),
              );
            } else {
              authorDirectory = server.directory;
              await writeFile(join(sibling, "value.ts"), "fixed\n");
              output!.stdout.write("Verified synthetic patch.");
            }
            return 0;
          },
        },
        {
          configure: (current) => {
            delete current.snapshotPatchReviewWorktree;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(authorDirectory).toBe(selected);
      expect(reviewerDirectory).toBe(repository);
      expect(issueInputs).toEqual([["nested issue\n"], ["nested issue\n"]]);
      expect(observed?.paths).toEqual(["packages/sibling/value.ts"]);
      expect(observed?.diff).toContain("-unsafe");
      expect(observed?.diff).toContain("+fixed");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("keeps baseline ignored files out of reviews in paths with list separators", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-ignored-patch-")),
    );
    const repository = join(
      root,
      process.platform === "win32" ? "repository;review" : "repository:review",
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let observed: { paths: string[]; diff: string } | undefined;
    try {
      await mkdir(join(repository, "src"), { recursive: true });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, ".gitignore"), ".env\n");
      await writeFile(join(repository, "src", "value.ts"), "unsafe\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(join(repository, ".env"), "SYNTHETIC_SECRET=value\n");

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            const server = output!.appServer!;
            if (server.sandbox === "read-only") {
              const lines = server.prompt.split("\n");
              const marker = lines.findIndex((line) =>
                line.startsWith("Review scope is exactly"),
              );
              observed = JSON.parse(lines[marker + 1]!);
              output!.stdout.write(
                JSON.stringify({ status: "approved", findings: [] }),
              );
            } else {
              await writeFile(join(repository, ".gitignore"), "");
              await writeFile(join(repository, "src", "value.ts"), "fixed\n");
              output!.stdout.write("Verified synthetic patch.");
            }
            return 0;
          },
        },
        {
          configure: (current) => {
            delete current.snapshotPatchReviewWorktree;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(observed?.paths).toEqual([".gitignore", "src/value.ts"]);
      expect(observed?.diff).not.toContain("SYNTHETIC_SECRET");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("reviews visible sparse-checkout changes without staging skipped paths", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-sparse-patch-")),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let observed: { paths: string[]; diff: string } | undefined;
    try {
      await mkdir(join(repository, "keep"), { recursive: true });
      await mkdir(join(repository, "omit"), { recursive: true });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      git("config", "color.ui", "always");
      await writeFile(join(repository, "keep", "value.ts"), "unsafe\n");
      await writeFile(join(repository, "omit", "value.ts"), "preserved\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      git("sparse-checkout", "init", "--cone");
      git("sparse-checkout", "set", "keep");

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            const server = output!.appServer!;
            if (server.sandbox === "read-only") {
              const lines = server.prompt.split("\n");
              const marker = lines.findIndex((line) =>
                line.startsWith("Review scope is exactly"),
              );
              observed = JSON.parse(lines[marker + 1]!);
              output!.stdout.write(
                JSON.stringify({ status: "approved", findings: [] }),
              );
            } else {
              await writeFile(join(repository, "keep", "value.ts"), "fixed\n");
              output!.stdout.write("Verified synthetic patch.");
            }
            return 0;
          },
        },
        {
          configure: (current) => {
            delete current.snapshotPatchReviewWorktree;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(observed?.paths).toEqual(["keep/value.ts"]);
      expect(observed?.diff).toContain("-unsafe");
      expect(observed?.diff).toContain("+fixed");
      expect(observed?.diff).not.toContain("\u001B[");
      expect(git("show", "HEAD:omit/value.ts")).toBe("preserved");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("rejects patch-review storage inside the reviewed worktree", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-review-temp-root-")),
    );
    const nestedTemporaryRoot = join(repository, "tmp");
    const previous = {
      TMPDIR: process.env["TMPDIR"],
      TMP: process.env["TMP"],
      TEMP: process.env["TEMP"],
    };
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let authorStarted = false;
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "tracked.ts"), "unsafe\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      await mkdir(nestedTemporaryRoot);
      process.env["TMPDIR"] = nestedTemporaryRoot;
      process.env["TMP"] = nestedTemporaryRoot;
      process.env["TEMP"] = nestedTemporaryRoot;

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: () => {
            authorStarted = true;
            return 0;
          },
        },
        {
          configure: (current) => {
            delete current.snapshotPatchReviewWorktree;
          },
        },
      );

      expect(outcome.exitCode).toBe(2);
      expect(authorStarted).toBe(false);
      expect(outcome.stderr).toContain(
        "temporary storage must be outside the selected Git worktree",
      );
    } finally {
      for (const [name, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      await rm(repository, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "accepts safe POSIX filenames that resemble Windows paths",
    async () => {
      const repository = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-posix-path-patch-")),
      );
      const filename = "C:\\outside.ts";
      const git = (...args: string[]) =>
        execFileSync("git", args, {
          cwd: repository,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();
      let observed: { paths: string[]; diff: string } | undefined;
      try {
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        await writeFile(join(repository, filename), "unsafe\n");
        git("add", "--", filename);
        git("commit", "-m", "Initial synthetic checkout");

        const outcome = await runWorkflow(
          ["patch", "Synthetic security issue", "--review-minimality"],
          {
            currentDirectory: repository,
            onCodex: async (_args, output) => {
              const server = output!.appServer!;
              if (server.sandbox === "read-only") {
                const lines = server.prompt.split("\n");
                const marker = lines.findIndex((line) =>
                  line.startsWith("Review scope is exactly"),
                );
                observed = JSON.parse(lines[marker + 1]!);
                output!.stdout.write(
                  JSON.stringify({ status: "approved", findings: [] }),
                );
              } else {
                await writeFile(join(repository, filename), "fixed\n");
                output!.stdout.write("Verified synthetic patch.");
              }
              return 0;
            },
          },
          {
            configure: (current) => {
              delete current.snapshotPatchReviewWorktree;
            },
          },
        );

        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(observed?.paths).toEqual([filename]);
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

  test("reviews only the observed delta and excludes same-file user changes", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-observed-patch-")),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    const result = resultWithFindings(["high"]);
    const reportedPaths = [
      "/tmp/outside.ts",
      "../outside.ts",
      "C:\\outside.ts",
      "\\\\server\\share\\outside.ts",
      "\\\\?\\C:\\device.ts",
      "linked/outside.ts",
    ];
    let observed: { paths: string[]; diff: string } | undefined;
    let revisionCandidate: { paths: string[]; diff: string } | undefined;
    let authors = 0;
    let reviews = 0;
    try {
      await mkdir(join(repository, "src"), { recursive: true });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(
        join(repository, "src", "finding-1.ts"),
        "base\nunsafe\n",
      );
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(
        join(repository, "src", "finding-1.ts"),
        "base\nuser pre-existing change\nunsafe\n",
      );
      const objectStateBefore = git("count-objects", "-v");

      const saved = savedScan(result);
      (saved["scan"] as JsonObject)["targetPath"] = repository;
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--review-minimality", "--json"],
        {
          currentDirectory: repository,
          result,
          onWorkbench: () => saved,
          onCodex: async (_args, output) => {
            const server = output!.appServer!;
            if (server.sandbox === "read-only") {
              const lines = server.prompt.split("\n");
              const marker = lines.findIndex((line) =>
                line.startsWith("Review scope is exactly"),
              );
              observed ??= JSON.parse(lines[marker + 1]!);
              reviews += 1;
              output!.stdout.write(
                JSON.stringify(
                  reviews === 1
                    ? {
                        status: "revise",
                        findings: ["Confirm only the candidate hunk."],
                      }
                    : { status: "approved", findings: [] },
                ),
              );
            } else {
              authors += 1;
              if (authors === 1) {
                await writeFile(
                  join(repository, "src", "finding-1.ts"),
                  "base\nuser pre-existing change\nfixed\n",
                );
              } else {
                const lines = server.prompt.split("\n");
                const marker = lines.findIndex((line) =>
                  line.startsWith("Current revision scope is exactly"),
                );
                revisionCandidate = JSON.parse(lines[marker + 1]!);
              }
              output!.stdout.write(
                JSON.stringify({
                  patches: [
                    {
                      occurrenceId: "occ_1",
                      status: "verified",
                      files: reportedPaths,
                      verification: "The exploit fails.",
                    },
                  ],
                }),
              );
            }
            return 0;
          },
        },
        {
          configure: (current) => {
            delete current.snapshotPatchReviewWorktree;
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect({ authors, reviews }).toEqual({ authors: 2, reviews: 2 });
      expect(observed?.paths).toEqual(["src/finding-1.ts"]);
      expect(observed?.diff).toContain("-unsafe");
      expect(observed?.diff).toContain("+fixed");
      expect(observed?.diff).not.toContain("+user pre-existing change");
      expect(revisionCandidate).toEqual(observed);
      expect(revisionCandidate?.diff).not.toContain(
        "+user pre-existing change",
      );
      expect(git("count-objects", "-v")).toBe(objectStateBefore);
      for (const path of reportedPaths) {
        expect(observed?.paths).not.toContain(path);
      }
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        patches: [
          {
            occurrenceId: "occ_1",
            status: "verified",
            files: ["src/finding-1.ts"],
          },
        ],
      });
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("does not turn a symlink escape into a review candidate", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-symlinked-patch-")),
    );
    const repository = join(root, "repository");
    const outside = join(root, "outside.ts");
    const result = resultWithFindings(["high"]);
    await mkdir(repository);
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let reviews = 0;
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "tracked.ts"), "tracked\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(outside, "outside before\n");
      await symlink(outside, join(repository, "linked.ts"));

      const saved = savedScan(result);
      (saved["scan"] as JsonObject)["targetPath"] = repository;
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--review-minimality", "--json"],
        {
          currentDirectory: repository,
          result,
          onWorkbench: () => saved,
          onCodex: async (args, output) => {
            if (output!.appServer!.sandbox === "read-only") reviews += 1;
            else {
              await writeFile(join(repository, "linked.ts"), "outside after\n");
              completePatches(args, output);
            }
            return 0;
          },
        },
        {
          configure: (current) => {
            delete current.snapshotPatchReviewWorktree;
          },
        },
      );

      expect(reviews).toBe(0);
      expect(outcome.exitCode).toBe(2);
      expect(await readFile(outside, "utf8")).toBe("outside after\n");
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        patches: [
          {
            status: "failed",
            files: [],
            reason:
              "The patch reported a verified result without any observed candidate changes.",
          },
        ],
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects a candidate symlink retargeted outside the Git worktree", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-candidate-link-")),
    );
    const repository = join(root, "repository");
    const linked = join(repository, "linked.ts");
    const outside = join(root, "outside.ts");
    await mkdir(repository);
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let reviews = 0;
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(linked, "inside\n");
      await writeFile(outside, "outside\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              reviews += 1;
            } else {
              await rm(linked);
              await symlink(outside, linked);
              output!.stdout.write("Verified synthetic patch.");
            }
            return 0;
          },
        },
        {
          configure: (current) => {
            delete current.snapshotPatchReviewWorktree;
          },
        },
      );

      expect(outcome.exitCode).toBe(2);
      expect(reviews).toBe(0);
      expect(outcome.stderr).toContain(
        "observed patch contains a path through a link outside",
      );
      expect(await readFile(outside, "utf8")).toBe("outside\n");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("does not create a pull request when an independent review rejects the patch", async () => {
    const result = resultWithFindings(["high"]);
    const commands: string[] = [];
    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        "--create-pr",
        "--review-minimality",
        "--json",
      ],
      {
        result,
        onWorkbench: () => savedScan(result),
        onRepositoryCommand: (command) => {
          commands.push(command);
          return "";
        },
        onCodex: (args, output) => {
          if (output!.appServer!.sandbox === "read-only") {
            output!.stdout.write(
              JSON.stringify({
                status: "blocked",
                findings: [
                  "The patch is outside the production threat model.\u001B[31m\n",
                ],
              }),
            );
          } else {
            completePatches(args, output);
          }
          return 0;
        },
      },
    );

    expect(outcome.exitCode).toBe(1);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [
        {
          occurrenceId: "occ_1",
          status: "blocked",
          files: ["src/finding-1.ts"],
          reason:
            "minimality review blocked the patch: The patch is outside the production threat model.",
        },
      ],
    });
    expect(outcome.stdout).not.toContain("\u001B");
    expect(commands).toEqual([]);
    expect(outcome.stderr).toContain('"status":"blocked"');
  });

  test("continues with separate patch tasks when one finding fails", async () => {
    const result = resultWithFindings(["critical", "high", "medium"]);
    const tasks: string[] = [];
    const outcome = await runWorkflow(["scan", "--patch", "--json"], {
      result,
      onCodex: (args, output) => {
        expect(args[0]).toBe("app-server");
        const [finding] = JSON.parse(
          output!.appServer!.prompt.split("\n").at(-1)!,
        ) as Finding[];
        tasks.push(finding!.occurrenceId);
        if (finding!.occurrenceId === "occ_2") return 1;
        completePatches(args, output);
        return 0;
      },
    });

    expect(tasks).toEqual(["occ_1", "occ_2", "occ_3"]);
    expect(outcome.exitCode).toBe(2);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [
        { occurrenceId: "occ_1", status: "verified" },
        {
          occurrenceId: "occ_2",
          status: "failed",
          reason: "Patch command exited with status 1.",
        },
        { occurrenceId: "occ_3", status: "verified" },
      ],
    });
  });

  test("passes the scan model, provider, and selected authentication to patching", async () => {
    const result = resultWithFindings(["high"]);
    let invocation: readonly string[] = [];
    let environment: NodeJS.ProcessEnv | undefined;
    const chatgpt = await runWorkflow(
      [
        "scan",
        "--patch",
        "--auth",
        "chatgpt",
        "--model",
        "gpt-5.6-terra",
        "--effort",
        "high",
        "--json",
      ],
      {
        result,
        environment: {
          OPENAI_API_KEY: "sk-proj-SYNTHETIC_KEY_123",
          CODEX_SECURITY_STATE_DIR: STATE_DIRECTORY,
        },
        onCodex: (args, output, selectedEnvironment) => {
          invocation = args;
          environment = selectedEnvironment;
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(chatgpt.exitCode).toBe(0);
    expect(invocation).toContain('model="gpt-5.6-terra"');
    expect(invocation).toContain('model_reasoning_effort="high"');
    expect(environment).not.toHaveProperty("OPENAI_API_KEY");
    expect(environment).toHaveProperty(
      "CODEX_HOME",
      join(STATE_DIRECTORY, "codex-home"),
    );

    const attributed = await runWorkflow(
      [
        "scan",
        "--patch",
        "--auth",
        "api-key",
        "--safety-identifier",
        "synthetic-user",
        "--json",
      ],
      {
        result,
        environment: { OPENAI_API_KEY: "synthetic-key" },
        onCodex: (args, output) => {
          invocation = args;
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(attributed.exitCode).toBe(0);
    expect(invocation).toContain('safety_identifier="synthetic-user"');

    const provider = await runWorkflow(
      [
        "scan",
        "--patch",
        "--provider",
        "fireworks",
        "--model",
        "accounts/fireworks/models/example",
        "--json",
      ],
      {
        result,
        environment: { FIREWORKS_API_KEY: "SYNTHETIC_FIREWORKS_KEY_123" },
        onCodex: (args, output) => {
          invocation = args;
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(provider.exitCode).toBe(0);
    expect(invocation).toContain('model_provider="fireworks"');
    expect(invocation).toContain(
      'model_providers.fireworks.env_key="FIREWORKS_API_KEY"',
    );
  });

  test("publishes only verified patch files and preserves unrelated staged changes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codex-security-patch-pr-"));
    const repository = join(directory, "repository");
    const remote = join(directory, "remote.git");
    const url = "https://github.example.test/example/repository/pull/15";
    const result = resultWithFindings(["high", "medium"]);
    result.findings.findings[0]!.title = "Synthetic private finding";
    let pullRequestArguments: readonly string[] = [];
    await mkdir(join(repository, "src"), { recursive: true });
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();

    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "src", "finding-1.ts"), "unsafe\n");
      await writeFile(join(repository, "unrelated.ts"), "original\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      git("push", "--set-upstream", "origin", "main");
      await writeFile(join(repository, "unrelated.ts"), "staged separately\n");
      git("add", "--", "unrelated.ts");

      const outcome = await runWorkflow(
        [
          "scan",
          "--patch",
          "--patch-severity",
          "high",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: repository,
          result,
          onCodex: async (args, output) => {
            await writeFile(join(repository, "src", "finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, workingDirectory) => {
            expect(workingDirectory).toBe(repository);
            if (command === "git") return git(...args);
            if (args[1] === "list") return "";
            pullRequestArguments = args;
            return url;
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(git("branch", "--show-current")).toBe("codex-security/patch-scan");
      expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
        "src/finding-1.ts",
      );
      expect(git("diff", "--cached", "--name-only")).toBe("unrelated.ts");
      expect(git("rev-parse", "HEAD")).toBe(
        git("rev-parse", "origin/codex-security/patch-scan"),
      );
      expect(pullRequestArguments).toEqual([
        "pr",
        "create",
        "--draft",
        "--head",
        "codex-security/patch-scan",
        "--title",
        "fix: patch verified security findings",
        "--body",
        "Applies verified security fixes from a completed scan.",
      ]);
      expect(JSON.stringify(pullRequestArguments)).not.toContain(
        "Synthetic private finding",
      );
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        patchSeverity: "high",
        pullRequest: { branch: "codex-security/patch-scan", url },
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("publishes reviewed paths from the Git root for nested scan targets", async () => {
    const root = resolve("/review/root");
    const selected = join(root, "packages", "selected");
    const result = resultWithFindings(["high"]);
    const url = "https://github.example.test/example/repository/pull/18";
    const commandDirectories: string[] = [];
    const saved = savedScan(result);
    (saved["scan"] as JsonObject)["targetPath"] = selected;

    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        "--review-minimality",
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: selected,
        result,
        onWorkbench: () => saved,
        onPatchReviewSnapshot: async (directory) => {
          expect(directory).toBe(selected);
          return {
            directory: root,
            candidate: async () => ({
              paths: ["packages/selected/src/finding-1.ts"],
              diff: "diff --git a/packages/selected/src/finding-1.ts b/packages/selected/src/finding-1.ts\n",
            }),
            dispose: async () => {},
          };
        },
        onCodex: (args, output) => {
          if (output!.appServer!.sandbox === "read-only") {
            output!.stdout.write(
              JSON.stringify({ status: "approved", findings: [] }),
            );
          } else {
            completePatches(args, output);
          }
          return 0;
        },
        onRepositoryCommand: (command, args, workingDirectory) => {
          commandDirectories.push(workingDirectory);
          if (command === "gh") return args[1] === "list" ? "" : url;
          return args[0] === "rev-parse" ? "verified-commit" : "";
        },
      },
    );

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(commandDirectories.length).toBeGreaterThan(0);
    expect(new Set(commandDirectories)).toEqual(new Set([root]));
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      repository: root,
      patches: [
        {
          status: "verified",
          files: ["packages/selected/src/finding-1.ts"],
        },
      ],
      pullRequest: { url },
    });
  });

  test("does not publish reviewed files with pre-existing changes", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-dirty-review-pr-")),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    const result = resultWithFindings(["high"]);
    const saved = savedScan(result);
    (saved["scan"] as JsonObject)["targetPath"] = repository;
    let commandStarted = false;
    try {
      await mkdir(join(repository, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(
        join(repository, "src", "finding-1.ts"),
        "base\nunsafe\n",
      );
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(
        join(repository, "src", "finding-1.ts"),
        "base\npre-existing user change\nunsafe\n",
      );

      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan-1",
          "--review-minimality",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: repository,
          result,
          onWorkbench: () => saved,
          onCodex: async (args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              output!.stdout.write(
                JSON.stringify({ status: "approved", findings: [] }),
              );
            } else {
              await writeFile(
                join(repository, "src", "finding-1.ts"),
                "base\npre-existing user change\nfixed\n",
              );
              completePatches(args, output);
            }
            return 0;
          },
          onRepositoryCommand: () => {
            commandStarted = true;
            return "";
          },
        },
        {
          configure: (current) => {
            delete current.snapshotPatchReviewWorktree;
          },
        },
      );

      expect(outcome.exitCode).toBe(2);
      expect(commandStarted).toBe(false);
      expect(outcome.stderr).toContain(
        "Reviewed patch files with pre-existing changes cannot be published automatically",
      );
      expect(outcome.stdout).toBe("");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("removes patch signal listeners before create and resume publication", async () => {
    for (const publication of ["create", "resume"] as const) {
      for (const signalName of ["SIGINT", "SIGTERM"] as const) {
        const signals = new FakeSignals();
        const result = resultWithFindings(["high"]);
        const branch = "codex-security/patch-scan-1";
        const commit = "verified-commit";
        const url = "https://github.example.test/example/repository/pull/17";
        let emitted = false;
        let commands = 0;
        const outcome = await runWorkflow(
          publication === "create"
            ? ["patch", "--scan", "scan-1", "--create-pr", "--json"]
            : ["patch", "--resume-pr", branch, "--json"],
          {
            signals,
            result,
            onWorkbench: () => savedScan(result),
            onRepositoryCommand: (command, args) => {
              commands += 1;
              expect(signals.listeners.get("SIGINT")?.size ?? 0).toBe(0);
              expect(signals.listeners.get("SIGTERM")?.size ?? 0).toBe(0);
              if (!emitted) {
                emitted = true;
                signals.emit(signalName);
              }
              if (command === "gh") return url;
              if (args[0] === "rev-parse") return commit;
              if (args.includes("--get")) return commit;
              return "";
            },
          },
        );

        expect(outcome.exitCode).toBe(0);
        expect(emitted).toBe(true);
        expect(commands).toBeGreaterThan(1);
        expect(signals.listeners.get("SIGINT")?.size ?? 0).toBe(0);
        expect(signals.listeners.get("SIGTERM")?.size ?? 0).toBe(0);
        expect(JSON.parse(outcome.stdout)).toHaveProperty(
          "pullRequest.url",
          url,
        );
      }
    }
  });

  test("removes scan signal listeners before create publication", async () => {
    for (const signalName of ["SIGINT", "SIGTERM"] as const) {
      const signals = new FakeSignals();
      const result = resultWithFindings(["high"]);
      const url = "https://github.example.test/example/repository/pull/18";
      let emitted = false;
      let commands = 0;
      const outcome = await runWorkflow(
        ["scan", "--patch", "--create-pr", "--json"],
        {
          signals,
          result,
          onRepositoryCommand: (command) => {
            commands += 1;
            expect(signals.listeners.get("SIGINT")?.size ?? 0).toBe(0);
            expect(signals.listeners.get("SIGTERM")?.size ?? 0).toBe(0);
            if (!emitted) {
              emitted = true;
              signals.emit(signalName);
            }
            return command === "gh" ? url : "";
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(emitted).toBe(true);
      expect(commands).toBeGreaterThan(1);
      expect(signals.listeners.get("SIGINT")?.size ?? 0).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size ?? 0).toBe(0);
      expect(JSON.parse(outcome.stdout)).toHaveProperty("pullRequest.url", url);
    }
  });

  test.each(["push", "create"])(
    "resumes publication after %s fails without patching again",
    async (failure) => {
      const directory = await mkdtemp(
        join(tmpdir(), "codex-security-pr-retry-"),
      );
      const repository = join(directory, "repository");
      const remote = join(directory, "remote.git");
      const branch = "codex-security/patch-scan-1";
      const url = "https://github.example.test/example/repository/pull/16";
      const result = resultWithFindings(["high"]);
      let modelCalls = 0;
      let pushCalls = 0;
      let created = 0;
      let failOnce = true;
      let publishedUrl = "";
      await mkdir(join(repository, "src"), { recursive: true });
      const git = (...args: string[]) =>
        execFileSync("git", args, {
          cwd: repository,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();

      try {
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        await writeFile(join(repository, "src", "finding-1.ts"), "unsafe\n");
        await writeFile(join(repository, "unrelated.ts"), "original\n");
        git("add", ".");
        git("commit", "-m", "Initial synthetic checkout");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        git("push", "--set-upstream", "origin", "main");

        const fixtures: Parameters<typeof dependencies>[0] = {
          currentDirectory: repository,
          onWorkbench: () => ({
            scan: {
              scanId: "scan-1",
              targetPath: repository,
              findings: result.findings.findings as unknown as JsonObject[],
            },
          }),
          onCodex: async (args, output) => {
            modelCalls += 1;
            await writeFile(join(repository, "src", "finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args) => {
            if (command === "git") {
              if (args[0] === "push") {
                pushCalls += 1;
                if (failure === "push" && failOnce) {
                  failOnce = false;
                  throw new Error("Synthetic push failure");
                }
              }
              return git(...args);
            }
            if (args[1] === "list") return publishedUrl;
            expect(args[1]).toBe("create");
            if (failure === "create" && failOnce) {
              failOnce = false;
              throw new Error("Synthetic PR service failure");
            }
            created += 1;
            publishedUrl = url;
            return url;
          },
        };

        const first = await runWorkflow(
          ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          fixtures,
        );
        expect(first.exitCode).toBe(2);
        expect(first.stderr).toContain(`patch --resume-pr ${branch}`);
        const commit = git("rev-parse", "HEAD");
        expect(
          git("config", "--get", `branch.${branch}.codexSecurityPatchCommit`),
        ).toBe(commit);
        if (failure === "create") {
          expect(git("rev-parse", `origin/${branch}`)).toBe(commit);
        }
        await writeFile(join(repository, "unrelated.ts"), "later local work\n");

        const retry = await runWorkflow(
          ["patch", "--resume-pr", branch, "--json"],
          fixtures,
        );
        expect(retry.exitCode).toBe(0);
        expect(JSON.parse(retry.stdout)).toEqual({
          pullRequest: { branch, url },
        });
        expect(modelCalls).toBe(1);
        expect(created).toBe(1);
        expect(git("rev-parse", "HEAD")).toBe(commit);
        expect(git("rev-parse", `origin/${branch}`)).toBe(commit);
        expect(git("diff", "--name-only")).toBe("unrelated.ts");

        const pushes = pushCalls;
        const repeated = await runWorkflow(
          ["patch", "--resume-pr", branch],
          fixtures,
        );
        expect(repeated.exitCode).toBe(0);
        expect(created).toBe(1);
        expect(pushCalls).toBe(pushes);
        expect(modelCalls).toBe(1);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test("refuses to resume a missing or changed patch commit", async () => {
    for (const saved of ["", "saved-commit"]) {
      let modelCalls = 0;
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1"],
        {
          onCodex: () => {
            modelCalls += 1;
            return 0;
          },
          onRepositoryCommand: (command, args) => {
            expect(command).toBe("git");
            return args[0] === "config" ? saved : "changed-commit";
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        saved ? "changed since verification" : "No verified patch commit",
      );
      expect(modelCalls).toBe(0);
    }
  });

  test("rejects new patch inputs when resuming publication", async () => {
    for (const input of [
      ["--scan", "scan-1"],
      ["--linear-issue", "SEC-123"],
      ["--create-pr"],
      ["--review-minimality"],
      ["--review-style"],
      ["--max-review-revisions", "5"],
      ["occ_1"],
    ]) {
      let commandStarted = false;
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1", ...input],
        {
          onCodex: () => {
            commandStarted = true;
            return 0;
          },
          onRepositoryCommand: () => {
            commandStarted = true;
            return "";
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain("--resume-pr cannot be combined");
      expect(commandStarted).toBe(false);
    }
  });

  test("does not publish blocked, unchanged, or repository-external patches", async () => {
    for (const status of ["blocked", "no_change", "outside"] as const) {
      let commandStarted = false;
      const outcome = await runWorkflow(
        ["scan", "--patch", "--create-pr", "--json"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (_args, output) => {
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: status === "outside" ? "verified" : status,
                    files: status === "outside" ? ["../outside.ts"] : [],
                    ...(status === "outside"
                      ? { verification: "Focused checks pass." }
                      : status === "blocked"
                        ? { reason: "A required service is unavailable." }
                        : {}),
                  },
                ],
              }),
            );
            return 0;
          },
          onRepositoryCommand: () => {
            commandStarted = true;
            return "";
          },
        },
      );

      expect(commandStarted).toBe(false);
      expect(outcome.exitCode).toBe(
        status === "blocked" ? 1 : status === "outside" ? 2 : 0,
      );
      expect(JSON.parse(outcome.stdout)).not.toHaveProperty("pullRequest");
      if (status === "outside") {
        expect(outcome.stderr).toContain(
          "Patch files must remain inside the scanned repository.",
        );
      }
    }
  });

  test("keeps verified scan results when pull request creation fails", async () => {
    const outcome = await runWorkflow(
      ["scan", "--patch", "--create-pr", "--json"],
      {
        result: resultWithFindings(["high"]),
        onRepositoryCommand: () => {
          throw new Error("GitHub authentication failed.");
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("GitHub authentication failed.");
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patchSeverity: "low",
      patches: [{ occurrenceId: "occ_1", status: "verified" }],
    });
  });

  test("keeps blocked findings in the failure policy and rejects unverified results", async () => {
    for (const failure of ["blocked", "malformed", "unverified"] as const) {
      const outcome = await runWorkflow(
        ["scan", "--patch", "--fail-on-severity", "high", "--json"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (args, output) => {
            if (failure === "malformed") {
              output?.stdout.write("The patch is probably fixed.");
            } else if (failure === "blocked") {
              completePatches(args, output, "blocked");
            } else {
              output?.stdout.write(
                JSON.stringify({
                  patches: [
                    { occurrenceId: "occ_1", status: "verified", files: [] },
                  ],
                }),
              );
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode).toBe(failure === "blocked" ? 1 : 2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        patches: [
          {
            occurrenceId: "occ_1",
            status: failure === "blocked" ? "blocked" : "failed",
            ...(failure === "unverified"
              ? { reason: "Patch verification was not reported." }
              : {}),
          },
        ],
      });
    }
  });

  test("does not patch incomplete scans or allow patching during a dry run", async () => {
    let invoked = false;
    const incomplete = resultWithFindings(["high"]);
    incomplete.coverage.completeness = "partial";
    const partial = await runWorkflow(["scan", "--patch", "--json"], {
      result: incomplete,
      onCodex: () => {
        invoked = true;
        return 0;
      },
    });
    expect(partial.exitCode).toBe(2);
    expect(invoked).toBe(false);

    const dryRun = await runWorkflow(["scan", "--patch", "--dry-run"]);
    expect(dryRun.exitCode).toBe(2);
    expect(dryRun.stderr).toContain(
      "--patch cannot be combined with --dry-run",
    );
  });

  test("reviews full findings and honors individual interactive patch selections", async () => {
    for (const [argv, selection, expected] of [
      [
        ["scan"],
        { severity: "medium", occurrenceIds: ["occ_1", "occ_2"] },
        ["occ_1", "occ_2"],
      ],
      [
        ["scan", "--patch"],
        { severity: "low", occurrenceIds: ["occ_1", "occ_3"] },
        ["occ_1", "occ_3"],
      ],
      [["scan"], null, []],
    ] as const) {
      let reviewed: readonly Finding[] = [];
      const patched: Finding[] = [];
      const outcome = await runWorkflow(
        [...argv],
        {
          result: resultWithFindings(["high", "medium", "low"]),
          onCodex: (args, output) => {
            patched.push(...completePatches(args, output));
            return 0;
          },
        },
        {
          interactive: true,
          configure: (value) => {
            value.patchEditor = async (repository, candidates) => {
              expect(repository).toBe(CURRENT_REPOSITORY);
              reviewed = candidates;
              return selection === null
                ? null
                : {
                    severity: selection.severity,
                    occurrenceIds: [...selection.occurrenceIds],
                  };
            };
          },
        },
      );
      expect(outcome.exitCode).toBe(0);
      expect(reviewed.map(({ occurrenceId }) => occurrenceId)).toEqual([
        "occ_1",
        "occ_2",
        "occ_3",
      ]);
      expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
        ...expected,
      ]);
      if (argv[1] === "--patch") {
        expect(outcome.stderr).not.toContain(
          "Review and patch these findings?",
        );
      } else {
        expect(outcome.stderr).toContain("Review and patch these findings?");
      }
    }
  });

  test("shows normal scan findings before optionally opening patch review", async () => {
    for (const review of [true, false]) {
      let opened = false;
      let patched = false;
      const outcome = await runWorkflow(
        ["scan"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (args, output) => {
            patched = true;
            completePatches(args, output);
            return 0;
          },
        },
        {
          interactive: true,
          review,
          configure: (value) => {
            value.patchEditor = async () => {
              opened = true;
              return { severity: "high", occurrenceIds: ["occ_1"] };
            };
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr.indexOf("FINDINGS")).toBeLessThan(
        outcome.stderr.indexOf("Review and patch these findings? (y/N)"),
      );
      expect(opened).toBe(review);
      expect(patched).toBe(review);
    }
  });

  test("does not offer patch review when there are no actionable findings", async () => {
    for (const severities of [[], ["informational"]] as const) {
      let offered = false;
      let opened = false;
      const outcome = await runWorkflow(
        ["scan"],
        {
          result: resultWithFindings(severities),
          environment: { NO_COLOR: "1" },
        },
        {
          interactive: true,
          configure: (value) => {
            value.confirmPatchReview = async () => {
              offered = true;
              return true;
            };
            value.patchEditor = async () => {
              opened = true;
              return null;
            };
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr).toContain(`FINDINGS  ${severities.length}`);
      expect(outcome.stderr).not.toContain("Review and patch these findings?");
      expect(offered).toBe(false);
      expect(opened).toBe(false);
    }
  });

  test("sanitizes interactive patch status", async () => {
    const result = resultWithFindings(["high"]);
    const finding = result.findings.findings[0]!;
    finding.title = "\u001B[31mUnsafe title\u001B[0m\nforged line";
    finding.locations[0]!.path = "src/\u001B[31mquery.ts\u001B[0m";
    const outcome = await runWorkflow(
      ["scan"],
      { result },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "high",
            occurrenceIds: ["occ_1"],
          });
        },
      },
    );
    expect(outcome.exitCode).toBe(0);
    expect(outcome.stderr).toContain("VERIFIED  Unsafe title forged line");
    expect(outcome.stderr).not.toContain("Unsafe title\u001B[0m");
  });

  test("passes separate instructions only for interactively selected findings", async () => {
    const prompts: string[] = [];
    const patched: Finding[] = [];
    const outcome = await runWorkflow(
      ["scan"],
      {
        result: resultWithFindings(["high", "medium", "low"]),
        onCodex: (args, output) => {
          prompts.push(output!.appServer!.prompt);
          patched.push(...completePatches(args, output));
          return 0;
        },
      },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "low",
            occurrenceIds: ["occ_1", "occ_3"],
            instructions: {
              occ_1: "Reuse the shared validator.\nDo not add a dependency.",
              occ_2: "This unselected guidance must not reach the model.",
              occ_3: "Preserve the public API.",
            },
          });
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
      "occ_1",
      "occ_3",
    ]);

    expect(prompts).toHaveLength(2);
    for (const [index, prompt] of prompts.entries()) {
      const lines = prompt.split("\n");
      const instructionsLine = lines.findIndex((line) =>
        line.startsWith("Follow these user-provided patch instructions"),
      );
      expect(instructionsLine).toBeGreaterThan(-1);
      expect(JSON.parse(lines[instructionsLine + 1]!)).toEqual(
        index === 0
          ? { occ_1: "Reuse the shared validator.\nDo not add a dependency." }
          : { occ_3: "Preserve the public API." },
      );
      expect(prompt).not.toContain("This unselected guidance");
    }
    expect(patched[0]).not.toHaveProperty("instructions");
  });

  test("creates a draft pull request when selected in the interactive review", async () => {
    let published = false;
    const url = "https://github.example.test/example/repository/pull/13";
    const outcome = await runWorkflow(
      ["scan"],
      {
        result: resultWithFindings(["high"]),
        onRepositoryCommand: (command, args) => {
          published ||= command === "gh" && args[1] === "create";
          return command === "gh" && args[1] === "create" ? url : "";
        },
      },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "high",
            occurrenceIds: ["occ_1"],
            createPullRequest: true,
          });
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(published).toBe(true);
    expect(outcome.stderr).toContain(`Pull request: ${url}`);
  });

  test("patches a saved scan by severity and supports structured output", async () => {
    const result = resultWithFindings(["high", "medium"]);
    let patched: Finding[] = [];
    let workingDirectory = "";
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--severity", "high", "--json"],
      {
        onWorkbench: (args): JsonObject => {
          expect(args).toEqual(["get-scan", "--scan-id", "scan-1"]);
          return savedScan(result);
        },
        onCodex: (args, output) => {
          workingDirectory = output!.appServer!.directory;
          patched = completePatches(args, output);
          return 0;
        },
      },
    );
    expect(outcome.exitCode).toBe(0);
    expect(workingDirectory).toBe(SAVED_REPOSITORY);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual(["occ_1"]);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      scanId: "scan-1",
      repository: SAVED_REPOSITORY,
      patches: [{ occurrenceId: "occ_1", status: "verified" }],
    });
  });

  test("creates a draft pull request for verified saved-finding patches", async () => {
    const result = resultWithFindings(["high"]);
    const url = "https://github.example.test/example/repository/pull/14";
    let repository = "";
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        onWorkbench: () => savedScan(result),
        onRepositoryCommand: (command, args, target) => {
          repository = target;
          return command === "gh" && args[1] === "create" ? url : "";
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(repository).toBe(SAVED_REPOSITORY);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      scanId: "scan-1",
      pullRequest: { branch: "codex-security/patch-scan-1", url },
    });
  });

  test("redacts credentials when saved-finding pull request creation fails", async () => {
    const result = resultWithFindings(["high"]);
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr"],
      {
        onWorkbench: () => savedScan(result),
        onRepositoryCommand: () => {
          throw new Error("GitHub rejected github_pat_SYNTHETIC_SECRET_123");
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("[redacted]");
    expect(outcome.stderr).not.toContain("SYNTHETIC_SECRET_123");
  });

  test("resolves a finding identifier to its saved scan and checkout", async () => {
    const result = resultWithFindings(["high"]);
    const finding = result.findings.findings[0]!;
    const calls: Array<readonly string[]> = [];
    let patched: Finding[] = [];
    const outcome = await runWorkflow(["patch", "occ_1"], {
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "list-global-findings") {
          return {
            findings: [
              { ...finding, scanId: "scan-1" } as unknown as JsonObject,
            ],
          };
        }
        return savedScan(result);
      },
      onCodex: (args, output) => {
        patched = completePatches(args, output);
        return 0;
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(calls).toEqual([
      ["list-global-findings", "--status", "open"],
      ["get-scan", "--scan-id", "scan-1", "--occurrence-id", "occ_1"],
    ]);
    expect(patched).toEqual([finding]);
  });

  test("selects the latest completed scan for the current repository", async () => {
    const result = resultWithFindings(["high"]);
    const calls: Array<readonly string[]> = [];
    const outcome = await runWorkflow(["patch", "--scan", "latest"], {
      currentDirectory: SAVED_REPOSITORY,
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "list-scans") {
          return { scans: [{ scanId: "scan-complete" }] };
        }
        return savedScan(result, "scan-complete");
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(calls).toEqual([
      ["list-scans", "--repository", SAVED_REPOSITORY, "--status", "complete"],
      ["get-scan", "--scan-id", "scan-complete"],
    ]);
  });

  test("reads every page when saved scan findings are truncated", async () => {
    const result = resultWithFindings(["high", "medium"]);
    const patched: Finding[] = [];
    const calls: Array<readonly string[]> = [];
    const outcome = await runWorkflow(["patch", "--scan", "scan-1"], {
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "get-scan") {
          return {
            scan: {
              scanId: "scan-1",
              targetPath: SAVED_REPOSITORY,
              findings: [],
              findingsTruncated: true,
            },
          };
        }
        const secondPage = args.includes("--offset");
        return {
          findingsPage: {
            findings: [
              result.findings.findings[
                secondPage ? 1 : 0
              ] as unknown as JsonObject,
            ],
            nextOffset: secondPage ? null : 1,
          },
        };
      },
      onCodex: (args, output) => {
        patched.push(...completePatches(args, output));
        return 0;
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
      "occ_1",
      "occ_2",
    ]);
    expect(calls).toEqual([
      ["get-scan", "--scan-id", "scan-1"],
      ["list-findings", "--scan-id", "scan-1", "--status", "open"],
      [
        "list-findings",
        "--scan-id",
        "scan-1",
        "--status",
        "open",
        "--offset",
        "1",
      ],
    ]);
  });

  test("rejects a severity threshold without an explicit patch request", async () => {
    const outcome = await runWorkflow(["scan", "--patch-severity", "high"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("--patch-severity requires --patch");
  });

  test("rejects optional patch reviews without an explicit patch request", async () => {
    for (const flag of ["--review-minimality", "--review-style"]) {
      let started = false;
      const outcome = await runWorkflow(["scan", flag], {
        onCodex: () => {
          started = true;
          return 0;
        },
      });
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain("Patch review options require --patch");
      expect(started).toBe(false);
    }
  });

  test("requires a selected review for a review revision budget", async () => {
    for (const arguments_ of [
      ["scan", "--patch", "--max-review-revisions", "1"],
      ["patch", "Synthetic security issue", "--max-review-revisions", "1"],
    ]) {
      let started = false;
      const outcome = await runWorkflow(arguments_, {
        onCodex: () => {
          started = true;
          return 0;
        },
      });
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        "--max-review-revisions requires --review-minimality or --review-style",
      );
      expect(started).toBe(false);
    }
  });

  test("requires verified patching before creating a pull request", async () => {
    const scan = await runWorkflow(["scan", "--create-pr"]);
    expect(scan.exitCode).toBe(2);
    expect(scan.stderr).toContain("--create-pr requires --patch");

    const literal = await runWorkflow([
      "patch",
      "Synthetic security issue",
      "--create-pr",
    ]);
    expect(literal.exitCode).toBe(2);
    expect(literal.stderr).toContain(
      "--create-pr requires a saved finding identifier or --scan",
    );
  });
});
