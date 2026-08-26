import { describe, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
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
const PATCH_REVIEW_RUNTIME = join(
  import.meta.dir,
  "../src/patch-review-mcp.ts",
);
const GIT_EXECUTABLE = Bun.which("git") ?? process.execPath;

function runRepositoryGit(
  repository: string,
  args: readonly string[],
  options?: { gitIndexFile?: string },
): string {
  return execFileSync("git", args, {
    cwd: repository,
    encoding: "utf8",
    env:
      options?.gitIndexFile === undefined
        ? process.env
        : { ...process.env, GIT_INDEX_FILE: options.gitIndexFile },
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

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
      diffBytes?: Buffer;
      publicationBaseCommit?: string | null;
      publicationUnsafePaths?: string[];
      publicationBaseEntries?: Array<{
        path: string;
        mode?: string;
        object?: string;
      }>;
      publicationEntries?: Array<{
        path: string;
        mode?: string;
        object?: string;
      }>;
      base?: string;
      head?: string;
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
      reviewRepository: {
        directory,
        repository: directory,
        tree: "synthetic-baseline-tree",
        objectDirectory: resolve(directory, ".git", "objects"),
        alternateObjectDirectory: resolve(directory, ".git", "objects"),
        runtime: PATCH_REVIEW_RUNTIME,
        gitExecutable: GIT_EXECUTABLE,
      },
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
          ...(selected.diffBytes === undefined
            ? {}
            : { diffBytes: Buffer.from(selected.diffBytes) }),
          ...(selected.publicationBaseCommit === undefined
            ? {}
            : { publicationBaseCommit: selected.publicationBaseCommit }),
          publicationUnsafePaths: [...(selected.publicationUnsafePaths ?? [])],
          publicationBaseEntries: [...(selected.publicationBaseEntries ?? [])],
          publicationEntries: [...(selected.publicationEntries ?? [])],
          base: selected.base ?? "a".repeat(40),
          head: selected.head ?? "b".repeat(40),
        };
      },
      dispose: async () => {},
    }));
  current.validatePatchRiskAssessment = async () => true;
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

function patchRiskArtifact(prompt: string) {
  const lines = prompt.split("\n");
  const marker = "CLI-owned immutable patch artifact (JSON object):";
  const index = lines.indexOf(marker);
  return JSON.parse(lines[index + 1]!) as {
    path: string;
    patch: {
      repository: string;
      sourceType: "patch_file";
      base: string;
      head: string;
      changedFiles: string[];
      sha256: string;
    };
  };
}

function approvedPatchRiskVerdict(prompt: string) {
  const artifact = patchRiskArtifact(prompt);
  return {
    status: "approved",
    findings: [],
    report: "## Patch risk\n\nThe synthetic patch is mergeable.",
    assessment: {
      schemaVersion: 1,
      patch: artifact.patch,
      recommendation: "merge",
      workflowLabel: "human_review_required",
    },
  };
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
        [
          ...arguments_,
          "--assess-patch-risk",
          "--review-style",
          "--review-minimality",
        ],
        {
          result,
          onWorkbench: () => savedScan(result),
          onCodex: (args, output) => {
            const { prompt, sandbox } = output!.appServer!;
            if (sandbox === "read-only") {
              expect(prompt).toContain(JSON.stringify(["src/finding-1.ts"]));
              const stage = [
                "minimality",
                "local-coding-style",
                "patch-risk-assessment",
              ].find((value) => prompt.includes(`only the ${value} review`))!;
              stages.push(stage);
              output!.stdout.write(
                JSON.stringify(
                  stage === "patch-risk-assessment"
                    ? approvedPatchRiskVerdict(prompt)
                    : { status: "approved", findings: [] },
                ),
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
      expect(stages).toEqual([
        "author",
        "minimality",
        "local-coding-style",
        "patch-risk-assessment",
      ]);
    }
  });

  test("reverifies all accepted findings after the final reviewed patch", async () => {
    const result = resultWithFindings(["high", "high"]);
    const stages: string[] = [];
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--review-minimality", "--json"],
      {
        result,
        onWorkbench: () => savedScan(result),
        onCodex: (args, output) => {
          const server = output!.appServer!;
          if (output!.command === "verify-fix") {
            stages.push("combined-verification");
            expect(server.prompt).toContain(JSON.stringify(["occ_1", "occ_2"]));
            output!.stdout.write(
              JSON.stringify({
                results: [
                  {
                    id: "occ_1",
                    status: "still_vulnerable",
                    evidence: "The later synthetic patch restores the issue.",
                  },
                  {
                    id: "occ_2",
                    status: "fixed",
                    evidence: "The second synthetic issue remains fixed.",
                  },
                ],
              }),
            );
          } else if (server.sandbox === "read-only") {
            stages.push("review");
            output!.stdout.write(
              JSON.stringify({ status: "approved", findings: [] }),
            );
          } else {
            stages.push("author");
            completePatches(args, output);
          }
          return 0;
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(stages).toEqual([
      "author",
      "review",
      "author",
      "review",
      "combined-verification",
    ]);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [
        {
          occurrenceId: "occ_1",
          status: "failed",
          reason:
            "Final combined verification found that a later patch reintroduced this finding.",
        },
        { occurrenceId: "occ_2", status: "verified" },
      ],
    });
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

  test("restages a restored tracked file even when ignore rules match", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-restored-ignored-")),
    );
    const path = join(repository, "value.ts");
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    const reviewDiffs: string[] = [];
    let authors = 0;
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, ".gitignore"), "value.ts\n");
      await writeFile(path, "unsafe\n");
      git("add", "--", ".gitignore");
      git("add", "--force", "--", "value.ts");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic security issue",
          "--review-minimality",
          "--max-review-revisions",
          "1",
        ],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            const server = output!.appServer!;
            if (server.sandbox === "read-only") {
              const lines = server.prompt.split("\n");
              const marker = lines.findIndex((line) =>
                line.startsWith("Review scope is exactly"),
              );
              reviewDiffs.push(JSON.parse(lines[marker + 1]!).diff);
              output!.stdout.write(
                JSON.stringify(
                  reviewDiffs.length === 1
                    ? { status: "revise", findings: ["Restore the API."] }
                    : { status: "approved", findings: [] },
                ),
              );
            } else {
              authors += 1;
              if (authors === 1) await rm(path);
              else await writeFile(path, "fixed\n");
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
      expect(authors).toBe(2);
      expect(reviewDiffs).toHaveLength(2);
      expect(reviewDiffs[0]).toContain("-unsafe");
      expect(reviewDiffs[1]).toContain("-unsafe");
      expect(reviewDiffs[1]).toContain("+fixed");
      expect(await readFile(path, "utf8")).toBe("fixed\n");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("provides exact diff bytes when the UTF-8 review presentation is lossy", async () => {
    const result = resultWithFindings(["high"]);
    const diffBytes = Buffer.from([
      ...Buffer.from("diff --git a/value.ts b/value.ts\n+unsafe", "utf8"),
      0xff,
      0x0a,
    ]);
    let canonicalDiff: { encoding: string; data: string } | undefined;
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--review-minimality"],
      {
        result,
        onWorkbench: () => savedScan(result),
        patchReviewDeltas: [
          {
            paths: ["value.ts"],
            diff: diffBytes.toString("utf8"),
            diffBytes,
          },
        ],
        onCodex: (args, output) => {
          const server = output!.appServer!;
          if (server.sandbox === "read-only") {
            const lines = server.prompt.split("\n");
            const marker = lines.findIndex((line) =>
              line.startsWith("Review scope is exactly"),
            );
            canonicalDiff = JSON.parse(lines[marker + 1]!).canonicalDiff;
            output!.stdout.write(
              JSON.stringify({ status: "approved", findings: [] }),
            );
          } else {
            completePatches(args, output);
          }
          return 0;
        },
      },
    );

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(canonicalDiff?.encoding).toBe("base64");
    expect(Buffer.from(canonicalDiff!.data, "base64").equals(diffBytes)).toBe(
      true,
    );
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
                    reviewRepository: {
                      directory,
                      repository: directory,
                      tree: "synthetic-baseline-tree",
                      objectDirectory: resolve(directory, ".git", "objects"),
                      alternateObjectDirectory: resolve(
                        directory,
                        ".git",
                        "objects",
                      ),
                      runtime: PATCH_REVIEW_RUNTIME,
                      gitExecutable: GIT_EXECUTABLE,
                    },
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

  test("rejects extra patch results before reviewing no_change output", async () => {
    const result = resultWithFindings(["high"]);
    let reviews = 0;
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--review-minimality", "--json"],
      {
        result,
        onWorkbench: () => savedScan(result),
        onCodex: (_args, output) => {
          if (output!.appServer!.sandbox === "read-only") {
            reviews += 1;
            output!.stdout.write(
              JSON.stringify({ status: "approved", findings: [] }),
            );
          } else {
            output!.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "no_change",
                    files: [],
                    verification: "The issue was already fixed.",
                  },
                  {
                    occurrenceId: "unexpected",
                    status: "verified",
                    files: ["src/finding-1.ts"],
                    verification: "Synthetic extra result.",
                  },
                ],
              }),
            );
          }
          return 0;
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(reviews).toBe(0);
    expect(outcome.stderr).toContain(
      "The generated patch did not return a valid review subject",
    );
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [
        {
          occurrenceId: "occ_1",
          status: "failed",
          reason: "Patch command exited with status 2.",
        },
      ],
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
    let reviewedRepository: string | undefined;
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
              reviewedRepository = server.reviewRepository?.repository;
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
      expect(reviewerDirectory).not.toBe(repository);
      expect(reviewedRepository).toBe(repository);
      expect(issueInputs).toEqual([["nested issue\n"], ["nested issue\n"]]);
      expect(observed?.paths).toEqual(["packages/sibling/value.ts"]);
      expect(observed?.diff).toContain("-unsafe");
      expect(observed?.diff).toContain("+fixed");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("reviews through a confined immutable baseline repository view", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-review-view-")),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let inspected = false;
    try {
      await mkdir(join(repository, ".codex"), { recursive: true });
      await mkdir(join(repository, "src"), { recursive: true });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(
        join(repository, ".codex", "config.toml"),
        'model_instructions_file = "baseline.md"\n',
      );
      await writeFile(join(repository, "baseline.md"), "Baseline guidance.\n");
      await writeFile(join(repository, ".gitignore"), "AGENTS.md\n");
      await writeFile(
        join(repository, "AGENTS.md"),
        "Local ignored instruction.\n",
      );
      await writeFile(join(repository, "src", "value.ts"), "unsafe\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-style"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            const server = output!.appServer!;
            if (server.sandbox !== "read-only") {
              await writeFile(
                join(repository, ".codex", "config.toml"),
                'model_instructions_file = "candidate.md"\n',
              );
              await writeFile(
                join(repository, "candidate.md"),
                "candidate-only-instruction\n",
              );
              await writeFile(join(repository, "src", "value.ts"), "fixed\n");
              output!.stdout.write("Verified synthetic patch.");
              return 0;
            }

            const view = server.reviewRepository!;
            expect(server.directory).toBe(view.directory);
            expect(server.directory).not.toBe(repository);
            expect(view.repository).toBe(repository);
            expect(view.runtime.startsWith(repository)).toBe(false);
            expect(await readFile(view.runtime, "utf8")).toContain(
              "codex-security-patch-review",
            );
            expect(server.prompt).toContain("candidate-only-instruction");
            const messages = [
              {
                jsonrpc: "2.0",
                id: 1,
                method: "initialize",
                params: {
                  protocolVersion: "2025-11-25",
                  capabilities: {},
                  clientInfo: { name: "synthetic-review", version: "1.0.0" },
                },
              },
              {
                jsonrpc: "2.0",
                method: "notifications/initialized",
                params: {},
              },
              { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
              {
                jsonrpc: "2.0",
                id: 3,
                method: "tools/call",
                params: {
                  name: "read_file",
                  arguments: { path: ".codex/config.toml" },
                },
              },
              {
                jsonrpc: "2.0",
                id: 4,
                method: "tools/call",
                params: {
                  name: "search",
                  arguments: { query: "candidate-only-instruction" },
                },
              },
              {
                jsonrpc: "2.0",
                id: 5,
                method: "tools/call",
                params: {
                  name: "read_file",
                  arguments: { path: "../outside" },
                },
              },
              {
                jsonrpc: "2.0",
                id: 6,
                method: "tools/call",
                params: {
                  name: "list_directory",
                  arguments: { path: "." },
                },
              },
              {
                jsonrpc: "2.0",
                id: 7,
                method: "tools/call",
                params: {
                  name: "search",
                  arguments: { query: "Baseline guidance.", path: "." },
                },
              },
              {
                jsonrpc: "2.0",
                id: 8,
                method: "tools/call",
                params: {
                  name: "read_file",
                  arguments: { path: "AGENTS.md" },
                },
              },
            ];
            const execution = spawnSync(
              process.execPath,
              [
                view.runtime,
                view.gitExecutable,
                view.repository,
                view.tree,
                view.objectDirectory,
                view.alternateObjectDirectory,
              ],
              {
                encoding: "utf8",
                input: `${messages.map((message) => JSON.stringify(message)).join("\n")}\n`,
                timeout: 30_000,
              },
            );
            expect(execution.status, execution.stderr).toBe(0);
            const responses = execution.stdout
              .trim()
              .split("\n")
              .map((line) => JSON.parse(line));
            expect(
              responses
                .find((response) => response.id === 2)
                .result.tools.map((tool: { name: string }) => tool.name),
            ).toEqual(["read_file", "list_directory", "search"]);
            expect(
              responses.find((response) => response.id === 3).result.content[0]
                .text,
            ).toBe('model_instructions_file = "baseline.md"\n');
            expect(
              responses.find((response) => response.id === 4).result.content[0]
                .text,
            ).toBe("");
            expect(
              responses.find((response) => response.id === 5).result.isError,
            ).toBe(true);
            expect(
              JSON.parse(
                responses.find((response) => response.id === 6).result
                  .content[0].text,
              ).map((entry: { path: string }) => entry.path),
            ).toContain("baseline.md");
            expect(
              responses.find((response) => response.id === 7).result.content[0]
                .text,
            ).toContain("baseline.md:1:Baseline guidance.");
            expect(
              responses.find((response) => response.id === 8).result.content[0]
                .text,
            ).toBe("Local ignored instruction.\n");
            inspected = true;
            output!.stdout.write(
              JSON.stringify({ status: "approved", findings: [] }),
            );
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
      expect(inspected).toBe(true);
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
      git("update-index", "--assume-unchanged", "omit/value.ts");

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
              await mkdir(join(repository, "omit"), { recursive: true });
              await writeFile(
                join(repository, "omit", "value.ts"),
                "materialized\n",
              );
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
      expect(observed?.paths).toEqual(["keep/value.ts", "omit/value.ts"]);
      expect(observed?.diff).toContain("-unsafe");
      expect(observed?.diff).toContain("+fixed");
      expect(observed?.diff).toContain("-preserved");
      expect(observed?.diff).toContain("+materialized");
      expect(observed?.diff).not.toContain("\u001B[");
      expect(git("show", "HEAD:omit/value.ts")).toBe("preserved");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("reviews deletion of a pre-existing untracked file", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-untracked-delete-")),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    const untracked = join(repository, "extra.ts");
    let observed: { paths: string[]; diff: string } | undefined;
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      git("add", "--", "value.ts");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(untracked, "pre-existing helper\n");

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
              await writeFile(join(repository, "value.ts"), "fixed\n");
              await rm(untracked);
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
      expect(observed?.paths).toEqual(["extra.ts", "value.ts"]);
      expect(observed?.diff).toContain("-pre-existing helper");
      expect(observed?.diff).toContain("+fixed");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("captures deletion of a materialized skip-worktree file", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-sparse-delete-")),
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
      await writeFile(join(repository, "keep", "value.ts"), "unchanged\n");
      await writeFile(join(repository, "omit", "value.ts"), "remove me\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      git("update-index", "--skip-worktree", "omit/value.ts");

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
              await rm(join(repository, "omit", "value.ts"));
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
      expect(observed?.paths).toEqual(["omit/value.ts"]);
      expect(observed?.diff).toContain("deleted file mode");
      expect(observed?.diff).toContain("-remove me");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("fails closed when the candidate changes while approval is running", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-review-race-")),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    const path = join(repository, "value.ts");
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(path, "unsafe\n");
      git("add", "--", "value.ts");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              await writeFile(path, "changed while review was running\n");
              output!.stdout.write(
                JSON.stringify({ status: "approved", findings: [] }),
              );
            } else {
              await writeFile(path, "fixed\n");
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
      expect(outcome.stderr).toContain(
        "review candidate changed while approval was running",
      );
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("fails closed when the candidate changes before revision", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-revision-race-")),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    const path = join(repository, "value.ts");
    let authors = 0;
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(path, "unsafe\n");
      git("add", "--", "value.ts");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              await writeFile(path, "concurrent user edit\n");
              output!.stdout.write(
                JSON.stringify({
                  status: "revise",
                  findings: ["Use the existing helper."],
                }),
              );
            } else {
              authors += 1;
              await writeFile(path, "fixed\n");
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
      expect(authors).toBe(1);
      expect(outcome.stderr).toContain(
        "review candidate changed while revision was being prepared",
      );
      expect(await readFile(path, "utf8")).toBe("concurrent user edit\n");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("fails closed when the author changes only the real Git index", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-index-only-change-")),
    );
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
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      await writeFile(join(repository, "staged.ts"), "baseline\n");
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
              await writeFile(join(repository, "value.ts"), "fixed\n");
              const object = execFileSync(
                "git",
                ["hash-object", "-w", "--stdin"],
                {
                  cwd: repository,
                  encoding: "utf8",
                  input: "index-only\n",
                },
              ).trim();
              git("update-index", "--cacheinfo", "100644", object, "staged.ts");
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
        "Git index changed after patch review started",
      );
      expect(await readFile(join(repository, "staged.ts"), "utf8")).toBe(
        "baseline\n",
      );
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("fails closed when the author changes only Git index flags", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-index-flags-")),
    );
    const hidden = join(repository, "hidden.ts");
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
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      await writeFile(hidden, "preserve\n");
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
              await writeFile(join(repository, "value.ts"), "fixed\n");
              git("update-index", "--skip-worktree", "hidden.ts");
              await rm(hidden);
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
        "Git index changed after patch review started",
      );
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test.each(["configuration", "hook"] as const)(
    "fails closed when the author changes top-level Git %s",
    async (kind) => {
      const repository = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-git-metadata-")),
      );
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
        await writeFile(join(repository, "value.ts"), "unsafe\n");
        git("add", "--", "value.ts");
        git("commit", "-m", "Initial synthetic checkout");

        const outcome = await runWorkflow(
          ["patch", "Synthetic security issue", "--review-minimality"],
          {
            currentDirectory: repository,
            onCodex: async (_args, output) => {
              if (output!.appServer!.sandbox === "read-only") {
                reviews += 1;
              } else {
                await writeFile(join(repository, "value.ts"), "fixed\n");
                if (kind === "configuration") {
                  git("config", "review.synthetic", "changed");
                } else {
                  await writeFile(
                    join(repository, ".git", "hooks", "pre-commit"),
                    "#!/bin/sh\nexit 0\n",
                  );
                }
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
          "Git metadata changed after patch review started",
        );
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

  test("rejects object alternates outside the selected repository", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-object-alternate-")),
    );
    const repository = join(root, "repository");
    const external = join(root, "external");
    const git = (directory: string, ...args: string[]) =>
      execFileSync("git", args, {
        cwd: directory,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let authorStarted = false;
    try {
      await Promise.all([mkdir(repository), mkdir(external)]);
      git(repository, "init", "--initial-branch=main");
      git(repository, "config", "user.name", "Synthetic User");
      git(repository, "config", "user.email", "synthetic@example.test");
      git(repository, "config", "commit.gpgsign", "false");
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      git(repository, "add", "--", "value.ts");
      git(repository, "commit", "-m", "Initial synthetic checkout");
      git(external, "init", "--initial-branch=main");
      await mkdir(join(repository, ".git", "objects", "info"), {
        recursive: true,
      });
      await writeFile(
        join(repository, ".git", "objects", "info", "alternates"),
        `${join(external, ".git", "objects")}\n`,
      );

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
        "Git object alternates must remain inside",
      );
      expect(outcome.stderr).not.toContain(external);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("ignores untracked nested Git repositories in the candidate", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-nested-repository-")),
    );
    const nested = join(repository, "nested");
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let observed: { paths: string[] } | undefined;
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      git("add", "--", "value.ts");
      git("commit", "-m", "Initial synthetic checkout");
      await mkdir(nested);
      execFileSync("git", ["init", "--initial-branch=main"], {
        cwd: nested,
        stdio: ["ignore", "pipe", "pipe"],
      });
      await writeFile(join(nested, "untracked.ts"), "nested\n");

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
              await writeFile(join(repository, "value.ts"), "fixed\n");
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
      expect(observed?.paths).toEqual(["value.ts"]);
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("accepts a stable conflicted nested Git repository", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-nested-conflict-")),
    );
    const nested = join(repository, "nested");
    const git = (directory: string, ...args: string[]) =>
      execFileSync("git", args, {
        cwd: directory,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    try {
      git(repository, "init", "--initial-branch=main");
      git(repository, "config", "user.name", "Synthetic User");
      git(repository, "config", "user.email", "synthetic@example.test");
      git(repository, "config", "commit.gpgsign", "false");
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      git(repository, "add", "--", "value.ts");
      git(repository, "commit", "-m", "Initial synthetic checkout");

      await mkdir(nested);
      git(nested, "init", "--initial-branch=main");
      git(nested, "config", "user.name", "Synthetic User");
      git(nested, "config", "user.email", "synthetic@example.test");
      git(nested, "config", "commit.gpgsign", "false");
      await writeFile(join(nested, "value.ts"), "baseline\n");
      git(nested, "add", "--", "value.ts");
      git(nested, "commit", "-m", "Initial nested checkout");
      git(nested, "switch", "-c", "other");
      await writeFile(join(nested, "value.ts"), "other\n");
      git(nested, "commit", "-am", "Other nested change");
      git(nested, "switch", "main");
      await writeFile(join(nested, "value.ts"), "main\n");
      git(nested, "commit", "-am", "Main nested change");
      const merge = spawnSync("git", ["merge", "--no-edit", "other"], {
        cwd: nested,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
      expect(merge.status).not.toBe(0);

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              output!.stdout.write(
                JSON.stringify({ status: "approved", findings: [] }),
              );
            } else {
              await writeFile(join(repository, "value.ts"), "fixed\n");
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
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("fails closed when the author changes a nested Git worktree", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-nested-change-")),
    );
    const nested = join(repository, "nested");
    const git = (directory: string, ...args: string[]) =>
      execFileSync("git", args, {
        cwd: directory,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let reviews = 0;
    try {
      git(repository, "init", "--initial-branch=main");
      git(repository, "config", "user.name", "Synthetic User");
      git(repository, "config", "user.email", "synthetic@example.test");
      git(repository, "config", "commit.gpgsign", "false");
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      git(repository, "add", "--", "value.ts");
      git(repository, "commit", "-m", "Initial synthetic checkout");
      await mkdir(nested);
      git(nested, "init", "--initial-branch=main");
      git(nested, "config", "user.name", "Synthetic User");
      git(nested, "config", "user.email", "synthetic@example.test");
      git(nested, "config", "commit.gpgsign", "false");
      await writeFile(join(nested, "value.ts"), "nested baseline\n");
      git(nested, "add", "--", "value.ts");
      git(nested, "commit", "-m", "Initial nested checkout");

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              reviews += 1;
            } else {
              await writeFile(join(repository, "value.ts"), "fixed\n");
              await writeFile(join(nested, "value.ts"), "nested changed\n");
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
      expect(outcome.stderr).toContain("nested Git worktree changed");
      expect(await readFile(join(nested, "value.ts"), "utf8")).toBe(
        "nested changed\n",
      );
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test.each(["tracked file marked assume-unchanged", "Git metadata"] as const)(
    "fails closed when the author changes a nested %s",
    async (kind) => {
      const repository = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-nested-boundary-")),
      );
      const nested = join(repository, "nested");
      const git = (directory: string, ...args: string[]) =>
        execFileSync("git", args, {
          cwd: directory,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();
      let reviews = 0;
      try {
        git(repository, "init", "--initial-branch=main");
        git(repository, "config", "user.name", "Synthetic User");
        git(repository, "config", "user.email", "synthetic@example.test");
        git(repository, "config", "commit.gpgsign", "false");
        await writeFile(join(repository, "value.ts"), "unsafe\n");
        git(repository, "add", "--", "value.ts");
        git(repository, "commit", "-m", "Initial synthetic checkout");

        await mkdir(nested);
        git(nested, "init", "--initial-branch=main");
        git(nested, "config", "user.name", "Synthetic User");
        git(nested, "config", "user.email", "synthetic@example.test");
        git(nested, "config", "commit.gpgsign", "false");
        await writeFile(join(nested, "tracked.ts"), "nested baseline\n");
        git(nested, "add", "--", "tracked.ts");
        git(nested, "commit", "-m", "Initial nested checkout");
        if (kind === "tracked file marked assume-unchanged") {
          git(nested, "update-index", "--assume-unchanged", "tracked.ts");
        }

        const outcome = await runWorkflow(
          ["patch", "Synthetic security issue", "--review-minimality"],
          {
            currentDirectory: repository,
            onCodex: async (_args, output) => {
              if (output!.appServer!.sandbox === "read-only") {
                reviews += 1;
              } else {
                await writeFile(join(repository, "value.ts"), "fixed\n");
                if (kind === "tracked file marked assume-unchanged") {
                  await writeFile(join(nested, "tracked.ts"), "changed\n");
                } else {
                  git(nested, "config", "review.synthetic", "changed");
                }
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
        expect(outcome.stderr).toContain("nested Git worktree changed");
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

  test.each(["overwrites", "deletes"] as const)(
    "fails closed when the author %s a pre-existing ignored file",
    async (operation) => {
      const repository = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-ignored-boundary-")),
      );
      const ignored = join(repository, "private.txt");
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
        await writeFile(join(repository, ".gitignore"), "private.txt\n");
        await writeFile(join(repository, "value.ts"), "unsafe\n");
        git("add", "--", ".gitignore", "value.ts");
        git("commit", "-m", "Initial synthetic checkout");
        await writeFile(ignored, "SYNTHETIC_PRIVATE_BASELINE\n");

        const outcome = await runWorkflow(
          ["patch", "Synthetic security issue", "--review-minimality"],
          {
            currentDirectory: repository,
            onCodex: async (_args, output) => {
              if (output!.appServer!.sandbox === "read-only") {
                reviews += 1;
              } else {
                await writeFile(join(repository, "value.ts"), "fixed\n");
                if (operation === "overwrites") {
                  await writeFile(ignored, "SYNTHETIC_PRIVATE_CHANGED\n");
                } else {
                  await rm(ignored);
                }
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
        expect(outcome.stderr).toContain("ignored path changed");
        expect(outcome.stderr).not.toContain("SYNTHETIC_PRIVATE");
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

  test("fails closed when changed ignore rules hide a new file", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-ignore-rules-")),
    );
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
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      git("add", "--", "value.ts");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              reviews += 1;
            } else {
              await writeFile(join(repository, "value.ts"), "fixed\n");
              await writeFile(
                join(repository, ".git", "info", "exclude"),
                "hidden.txt\n",
              );
              await writeFile(
                join(repository, "hidden.txt"),
                "SYNTHETIC_PRIVATE\n",
              );
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
        "Git metadata changed after patch review started",
      );
      expect(outcome.stderr).not.toContain("SYNTHETIC_PRIVATE");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "fails closed when a reviewed file changes non-executable permissions",
    async () => {
      const repository = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-file-mode-")),
      );
      const path = join(repository, "value.ts");
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
        await writeFile(path, "unsafe\n");
        await chmod(path, 0o644);
        git("add", "--", "value.ts");
        git("commit", "-m", "Initial synthetic checkout");

        const outcome = await runWorkflow(
          ["patch", "Synthetic security issue", "--review-minimality"],
          {
            currentDirectory: repository,
            onCodex: async (_args, output) => {
              if (output!.appServer!.sandbox === "read-only") {
                reviews += 1;
              } else {
                await writeFile(path, "fixed\n");
                await chmod(path, 0o666);
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
          "file permission changed outside Git's reviewed mode",
        );
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "fails closed when a reviewed path ancestor changes permissions",
    async () => {
      const repository = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-directory-mode-")),
      );
      const directory = join(repository, "src");
      const path = join(directory, "value.ts");
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
        await mkdir(directory);
        await writeFile(path, "unsafe\n");
        await chmod(directory, 0o755);
        git("add", "--", "src/value.ts");
        git("commit", "-m", "Initial synthetic checkout");

        const outcome = await runWorkflow(
          ["patch", "Synthetic security issue", "--review-minimality"],
          {
            currentDirectory: repository,
            onCodex: async (_args, output) => {
              if (output!.appServer!.sandbox === "read-only") {
                reviews += 1;
              } else {
                await writeFile(path, "fixed\n");
                await chmod(directory, 0o777);
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
          "directory permission changed outside Git's reviewed state",
        );
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

  test("reviews case-only renames using the worktree spelling", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-case-rename-")),
    );
    const original = join(repository, "Value.ts");
    const renamed = join(repository, "value.ts");
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let observed: { paths: string[] } | undefined;
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(original, "unsafe\n");
      git("add", "--", "Value.ts");
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
              await rename(original, renamed);
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
      expect(new Set(observed?.paths)).toEqual(
        new Set(["Value.ts", "value.ts"]),
      );
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test("rejects a tracked path through an external ancestor link before authoring", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-baseline-link-")),
    );
    const repository = join(root, "repository");
    const linked = join(repository, "linked");
    const outside = join(root, "outside");
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let authorStarted = false;
    try {
      await mkdir(linked, { recursive: true });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(linked, "value.ts"), "inside\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");

      await rm(linked, { recursive: true });
      await mkdir(outside);
      await writeFile(join(outside, "value.ts"), "SYNTHETIC_PRIVATE\n");
      await symlink(outside, linked);

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
      expect(outcome.stderr).toContain("path through a link outside");
      expect(outcome.stderr).not.toContain("SYNTHETIC_PRIVATE");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("binds patch-risk artifacts to canonical raw diff bytes", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-raw-risk-patch-")),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let artifactMatched = false;
    try {
      await mkdir(join(repository, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "src", "value.ts"), "safe\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--assess-patch-risk"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            const server = output!.appServer!;
            if (server.sandbox !== "read-only") {
              await writeFile(
                join(repository, "src", "value.ts"),
                Buffer.from([0x75, 0x6e, 0x73, 0x61, 0x66, 0xff, 0x0a]),
              );
              output!.stdout.write("Verified synthetic patch.");
              return 0;
            }

            const lines = server.prompt.split("\n");
            const marker = lines.indexOf(
              "CLI-owned immutable patch artifact (JSON object):",
            );
            const artifact = JSON.parse(lines[marker + 1]!) as {
              path: string;
              patch: { sha256: string };
            };
            const actual = await readFile(artifact.path);
            const expected = execFileSync(
              "git",
              [
                "--no-pager",
                "diff",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--binary",
                "--relative",
                "HEAD",
                "--",
                ".",
              ],
              {
                cwd: repository,
                stdio: ["ignore", "pipe", "pipe"],
              },
            );
            expect(actual.includes(0xff)).toBe(true);
            expect(actual.equals(expected)).toBe(true);
            expect(createHash("sha256").update(actual).digest("hex")).toBe(
              artifact.patch.sha256,
            );
            const scope = lines.findIndex((line) =>
              line.startsWith("Review scope is exactly"),
            );
            const reviewCandidate = JSON.parse(lines[scope + 1]!) as {
              canonicalDiff?: { encoding: string; data: string };
            };
            expect(reviewCandidate.canonicalDiff?.encoding).toBe("base64");
            expect(
              Buffer.from(reviewCandidate.canonicalDiff!.data, "base64").equals(
                actual,
              ),
            ).toBe(true);
            artifactMatched = true;
            output!.stdout.write(
              JSON.stringify(approvedPatchRiskVerdict(server.prompt)),
            );
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
      expect(artifactMatched).toBe(true);
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test.each(["untracked", "ignored"] as const)(
    "fails closed when the author overwrites a pre-existing %s nested file",
    async (kind) => {
      const repository = await realpath(
        await mkdtemp(join(tmpdir(), `codex-security-nested-${kind}-`)),
      );
      const nested = join(repository, "nested");
      const git = (directory: string, ...args: string[]) =>
        execFileSync("git", args, {
          cwd: directory,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();
      let reviews = 0;
      try {
        git(repository, "init", "--initial-branch=main");
        git(repository, "config", "user.name", "Synthetic User");
        git(repository, "config", "user.email", "synthetic@example.test");
        git(repository, "config", "commit.gpgsign", "false");
        await writeFile(join(repository, "value.ts"), "unsafe\n");
        if (kind === "ignored") {
          await writeFile(join(repository, ".gitignore"), "nested/\n");
        }
        git(repository, "add", "--", ".");
        git(repository, "commit", "-m", "Initial synthetic checkout");

        await mkdir(nested);
        git(nested, "init", "--initial-branch=main");
        git(nested, "config", "user.name", "Synthetic User");
        git(nested, "config", "user.email", "synthetic@example.test");
        git(nested, "config", "commit.gpgsign", "false");
        await writeFile(join(nested, ".gitignore"), "ignored.ts\n");
        await writeFile(join(nested, "tracked.ts"), "tracked baseline\n");
        git(nested, "add", "--", ".gitignore", "tracked.ts");
        git(nested, "commit", "-m", "Initial nested checkout");
        const nestedPath = join(nested, `${kind}.ts`);
        await writeFile(nestedPath, "local baseline\n");

        const outcome = await runWorkflow(
          ["patch", "Synthetic security issue", "--review-minimality"],
          {
            currentDirectory: repository,
            onCodex: async (_args, output) => {
              if (output!.appServer!.sandbox === "read-only") {
                reviews += 1;
              } else {
                await writeFile(join(repository, "value.ts"), "fixed\n");
                await writeFile(nestedPath, "overwritten by author\n");
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
        expect(outcome.stderr).toContain("nested Git worktree changed");
        expect(await readFile(nestedPath, "utf8")).toBe(
          "overwritten by author\n",
        );
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

  test("does not inspect descendant submodule Git metadata", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-nested-submodule-")),
    );
    const repository = join(root, "repository");
    const nested = join(repository, "nested");
    const dependency = join(nested, "dependency");
    const git = (directory: string, ...args: string[]) =>
      execFileSync("git", args, {
        cwd: directory,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    try {
      await mkdir(repository);
      git(repository, "init", "--initial-branch=main");
      git(repository, "config", "user.name", "Synthetic User");
      git(repository, "config", "user.email", "synthetic@example.test");
      git(repository, "config", "commit.gpgsign", "false");
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      git(repository, "add", "--", "value.ts");
      git(repository, "commit", "-m", "Initial synthetic checkout");

      await mkdir(nested);
      git(nested, "init", "--initial-branch=main");
      git(nested, "config", "user.name", "Synthetic User");
      git(nested, "config", "user.email", "synthetic@example.test");
      git(nested, "config", "commit.gpgsign", "false");
      await writeFile(join(nested, "tracked.ts"), "nested baseline\n");
      git(nested, "add", "--", "tracked.ts");
      git(nested, "commit", "-m", "Initial nested checkout");

      await mkdir(dependency);
      await writeFile(
        join(dependency, ".git"),
        `gitdir: ${join(root, "outside", ".git")}\n`,
      );
      await writeFile(join(dependency, "value.ts"), "dependency baseline\n");
      git(
        nested,
        "update-index",
        "--add",
        "--cacheinfo",
        "160000",
        git(nested, "rev-parse", "HEAD"),
        "dependency",
      );

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              output!.stdout.write(
                JSON.stringify({ status: "approved", findings: [] }),
              );
            } else {
              await writeFile(join(repository, "value.ts"), "fixed\n");
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
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects nested Git metadata redirected outside the repository", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-nested-gitdir-")),
    );
    const repository = join(root, "repository");
    const nested = join(repository, "nested");
    const external = join(root, "external");
    const git = (directory: string, ...args: string[]) =>
      execFileSync("git", args, {
        cwd: directory,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let authorStarted = false;
    try {
      await Promise.all([mkdir(repository), mkdir(external)]);
      git(repository, "init", "--initial-branch=main");
      git(repository, "config", "user.name", "Synthetic User");
      git(repository, "config", "user.email", "synthetic@example.test");
      git(repository, "config", "commit.gpgsign", "false");
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      git(repository, "add", "--", "value.ts");
      git(repository, "commit", "-m", "Initial synthetic checkout");
      git(external, "init", "--initial-branch=main");
      await mkdir(nested);
      await writeFile(
        join(nested, ".git"),
        `gitdir: ${join(external, ".git")}\n`,
      );
      await writeFile(join(nested, "value.ts"), "nested\n");

      const outcome = await runWorkflow(
        ["patch", "Synthetic security issue", "--review-minimality"],
        {
          currentDirectory: repository,
          onCodex: (_args, output) => {
            if (output!.appServer!.sandbox !== "read-only")
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
        "Nested Git metadata must remain inside the selected repository",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "preserves unrelated non-UTF-8 Git paths while capturing the baseline",
    async () => {
      const repository = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-non-utf8-path-")),
      );
      const git = (...args: string[]) =>
        execFileSync("git", args, {
          cwd: repository,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();
      const rawPath = Buffer.concat([
        Buffer.from(`${repository}/invalid-`),
        Buffer.from([0x80]),
      ]);
      let observed: { paths: string[] } | undefined;
      try {
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        await writeFile(rawPath, "preserve\n");
        await writeFile(join(repository, "value.ts"), "unsafe\n");
        git("add", "--all");
        git("commit", "-m", "Initial synthetic checkout");

        const outcome = await runWorkflow(
          ["patch", "Synthetic security issue", "--review-minimality"],
          {
            currentDirectory: repository,
            onCodex: async (_args, output) => {
              if (output!.appServer!.sandbox === "read-only") {
                const lines = output!.appServer!.prompt.split("\n");
                const marker = lines.findIndex((line) =>
                  line.startsWith("Review scope is exactly"),
                );
                observed = JSON.parse(lines[marker + 1]!);
                output!.stdout.write(
                  JSON.stringify({ status: "approved", findings: [] }),
                );
              } else {
                await writeFile(join(repository, "value.ts"), "fixed\n");
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
        expect(observed?.paths).toEqual(["value.ts"]);
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

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
      const filename = "line\tbreak\n\u2028C:\\outside.ts";
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

  test("ignores Git replacement objects when constructing review candidates", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-replace-object-")),
    );
    const git = (...args: string[]) =>
      execFileSync("git", args, {
        cwd: repository,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    let observed: { diff: string } | undefined;
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "value.ts"), "unsafe\n");
      git("add", "--", "value.ts");
      git("commit", "-m", "Initial synthetic checkout");
      const replacementBlob = execFileSync(
        "git",
        ["hash-object", "-w", "--stdin"],
        { cwd: repository, encoding: "utf8", input: "replacement\n" },
      ).trim();
      const replacementTree = execFileSync("git", ["mktree"], {
        cwd: repository,
        encoding: "utf8",
        input: `100644 blob ${replacementBlob}\tvalue.ts\n`,
      }).trim();
      git("replace", git("rev-parse", "HEAD^{tree}"), replacementTree);

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
              await writeFile(join(repository, "value.ts"), "fixed\n");
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
      expect(observed?.diff).toContain("-unsafe");
      expect(observed?.diff).not.toContain("-replacement");
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "does not invoke repository clean filters while capturing review snapshots",
    async () => {
      const root = await mkdtemp(
        join(tmpdir(), "codex-security-review-git-environment-"),
      );
      const repository = join(root, "repository");
      const filter = join(root, "filter.mjs");
      const leaked = join(root, "leaked.txt");
      const invoked = join(root, "invoked.txt");
      const armed = join(root, "armed");
      const inherited = {
        count: process.env["GIT_CONFIG_COUNT"],
        key: process.env["GIT_CONFIG_KEY_0"],
        value: process.env["GIT_CONFIG_VALUE_0"],
        apiKey: process.env["OPENAI_API_KEY"],
      };
      try {
        await mkdir(repository);
        const git = (...args: string[]) =>
          execFileSync("git", args, {
            cwd: repository,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
          }).trim();
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        await writeFile(
          filter,
          [
            'import { existsSync, readFileSync, writeFileSync } from "node:fs";',
            "const credential = process.env.GIT_CONFIG_VALUE_0 ?? process.env.OPENAI_API_KEY;",
            `if (existsSync(${JSON.stringify(armed)})) writeFileSync(${JSON.stringify(invoked)}, "invoked");`,
            `if (existsSync(${JSON.stringify(armed)}) && credential) writeFileSync(${JSON.stringify(leaked)}, credential);`,
            "process.stdout.write(readFileSync(0));",
          ].join("\n"),
        );
        git(
          "config",
          "filter.capture.clean",
          `${JSON.stringify(process.execPath)} ${JSON.stringify(filter)}`,
        );
        await writeFile(
          join(repository, ".gitattributes"),
          "value.ts filter=capture\n",
        );
        await writeFile(join(repository, "value.ts"), "unsafe\n");
        git("add", "--", ".");
        git("commit", "-m", "Initial synthetic checkout");

        process.env["GIT_CONFIG_COUNT"] = "1";
        process.env["GIT_CONFIG_KEY_0"] = "http.extraHeader";
        process.env["GIT_CONFIG_VALUE_0"] = "SYNTHETIC_GIT_CREDENTIAL";
        process.env["OPENAI_API_KEY"] = "sk-proj-SYNTHETIC_REVIEW_CREDENTIAL";
        await writeFile(armed, "armed\n");
        const outcome = await runWorkflow(
          ["patch", "Synthetic security issue", "--review-minimality"],
          {
            currentDirectory: repository,
            onCodex: async (_args, output) => {
              if (output!.appServer!.sandbox === "read-only") {
                output!.stdout.write(
                  JSON.stringify({ status: "approved", findings: [] }),
                );
              } else {
                await writeFile(join(repository, "value.ts"), "fixed\n");
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
        expect(
          await readFile(leaked, "utf8").catch(
            (error: NodeJS.ErrnoException) => {
              if (error.code === "ENOENT") return undefined;
              throw error;
            },
          ),
        ).toBeUndefined();
        expect(
          await readFile(invoked, "utf8").catch(
            (error: NodeJS.ErrnoException) => {
              if (error.code === "ENOENT") return undefined;
              throw error;
            },
          ),
        ).toBeUndefined();
      } finally {
        for (const [name, value] of [
          ["GIT_CONFIG_COUNT", inherited.count],
          ["GIT_CONFIG_KEY_0", inherited.key],
          ["GIT_CONFIG_VALUE_0", inherited.value],
          ["OPENAI_API_KEY", inherited.apiKey],
        ] as const) {
          if (value === undefined) delete process.env[name];
          else process.env[name] = value;
        }
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test("captures broad review candidates without per-path Git fan-out", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-broad-review-")),
    );
    const files = Array.from(
      { length: 256 },
      (_, index) => `src/file-${index}.ts`,
    );
    let reviewedPaths: string[] = [];
    try {
      await mkdir(join(repository, "src"));
      const git = (...args: string[]) =>
        execFileSync("git", args, {
          cwd: repository,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      for (const file of files) {
        await writeFile(join(repository, file), "unsafe\n");
      }
      git("add", "--", ".");
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
              reviewedPaths = (
                JSON.parse(lines[marker + 1]!) as {
                  paths: string[];
                }
              ).paths;
              output!.stdout.write(
                JSON.stringify({ status: "approved", findings: [] }),
              );
            } else {
              for (const file of files) {
                await writeFile(join(repository, file), "fixed\n");
              }
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
      expect(reviewedPaths).toHaveLength(files.length);
      expect(new Set(reviewedPaths)).toEqual(new Set(files));
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

  test("rejects a dangling candidate symlink outside the Git worktree", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-dangling-link-")),
    );
    const repository = join(root, "repository");
    const linked = join(repository, "linked.ts");
    const outside = join(root, "outside-missing.ts");
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
            "minimality review blocked the patch: The patch is outside the production threat model.\u001B[31m\n",
        },
      ],
    });
    expect(outcome.stdout).not.toContain("\u001B");
    expect(outcome.stderr).not.toContain("\u001B");
    expect(outcome.stderr).toContain(
      "The patch is outside the production threat model.",
    );
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
    const result = resultWithFindings(["high", "high", "medium"]);
    result.findings.findings[0]!.title = "Synthetic private finding";
    let pullRequestArguments: readonly string[] = [];
    const assessedPatches: Array<{
      base: string;
      head: string;
      changedFiles: string[];
    }> = [];
    const assessedDiffs: string[] = [];
    await mkdir(join(repository, "src"), { recursive: true });
    const canonicalRepository = await realpath(repository);
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
      await writeFile(join(repository, "src", "finding-2.ts"), "unsafe\n");
      await writeFile(join(repository, "unrelated.ts"), "original\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      const baseTree = git("rev-parse", "HEAD^{tree}");
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
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: repository,
          result,
          onCodex: async (args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              const artifact = patchRiskArtifact(output!.appServer!.prompt);
              expect(output!.appServer!.reviewRepository?.tree).toBe(
                artifact.patch.base,
              );
              assessedPatches.push(artifact.patch);
              assessedDiffs.push(await readFile(artifact.path, "utf8"));
              output!.stdout.write(
                JSON.stringify(
                  approvedPatchRiskVerdict(output!.appServer!.prompt),
                ),
              );
              return 0;
            }
            const [finding] = JSON.parse(
              output!.appServer!.prompt.split("\n").at(-1)!,
            ) as Finding[];
            await writeFile(
              join(repository, finding!.locations[0]!.path),
              "fixed\n",
            );
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, workingDirectory, options) => {
            expect(workingDirectory).toBe(canonicalRepository);
            if (command === "git")
              return runRepositoryGit(repository, args, options);
            if (args[1] === "list") return "";
            pullRequestArguments = args;
            return url;
          },
        },
        {
          configure: (current) => {
            delete current.snapshotPatchReviewWorktree;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("branch", "--show-current")).toBe("codex-security/patch-scan");
      expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
        "src/finding-1.ts\nsrc/finding-2.ts",
      );
      expect(git("show", "HEAD:unrelated.ts")).toBe("original");
      expect(git("diff", "--cached", "--name-only")).toBe("unrelated.ts");
      expect(
        assessedPatches.map(({ base, changedFiles }) => ({
          base,
          changedFiles,
        })),
      ).toEqual([
        { base: baseTree, changedFiles: ["src/finding-1.ts"] },
        {
          base: baseTree,
          changedFiles: ["src/finding-1.ts", "src/finding-2.ts"],
        },
      ]);
      expect(assessedPatches.at(-1)?.head).toBe(
        git("rev-parse", "HEAD^{tree}"),
      );
      expect(assessedDiffs.at(-1)).toContain("src/finding-1.ts");
      expect(assessedDiffs.at(-1)).toContain("src/finding-2.ts");
      expect(assessedDiffs.at(-1)).not.toContain("unrelated.ts");
      expect(assessedDiffs.at(-1)).not.toContain("staged separately");
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

  test("creates a patch pull request from an unborn repository", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "codex-security-unborn-pr-"),
    );
    const repository = join(directory, "repository");
    const remote = join(directory, "remote.git");
    const result = resultWithFindings(["high"]);
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
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);

      const outcome = await runWorkflow(
        ["scan", "--patch", "--create-pr", "--json"],
        {
          currentDirectory: repository,
          result,
          onCodex: async (args, output) => {
            await writeFile(join(repository, "src", "finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, _repository, options) => {
            if (command === "git") {
              return runRepositoryGit(repository, args, options);
            }
            return args[1] === "list"
              ? ""
              : "https://github.example.test/example/repository/pull/22";
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("branch", "--show-current")).toBe("codex-security/patch-scan");
      expect(git("show", "HEAD:src/finding-1.ts")).toBe("fixed");
      expect(git("status", "--short")).toBe("");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "does not publish files staged by a commit hook",
    async () => {
      const directory = await mkdtemp(
        join(tmpdir(), "codex-security-hook-publication-"),
      );
      const repository = join(directory, "repository");
      const remote = join(directory, "remote.git");
      const result = resultWithFindings(["high"]);
      let githubInvoked = false;
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
        await writeFile(join(repository, "unrelated.ts"), "hook staged\n");
        await writeFile(
          join(repository, ".git", "hooks", "pre-commit"),
          "#!/bin/sh\ngit add -- unrelated.ts\n",
          { mode: 0o700 },
        );

        const outcome = await runWorkflow(
          ["scan", "--patch", "--review-minimality", "--create-pr", "--json"],
          {
            currentDirectory: repository,
            result,
            onCodex: async (args, output) => {
              if (output!.appServer!.sandbox === "read-only") {
                output!.stdout.write(
                  JSON.stringify({ status: "approved", findings: [] }),
                );
              } else {
                await writeFile(
                  join(repository, "src", "finding-1.ts"),
                  "fixed\n",
                );
                completePatches(args, output);
              }
              return 0;
            },
            onRepositoryCommand: (command, args, _repository, options) => {
              if (command === "git") {
                return runRepositoryGit(repository, args, options);
              }
              githubInvoked = true;
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
        expect(outcome.stderr).toContain(
          "contains changes outside the independently reviewed tree",
        );
        expect(githubInvoked).toBe(false);
        expect(
          git("ls-remote", "--heads", "origin", "codex-security/patch-scan"),
        ).toBe("");
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test("preserves global Git normalization while reviewing publication paths", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "codex-security-git-config-"),
    );
    const repository = join(directory, "repository");
    const remote = join(directory, "remote.git");
    const home = join(directory, "home");
    const result = resultWithFindings(["high"]);
    result.findings.findings[0]!.locations[0]!.path = "value.ts";
    const previous = {
      HOME: process.env["HOME"],
      USERPROFILE: process.env["USERPROFILE"],
      XDG_CONFIG_HOME: process.env["XDG_CONFIG_HOME"],
    };
    await Promise.all([mkdir(repository), mkdir(home)]);
    await writeFile(join(home, ".gitconfig"), "[core]\n\tautocrlf = true\n");
    process.env["HOME"] = home;
    process.env["USERPROFILE"] = home;
    delete process.env["XDG_CONFIG_HOME"];
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
      await writeFile(join(repository, "value.ts"), "unsafe\r\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      expect(git("status", "--short")).toBe("");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      git("push", "--set-upstream", "origin", "main");

      const outcome = await runWorkflow(
        ["scan", "--patch", "--review-minimality", "--create-pr", "--json"],
        {
          currentDirectory: repository,
          result,
          onCodex: async (args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              output!.stdout.write(
                JSON.stringify({ status: "approved", findings: [] }),
              );
            } else {
              await writeFile(join(repository, "value.ts"), "fixed\r\n");
              completePatches(args, output);
            }
            return 0;
          },
          onRepositoryCommand: (command, args, _repository, options) => {
            if (command === "git")
              return runRepositoryGit(repository, args, options);
            return args[1] === "list"
              ? ""
              : "https://github.example.test/example/repository/pull/21";
          },
        },
        {
          configure: (current) => {
            delete current.snapshotPatchReviewWorktree;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("show", "HEAD:value.ts")).toBe("fixed");
      expect(git("status", "--short")).toBe("");
    } finally {
      for (const [name, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("projects file and directory replacements before publication", async () => {
    for (const transition of [
      "directory-to-file",
      "file-to-directory",
    ] as const) {
      const directory = await mkdtemp(
        join(tmpdir(), `codex-security-patch-${transition}-`),
      );
      const repository = join(directory, "repository");
      const remote = join(directory, "remote.git");
      const target = join(repository, "shape");
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path =
        transition === "directory-to-file" ? "shape/value.ts" : "shape";
      let assessedHead = "";
      await mkdir(repository);
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
        if (transition === "directory-to-file") {
          await mkdir(target);
          await writeFile(join(target, "value.ts"), "unsafe\n");
        } else {
          await writeFile(target, "unsafe\n");
        }
        git("add", "--", ".");
        git("commit", "-m", "Initial synthetic checkout");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        git("push", "--set-upstream", "origin", "main");

        const outcome = await runWorkflow(
          ["scan", "--patch", "--assess-patch-risk", "--create-pr", "--json"],
          {
            currentDirectory: repository,
            result,
            onCodex: async (args, output) => {
              const server = output!.appServer!;
              if (server.sandbox === "read-only") {
                const artifact = patchRiskArtifact(server.prompt);
                assessedHead = artifact.patch.head;
                output!.stdout.write(
                  JSON.stringify(approvedPatchRiskVerdict(server.prompt)),
                );
                return 0;
              }
              await rm(target, { recursive: true, force: true });
              if (transition === "directory-to-file") {
                await writeFile(target, "fixed\n");
              } else {
                await mkdir(target);
                await writeFile(join(target, "value.ts"), "fixed\n");
              }
              completePatches(args, output);
              return 0;
            },
            onRepositoryCommand: (command, args, _repository, options) => {
              if (command === "git")
                return runRepositoryGit(repository, args, options);
              return args[1] === "list"
                ? ""
                : "https://github.example.test/example/repository/pull/19";
            },
          },
          {
            configure: (current) => {
              delete current.snapshotPatchReviewWorktree;
            },
          },
        );

        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(git("rev-parse", "HEAD^{tree}")).toBe(assessedHead);
        expect(git("ls-tree", "-r", "--name-only", "HEAD", "--", "shape")).toBe(
          transition === "directory-to-file" ? "shape" : "shape/value.ts",
        );
        expect(git("status", "--short")).toBe("");
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
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
            reviewRepository: {
              directory: root,
              repository: root,
              tree: "synthetic-baseline-tree",
              objectDirectory: resolve(root, ".git", "objects"),
              alternateObjectDirectory: resolve(root, ".git", "objects"),
              runtime: PATCH_REVIEW_RUNTIME,
              gitExecutable: GIT_EXECUTABLE,
            },
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
          if (args[0] === "write-tree") return "verified-tree";
          if (args[0] === "rev-parse" && args[1] === "HEAD^{tree}") {
            return "verified-tree";
          }
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

  test("does not publish when the committed tree differs from the reviewed tree", async () => {
    const result = resultWithFindings(["high"]);
    const commands: Array<{ command: string; args: readonly string[] }> = [];
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
        result,
        onWorkbench: () => savedScan(result),
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
        patchReviewDeltas: [
          {
            paths: ["src/finding-1.ts"],
            diff: "diff --git a/src/finding-1.ts b/src/finding-1.ts\n",
            publicationEntries: [
              {
                path: "src/finding-1.ts",
                mode: "100644",
                object: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              },
            ],
          },
        ],
        onRepositoryCommand: (command, args) => {
          commands.push({ command, args });
          if (command === "git" && args[0] === "ls-tree") {
            return `100644 blob ${"b".repeat(40)}\tsrc/finding-1.ts\0`;
          }
          return "";
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain(
      "The patch changed after independent review",
    );
    expect(commands.some(({ command }) => command === "gh")).toBe(false);
    expect(
      commands.some(
        ({ command, args }) => command === "git" && args[0] === "commit",
      ),
    ).toBe(false);
  });

  test("does not publish from a HEAD that changed after review", async () => {
    const result = resultWithFindings(["high"]);
    const commands: Array<{ command: string; args: readonly string[] }> = [];
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
        result,
        onWorkbench: () => savedScan(result),
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
        patchReviewDeltas: [
          {
            paths: ["src/finding-1.ts"],
            diff: "diff --git a/src/finding-1.ts b/src/finding-1.ts\n",
            publicationBaseCommit: "a".repeat(40),
          },
        ],
        onRepositoryCommand: (command, args) => {
          commands.push({ command, args });
          if (
            command === "git" &&
            args[0] === "rev-parse" &&
            args[1] === "--verify" &&
            args[2] === "HEAD"
          ) {
            return "b".repeat(40);
          }
          return "";
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain(
      "repository HEAD changed after independent review",
    );
    expect(
      commands.some(
        ({ command, args }) => command === "git" && args[0] === "switch",
      ),
    ).toBe(false);
    expect(commands.some(({ command }) => command === "gh")).toBe(false);
  });

  test("does not publish edits interleaved between reviewed findings", async () => {
    const result = resultWithFindings(["high", "high"]);
    const sharedPath = "src/shared.ts";
    const delta = (
      baseObject: string,
      object: string,
      publicationUnsafePaths: string[] = [],
    ) => ({
      paths: [sharedPath],
      diff: `diff --git a/${sharedPath} b/${sharedPath}\n`,
      publicationUnsafePaths,
      publicationBaseEntries: [
        { path: sharedPath, mode: "100644", object: baseObject },
      ],
      publicationEntries: [{ path: sharedPath, mode: "100644", object }],
    });
    let commandStarted = false;
    const firstBase = "a".repeat(40);
    const firstReviewed = "b".repeat(40);
    const interleaved = "c".repeat(40);
    const secondReviewed = "d".repeat(40);
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
        result,
        onWorkbench: () => savedScan(result),
        patchReviewDeltas: [
          delta(firstBase, firstReviewed),
          delta(firstBase, firstReviewed),
          delta(interleaved, secondReviewed, [sharedPath]),
          delta(interleaved, secondReviewed, [sharedPath]),
        ],
        onCodex: (args, output) => {
          if (output!.command === "verify-fix") {
            output!.stdout.write(
              JSON.stringify({
                results: ["occ_1", "occ_2"].map((id) => ({
                  id,
                  status: "fixed",
                  evidence: "The complete synthetic patch preserves the fix.",
                })),
              }),
            );
          } else if (output!.appServer!.sandbox === "read-only") {
            output!.stdout.write(
              JSON.stringify({ status: "approved", findings: [] }),
            );
          } else {
            completePatches(args, output);
          }
          return 0;
        },
        onRepositoryCommand: () => {
          commandStarted = true;
          return "";
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(commandStarted).toBe(false);
    expect(outcome.stderr).toContain(
      "Reviewed patch files with pre-existing changes cannot be published automatically",
    );
  });

  test("publishes cumulative reviews when each baseline matches the prior tree", async () => {
    const result = resultWithFindings(["high", "high"]);
    const sharedPath = "src/shared.ts";
    const firstBase = "a".repeat(40);
    const firstReviewed = "b".repeat(40);
    const secondReviewed = "d".repeat(40);
    const delta = (
      baseObject: string,
      object: string,
      publicationUnsafePaths: string[] = [],
    ) => ({
      paths: [sharedPath],
      diff: `diff --git a/${sharedPath} b/${sharedPath}\n`,
      publicationUnsafePaths,
      publicationBaseEntries: [
        { path: sharedPath, mode: "100644", object: baseObject },
      ],
      publicationEntries: [{ path: sharedPath, mode: "100644", object }],
    });
    const url = "https://github.example.test/example/repository/pull/19";
    let pullRequestCreated = false;
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
        result,
        onWorkbench: () => savedScan(result),
        patchReviewDeltas: [
          delta(firstBase, firstReviewed),
          delta(firstBase, firstReviewed),
          delta(firstReviewed, secondReviewed, [sharedPath]),
          delta(firstReviewed, secondReviewed, [sharedPath]),
        ],
        onCodex: (args, output) => {
          if (output!.command === "verify-fix") {
            output!.stdout.write(
              JSON.stringify({
                results: ["occ_1", "occ_2"].map((id) => ({
                  id,
                  status: "fixed",
                  evidence: "The complete synthetic patch preserves the fix.",
                })),
              }),
            );
          } else if (output!.appServer!.sandbox === "read-only") {
            output!.stdout.write(
              JSON.stringify({ status: "approved", findings: [] }),
            );
          } else {
            completePatches(args, output);
          }
          return 0;
        },
        onRepositoryCommand: (command, args) => {
          if (command === "git" && args[0] === "ls-files") {
            return `100644 ${secondReviewed} 0\t${sharedPath}\0`;
          }
          if (command === "git" && args[0] === "ls-tree") {
            return `100644 blob ${secondReviewed}\t${sharedPath}\0`;
          }
          if (command === "git" && args[0] === "write-tree") {
            return "verified-tree";
          }
          if (
            command === "git" &&
            args[0] === "rev-parse" &&
            args[1] === "HEAD^{tree}"
          ) {
            return "verified-tree";
          }
          if (command === "git" && args[0] === "rev-parse") {
            return "verified-commit";
          }
          if (command === "gh" && args[1] === "list") return "";
          if (command === "gh" && args[1] === "create") {
            pullRequestCreated = true;
            return url;
          }
          return "";
        },
      },
    );

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(pullRequestCreated).toBe(true);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
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

  test("preserves staged changes hidden by matching worktree content", async () => {
    const repository = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-staged-review-pr-")),
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
    const path = join(repository, "src", "finding-1.ts");
    let commandStarted = false;
    try {
      await mkdir(join(repository, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(path, "base\nunsafe\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(path, "base\nstaged user change\nunsafe\n");
      git("add", "--", "src/finding-1.ts");
      await writeFile(path, "base\nunsafe\n");

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
              await writeFile(path, "base\nfixed\n");
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
      expect(git("show", ":src/finding-1.ts")).toBe(
        "base\nstaged user change\nunsafe",
      );
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
              if (args[0] === "write-tree") return "verified-tree";
              if (args[0] === "rev-parse" && args[1] === "HEAD^{tree}") {
                return "verified-tree";
              }
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
          onRepositoryCommand: (command, args, _repository, options) => {
            if (command === "git") {
              if (args[0] === "push") {
                pushCalls += 1;
                if (failure === "push" && failOnce) {
                  failOnce = false;
                  throw new Error("Synthetic push failure");
                }
              }
              return runRepositoryGit(repository, args, options);
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
      ["--assess-patch-risk"],
      ["--python", "/synthetic/python"],
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

  test("gives independent reviewers the matching user patch constraints", async () => {
    const instruction = "Preserve the synthetic compatibility path.";
    let reviewerPrompt = "";
    const outcome = await runWorkflow(
      ["scan", "--patch", "--review-minimality"],
      {
        result: resultWithFindings(["high"]),
        onCodex: (args, output) => {
          if (output!.appServer!.sandbox === "read-only") {
            reviewerPrompt = output!.appServer!.prompt;
            output!.stdout.write(
              JSON.stringify({ status: "approved", findings: [] }),
            );
          } else {
            completePatches(args, output);
          }
          return 0;
        },
      },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "high",
            occurrenceIds: ["occ_1"],
            instructions: { occ_1: instruction },
          });
        },
      },
    );

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(reviewerPrompt).toContain(
      "Evaluate the candidate against these user-provided task constraints",
    );
    expect(reviewerPrompt).toContain(JSON.stringify({ occ_1: instruction }));
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
    for (const flag of [
      "--review-minimality",
      "--review-style",
      "--assess-patch-risk",
    ]) {
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
        "--max-review-revisions requires a selected patch review",
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
