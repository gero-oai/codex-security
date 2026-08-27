import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { afterEach, describe, expect, test } from "bun:test";
import { loadContract } from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

type JsonObject = Record<string, unknown>;

const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function createRepository(): { root: string; repository: string } {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-diff-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  mkdirSync(repository);
  git(repository, "init", "-q");
  return { root, repository };
}

function createMcpDirectories(root: string): void {
  mkdirSync(join(root, "scans"), { mode: 0o700 });
  mkdirSync(join(root, "scans", "repository"), { mode: 0o700 });
  mkdirSync(join(root, "state"), { mode: 0o700 });
}

function git(repository: string, ...args: string[]): string {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...args,
    ],
    { cwd: repository, encoding: "utf8" },
  ).trim();
}

function writeSource(
  repository: string,
  path: string,
  content: string | Buffer,
): void {
  const destination = join(repository, path);
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, content);
}

function python(script: string, ...args: string[]) {
  const command =
    Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(command).not.toBeNull();
  return spawnSync(
    command!,
    ["-B", join(PLUGIN_ROOT, "scripts", script), ...args],
    { encoding: "utf8" },
  );
}

function candidate(path: string): JsonObject {
  return {
    cwe_ids: [],
    locations: [{ path, start_line: 1, role: "root_control" }],
    summary: "The handler may rely on a removed guard.",
    evidence: "The selected change removes the neighboring guard.",
  };
}

function workbenchState(root: string): {
  scans: number;
  submitted: number;
  workspaces: number;
} {
  const command =
    Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(command).not.toBeNull();
  const result = spawnSync(
    command!,
    [
      "-I",
      "-B",
      "-c",
      [
        "import json, sqlite3, sys",
        "with sqlite3.connect(sys.argv[1]) as connection:",
        "    print(json.dumps({",
        "        'workspaces': connection.execute('SELECT COUNT(*) FROM workspaces').fetchone()[0],",
        "        'submitted': connection.execute('SELECT COUNT(*) FROM workspaces WHERE submitted = 1').fetchone()[0],",
        "        'scans': connection.execute('SELECT COUNT(*) FROM scans').fetchone()[0],",
        "    }))",
      ].join("\n"),
      join(root, "state", "workbench.sqlite3"),
    ],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as {
    scans: number;
    submitted: number;
    workspaces: number;
  };
}

function workspaceDiffSelection(
  root: string,
  workspaceId: string,
): {
  baseRevision: string | null;
  contentDigest: string | null;
  headRevision: string | null;
} {
  const command =
    Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(command).not.toBeNull();
  const result = spawnSync(
    command!,
    [
      "-I",
      "-B",
      "-c",
      [
        "import json, sqlite3, sys",
        "with sqlite3.connect(sys.argv[1]) as connection:",
        "    row = connection.execute('SELECT diff_base_revision, diff_head_revision, diff_content_digest FROM workspaces WHERE id = ?', (sys.argv[2],)).fetchone()",
        "    print(json.dumps({'baseRevision': row[0], 'headRevision': row[1], 'contentDigest': row[2]}))",
      ].join("\n"),
      join(root, "state", "workbench.sqlite3"),
      workspaceId,
    ],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as {
    baseRevision: string | null;
    contentDigest: string | null;
    headRevision: string | null;
  };
}

async function startMcp(root: string) {
  const child = spawn(
    process.execPath,
    [join(PLUGIN_ROOT, "mcp", "server.mjs"), "--stdio"],
    {
      env: {
        ...process.env,
        CODEX_SECURITY_SCAN_ROOT: join(root, "scans"),
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        PYTHONDONTWRITEBYTECODE: "1",
      },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const messages = createInterface({ input: child.stdout })[
    Symbol.asyncIterator
  ]();
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  let nextId = 0;

  async function request(
    method: string,
    params: JsonObject,
  ): Promise<JsonObject> {
    const id = ++nextId;
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    child.stdin.write("\n");

    while (true) {
      const message = await messages.next();
      if (message.done) {
        throw new Error(`MCP server exited before replying: ${stderr}`);
      }
      const response = JSON.parse(message.value) as JsonObject;
      if (response["id"] !== id) continue;
      if (response["error"] !== undefined) {
        throw new Error(JSON.stringify(response["error"]));
      }
      return response["result"] as JsonObject;
    }
  }

  await request("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "compact-diff-test", version: "1.0.0" },
  });
  child.stdin.write(
    `${JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    })}\n`,
  );

  return {
    request,
    async call(
      name: string,
      args: JsonObject,
      owner: string,
    ): Promise<JsonObject> {
      const result = await request("tools/call", {
        name,
        arguments: args,
        _meta: { "openai/threadId": owner },
      });
      expect(result["isError"], JSON.stringify(result)).not.toBe(true);
      return result["structuredContent"] as JsonObject;
    },
    async close(): Promise<void> {
      child.stdin.end();
      await new Promise<void>((resolve) => {
        child.once("close", () => resolve());
      });
    },
  };
}

describe("compact diff scan", () => {
  test("reads committed diff previews from the selected head revision", () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/feature.ts", "const marker = 'base';\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "base");
    const base = git(repository, "rev-parse", "HEAD");

    writeSource(repository, "src/feature.ts", "const marker = 'head';\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "head");
    const head = git(repository, "rev-parse", "HEAD");
    git(repository, "checkout", "--detach", base);

    const output = join(root, "rank-input.jsonl");
    const result = python(
      "generate_rank_input.py",
      "make-diff-rank-input",
      "--repo",
      repository,
      "--base",
      base,
      "--head",
      head,
      "--mode",
      "revisions",
      "--out",
      output,
    );

    expect(result.status, result.stderr).toBe(0);
    const row = JSON.parse(readFileSync(output, "utf8")) as {
      path: string;
      preview: string;
    };
    expect(row.path).toBe("src/feature.ts");
    expect(row.preview).toContain("head");
    expect(row.preview).not.toContain("base");
  });

  test("uses the selected Git revisions and keeps deleted source files", () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/guard.py", "allowed = True\n");
    writeSource(repository, "src/handler.py", "value = 1\n");
    writeSource(repository, "src/untouched.py", "unchanged = True\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "base");
    const base = git(repository, "rev-parse", "HEAD");

    rmSync(join(repository, "src", "guard.py"));
    writeSource(repository, "src/handler.py", "value = 2\n");
    writeSource(repository, "src/new handler.py", "created = True\n");
    writeSource(repository, "src/binary.py", Buffer.from([0, 255, 1]));
    writeSource(repository, "tests/ignored.py", "ignored = True\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "selected changes");
    const head = git(repository, "rev-parse", "HEAD");
    writeSource(repository, "src/handler.py", Buffer.from([0, 255, 1]));
    const output = join(root, "in-scope.txt");

    const result = python(
      "generate_in_scope_files.py",
      "--repo",
      repository,
      "--scope",
      ".",
      "--diff-base",
      base,
      "--diff-head",
      head,
      "--out",
      output,
    );

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(output, "utf8").split("\n").filter(Boolean)).toEqual([
      "src/guard.py",
      "src/handler.py",
      "src/new handler.py",
    ]);
  });

  test("omits committed symlinks from the revision inventory", () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/handler.py", "value = 1\n");
    writeSource(repository, "src/deleted-link.py", "handler.py");
    git(repository, "add", ".");
    const deletedLink = git(repository, "hash-object", "src/deleted-link.py");
    git(
      repository,
      "update-index",
      "--cacheinfo",
      `120000,${deletedLink},src/deleted-link.py`,
    );
    git(repository, "commit", "-qm", "base");
    const base = git(repository, "rev-parse", "HEAD");

    rmSync(join(repository, "src", "deleted-link.py"));
    writeSource(repository, "src/handler.py", "value = 2\n");
    writeSource(repository, "src/丁.py", "value = 3\n");
    writeSource(repository, "src/added-link.py", "handler.py");
    git(repository, "add", ".");
    const addedLink = git(repository, "hash-object", "src/added-link.py");
    git(
      repository,
      "update-index",
      "--cacheinfo",
      `120000,${addedLink},src/added-link.py`,
    );
    git(repository, "commit", "-qm", "selected changes");
    const head = git(repository, "rev-parse", "HEAD");
    const output = join(root, "in-scope.txt");

    const executable = Bun.which("python3") ?? Bun.which("python");
    expect(executable).not.toBeNull();
    const result = spawnSync(
      executable!,
      [
        "-B",
        "-c",
        "import locale, runpy, sys; locale.setlocale(locale.LC_CTYPE, 'C'); runpy.run_path(sys.argv.pop(1), run_name='__main__')",
        join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
        "--repo",
        repository,
        "--scope",
        ".",
        "--diff-base",
        base,
        "--diff-head",
        head,
        "--out",
        output,
      ],
      { encoding: "utf8", env: { ...process.env, PYTHONUTF8: "0" } },
    );

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(output, "utf8").split("\n").filter(Boolean)).toEqual([
      "src/handler.py",
      "src/丁.py",
    ]);
  });

  test("keeps staged, unstaged, and untracked working-tree inputs aligned", () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/handler.py", "value = 1\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "base");
    writeSource(repository, "src/handler.py", "value = 2\n");
    writeSource(repository, "src/staged.py", "staged = True\n");
    git(repository, "add", "src/staged.py");
    writeSource(repository, "src/untracked.py", "untracked = True\n");
    writeSource(repository, "src/binary.py", Buffer.from([0, 255, 1]));
    const output = join(root, "in-scope.txt");

    const result = python(
      "generate_in_scope_files.py",
      "--repo",
      repository,
      "--scope",
      ".",
      "--diff-base",
      "HEAD",
      "--diff-mode",
      "local-patch",
      "--out",
      output,
    );

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(output, "utf8").split("\n").filter(Boolean)).toEqual([
      "src/handler.py",
      "src/staged.py",
      "src/untracked.py",
    ]);

    const reviewOutput = join(root, "rank-input.jsonl");
    const review = python(
      "generate_rank_input.py",
      "make-diff-rank-input",
      "--repo",
      repository,
      "--base",
      "HEAD",
      "--mode",
      "local-patch",
      "--out",
      reviewOutput,
    );
    expect(review.status, review.stderr).toBe(0);
    expect(
      readFileSync(reviewOutput, "utf8")
        .trim()
        .split("\n")
        .map((row) => (JSON.parse(row) as { path: string }).path),
    ).toEqual(["src/handler.py", "src/staged.py", "src/untracked.py"]);
  });

  test("keeps deleted inventory paths without accepting unsafe candidates", () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/handler.py", "value = 1\n");
    writeSource(repository, "src/second.py", "value = 2\n");
    const inventory = join(root, "in-scope.txt");
    const input = join(root, "candidates.jsonl");
    const output = join(root, "normalized.jsonl");
    writeFileSync(inventory, "src/deleted.py\nsrc/handler.py\nsrc/second.py\n");
    writeFileSync(
      input,
      [
        candidate("src/handler.py"),
        { ...candidate("src/second.py"), summary: "Résumé: missing guard" },
      ]
        .map((entry) => JSON.stringify(entry))
        .join("\n") + "\n",
    );
    const args = [
      "--input",
      input,
      "--out",
      output,
      "--repo-root",
      repository,
      "--in-scope-files",
      inventory,
    ];

    expect(python("normalize_candidates.py", ...args).status).toBe(2);
    const accepted = python(
      "normalize_candidates.py",
      ...args,
      "--allow-missing-in-scope",
    );
    expect(accepted.status, accepted.stderr).toBe(0);
    const contents = readFileSync(output, "utf8");
    expect(contents).toContain("Résumé: missing guard");
    const normalized = contents
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as { locations: { path: string }[] });
    expect(normalized.map((entry) => entry.locations[0]?.path).sort()).toEqual([
      "src/handler.py",
      "src/second.py",
    ]);

    writeFileSync(inventory, "../escaped.py\nsrc/handler.py\n");
    const escaped = python(
      "normalize_candidates.py",
      ...args,
      "--allow-missing-in-scope",
    );
    expect(escaped.status).toBe(2);
    expect(escaped.stderr).toContain("in-scope file row 1");
  });

  test("streams maximum-size preflight checks through the MCP workbench", async () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/handler.py", "value = 1\n");
    createMcpDirectories(root);
    const client = await startMcp(root);
    const owner = "preflight-stdin-owner";

    try {
      const started = await client.call(
        "start_codex_security_prompt_only_scan",
        { mode: "standard", targetPath: repository, scope: "." },
        owner,
      );
      const scanId = (started["scan"] as JsonObject)["scanId"] as string;
      const preflightChecks = Array.from({ length: 32 }, (_, index) => ({
        capability: `windows_process_boundary_${index}`,
        reason: "é".repeat(1_200),
        severity: "warn",
        status: "fail",
      }));
      expect(JSON.stringify(preflightChecks).length).toBeGreaterThan(
        32 * 1_024,
      );

      await client.call(
        "update_codex_security_scan_progress",
        { scanId, phase: "preflight", preflightChecks },
        owner,
      );
    } finally {
      await client.close();
    }
  });

  test("streams oversized option-like user context through the MCP workbench", async () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/handler.py", "value = 1\n");
    createMcpDirectories(root);
    const client = await startMcp(root);
    const userContext = `--${"é".repeat(64 * 1_024)}`;

    try {
      const selection = {
        mode: "standard",
        targetPath: repository,
        scope: ".",
        userContext,
      };
      const opened = await client.call(
        "open_codex_security_workspace",
        selection,
        "user-context-stdin-owner",
      );
      expect((opened["workspace"] as JsonObject)["userContext"]).toBe(
        userContext,
      );
      const sessionId = (opened["workspace"] as JsonObject)["id"] as string;
      const saved = await client.call(
        "submit_codex_security_setup",
        { ...selection, sessionId },
        "user-context-stdin-owner",
      );
      expect((saved["workspace"] as JsonObject)["userContext"]).toBe(
        userContext,
      );

      const started = await client.call(
        "start_codex_security_prompt_only_scan",
        selection,
        "user-context-stdin-owner",
      );
      const scan = started["scan"] as JsonObject;
      expect(scan["userContext"]).toBe(userContext);
      const updated = await client.call(
        "update_codex_security_scan_context",
        { scanId: scan["scanId"], userContext: "" },
        "user-context-stdin-owner",
      );
      expect((updated["scan"] as JsonObject)["userContext"]).toBeNull();
    } finally {
      await client.close();
    }
  }, 30_000);

  test.each(["object", "Markdown"])(
    "MCP diff retains %s",
    async (format) => {
      const { root, repository } = createRepository();
      writeSource(repository, "src/guard.py", "allowed = True\n");
      writeSource(repository, "src/handler.py", "value = 1\n");
      git(repository, "add", ".");
      git(repository, "commit", "-qm", "base");
      const baseRevision = git(repository, "rev-parse", "HEAD");
      rmSync(join(repository, "src", "guard.py"));
      writeSource(repository, "src/handler.py", "value = 2\n");
      git(repository, "add", ".");
      git(repository, "commit", "-qm", "changed");
      const headRevision = git(repository, "rev-parse", "HEAD");
      createMcpDirectories(root);
      const client = await startMcp(root);
      const owner = "compact-diff-owner";
      const call = (name: string, args: JsonObject) =>
        client.call(name, args, owner);

      try {
        const tools = (await client.request("tools/list", {}))["tools"] as {
          name: string;
          inputSchema: { properties: Record<string, { maxLength?: number }> };
        }[];
        expect(tools.map((tool) => tool.name)).toContain(
          "prepare_codex_security_review_items",
        );
        expect(tools.map((tool) => tool.name)).toContain(
          "record_codex_security_discovery_candidates",
        );
        const preservedContextMaxLength = tools.find(
          (tool) => tool.name === "start_codex_security_standard_scan",
        )?.inputSchema.properties["userContext"]?.maxLength;
        expect(preservedContextMaxLength).toBeUndefined();

        const selection = {
          targetPath: repository,
          scope: ".",
          mode: "diff",
          diffTarget: { kind: "range", baseRevision, headRevision },
        };
        const opened = await call("open_codex_security_workspace", selection);
        const openedWorkspace = opened["workspace"] as JsonObject;
        const selectedDiffTarget = openedWorkspace["diffTarget"] as JsonObject;
        const contentDigest = selectedDiffTarget["contentDigest"] as string;
        expect(contentDigest).toMatch(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        );
        const sessionId = openedWorkspace["id"] as string;
        await call("submit_codex_security_setup", {
          ...selection,
          diffTarget: selectedDiffTarget,
          sessionId,
        });
        const started = await call("start_codex_security_scan", { sessionId });
        const results = (started["workspace"] as JsonObject)[
          "results"
        ] as JsonObject;
        const scanId = results["scanId"] as string;
        const handoffClaimToken = randomUUID();
        await call("claim_codex_security_scan_handoff_delivery", {
          scanId,
          claimToken: handoffClaimToken,
        });
        await call("attach_codex_security_scan_continuation_thread", {
          scanId,
          claimToken: handoffClaimToken,
          threadId: owner,
        });
        const context = await call("get_codex_security_scan_context", {
          scanId,
          handoffClaimToken,
        });
        const scanDir = (context["scan"] as JsonObject)["scanDir"] as string;

        const inventory = await call("prepare_codex_security_review_items", {
          scanId,
          handoffClaimToken,
        });
        expect(inventory["reviewItemsTotal"]).toBe(2);
        const items = await call("list_codex_security_review_items", {
          scanId,
          handoffClaimToken,
        });
        expect(items["items"]).toEqual([
          { path: "src/guard.py" },
          { path: "src/handler.py" },
        ]);

        await call("record_codex_security_discovery_candidates", {
          scanId,
          candidates: [candidate("src/handler.py")],
        });
        const listed = await call("list_codex_security_candidates", { scanId });
        const rows = listed["rows"] as JsonObject[];
        expect(rows).toHaveLength(1);
        await call("record_codex_security_candidate_validations", {
          scanId,
          validations: [
            {
              candidateId: rows[0]?.["candidate_id"],
              validation: {
                disposition: "suppressed",
                method: "Static review of the changed handler.",
                confidence: "high",
                confidence_rationale: "The assignment is directly visible.",
                rubric: ["The assignment does not cross a trust boundary."],
                evidence: ["value = 2"],
                counterevidence_or_proof_gap: "No sensitive operation exists.",
                remaining_uncertainty: "",
              },
            },
          ],
        });
        await call("record_candidate_attack_paths", {
          scanId,
          attackPaths: [],
        });
        const canonicalModel = {
          summary:
            "A local handler processes selected input (src/handler.py:1).",
          assets: ["Integrity of the selected result."],
          trustBoundaries: [
            "Caller input reaches the handler without authority over private state (src/handler.py:1).",
          ],
          attackerCapabilities: [
            "A caller can choose input but cannot choose another user's state.",
          ],
          securityObjectives: ["Keep each result bound to its selected input."],
          assumptions: [
            "A shared-service deployment has not been established.",
          ],
        };
        const markdownFact =
          "Selected input stays separate from private state (src/handler.py:1).";
        const savedModelPath = join(
          scanDir,
          "artifacts",
          "01_context",
          "threat_model.md",
        );
        mkdirSync(dirname(savedModelPath), { recursive: true, mode: 0o700 });
        writeFileSync(
          savedModelPath,
          `# Saved threat model\n\n${markdownFact}\n`,
        );
        const threatModel =
          format === "Markdown"
            ? { summary: readFileSync(savedModelPath, "utf8") }
            : canonicalModel;
        const openQuestions = [
          {
            question:
              "Does a supported embedding share this worker across callers?",
            followUpPrompt:
              "Confirm the deployment's ownership and isolation controls.",
          },
        ];
        const coverageNote =
          "The handler does not grant access to another caller's state (src/handler.py:1).";
        const finding = {
          ruleId: "path-traversal.archive-extraction",
          title: "Unsafe archive extraction",
          summary: "An untrusted archive entry reaches a filesystem write.",
          severity: { level: "high" },
          confidence: {
            level: "high",
            rationale: "Source evidence establishes reachability.",
          },
          taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
          locations: [{ path: "src/handler.py", startLine: 1 }],
          remediation: "Validate each output path before writing.",
          provenance: { source: "local_plugin" },
        };
        const invalidRootCauseReference = await client.request("tools/call", {
          name: "record_codex_security_scan_draft",
          arguments: {
            scanId,
            handoffClaimToken,
            findings: [
              {
                ...finding,
                root_cause: {
                  evidenceRefs: ["missing-root-cause-evidence"],
                },
              },
            ],
            coverage: {
              completeness: "complete",
              surfaces: [{ label: "Changed files", disposition: "rejected" }],
              explicitExclusions: [],
              deferred: [],
            },
          },
          _meta: { "openai/threadId": owner },
        });
        expect(invalidRootCauseReference["isError"]).toBe(true);
        expect(JSON.stringify(invalidRootCauseReference)).toContain(
          "root_cause.evidenceRefs",
        );
        await call("record_codex_security_scan_draft", {
          scanId,
          handoffClaimToken,
          findings: [
            {
              ...finding,
              identity: {
                anchor: "candidate-duplicate-instance",
                instance: "dss-147-a",
              },
            },
            {
              ...finding,
              extensions: {
                candidateId: "candidate-duplicate-instance",
                reportId: "DSS-147-A",
              },
            },
          ],
          coverage: {
            completeness: "complete",
            surfaces: [{ label: "Changed files", disposition: "rejected" }],
            explicitExclusions: [],
            deferred: [],
          },
        });
        expect(
          (
            JSON.parse(
              readFileSync(join(scanDir, "findings.json"), "utf8"),
            ) as {
              findings: JsonObject[];
            }
          ).findings.map((draftFinding) => draftFinding["identity"]),
        ).toEqual([
          { anchor: "candidate-duplicate-instance", instance: "dss-147-a" },
          { anchor: "candidate-duplicate-instance", instance: "dss-147-a" },
        ]);
        await call("record_codex_security_scan_draft", {
          scanId,
          handoffClaimToken,
          findings: [
            {
              ...finding,
              extensions: {
                candidateId: "candidate-singleton",
                reportId: "DSS-144-A",
              },
            },
            {
              ...finding,
              code_evidence: [
                {
                  code: "value = 2",
                  id: "legacy-source",
                },
              ],
              attackPath: {
                dataflow: { evidence_refs: ["legacy-source"] },
              },
            },
            {
              ...finding,
              ruleId: "path-traversal.archive-upload",
              identity: {
                anchor: "candidate-cross-rule",
                instance: "shared-report",
              },
            },
            {
              ...finding,
              extensions: {
                candidateId: "candidate-cross-rule",
                reportId: "shared-report",
              },
            },
            {
              ...finding,
              extensions: {
                candidateId: "candidate-cross-rule",
                reportId: "second-report",
              },
            },
            {
              ...finding,
              identity: {
                anchor: "candidate-authored-instance",
                instance: "dss-147-a",
              },
            },
            {
              ...finding,
              extensions: {
                candidateId: "candidate-authored-instance",
                reportId: "DSS-147-B",
              },
            },
            {
              ...finding,
              extensions: {
                candidateId: "candidate-authored-instance",
                ledgerRowId: "ledger-row-c",
              },
            },
          ],
          threatModel,
          coverage: {
            completeness: "complete",
            surfaces: [
              {
                label: "Changed files",
                disposition: "rejected",
                notes: coverageNote,
              },
            ],
            explicitExclusions: [],
            deferred: [],
            openQuestions,
          },
        });
        const draftManifest = JSON.parse(
          readFileSync(join(scanDir, "scan-manifest.json"), "utf8"),
        ) as JsonObject;
        const draftTarget = (draftManifest["scan"] as JsonObject)[
          "target"
        ] as JsonObject;
        expect(draftTarget["snapshotDigest"]).toBe(contentDigest);
        const canonicalDraftIdentities = (
          JSON.parse(readFileSync(join(scanDir, "findings.json"), "utf8")) as {
            findings: JsonObject[];
          }
        ).findings.map((draftFinding) => draftFinding["identity"]);
        expect(canonicalDraftIdentities).toHaveLength(9);
        const legacyCoordinateDigest = `codex-security-snapshot/v1:sha256:${createHash(
          "sha256",
        )
          .update("codex-security-diff/v1\0")
          .update("range")
          .update("\0")
          .update(baseRevision)
          .update("\0")
          .update(headRevision)
          .digest("hex")}`;
        await call("complete_codex_security_scan", {
          scanId,
          handoffClaimToken,
        });
        const completed = await call("get_codex_security_completed_scan", {
          scanId,
          handoffClaimToken,
        });
        const target = (
          (completed["manifest"] as JsonObject)["scan"] as JsonObject
        )["target"] as JsonObject;
        expect(target["snapshotDigest"]).toBe(contentDigest);
        expect((completed["coverage"] as JsonObject)["inventoryStrategy"]).toBe(
          "diff",
        );
        const completedIdentities = (
          (completed["findings"] as JsonObject)["findings"] as JsonObject[]
        ).map((completedFinding) => completedFinding["identity"]);
        expect(completedIdentities).toEqual(canonicalDraftIdentities);
        expect(completedIdentities).toEqual([
          { anchor: "candidate-singleton", instance: "dss-144-a" },
          { anchor: "unsafe-archive-extraction" },
          { anchor: "candidate-cross-rule", instance: "shared-report" },
          { anchor: "candidate-cross-rule", instance: "shared-report" },
          { anchor: "candidate-cross-rule", instance: "second-report" },
          { anchor: "candidate-authored-instance", instance: "dss-147-a" },
          {
            anchor: "candidate-authored-instance",
            instance: "dss-147-b",
          },
          { anchor: "candidate-authored-instance", instance: "ledger-row-c" },
          { anchor: "candidate-duplicate-instance", instance: "dss-147-a" },
        ]);
        const legacyFinding = (
          (completed["findings"] as JsonObject)["findings"] as JsonObject[]
        )[1];
        expect(legacyFinding?.["code_evidence"]).toEqual([
          { code: "value = 2", id: "legacy-source" },
        ]);
        expect(legacyFinding?.["attackPath"]).toEqual({
          dataflow: { evidence_refs: ["legacy-source"] },
        });
        expect(
          ((completed["manifest"] as JsonObject)["scan"] as JsonObject)[
            "threatModel"
          ],
        ).toEqual(threatModel);
        expect((completed["coverage"] as JsonObject)["openQuestions"]).toEqual(
          openQuestions,
        );
        const contract = await loadContract(scanDir, {
          pluginRoot: PLUGIN_ROOT,
        });
        expect(contract.manifest.scan.threatModel).toEqual(threatModel);
        expect(contract.coverage.openQuestions).toEqual(openQuestions);
        expect(contract.coverage.surfaces[0]?.notes).toBe(coverageNote);
        const report = readFileSync(join(scanDir, "report.md"), "utf8");
        const modelFacts =
          format === "Markdown"
            ? [markdownFact]
            : Object.values(canonicalModel).flat();
        for (const fact of modelFacts) {
          expect(report).toContain(fact);
        }
        expect(report).toContain(openQuestions[0]!.question);
        expect(report).toContain(openQuestions[0]!.followUpPrompt);
        expect(report).toContain(coverageNote);

        const terminalDir = join(root, "terminal-scan");
        mkdirSync(terminalDir, { mode: 0o700 });
        const markdownModel = `# Existing threat model\n\n## Assumptions\n\n${markdownFact}\n`;
        const terminalManifest = structuredClone(
          completed["manifest"],
        ) as JsonObject;
        const terminalScan = terminalManifest["scan"] as JsonObject;
        terminalScan["threatModel"] = { summary: markdownModel };
        (terminalScan["target"] as JsonObject)["snapshotDigest"] =
          legacyCoordinateDigest;
        delete terminalScan["sealedAt"];
        delete terminalScan["artifacts"];
        for (const [name, document] of [
          ["scan-manifest.json", terminalManifest],
          ["findings.json", completed["findings"]],
          ["coverage.json", completed["coverage"]],
        ] as const) {
          writeFileSync(join(terminalDir, name), JSON.stringify(document));
        }
        const finalized = python(
          "finalize_scan_contract.py",
          "--scan-dir",
          terminalDir,
          "--source-root",
          repository,
        );
        expect(finalized.status, finalized.stderr).toBe(0);
        const validated = python(
          "validate_scan_contract.py",
          "--scan-dir",
          terminalDir,
        );
        expect(validated.status, validated.stderr).toBe(0);
        const terminalResult = JSON.parse(
          readFileSync(join(terminalDir, "scan-manifest.json"), "utf8"),
        ) as {
          scan: {
            sealedAt: string;
            target: { snapshotDigest: string };
            threatModel: unknown;
          };
        };
        expect(terminalResult.scan.threatModel).toEqual({
          summary: markdownModel,
        });
        expect(terminalResult.scan.target.snapshotDigest).toBe(
          legacyCoordinateDigest,
        );
        expect(terminalResult.scan.sealedAt).toBeDefined();
        const terminalReport = readFileSync(
          join(terminalDir, "report.md"),
          "utf8",
        );
        expect(terminalReport).toContain(markdownFact);
        expect(terminalReport.match(/^#{1,2} .+$/gm)).toEqual(
          report.match(/^#{1,2} .+$/gm),
        );
      } finally {
        await client.close();
      }
    },
    30_000,
  );

  test.each(["commit", "range"] as const)(
    "accepts a new clean %s selection without a repeated digest",
    async (kind) => {
      const { root, repository } = createRepository();
      writeSource(repository, "fixture.txt", "base\n");
      git(repository, "add", "fixture.txt");
      git(repository, "commit", "-qm", "base");
      const baseRevision = git(repository, "rev-parse", "HEAD");
      writeSource(repository, "fixture.txt", "head\n");
      git(repository, "add", "fixture.txt");
      git(repository, "commit", "-qm", "head");
      const headRevision = git(repository, "rev-parse", "HEAD");
      createMcpDirectories(root);
      const client = await startMcp(root);
      const owner = `new-${kind}-owner`;
      const selection = {
        targetPath: repository,
        scope: ".",
        mode: "diff",
        diffTarget:
          kind === "commit"
            ? { kind, headRevision }
            : { kind, baseRevision, headRevision },
      };

      try {
        const opened = await client.call(
          "open_codex_security_workspace",
          selection,
          owner,
        );
        const sessionId = (opened["workspace"] as JsonObject)["id"] as string;
        writeSource(repository, "fixture.txt", "next\n");
        git(repository, "add", "fixture.txt");
        git(repository, "commit", "-qm", "next");
        const nextRevision = git(repository, "rev-parse", "HEAD");
        const nextDiffTarget =
          kind === "commit"
            ? { kind, headRevision: nextRevision }
            : {
                kind,
                baseRevision: headRevision,
                headRevision: nextRevision,
              };

        const submitted = await client.call(
          "submit_codex_security_setup",
          {
            targetPath: repository,
            scope: ".",
            mode: "diff",
            diffTarget: nextDiffTarget,
            sessionId,
          },
          owner,
        );
        const submittedDiffTarget = (submitted["workspace"] as JsonObject)[
          "diffTarget"
        ] as JsonObject;
        expect(submittedDiffTarget).toMatchObject(nextDiffTarget);
        expect(submittedDiffTarget["contentDigest"]).toMatch(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        );
        expect(workspaceDiffSelection(root, sessionId).contentDigest).toBe(
          submittedDiffTarget["contentDigest"] as string,
        );
        expect(workbenchState(root)).toEqual({
          workspaces: 1,
          submitted: 1,
          scans: 0,
        });

        await client.call("start_codex_security_scan", { sessionId }, owner);
        expect(workbenchState(root)).toEqual({
          workspaces: 1,
          submitted: 1,
          scans: 1,
        });
      } finally {
        await client.close();
      }
    },
    30_000,
  );

  test.each(["commit", "range"] as const)(
    "recovers a persisted NULL-digest %s workspace after a missing blob is restored",
    async (kind) => {
      const { root, repository } = createRepository();
      writeSource(repository, "fixture.txt", "base\n");
      git(repository, "add", "fixture.txt");
      git(repository, "commit", "-qm", "base");
      const baseRevision = git(repository, "rev-parse", "HEAD");
      writeSource(repository, "fixture.txt", "head\n");
      git(repository, "add", "fixture.txt");
      git(repository, "commit", "-qm", "head");
      const headRevision = git(repository, "rev-parse", "HEAD");
      const blob = git(repository, "rev-parse", `${headRevision}:fixture.txt`);
      const objectPath = join(
        repository,
        ".git",
        "objects",
        blob.slice(0, 2),
        blob.slice(2),
      );
      const backupPath = `${objectPath}.missing`;
      mkdirSync(join(repository, "nested"));
      const selectedPath = join(repository, "nested", "..");
      createMcpDirectories(root);
      const client = await startMcp(root);
      const owner = `missing-blob-${kind}-owner`;
      const selection = {
        targetPath: selectedPath,
        scope: ".",
        mode: "diff",
        diffTarget:
          kind === "commit"
            ? { kind, headRevision }
            : { kind, baseRevision, headRevision },
      };

      try {
        renameSync(objectPath, backupPath);
        const opened = await client.call(
          "open_codex_security_workspace",
          selection,
          owner,
        );
        renameSync(backupPath, objectPath);
        const openedWorkspace = opened["workspace"] as JsonObject;
        const sessionId = openedWorkspace["id"] as string;
        expect(openedWorkspace["setupValidation"]).toMatchObject({
          valid: false,
        });
        expect(JSON.stringify(openedWorkspace["setupValidation"])).toContain(
          "Could not snapshot the selected committed changes.",
        );
        expect(workspaceDiffSelection(root, sessionId)).toEqual({
          baseRevision: kind === "commit" ? null : baseRevision,
          contentDigest: null,
          headRevision,
        });

        const omittedDigest = await client.request("tools/call", {
          name: "submit_codex_security_setup",
          arguments: { ...selection, sessionId },
          _meta: { "openai/threadId": owner },
        });
        expect(omittedDigest["isError"], JSON.stringify(omittedDigest)).toBe(
          true,
        );
        expect(JSON.stringify(omittedDigest)).toContain(
          "no longer produce the same diff",
        );
        expect(workspaceDiffSelection(root, sessionId)).toEqual({
          baseRevision: kind === "commit" ? null : baseRevision,
          contentDigest: null,
          headRevision,
        });

        const inspected = await client.call(
          "inspect_codex_security_setup",
          selection,
          owner,
        );
        const currentDiffTarget = (inspected["setup"] as JsonObject)[
          "diffTarget"
        ] as JsonObject;
        expect(currentDiffTarget).toMatchObject({
          baseRevision,
          headRevision,
          kind,
        });
        expect(currentDiffTarget["contentDigest"]).toMatch(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        );

        const submitted = await client.call(
          "submit_codex_security_setup",
          {
            ...selection,
            diffTarget: currentDiffTarget,
            sessionId,
          },
          owner,
        );
        expect(
          ((submitted["workspace"] as JsonObject)["diffTarget"] as JsonObject)[
            "contentDigest"
          ],
        ).toBe(currentDiffTarget["contentDigest"]);
        expect(workspaceDiffSelection(root, sessionId)).toEqual({
          baseRevision,
          contentDigest: currentDiffTarget["contentDigest"] as string,
          headRevision,
        });
        expect(workbenchState(root)).toEqual({
          workspaces: 1,
          submitted: 1,
          scans: 0,
        });

        await client.call("start_codex_security_scan", { sessionId }, owner);
        expect(workbenchState(root)).toEqual({
          workspaces: 1,
          submitted: 1,
          scans: 1,
        });
      } finally {
        if (existsSync(backupPath)) renameSync(backupPath, objectPath);
        await client.close();
      }
    },
    30_000,
  );

  test.each(["commit", "range"] as const)(
    "rejects a stale %s selection through the bundled MCP",
    async (kind) => {
      const { root, repository } = createRepository();
      writeSource(repository, "fixture.txt", "base\n");
      git(repository, "add", "fixture.txt");
      git(repository, "commit", "-qm", "base");
      const baseRevision = git(repository, "rev-parse", "HEAD");
      writeSource(repository, "fixture.txt", "head\n");
      git(repository, "add", "fixture.txt");
      git(repository, "commit", "-qm", "head");
      const headRevision = git(repository, "rev-parse", "HEAD");
      createMcpDirectories(root);
      const client = await startMcp(root);
      const owner = `stale-${kind}-owner`;
      const requestedDiffTarget =
        kind === "commit"
          ? { kind, headRevision }
          : { kind, baseRevision, headRevision };
      const selection = {
        targetPath: repository,
        scope: ".",
        mode: "diff",
        diffTarget: requestedDiffTarget,
      };

      try {
        const opened = await client.call(
          "open_codex_security_workspace",
          selection,
          owner,
        );
        const workspace = opened["workspace"] as JsonObject;
        const sessionId = workspace["id"] as string;
        const selectedDiffTarget = workspace["diffTarget"] as JsonObject;
        expect(selectedDiffTarget["kind"]).toBe(kind);
        expect(selectedDiffTarget["contentDigest"]).toMatch(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        );
        expect(workbenchState(root)).toEqual({
          workspaces: 1,
          submitted: 0,
          scans: 0,
        });

        const selectedBlob = git(
          repository,
          "rev-parse",
          `${headRevision}:fixture.txt`,
        );
        const replacement = execFileSync(
          "git",
          ["hash-object", "-w", "--stdin"],
          { cwd: repository, encoding: "utf8", input: "substituted\n" },
        ).trim();
        git(repository, "replace", "-f", selectedBlob, replacement);

        const inspected = await client.call(
          "inspect_codex_security_setup",
          selection,
          owner,
        );
        const currentDiffTarget = (inspected["setup"] as JsonObject)[
          "diffTarget"
        ] as JsonObject;
        expect(currentDiffTarget["contentDigest"]).toMatch(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        );
        expect(currentDiffTarget["contentDigest"]).not.toBe(
          selectedDiffTarget["contentDigest"],
        );
        const withoutContentDigest = { ...selectedDiffTarget };
        delete withoutContentDigest["contentDigest"];
        for (const diffTarget of [
          withoutContentDigest,
          selectedDiffTarget,
          currentDiffTarget,
        ]) {
          const submitted = await client.request("tools/call", {
            name: "submit_codex_security_setup",
            arguments: {
              ...selection,
              diffTarget,
              sessionId,
            },
            _meta: { "openai/threadId": owner },
          });
          expect(submitted["isError"], JSON.stringify(submitted)).toBe(true);
          expect(JSON.stringify(submitted)).toContain(
            "no longer produce the same diff",
          );
          expect(workbenchState(root)).toEqual({
            workspaces: 1,
            submitted: 0,
            scans: 0,
          });
          expect(workspaceDiffSelection(root, sessionId).contentDigest).toBe(
            selectedDiffTarget["contentDigest"] as string,
          );
        }

        const started = await client.request("tools/call", {
          name: "start_codex_security_scan",
          arguments: { sessionId },
          _meta: { "openai/threadId": owner },
        });
        expect(started["isError"], JSON.stringify(started)).toBe(true);
        expect(JSON.stringify(started)).toContain(
          "Save the Codex Security setup",
        );
        expect(workbenchState(root)).toEqual({
          workspaces: 1,
          submitted: 0,
          scans: 0,
        });

        const replacementWorkspace = await client.call(
          "open_codex_security_workspace",
          { ...selection, diffTarget: currentDiffTarget },
          owner,
        );
        const replacementSessionId = (
          replacementWorkspace["workspace"] as JsonObject
        )["id"] as string;
        expect(replacementSessionId).not.toBe(sessionId);
        await client.call(
          "submit_codex_security_setup",
          {
            ...selection,
            diffTarget: currentDiffTarget,
            sessionId: replacementSessionId,
          },
          owner,
        );
        expect(
          workspaceDiffSelection(root, replacementSessionId).contentDigest,
        ).toBe(currentDiffTarget["contentDigest"] as string);
        expect(workbenchState(root)).toEqual({
          workspaces: 2,
          submitted: 1,
          scans: 0,
        });
        await client.call(
          "start_codex_security_scan",
          { sessionId: replacementSessionId },
          owner,
        );
        expect(workbenchState(root)).toEqual({
          workspaces: 2,
          submitted: 1,
          scans: 1,
        });
      } finally {
        await client.close();
      }
    },
    30_000,
  );
});
