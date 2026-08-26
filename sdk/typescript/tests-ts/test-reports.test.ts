import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import { bashCommand } from "./support/shell.js";

const bash = bashCommand();
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixtures() {
  const root = await mkdtemp(join(tmpdir(), "codex-security-test-reports-"));
  directories.push(root);
  return {
    root,
    async report(
      name: string,
      cases: string[],
      failures = 0,
      count = cases.length,
    ) {
      const path = join(root, name);
      await writeFile(
        path,
        `<testsuites tests="${count}" failures="${failures}" time="1.25"><testsuite>${cases.join("")}</testsuite></testsuites>`,
      );
      return path;
    },
  };
}

function testcase(name: string, status = "") {
  return `<testcase file="tests-ts/example.test.ts" classname="example" name="${name}">${status}</testcase>`;
}

async function runCommand(
  cmd: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; timeout?: number } = {},
) {
  const child = Bun.spawn({
    ...options,
    cmd,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { status, stdout, stderr };
}

async function compare(baseline: string, ...candidates: string[]) {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");
  return await runCommand([
    python,
    "-I",
    "-B",
    fileURLToPath(
      new URL("../scripts/compare-test-reports.py", import.meta.url),
    ),
    baseline,
    ...candidates,
  ]);
}

describe("CI file shards", () => {
  test("balances slow files without dropping new files or depending on discovery order", async () => {
    const { partitionTestFiles } = (await import(
      new URL("../scripts/test-shards.mjs", import.meta.url).href
    )) as {
      partitionTestFiles: (
        files: string[],
        count: number,
        platform: string,
      ) => string[][];
    };
    const files = [
      "runtime.test.ts",
      "scan-recovery.test.ts",
      "api.test.ts",
      "new.test.ts",
    ];
    for (const platform of ["linux", "darwin", "win32"]) {
      const shards = partitionTestFiles(files, 3, platform);
      expect(shards.flat().sort()).toEqual([...files].sort());
      expect(shards).toEqual(
        partitionTestFiles([...files].reverse(), 3, platform),
      );
      expect(
        shards.every(
          (shard) =>
            shard.filter((file) => file !== "new.test.ts").length === 1,
        ),
      ).toBe(true);
    }
  });

  test("runs every shard, forwards Bun options, and preserves failures and separate reports", async () => {
    const { root } = await fixtures();
    await mkdir(join(root, "scripts"));
    await mkdir(join(root, "tests-ts", "nested"), { recursive: true });
    for (const file of ["run-ci-tests.mjs", "test-shards.mjs"]) {
      await copyFile(
        new URL(`../scripts/${file}`, import.meta.url),
        join(root, "scripts", file),
      );
    }
    for (const name of ["a", "b", "c", "nested/d"]) {
      await writeFile(
        join(root, "tests-ts", `${name}.test.ts`),
        `import { test, expect } from "bun:test"; test("${name}", () => expect(${name !== "a"}).toBe(true));\n`,
      );
    }
    const runner = join(root, "scripts", "run-ci-tests.mjs");
    const node = Bun.which("node");
    if (node === null) throw new Error("Node is required for the CI runner.");
    const run = (...args: string[]) =>
      runCommand([node, runner, ...args], {
        cwd: root,
        timeout: 30_000,
      });

    const failed = await run("--seed", "12345");
    expect(failed.status, failed.stderr).toBe(1);
    expect((await readdir(join(root, "reports"))).sort()).toEqual([
      "junit-1.xml",
      "junit-2.xml",
      "junit-3.xml",
      "junit-4.xml",
    ]);
    expect(
      await readFile(join(root, "reports", "junit-1.xml"), "utf8"),
    ).toContain("<failure");
    expect(
      await readFile(join(root, "reports", "junit-4.xml"), "utf8"),
    ).toContain('name="nested/d"');

    await rm(join(root, "reports"), { recursive: true });
    const selectedFailure = await run("1/2");
    expect(selectedFailure.status, selectedFailure.stderr).toBe(1);
    const selectedReports = (await readdir(join(root, "reports"))).sort();
    expect(selectedReports).toEqual(
      process.platform === "win32"
        ? ["junit-1-1.xml", "junit-1-2.xml"]
        : ["junit-1.xml"],
    );
    const selectedContents = await Promise.all(
      selectedReports.map((file) =>
        readFile(join(root, "reports", file), "utf8"),
      ),
    );
    expect(selectedContents.join("\n")).toContain('name="a"');
    expect(selectedContents.join("\n")).toContain('name="c"');
    expect(selectedContents.join("\n")).toContain("<failure");

    // Allow a worker with no matches when intentionally filtering the suite.
    const selected = await run(
      "1/2",
      "--test-name-pattern",
      "^c$",
      "--pass-with-no-tests",
    );
    expect(selected.status, selected.stderr).toBe(0);
    const report = await readFile(
      join(root, "reports", selectedReports.at(-1)!),
      "utf8",
    );
    expect(report).toContain('name="c"');
    expect(report).not.toContain("<failure");

    // A singleton shard must not start an empty worker that discovers all tests.
    await rm(join(root, "reports"), { recursive: true });
    const singleton = await run("2/4");
    expect(singleton.status, singleton.stderr).toBe(0);
    const singletonReports = await readdir(join(root, "reports"));
    expect(singletonReports).toEqual([
      process.platform === "win32" ? "junit-2-1.xml" : "junit-2.xml",
    ]);
    expect(
      await readFile(join(root, "reports", singletonReports[0]!), "utf8"),
    ).toContain('name="b"');
    expect((await run("0/2")).status).toBe(1);
    expect((await run("3/2")).status).toBe(1);
  });
});

describe("JUnit inventory comparison", () => {
  test("runs every workflow comparison before reporting a mismatch", async () => {
    const fixture = await fixtures();
    const workflow = Bun.YAML.parse(
      await readFile(
        new URL("../../../.github/workflows/test-quality.yml", import.meta.url),
        "utf8",
      ),
    ) as {
      jobs: { compare: { steps: Array<{ name?: string; run?: string }> } };
    };
    const script = workflow.jobs.compare.steps.find(
      (step) => step.name === "Compare inventories and outcomes",
    )!.run!;
    const expected = [
      ...["ubuntu-latest", "windows-latest"].flatMap((os) =>
        ["isolated", "parallel"].map(
          (mode) => `reports/runner-${os}-${mode}.xml`,
        ),
      ),
      "reports/runner-windows-latest-shard-*.xml",
    ];
    const mock = `python3() {
  printf '%s\\n' "$3"
  [[ "$3" != "$CODEX_SECURITY_TEST_FAIL_REPORT" ]]
}`;
    const summary = join(fixture.root, "summary.md");
    for (const failedReport of ["", expected[0]!]) {
      await writeFile(summary, "");
      const result = await runCommand(
        [bash, "-e", "-o", "pipefail", "-c", `${mock}\n${script}`],
        {
          cwd: fixture.root,
          env: {
            ...process.env,
            GITHUB_STEP_SUMMARY: "summary.md",
            CODEX_SECURITY_TEST_FAIL_REPORT: failedReport,
          },
          timeout: 10_000,
        },
      );
      expect(result.status, result.stderr).toBe(failedReport === "" ? 0 : 1);
      expect((await readFile(summary, "utf8")).trim().split(/\r?\n/u)).toEqual(
        expected,
      );
    }
  });

  test("merges native shards without depending on test order", async () => {
    const fixture = await fixtures();
    const passed = testcase("accepts &amp; preserves");
    const skipped = testcase("platform-only", "<skipped/>");
    const baseline = await fixture.report("baseline.xml", [passed, skipped]);
    await fixture.report("shard-1.xml", [skipped]);
    await fixture.report("shard-2.xml", [passed]);
    const result = await compare(baseline, join(fixture.root, "shard-*.xml"));
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("combined test time: 2.50s");
  });

  test("rejects ambiguous test identities even when totals match", async () => {
    const fixture = await fixtures();
    const first = testcase("same parameterized name");
    for (const [name, repeated] of [
      ["same-outcome", first],
      ["different-outcome", testcase("same parameterized name", "<skipped/>")],
    ] as const) {
      const baseline = await fixture.report(`${name}-baseline.xml`, [
        first,
        repeated,
      ]);
      const candidate = await fixture.report(`${name}-candidate.xml`, [
        first,
        repeated,
      ]);
      const result = await compare(baseline, candidate);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("duplicate test identity");
    }
  });

  test("reports every shard's timing even when an earlier shard fails", async () => {
    const fixture = await fixtures();
    const first = testcase("first");
    const second = testcase("second");
    const baseline = await fixture.report("baseline.xml", [first, second]);
    const failed = await fixture.report("shard-1.xml", [
      testcase("first", "<failure/>"),
    ]);
    const passed = await fixture.report("shard-2.xml", [second]);
    const result = await compare(baseline, failed, passed);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("test run failed");
    expect(result.stdout).toContain("shard-1.xml");
    expect(result.stdout).toContain("shard-2.xml");
  });

  test("rejects dropped, duplicated, skipped, failed, or incomplete results", async () => {
    const fixture = await fixtures();
    const first = testcase("first");
    const second = testcase("second");
    const baseline = await fixture.report("baseline.xml", [first, second]);
    for (const [name, cases, failures, count] of [
      ["missing", [first], 0, 1],
      ["duplicate", [first, second, second], 0, 3],
      ["skipped", [first, testcase("second", "<skipped/>")], 0, 2],
      ["failed", [first, testcase("second", "<failure/>")], 1, 2],
      ["summary-failed", [first, second], 1, 2],
      ["incomplete", [first], 0, 2],
      ["empty", [], 0, 0],
    ] as const) {
      const candidate = await fixture.report(
        `${name}.xml`,
        [...cases],
        failures,
        count,
      );
      expect((await compare(baseline, candidate)).status, name).toBe(1);
    }
    expect(
      (await compare(baseline, join(fixture.root, "absent-*.xml"))).status,
    ).toBe(1);
  });
});
