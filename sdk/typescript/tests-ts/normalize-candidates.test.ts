import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  normalizerArguments as argumentsFor,
  runPythonNormalizer as runPython,
  runTypeScriptNormalizer as runTypeScript,
  writeSource,
} from "./support/normalize-candidates.js";

const temporaryRoots: string[] = [];
const directoryLinkType = process.platform === "win32" ? "junction" : "dir";

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function fixture(): { root: string; repository: string } {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-normalizer-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  mkdirSync(repository);
  return { root, repository };
}

describe("TypeScript candidate normalizer prototype", () => {
  test("matches Python output for normalization, merging, and deleted scope entries", () => {
    const { root, repository } = fixture();
    writeSource(repository, "src/alpha.ts", "alpha\rsecond\r");
    writeSource(repository, "src/é-handler.ts", "one\ntwo\nthree\n");
    const inventory = join(root, "in-scope.txt");
    writeFileSync(
      inventory,
      "src/alpha.ts\r\nsrc/é-handler.ts\r\nsrc/deleted.ts\r\n",
    );
    const sharedLocations = [
      {
        path: "src/é-handler.ts",
        start_line: 2,
        end_line: 2,
        role: "sink",
      },
      { path: "src/alpha.ts", start_line: 1, role: "source" },
      { path: "src/alpha.ts", start_line: 1, role: "source" },
    ];
    const firstInput = join(root, "a-candidates.jsonl");
    const secondInput = join(root, "z-candidates.jsonl");
    writeFileSync(
      firstInput,
      `${JSON.stringify({
        candidate_id: " ignored-upstream-id ",
        cwe_ids: ["CWE-89", "cwe-079"],
        locations: sharedLocations.slice().reverse(),
        summary: " Résumé: missing guard ",
        evidence: "earlier evidence",
        context: "first context",
        instance: " route:a ",
      })}\n`,
    );
    writeFileSync(
      secondInput,
      [
        "",
        JSON.stringify({
          cwe_ids: [" CWE-089 ", "CWE-79", "CWE-89"],
          locations: sharedLocations,
          summary: "Zeta summary",
          evidence: "later evidence",
          context: "second context",
          instance: "route:a",
        }),
        JSON.stringify({
          cwe_ids: ["CWE-79", "CWE-89"],
          locations: sharedLocations,
          summary: "\ue000 private-use summary",
          evidence: "later evidence",
          instance: "route:a",
        }),
        JSON.stringify({
          cwe_ids: ["CWE-89", "CWE-79"],
          locations: sharedLocations,
          summary: "😀 non-BMP summary",
          evidence: "earlier evidence",
          instance: "route:a",
        }),
        JSON.stringify({
          cwe_ids: [],
          locations: [
            { path: "src/alpha.ts", start_line: 2, role: "evidence" },
          ],
          summary: "Independent candidate",
          evidence: "Separate identity",
        }),
        "",
      ].join("\n"),
    );
    const pythonOutput = join(root, "python.jsonl");
    const typescriptOutput = join(root, "typescript.jsonl");
    writeFileSync(pythonOutput, "stale\n");
    writeFileSync(typescriptOutput, "stale\n");

    const pythonResult = runPython(
      argumentsFor(
        [secondInput, firstInput],
        pythonOutput,
        repository,
        inventory,
        true,
      ),
    );
    const typescriptResult = runTypeScript(
      argumentsFor(
        [secondInput, firstInput],
        typescriptOutput,
        repository,
        inventory,
        true,
      ),
    );

    expect(pythonResult.status, pythonResult.stderr).toBe(0);
    expect(typescriptResult.status, typescriptResult.stderr).toBe(0);
    const expected = readFileSync(pythonOutput);
    expect(readFileSync(typescriptOutput).equals(expected)).toBe(true);
    expect(expected.toString("utf8")).toBe(
      '{"candidate_id":"candidate-b61c9dbdc94bb668","context":"first context\\nsecond context","cwe_ids":["CWE-79","CWE-89"],"evidence":"earlier evidence\\nlater evidence","instance":"route:a","locations":[{"end_line":1,"path":"src/alpha.ts","role":"source","start_line":1},{"end_line":2,"path":"src/é-handler.ts","role":"sink","start_line":2}],"summary":"Résumé: missing guard\\nZeta summary\\n\ue000 private-use summary\\n😀 non-BMP summary"}\n' +
        '{"candidate_id":"candidate-cc6760fcb9e3a98d","cwe_ids":[],"evidence":"Separate identity","locations":[{"end_line":2,"path":"src/alpha.ts","role":"evidence","start_line":2}],"summary":"Independent candidate"}\n',
    );
    const rows = expected
      .toString("utf8")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(rows).toHaveLength(2);
    expect(rows).toContainEqual(
      expect.objectContaining({
        cwe_ids: ["CWE-79", "CWE-89"],
        context: "first context\nsecond context",
        evidence: "earlier evidence\nlater evidence",
        summary:
          "Résumé: missing guard\nZeta summary\n\ue000 private-use summary\n😀 non-BMP summary",
      }),
    );
  });

  test("rejects the same semantic contract violations as Python", () => {
    const { root, repository } = fixture();
    writeSource(repository, "src/in-scope.ts", "one\ntwo\n");
    writeSource(repository, "src/out-of-scope.ts", "one\n");
    writeSource(root, "outside.ts", "outside\n");
    const inventory = join(root, "in-scope.txt");
    writeFileSync(inventory, "src/in-scope.ts\n");
    const base = {
      cwe_ids: ["CWE-89"],
      locations: [{ path: "src/in-scope.ts", start_line: 1, role: "source" }],
      summary: "Candidate",
      evidence: "Evidence",
    };
    const cases = [
      {
        name: "unknown field",
        row: { ...base, unexpected: true },
        message: "unsupported fields unexpected",
      },
      {
        name: "out of scope",
        row: {
          ...base,
          locations: [
            {
              path: "src/out-of-scope.ts",
              start_line: 1,
              role: "source",
            },
          ],
        },
        message: "expected at least one in-scope file",
      },
      {
        name: "line range",
        row: {
          ...base,
          locations: [
            { path: "src/in-scope.ts", start_line: 3, role: "source" },
          ],
        },
        message: "line range 3-3 exceeds src/in-scope.ts:2",
      },
      {
        name: "path traversal",
        row: {
          ...base,
          locations: [{ path: "../outside.ts", start_line: 1, role: "source" }],
        },
        message: "repository-relative path without traversal",
      },
    ];

    for (const [index, item] of cases.entries()) {
      const input = join(root, `invalid-${index}.jsonl`);
      writeFileSync(input, `${JSON.stringify(item.row)}\n`);
      const pythonResult = runPython(
        argumentsFor(
          [input],
          join(root, `python-${index}.jsonl`),
          repository,
          inventory,
        ),
      );
      const typescriptResult = runTypeScript(
        argumentsFor(
          [input],
          join(root, `typescript-${index}.jsonl`),
          repository,
          inventory,
        ),
      );
      expect(pythonResult.status, item.name).toBe(2);
      expect(typescriptResult.status, item.name).toBe(2);
      expect(pythonResult.stderr, item.name).toContain(item.message);
      expect(typescriptResult.stderr, item.name).toContain(item.message);
    }
  });

  test("matches argparse equals and abbreviated long-option forms", () => {
    const { root, repository } = fixture();
    writeSource(repository, "src/in-scope.ts", "one\n");
    const inventory = join(root, "in scope.txt");
    const input = join(root, "candidate input.jsonl");
    writeFileSync(inventory, "src/in-scope.ts\n");
    writeFileSync(
      input,
      `${JSON.stringify({
        cwe_ids: ["CWE-79"],
        locations: [{ path: "src/in-scope.ts", start_line: 1, role: "source" }],
        summary: "Candidate",
        evidence: "Evidence",
      })}\n`,
    );
    const forms = [
      {
        name: "equals",
        args: (output: string) => [
          `--input=${input}`,
          `--out=${output}`,
          `--repo-root=${repository}`,
          `--in-scope-files=${inventory}`,
        ],
      },
      {
        name: "abbreviations",
        args: (output: string) => [
          `--inp=${input}`,
          `--o=${output}`,
          `--repo=${repository}`,
          `--in-s=${inventory}`,
          "--a",
        ],
      },
    ];

    for (const [index, form] of forms.entries()) {
      const pythonOutput = join(root, `python-arguments-${index}.jsonl`);
      const typescriptOutput = join(
        root,
        `typescript-arguments-${index}.jsonl`,
      );
      const pythonResult = runPython(form.args(pythonOutput));
      const typescriptResult = runTypeScript(form.args(typescriptOutput));
      expect(pythonResult.status, form.name).toBe(0);
      expect(typescriptResult.status, form.name).toBe(0);
      expect(
        readFileSync(typescriptOutput).equals(readFileSync(pythonOutput)),
        form.name,
      ).toBe(true);
    }

    for (const args of [["--in"], ["--allow-missing-in-scope=true"]]) {
      expect(runPython(args).status).toBe(2);
      expect(runTypeScript(args).status).toBe(2);
    }
  });

  test("rejects a deleted scope path through an escaping directory link", () => {
    const { root, repository } = fixture();
    const outside = join(root, "outside");
    mkdirSync(outside);
    symlinkSync(outside, join(repository, "linked"), directoryLinkType);
    writeSource(repository, "src/in-scope.ts", "one\n");
    const inventory = join(root, "in-scope.txt");
    const input = join(root, "candidates.jsonl");
    writeFileSync(inventory, "linked/deleted.ts\nsrc/in-scope.ts\n");
    writeFileSync(
      input,
      `${JSON.stringify({
        cwe_ids: [],
        locations: [{ path: "src/in-scope.ts", start_line: 1, role: "source" }],
        summary: "Candidate",
        evidence: "Evidence",
      })}\n`,
    );
    const pythonResult = runPython(
      argumentsFor(
        [input],
        join(root, "python.jsonl"),
        repository,
        inventory,
        true,
      ),
    );
    const typescriptResult = runTypeScript(
      argumentsFor(
        [input],
        join(root, "typescript.jsonl"),
        repository,
        inventory,
        true,
      ),
    );

    expect(pythonResult.status).toBe(2);
    expect(typescriptResult.status).toBe(2);
    expect(pythonResult.stderr).toContain("path escapes repository");
    expect(typescriptResult.stderr).toContain("path escapes repository");
  });

  test("resolves output parent components after directory links", () => {
    const { root, repository } = fixture();
    writeSource(repository, "src/in-scope.ts", "one\n");
    const inventory = join(root, "in-scope.txt");
    const input = join(root, "candidates.jsonl");
    writeFileSync(inventory, "src/in-scope.ts\n");
    writeFileSync(
      input,
      `${JSON.stringify({
        cwe_ids: [],
        locations: [{ path: "src/in-scope.ts", start_line: 1, role: "source" }],
        summary: "Candidate",
        evidence: "Evidence",
      })}\n`,
    );
    const nestedOutput = join(root, "output", "nested");
    mkdirSync(nestedOutput, { recursive: true });
    const outputLink = join(root, "output-link");
    symlinkSync(nestedOutput, outputLink, directoryLinkType);
    const pythonOutput = join(root, "output", "python.jsonl");
    const typescriptOutput = join(root, "output", "typescript.jsonl");

    const pythonResult = runPython(
      argumentsFor(
        [input],
        `${outputLink}${sep}..${sep}python.jsonl`,
        repository,
        inventory,
      ),
    );
    const typescriptResult = runTypeScript(
      argumentsFor(
        [input],
        `${outputLink}${sep}..${sep}typescript.jsonl`,
        repository,
        inventory,
      ),
    );

    expect(pythonResult.status, pythonResult.stderr).toBe(0);
    expect(typescriptResult.status, typescriptResult.stderr).toBe(0);
    expect(
      readFileSync(typescriptOutput).equals(readFileSync(pythonOutput)),
    ).toBe(true);
  });
});
