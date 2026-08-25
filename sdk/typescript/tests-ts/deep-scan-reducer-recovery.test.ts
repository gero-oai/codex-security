import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { expect, test } from "bun:test";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

function bundledFunction(runtime: string, name: string): string {
  const source = new RegExp(
    `function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}`,
    "u",
  ).exec(runtime)?.[0];
  if (!source) throw new Error(`Missing bundled runtime function: ${name}.`);
  return source;
}

type ReducerFinding = {
  ruleId: string;
  identity: { anchor: string };
  title: string;
  locations: Array<{ path: string; startLine: number }>;
  summary: string;
  taxonomy: { category: string; cwe: string[]; [field: string]: unknown };
  remediation: string;
  severity?: { level: string; [field: string]: unknown };
  confidence?: { level: string; rationale?: string; [field: string]: unknown };
  rootCause?:
    | {
        summary: string;
        evidenceRefs?: string[];
        [field: string]: unknown;
      }
    | string;
  root_cause?:
    | {
        summary?: string;
        evidenceRefs?: string[];
        evidence_refs?: string[];
        [field: string]: unknown;
      }
    | string;
  codeEvidence?: Array<{ id: string; code: string }>;
  validation?: { summary?: string; [field: string]: unknown } | null;
  attackPath?: Record<string, unknown> | null;
  writeup?: { reportPath: string };
  provenance: {
    source: string;
    sourceFindingIds?: string[];
    sourceFindings?: Array<{ id: string; finding: ReducerFinding }>;
    [field: string]: unknown;
  };
};

type ReducerDraft = {
  scanId: string;
  findings: ReducerFinding[];
  coverage: {
    completeness: "complete" | "partial" | "unknown";
    surfaces: Array<Record<string, unknown>>;
    explicitExclusions: Array<Record<string, unknown>>;
    deferred: Array<Record<string, unknown>>;
    [field: string]: unknown;
  };
  scope?: Record<string, unknown>;
  threatModel?: Record<string, unknown>;
};

function reducerFinding(anchor: string, summary = "Accepted worker evidence.") {
  return {
    ruleId: "synthetic.shared-control",
    identity: { anchor },
    title: `Accepted finding ${anchor}.`,
    locations: [{ path: "src/shared.ts", startLine: 10 }],
    summary,
    taxonomy: { category: "injection", cwe: ["CWE-89"] },
    remediation: "Apply the accepted input control.",
    provenance: { source: "local_plugin" },
  } satisfies ReducerFinding;
}

function reducerDraft(
  findings: ReducerFinding[],
  metadata: Partial<Omit<ReducerDraft, "scanId" | "findings">> = {},
): ReducerDraft {
  return {
    scanId: "synthetic-scan",
    findings,
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
    ...metadata,
  };
}

function bundledReducer(
  runtime: string,
  options: {
    files?: Map<string, ReducerDraft>;
    inspected?: Array<{ path: string; root: string }>;
    checkpoints?: ReducerDraft[];
    writes?: Array<{ path: string; result: ReducerDraft }>;
  } = {},
) {
  const start = runtime.indexOf("// src/deep-scan/artifact-validation.ts\n");
  const end = runtime.indexOf("\n// src/artifact-deep-reducer.ts\n", start);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  const preserveCoverage = new Function(
    [
      bundledFunction(runtime, "exactUnion"),
      bundledFunction(runtime, "preserveScanCoverage"),
      "return preserveScanCoverage;",
    ].join("\n"),
  )();
  return new Function(
    "require",
    "scanFindingIdentity",
    "preserveFindingDetails",
    "preserveScanCoverage",
    "parsePersistedScanDraft",
    "requireRegularFile",
    "readJsonObject",
    "saveScanDraftCheckpoint",
    "writeJsonAtomic",
    `${runtime.slice(start, end)}\nreturn { reconcileDeepReduction, validateReducerArtifacts };`,
  )(
    () => ({ isDeepStrictEqual }),
    (finding: ReducerFinding) =>
      JSON.stringify([finding.ruleId, finding.identity.anchor]),
    () => {},
    preserveCoverage,
    (value: ReducerDraft) => value,
    async (path: string, root: string) => {
      options.inspected?.push({ path, root });
    },
    async (path: string) => {
      const result = options.files?.get(path);
      if (!result) throw new Error(`Missing synthetic artifact: ${path}`);
      return structuredClone(result);
    },
    async (_context: unknown, result: ReducerDraft) => {
      options.checkpoints?.push(structuredClone(result));
    },
    async (path: string, result: ReducerDraft) => {
      const saved = structuredClone(result);
      options.writes?.push({ path, result: saved });
      options.files?.set(path, saved);
    },
  ) as {
    reconcileDeepReduction: (
      result: ReducerDraft,
      discoveries: Array<{ workerId: string; result: ReducerDraft }>,
      previous: ReducerDraft | null,
    ) => ReducerDraft;
    validateReducerArtifacts: (
      input: Record<string, unknown>,
      scanId: string,
    ) => Promise<{ newFindings: number }>;
  };
}

test("retains every accepted observation when workers report the same identity", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const first = reducerFinding("shared", "First accepted worker evidence.");
  const second = reducerFinding("shared", "Second accepted worker evidence.");
  const result = reducerDraft([
    {
      ...first,
      summary: `${first.summary}\n\n${second.summary}`,
      provenance: {
        ...first.provenance,
        sourceFindingIds: ["worker-first:0", "worker-second:0"],
      },
    },
  ]);

  const reduced = reconcileDeepReduction(
    result,
    [
      { workerId: "worker-first", result: reducerDraft([first]) },
      { workerId: "worker-second", result: reducerDraft([second]) },
    ],
    null,
  );

  expect(reduced.findings).toHaveLength(1);
  expect(reduced.findings[0]!.provenance.sourceFindings).toEqual([
    { id: "worker-first:0", finding: first },
    { id: "worker-second:0", finding: second },
  ]);
  expect(reduced.findings[0]!.summary).toBe(result.findings[0]!.summary);
});

test("preserves the accepted finding producer in canonical provenance", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const original = reducerFinding("accepted-producer");
  const first = {
    ...original,
    provenance: {
      ...original.provenance,
      source: "local_plugin",
      candidateId: "candidate-first",
      workerId: "worker-first",
      provider: "accepted-first-provider",
      details: {
        outcome: "accepted-first-outcome",
        nested: { worker: "accepted-first-worker" },
      },
      labels: ["first", "accepted"],
    },
  };
  const second = {
    ...original,
    provenance: {
      ...original.provenance,
      source: "accepted_import",
      candidateId: "candidate-second",
      workerId: "worker-second",
      provider: "accepted-second-provider",
      details: {
        outcome: "accepted-second-outcome",
        nested: { worker: "accepted-second-worker" },
      },
      labels: ["second", "accepted"],
    },
  };
  const discoveries = [
    { workerId: "first", result: reducerDraft([first]) },
    { workerId: "second", result: reducerDraft([second]) },
  ];
  const result = (source: string, metadata: Record<string, unknown> = {}) =>
    reducerDraft([
      {
        ...original,
        provenance: {
          source,
          ...metadata,
          sourceFindingIds: ["first:0", "second:0"],
        },
      },
    ]);

  for (const source of ["local_plugin", "accepted_import"]) {
    const finding = reconcileDeepReduction(result(source), discoveries, null)
      .findings[0]!;
    const accepted = source === "local_plugin" ? first : second;
    expect(finding.provenance).toMatchObject(accepted.provenance);
    expect(finding.provenance.sourceFindings).toEqual([
      { id: "first:0", finding: first },
      { id: "second:0", finding: second },
    ]);
  }

  expect(() =>
    reconcileDeepReduction(result("fabricated_import"), discoveries, null),
  ).toThrow("provenance.source");

  const fabricated: Array<[string, unknown]> = [
    ["candidateId", "fabricated-candidate"],
    ["workerId", "fabricated-worker"],
    ["provider", "fabricated-provider"],
    ["invented", "reducer-only-metadata"],
    ["details", { outcome: "fabricated" }],
    [
      "details",
      {
        outcome: "accepted-first-outcome",
        nested: { worker: "fabricated-worker" },
      },
    ],
    ["labels", ["fabricated"]],
    ["labels", ["accepted", "first"]],
    ["inventedObject", { outcome: "fabricated" }],
    ["inventedArray", ["fabricated"]],
  ];
  for (const [field, value] of fabricated) {
    expect(() =>
      reconcileDeepReduction(
        result("local_plugin", { [field]: value }),
        discoveries,
        null,
      ),
    ).toThrow(`provenance.${field}`);
  }

  expect(() =>
    reconcileDeepReduction(
      result("local_plugin", {
        candidateId: "candidate-second",
        workerId: "worker-first",
      }),
      discoveries,
      null,
    ),
  ).toThrow("provenance");

  expect(() =>
    reconcileDeepReduction(
      result("local_plugin", {
        details: second.provenance.details,
      }),
      discoveries,
      null,
    ),
  ).toThrow("provenance");

  expect(
    reconcileDeepReduction(
      result("local_plugin", { previousFindings: "legacy-host-history" }),
      discoveries,
      null,
    ).findings[0]?.provenance["previousFindings"],
  ).toBe("legacy-host-history");

  const inheritedNames = JSON.parse(
    '{"source":"local_plugin","__proto__":{"outcome":"accepted"},"constructor":{"outcome":"accepted constructor"},"prototype":{"outcome":"accepted prototype"}}',
  ) as ReducerFinding["provenance"];
  const inheritedFinding = { ...original, provenance: inheritedNames };
  const restored = reconcileDeepReduction(
    reducerDraft([
      {
        ...original,
        provenance: {
          source: "local_plugin",
          sourceFindingIds: ["inherited:0"],
        },
      },
    ]),
    [{ workerId: "inherited", result: reducerDraft([inheritedFinding]) }],
    null,
  ).findings[0]!.provenance;
  expect(Object.getPrototypeOf(restored)).toBe(Object.prototype);
  for (const key of ["__proto__", "constructor", "prototype"]) {
    expect(Object.hasOwn(restored, key)).toBe(true);
    expect(restored[key]).toEqual(inheritedNames[key]);
  }
});

test("preserves inherited property names in structured finding evidence", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const original = reducerFinding("structured-inherited-names");
  const inherited = JSON.parse(
    '{"summary":"Accepted structured evidence.","__proto__":{"outcome":"accepted"},"constructor":{"outcome":"accepted constructor"},"prototype":{"outcome":"accepted prototype"}}',
  ) as Record<string, unknown>;

  for (const field of ["rootCause", "root_cause", "validation", "attackPath"]) {
    const accepted = { ...original, [field]: inherited };
    for (const supplied of [undefined, { summary: inherited["summary"] }]) {
      const result = reconcileDeepReduction(
        reducerDraft([
          {
            ...original,
            ...(supplied === undefined ? {} : { [field]: supplied }),
            provenance: {
              ...original.provenance,
              sourceFindingIds: ["worker:0"],
            },
          },
        ]),
        [{ workerId: "worker", result: reducerDraft([accepted]) }],
        null,
      ).findings[0]?.[field as keyof ReducerFinding] as Record<string, unknown>;

      expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
      for (const key of ["__proto__", "constructor", "prototype"]) {
        expect(Object.hasOwn(result, key)).toBe(true);
        expect(result[key]).toEqual(inherited[key]);
      }
      expect(Object.getPrototypeOf(inherited)).toBe(Object.prototype);
      expect(Object.hasOwn(inherited, "__proto__")).toBe(true);
    }
  }

  const nested = { ...original, attackPath: { reachability: inherited } };
  const restored = reconcileDeepReduction(
    reducerDraft([
      {
        ...original,
        attackPath: { reachability: { summary: inherited["summary"] } },
        provenance: {
          ...original.provenance,
          sourceFindingIds: ["worker:0"],
        },
      },
    ]),
    [{ workerId: "worker", result: reducerDraft([nested]) }],
    null,
  ).findings[0]?.attackPath?.["reachability"] as Record<string, unknown>;
  expect(Object.getPrototypeOf(restored)).toBe(Object.prototype);
  expect(Object.hasOwn(restored, "__proto__")).toBe(true);
  expect(restored["__proto__"]).toEqual(inherited["__proto__"]);

  const fabricated = JSON.parse(
    '{"summary":"Accepted structured evidence.","__proto__":{"outcome":"fabricated"}}',
  ) as Record<string, unknown>;
  expect(() =>
    reconcileDeepReduction(
      reducerDraft([
        {
          ...original,
          validation: fabricated,
          provenance: {
            ...original.provenance,
            sourceFindingIds: ["worker:0"],
          },
        },
      ]),
      [
        {
          workerId: "worker",
          result: reducerDraft([{ ...original, validation: inherited }]),
        },
      ],
      null,
    ),
  ).toThrow("__proto__");
});

test("preserves complete source-backed finding classifications and details", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const original = reducerFinding("source-backed-finding");
  const first = {
    ...original,
    title: "Accepted SQL injection.",
    summary: "An accepted SQL query is injectable.",
    remediation: "Parameterize the accepted SQL query.",
    taxonomy: {
      category: "injection",
      cwe: ["CWE-89", "CWE-20"],
      details: { control: "query parameterization" },
    },
    extensions: { candidateId: "candidate-sql", reportId: "report-sql" },
    remediationTests: ["Reject the accepted SQL payload."],
    preventiveControls: ["Bind accepted SQL parameters."],
    status: "accepted-injection",
  };
  const second = {
    ...original,
    title: "Accepted authentication failure.",
    summary: "An accepted authentication control is missing.",
    remediation: "Require the accepted authentication control.",
    taxonomy: {
      category: "authentication",
      cwe: ["CWE-287"],
      details: { control: "authentication" },
    },
    extensions: { candidateId: "candidate-auth", reportId: "report-auth" },
    remediationTests: ["Reject the accepted anonymous request."],
    preventiveControls: ["Require accepted authentication."],
    status: "accepted-authentication",
  };
  const discoveries = [
    { workerId: "first", result: reducerDraft([first]) },
    { workerId: "second", result: reducerDraft([second]) },
  ];
  const reduce = (
    source: typeof first,
    overrides: Record<string, unknown> = {},
  ) =>
    reconcileDeepReduction(
      reducerDraft([
        {
          ...source,
          ...overrides,
          provenance: {
            ...source.provenance,
            sourceFindingIds: ["first:0", "second:0"],
          },
        },
      ]),
      discoveries,
      null,
    ).findings[0]!;

  for (const source of [first, second]) {
    const reduced = reduce(source);
    expect(reduced.title).toBe(source.title);
    expect(reduced.taxonomy).toEqual(source.taxonomy);
    expect(reduced["extensions" as keyof ReducerFinding]).toEqual(
      source.extensions,
    );
    expect(reduced["status" as keyof ReducerFinding]).toBe(source.status);
    for (const other of [first, second]) {
      expect(reduced.summary.split(/\n\s*\n/u)).toContain(other.summary);
      expect(reduced.remediation.split(/\n\s*\n/u)).toContain(
        other.remediation,
      );
      expect(reduced["remediationTests" as keyof ReducerFinding]).toContain(
        other.remediationTests[0],
      );
      expect(reduced["preventiveControls" as keyof ReducerFinding]).toContain(
        other.preventiveControls[0],
      );
    }
  }

  const fabricated: Array<[string, unknown]> = [
    ["title", "No accepted finding exists."],
    ["summary", "The reducer fabricated dynamic exploitation."],
    ["remediation", "Disable all access controls."],
    ["taxonomy", { category: "authentication", cwe: ["CWE-89"] }],
    ["taxonomy", { ...first.taxonomy, cwe: ["CWE-999"] }],
    ["taxonomy", { ...first.taxonomy, cwe: ["CWE-89", "CWE-89"] }],
    ["extensions", { ...first.extensions, candidateId: "fabricated" }],
    ["remediationTests", ["Disable the accepted control."]],
    ["preventiveControls", ["Trust all request parameters."]],
    ["status", "dismissed"],
    ["type", "not_vulnerable"],
  ];
  for (const [field, value] of fabricated) {
    expect(() => reduce(first, { [field]: value })).toThrow(`finding.${field}`);
  }

  expect(() => reduce(first, { taxonomy: second.taxonomy })).toThrow(
    "finding evidence tuple",
  );
  expect(
    reduce(first, {
      taxonomy: { ...first.taxonomy, cwe: ["CWE-20", "CWE-89"] },
    }).taxonomy,
  ).toEqual(first.taxonomy);

  for (const field of ["summary", "remediation"]) {
    const broad = "The accepted exploit succeeds";
    const qualified = `${broad} only in tests.`;
    const sources = [
      { ...original, [field]: broad },
      { ...original, [field]: qualified },
    ];
    const combined = reconcileDeepReduction(
      reducerDraft([
        {
          ...sources[1]!,
          provenance: {
            ...original.provenance,
            sourceFindingIds: ["broad:0", "qualified:0"],
          },
        },
      ]),
      [
        { workerId: "broad", result: reducerDraft([sources[0]!]) },
        { workerId: "qualified", result: reducerDraft([sources[1]!]) },
      ],
      null,
    ).findings[0]!;
    const claims = (
      combined[field as "summary" | "remediation"] as string
    ).split(/\n\s*\n/u);
    expect(claims).toContain(broad);
    expect(claims).toContain(qualified);

    expect(() =>
      reconcileDeepReduction(
        reducerDraft([
          {
            ...sources[0]!,
            [field]: `${broad}? No.`,
            provenance: {
              ...original.provenance,
              sourceFindingIds: ["broad:0"],
            },
          },
        ]),
        [{ workerId: "broad", result: reducerDraft([sources[0]!]) }],
        null,
      ),
    ).toThrow(`finding.${field}`);
  }

  const inherited = JSON.parse(
    '{"__proto__":{"outcome":"accepted"},"constructor":{"outcome":"accepted constructor"},"prototype":{"outcome":"accepted prototype"}}',
  ) as Record<string, unknown>;
  const accepted = { ...original, ...inherited };
  const restored = reconcileDeepReduction(
    reducerDraft([
      {
        ...original,
        provenance: {
          ...original.provenance,
          sourceFindingIds: ["worker:0"],
        },
      },
    ]),
    [{ workerId: "worker", result: reducerDraft([accepted]) }],
    null,
  ).findings[0]!;
  expect(Object.getPrototypeOf(restored)).toBe(Object.prototype);
  for (const key of ["__proto__", "constructor", "prototype"]) {
    expect(Object.hasOwn(restored, key)).toBe(true);
    expect((restored as unknown as Record<string, unknown>)[key]).toEqual(
      inherited[key],
    );
  }
});

test("rejects a fabricated identity claiming an accepted source finding", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const accepted = reducerFinding("accepted");
  const fabricated = {
    ...accepted,
    ruleId: "synthetic.fabricated-control",
    identity: { anchor: "fabricated" },
    summary: "Unsupported reducer-authored finding.",
    provenance: {
      ...accepted.provenance,
      sourceFindingIds: ["worker:0"],
    },
  };

  expect(() =>
    reconcileDeepReduction(
      reducerDraft([fabricated]),
      [{ workerId: "worker", result: reducerDraft([accepted]) }],
      null,
    ),
  ).toThrow("finding identity");
});

test("rejects duplicate result identities even when each source reference is valid", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const first = reducerFinding("shared", "First accepted worker evidence.");
  const second = reducerFinding("shared", "Second accepted worker evidence.");

  expect(() =>
    reconcileDeepReduction(
      reducerDraft([
        {
          ...first,
          provenance: { ...first.provenance, sourceFindingIds: ["first:0"] },
        },
        {
          ...second,
          provenance: {
            ...second.provenance,
            sourceFindingIds: ["second:0"],
          },
        },
      ]),
      [
        { workerId: "first", result: reducerDraft([first]) },
        { workerId: "second", result: reducerDraft([second]) },
      ],
      null,
    ),
  ).toThrow("duplicate");
});

test("recovers established duplicate identities only through distinct previous source groups", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const first = reducerFinding(
    "shared",
    "First previously accepted observation.",
  );
  const second = reducerFinding(
    "shared",
    "Second previously accepted observation.",
  );
  const previous = reducerDraft([
    {
      ...first,
      provenance: {
        ...first.provenance,
        sourceFindingIds: ["origin:first"],
        sourceFindings: [{ id: "origin:first", finding: first }],
      },
    },
    {
      ...second,
      provenance: {
        ...second.provenance,
        sourceFindingIds: ["origin:second"],
        sourceFindings: [{ id: "origin:second", finding: second }],
      },
    },
  ]);
  const recovered = reconcileDeepReduction(
    reducerDraft([
      {
        ...first,
        provenance: {
          ...first.provenance,
          sourceFindingIds: ["origin:first"],
        },
      },
      {
        ...second,
        provenance: {
          ...second.provenance,
          sourceFindingIds: ["origin:second"],
        },
      },
    ]),
    [],
    previous,
  );

  expect(
    recovered.findings.map((finding) => finding.provenance.sourceFindingIds),
  ).toEqual([["origin:first"], ["origin:second"]]);
});

test("rejects reduced severity or confidence for accepted source findings", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const accepted: ReducerFinding = {
    ...reducerFinding("accepted"),
    severity: {
      level: "high",
      score: 8.2,
      vector: "synthetic-accepted-vector",
      rationale: "Accepted severity evidence.",
      conditions: { review: "Accepted conditions." },
    },
    confidence: {
      level: "high",
      rationale: "Confirmed accepted evidence.",
      conditions: { validation: "Accepted source trace." },
    },
  };
  const reduced = {
    ...accepted,
    provenance: { ...accepted.provenance, sourceFindingIds: ["worker:0"] },
  };
  for (const { finding, error } of [
    { finding: { ...reduced, severity: { level: "low" } }, error: "severity" },
    {
      finding: {
        ...reduced,
        confidence: { level: "low", rationale: "Unsupported uncertainty." },
      },
      error: "confidence",
    },
    {
      finding: {
        ...reduced,
        confidence: {
          ...accepted.confidence!,
          rationale: "Dynamic exploitation succeeded.",
        },
      },
      error: "confidence",
    },
    {
      finding: { ...reduced, confidence: { level: "high" } },
      error: "confidence",
    },
    {
      finding: {
        ...reduced,
        confidence: {
          ...accepted.confidence!,
          conditions: { validation: "Invented validation." },
        },
      },
      error: "confidence",
    },
    {
      finding: {
        ...reduced,
        severity: { ...accepted.severity!, score: 10 },
      },
      error: "severity",
    },
    {
      finding: {
        ...reduced,
        severity: {
          ...accepted.severity!,
          vector: "synthetic-invented-vector",
        },
      },
      error: "severity",
    },
    {
      finding: { ...reduced, severity: { level: "high" } },
      error: "severity",
    },
    {
      finding: {
        ...reduced,
        severity: {
          ...accepted.severity!,
          conditions: { review: "Invented conditions." },
        },
      },
      error: "severity",
    },
  ]) {
    expect(() =>
      reconcileDeepReduction(
        reducerDraft([finding]),
        [{ workerId: "worker", result: reducerDraft([accepted]) }],
        null,
      ),
    ).toThrow(error);
  }
});

test("retains complete source-backed ratings at their strongest accepted levels", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const lower: ReducerFinding = {
    ...reducerFinding("shared", "First independently accepted observation."),
    severity: { level: "low", score: 2.1, rationale: "Limited exposure." },
    confidence: { level: "high", rationale: "First accepted trace." },
  };
  const stronger: ReducerFinding = {
    ...reducerFinding("shared", "Second independently accepted observation."),
    severity: {
      level: "high",
      score: 8.2,
      vector: "synthetic-accepted-vector",
      conditions: { validation: "Second accepted trace." },
    },
    confidence: { level: "high", rationale: "Second accepted trace." },
  };
  const reduced = reconcileDeepReduction(
    reducerDraft([
      {
        ...stronger,
        provenance: {
          ...stronger.provenance,
          sourceFindingIds: ["first:0", "second:0"],
        },
      },
    ]),
    [
      { workerId: "first", result: reducerDraft([lower]) },
      { workerId: "second", result: reducerDraft([stronger]) },
    ],
    null,
  );

  expect(reduced.findings[0]?.severity).toEqual(stronger.severity);
  expect(reduced.findings[0]?.confidence).toEqual(stronger.confidence);
});

test("keeps accepted source evidence visible on the reduced finding", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const accepted: ReducerFinding = {
    ...reducerFinding("accepted"),
    rootCause: { summary: "The request reaches an unescaped response." },
    codeEvidence: [
      { id: "source", code: "response.send(request.query.value)" },
    ],
    validation: { summary: "The accepted worker traced the request." },
    writeup: { reportPath: "findings/accepted/accepted.md" },
  };
  const {
    rootCause: _rootCause,
    codeEvidence: _codeEvidence,
    validation: _validation,
    writeup: _writeup,
    ...withoutEvidence
  } = accepted;
  const reduced = reconcileDeepReduction(
    reducerDraft([
      {
        ...withoutEvidence,
        provenance: {
          ...withoutEvidence.provenance,
          sourceFindingIds: ["worker:0"],
        },
        writeup: accepted.writeup,
      },
    ]),
    [{ workerId: "worker", result: reducerDraft([accepted]) }],
    null,
  );

  expect(reduced.findings[0]).toMatchObject({
    rootCause: accepted.rootCause,
    codeEvidence: accepted.codeEvidence,
    validation: accepted.validation,
    writeup: accepted.writeup,
  });
});

test("rejects changed accepted validation outcomes and unsupported evidence", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const accepted: ReducerFinding = {
    ...reducerFinding("accepted"),
    rootCause: {
      summary: "Accepted root-cause evidence.",
      classification: "input_validation",
    },
    validation: {
      status: "not_exploited",
      summary: "Accepted static trace.",
      details: { outcome: "not_reachable" },
    },
    attackPath: { reachability: { outcome: "not_reachable" } },
  };
  const reduced = {
    ...accepted,
    provenance: { ...accepted.provenance, sourceFindingIds: ["worker:0"] },
  };
  const acceptedRootCause = accepted.rootCause;
  if (!acceptedRootCause || typeof acceptedRootCause === "string") {
    throw new Error("Expected a structured accepted root cause.");
  }

  for (const { finding, error } of [
    {
      finding: {
        ...reduced,
        validation: { ...accepted.validation!, status: "exploited" },
      },
      error: "validation.status",
    },
    {
      finding: {
        ...reduced,
        validation: {
          ...accepted.validation!,
          details: { outcome: "reachable" },
        },
      },
      error: "validation.details.outcome",
    },
    {
      finding: {
        ...reduced,
        validation: {
          ...accepted.validation!,
          dynamicResult: "Exploited during runtime validation.",
        },
      },
      error: "validation.dynamicResult",
    },
    {
      finding: {
        ...reduced,
        rootCause: {
          ...acceptedRootCause,
          classification: "remote_code_execution",
        },
      },
      error: "rootCause.classification",
    },
    {
      finding: {
        ...reduced,
        attackPath: { reachability: { outcome: "reachable" } },
      },
      error: "attackPath.reachability.outcome",
    },
  ]) {
    expect(() =>
      reconcileDeepReduction(
        reducerDraft([finding]),
        [{ workerId: "worker", result: reducerDraft([accepted]) }],
        null,
      ),
    ).toThrow(error);
  }

  const plain = reducerFinding("unsupported-evidence");
  for (const { evidence, error } of [
    {
      evidence: {
        validation: {
          status: "exploited",
          result: "Dynamic exploitation succeeded.",
        },
      },
      error: "validation",
    },
    {
      evidence: {
        rootCause: {
          summary: "Invented remote execution.",
          classification: "remote_code_execution",
        },
      },
      error: "rootCause",
    },
    {
      evidence: {
        attackPath: { reachability: { outcome: "reachable" } },
      },
      error: "attackPath",
    },
    {
      evidence: {
        codeEvidence: [{ id: "invented", code: "inventedDynamicExploit()" }],
      },
      error: "codeEvidence",
    },
  ]) {
    expect(() =>
      reconcileDeepReduction(
        reducerDraft([
          {
            ...plain,
            ...evidence,
            provenance: {
              ...plain.provenance,
              sourceFindingIds: ["worker:0"],
            },
          },
        ]),
        [{ workerId: "worker", result: reducerDraft([plain]) }],
        null,
      ),
    ).toThrow(error);
  }
});

test("reconciles schema-valid alternate encodings without inventing evidence", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const rootSummary = "Accepted root-cause explanation.";
  const pathSummary = "Accepted request reaches the sensitive sink.";
  const cases: Array<{
    field: string;
    first: unknown;
    second: unknown;
    expected: unknown;
    fabricated: unknown;
    error: string;
  }> = [
    ...["rootCause", "root_cause"].map((field) => ({
      field,
      first: rootSummary,
      second: { summary: rootSummary, code: "acceptedSourceTrace()" },
      expected: { summary: rootSummary, code: "acceptedSourceTrace()" },
      fabricated: {
        summary: "Invented remote exploitation.",
        code: "acceptedSourceTrace()",
      },
      error: `${field}.summary`,
    })),
    ...["dataFlow", "data_flow", "dataflow", "reachability"].map((field) => ({
      field: "attackPath",
      first: { [field]: pathSummary },
      second: {
        [field]: { summary: pathSummary, outcome: "not_reachable" },
      },
      expected: {
        [field]: { summary: pathSummary, outcome: "not_reachable" },
      },
      fabricated: {
        [field]: { summary: pathSummary, outcome: "exploited" },
      },
      error: `attackPath.${field}.outcome`,
    })),
    ...["impact", "likelihood"].map((field) => ({
      field: "attackPath",
      first: { [field]: "high" },
      second: {
        [field]: { level: "high", rationale: "Accepted assessment." },
      },
      expected: {
        [field]: { level: "high", rationale: "Accepted assessment." },
      },
      fabricated: {
        [field]: { level: "critical", rationale: "Accepted assessment." },
      },
      error: `attackPath.${field}.level`,
    })),
    ...["impact", "likelihood"].map((field) => ({
      field: "attackPath",
      first: { [field]: null },
      second: {
        [field]: { level: "high", rationale: "Accepted assessment." },
      },
      expected: {
        [field]: { level: "high", rationale: "Accepted assessment." },
      },
      fabricated: {
        [field]: { level: "critical", rationale: "Accepted assessment." },
      },
      error: `attackPath.${field}.level`,
    })),
    {
      field: "validation",
      first: { evidence: "Accepted source trace." },
      second: {
        evidence: ["Accepted source trace.", "Accepted independent trace."],
      },
      expected: {
        evidence: ["Accepted source trace.", "Accepted independent trace."],
      },
      fabricated: {
        evidence: [
          "Accepted source trace.",
          "Accepted independent trace.",
          "Invented dynamic exploitation.",
        ],
      },
      error: "validation.evidence",
    },
  ];

  for (const { field, first, second, expected, fabricated, error } of cases) {
    for (const values of [
      [first, second],
      [second, first],
    ]) {
      const original = reducerFinding("alternate-evidence");
      const originals = values.map((value) => ({
        ...original,
        [field]: value,
      }));
      const discoveries = originals.map((finding, index) => ({
        workerId: `worker-${index}`,
        result: reducerDraft([finding]),
      }));
      const draft = (value: unknown) =>
        reducerDraft([
          {
            ...original,
            [field]: value,
            provenance: {
              ...original.provenance,
              sourceFindingIds: ["worker-0:0", "worker-1:0"],
            },
          },
        ]);

      for (const supplied of [first, second]) {
        const reduced = reconcileDeepReduction(
          draft(supplied),
          discoveries,
          null,
        );
        expect(reduced.findings[0]).toMatchObject({ [field]: expected });
        expect(reduced.findings[0]!.provenance.sourceFindings).toEqual([
          { id: "worker-0:0", finding: originals[0]! },
          { id: "worker-1:0", finding: originals[1]! },
        ]);
        expect(
          reconcileDeepReduction(structuredClone(reduced), discoveries, null),
        ).toEqual(reduced);
      }

      expect(() =>
        reconcileDeepReduction(draft(fabricated), discoveries, null),
      ).toThrow(error);
    }
  }
});

test("preserves conflicting categorical evidence without inventing combined outcomes", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  for (const { field, first, second, fabricated, path } of [
    {
      field: "validation",
      first: { status: "not_exploited" },
      second: { status: "exploited" },
      fabricated: { status: "not_exploitedexploited" },
      path: "validation.status",
    },
    {
      field: "validation",
      first: { result: "blocked" },
      second: { result: "reachable" },
      fabricated: { result: "blockedreachable" },
      path: "validation.result",
    },
    {
      field: "validation",
      first: { certainty: 0.2 },
      second: { certainty: 0.9 },
      fabricated: { certainty: 0.5 },
      path: "validation.certainty",
    },
    {
      field: "attackPath",
      first: { reachability: { outcome: "blocked" } },
      second: { reachability: { outcome: "reachable" } },
      fabricated: { reachability: { outcome: "blockedreachable" } },
      path: "attackPath.reachability.outcome",
    },
    {
      field: "rootCause",
      first: {
        summary: "Accepted source explanation.",
        classification: "local",
      },
      second: {
        summary: "Accepted source explanation.",
        classification: "remote",
      },
      fabricated: {
        summary: "Accepted source explanation.",
        classification: "localremote",
      },
      path: "rootCause.classification",
    },
  ]) {
    const original = reducerFinding("conflicting-evidence");
    const firstFinding = { ...original, [field]: first };
    const secondFinding = { ...original, [field]: second };
    const discoveries = [
      { workerId: "first", result: reducerDraft([firstFinding]) },
      { workerId: "second", result: reducerDraft([secondFinding]) },
    ];
    const reducedFinding = (value: unknown) => ({
      ...original,
      [field]: value,
      provenance: {
        ...original.provenance,
        sourceFindingIds: ["first:0", "second:0"],
      },
    });

    for (const accepted of [first, second]) {
      const reduced = reconcileDeepReduction(
        reducerDraft([reducedFinding(accepted)]),
        discoveries,
        null,
      ).findings[0]!;
      expect(reduced).toMatchObject({ [field]: accepted });
      expect(reduced.provenance.sourceFindings).toEqual([
        { id: "first:0", finding: firstFinding },
        { id: "second:0", finding: secondFinding },
      ]);
    }

    expect(() =>
      reconcileDeepReduction(
        reducerDraft([reducedFinding(fabricated)]),
        discoveries,
        null,
      ),
    ).toThrow(path);
  }
});

test("binds related structured finding evidence to one accepted source", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  for (const { field, first, second, fabricated } of [
    {
      field: "validation",
      first: { method: "dynamic reproduction", status: "exploited" },
      second: { method: "static review", status: "not_exploited" },
      fabricated: { method: "dynamic reproduction", status: "not_exploited" },
    },
    {
      field: "attackPath",
      first: {
        reachability: {
          attacker: "remote attacker",
          entrypoint: "public upload",
          outcome: "reachable",
        },
      },
      second: {
        reachability: {
          attacker: "administrator",
          entrypoint: "private administration",
          outcome: "blocked",
        },
      },
      fabricated: {
        reachability: {
          attacker: "remote attacker",
          entrypoint: "private administration",
          outcome: "blocked",
        },
      },
    },
    ...["rootCause", "root_cause"].map((field) => ({
      field,
      first: {
        summary: "Accepted root cause.",
        code: "first()",
        language: "javascript",
      },
      second: {
        summary: "Accepted root cause.",
        code: "second()",
        language: "python",
      },
      fabricated: {
        summary: "Accepted root cause.",
        code: "first()",
        language: "python",
      },
    })),
  ]) {
    for (const accepted of [
      [first, second],
      [second, first],
    ]) {
      const original = reducerFinding("coherent-evidence");
      const sources = accepted.map((evidence) => ({
        ...original,
        [field]: evidence,
      }));
      const discoveries = sources.map((finding, index) => ({
        workerId: `worker-${index}`,
        result: reducerDraft([finding]),
      }));
      const reduced = (evidence: unknown) =>
        reducerDraft([
          {
            ...original,
            [field]: evidence,
            provenance: {
              ...original.provenance,
              sourceFindingIds: ["worker-0:0", "worker-1:0"],
            },
          },
        ]);

      for (const evidence of accepted) {
        const result = reconcileDeepReduction(
          reduced(evidence),
          discoveries,
          null,
        ).findings[0]!;
        expect(result).toMatchObject({ [field]: evidence });
        expect(result.provenance.sourceFindings).toEqual(
          sources.map((finding, index) => ({
            id: `worker-${index}:0`,
            finding,
          })),
        );
      }

      expect(() =>
        reconcileDeepReduction(reduced(fabricated), discoveries, null),
      ).toThrow(field);
    }
  }

  const original = reducerFinding("independent-evidence-fields");
  expect(
    reconcileDeepReduction(
      reducerDraft([
        {
          ...original,
          validation: { method: "static review", status: "not_exploited" },
          provenance: {
            ...original.provenance,
            sourceFindingIds: ["method:0", "status:0"],
          },
        },
      ]),
      [
        {
          workerId: "method",
          result: reducerDraft([
            { ...original, validation: { method: "static review" } },
          ]),
        },
        {
          workerId: "status",
          result: reducerDraft([
            { ...original, validation: { status: "not_exploited" } },
          ]),
        },
      ],
      null,
    ).findings[0]?.validation,
  ).toEqual({ method: "static review", status: "not_exploited" });

  for (const key of ["status", "disposition", "result"]) {
    const certain = {
      ...original,
      validation: { method: "dynamic reproduction", [key]: "exploited" },
    };
    const unknown = {
      ...original,
      validation: { method: "static review", [key]: null },
    };
    for (const accepted of [
      [certain, unknown],
      [unknown, certain],
    ]) {
      const discoveries = accepted.map((finding, index) => ({
        workerId: `nullable-${index}`,
        result: reducerDraft([finding]),
      }));
      const result = (validation: Record<string, unknown>) =>
        reducerDraft([
          {
            ...original,
            validation,
            provenance: {
              ...original.provenance,
              sourceFindingIds: ["nullable-0:0", "nullable-1:0"],
            },
          },
        ]);

      for (const source of [certain, unknown]) {
        expect(
          reconcileDeepReduction(result(source.validation), discoveries, null)
            .findings[0]?.validation,
        ).toEqual(source.validation);
      }
      expect(() =>
        reconcileDeepReduction(
          result({ method: "dynamic reproduction", [key]: null }),
          discoveries,
          null,
        ),
      ).toThrow("validation");
    }
  }
});

test("preserves the complete accepted order of attack-path steps", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const input = "Read attacker input.";
  const bypass = "Bypass authorization.";
  const audit = "Inspect the accepted audit control.";
  const sink = "Write administrator state.";
  const original = reducerFinding("ordered-attack-path");
  const first = { ...original, attackPath: { steps: [input, bypass, sink] } };
  const second = { ...original, attackPath: { steps: [input, audit, sink] } };
  const reducedFinding = (steps: string[], references: string[]) => ({
    ...original,
    attackPath: { steps },
    provenance: { ...original.provenance, sourceFindingIds: references },
  });

  expect(() =>
    reconcileDeepReduction(
      reducerDraft([reducedFinding([sink, bypass, input], ["first:0"])]),
      [{ workerId: "first", result: reducerDraft([first]) }],
      null,
    ),
  ).toThrow("attackPath.steps");
  expect(() =>
    reconcileDeepReduction(
      reducerDraft([reducedFinding([input, bypass, sink, sink], ["first:0"])]),
      [{ workerId: "first", result: reducerDraft([first]) }],
      null,
    ),
  ).toThrow("attackPath.steps");

  const combined = [input, bypass, audit, sink];
  expect(
    reconcileDeepReduction(
      reducerDraft([reducedFinding(combined, ["first:0", "second:0"])]),
      [
        { workerId: "first", result: reducerDraft([first]) },
        { workerId: "second", result: reducerDraft([second]) },
      ],
      null,
    ).findings[0]?.attackPath,
  ).toEqual({ steps: combined });

  const chained = [
    { ...original, attackPath: { steps: [input] } },
    { ...original, attackPath: { steps: [input, bypass] } },
    { ...original, attackPath: { steps: [bypass, sink] } },
  ];
  for (const order of [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
  ]) {
    const discoveries = order.map((index, position) => ({
      workerId: `chain-${position}`,
      result: reducerDraft([chained[index]!]),
    }));
    for (const source of chained) {
      expect(
        reconcileDeepReduction(
          reducerDraft([
            reducedFinding(source.attackPath.steps, [
              "chain-0:0",
              "chain-1:0",
              "chain-2:0",
            ]),
          ]),
          discoveries,
          null,
        ).findings[0]?.attackPath,
      ).toEqual({ steps: [input, bypass, sink] });
    }
  }

  for (const values of [
    [first, second],
    [second, first],
  ]) {
    for (const supplied of [first.attackPath.steps, second.attackPath.steps]) {
      const discoveries = values.map((finding, index) => ({
        workerId: `worker-${index}`,
        result: reducerDraft([finding]),
      }));
      const reduced = reconcileDeepReduction(
        reducerDraft([reducedFinding(supplied, ["worker-0:0", "worker-1:0"])]),
        discoveries,
        null,
      ).findings[0]?.attackPath?.["steps"] as string[];
      expect(reduced[0]).toBe(input);
      expect(reduced.at(-1)).toBe(sink);
      expect(reduced).toContain(bypass);
      expect(reduced).toContain(audit);
    }
  }

  const repeatedFirst = {
    ...original,
    attackPath: { steps: [input, bypass, input, sink] },
  };
  const repeatedSecond = {
    ...original,
    attackPath: { steps: [input, audit, input, sink] },
  };
  expect(
    reconcileDeepReduction(
      reducerDraft([
        reducedFinding(repeatedFirst.attackPath.steps, ["first:0", "second:0"]),
      ]),
      [
        { workerId: "first", result: reducerDraft([repeatedFirst]) },
        { workerId: "second", result: reducerDraft([repeatedSecond]) },
      ],
      null,
    ).findings[0]?.attackPath,
  ).toEqual({ steps: [input, bypass, audit, input, sink] });

  const repeatedSuffix = {
    ...original,
    attackPath: { steps: [bypass, input, sink] },
  };
  expect(
    reconcileDeepReduction(
      reducerDraft([
        reducedFinding(repeatedFirst.attackPath.steps, ["first:0", "suffix:0"]),
      ]),
      [
        { workerId: "first", result: reducerDraft([repeatedFirst]) },
        { workerId: "suffix", result: reducerDraft([repeatedSuffix]) },
      ],
      null,
    ).findings[0]?.attackPath,
  ).toEqual({ steps: repeatedFirst.attackPath.steps });

  const asymmetric = {
    ...original,
    attackPath: { steps: [bypass, input, audit, sink] },
  };
  expect(
    reconcileDeepReduction(
      reducerDraft([
        reducedFinding(repeatedFirst.attackPath.steps, ["first:0", "other:0"]),
      ]),
      [
        { workerId: "first", result: reducerDraft([repeatedFirst]) },
        { workerId: "other", result: reducerDraft([asymmetric]) },
      ],
      null,
    ).findings[0]?.attackPath,
  ).toEqual({ steps: [input, bypass, input, audit, sink] });

  const repeatedGlobally = [
    { ...original, attackPath: { steps: [input, input] } },
    { ...original, attackPath: { steps: [input, bypass, input] } },
    { ...original, attackPath: { steps: [input, bypass, bypass, bypass] } },
  ];
  for (const order of [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
  ]) {
    const discoveries = order.map((index, position) => ({
      workerId: `repeat-${position}`,
      result: reducerDraft([repeatedGlobally[index]!]),
    }));
    for (const source of repeatedGlobally) {
      const reconciled = reconcileDeepReduction(
        reducerDraft([
          reducedFinding(source.attackPath.steps, [
            "repeat-0:0",
            "repeat-1:0",
            "repeat-2:0",
          ]),
        ]),
        discoveries,
        null,
      ).findings[0]?.attackPath?.["steps"] as string[];

      expect(reconciled).toHaveLength(5);
      expect(reconciled.filter((step) => step === input)).toHaveLength(2);
      expect(reconciled.filter((step) => step === bypass)).toHaveLength(3);
      for (const { attackPath } of repeatedGlobally) {
        let index = 0;
        for (const step of reconciled) {
          if (attackPath.steps[index] === step) index += 1;
        }
        expect(index).toBe(attackPath.steps.length);
      }
    }
  }

  const repeatedBeyondSeeds = [
    { ...original, attackPath: { steps: [input, input] } },
    { ...original, attackPath: { steps: [bypass, input, bypass, bypass] } },
    { ...original, attackPath: { steps: [bypass, bypass, input, bypass] } },
  ];
  for (const order of [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
  ]) {
    const discoveries = order.map((index, position) => ({
      workerId: `complex-${position}`,
      result: reducerDraft([repeatedBeyondSeeds[index]!]),
    }));
    for (const source of repeatedBeyondSeeds) {
      const reconciled = reconcileDeepReduction(
        reducerDraft([
          reducedFinding(source.attackPath.steps, [
            "complex-0:0",
            "complex-1:0",
            "complex-2:0",
          ]),
        ]),
        discoveries,
        null,
      ).findings[0]?.attackPath?.["steps"] as string[];

      expect(reconciled).toHaveLength(5);
      expect(reconciled.filter((step) => step === input)).toHaveLength(2);
      expect(reconciled.filter((step) => step === bypass)).toHaveLength(3);
      for (const { attackPath } of repeatedBeyondSeeds) {
        let index = 0;
        for (const step of reconciled) {
          if (attackPath.steps[index] === step) index += 1;
        }
        expect(index).toBe(attackPath.steps.length);
      }
    }
  }

  const repeatedAtScale = repeatedGlobally.map(({ attackPath }) => ({
    ...original,
    attackPath: {
      steps: Array.from({ length: 12 }, () => attackPath.steps).flat(),
    },
  }));
  const scaled = reconcileDeepReduction(
    reducerDraft([
      reducedFinding(repeatedAtScale[0]!.attackPath.steps, [
        "scaled-0:0",
        "scaled-1:0",
        "scaled-2:0",
      ]),
    ]),
    repeatedAtScale.map((finding, index) => ({
      workerId: `scaled-${index}`,
      result: reducerDraft([finding]),
    })),
    null,
  ).findings[0]?.attackPath?.["steps"] as string[];
  expect(scaled).toHaveLength(60);
  expect(scaled.filter((step) => step === input)).toHaveLength(24);
  expect(scaled.filter((step) => step === bypass)).toHaveLength(36);
  for (const { attackPath } of repeatedAtScale) {
    let index = 0;
    for (const step of scaled) {
      if (attackPath.steps[index] === step) index += 1;
    }
    expect(index).toBe(attackPath.steps.length);
  }

  const leftSteps = [
    input,
    ...Array.from({ length: 32 }, (_, index) => `Accepted left step ${index}.`),
    sink,
  ];
  const rightSteps = [
    input,
    ...Array.from(
      { length: 32 },
      (_, index) => `Accepted right step ${index}.`,
    ),
    sink,
  ];
  const left = { ...original, attackPath: { steps: leftSteps } };
  const right = { ...original, attackPath: { steps: rightSteps } };
  const larger = reconcileDeepReduction(
    reducerDraft([reducedFinding(leftSteps, ["left:0", "right:0"])]),
    [
      { workerId: "left", result: reducerDraft([left]) },
      { workerId: "right", result: reducerDraft([right]) },
    ],
    null,
  ).findings[0]?.attackPath?.["steps"] as string[];
  expect(larger).toHaveLength(66);
  expect(larger[0]).toBe(input);
  expect(larger.at(-1)).toBe(sink);

  const reversed = {
    ...original,
    attackPath: { steps: [bypass, input, sink] },
  };
  expect(() =>
    reconcileDeepReduction(
      reducerDraft([
        reducedFinding([input, bypass, sink], ["first:0", "reversed:0"]),
      ]),
      [
        { workerId: "first", result: reducerDraft([first]) },
        { workerId: "reversed", result: reducerDraft([reversed]) },
      ],
      null,
    ),
  ).toThrow("attackPath.steps");
});

test("preserves the accepted source-to-sink transformation sequence", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const original = reducerFinding("ordered-transformations");
  const decode = "Decode the attacker-controlled request.";
  const validate = "Validate the decoded request.";
  const audit = "Audit the accepted request.";

  for (const field of ["dataFlow", "data_flow", "dataflow"]) {
    const finding = (transformations: string[]) => ({
      ...original,
      attackPath: {
        [field]: {
          summary: "Accepted source-to-sink data flow.",
          transformations,
        },
      },
    });
    const reduced = (transformations: string[], workers: number) => ({
      ...finding(transformations),
      provenance: {
        ...original.provenance,
        sourceFindingIds: Array.from(
          { length: workers },
          (_, index) => `worker-${index}:0`,
        ),
      },
    });

    expect(() =>
      reconcileDeepReduction(
        reducerDraft([reduced([validate, decode], 1)]),
        [
          {
            workerId: "worker-0",
            result: reducerDraft([finding([decode, validate])]),
          },
        ],
        null,
      ),
    ).toThrow(`attackPath.${field}.transformations`);

    const accepted = [
      finding([decode, validate]),
      finding([decode, audit, validate]),
    ];
    const retained = reconcileDeepReduction(
      reducerDraft([reduced([decode, validate], 2)]),
      accepted.map((source, index) => ({
        workerId: `worker-${index}`,
        result: reducerDraft([source]),
      })),
      null,
    ).findings[0]?.attackPath?.[field] as {
      transformations: string[];
    };
    expect(retained.transformations).toEqual([decode, audit, validate]);

    const repeated = [
      finding([decode, decode]),
      finding([validate, decode, validate, validate]),
      finding([validate, validate, decode, validate]),
    ];
    const merged = reconcileDeepReduction(
      reducerDraft([reduced([decode, decode], 3)]),
      repeated.map((source, index) => ({
        workerId: `worker-${index}`,
        result: reducerDraft([source]),
      })),
      null,
    ).findings[0]?.attackPath?.[field] as {
      transformations: string[];
    };
    expect(merged.transformations).toEqual([
      validate,
      decode,
      validate,
      decode,
      validate,
    ]);
  }

  const controls = {
    ...original,
    attackPath: { controls: [decode, validate] },
  };
  expect(
    reconcileDeepReduction(
      reducerDraft([
        {
          ...original,
          attackPath: { controls: [validate, decode] },
          provenance: {
            ...original.provenance,
            sourceFindingIds: ["worker:0"],
          },
        },
      ]),
      [{ workerId: "worker", result: reducerDraft([controls]) }],
      null,
    ).findings[0]?.attackPath?.["controls"],
  ).toEqual([validate, decode]);
});

test("retains overlapping accepted narratives without duplicating source evidence", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const shorter = "Input reaches the sink.";
  const longer = "Input reaches the sink. The guard sanitizes it.";

  for (const field of ["validation", "rootCause"]) {
    for (const summaries of [
      [shorter, longer],
      [longer, shorter],
    ]) {
      const original = reducerFinding("overlapping-evidence");
      const originals = summaries.map((summary) => ({
        ...original,
        [field]: { summary },
      }));
      const discoveries = originals.map((finding, index) => ({
        workerId: `worker-${index}`,
        result: reducerDraft([finding]),
      }));
      const result = (summary: string) =>
        reducerDraft([
          {
            ...original,
            [field]: { summary },
            provenance: {
              ...original.provenance,
              sourceFindingIds: ["worker-0:0", "worker-1:0"],
            },
          },
        ]);

      for (const summary of [longer, `${shorter}\n\n${longer}`]) {
        const finding = reconcileDeepReduction(
          result(summary),
          discoveries,
          null,
        ).findings[0]!;
        expect(finding).toMatchObject({ [field]: { summary } });
        expect(finding.provenance.sourceFindings).toEqual([
          { id: "worker-0:0", finding: originals[0]! },
          { id: "worker-1:0", finding: originals[1]! },
        ]);
      }

      expect(() =>
        reconcileDeepReduction(
          result(`${longer} An invented dynamic exploit succeeds.`),
          discoveries,
          null,
        ),
      ).toThrow(`${field}.summary`);
    }
  }
});

test("preserves contradictory and qualified source narratives as complete claims", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  for (const field of ["validation", "rootCause"]) {
    for (const [first, second] of [
      ["reachable", "unreachable"],
      ["reachable", "not reachable"],
      ["safe", "unsafe"],
      ["exploited", "not_exploited"],
      ["Exploit succeeds", "Exploit succeeds only in tests"],
      ["Exploit succeeds", "Exploit succeeds? No."],
      ["Exploit succeeds", "Exploit succeeds! Never."],
      ["Exploit succeeds", "Exploit succeeds. Never."],
      ["Exploit succeeds", "Exploit succeeds？ No."],
      ["Exploit succeeds", "Exploit succeeds！ Never."],
      ["Accès autorisé", "Accès autorisé uniquement en test"],
    ] as Array<[string, string]>) {
      for (const values of [
        [first, second],
        [second, first],
      ]) {
        const original = reducerFinding("contradictory-evidence");
        const originals = values.map((summary) => ({
          ...original,
          [field]: { summary },
        }));
        const discoveries = originals.map((finding, index) => ({
          workerId: `worker-${index}`,
          result: reducerDraft([finding]),
        }));
        for (const summary of [first, second]) {
          const reduced = reconcileDeepReduction(
            reducerDraft([
              {
                ...original,
                [field]: { summary },
                provenance: {
                  ...original.provenance,
                  sourceFindingIds: ["worker-0:0", "worker-1:0"],
                },
              },
            ]),
            discoveries,
            null,
          ).findings[0]!;
          const narrative = (
            reduced[field as "validation" | "rootCause"] as {
              summary: string;
            }
          ).summary;
          expect(narrative.split(/\n\s*\n/u)).toContain(first);
          expect(narrative.split(/\n\s*\n/u)).toContain(second);
          expect(reduced.provenance.sourceFindings).toEqual([
            { id: "worker-0:0", finding: originals[0]! },
            { id: "worker-1:0", finding: originals[1]! },
          ]);
        }
      }
    }
  }
});

test("reconciles absent and populated worker evidence in either source order", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  for (const { field, accepted } of [
    { field: "validation", accepted: { status: "not_exploited" } },
    {
      field: "attackPath",
      accepted: { reachability: { outcome: "not_reachable" } },
    },
  ]) {
    for (const values of [
      [null, accepted],
      [accepted, null],
    ]) {
      const original = reducerFinding("nullable-evidence");
      const originals = values.map((value) => ({
        ...original,
        [field]: value,
      }));
      const discoveries = originals.map((finding, index) => ({
        workerId: `worker-${index}`,
        result: reducerDraft([finding]),
      }));

      for (const supplied of [undefined, null, accepted]) {
        const reduced = reconcileDeepReduction(
          reducerDraft([
            {
              ...original,
              ...(supplied === undefined ? {} : { [field]: supplied }),
              provenance: {
                ...original.provenance,
                sourceFindingIds: ["worker-0:0", "worker-1:0"],
              },
            },
          ]),
          discoveries,
          null,
        ).findings[0]!;

        expect(reduced).toMatchObject({ [field]: accepted });
        expect(reduced.provenance.sourceFindings).toEqual([
          { id: "worker-0:0", finding: originals[0]! },
          { id: "worker-1:0", finding: originals[1]! },
        ]);
      }
    }

    const empty = { ...reducerFinding("all-null-evidence"), [field]: null };
    const source = [{ workerId: "empty", result: reducerDraft([empty]) }];
    const result = (value: unknown) =>
      reducerDraft([
        {
          ...empty,
          [field]: value,
          provenance: { ...empty.provenance, sourceFindingIds: ["empty:0"] },
        },
      ]);
    expect(
      reconcileDeepReduction(result(null), source, null).findings[0],
    ).toEqual(expect.objectContaining({ [field]: null }));
    expect(() =>
      reconcileDeepReduction(result(accepted), source, null),
    ).toThrow(field);
  }
});

test("preserves every accepted finding location and rejects fabricated locations", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const first: ReducerFinding = {
    ...reducerFinding("shared"),
    locations: [{ path: "src/first.ts", startLine: 10 }],
  };
  const second: ReducerFinding = {
    ...reducerFinding("shared", "A second accepted request path."),
    locations: [{ path: "src/second.ts", startLine: 20 }],
  };
  const discoveries = [
    { workerId: "first", result: reducerDraft([first]) },
    { workerId: "second", result: reducerDraft([second]) },
  ];
  const reducedFinding = (locations: ReducerFinding["locations"]) => ({
    ...first,
    locations,
    provenance: {
      ...first.provenance,
      sourceFindingIds: ["first:0", "second:0"],
    },
  });

  for (const locations of [[], first.locations]) {
    expect(
      reconcileDeepReduction(
        reducerDraft([reducedFinding(locations)]),
        discoveries,
        null,
      ).findings[0]?.locations,
    ).toEqual([...first.locations, ...second.locations]);
  }

  expect(() =>
    reconcileDeepReduction(
      reducerDraft([
        reducedFinding([{ path: "src/fabricated.ts", startLine: 999 }]),
      ]),
      discoveries,
      null,
    ),
  ).toThrow("location");
});

test("rejects an omitted writeup instead of inventing an unbacked artifact path", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const accepted: ReducerFinding = {
    ...reducerFinding("accepted"),
    writeup: { reportPath: "findings/accepted/accepted.md" },
  };
  const { writeup: _writeup, ...withoutWriteup } = accepted;

  expect(() =>
    reconcileDeepReduction(
      reducerDraft([
        {
          ...withoutWriteup,
          provenance: {
            ...withoutWriteup.provenance,
            sourceFindingIds: ["worker:0"],
          },
        },
      ]),
      [{ workerId: "worker", result: reducerDraft([accepted]) }],
      null,
    ),
  ).toThrow("writeup");
});

test("renames colliding accepted code-evidence IDs and preserves every reference", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const first: ReducerFinding = {
    ...reducerFinding("shared", "First accepted worker evidence."),
    rootCause: {
      summary: "First independently accepted root cause.",
      evidenceRefs: ["evidence-1"],
    },
    codeEvidence: [{ id: "evidence-1", code: "firstProof()" }],
  };
  const second: ReducerFinding = {
    ...reducerFinding("shared", "Second accepted worker evidence."),
    rootCause: {
      summary: "Second independently accepted root cause.",
      evidenceRefs: ["evidence-1"],
    },
    codeEvidence: [{ id: "evidence-1", code: "secondProof()" }],
  };
  const reduced = reconcileDeepReduction(
    reducerDraft([
      {
        ...reducerFinding("shared", `${first.summary}\n\n${second.summary}`),
        provenance: {
          source: "local_plugin",
          sourceFindingIds: ["first:0", "second:0"],
        },
      },
    ]),
    [
      { workerId: "first", result: reducerDraft([first]) },
      { workerId: "second", result: reducerDraft([second]) },
    ],
    null,
  ).findings[0]!;

  expect(reduced.codeEvidence).toEqual([
    { id: "evidence-1", code: "firstProof()" },
    { id: "evidence-1-2", code: "secondProof()" },
  ]);
  if (!reduced.rootCause || typeof reduced.rootCause === "string") {
    throw new Error("Expected structured merged root-cause evidence.");
  }
  expect(reduced.rootCause.evidenceRefs).toEqual([
    "evidence-1",
    "evidence-1-2",
  ]);
  expect(reduced.rootCause.summary).toContain(
    "First independently accepted root cause.",
  );
  expect(reduced.rootCause.summary).toContain(
    "Second independently accepted root cause.",
  );
});

test("preserves ordered evidence-reference chains across all supported sections", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const ordered = ["input", "transition", "sink"];
  const codeEvidence = ordered.map((id) => ({ id, code: `${id}()` }));
  const fields: Array<{ section: string; key: string; nested?: string }> = [
    ...["rootCause", "root_cause", "validation", "attackPath"].flatMap(
      (section) =>
        ["evidenceRefs", "evidence_refs"].map((key) => ({ section, key })),
    ),
    ...["dataFlow", "data_flow", "dataflow", "reachability"].flatMap((nested) =>
      ["evidenceRefs", "evidence_refs"].map((key) => ({
        section: "attackPath",
        nested,
        key,
      })),
    ),
  ];

  for (const { section, nested, key } of fields) {
    const original = reducerFinding("ordered-evidence-references");
    const detail = (references: string[]) =>
      nested
        ? { [nested]: { summary: "Accepted dataflow.", [key]: references } }
        : {
            ...(section === "rootCause" || section === "root_cause"
              ? { summary: "Accepted root cause." }
              : {}),
            [key]: references,
          };
    const accepted = { ...original, codeEvidence, [section]: detail(ordered) };
    const result = (references: string[]) =>
      reducerDraft([
        {
          ...original,
          codeEvidence,
          [section]: detail(references),
          provenance: {
            ...original.provenance,
            sourceFindingIds: ["worker:0"],
          },
        },
      ]);
    const source = [{ workerId: "worker", result: reducerDraft([accepted]) }];
    expect(
      reconcileDeepReduction(result(ordered), source, null).findings[0],
    ).toMatchObject({
      [section]: detail(ordered),
    });
    expect(() =>
      reconcileDeepReduction(result([...ordered].reverse()), source, null),
    ).toThrow(nested ? `${section}.${nested}.${key}` : `${section}.${key}`);
  }

  const original = reducerFinding("ordered-overlapping-references");
  const first = {
    ...original,
    codeEvidence,
    rootCause: {
      summary: "Accepted root cause.",
      evidenceRefs: ["input", "transition"],
    },
  };
  const second = {
    ...original,
    codeEvidence,
    rootCause: {
      summary: "Accepted root cause.",
      evidenceRefs: ["transition", "sink"],
    },
  };
  expect(
    reconcileDeepReduction(
      reducerDraft([
        {
          ...original,
          codeEvidence,
          rootCause: {
            summary: "Accepted root cause.",
            evidenceRefs: ["transition", "sink"],
          },
          provenance: {
            ...original.provenance,
            sourceFindingIds: ["first:0", "second:0"],
          },
        },
      ]),
      [
        { workerId: "first", result: reducerDraft([first]) },
        { workerId: "second", result: reducerDraft([second]) },
      ],
      null,
    ).findings[0],
  ).toMatchObject({ rootCause: { evidenceRefs: ordered } });

  for (const { section, key } of [
    { section: "rootCause", key: "evidenceRefs" },
    { section: "root_cause", key: "evidence_refs" },
    { section: "validation", key: "evidence_refs" },
    { section: "attackPath", key: "evidenceRefs" },
  ]) {
    const sequences = [
      ["input", "input"],
      ["input", "transition", "input"],
      ["input", "transition", "transition", "transition"],
    ];
    const detail = (references: string[]) => ({
      ...(section === "rootCause" || section === "root_cause"
        ? { summary: "Accepted root cause." }
        : {}),
      [key]: references,
    });
    const references = reconcileDeepReduction(
      reducerDraft([
        {
          ...original,
          codeEvidence,
          [section]: detail(sequences[0]!),
          provenance: {
            ...original.provenance,
            sourceFindingIds: ["refs-0:0", "refs-1:0", "refs-2:0"],
          },
        },
      ]),
      sequences.map((source, index) => ({
        workerId: `refs-${index}`,
        result: reducerDraft([
          { ...original, codeEvidence, [section]: detail(source) },
        ]),
      })),
      null,
    ).findings[0]![
      section as "rootCause" | "root_cause" | "validation" | "attackPath"
    ] as Record<string, unknown> | undefined;

    expect(references?.[key]).toHaveLength(5);
    for (const sequence of sequences) {
      let index = 0;
      for (const reference of references?.[key] as string[]) {
        if (sequence[index] === reference) index += 1;
      }
      expect(index).toBe(sequence.length);
    }
  }
});

test("rejects transferring accepted threat predicates to unrelated subjects", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const administrator = reducerFinding("administrator");
  const attacker = reducerFinding("attacker");
  const source = reducerDraft([administrator], {
    threatModel: { summary: "Administrator cannot bypass authentication." },
  });
  const unrelated = reducerDraft([attacker], {
    scope: {
      summary: "Administrator and attacker routes use distinct controls.",
    },
  });

  expect(() =>
    reconcileDeepReduction(
      reducerDraft([administrator, attacker], {
        scope: unrelated.scope,
        threatModel: {
          summary: "Administrator and attacker cannot bypass authentication.",
        },
      }),
      [
        { workerId: "administrator", result: source },
        { workerId: "attacker", result: unrelated },
      ],
      null,
    ),
  ).toThrow("threatModel.summary");
});

test("keeps Boolean and qualified threat claims independently attributable", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const administrator = reducerFinding("administrator");
  const attacker = reducerFinding("attacker");
  const scope = {
    summary: "Administrator and attacker request paths were reviewed.",
  };

  for (const { first, second, synthesized } of [
    {
      first: "The administrator, or the service, can bypass authentication.",
      second: "The attacker, or the service, can bypass authentication.",
      synthesized:
        "The administrator and attacker, or the service, can bypass authentication.",
    },
    {
      first: "The administrator or service can bypass authentication.",
      second: "The attacker or service can bypass authentication.",
      synthesized:
        "The administrator and attacker or service can bypass authentication.",
    },
    {
      first: "The administrator (or service) can bypass authentication.",
      second: "The attacker (or service) can bypass authentication.",
      synthesized:
        "The administrator and attacker (or service) can bypass authentication.",
    },
    {
      first: "The administrator cannot bypass authentication.",
      second: "The attacker cannot bypass authentication.",
      synthesized:
        "The administrator and attacker cannot bypass authentication.",
    },
    {
      first: "The administrator can bypass authentication only in testing.",
      second: "The attacker can bypass authentication only in testing.",
      synthesized:
        "The administrator and attacker can bypass authentication only in testing.",
    },
    {
      first:
        "The administrator can bypass authentication if the service is offline.",
      second:
        "The attacker can bypass authentication if the service is offline.",
      synthesized:
        "The administrator and attacker can bypass authentication if the service is offline.",
    },
  ]) {
    for (const discoveries of [
      [
        {
          workerId: "administrator",
          result: reducerDraft([administrator], {
            threatModel: { summary: first },
          }),
        },
        {
          workerId: "attacker",
          result: reducerDraft([attacker], {
            scope,
            threatModel: { summary: second },
          }),
        },
      ],
      [
        {
          workerId: "attacker",
          result: reducerDraft([attacker], {
            scope,
            threatModel: { summary: second },
          }),
        },
        {
          workerId: "administrator",
          result: reducerDraft([administrator], {
            threatModel: { summary: first },
          }),
        },
      ],
    ]) {
      expect(() =>
        reconcileDeepReduction(
          reducerDraft([administrator, attacker], {
            scope,
            threatModel: { summary: synthesized },
          }),
          discoveries,
          null,
        ),
      ).toThrow("threatModel.summary");

      const preserved = `${first}\n\n${second}`;
      expect(
        reconcileDeepReduction(
          reducerDraft([administrator, attacker], {
            scope,
            threatModel: { summary: preserved },
          }),
          discoveries,
          null,
        ).threatModel?.["summary"],
      ).toBe(preserved);
    }
  }

  const shared = reducerFinding("shared");
  const independent = reducerFinding("independent");
  const modifierScope = {
    summary: "Shared and independent request paths were reviewed.",
  };
  for (const prefix of [
    "Requests or automated tools may reach",
    "Requests and automated tools may reach",
    "Neither requests nor automated tools may reach",
    "Requests cannot reach",
    "Requests do not reach",
    "Only authenticated requests reach",
    "Requests reach unless excluded from",
  ]) {
    const first = `${prefix} shared code.`;
    const second = `${prefix} independent code.`;
    const discoveries = [
      {
        workerId: "shared",
        result: reducerDraft([shared], { threatModel: { summary: first } }),
      },
      {
        workerId: "independent",
        result: reducerDraft([independent], {
          scope: modifierScope,
          threatModel: { summary: second },
        }),
      },
    ];
    expect(() =>
      reconcileDeepReduction(
        reducerDraft([shared, independent], {
          scope: modifierScope,
          threatModel: { summary: `${prefix} shared and independent code.` },
        }),
        discoveries,
        null,
      ),
    ).toThrow("threatModel.summary");
    expect(
      reconcileDeepReduction(
        reducerDraft([shared, independent], {
          scope: modifierScope,
          threatModel: { summary: `${first}\n\n${second}` },
        }),
        discoveries,
        null,
      ).threatModel?.["summary"],
    ).toBe(`${first}\n\n${second}`);
  }

  const unicodeFirst = "Requests may reach shared sécurité。";
  const unicodeSecond = "Requests may reach independent sécurité。";
  const unicodeDiscoveries = [
    {
      workerId: "shared",
      result: reducerDraft([shared], {
        threatModel: { summary: unicodeFirst },
      }),
    },
    {
      workerId: "independent",
      result: reducerDraft([independent], {
        scope: modifierScope,
        threatModel: { summary: unicodeSecond },
      }),
    },
  ];
  expect(() =>
    reconcileDeepReduction(
      reducerDraft([shared, independent], {
        scope: modifierScope,
        threatModel: {
          summary: "Requests may reach shared and independent sécurité。",
        },
      }),
      unicodeDiscoveries,
      null,
    ),
  ).toThrow("threatModel.summary");
  expect(
    reconcileDeepReduction(
      reducerDraft([shared, independent], {
        scope: modifierScope,
        threatModel: {
          summary: `${unicodeFirst}\n\n${unicodeSecond}`,
        },
      }),
      unicodeDiscoveries,
      null,
    ).threatModel?.["summary"],
  ).toBe(`${unicodeFirst}\n\n${unicodeSecond}`);

  for (const { first, second, combined } of [
    {
      first: "Remote attackers reach administrator endpoints",
      second: "only in tests.",
      combined: "Remote attackers reach administrator endpoints only in tests.",
    },
    {
      first: "Remote attackers are trusted",
      second: "not.",
      combined: "Remote attackers are trustednot.",
    },
    {
      first: "Authentication may block attackers",
      second: "Remote execution succeeds",
      combined: "Authentication may block attackers Remote execution succeeds",
    },
  ]) {
    const discoveries = [
      {
        workerId: "first-claim",
        result: reducerDraft([], { threatModel: { summary: first } }),
      },
      {
        workerId: "second-claim",
        result: reducerDraft([], { threatModel: { summary: second } }),
      },
    ];
    expect(() =>
      reconcileDeepReduction(
        reducerDraft([], { threatModel: { summary: combined } }),
        discoveries,
        null,
      ),
    ).toThrow("threatModel.summary");
    const separate = `${first}\n\n${second}`;
    expect(
      reconcileDeepReduction(
        reducerDraft([], { threatModel: { summary: separate } }),
        discoveries,
        null,
      ).threatModel?.["summary"],
    ).toBe(separate);
  }
});

test("preserves each complete accepted threat claim when claims overlap", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  for (const { broad, qualified } of [
    {
      broad: "Remote attackers reach administrator endpoints",
      qualified:
        "Remote attackers reach administrator endpoints only in tests.",
    },
    {
      broad: "Les attaquants atteignent la sécurité",
      qualified: "Les attaquants atteignent la sécurité uniquement en test.",
    },
    {
      broad: "Exploit succeeds",
      qualified: "Exploit succeeds? No.",
    },
    {
      broad: "Exploit succeeds",
      qualified: "Exploit succeeds! Never.",
    },
    {
      broad: "Exploit succeeds",
      qualified: "Exploit succeeds？ No.",
    },
    {
      broad: "Exploit succeeds",
      qualified: "Exploit succeeds！ Never.",
    },
  ]) {
    for (const summaries of [
      [broad, qualified],
      [qualified, broad],
    ]) {
      const discoveries = summaries.map((summary, index) => ({
        workerId: `worker-${index}`,
        result: reducerDraft([], { threatModel: { summary } }),
      }));

      expect(() =>
        reconcileDeepReduction(
          reducerDraft([], { threatModel: { summary: qualified } }),
          discoveries,
          null,
        ),
      ).toThrow("threatModel.summary");

      const complete = `${broad}\n\n${qualified}`;
      expect(
        reconcileDeepReduction(
          reducerDraft([], { threatModel: { summary: complete } }),
          discoveries,
          null,
        ).threatModel?.["summary"],
      ).toBe(complete);
    }
  }
});

test("preserves every distinct accepted threat-model claim without synthesis", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const shared = reducerFinding("shared", "Accepted shared request path.");
  const independent = reducerFinding(
    "independent",
    "Accepted independent request path.",
  );
  const threatModelSource = reducerDraft([shared], {
    threatModel: { summary: "Requests may reach shared code." },
  });
  const scopeSource = reducerDraft([independent], {
    scope: { summary: "Shared and independent request handling." },
    threatModel: { summary: "Requests may reach independent code." },
  });
  const discoveries = [
    { workerId: "threat-model", result: threatModelSource },
    { workerId: "scope", result: scopeSource },
  ];

  const reduced = reconcileDeepReduction(
    reducerDraft([shared, independent], {
      scope: scopeSource.scope,
      threatModel: {
        summary:
          "Requests may reach shared code.\n\nRequests may reach independent code.",
      },
    }),
    discoveries,
    null,
  );
  expect(reduced.threatModel?.["summary"]).toBe(
    "Requests may reach shared code.\n\nRequests may reach independent code.",
  );

  expect(() =>
    reconcileDeepReduction(
      reducerDraft([shared, independent], {
        scope: scopeSource.scope,
        threatModel: {
          summary: "Requests may reach shared and independent code.",
        },
      }),
      discoveries,
      null,
    ),
  ).toThrow("threatModel.summary");

  expect(() =>
    reconcileDeepReduction(
      reducerDraft([shared, independent], {
        scope: scopeSource.scope,
        threatModel: {
          summary: "Unauthenticated remote attackers exploit the service.",
        },
      }),
      discoveries,
      null,
    ),
  ).toThrow("threatModel.summary");

  expect(() =>
    reconcileDeepReduction(
      reducerDraft([], {
        scope: scopeSource.scope,
        threatModel: {
          summary: "Requests may reach shared and independent code.",
        },
      }),
      [
        {
          workerId: "threat-model",
          result: reducerDraft([], {
            threatModel: threatModelSource.threatModel,
          }),
        },
        {
          workerId: "scope",
          result: reducerDraft([], { scope: scopeSource.scope }),
        },
      ],
      null,
    ),
  ).toThrow("threatModel.summary");

  const firstClaim = "Administrators are not trusted.";
  const secondClaim = "Workers are not privileged.";
  const independentlyGrounded = reconcileDeepReduction(
    reducerDraft([], {
      threatModel: { summary: `${firstClaim} ${secondClaim}` },
    }),
    [
      {
        workerId: "administrator-boundary",
        result: reducerDraft([], { threatModel: { summary: firstClaim } }),
      },
      {
        workerId: "worker-boundary",
        result: reducerDraft([], { threatModel: { summary: secondClaim } }),
      },
    ],
    null,
  );
  expect(independentlyGrounded.threatModel?.["summary"]).toBe(
    `${firstClaim} ${secondClaim}`,
  );

  const overlappingFirst = "Remote attackers are not trusted.";
  const overlappingSecond = "Remote attackers are not privileged.";
  expect(
    reconcileDeepReduction(
      reducerDraft([], {
        threatModel: {
          summary: `${overlappingFirst} ${overlappingSecond}`,
        },
      }),
      [
        {
          workerId: "trust-boundary",
          result: reducerDraft([], {
            threatModel: { summary: overlappingFirst },
          }),
        },
        {
          workerId: "privilege-boundary",
          result: reducerDraft([], {
            threatModel: { summary: overlappingSecond },
          }),
        },
      ],
      null,
    ).threatModel?.["summary"],
  ).toBe(`${overlappingFirst} ${overlappingSecond}`);
});

test("rejects threat-model synthesis that drops or reverses accepted claims", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());

  const unsupported: Array<{
    accepted: string;
    synthesized: string;
    scope?: string;
    duplicate?: boolean;
    anotherAccepted?: string;
  }> = [
    {
      accepted: "Unauthenticated attackers cannot reach admin endpoints.",
      synthesized: "Attackers reach admin endpoints.",
    },
    {
      accepted: "Requests may reach shared code.",
      synthesized: "Requests reach shared code.",
    },
    {
      accepted: "Authentication may block attackers.",
      synthesized: "Authentication blocks attackers.",
    },
    {
      accepted: "Remote attackers are not trusted.",
      synthesized: "Remote attackers are trusted.",
    },
    {
      accepted: "Remote attackers are not trusted.",
      synthesized: "Remote attackers are not not trusted.",
    },
    {
      accepted: "Remote attackers are not trusted.",
      synthesized: "Remote attackers are not not trusted.",
      duplicate: true,
    },
    {
      accepted: "Remote attackers are not trusted.",
      anotherAccepted: "Remote attackers are not trusted. Always.",
      synthesized: "Remote attackers are not not trusted. Always.",
    },
    {
      accepted: "Remote attackers are not trusted.",
      synthesized: "Remote attackers are trusted not trusted.",
    },
    {
      accepted: "Remote attackers are not trusted.",
      synthesized: "!!!",
    },
    {
      accepted: "Remote attackers are not trusted.",
      synthesized: "Trusted attackers are not remote.",
    },
    {
      accepted: "No authentication is required.",
      synthesized: "No, authentication is required.",
    },
    {
      accepted: "No remote attacker is trusted.",
      synthesized: "No, remote attacker is trusted.",
    },
    {
      accepted: "Remote attackers are trusted.",
      synthesized: "Remote attackers are trusted?",
    },
    {
      accepted: "Remote attackers are trusted.",
      synthesized: "Remote attackers are not trusted.",
      scope: "Not all request handlers were assessed.",
    },
    {
      accepted: "Remote attackers are trusted.",
      synthesized: "No remote attackers are trusted.",
      scope: "No request handler was assessed.",
    },
    {
      accepted: "Remote attackers are trusted.",
      synthesized: "Remote attackers are never trusted.",
      scope: "Never assessed the request handler.",
    },
    {
      accepted: "Remote attackers are trusted.",
      synthesized: "Remote attackers are trusted without review.",
      scope: "Without review.",
    },
    {
      accepted: "Remote attackers reach admin endpoints.",
      synthesized: "Remote attackers cannot reach admin endpoints.",
      scope: "Some users cannot authenticate.",
    },
    {
      accepted: "Remote attackers can reach admin endpoints.",
      synthesized: "Remote attackers can't reach admin endpoints.",
      scope: "We can't inspect every request handler.",
    },
    {
      accepted: "Remote attackers cannot reach admin endpoints.",
      synthesized:
        "Remote attackers cannot reach admin endpoints unless authenticated.",
      scope: "Review the endpoint unless authenticated.",
    },
    {
      accepted: "Remote attackers cannot reach admin endpoints.",
      synthesized:
        "Remote attackers cannot reach admin endpoints except when authenticated.",
      scope: "Except when authenticated.",
    },
    {
      accepted: "Remote attackers can reach admin endpoints.",
      synthesized:
        "Remote attackers can reach admin endpoints only after authentication.",
      scope: "Only after authentication.",
    },
    {
      accepted: "Remote attackers can reach admin endpoints.",
      synthesized: "Remote attackers can only reach admin endpoints.",
      scope: "Only after authentication.",
    },
    {
      accepted: "Remote attackers can reach admin endpoints.",
      synthesized:
        "Remote attackers can reach admin endpoints if authenticated.",
      scope: "If authenticated.",
    },
    {
      accepted: "Remote attackers can reach admin endpoints.",
      synthesized:
        "Remote attackers can reach admin endpoints when authenticated.",
      scope: "When authenticated.",
    },
    {
      accepted: "Remote attackers can reach admin endpoints.",
      synthesized:
        "Remote attackers can reach admin endpoints provided authentication succeeds.",
      scope: "Provided authentication succeeds.",
    },
    {
      accepted: "Remote attackers can reach admin endpoints.",
      synthesized:
        "Remote attackers can reach admin endpoints following successful authentication.",
      scope: "Following successful authentication.",
    },
    {
      accepted: "Remote requests are accepted unconditionally.",
      synthesized: "Remote requests are accepted and not unconditionally.",
      scope: "Accepted and not audited requests were assessed.",
    },
    {
      accepted: "Authentication is required always.",
      synthesized: "Authentication is required and not always.",
      scope: "Required and not audited controls were assessed.",
    },
  ];

  for (const {
    accepted,
    synthesized,
    scope,
    duplicate,
    anotherAccepted,
  } of unsupported) {
    const acceptedScope =
      scope === undefined ? {} : { scope: { summary: scope } };
    const acceptedDraft = reducerDraft([], {
      ...acceptedScope,
      threatModel: { summary: accepted },
    });
    expect(() =>
      reconcileDeepReduction(
        reducerDraft([], {
          ...acceptedScope,
          threatModel: { summary: synthesized },
        }),
        [
          { workerId: "worker", result: acceptedDraft },
          ...(duplicate || anotherAccepted !== undefined
            ? [
                {
                  workerId: "another-worker",
                  result:
                    anotherAccepted === undefined
                      ? acceptedDraft
                      : reducerDraft([], {
                          ...acceptedScope,
                          threatModel: { summary: anotherAccepted },
                        }),
                },
              ]
            : []),
        ],
        null,
      ),
    ).toThrow("threatModel.summary");
  }
});

test("reconciles unknown coverage with deferred and follow-up work", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());

  for (const pending of [
    { deferred: [{ reason: "The accepted surface needs follow-up." }] },
    {
      surfaces: [
        {
          label: "Accepted request handler",
          disposition: "needs_follow_up",
        },
      ],
    },
  ]) {
    const coverage: ReducerDraft["coverage"] = {
      completeness: "unknown",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      ...pending,
    };
    const reduced = reconcileDeepReduction(
      reducerDraft([], { coverage: structuredClone(coverage) }),
      [{ workerId: "worker", result: reducerDraft([], { coverage }) }],
      null,
    );

    expect(reduced.coverage).toEqual({ ...coverage, completeness: "partial" });
  }
});

test("preserves conflicting scan-wide scope evidence without inventing statuses", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  for (const field of ["runtimeStatus", "context", "summary"]) {
    const first = "Static review only.";
    const second = "Runtime exploit independently reproduced.";
    const discoveries = [
      {
        workerId: "static",
        result: reducerDraft([], { scope: { [field]: first } }),
      },
      {
        workerId: "runtime",
        result: reducerDraft([], { scope: { [field]: second } }),
      },
    ];
    for (const supplied of [first, second, `${first}\n\n${second}`]) {
      const reduced = reconcileDeepReduction(
        reducerDraft([], { scope: { [field]: supplied } }),
        discoveries,
        null,
      );
      const claims = (reduced.scope?.[field] as string).split(/\n\s*\n/u);
      expect(claims).toContain(first);
      expect(claims).toContain(second);
    }

    expect(() =>
      reconcileDeepReduction(
        reducerDraft([], {
          scope: {
            [field]: `${first}\n\n${second}\n\nInvented dynamic result.`,
          },
        }),
        discoveries,
        null,
      ),
    ).toThrow(`scope.${field}`);
  }

  expect(() =>
    reconcileDeepReduction(
      reducerDraft([], { scope: { reviewCount: 1 } }),
      [
        {
          workerId: "first",
          result: reducerDraft([], { scope: { reviewCount: 1 } }),
        },
        {
          workerId: "second",
          result: reducerDraft([], { scope: { reviewCount: 2 } }),
        },
      ],
      null,
    ),
  ).toThrow("scope.reviewCount");
});

test("preserves conflicting validation modes without disabling custom validation", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const pending = {
    validationMode: "custom_pending",
    context: "Accepted validation is still pending.",
  };
  const completed = {
    validationMode: "custom",
    context: "Accepted custom validation already ran.",
  };

  for (const sources of [
    [pending, completed],
    [completed, pending],
  ]) {
    const discoveries = sources.map((scope, index) => ({
      workerId: `worker-${index}`,
      result: reducerDraft([], { scope }),
    }));
    for (const supplied of ["custom_pending", "custom", undefined]) {
      const scope = reconcileDeepReduction(
        reducerDraft([], {
          scope: {
            ...(supplied === undefined ? {} : { validationMode: supplied }),
          },
        }),
        discoveries,
        null,
      ).scope!;

      // Custom validation starts only when this exact status remains pending.
      expect(scope["validationMode"]).toBe("custom_pending");
      const claims = (scope["context"] as string).split(/\n\s*\n/u);
      expect(claims).toContain(pending.context);
      expect(claims).toContain(completed.context);
      expect(claims).toContain("custom_pending");
      expect(claims).toContain("custom");
    }

    expect(() =>
      reconcileDeepReduction(
        reducerDraft([], { scope: { validationMode: "fabricated" } }),
        discoveries,
        null,
      ),
    ).toThrow("scope.validationMode");
    expect(() =>
      reconcileDeepReduction(
        reducerDraft([], {
          scope: { validationMode: "custom", context: "Invented outcome." },
        }),
        discoveries,
        null,
      ),
    ).toThrow("scope.context");
  }

  for (const selected of ["static", "dynamic", undefined]) {
    const scope = reconcileDeepReduction(
      reducerDraft([], {
        scope: {
          ...(selected === undefined ? {} : { validationMode: selected }),
        },
      }),
      [
        {
          workerId: "static",
          result: reducerDraft([], { scope: { validationMode: "static" } }),
        },
        {
          workerId: "dynamic",
          result: reducerDraft([], { scope: { validationMode: "dynamic" } }),
        },
      ],
      null,
    ).scope!;
    expect(scope["validationMode"]).toBe(selected ?? "static");
    expect((scope["context"] as string).split(/\n\s*\n/u)).toEqual([
      "static",
      "dynamic",
    ]);
  }

  const matching = reconcileDeepReduction(
    reducerDraft([], { scope: { validationMode: "custom_pending" } }),
    [
      {
        workerId: "first",
        result: reducerDraft([], {
          scope: { validationMode: "custom_pending" },
        }),
      },
      {
        workerId: "second",
        result: reducerDraft([], {
          scope: { validationMode: "custom_pending" },
        }),
      },
    ],
    null,
  ).scope!;
  expect(matching).toEqual({ validationMode: "custom_pending" });
});

test("rejects reducer-only scope, coverage, and threat-model evidence", async () => {
  const { reconcileDeepReduction } = bundledReducer(await loadBundledRuntime());
  const acceptedScope = {
    summary: "Accepted review.",
    limitations: ["No runtime access."],
    nested: { source: "accepted" },
  };
  const first = reducerFinding("first");
  const second = reducerFinding("second");
  const firstSource = reducerDraft([first], {
    scope: acceptedScope,
    threatModel: {
      summary: "Administrator boundary.",
      assets: ["accounts"],
    },
  });
  const secondSource = reducerDraft([second], {
    threatModel: {
      summary: "Worker boundary.",
      assets: ["workers"],
    },
  });
  const firstResult = () =>
    reducerDraft([first], {
      scope: structuredClone(acceptedScope),
      threatModel: structuredClone(firstSource.threatModel),
    });

  for (const { result, discoveries, error } of [
    {
      result: reducerDraft([first], {
        scope: { runtimeStatus: "Dynamically validated." },
      }),
      discoveries: [{ workerId: "first", result: reducerDraft([first]) }],
      error: "scope",
    },
    {
      result: {
        ...firstResult(),
        scope: { ...acceptedScope, runtimeStatus: "Dynamically validated." },
      },
      discoveries: [{ workerId: "first", result: firstSource }],
      error: "scope.runtimeStatus",
    },
    {
      result: {
        ...firstResult(),
        scope: {
          ...acceptedScope,
          nested: { source: "accepted", invented: "reducer-only" },
        },
      },
      discoveries: [{ workerId: "first", result: firstSource }],
      error: "scope.nested.invented",
    },
    {
      result: {
        ...firstResult(),
        scope: { ...acceptedScope, limitations: [] },
      },
      discoveries: [{ workerId: "first", result: firstSource }],
      error: "scope.limitations",
    },
    {
      result: {
        ...firstResult(),
        scope: { ...acceptedScope, summary: "Invented review." },
      },
      discoveries: [{ workerId: "first", result: firstSource }],
      error: "scope.summary",
    },
    {
      result: reducerDraft([first], {
        threatModel: { summary: "Invented boundary." },
      }),
      discoveries: [{ workerId: "first", result: reducerDraft([first]) }],
      error: "threatModel",
    },
    {
      result: reducerDraft([first, second], {
        scope: acceptedScope,
        threatModel: {
          summary: "Administrator boundary.\n\nWorker boundary.",
          assets: ["accounts", "workers"],
          attackerCapabilities: ["unauthenticated remote attacker"],
        },
      }),
      discoveries: [
        { workerId: "first", result: firstSource },
        { workerId: "second", result: secondSource },
      ],
      error: "threatModel.attackerCapabilities",
    },
    {
      result: {
        ...firstResult(),
        coverage: {
          ...firstResult().coverage,
          runtimeStatus: "Dynamically validated.",
        },
      },
      discoveries: [{ workerId: "first", result: firstSource }],
      error: "coverage.runtimeStatus",
    },
  ]) {
    expect(() => reconcileDeepReduction(result, discoveries, null)).toThrow(
      error,
    );
  }

  const valid = reconcileDeepReduction(
    reducerDraft([first, second], {
      scope: acceptedScope,
      threatModel: {
        summary: "Administrator boundary.\n\nWorker boundary.",
        assets: ["accounts", "workers"],
      },
    }),
    [
      { workerId: "first", result: firstSource },
      { workerId: "second", result: secondSource },
    ],
    null,
  );
  expect(valid.threatModel?.["assets"]).toEqual(["accounts", "workers"]);
});

test("revalidates original workers when recovering a Deep reduction", async () => {
  const first: ReducerFinding = {
    ...reducerFinding("first"),
    rootCause: { summary: "Accepted worker evidence reaches the response." },
  };
  const worker = reducerDraft([first]);
  const { rootCause: _rootCause, ...withoutRootCause } = first;
  const result = reducerDraft([withoutRootCause]);
  const files = new Map([
    ["worker.json", worker],
    ["result.json", result],
  ]);
  const inspected: Array<{ path: string; root: string }> = [];
  const checkpoints: ReducerDraft[] = [];
  const writes: Array<{ path: string; result: ReducerDraft }> = [];
  const { validateReducerArtifacts } = bundledReducer(
    await loadBundledRuntime(),
    { files, inspected, checkpoints, writes },
  );
  const input = {
    artifacts: { workersRoot: "workers", dedupRoot: "reducers" },
    artifactDir: "reducer",
    resultPath: "result.json",
    reducerId: "reducer",
    sourceDiscoveries: [{ id: "first", resultPath: "worker.json" }],
  };

  expect(await validateReducerArtifacts(input, "synthetic-scan")).toEqual({
    newFindings: 1,
  });
  expect(inspected).toContainEqual({ path: "worker.json", root: "workers" });
  expect(files.get("result.json")?.findings[0]?.rootCause).toEqual(
    first.rootCause,
  );
  expect(writes).toHaveLength(1);
  expect(writes[0]?.path).toBe("result.json");
  expect(checkpoints).toHaveLength(1);

  files.set("result.json", {
    ...result,
    scope: { runtimeStatus: "Dynamically validated." },
  });
  await expect(
    validateReducerArtifacts(input, "synthetic-scan"),
  ).rejects.toThrow("scope");
});

test("keeps every advertised Deep worker tool within Codex's name limit", async () => {
  const runtime = await loadBundledRuntime();
  const method = /  compactArtifactServer\(request\) \{[\s\S]*?\n  \}/u.exec(
    runtime,
  )?.[0];
  expect(method).toBeDefined();
  const pathImport = /\(0, (import_node_path\d+)\.join\)/u.exec(method!)?.[1];
  expect(pathImport).toBeDefined();
  const compactArtifactServer = new Function(
    pathImport!,
    `return ({${method}}).compactArtifactServer;`,
  )({ join }) as (
    this: { modelSettings: { artifactContext: Record<string, string> } },
    request: Record<string, unknown>,
  ) => Record<string, { args: string[]; env: NodeJS.ProcessEnv }>;

  const node = Bun.which("node");
  expect(node).not.toBeNull();
  const root = mkdtempSync(join(tmpdir(), "codex-security-deep-tools-"));
  const repoRoot = join(root, "repository");
  const scanRoot = join(root, "scan");
  mkdirSync(repoRoot);
  mkdirSync(scanRoot);

  try {
    for (const layout of ["worker", "reducer"] as const) {
      const artifactRoot = join(scanRoot, layout);
      mkdirSync(artifactRoot);
      const servers = compactArtifactServer.call(
        {
          modelSettings: {
            artifactContext: {
              pluginRoot: PLUGIN_ROOT,
              scanRoot,
              repoRoot,
              scanId: "test-scan",
            },
          },
        },
        {
          kind: layout === "reducer" ? "dedup" : "discovery",
          artifactContext: {
            root: artifactRoot,
            layout,
            ...(layout === "reducer"
              ? { deepReducer: { scanRoot, claimedWorkers: [] } }
              : {}),
          },
        },
      );
      expect(Object.keys(servers)).toEqual(["cs_artifacts"]);
      const server = servers["cs_artifacts"]!;
      const result = spawnSync(node!, server.args, {
        encoding: "utf8",
        env: { ...process.env, ...server.env },
        input: [
          '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"codex-security-test","version":"1.0.0"}}}',
          '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}',
          '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}',
          "",
        ].join("\n"),
        timeout: 30_000,
      });
      expect(result.status, result.stderr).toBe(0);
      const response = result.stdout
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as { id?: number; result?: unknown })
        .find((message) => message.id === 2)?.result as
        | { tools: Array<{ name: string }> }
        | undefined;
      expect(response).toBeDefined();
      expect(response!.tools.length).toBeGreaterThan(0);
      for (const tool of response!.tools) {
        expect(`mcp__cs_artifacts__${tool.name}`.length).toBeLessThanOrEqual(
          64,
        );
      }
      if (layout === "reducer") {
        expect(response!.tools.map((tool) => tool.name)).toContain(
          "record_codex_security_deep_reduction",
        );
      }
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("classifies owned worker tool failures without exposing their contents", async () => {
  const runtime = await loadBundledRuntime();
  const diagnosticSource = bundledFunction(runtime, "appendSafeItemDiagnostic");
  const recordHelper = /\b(isRecord\d*)\(item\)/u.exec(diagnosticSource)?.[1];
  expect(recordHelper).toBeDefined();
  const appendDiagnostic = new Function(
    [
      bundledFunction(runtime, recordHelper!),
      bundledFunction(runtime, "isSandboxNamespaceExhaustion"),
      bundledFunction(runtime, "appendUniqueDiagnostic"),
      diagnosticSource,
      "return appendSafeItemDiagnostic;",
    ].join("\n"),
  )() as (
    diagnostics: Array<{ code: string; message: string }>,
    event: Record<string, unknown>,
  ) => void;

  const secret = "synthetic-secret-never-log";
  for (const fixture of [
    {
      server: "cs_artifacts",
      tool: "record_codex_security_deep_reduction",
      result: { isError: true, content: [{ text: secret }] },
      error: null,
      reason: "returned an error",
    },
    {
      server: "cs_artifacts",
      tool: "additional_codex_security_worker_tool",
      result: null,
      error: { message: secret },
      reason: "transport failed",
    },
    {
      server: "codex_security_artifacts",
      tool: "record_codex_security_discovery_candidates",
      result: null,
      error: null,
      reason: "failed",
    },
  ]) {
    const diagnostics: Array<{ code: string; message: string }> = [];
    appendDiagnostic(diagnostics, {
      type: "mcp_tool_call",
      status: "failed",
      arguments: { token: secret },
      ...fixture,
    });
    expect(diagnostics).toEqual([
      {
        code: "artifact_tool_failed",
        message: `Codex worker artifact tool ${fixture.tool} ${fixture.reason}.`,
      },
    ]);
    expect(JSON.stringify(diagnostics)).not.toContain(secret);
  }

  const unrelatedDiagnostics: Array<{ code: string; message: string }> = [];
  appendDiagnostic(unrelatedDiagnostics, {
    type: "mcp_tool_call",
    status: "failed",
    server: "unrelated_server",
    tool: "record_codex_security_deep_reduction",
    result: { isError: true },
    error: null,
  });
  expect(unrelatedDiagnostics).toEqual([]);
});

test("does not retry textual missing-path worker failures", async () => {
  const runtime = await loadBundledRuntime();
  const errorClass =
    /var DeepScanNonRetryableError = class extends Error \{[\s\S]*?\n\};/u.exec(
      runtime,
    )?.[0];
  expect(errorClass).toBeDefined();
  const classify = new Function(
    "ARTIFACT_MCP_STARTUP_TIMEOUT_PATTERN",
    "REMOTE_PLUGIN_AUTH_WARNING_PATTERN",
    "isCodexCybersecurityPolicyRefusal",
    [
      errorClass!,
      bundledFunction(runtime, "classifyCodexWorkerError"),
      bundledFunction(runtime, "isCodexConfigurationFailure"),
      "return classifyCodexWorkerError;",
    ].join("\n"),
  )(/$^/u, /$^/u, () => false) as (error: Error) => Error;

  for (const diagnostic of [
    "Error: No such file or directory (os error 2)",
    "Error: The system cannot find the file specified. (os error 2)",
  ]) {
    const original = new Error(
      ["Codex Exec exited with code 1:", diagnostic].join("\n"),
    );
    const classified = classify(original);
    expect(classified.name).toBe("DeepScanNonRetryableError");
    expect(classified.cause).toBe(original);
  }
});

test("resumes only when the exact Standard worker or reducer result is missing", async () => {
  const runtime = await loadBundledRuntime();
  const source = bundledFunction(runtime, "isMissingWorkerResult");
  const pathImport = /\(0, (import_node_path\d+)\.join\)/u.exec(source)?.[1];
  expect(pathImport).toBeDefined();
  const isMissingWorkerResult = new Function(
    pathImport!,
    `${source}\nreturn isMissingWorkerResult;`,
  )({ join }) as (error: Error, artifactDirectory: string) => boolean;
  const artifactDirectory = join(tmpdir(), "codex-security-reducer-artifacts");
  const missingResult = Object.assign(new Error("result missing"), {
    code: "ENOENT",
    path: join(artifactDirectory, "result.json"),
  });
  const diagnosedMissingResult = Object.assign(
    new Error("artifact tool failed", { cause: missingResult }),
    { code: "artifact_tool_failed" },
  );

  expect(isMissingWorkerResult(missingResult, artifactDirectory)).toBe(true);
  expect(isMissingWorkerResult(diagnosedMissingResult, artifactDirectory)).toBe(
    true,
  );
  expect(
    isMissingWorkerResult(
      Object.assign(new Error("different artifact missing"), {
        code: "ENOENT",
        path: join(artifactDirectory, "candidates.jsonl"),
      }),
      artifactDirectory,
    ),
  ).toBe(false);
  expect(
    isMissingWorkerResult(
      Object.assign(new Error("result cannot be read"), {
        code: "EACCES",
        path: join(artifactDirectory, "result.json"),
      }),
      artifactDirectory,
    ),
  ).toBe(false);

  const standardContinuation = new Function(
    `${bundledFunction(runtime, "standardScanCompletionContinuation")}\nreturn standardScanCompletionContinuation;`,
  )() as (attempt: number) => string;
  expect(standardContinuation(1)).toContain("record_codex_security_scan_draft");
  expect(standardContinuation(1)).toMatch(/retry.*until it succeeds/iu);

  const continuation = new Function(
    `${bundledFunction(runtime, "reducerCompletionContinuation")}\nreturn reducerCompletionContinuation;`,
  )() as (attempt: number) => string;
  expect(continuation(1)).toContain("record_codex_security_deep_reduction");
  expect(continuation(1)).toMatch(/retry.*until it succeeds/iu);
});
