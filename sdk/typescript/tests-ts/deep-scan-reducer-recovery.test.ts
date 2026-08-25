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
  locations: Array<{ path: string; startLine: number }>;
  summary: string;
  severity?: { level: string; [field: string]: unknown };
  confidence?: { level: string; rationale?: string; [field: string]: unknown };
  rootCause?: {
    summary: string;
    evidenceRefs?: string[];
    [field: string]: unknown;
  };
  codeEvidence?: Array<{ id: string; code: string }>;
  validation?: { summary?: string; [field: string]: unknown };
  attackPath?: Record<string, unknown>;
  writeup?: { reportPath: string };
  provenance: {
    source: string;
    sourceFindingIds?: string[];
    sourceFindings?: Array<{ id: string; finding: ReducerFinding }>;
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
    locations: [{ path: "src/shared.ts", startLine: 10 }],
    summary,
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
      summary: "The reducer grouped both independently accepted observations.",
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
      evidence: { outcome: "not_reachable" },
    },
    attackPath: { reachability: { outcome: "not_reachable" } },
  };
  const reduced = {
    ...accepted,
    provenance: { ...accepted.provenance, sourceFindingIds: ["worker:0"] },
  };

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
          evidence: { outcome: "reachable" },
        },
      },
      error: "validation.evidence.outcome",
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
          ...accepted.rootCause!,
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
        ...reducerFinding("shared", "Both accepted observations."),
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
  expect(reduced.rootCause?.evidenceRefs).toEqual([
    "evidence-1",
    "evidence-1-2",
  ]);
  expect(reduced.rootCause?.summary).toContain(first.rootCause!.summary);
  expect(reduced.rootCause?.summary).toContain(second.rootCause!.summary);
});

test("accepts threat-model synthesis grounded in accepted scope and finding evidence", async () => {
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
  });
  const discoveries = [
    { workerId: "threat-model", result: threatModelSource },
    { workerId: "scope", result: scopeSource },
  ];

  const reduced = reconcileDeepReduction(
    reducerDraft([shared, independent], {
      scope: scopeSource.scope,
      threatModel: {
        summary: "Requests may reach shared and independent code.",
      },
    }),
    discoveries,
    null,
  );
  expect(reduced.threatModel?.["summary"]).toBe(
    "Requests may reach shared and independent code.",
  );

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
