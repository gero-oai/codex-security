import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

interface Assessment {
  [key: string]: unknown;
  schemaVersion: number;
  patch: {
    repository: string;
    sourceType: string;
    base: string;
    head: string;
    changedFiles: string[];
    sha256: string;
  };
  recommendation: string;
  workflowLabel: string;
  impact: { rating: string; rationale: string };
  regressionLikelihood: { rating: string; rationale: string };
  materialSafetyFailure: { established: boolean; evidence: string };
  regressionProtection: {
    rating: string;
    rationale: string;
    exactHeadChecksPassed: boolean;
  };
  recoverability: { rating: string; rationale: string };
  confidence: { rating: string; rationale: string };
  applicability: { status: string; rationale: string };
  statusQuoRisk: { rating: string; rationale: string };
  autoMergeExclusions: string[];
  affectedRuntimeRoots: string[];
  materialBoundaries: Array<{
    id: string;
    invariant: string;
    runtimeRoot: string;
    counterexample: string;
    counterexamplePath: string;
    legitimateControl: string;
    legitimateControlPath: string;
    result: string;
  }>;
  validation: Array<{
    name: string;
    status: string;
    protects: string;
    requiredForMerge: boolean;
    failureAttribution?: string;
  }>;
  unknowns: Array<{
    id: string;
    summary: string;
    decisionCritical: boolean;
  }>;
  evidencePlan: Array<{
    question: string;
    action: string;
    resolvesUnknowns: string[];
    remainingUnknowns?: Record<string, string[]>;
    resolvesBoundaries?: string[];
    boundaryOutcomes?: Record<string, Record<string, string>>;
    applicabilityOutcomes?: Record<string, string>;
    regressionLikelihoodOutcomes?: Record<string, string>;
    materialSafetyFailureOutcomes?: Record<string, boolean>;
    resolvesFailedValidation?: string[];
    outcomes: Record<string, string>;
  }>;
}

const schemaPath = join(
  PLUGIN_ROOT,
  "schemas",
  "patch-risk-assessment.schema.json",
);
const validatorPath = join(
  PLUGIN_ROOT,
  "skills",
  "assess-patch-risk",
  "scripts",
  "validate_patch_risk_assessment.py",
);
const skillPath = join(PLUGIN_ROOT, "skills", "assess-patch-risk", "SKILL.md");
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryRoots
      .splice(0)
      .map((root) => rm(root, { recursive: true, force: true })),
  );
});

function assessment(): Assessment {
  return {
    schemaVersion: 1,
    patch: {
      repository: "example/project",
      sourceType: "pull_request_diff",
      base: "a".repeat(40),
      head: "b".repeat(40),
      changedFiles: ["src/request.ts"],
      sha256: "c".repeat(64),
    },
    recommendation: "merge",
    workflowLabel: "human_review_required",
    impact: { rating: "moderate", rationale: "A bounded caller can fail." },
    regressionLikelihood: {
      rating: "low",
      rationale: "The changed path and its caller are covered.",
    },
    materialSafetyFailure: {
      established: false,
      evidence: "No material safety failure was established.",
    },
    regressionProtection: {
      rating: "strong",
      rationale: "Focused and integration checks passed at the exact head.",
      exactHeadChecksPassed: true,
    },
    recoverability: { rating: "easy", rationale: "A revert is isolated." },
    confidence: { rating: "high", rationale: "Runtime callers are known." },
    applicability: {
      status: "confirmed",
      rationale: "The path is deployed.",
    },
    statusQuoRisk: {
      rating: "moderate",
      rationale: "The defect remains.",
    },
    autoMergeExclusions: [],
    affectedRuntimeRoots: ["service.request"],
    materialBoundaries: [
      {
        id: "request-contract",
        invariant:
          "Supported requests retain their existing response contract.",
        runtimeRoot: "service.request",
        counterexample: "A supported request takes the changed branch.",
        counterexamplePath: "src/request.ts",
        legitimateControl: "A supported request takes the unchanged branch.",
        legitimateControlPath: "src/request.ts",
        result: "supported",
      },
    ],
    validation: [
      {
        name: "focused request tests",
        status: "passed",
        protects: "Changed behavior through the production caller.",
        requiredForMerge: true,
      },
    ],
    unknowns: [],
    evidencePlan: [],
  };
}

async function validateRaw(contents: string, stdin = false) {
  const root = await mkdtemp(join(tmpdir(), "codex-security-patch-risk-"));
  temporaryRoots.push(root);
  const assessmentPath = join(root, "assessment.json");
  await writeFile(assessmentPath, contents, "utf8");
  const python =
    process.env["PYTHON"] ??
    Bun.which("python3") ??
    Bun.which("python") ??
    Bun.which("py");
  expect(python).not.toBeNull();
  const result = spawnSync(
    python!,
    ["-I", "-S", "-B", validatorPath, stdin ? "-" : assessmentPath],
    {
      cwd: PLUGIN_ROOT,
      encoding: "utf8",
      input: stdin ? contents : undefined,
      env: {
        ...process.env,
        PYTHONNOUSERSITE: "1",
        PYTHONPATH: join(root, "unavailable-site-packages"),
        ...(stdin ? { PYTHONIOENCODING: "cp1252" } : {}),
      },
    },
  );
  return {
    ...result,
    stderr: result.stderr.replaceAll("\r\n", "\n"),
    assessmentPath,
    contents,
  };
}

async function validate(payload: Assessment, stdin = false) {
  return validateRaw(JSON.stringify(payload), stdin);
}

describe("patch risk assessment contract", () => {
  test("publishes a valid draft 2020-12 schema", async () => {
    const schema = JSON.parse(await readFile(schemaPath, "utf8"));
    expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    const validateSchema = new Ajv2020({
      strict: false,
      validateFormats: false,
    }).compile(schema);
    const valid = assessment();
    expect(validateSchema(valid), JSON.stringify(validateSchema.errors)).toBe(
      true,
    );

    const digestWithTrailingNewline = assessment();
    digestWithTrailingNewline.patch.sha256 = `${"c".repeat(64)}\n`;
    expect(validateSchema(digestWithTrailingNewline)).toBe(false);

    const identifierWithTrailingNewline = assessment();
    identifierWithTrailingNewline.materialBoundaries[0]!.id =
      "request-contract\n";
    expect(validateSchema(identifierWithTrailingNewline)).toBe(false);

    const byteOrderMarkOnly = assessment();
    byteOrderMarkOnly.patch.repository = "\uFEFF";
    expect(validateSchema(byteOrderMarkOnly)).toBe(false);

    for (const control of ["\u001C", "\u0085"]) {
      const ecmaNonWhitespace = assessment();
      ecmaNonWhitespace.patch.repository = control;
      expect(validateSchema(ecmaNonWhitespace)).toBe(true);
    }
  });

  test("documents the configured validator command over stdin", async () => {
    const skill = await readFile(skillPath, "utf8");
    const command = /```text\s+(.*?)\s+```/su.exec(skill)?.[1];
    expect(command?.trim().split(/\s+/u)).toEqual([
      "<python_command>",
      "-I",
      "-S",
      "-B",
      "<plugin_dir>/skills/assess-patch-risk/scripts/validate_patch_risk_assessment.py",
      "-",
    ]);
    expect(skill).not.toMatch(
      /^python\s+.*validate_patch_risk_assessment\.py/mu,
    );
  });

  test("requires fresh authorization decisions to reclassify every input and result", async () => {
    const skill = await readFile(skillPath, "utf8");
    expect(skill).toContain(
      "either reclassify every authorization-relevant principal attribute, resource attribute, policy input, entity binding, and resulting decision from current state",
    );
  });

  test.each(["\u001C", "\u0085"])(
    "matches ECMAScript non-whitespace handling for %p",
    async (control) => {
      const payload = assessment();
      payload.patch.repository = control;

      const result = await validate(payload);
      expect(result.status, result.stderr).toBe(0);
    },
  );

  test("isolates validator imports from the subject environment", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-patch-risk-imports-"),
    );
    temporaryRoots.push(root);
    const marker = join(root, "executed");
    await writeFile(
      join(root, "json.py"),
      [
        "from pathlib import Path",
        `Path(${JSON.stringify(marker)}).write_text(\"executed\")`,
        'raise RuntimeError("subject module executed")',
      ].join("\n"),
      "utf8",
    );
    const python =
      process.env["PYTHON"] ??
      Bun.which("python3") ??
      Bun.which("python") ??
      Bun.which("py");
    expect(python).not.toBeNull();

    const result = spawnSync(python!, ["-I", "-S", "-B", validatorPath, "-"], {
      cwd: PLUGIN_ROOT,
      encoding: "utf8",
      input: JSON.stringify(assessment()),
      env: { ...process.env, PYTHONPATH: root },
    });

    expect(result.status, result.stderr).toBe(0);
    expect(
      await readFile(marker, "utf8").catch(() => undefined),
    ).toBeUndefined();
  });

  test("validates a supported human-review merge without site packages", async () => {
    const result = await validate(assessment());
    expect(result.status, result.stderr).toBe(0);
  });

  test.each(["counterexamplePath", "legitimateControlPath"] as const)(
    "requires a patched source trace in %s",
    async (field) => {
      const payload = assessment();
      delete (
        payload.materialBoundaries[0] as Partial<
          Assessment["materialBoundaries"][number]
        >
      )[field];

      const result = await validate(payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(
        `required property '${field}' is missing`,
      );
    },
  );

  test("accepts omitted and empty optional evidence lists", async () => {
    const omitted = await validate(assessment());
    expect(omitted.status, omitted.stderr).toBe(0);

    const payload = assessment();
    payload["importantCallers"] = [];
    payload["riskDrivers"] = [];
    payload["protectiveFactors"] = [];
    const empty = await validate(payload);
    expect(empty.status, empty.stderr).toBe(0);
  });

  test("accepts UTF-8 assessment JSON on stdin", async () => {
    const payload = assessment();
    payload.impact.rationale =
      "A bounded caller can fail safely — verified with ā and 🛡️.";
    const result = await validate(payload, true);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
  });

  test("emits UTF-8 validation errors under a legacy console encoding", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    payload.validation[0]!.name = "検証";
    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "unknown";
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Which runtime owns this path?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-owner"],
        outcomes: { owned: "merge", unavailable: "hold_for_evidence" },
      },
    ];

    const result = await validate(payload, true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("failed validation '検証'");
    expect(result.stderr).not.toContain("UnicodeEncodeError");
  });

  test("accepts a strict low-risk auto-merge candidate", async () => {
    const payload = assessment();
    payload.workflowLabel = "auto_merge_candidate";
    payload.impact.rating = "low";
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("rejects whitespace-only decision evidence", async () => {
    const cases: Array<[string, (payload: Assessment) => void]> = [
      ["impact.rationale", (payload) => (payload.impact.rationale = " \t")],
      [
        "regressionLikelihood.rationale",
        (payload) => (payload.regressionLikelihood.rationale = " \t"),
      ],
      [
        "regressionProtection.rationale",
        (payload) => (payload.regressionProtection.rationale = " \t"),
      ],
      [
        "recoverability.rationale",
        (payload) => (payload.recoverability.rationale = " \t"),
      ],
      [
        "confidence.rationale",
        (payload) => (payload.confidence.rationale = " \t"),
      ],
      [
        "applicability.rationale",
        (payload) => (payload.applicability.rationale = " \t"),
      ],
      [
        "statusQuoRisk.rationale",
        (payload) => (payload.statusQuoRisk.rationale = " \t"),
      ],
      [
        "validation.0.protects",
        (payload) => (payload.validation[0]!.protects = " \t"),
      ],
    ];

    for (const [field, mutate] of cases) {
      const payload = assessment();
      payload.workflowLabel = "auto_merge_candidate";
      payload.impact.rating = "low";
      mutate(payload);

      const result = await validate(payload);
      expect(result.status, `${field}: ${result.stderr}`).not.toBe(0);
      expect(result.stderr).toContain(
        `${field}: string does not match the required pattern`,
      );
    }
  });

  test("requires usable and distinct range identities", async () => {
    for (const field of ["repository", "base", "head"] as const) {
      const payload = assessment();
      payload.patch[field] = " \t";

      const result = await validate(payload);
      expect(result.status, `${field}: ${result.stderr}`).not.toBe(0);
      expect(result.stderr).toContain(
        `patch.${field}: string does not match the required pattern`,
      );
    }

    const emptyRange = assessment();
    emptyRange.patch.head = emptyRange.patch.base;
    const rejected = await validate(emptyRange);
    expect(rejected.status).not.toBe(0);
    expect(rejected.stderr).toContain(
      "patch base and head must identify distinct revisions",
    );

    emptyRange.recommendation = "no_op";
    emptyRange.workflowLabel = "no_op";
    emptyRange.applicability = {
      status: "wrong_owner",
      rationale: "The comparison belongs to a different runtime owner.",
    };
    const noOp = await validate(emptyRange);
    expect(noOp.status, noOp.stderr).toBe(0);

    const opaqueRange = assessment();
    opaqueRange.patch.base = "\u00a0revision";
    opaqueRange.patch.head = "revision";
    const opaque = await validate(opaqueRange);
    expect(opaque.status, opaque.stderr).toBe(0);
  });

  test("accepts uppercase SHA-256 digests", async () => {
    const payload = assessment();
    payload.patch.sha256 = "A".repeat(64);
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("rejects non-low impact for auto-merge", async () => {
    const payload = assessment();
    payload.workflowLabel = "auto_merge_candidate";
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "auto_merge_candidate gate failed: impact.rating",
    );
  });

  test("rejects a material auto-merge exclusion", async () => {
    const payload = assessment();
    payload.workflowLabel = "auto_merge_candidate";
    payload.impact.rating = "low";
    payload.autoMergeExclusions = ["public_contract"];
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "auto_merge_candidate gate failed: autoMergeExclusions",
    );
  });

  test("allows skipped non-required validation evidence for auto-merge", async () => {
    const payload = assessment();
    payload.workflowLabel = "auto_merge_candidate";
    payload.impact.rating = "low";
    payload.validation.push({
      name: "optional platform benchmark",
      status: "skipped",
      protects: "An unaffected platform-specific performance boundary.",
      requiredForMerge: false,
    });

    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("rejects a merge with a decision-critical unknown", async () => {
    const payload = assessment();
    payload.unknowns = [
      {
        id: "deployment-ownership",
        summary: "Deployment ownership is unresolved.",
        decisionCritical: true,
      },
    ];
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "merge cannot retain a decision-critical unknown",
    );
  });

  test.each(["revise", "block"] as const)(
    "rejects a terminal %s verdict with a decision-critical unknown",
    async (recommendation) => {
      const payload = assessment();
      payload.recommendation = recommendation;
      payload.workflowLabel = recommendation;
      payload.unknowns = [
        {
          id: "deployment-scope",
          summary: "The deployment scope can still change the decision.",
          decisionCritical: true,
        },
      ];
      if (recommendation === "block") {
        payload.regressionLikelihood.rating = "critical";
      } else {
        payload.materialBoundaries[0]!.result = "contradicted";
      }

      const result = await validate(payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(
        `${recommendation} cannot retain a decision-critical unknown`,
      );
    },
  );

  test("rejects a merge with unknown applicability", async () => {
    const payload = assessment();
    payload.applicability = {
      status: "unknown",
      rationale: "The supported runtime owner is unresolved.",
    };
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("merge requires confirmed applicability");
  });

  test("rejects a merge with critical regression likelihood", async () => {
    const payload = assessment();
    payload.regressionLikelihood.rating = "critical";
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "merge cannot have critical regression likelihood",
    );
  });

  test("rejects a merge with low confidence", async () => {
    const payload = assessment();
    payload.confidence.rating = "low";
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("merge cannot have low confidence");
  });

  test("accepts unknown risk ratings while holding for evidence", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.impact.rating = "unknown";
    payload.regressionLikelihood.rating = "unknown";
    payload.confidence.rating = "low";
    payload.applicability = {
      status: "unknown",
      rationale: "Runtime reachability remains unresolved.",
    };
    payload.unknowns = [
      {
        id: "runtime-impact",
        summary: "The changed path's runtime impact is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the changed path reach a supported runtime?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-impact"],
        outcomes: {
          reachable: "merge",
          unreachable: "no_op",
        },
        applicabilityOutcomes: {
          reachable: "confirmed",
          unreachable: "no_live_effect",
        },
      },
    ];
    const unsafeMerge = await validate(payload);
    expect(unsafeMerge.status).not.toBe(0);
    expect(unsafeMerge.stderr).toContain(
      "a merge outcome cannot retain unknown impact",
    );

    payload.evidencePlan[0]!.outcomes["reachable"] = "hold_for_evidence";
    payload.evidencePlan[0]!.remainingUnknowns = {
      reachable: ["runtime-impact"],
      unreachable: [],
    };
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("rejects unknown risk ratings for merge", async () => {
    const payload = assessment();
    payload.impact.rating = "unknown";
    payload.regressionLikelihood.rating = "unknown";
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("merge cannot use impact.rating=unknown");
    expect(result.stderr).toContain(
      "only hold_for_evidence may use regressionLikelihood.rating=unknown",
    );
  });

  test.each(["revise", "no_op", "block"] as const)(
    "accepts unknown impact for a terminal %s recommendation",
    async (recommendation) => {
      const payload = assessment();
      payload.recommendation = recommendation;
      payload.workflowLabel = recommendation;
      payload.impact.rating = "unknown";
      payload.confidence.rating = "moderate";
      if (recommendation === "revise") {
        payload.materialBoundaries[0]!.result = "contradicted";
      } else if (recommendation === "no_op") {
        payload.applicability = {
          status: "superseded",
          rationale: "A narrower patch already landed.",
        };
      } else {
        payload.regressionLikelihood.rating = "critical";
        payload.materialSafetyFailure = {
          established: true,
          evidence: "The affected boundary permits a cross-subject decision.",
        };
      }

      const result = await validate(payload);
      expect(result.status, result.stderr).toBe(0);
    },
  );

  test("allows an empty changed-file identity only for no-op or an evidence hold", async () => {
    const payload = assessment();
    payload.patch.changedFiles = [];
    const merge = await validate(payload);
    expect(merge.status).not.toBe(0);
    expect(merge.stderr).toContain(
      "patch.changedFiles must be non-empty unless recommendation is no_op or hold_for_evidence",
    );

    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        id: "changed-file-inventory",
        summary:
          "The provider did not return a complete changed-file inventory.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Can the immutable final comparison be retrieved completely?",
        action: "Retrieve the same final comparison again from the provider.",
        resolvesUnknowns: ["changed-file-inventory"],
        remainingUnknowns: {
          complete: [],
          still_incomplete: ["changed-file-inventory"],
        },
        outcomes: {
          complete: "merge",
          still_incomplete: "hold_for_evidence",
        },
      },
    ];
    const hold = await validate(payload);
    expect(hold.status, hold.stderr).toBe(0);

    payload.recommendation = "no_op";
    payload.workflowLabel = "no_op";
    payload.confidence.rating = "high";
    payload.unknowns = [];
    payload.evidencePlan = [];
    payload.applicability = {
      status: "no_live_effect",
      rationale: "The immutable comparison contains no changed files.",
    };
    const noOp = await validate(payload);
    expect(noOp.status, noOp.stderr).toBe(0);
  });

  test("requires an affected runtime root for auto-merge", async () => {
    const payload = assessment();
    payload.workflowLabel = "auto_merge_candidate";
    payload.impact.rating = "low";
    payload.affectedRuntimeRoots = [];
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "auto_merge_candidate gate failed: affectedRuntimeRoots",
    );
  });

  test("requires a bounded evidence plan when holding", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.applicability = {
      status: "unknown",
      rationale: "Ownership of the rollout target remains unresolved.",
    };
    payload.unknowns = [
      {
        id: "rollout-target",
        summary: "The rollout target is unavailable.",
        decisionCritical: true,
      },
    ];
    const missingPlan = await validate(payload);
    expect(missingPlan.status).not.toBe(0);
    expect(missingPlan.stderr).toContain(
      "hold_for_evidence requires a bounded evidence plan",
    );

    payload.evidencePlan = [
      {
        question: "Does the changed configuration own the rollout target?",
        action: "Inspect the checked-in deployment mapping.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: {
          supported: "merge",
          contradicted: "no_op",
          unavailable: "hold_for_evidence",
        },
        applicabilityOutcomes: {
          supported: "confirmed",
          contradicted: "wrong_owner",
          unavailable: "unknown",
        },
      },
    ];
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("preserves known defect evidence while applicability remains unknown", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.regressionLikelihood.rating = "high";
    payload.applicability = {
      status: "unknown",
      rationale: "Runtime ownership remains unresolved.",
    };
    payload.materialBoundaries[0]!.result = "contradicted";
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The deployment owner is unknown.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does this repository own the affected runtime?",
        action: "Inspect the checked-in deployment registry.",
        resolvesUnknowns: ["runtime-owner"],
        outcomes: {
          owned: "revise",
          not_owned: "no_op",
        },
        applicabilityOutcomes: {
          owned: "confirmed",
          not_owned: "wrong_owner",
        },
      },
    ];

    const contradicted = await validate(payload);
    expect(contradicted.status, contradicted.stderr).toBe(0);

    payload.materialBoundaries[0]!.result = "supported";
    payload.regressionLikelihood.rating = "critical";
    const critical = await validate(payload);
    expect(critical.status, critical.stderr).toBe(0);

    payload.regressionLikelihood.rating = "high";
    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "patch_caused";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    const failed = await validate(payload);
    expect(failed.status, failed.stderr).toBe(0);
  });

  test("allows an evidence action for every decision-critical unknown", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = Array.from({ length: 4 }, (_, index) => ({
      id: `unknown-${index + 1}`,
      summary: `Decision-critical unknown ${index + 1}.`,
      decisionCritical: true,
    }));
    payload.evidencePlan = Array.from({ length: 4 }, (_, index) => ({
      question: `Question ${index + 1}?`,
      action: `Resolve unknown ${index + 1}.`,
      resolvesUnknowns: [`unknown-${index + 1}`],
      outcomes: {
        supported: "hold_for_evidence",
        contradicted: "hold_for_evidence",
      },
    }));

    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("binds every decision-critical unknown to a matching evidence action", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
      {
        id: "rollout-target",
        summary: "The rollout target is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Who owns the runtime?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-owner"],
        outcomes: {
          owned: "merge",
          not_owned: "no_op",
        },
      },
    ];

    const uncovered = await validate(payload);
    expect(uncovered.status).not.toBe(0);
    expect(uncovered.stderr).toContain(
      "decision-critical unknown 'rollout-target' requires a matching evidence plan",
    );

    payload.evidencePlan[0]!.resolvesUnknowns = [
      "runtime-owner",
      "missing-unknown",
    ];
    const mismatched = await validate(payload);
    expect(mismatched.status).not.toBe(0);
    expect(mismatched.stderr).toContain(
      "'missing-unknown' is not a decision-critical unknown",
    );
  });

  test("keeps a favorable evidence outcome on hold while another pivot remains", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
      {
        id: "rollout-target",
        summary: "The rollout target is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Who owns the runtime?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-owner"],
        outcomes: { owned: "merge", not_owned: "revise" },
      },
      {
        question: "Which target receives the rollout?",
        action: "Inspect the checked-in rollout registry.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: { targeted: "hold_for_evidence", absent: "revise" },
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "a merge outcome must resolve every decision-critical unknown",
    );
  });

  test("binds every unresolved boundary to a matching evidence action", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.materialBoundaries[0]!.result = "unresolved";
    payload.unknowns = [
      {
        id: "request-contract-evidence",
        summary: "The request contract evidence is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the request contract remain supported?",
        action: "Exercise the request contract through its production caller.",
        resolvesUnknowns: ["request-contract-evidence"],
        outcomes: { supported: "merge", contradicted: "revise" },
      },
    ];

    const missing = await validate(payload);
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain(
      "unresolved material boundary 'request-contract' requires a matching evidence plan",
    );

    payload.evidencePlan[0]!.resolvesBoundaries = ["request-contract"];
    payload.evidencePlan[0]!.boundaryOutcomes = {
      supported: { "request-contract": "supported" },
      contradicted: { "request-contract": "contradicted" },
    };
    const covered = await validate(payload);
    expect(covered.status, covered.stderr).toBe(0);
  });

  test("requires unique material boundary identifiers", async () => {
    const payload = assessment();
    payload.materialBoundaries.push({ ...payload.materialBoundaries[0]! });

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "material boundary identifiers must be unique",
    );
  });

  test("binds resolved boundaries to each evidence outcome", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.materialBoundaries[0]!.result = "unresolved";
    payload.unknowns = [
      {
        id: "request-contract-evidence",
        summary: "The request contract evidence is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the request contract remain supported?",
        action: "Exercise the contract through its production caller.",
        resolvesUnknowns: ["request-contract-evidence"],
        resolvesBoundaries: ["request-contract"],
        outcomes: { supported: "merge", contradicted: "revise" },
      },
    ];

    const missing = await validate(payload);
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain(
      "resolvesBoundaries requires boundaryOutcomes",
    );

    payload.evidencePlan[0]!.boundaryOutcomes = {
      supported: { "request-contract": "supported" },
      contradicted: { "request-contract": "contradicted" },
    };
    const valid = await validate(payload);
    expect(valid.status, valid.stderr).toBe(0);

    payload.evidencePlan[0]!.boundaryOutcomes!["supported"]![
      "request-contract"
    ] = "contradicted";
    const unsafeMerge = await validate(payload);
    expect(unsafeMerge.status).not.toBe(0);
    expect(unsafeMerge.stderr).toContain(
      "a merge outcome requires every resolved material boundary to be supported",
    );
  });

  test("requires unique unknown identifiers", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
      {
        id: "runtime-owner",
        summary: "The rollout owner is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Who owns the runtime?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-owner"],
        outcomes: {
          owned: "merge",
          not_owned: "no_op",
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("unknown identifiers must be unique");
  });

  test("requires failed checks to be attributed or matched to evidence", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        id: "rollout-target",
        summary: "The rollout target is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the changed configuration own the rollout target?",
        action: "Inspect the checked-in deployment mapping.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: {
          supported: "merge",
          contradicted: "revise",
        },
      },
    ];

    payload.regressionLikelihood.rating = "critical";
    const critical = await validate(payload);
    expect(critical.status).not.toBe(0);
    expect(critical.stderr).toContain(
      "hold_for_evidence cannot have critical regression likelihood",
    );

    payload.regressionLikelihood.rating = "high";
    payload.materialBoundaries[0]!.result = "contradicted";
    const contradicted = await validate(payload);
    expect(contradicted.status).not.toBe(0);
    expect(contradicted.stderr).toContain(
      "hold_for_evidence cannot retain a contradicted material boundary",
    );

    payload.materialBoundaries[0]!.result = "supported";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    payload.validation[0]!.status = "failed";
    const missingAttribution = await validate(payload);
    expect(missingAttribution.status).not.toBe(0);
    expect(missingAttribution.stderr).toContain(
      "failed validation requires failureAttribution",
    );

    payload.validation[0]!.failureAttribution = "patch_caused";
    const establishedFailure = await validate(payload);
    expect(establishedFailure.status).not.toBe(0);
    expect(establishedFailure.stderr).toContain(
      "a patch-caused validation failure requires revise, a separately justified block, or an established no-op disposition",
    );

    payload.validation[0]!.failureAttribution = "unknown";
    const missingMatchingPlan = await validate(payload);
    expect(missingMatchingPlan.status).not.toBe(0);
    expect(missingMatchingPlan.stderr).toContain(
      "with unknown attribution requires a matching evidence plan",
    );

    payload.evidencePlan[0]!.resolvesFailedValidation = ["another check"];
    const mismatchedPlan = await validate(payload);
    expect(mismatchedPlan.status).not.toBe(0);
    expect(mismatchedPlan.stderr).toContain(
      "is not a failed validation with unknown attribution",
    );

    payload.evidencePlan[0]!.resolvesFailedValidation = [
      "focused request tests",
    ];
    const missingAttributionOutcomes = await validate(payload);
    expect(missingAttributionOutcomes.status).not.toBe(0);
    expect(missingAttributionOutcomes.stderr).toContain(
      "failed-validation attribution requires patch_caused and not_patch_caused outcomes",
    );

    payload.evidencePlan[0]!.outcomes = {
      patch_caused: "no_op",
      not_patch_caused: "merge",
    };
    const applicableNoOp = await validate(payload);
    expect(applicableNoOp.status).not.toBe(0);
    expect(applicableNoOp.stderr).toContain(
      "a no_op outcome requires a non-applicable applicability outcome from the same action",
    );

    payload.applicability = {
      status: "unknown",
      rationale:
        "The same evidence action determines whether the patch still applies.",
    };
    const unboundNoOp = await validate(payload);
    expect(unboundNoOp.status).not.toBe(0);
    expect(unboundNoOp.stderr).toContain(
      "a no_op outcome requires a non-applicable applicability outcome from the same action",
    );

    payload.evidencePlan[0]!.applicabilityOutcomes = {
      patch_caused: "no_live_effect",
      not_patch_caused: "confirmed",
    };
    payload.evidencePlan[0]!.outcomes = {
      patch_caused: "merge",
      not_patch_caused: "revise",
    };
    const unsafePatchOutcome = await validate(payload);
    expect(unsafePatchOutcome.status).not.toBe(0);
    expect(unsafePatchOutcome.stderr).toContain(
      "a patch_caused outcome must recommend revise, block, or no_op",
    );

    payload.evidencePlan[0]!.outcomes = {
      patch_caused: "no_op",
      not_patch_caused: "merge",
    };
    const inapplicablePatchOutcome = await validate(payload);
    expect(
      inapplicablePatchOutcome.status,
      inapplicablePatchOutcome.stderr,
    ).toBe(0);

    payload.validation[0]!.failureAttribution = "patch_caused";
    delete payload.evidencePlan[0]!.resolvesFailedValidation;
    payload.evidencePlan[0]!.outcomes = {
      applicable: "merge",
      not_applicable: "no_op",
    };
    payload.evidencePlan[0]!.applicabilityOutcomes = {
      applicable: "confirmed",
      not_applicable: "no_live_effect",
    };
    const establishedDefectMerge = await validate(payload);
    expect(establishedDefectMerge.status).not.toBe(0);
    expect(establishedDefectMerge.stderr).toContain(
      "a merge outcome cannot retain an established defect",
    );

    payload.evidencePlan[0]!.outcomes["applicable"] = "hold_for_evidence";
    const establishedDefectHold = await validate(payload);
    expect(establishedDefectHold.status).not.toBe(0);
    expect(establishedDefectHold.stderr).toContain(
      "confirmed applicability with an established defect requires revise or block",
    );

    payload.validation[0]!.failureAttribution = "unknown";
    payload.evidencePlan[0]!.resolvesFailedValidation = [
      "focused request tests",
    ];
    payload.evidencePlan[0]!.outcomes = {
      patch_caused: "revise",
      not_patch_caused: "merge",
    };
    payload.evidencePlan[0]!.applicabilityOutcomes = {
      patch_caused: "confirmed",
      not_patch_caused: "confirmed",
    };
    const unattributedFailure = await validate(payload);
    expect(unattributedFailure.status, unattributedFailure.stderr).toBe(0);

    payload.validation[0]!.failureAttribution = "not_patch_caused";
    delete payload.evidencePlan[0]!.resolvesFailedValidation;
    payload.evidencePlan[0]!.outcomes = {
      supported: "merge",
      alternate: "merge",
    };
    payload.evidencePlan[0]!.applicabilityOutcomes = {
      supported: "confirmed",
      alternate: "confirmed",
    };
    const attributedFailure = await validate(payload);
    expect(attributedFailure.status, attributedFailure.stderr).toBe(0);

    payload.validation[0]!.status = "unavailable";
    delete payload.validation[0]!.failureAttribution;
    const unresolved = await validate(payload);
    expect(unresolved.status, unresolved.stderr).toBe(0);
  });

  test("allows evidence outcomes with the same terminal recommendation", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        id: "rollout-target",
        summary: "The rollout target is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the changed configuration own the rollout target?",
        action: "Inspect the checked-in deployment mapping.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: {
          supported: "merge",
          contradicted: "merge",
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("requires terminal evidence branches to justify revise or block", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.regressionLikelihood.rating = "moderate";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "unknown";
    payload.unknowns = [
      {
        id: "failure-attribution",
        summary: "The failed check attribution is unknown.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Did the patch cause the failed check?",
        action: "Run the same check against the immutable base.",
        resolvesUnknowns: ["failure-attribution"],
        resolvesFailedValidation: ["focused request tests"],
        outcomes: {
          patch_caused: "revise",
          not_patch_caused: "block",
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "a block outcome requires critical regression likelihood",
    );
  });

  test("requires critical likelihood for a patch-caused block", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.regressionLikelihood.rating = "moderate";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "unknown";
    payload.unknowns = [
      {
        id: "failure-attribution",
        summary: "The failed check attribution is unknown.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Did the patch cause the failed check?",
        action: "Run the same check against the immutable base.",
        resolvesUnknowns: ["failure-attribution"],
        resolvesFailedValidation: ["focused request tests"],
        outcomes: {
          patch_caused: "block",
          not_patch_caused: "merge",
        },
      },
    ];

    const unqualified = await validate(payload);
    expect(unqualified.status).not.toBe(0);
    expect(unqualified.stderr).toContain(
      "a block outcome requires critical regression likelihood",
    );

    payload.materialBoundaries[0]!.result = "unresolved";
    payload.evidencePlan[0]!.resolvesBoundaries = ["request-contract"];
    payload.evidencePlan[0]!.boundaryOutcomes = {
      patch_caused: { "request-contract": "contradicted" },
      not_patch_caused: { "request-contract": "supported" },
    };
    const contradicted = await validate(payload);
    expect(contradicted.status).not.toBe(0);
    expect(contradicted.stderr).toContain(
      "a block outcome requires critical regression likelihood",
    );

    payload.evidencePlan[0]!.outcomes["inconclusive"] = "merge";
    const inconclusive = await validate(payload);
    expect(inconclusive.status).not.toBe(0);
    expect(inconclusive.stderr).toContain(
      "an inconclusive failed-validation outcome must remain on hold",
    );
  });

  test("allows an evidence branch to establish a material critical block", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.regressionLikelihood.rating = "moderate";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "unknown";
    payload.unknowns = [
      {
        id: "failure-attribution",
        summary: "The failed safety check attribution is unknown.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Did the patch cause the material safety failure?",
        action: "Run the safety check against the immutable base.",
        resolvesUnknowns: ["failure-attribution"],
        resolvesFailedValidation: ["focused request tests"],
        outcomes: {
          patch_caused: "block",
          not_patch_caused: "merge",
        },
        regressionLikelihoodOutcomes: {
          patch_caused: "critical",
          not_patch_caused: "low",
        },
        materialSafetyFailureOutcomes: {
          patch_caused: true,
          not_patch_caused: false,
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("rejects merge and applicable hold branches with critical safety failures", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        id: "safety-result",
        summary: "The material safety result is unknown.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the patch create a material safety failure?",
        action: "Run the safety check against the immutable patch.",
        resolvesUnknowns: ["safety-result"],
        outcomes: { unsafe: "merge", safe: "merge" },
        regressionLikelihoodOutcomes: { unsafe: "critical", safe: "low" },
        materialSafetyFailureOutcomes: { unsafe: true, safe: false },
      },
    ];

    const merge = await validate(payload);
    expect(merge.status).not.toBe(0);
    expect(merge.stderr).toContain(
      "a merge outcome cannot establish critical regression likelihood",
    );
    expect(merge.stderr).toContain(
      "a merge outcome cannot establish a material safety failure",
    );

    payload.unknowns.push({
      id: "deployment-target",
      summary: "The deployment target is unknown.",
      decisionCritical: true,
    });
    payload.evidencePlan[0]!.outcomes["unsafe"] = "hold_for_evidence";
    payload.evidencePlan[0]!.remainingUnknowns = {
      unsafe: ["deployment-target"],
      safe: ["deployment-target"],
    };
    const hold = await validate(payload);
    expect(hold.status).not.toBe(0);
    expect(hold.stderr).toContain(
      "an applicable hold outcome cannot establish critical regression likelihood",
    );
    expect(hold.stderr).toContain(
      "an applicable hold outcome cannot establish a material safety failure",
    );
  });

  test("rejects a hold branch that establishes a contradicted boundary", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.materialBoundaries[0]!.result = "unresolved";
    payload.unknowns = [
      {
        id: "boundary-result",
        summary: "The boundary result is unknown.",
        decisionCritical: true,
      },
      {
        id: "rollout-target",
        summary: "The rollout target is unknown.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the boundary preserve the required control?",
        action: "Trace both cases through the patched source.",
        resolvesUnknowns: ["boundary-result"],
        remainingUnknowns: {
          supported: ["rollout-target"],
          contradicted: ["rollout-target"],
        },
        resolvesBoundaries: ["request-contract"],
        boundaryOutcomes: {
          supported: { "request-contract": "supported" },
          contradicted: { "request-contract": "contradicted" },
        },
        outcomes: {
          supported: "hold_for_evidence",
          contradicted: "hold_for_evidence",
        },
      },
      {
        question: "Which runtime receives the patch?",
        action: "Inspect the checked-in rollout mapping.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: {
          known: "hold_for_evidence",
          unavailable: "hold_for_evidence",
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "a contradicted boundary outcome requires revise or block",
    );
  });

  test("keeps terminal evidence branches on hold while another pivot remains", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.materialBoundaries[0]!.result = "unresolved";
    payload.unknowns = [
      {
        id: "defect-signal",
        summary: "The defect signal is unavailable.",
        decisionCritical: true,
      },
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the observed signal contradict the boundary?",
        action: "Reproduce the signal against the immutable patch.",
        resolvesUnknowns: ["defect-signal"],
        remainingUnknowns: {
          defect: [],
          inconclusive: ["runtime-owner"],
        },
        resolvesBoundaries: ["request-contract"],
        boundaryOutcomes: {
          defect: { "request-contract": "contradicted" },
          inconclusive: { "request-contract": "unresolved" },
        },
        outcomes: {
          defect: "revise",
          inconclusive: "hold_for_evidence",
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "a terminal outcome cannot retain a decision-critical unknown",
    );
  });

  test("allows a non-applicable no-op to discard unrelated pivots", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.applicability = {
      status: "unknown",
      rationale: "Runtime ownership remains unresolved.",
    };
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
      {
        id: "patch-behavior",
        summary: "The patch behavior is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Which runtime owns this path?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-owner"],
        remainingUnknowns: {
          owned: ["patch-behavior"],
          not_owned: ["patch-behavior"],
        },
        applicabilityOutcomes: {
          owned: "confirmed",
          not_owned: "wrong_owner",
        },
        outcomes: {
          owned: "hold_for_evidence",
          not_owned: "no_op",
        },
      },
      {
        question: "Does the patch preserve the runtime behavior?",
        action: "Trace the immutable patch through its caller.",
        resolvesUnknowns: ["patch-behavior"],
        remainingUnknowns: {
          preserved: ["runtime-owner"],
          contradicted: ["runtime-owner"],
        },
        outcomes: {
          preserved: "hold_for_evidence",
          contradicted: "hold_for_evidence",
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("requires each claimed unknown resolver to make progress", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Which runtime owns this path?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-owner"],
        remainingUnknowns: {
          unavailable: ["runtime-owner"],
          still_unavailable: ["runtime-owner"],
        },
        outcomes: {
          unavailable: "hold_for_evidence",
          still_unavailable: "hold_for_evidence",
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "'runtime-owner' remains unresolved in every outcome",
    );
  });

  test("reports mismatched remaining-unknown keys without a traceback", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Which runtime owns this path?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-owner"],
        remainingUnknowns: {
          first: [],
          extra: ["runtime-owner"],
        },
        outcomes: {
          first: "hold_for_evidence",
          second: "hold_for_evidence",
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "remainingUnknowns must name exactly the evidence outcome keys",
    );
    expect(result.stderr).not.toContain("Traceback");
  });

  test("requires each claimed boundary resolver to make progress", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.materialBoundaries[0]!.result = "unresolved";
    payload.unknowns = [
      {
        id: "boundary-evidence",
        summary: "The boundary evidence is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the patch preserve the boundary?",
        action: "Trace both controls through the immutable patch.",
        resolvesUnknowns: ["boundary-evidence"],
        remainingUnknowns: { first: [], second: [] },
        resolvesBoundaries: ["request-contract"],
        boundaryOutcomes: {
          first: { "request-contract": "unresolved" },
          second: { "request-contract": "unresolved" },
        },
        outcomes: {
          first: "hold_for_evidence",
          second: "hold_for_evidence",
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "'request-contract' remains unresolved in every outcome",
    );
  });

  test("requires applicability evidence to make progress", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.applicability = {
      status: "unknown",
      rationale: "Runtime ownership remains unavailable.",
    };
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Which runtime owns this path?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-owner"],
        remainingUnknowns: { first: [], second: [] },
        applicabilityOutcomes: { first: "unknown", second: "unknown" },
        outcomes: {
          first: "hold_for_evidence",
          second: "hold_for_evidence",
        },
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "applicability remains unknown in every outcome",
    );
  });

  test("requires a hold outcome to retain an explicit pivot", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Which runtime owns this path?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-owner"],
        outcomes: { owned: "merge", unavailable: "hold_for_evidence" },
      },
    ];

    const missing = await validate(payload);
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain(
      "a hold outcome must retain an explicit unresolved pivot",
    );

    payload.evidencePlan[0]!.remainingUnknowns = {
      owned: [],
      unavailable: ["runtime-owner"],
    };
    const valid = await validate(payload);
    expect(valid.status, valid.stderr).toBe(0);
  });

  test("requires structured evidence for unknown applicability", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.applicability = {
      status: "unknown",
      rationale: "Runtime ownership remains unresolved.",
    };
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Which owned runtime applies?",
        action: "Inspect the checked-in runtime registry.",
        resolvesUnknowns: ["runtime-owner"],
        outcomes: {
          supported: "merge",
          defective: "merge",
        },
      },
    ];

    const missing = await validate(payload);
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain(
      "unknown applicability requires a matching applicability evidence plan",
    );

    payload.evidencePlan[0]!.applicabilityOutcomes = {
      supported: "confirmed",
      unavailable: "unknown",
    };
    const mismatched = await validate(payload);
    expect(mismatched.status).not.toBe(0);
    expect(mismatched.stderr).toContain(
      "applicabilityOutcomes must name exactly the evidence outcome keys",
    );

    delete payload.evidencePlan[0]!.applicabilityOutcomes["unavailable"];
    payload.evidencePlan[0]!.applicabilityOutcomes["defective"] = "unknown";
    const unresolved = await validate(payload);
    expect(unresolved.status).not.toBe(0);
    expect(unresolved.stderr).toContain(
      "unknown applicability requires hold_for_evidence",
    );

    payload.evidencePlan[0]!.applicabilityOutcomes["defective"] = "confirmed";
    const complete = await validate(payload);
    expect(complete.status, complete.stderr).toBe(0);
  });

  test("keeps terminal defect outcomes on hold until applicability resolves", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.applicability = {
      status: "unknown",
      rationale: "Runtime ownership remains unresolved.",
    };
    payload.unknowns = [
      {
        id: "runtime-owner",
        summary: "The runtime owner is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the changed runtime expose the defect?",
        action: "Exercise the changed path through the runtime entry point.",
        resolvesUnknowns: ["runtime-owner"],
        outcomes: { defective: "revise", unavailable: "hold_for_evidence" },
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "a terminal outcome must resolve unknown applicability",
    );
  });

  test.each(["high", "moderate"] as const)(
    "rejects %s confidence when holding for evidence",
    async (confidence) => {
      const payload = assessment();
      payload.recommendation = "hold_for_evidence";
      payload.workflowLabel = "hold_for_evidence";
      payload.confidence.rating = confidence;
      payload.unknowns = [
        {
          id: "rollout-target",
          summary: "The rollout target is unavailable.",
          decisionCritical: true,
        },
      ];
      payload.evidencePlan = [
        {
          question: "Does the changed configuration own the rollout target?",
          action: "Inspect the checked-in deployment mapping.",
          resolvesUnknowns: ["rollout-target"],
          outcomes: {
            supported: "merge",
            contradicted: "revise",
          },
        },
      ];

      const result = await validate(payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(
        "hold_for_evidence requires low confidence",
      );
    },
  );

  test("rejects block without affirmative material failure evidence", async () => {
    const payload = assessment();
    payload.recommendation = "block";
    payload.workflowLabel = "block";
    payload.regressionProtection.rating = "partial";
    payload.validation[0]!.status = "unavailable";
    payload.regressionProtection.exactHeadChecksPassed = false;
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toBe(
      "block requires critical regression likelihood and an established material safety failure\n",
    );

    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "patch_caused";
    const patchFailure = await validate(payload);
    expect(patchFailure.status).not.toBe(0);
    expect(patchFailure.stderr).toContain(
      "block requires critical regression likelihood",
    );
  });

  test("requires critical likelihood and a material safety failure for block", async () => {
    const critical = assessment();
    critical.recommendation = "block";
    critical.workflowLabel = "block";
    critical.regressionLikelihood.rating = "critical";
    const nonSafetyCritical = await validate(critical);
    expect(nonSafetyCritical.status).not.toBe(0);
    expect(nonSafetyCritical.stderr).toContain(
      "an established material safety failure",
    );
    critical.materialSafetyFailure = {
      established: true,
      evidence: "The affected boundary permits a cross-subject decision.",
    };
    const criticalResult = await validate(critical);
    expect(criticalResult.status, criticalResult.stderr).toBe(0);

    const contradicted = assessment();
    contradicted.recommendation = "block";
    contradicted.workflowLabel = "block";
    contradicted.materialBoundaries[0]!.result = "contradicted";
    const contradictedResult = await validate(contradicted);
    expect(contradictedResult.status).not.toBe(0);
    expect(contradictedResult.stderr).toContain(
      "block requires critical regression likelihood",
    );
  });

  test.each([
    ["merge", (_payload: Assessment) => {}],
    [
      "revise",
      (payload: Assessment) => {
        payload.recommendation = "revise";
        payload.workflowLabel = "revise";
        payload.validation[0]!.status = "failed";
        payload.validation[0]!.failureAttribution = "patch_caused";
      },
    ],
    [
      "no_op",
      (payload: Assessment) => {
        payload.recommendation = "no_op";
        payload.workflowLabel = "no_op";
        payload.applicability = {
          status: "superseded",
          rationale: "A narrower patch already landed.",
        };
      },
    ],
    [
      "block",
      (payload: Assessment) => {
        payload.recommendation = "block";
        payload.workflowLabel = "block";
        payload.regressionLikelihood.rating = "critical";
      },
    ],
    [
      "hold_for_evidence",
      (payload: Assessment) => {
        payload.recommendation = "hold_for_evidence";
        payload.workflowLabel = "hold_for_evidence";
        payload.confidence.rating = "low";
        payload.unknowns = [
          {
            id: "rollout-target",
            summary: "The rollout target is unavailable.",
            decisionCritical: true,
          },
        ];
        payload.evidencePlan = [
          {
            question: "Does the changed configuration own the rollout target?",
            action: "Inspect the checked-in deployment mapping.",
            resolvesUnknowns: ["rollout-target"],
            outcomes: {
              supported: "merge",
              contradicted: "revise",
            },
          },
        ];
      },
    ],
  ] as const)(
    "requires exact-head checks for strong protection on %s",
    async (_, configure) => {
      const payload = assessment();
      configure(payload);
      payload.regressionProtection.exactHeadChecksPassed = false;
      const result = await validate(payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(
        "strong regression protection requires exact-head checks to pass",
      );
    },
  );

  test("allows partial protection without exact-head checks for human review", async () => {
    const payload = assessment();
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    payload.validation[0]!.status = "passed";
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("requires an executed validation for strong protection", async () => {
    const payload = assessment();
    payload.validation[0]!.status = "skipped";
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "strong regression protection requires an executed validation",
    );
  });

  test("requires required validation to pass for an exact-head pass claim", async () => {
    const payload = assessment();
    payload.regressionProtection.rating = "partial";
    payload.validation[0]!.status = "skipped";
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "exact-head checks passed requires every required validation to pass",
    );
  });

  test("allows an exact-head pass claim with only optional passing validation", async () => {
    const payload = assessment();
    payload.workflowLabel = "human_review_required";
    payload.regressionLikelihood.rating = "moderate";
    payload.validation[0]!.requiredForMerge = false;

    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("rejects an exact-head pass claim when another required validation failed", async () => {
    const payload = assessment();
    payload.workflowLabel = "human_review_required";
    payload.regressionLikelihood.rating = "moderate";
    payload.validation.push({
      name: "required integration tests",
      status: "failed",
      protects: "The changed behavior through its integration boundary.",
      requiredForMerge: true,
      failureAttribution: "not_patch_caused",
    });

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "exact-head checks passed requires every required validation to pass",
    );
  });

  test("rejects high confidence when regression protection is unknown", async () => {
    const payload = assessment();
    payload.regressionLikelihood.rating = "moderate";
    payload.regressionProtection.rating = "unknown";
    payload.regressionProtection.exactHeadChecksPassed = false;
    payload.validation[0]!.status = "unavailable";

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "unknown regression protection cannot support high confidence",
    );
  });

  test("rejects high confidence while an explicit bounded unknown remains", async () => {
    const payload = assessment();
    payload.regressionLikelihood.rating = "moderate";
    payload.unknowns = [
      {
        id: "bounded-observability-gap",
        summary: "A non-decision-critical observability detail is unavailable.",
        decisionCritical: false,
      },
    ];

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "high confidence cannot retain an explicit unknown",
    );
  });

  test.each(["impact", "boundary"] as const)(
    "rejects high confidence with unresolved %s evidence",
    async (kind) => {
      const payload = assessment();
      payload.recommendation = "revise";
      payload.workflowLabel = "revise";
      payload.validation[0]!.status = "failed";
      payload.validation[0]!.failureAttribution = "patch_caused";
      if (kind === "impact") payload.impact.rating = "unknown";
      else payload.materialBoundaries[0]!.result = "unresolved";

      const result = await validate(payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(
        kind === "impact"
          ? "unknown impact cannot support high confidence"
          : "an unresolved material boundary cannot support high confidence",
      );
    },
  );

  test.each(["none", "unknown"])(
    "requires passing protection for a low-likelihood merge with %s protection",
    async (rating) => {
      const payload = assessment();
      payload.regressionProtection.rating = rating;
      payload.regressionProtection.exactHeadChecksPassed = false;

      const result = await validate(payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(
        "merge with low regression likelihood requires passing protection",
      );
    },
  );

  test("rejects failed validation for merge", async () => {
    const payload = assessment();
    payload.regressionLikelihood.rating = "moderate";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "patch_caused";

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "merge cannot include a patch-caused or unattributed failure",
    );
  });

  test("allows human review when a failed check is not patch caused", async () => {
    const payload = assessment();
    payload.regressionLikelihood.rating = "moderate";
    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "not_patch_caused";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;

    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("validates large unique changed-file lists without dropping duplicates", async () => {
    const payload = assessment();
    payload.patch.changedFiles = Array.from(
      { length: 5_000 },
      (_, index) => `generated/file-${index}.ts`,
    );
    const unique = await validate(payload);
    expect(unique.status, unique.stderr).toBe(0);

    payload.patch.changedFiles.push(payload.patch.changedFiles[0]!);
    const duplicate = await validate(payload);
    expect(duplicate.status).not.toBe(0);
    expect(duplicate.stderr).toContain(
      "patch.changedFiles: array items must be unique",
    );
  });

  test("allows partial protection alongside a patch-caused failure", async () => {
    const payload = assessment();
    payload.recommendation = "revise";
    payload.workflowLabel = "revise";
    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "patch_caused";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("allows no validation entries when no check is relevant", async () => {
    const payload = assessment();
    payload.recommendation = "no_op";
    payload.workflowLabel = "no_op";
    payload.applicability = {
      status: "superseded",
      rationale: "A narrower patch already landed.",
    };
    payload.validation = [];
    payload.regressionProtection.rating = "none";
    payload.regressionProtection.exactHeadChecksPassed = false;

    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test.each(["revise", "block"])(
    "requires an evidence hold when applicability is unknown before %s",
    async (recommendation) => {
      const payload = assessment();
      payload.recommendation = recommendation;
      payload.workflowLabel = recommendation;
      payload.applicability = {
        status: "unknown",
        rationale: "Runtime ownership has not been established.",
      };
      if (recommendation === "revise") {
        payload.validation[0]!.status = "failed";
        payload.validation[0]!.failureAttribution = "patch_caused";
      } else {
        payload.regressionLikelihood.rating = "critical";
      }

      const result = await validate(payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(
        "unknown applicability requires hold_for_evidence",
      );
    },
  );

  test("rejects revise without affirmative correction evidence", async () => {
    const payload = assessment();
    payload.recommendation = "revise";
    payload.workflowLabel = "revise";

    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toBe(
      "revise requires critical regression likelihood, an established material safety failure, a contradicted material boundary, or a patch-caused validation failure\n",
    );
  });

  test("accepts each affirmative correction signal for revise", async () => {
    const critical = assessment();
    critical.recommendation = "revise";
    critical.workflowLabel = "revise";
    critical.regressionLikelihood.rating = "critical";
    const criticalResult = await validate(critical);
    expect(criticalResult.status, criticalResult.stderr).toBe(0);

    const contradicted = assessment();
    contradicted.recommendation = "revise";
    contradicted.workflowLabel = "revise";
    contradicted.materialBoundaries[0]!.result = "contradicted";
    const contradictedResult = await validate(contradicted);
    expect(contradictedResult.status, contradictedResult.stderr).toBe(0);

    const failed = assessment();
    failed.recommendation = "revise";
    failed.workflowLabel = "revise";
    failed.validation[0]!.status = "failed";
    failed.validation[0]!.failureAttribution = "patch_caused";
    failed.regressionProtection.rating = "partial";
    failed.regressionProtection.exactHeadChecksPassed = false;
    const failedResult = await validate(failed);
    expect(failedResult.status, failedResult.stderr).toBe(0);
  });

  test("requires an established non-applicable no-op disposition", async () => {
    const payload = assessment();
    payload.recommendation = "no_op";
    payload.workflowLabel = "no_op";
    const applicable = await validate(payload);
    expect(applicable.status).not.toBe(0);
    expect(applicable.stderr).toContain(
      "no_op requires an established non-applicable disposition",
    );

    payload.applicability = {
      status: "superseded",
      rationale: "A narrower patch already landed.",
    };
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("preserves no-op when an inapplicable patch has a patch-caused failure", async () => {
    const payload = assessment();
    payload.recommendation = "no_op";
    payload.workflowLabel = "no_op";
    payload.applicability = {
      status: "superseded",
      rationale: "A replacement patch already landed.",
    };
    payload.regressionLikelihood.rating = "critical";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "patch_caused";

    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test.each([
    "no_live_effect",
    "wrong_owner",
    "duplicate",
    "superseded",
  ] as const)(
    "requires no-op for the established %s disposition",
    async (status) => {
      const payload = assessment();
      payload.recommendation = "revise";
      payload.workflowLabel = "revise";
      payload.applicability = {
        status,
        rationale: "The applicability disposition is established.",
      };

      const result = await validate(payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(
        "an established non-applicable disposition requires no_op",
      );
    },
  );

  test("rejects low confidence for no-op", async () => {
    const payload = assessment();
    payload.recommendation = "no_op";
    payload.workflowLabel = "no_op";
    payload.applicability = {
      status: "no_live_effect",
      rationale: "The immutable comparison has no live runtime effect.",
    };
    payload.confidence.rating = "low";
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toBe("no_op cannot have low confidence\n");
  });

  test("rejects a decision-critical unknown for no-op", async () => {
    const payload = assessment();
    payload.recommendation = "no_op";
    payload.workflowLabel = "no_op";
    payload.applicability = {
      status: "superseded",
      rationale: "A sibling patch may cover the affected runtime.",
    };
    payload.unknowns = [
      {
        id: "sibling-coverage",
        summary: "Whether the sibling covers the runtime is unresolved.",
        decisionCritical: true,
      },
    ];
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "no_op cannot retain a decision-critical unknown",
    );
  });

  test("does not accept a raw working tree as the patch source", async () => {
    const payload = assessment();
    payload.patch.sourceType = "raw_worktree";
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "patch.sourceType: value is not one of the allowed choices",
    );
  });

  test("requires a matching workflow label for non-merge recommendations", async () => {
    const payload = assessment();
    payload.recommendation = "revise";
    const mismatched = await validate(payload);
    expect(mismatched.status).not.toBe(0);
    expect(mismatched.stderr).toContain(
      "non-merge workflow label must match the recommendation",
    );

    payload.workflowLabel = "revise";
    payload.validation[0]!.status = "failed";
    payload.validation[0]!.failureAttribution = "patch_caused";
    payload.regressionProtection.rating = "partial";
    payload.regressionProtection.exactHeadChecksPassed = false;
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test.each([
    [
      "missing changed-file identity",
      (payload: Assessment) => {
        delete (payload.patch as Partial<Assessment["patch"]>).changedFiles;
      },
      "required property 'changedFiles' is missing",
    ],
    [
      "missing required fields",
      (payload: Assessment) => {
        delete (payload.patch as Partial<Assessment["patch"]>).sha256;
      },
      "required property 'sha256' is missing",
    ],
    [
      "additional fields",
      (payload: Assessment) => {
        (payload.patch as Record<string, unknown>)["mutable"] = true;
      },
      "additional property 'mutable' is not allowed",
    ],
    [
      "malformed digests",
      (payload: Assessment) => {
        payload.patch.sha256 = "not-a-digest";
      },
      "patch.sha256: string does not match the required pattern",
    ],
    [
      "digests with a trailing newline",
      (payload: Assessment) => {
        payload.patch.sha256 = `${"c".repeat(64)}\n`;
      },
      "patch.sha256: string does not match the required pattern",
    ],
    [
      "boundary identifiers with a trailing newline",
      (payload: Assessment) => {
        payload.materialBoundaries[0]!.id = "request-contract\n";
      },
      "materialBoundaries.0.id: string does not match the required pattern",
    ],
    [
      "byte-order-mark-only strings",
      (payload: Assessment) => {
        payload.patch.repository = "\uFEFF";
      },
      "patch.repository: string does not match the required pattern",
    ],
    [
      "duplicate string-list items",
      (payload: Assessment) => {
        payload.affectedRuntimeRoots = ["service.request", "service.request"];
      },
      "affectedRuntimeRoots: array items must be unique",
    ],
    [
      "duplicate changed files",
      (payload: Assessment) => {
        payload.patch.changedFiles.push("src/request.ts");
      },
      "patch.changedFiles: array items must be unique",
    ],
  ] as const)(
    "rejects structurally invalid assessments with %s",
    async (_, mutate, message) => {
      const payload = assessment();
      mutate(payload);
      const result = await validate(payload);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(message);
      expect(result.stderr).not.toContain("Traceback");
    },
  );

  test("rejects duplicate JSON object keys deterministically", async () => {
    const raw = JSON.stringify(assessment()).replace(
      '"schemaVersion":1',
      '"schemaVersion":1,"schemaVersion":1',
    );
    const first = await validateRaw(raw);
    const second = await validateRaw(raw);
    expect(first.status).not.toBe(0);
    expect(first.stderr).toBe(
      "cannot read assessment: duplicate JSON object key\n",
    );
    expect(second.stderr).toBe(first.stderr);
    expect(first.stderr).not.toContain("Traceback");
  });

  test("does not modify the input artifact", async () => {
    const payload = assessment();
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
    expect(await readFile(result.assessmentPath, "utf8")).toBe(result.contents);
  });
});
