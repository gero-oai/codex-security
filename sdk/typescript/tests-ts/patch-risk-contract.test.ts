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
    legitimateControl: string;
    result: string;
  }>;
  validation: Array<{
    name: string;
    status: string;
    protects: string;
    failureAttribution?: string;
  }>;
  unknowns: Array<{ summary: string; decisionCritical: boolean }>;
  evidencePlan: Array<{
    question: string;
    action: string;
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
        legitimateControl: "A supported request takes the unchanged branch.",
        result: "supported",
      },
    ],
    validation: [
      {
        name: "focused request tests",
        status: "passed",
        protects: "Changed behavior through the production caller.",
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
    expect(() =>
      new Ajv2020({ strict: false, validateFormats: false }).compile(schema),
    ).not.toThrow();
  });

  test("documents the configured validator command over stdin", async () => {
    const skill = await readFile(skillPath, "utf8");
    const command = /```text\s+(.*?)\s+```/su.exec(skill)?.[1];
    expect(command?.trim().split(/\s+/u)).toEqual([
      "<python_command>",
      "<plugin_dir>/skills/assess-patch-risk/scripts/validate_patch_risk_assessment.py",
      "-",
    ]);
    expect(skill).not.toMatch(
      /^python\s+.*validate_patch_risk_assessment\.py/mu,
    );
    expect(skill).toContain('`"$PYTHON"` in POSIX shells');
    expect(skill).toContain('`& "$env:PYTHON"` in PowerShell');
    expect(skill).toContain("the directory three levels above this `SKILL.md`");
    expect(skill).toContain("paths remain single arguments");
  });

  test("validates a supported human-review merge without site packages", async () => {
    const result = await validate(assessment());
    expect(result.status, result.stderr).toBe(0);
  });

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

  test("accepts a strict low-risk auto-merge candidate", async () => {
    const payload = assessment();
    payload.workflowLabel = "auto_merge_candidate";
    payload.impact.rating = "low";
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

  test("rejects a merge with a decision-critical unknown", async () => {
    const payload = assessment();
    payload.unknowns = [
      {
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
    payload.unknowns = [
      {
        summary: "The changed path's runtime impact is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the changed path reach a supported runtime?",
        action: "Inspect the checked-in runtime registry.",
        outcomes: {
          reachable: "merge",
          unreachable: "no_op",
        },
      },
    ];
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("rejects unknown risk ratings for merge", async () => {
    const payload = assessment();
    payload.impact.rating = "unknown";
    payload.regressionLikelihood.rating = "unknown";
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "only hold_for_evidence may use impact.rating=unknown",
    );
    expect(result.stderr).toContain(
      "only hold_for_evidence may use regressionLikelihood.rating=unknown",
    );
  });

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
        summary:
          "The provider did not return a complete changed-file inventory.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Can the immutable final comparison be retrieved completely?",
        action: "Retrieve the same final comparison again from the provider.",
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
    payload.unknowns = [
      {
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
        outcomes: {
          supported: "merge",
          contradicted: "no_op",
          unavailable: "hold_for_evidence",
        },
      },
    ];
    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("allows an evidence action for every decision-critical unknown", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = Array.from({ length: 4 }, (_, index) => ({
      summary: `Decision-critical unknown ${index + 1}.`,
      decisionCritical: true,
    }));
    payload.evidencePlan = Array.from({ length: 4 }, (_, index) => ({
      question: `Question ${index + 1}?`,
      action: `Resolve unknown ${index + 1}.`,
      outcomes: {
        supported: "merge",
        contradicted: "revise",
      },
    }));

    const result = await validate(payload);
    expect(result.status, result.stderr).toBe(0);
  });

  test("requires failed checks to be attributed or matched to evidence", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        summary: "The rollout target is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the changed configuration own the rollout target?",
        action: "Inspect the checked-in deployment mapping.",
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

    payload.materialBoundaries[0]!.result = "unresolved";
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
      "a patch-caused validation failure requires revise or block",
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
      patch_caused: "merge",
      not_patch_caused: "revise",
    };
    const unsafePatchOutcome = await validate(payload);
    expect(unsafePatchOutcome.status).not.toBe(0);
    expect(unsafePatchOutcome.stderr).toContain(
      "a patch_caused outcome must recommend revise or block",
    );

    payload.evidencePlan[0]!.outcomes = {
      patch_caused: "revise",
      not_patch_caused: "merge",
    };
    const unattributedFailure = await validate(payload);
    expect(unattributedFailure.status, unattributedFailure.stderr).toBe(0);

    payload.validation[0]!.failureAttribution = "not_patch_caused";
    delete payload.evidencePlan[0]!.resolvesFailedValidation;
    const attributedFailure = await validate(payload);
    expect(attributedFailure.status, attributedFailure.stderr).toBe(0);

    payload.validation[0]!.status = "unavailable";
    delete payload.validation[0]!.failureAttribution;
    const unresolved = await validate(payload);
    expect(unresolved.status, unresolved.stderr).toBe(0);
  });

  test("requires every evidence-plan item to have distinct recommendations", async () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.confidence.rating = "low";
    payload.unknowns = [
      {
        summary: "The rollout target is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Does the changed configuration own the rollout target?",
        action: "Inspect the checked-in deployment mapping.",
        outcomes: {
          supported: "merge",
          contradicted: "merge",
        },
      },
    ];

    const first = await validate(payload);
    const second = await validate(payload);
    expect(first.status).not.toBe(0);
    expect(first.stderr).toBe(
      "evidencePlan.0: requires at least two distinct outcome recommendations\n",
    );
    expect(second.stderr).toBe(first.stderr);
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
          summary: "The rollout target is unavailable.",
          decisionCritical: true,
        },
      ];
      payload.evidencePlan = [
        {
          question: "Does the changed configuration own the rollout target?",
          action: "Inspect the checked-in deployment mapping.",
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
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toBe(
      "block requires critical regression likelihood or a contradicted material boundary\n",
    );
  });

  test("accepts either affirmative material failure signal for block", async () => {
    const critical = assessment();
    critical.recommendation = "block";
    critical.workflowLabel = "block";
    critical.regressionLikelihood.rating = "critical";
    const criticalResult = await validate(critical);
    expect(criticalResult.status, criticalResult.stderr).toBe(0);

    const contradicted = assessment();
    contradicted.recommendation = "block";
    contradicted.workflowLabel = "block";
    contradicted.materialBoundaries[0]!.result = "contradicted";
    const contradictedResult = await validate(contradicted);
    expect(contradictedResult.status, contradictedResult.stderr).toBe(0);
  });

  test.each([
    ["merge", (_payload: Assessment) => {}],
    [
      "revise",
      (payload: Assessment) => {
        payload.recommendation = "revise";
        payload.workflowLabel = "revise";
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
            summary: "The rollout target is unavailable.",
            decisionCritical: true,
          },
        ];
        payload.evidencePlan = [
          {
            question: "Does the changed configuration own the rollout target?",
            action: "Inspect the checked-in deployment mapping.",
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
    expect(result.stderr).toContain("merge cannot include failed validation");
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

  test("requires every validation item to pass for strong protection", async () => {
    const payload = assessment();
    payload.validation.push({
      name: "platform check",
      status: "unavailable",
      protects: "Architecture-specific behavior.",
    });
    const result = await validate(payload);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "strong regression protection requires every validation item to pass",
    );
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
      "empty validation evidence",
      (payload: Assessment) => {
        payload.validation = [];
      },
      "validation: array has fewer than 1 items",
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
