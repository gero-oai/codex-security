import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { describe, expect, test } from "bun:test";
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
  importantCallers: string[];
  riskDrivers: string[];
  protectiveFactors: string[];
  materialBoundaries: Array<{
    id: string;
    invariant: string;
    runtimeRoot: string;
    counterexample: string;
    counterexampleSource: string;
    legitimateControl: string;
    legitimateControlSource: string;
    result: string;
  }>;
  validation: Array<{
    name: string;
    status: string;
    protects: string;
    relevant: boolean;
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
const python =
  process.env["PYTHON"] ??
  Bun.which("python3") ??
  Bun.which("python") ??
  Bun.which("py");

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
    importantCallers: ["request handler"],
    riskDrivers: ["changed request behavior"],
    protectiveFactors: ["focused request coverage"],
    materialBoundaries: [
      {
        id: "request-contract",
        invariant:
          "Supported requests retain their existing response contract.",
        runtimeRoot: "service.request",
        counterexample: "A supported request takes the changed branch.",
        counterexampleSource: "src/request.ts:20",
        legitimateControl: "A supported request takes the unchanged branch.",
        legitimateControlSource: "src/request.ts:12",
        result: "supported",
      },
    ],
    validation: [
      {
        name: "focused request tests",
        status: "passed",
        protects: "Changed behavior through the production caller.",
        relevant: true,
      },
    ],
    unknowns: [],
    evidencePlan: [],
  };
}

function validateText(input: string, cwd = PLUGIN_ROOT) {
  expect(python).toBeDefined();
  expect(python).not.toBeNull();
  return spawnSync(python!, ["-I", "-S", validatorPath, "-"], {
    cwd,
    encoding: "utf8",
    input,
  });
}

function validate(payload: Assessment) {
  return validateText(JSON.stringify(payload));
}

function validateWithSharedSchema(payload: Assessment) {
  expect(python).toBeDefined();
  expect(python).not.toBeNull();
  const program = [
    "import json, pathlib, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import finalize_scan_contract as finalizer",
    "finalizer.validate_against_schema(json.load(sys.stdin), pathlib.Path(sys.argv[2]))",
  ].join("\n");
  return spawnSync(
    python!,
    ["-I", "-B", "-S", "-c", program, join(PLUGIN_ROOT, "scripts"), schemaPath],
    {
      encoding: "utf8",
      input: JSON.stringify(payload),
    },
  );
}

function validateUniqueValues(input: string) {
  expect(python).toBeDefined();
  expect(python).not.toBeNull();
  const program = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import finalize_scan_contract as finalizer",
    'finalizer._validate_schema_node(json.load(sys.stdin), {"type": "array", "uniqueItems": True}, "value")',
  ].join("\n");
  return spawnSync(
    python!,
    ["-I", "-B", "-S", "-c", program, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8", input },
  );
}

describe("patch risk assessment contract", () => {
  test("resolves the validator from the installed skill", async () => {
    const outside = await mkdtemp(join(tmpdir(), "patch-risk-contract-"));
    try {
      const result = validateText(JSON.stringify(assessment()), outside);
      expect(result.status, result.stderr).toBe(0);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  test("publishes a valid draft 2020-12 schema", async () => {
    const schema = JSON.parse(await readFile(schemaPath, "utf8"));
    const validateSchema = new Ajv2020({
      strict: false,
      validateFormats: false,
    }).compile(schema);

    expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(
      validateSchema(assessment()),
      JSON.stringify(validateSchema.errors),
    ).toBe(true);

    const rawWorktree = assessment();
    rawWorktree.patch.sourceType = "raw_worktree";
    expect(validateSchema(rawWorktree)).toBe(false);

    const uppercaseDigest = assessment();
    uppercaseDigest.patch.sha256 = "A".repeat(64);
    expect(
      validateSchema(uppercaseDigest),
      JSON.stringify(validateSchema.errors),
    ).toBe(true);
    expect(validate(uppercaseDigest).status).toBe(0);
  });

  test("enforces the patch-risk schema through the shared validator", () => {
    const valid = validateWithSharedSchema(assessment());
    expect(valid.status, valid.stderr).toBe(0);

    const duplicateChangedFiles = assessment();
    duplicateChangedFiles.patch.changedFiles = [
      "src/request.ts",
      "src/request.ts",
    ];
    expect(validateWithSharedSchema(duplicateChangedFiles).status).not.toBe(0);

    const emptyRationale = assessment();
    emptyRationale.impact.rationale = "";
    expect(validateWithSharedSchema(emptyRationale).status).not.toBe(0);

    const whitespaceRationale = assessment();
    whitespaceRationale.impact.rationale = " \t\n";
    expect(validateWithSharedSchema(whitespaceRationale).status).not.toBe(0);

    const duplicateItems = assessment();
    duplicateItems.autoMergeExclusions = ["migration", "migration"];
    expect(validateWithSharedSchema(duplicateItems).status).not.toBe(0);

    const tooManyEvidenceSteps = assessment();
    tooManyEvidenceSteps.evidencePlan = Array.from(
      { length: 4 },
      (_, index) => ({
        question: `Question ${index}`,
        action: "Inspect the corresponding evidence.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: { supported: "merge", contradicted: "revise" },
      }),
    );
    expect(validateWithSharedSchema(tooManyEvidenceSteps).status).not.toBe(0);

    const incompleteOutcomes = assessment();
    incompleteOutcomes.evidencePlan = [
      {
        question: "Is the boundary protected?",
        action: "Inspect the corresponding evidence.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: { supported: "merge" },
      },
    ];
    expect(validateWithSharedSchema(incompleteOutcomes).status).not.toBe(0);

    const emptyOutcome = assessment();
    emptyOutcome.evidencePlan = [
      {
        question: "Is the boundary protected?",
        action: "Inspect the corresponding evidence.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: { supported: "", contradicted: "revise" },
      },
    ];
    expect(validateWithSharedSchema(emptyOutcome).status).not.toBe(0);

    const emptyOutcomeName = assessment();
    emptyOutcomeName.evidencePlan = [
      {
        question: "Is the boundary protected?",
        action: "Inspect the corresponding evidence.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: { "": "merge", " ": "revise" },
      },
    ];
    expect(validateWithSharedSchema(emptyOutcomeName).status).not.toBe(0);

    const largeChangedFileList = assessment();
    largeChangedFileList.patch.changedFiles = Array.from(
      { length: 5_000 },
      (_, index) => `generated/file-${index}.ts`,
    );
    expect(validateWithSharedSchema(largeChangedFileList).status).toBe(0);
  });

  test("enforces the published schema without site packages", async () => {
    const schema = JSON.parse(await readFile(schemaPath, "utf8"));
    const validateSchema = new Ajv2020({
      strict: false,
      validateFormats: false,
    }).compile(schema);
    const invalidAssessments: Assessment[] = [];

    const missingRequired = assessment();
    delete (missingRequired as Record<string, unknown>)["patch"];
    invalidAssessments.push(missingRequired);

    const additionalProperty = assessment();
    additionalProperty["unexpected"] = true;
    invalidAssessments.push(additionalProperty);

    const missingEvidenceCollection = assessment();
    delete (missingEvidenceCollection as Record<string, unknown>)[
      "importantCallers"
    ];
    invalidAssessments.push(missingEvidenceCollection);

    const invalidPattern = assessment();
    invalidPattern.patch.sha256 = "g".repeat(64);
    invalidAssessments.push(invalidPattern);

    const trailingNewlineDigest = assessment();
    trailingNewlineDigest.patch.sha256 = `${"c".repeat(64)}\n`;
    invalidAssessments.push(trailingNewlineDigest);

    const duplicateItems = assessment();
    duplicateItems["autoMergeExclusions"] = ["migration", "migration"];
    invalidAssessments.push(duplicateItems);

    const emptyString = assessment();
    emptyString.impact.rationale = "";
    invalidAssessments.push(emptyString);

    for (const payload of invalidAssessments) {
      expect(validateSchema(payload)).toBe(false);
      expect(validate(payload).status).not.toBe(0);
    }
  });

  test("accepts a supported human-review merge without site packages", () => {
    const result = validate(assessment());
    expect(result.status, result.stderr).toBe(0);
  });

  test("compares JSON numeric constants by value", () => {
    const serialized = JSON.stringify(assessment()).replace(
      '"schemaVersion":1',
      '"schemaVersion":1.0',
    );

    const result = validateText(serialized);
    expect(result.status, result.stderr).toBe(0);
  });

  test("compares unique JSON values by schema equality", () => {
    expect(validateUniqueValues("[true, 1]").status).toBe(0);
    expect(validateUniqueValues("[1, 1.0]").status).not.toBe(0);
    expect(
      validateUniqueValues('[{"a": 1, "b": [2]}, {"b": [2.0], "a": 1.0}]')
        .status,
    ).not.toBe(0);
  });

  test("enforces strict auto-merge gates", () => {
    const payload = assessment();
    payload.workflowLabel = "auto_merge_candidate";

    const rejected = validate(payload);
    expect(rejected.status).not.toBe(0);

    payload.impact.rating = "low";
    const accepted = validate(payload);
    expect(accepted.status, accepted.stderr).toBe(0);
  });

  test("requires a bounded evidence plan for an evidence hold", () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.unknowns = [
      {
        id: "rollout-target",
        summary: "The rollout target is unavailable.",
        decisionCritical: true,
      },
    ];

    expect(validate(payload).status).not.toBe(0);

    payload.evidencePlan = [
      {
        question: "Does the changed configuration own the rollout target?",
        action: "Inspect the checked-in deployment mapping.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: {
          unavailable: "hold_for_evidence",
          inaccessible: "hold_for_evidence",
        },
      },
    ];
    expect(validate(payload).status).not.toBe(0);

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
      },
    ];
    const accepted = validate(payload);
    expect(accepted.status, accepted.stderr).toBe(0);
  });

  test("requires an established non-applicable no-op", () => {
    const payload = assessment();
    payload.recommendation = "no_op";
    payload.workflowLabel = "no_op";

    expect(validate(payload).status).not.toBe(0);

    payload.applicability = {
      status: "superseded",
      rationale: "A narrower patch already landed.",
    };
    payload.regressionLikelihood.rating = "moderate";
    payload.regressionProtection.rating = "none";
    payload.regressionProtection.exactHeadChecksPassed = false;
    payload.validation = [];
    const accepted = validate(payload);
    expect(accepted.status, accepted.stderr).toBe(0);
  });

  test("requires affirmative failure evidence for a block", () => {
    const payload = assessment();
    payload.recommendation = "block";
    payload.workflowLabel = "block";

    expect(validate(payload).status).not.toBe(0);

    payload.validation[0]!.status = "failed";
    expect(validate(payload).status).not.toBe(0);

    payload.materialBoundaries[0]!.result = "contradicted";
    payload.regressionLikelihood.rating = "critical";
    payload.regressionProtection.rating = "partial";
    const accepted = validate(payload);
    expect(accepted.status, accepted.stderr).toBe(0);
  });

  test("requires affirmative failure evidence for a revision", () => {
    const payload = assessment();
    payload.recommendation = "revise";
    payload.workflowLabel = "revise";

    expect(validate(payload).status).not.toBe(0);

    payload.validation[0]!.status = "failed";
    payload.regressionLikelihood.rating = "high";
    payload.regressionProtection.rating = "partial";
    const accepted = validate(payload);
    expect(accepted.status, accepted.stderr).toBe(0);
  });

  test("requires complete merge evidence", () => {
    const lowConfidence = assessment();
    lowConfidence.confidence.rating = "low";
    expect(validate(lowConfidence).status).not.toBe(0);

    const emptyChangedFiles = assessment();
    emptyChangedFiles.patch.changedFiles = [];
    expect(validate(emptyChangedFiles).status).not.toBe(0);

    const unrelatedRuntimeRoot = assessment();
    unrelatedRuntimeRoot.materialBoundaries[0]!.runtimeRoot = "worker.request";
    expect(validate(unrelatedRuntimeRoot).status).not.toBe(0);

    const descriptiveBoundaryId = assessment();
    descriptiveBoundaryId.materialBoundaries[0]!.id = "Request.Contract.v2";
    const accepted = validate(descriptiveBoundaryId);
    expect(accepted.status, accepted.stderr).toBe(0);

    const strongWithoutExactHead = assessment();
    strongWithoutExactHead.regressionProtection.exactHeadChecksPassed = false;
    expect(validate(strongWithoutExactHead).status).not.toBe(0);

    const strongWithoutPassedValidation = assessment();
    strongWithoutPassedValidation.validation[0]!.status = "skipped";
    expect(validate(strongWithoutPassedValidation).status).not.toBe(0);

    const unknownProtectionWithHighConfidence = assessment();
    unknownProtectionWithHighConfidence.regressionProtection.rating = "unknown";
    expect(validate(unknownProtectionWithHighConfidence).status).not.toBe(0);

    const lowLikelihoodWithoutPassingProtection = assessment();
    lowLikelihoodWithoutPassingProtection.regressionProtection.rating = "none";
    lowLikelihoodWithoutPassingProtection.regressionProtection.exactHeadChecksPassed =
      false;
    lowLikelihoodWithoutPassingProtection.validation[0]!.status = "skipped";
    expect(validate(lowLikelihoodWithoutPassingProtection).status).not.toBe(0);

    const lowLikelihoodWithOnlyIrrelevantPassingProtection = assessment();
    lowLikelihoodWithOnlyIrrelevantPassingProtection.regressionProtection.rating =
      "partial";
    lowLikelihoodWithOnlyIrrelevantPassingProtection.regressionProtection.exactHeadChecksPassed =
      false;
    lowLikelihoodWithOnlyIrrelevantPassingProtection.validation = [
      {
        name: "formatting",
        status: "passed",
        protects: "Formatting only.",
        relevant: false,
      },
      {
        name: "request regression",
        status: "skipped",
        protects: "Changed behavior through the production caller.",
        relevant: true,
      },
    ];
    expect(
      validate(lowLikelihoodWithOnlyIrrelevantPassingProtection).status,
    ).not.toBe(0);

    const privilegedLowImpact = assessment();
    privilegedLowImpact.impact.rating = "low";
    privilegedLowImpact.autoMergeExclusions = ["privileged_boundary"];
    expect(validate(privilegedLowImpact).status).not.toBe(0);

    const publicContractModerateImpact = assessment();
    publicContractModerateImpact.autoMergeExclusions = ["public_contract"];
    expect(validate(publicContractModerateImpact).status).not.toBe(0);

    const criticalRegression = assessment();
    criticalRegression.regressionLikelihood.rating = "critical";
    expect(validate(criticalRegression).status).not.toBe(0);
  });

  test("keeps failed validation and established defects out of merge and hold", () => {
    const merge = assessment();
    merge.validation[0]!.status = "failed";
    expect(validate(merge).status).not.toBe(0);

    const hold = assessment();
    hold.recommendation = "hold_for_evidence";
    hold.workflowLabel = "hold_for_evidence";
    hold.materialBoundaries[0]!.result = "contradicted";
    hold.unknowns = [
      {
        id: "rollout-target",
        summary: "A separate rollout detail is unavailable.",
        decisionCritical: true,
      },
    ];
    hold.evidencePlan = [
      {
        question: "Which rollout target is selected?",
        action: "Inspect the checked-in deployment mapping.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: { found: "revise", unavailable: "hold_for_evidence" },
      },
    ];
    expect(validate(hold).status).not.toBe(0);

    hold.materialBoundaries[0]!.result = "supported";
    hold.validation[0]!.status = "failed";
    expect(validate(hold).status).not.toBe(0);
  });

  test("binds terminal evidence outcomes to every critical unknown", () => {
    const payload = assessment();
    payload.recommendation = "hold_for_evidence";
    payload.workflowLabel = "hold_for_evidence";
    payload.unknowns = [
      {
        id: "rollout-target",
        summary: "The rollout target is unavailable.",
        decisionCritical: true,
      },
      {
        id: "request-contract",
        summary: "The supported request contract is unavailable.",
        decisionCritical: true,
      },
    ];
    payload.evidencePlan = [
      {
        question: "Which rollout target is selected?",
        action: "Inspect the checked-in deployment mapping.",
        resolvesUnknowns: ["rollout-target"],
        outcomes: { found: "merge", unavailable: "hold_for_evidence" },
      },
    ];

    expect(validate(payload).status).not.toBe(0);
  });

  test("requires no-op for an established non-applicable disposition", () => {
    const payload = assessment();
    payload.recommendation = "block";
    payload.workflowLabel = "block";
    payload.applicability.status = "wrong_owner";
    payload.materialBoundaries[0]!.result = "contradicted";

    expect(validate(payload).status).not.toBe(0);
  });

  test("rejects duplicate JSON object keys", () => {
    const serialized = JSON.stringify(assessment()).replace(
      '"recommendation":"merge"',
      '"recommendation":"block","recommendation":"merge"',
    );

    const rejected = validateText(serialized);
    expect(rejected.status).not.toBe(0);
    expect(rejected.stderr).toContain(
      "duplicate JSON object key: recommendation",
    );
  });
});
