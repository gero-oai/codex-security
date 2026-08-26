#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "patch-risk-assessment.schema.json"
NON_APPLICABLE = {"no_live_effect", "wrong_owner", "duplicate", "superseded"}


class DuplicateJsonKeyError(ValueError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a patch-risk assessment.")
    parser.add_argument("assessment", help="Assessment JSON path, or - for stdin.")
    return parser.parse_args()


def object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError("duplicate JSON object key")
        value[key] = item
    return value


def read_json_object(path: str, *, label: str) -> dict[str, Any]:
    try:
        text = (
            sys.stdin.buffer.read().decode("utf-8-sig")
            if path == "-"
            else Path(path).read_text(encoding="utf-8-sig")
        )
        value = json.loads(text, object_pairs_hook=object_without_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise ValueError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    return type(left) is type(right) and left == right


def json_identity(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, (int, float)):
        return ("number", value)
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, list):
        return ("array", tuple(json_identity(item) for item in value))
    if isinstance(value, dict):
        return (
            "object",
            tuple(
                sorted((key, json_identity(item)) for key, item in value.items())
            ),
        )
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def python_pattern(pattern: str) -> str:
    if not pattern.endswith("$"):
        return pattern

    backslashes = 0
    for character in reversed(pattern[:-1]):
        if character != "\\":
            break
        backslashes += 1
    if backslashes % 2:
        return pattern
    return f"{pattern[:-1]}\\Z"


def matches_type(value: Any, expected: str) -> bool:
    return {
        "array": lambda: isinstance(value, list),
        "boolean": lambda: isinstance(value, bool),
        "integer": lambda: isinstance(value, int) and not isinstance(value, bool),
        "null": lambda: value is None,
        "number": lambda: isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": lambda: isinstance(value, dict),
        "string": lambda: isinstance(value, str),
    }.get(expected, lambda: False)()


def resolve_reference(reference: str, root_schema: dict[str, Any]) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise ValueError(f"unsupported assessment schema reference: {reference}")
    value: Any = root_schema
    for encoded_part in reference[2:].split("/"):
        part = encoded_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or part not in value:
            raise ValueError(f"unresolved assessment schema reference: {reference}")
        value = value[part]
    if not isinstance(value, dict):
        raise ValueError(f"assessment schema reference is not an object: {reference}")
    return value


def display_path(path: tuple[str | int, ...]) -> str:
    return ".".join(str(part) for part in path) or "$"


def structural_errors(
    value: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any],
    path: tuple[str | int, ...] = (),
) -> Iterator[str]:
    reference = schema.get("$ref")
    if isinstance(reference, str):
        yield from structural_errors(
            value,
            resolve_reference(reference, root_schema),
            root_schema,
            path,
        )

    location = display_path(path)
    if "const" in schema and not json_equal(value, schema["const"]):
        expected = json.dumps(schema["const"], separators=(",", ":"))
        yield f"{location}: value must equal {expected}"

    choices = schema.get("enum")
    if isinstance(choices, list) and not any(json_equal(value, choice) for choice in choices):
        yield f"{location}: value is not one of the allowed choices"

    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not matches_type(value, expected_type):
        yield f"{location}: value must be of type {expected_type}"
        return

    if isinstance(value, str):
        minimum_length = schema.get("minLength")
        if isinstance(minimum_length, int) and len(value) < minimum_length:
            yield f"{location}: string is shorter than {minimum_length} characters"
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(python_pattern(pattern), value) is None:
            yield f"{location}: string does not match the required pattern"

    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            yield f"{location}: array has fewer than {minimum_items} items"
        maximum_items = schema.get("maxItems")
        if isinstance(maximum_items, int) and len(value) > maximum_items:
            yield f"{location}: array has more than {maximum_items} items"
        if schema.get("uniqueItems") is True:
            seen: set[tuple[Any, ...]] = set()
            for item in value:
                identity = json_identity(item)
                if identity in seen:
                    yield f"{location}: array items must be unique"
                    break
                seen.add(identity)
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                yield from structural_errors(
                    item,
                    item_schema,
                    root_schema,
                    (*path, index),
                )

    if isinstance(value, dict):
        minimum_properties = schema.get("minProperties")
        if isinstance(minimum_properties, int) and len(value) < minimum_properties:
            yield f"{location}: object has fewer than {minimum_properties} properties"

        required = schema.get("required")
        if isinstance(required, list):
            for property_name in required:
                if isinstance(property_name, str) and property_name not in value:
                    yield f"{location}: required property {property_name!r} is missing"

        properties = schema.get("properties")
        known_properties = properties if isinstance(properties, dict) else {}
        for property_name, property_schema in known_properties.items():
            if property_name in value and isinstance(property_schema, dict):
                yield from structural_errors(
                    value[property_name],
                    property_schema,
                    root_schema,
                    (*path, property_name),
                )

        additional = schema.get("additionalProperties", True)
        for property_name in value.keys() - known_properties.keys():
            if additional is False:
                yield f"{location}: additional property {property_name!r} is not allowed"
            elif isinstance(additional, dict):
                yield from structural_errors(
                    value[property_name],
                    additional,
                    root_schema,
                    (*path, property_name),
                )


def schema_errors(value: dict[str, Any]) -> list[str]:
    schema = read_json_object(str(SCHEMA_PATH), label="assessment schema")
    return sorted(structural_errors(value, schema, schema))


def semantic_errors(value: dict[str, Any]) -> list[str]:
    recommendation = value["recommendation"]
    workflow_label = value["workflowLabel"]
    unknowns = value["unknowns"]
    evidence_plan = value["evidencePlan"]
    boundaries = value["materialBoundaries"]
    validations = value["validation"]
    errors: list[str] = []

    validation_names = [item["name"] for item in validations]
    if len(set(validation_names)) != len(validation_names):
        errors.append("validation names must be unique")

    unknown_ids = [item["id"] for item in unknowns]
    if len(set(unknown_ids)) != len(unknown_ids):
        errors.append("unknown identifiers must be unique")
    boundary_ids = [item["id"] for item in boundaries]
    if len(set(boundary_ids)) != len(boundary_ids):
        errors.append("material boundary identifiers must be unique")
    decision_critical_unknowns = {
        item["id"] for item in unknowns if item["decisionCritical"]
    }
    noncritical_unknowns = {
        item["id"] for item in unknowns if not item["decisionCritical"]
    }
    unresolved_boundaries = {
        item["id"] for item in boundaries if item["result"] == "unresolved"
    }

    unknown_failed_validations: set[str] = set()
    for index, item in enumerate(validations):
        attribution = item.get("failureAttribution")
        if item["status"] == "failed":
            if attribution is None:
                errors.append(
                    f"validation.{index}: failed validation requires failureAttribution"
                )
            elif attribution == "unknown":
                unknown_failed_validations.add(item["name"])
            elif (
                attribution == "patch_caused"
                and recommendation not in {"revise", "block"}
                and not (
                    recommendation == "no_op"
                    and value["applicability"]["status"] in NON_APPLICABLE
                )
                and not (
                    recommendation == "hold_for_evidence"
                    and value["applicability"]["status"] == "unknown"
                )
            ):
                errors.append(
                    "a patch-caused validation failure requires revise, a separately justified block, or an established no-op disposition"
                )
        elif attribution is not None:
            errors.append(
                f"validation.{index}: only failed validation may set failureAttribution"
            )

    if (
        value["patch"]["sourceType"] in {"pull_request_diff", "commit_range"}
        and recommendation != "no_op"
        and value["patch"]["base"] == value["patch"]["head"]
    ):
        errors.append("patch base and head must identify distinct revisions")

    if recommendation not in {"no_op", "hold_for_evidence"} and not value[
        "patch"
    ]["changedFiles"]:
        errors.append(
            "patch.changedFiles must be non-empty unless recommendation is no_op or hold_for_evidence"
        )

    if recommendation == "merge" and value["impact"]["rating"] == "unknown":
        errors.append("merge cannot use impact.rating=unknown")
    if recommendation != "hold_for_evidence":
        if value["regressionLikelihood"]["rating"] == "unknown":
            errors.append(
                "only hold_for_evidence may use regressionLikelihood.rating=unknown"
            )
    if (
        value["regressionProtection"]["rating"] == "unknown"
        and value["confidence"]["rating"] == "high"
    ):
        errors.append("unknown regression protection cannot support high confidence")
    if value["impact"]["rating"] == "unknown" and value["confidence"]["rating"] == "high":
        errors.append("unknown impact cannot support high confidence")
    if unknowns and value["confidence"]["rating"] == "high":
        errors.append("high confidence cannot retain an explicit unknown")
    if unresolved_boundaries and value["confidence"]["rating"] == "high":
        errors.append("an unresolved material boundary cannot support high confidence")
    if (
        unknown_failed_validations
        and value["applicability"]["status"] == "confirmed"
        and value["confidence"]["rating"] == "high"
    ):
        errors.append(
            "a failed validation with unknown attribution cannot support high confidence"
        )

    if recommendation == "merge":
        if workflow_label not in {"auto_merge_candidate", "human_review_required"}:
            errors.append("merge requires an auto-merge or human-review workflow label")
        if value["applicability"]["status"] != "confirmed":
            errors.append("merge requires confirmed applicability")
        if any(item["result"] != "supported" for item in boundaries):
            errors.append("merge requires every material boundary to be supported")
        if value["regressionLikelihood"]["rating"] == "critical":
            errors.append("merge cannot have critical regression likelihood")
        if value["materialSafetyFailure"]["established"]:
            errors.append("merge cannot retain an established material safety failure")
        if value["confidence"]["rating"] == "low":
            errors.append("merge cannot have low confidence")
        if any(
            item["status"] == "failed"
            and item.get("failureAttribution") != "not_patch_caused"
            for item in value["validation"]
        ):
            errors.append("merge cannot include a patch-caused or unattributed failure")
        if value["regressionLikelihood"]["rating"] == "low" and (
            value["regressionProtection"]["rating"] in {"none", "unknown"}
            or not any(item["status"] == "passed" for item in value["validation"])
        ):
            errors.append(
                "merge with low regression likelihood requires passing protection"
            )
        if evidence_plan:
            errors.append("merge cannot retain an evidence plan")
    elif workflow_label != recommendation:
        errors.append("non-merge workflow label must match the recommendation")

    if value["applicability"]["status"] == "unknown" and recommendation != "hold_for_evidence":
        errors.append("unknown applicability requires hold_for_evidence")

    if value["applicability"]["status"] in NON_APPLICABLE and recommendation != "no_op":
        errors.append("an established non-applicable disposition requires no_op")

    if recommendation != "hold_for_evidence" and decision_critical_unknowns:
        errors.append(
            f"{recommendation} cannot retain a decision-critical unknown"
        )

    if recommendation == "hold_for_evidence":
        if not decision_critical_unknowns:
            errors.append("hold_for_evidence requires a decision-critical unknown")
        if value["confidence"]["rating"] != "low":
            errors.append("hold_for_evidence requires low confidence")
        if not evidence_plan:
            errors.append("hold_for_evidence requires a bounded evidence plan")
        if (
            value["regressionLikelihood"]["rating"] == "critical"
            and value["applicability"]["status"] != "unknown"
        ):
            errors.append("hold_for_evidence cannot have critical regression likelihood")
        if (
            any(item["result"] == "contradicted" for item in boundaries)
            and value["applicability"]["status"] != "unknown"
        ):
            errors.append("hold_for_evidence cannot retain a contradicted material boundary")
        if (
            value["materialSafetyFailure"]["established"]
            and value["applicability"]["status"] != "unknown"
        ):
            errors.append(
                "hold_for_evidence cannot retain an established material safety failure"
            )
        planned_failed_validations: set[str] = set()
        planned_unknowns: set[str] = set()
        planned_boundaries: set[str] = set()
        planned_applicability = False
        planned_impact = value["impact"]["rating"] != "unknown"
        planned_likelihood = value["regressionLikelihood"]["rating"] != "unknown"
        planned_changed_files = bool(value["patch"]["changedFiles"])
        for index, item in enumerate(evidence_plan):
            applicability_outcomes = item.get("applicabilityOutcomes")
            changed_files_outcomes = item.get("changedFilesOutcomes")
            impact_outcomes = item.get("impactOutcomes")
            confidence_outcomes = item.get("confidenceOutcomes")
            likelihood_outcomes = item.get("regressionLikelihoodOutcomes")
            safety_failure_outcomes = item.get("materialSafetyFailureOutcomes")
            resolved_boundaries = item.get("resolvesBoundaries", [])
            boundary_outcomes = item.get("boundaryOutcomes")
            remaining_unknown_outcomes = item.get("remainingUnknowns")
            if applicability_outcomes is not None:
                if any(
                    status != "unknown"
                    for status in applicability_outcomes.values()
                ):
                    planned_applicability = True
                else:
                    errors.append(
                        f"evidencePlan.{index}: applicability remains unknown in every outcome"
                    )
            if applicability_outcomes is not None and value["applicability"][
                "status"
            ] != "unknown":
                errors.append(
                    f"evidencePlan.{index}: applicabilityOutcomes requires unknown applicability"
                )
            if applicability_outcomes is not None and set(
                applicability_outcomes
            ) != set(item["outcomes"]):
                errors.append(
                    f"evidencePlan.{index}: applicabilityOutcomes must name exactly the evidence outcome keys"
                )
            if impact_outcomes is not None and set(impact_outcomes) != set(
                item["outcomes"]
            ):
                errors.append(
                    f"evidencePlan.{index}: impactOutcomes must name exactly the evidence outcome keys"
                )
            if impact_outcomes is not None and any(
                rating != "unknown" for rating in impact_outcomes.values()
            ):
                planned_impact = True
            if changed_files_outcomes is not None and set(
                changed_files_outcomes
            ) != set(item["outcomes"]):
                errors.append(
                    f"evidencePlan.{index}: changedFilesOutcomes must name exactly the evidence outcome keys"
                )
            if changed_files_outcomes is not None:
                if value["patch"]["changedFiles"]:
                    errors.append(
                        f"evidencePlan.{index}: changedFilesOutcomes may only resolve an empty patch.changedFiles inventory"
                    )
                if any(changed_files_outcomes.values()):
                    planned_changed_files = True
                else:
                    errors.append(
                        f"evidencePlan.{index}: changedFilesOutcomes must complete the inventory in at least one outcome"
                    )
            if confidence_outcomes is not None and set(confidence_outcomes) != set(
                item["outcomes"]
            ):
                errors.append(
                    f"evidencePlan.{index}: confidenceOutcomes must name exactly the evidence outcome keys"
                )
            if likelihood_outcomes is not None and set(likelihood_outcomes) != set(
                item["outcomes"]
            ):
                errors.append(
                    f"evidencePlan.{index}: regressionLikelihoodOutcomes must name exactly the evidence outcome keys"
                )
            if likelihood_outcomes is not None and any(
                rating != "unknown" for rating in likelihood_outcomes.values()
            ):
                planned_likelihood = True
            if safety_failure_outcomes is not None and set(
                safety_failure_outcomes
            ) != set(item["outcomes"]):
                errors.append(
                    f"evidencePlan.{index}: materialSafetyFailureOutcomes must name exactly the evidence outcome keys"
                )
            if resolved_boundaries and boundary_outcomes is None:
                errors.append(
                    f"evidencePlan.{index}: resolvesBoundaries requires boundaryOutcomes"
                )
            if boundary_outcomes is not None and not resolved_boundaries:
                errors.append(
                    f"evidencePlan.{index}: boundaryOutcomes requires resolvesBoundaries"
                )
            if boundary_outcomes is not None and set(boundary_outcomes) != set(
                item["outcomes"]
            ):
                errors.append(
                    f"evidencePlan.{index}: boundaryOutcomes must name exactly the evidence outcome keys"
                )
            if remaining_unknown_outcomes is not None and set(
                remaining_unknown_outcomes
            ) != set(item["outcomes"]):
                errors.append(
                    f"evidencePlan.{index}: remainingUnknowns must name exactly the evidence outcome keys"
                )
            for outcome, outcome_recommendation in item["outcomes"].items():
                outcome_applicability = (
                    applicability_outcomes.get(outcome)
                    if applicability_outcomes is not None
                    else None
                )
                outcome_boundaries = (
                    boundary_outcomes.get(outcome)
                    if boundary_outcomes is not None
                    else None
                )
                effective_unresolved_boundaries = unresolved_boundaries - set(
                    resolved_boundaries
                )
                if outcome_boundaries is not None:
                    effective_unresolved_boundaries |= {
                        boundary_id
                        for boundary_id, result in outcome_boundaries.items()
                        if result == "unresolved"
                    }
                effective_unknown_failed_validations = (
                    unknown_failed_validations
                    - set(item.get("resolvesFailedValidation", []))
                )
                outcome_remaining_unknowns = set(
                    remaining_unknown_outcomes.get(outcome, [])
                    if remaining_unknown_outcomes is not None
                    else []
                )
                outcome_likelihood = (
                    likelihood_outcomes.get(outcome)
                    if likelihood_outcomes is not None
                    else value["regressionLikelihood"]["rating"]
                )
                outcome_impact = (
                    impact_outcomes.get(outcome)
                    if impact_outcomes is not None
                    else value["impact"]["rating"]
                )
                outcome_changed_files = (
                    changed_files_outcomes.get(outcome)
                    if changed_files_outcomes is not None
                    else value["patch"]["changedFiles"]
                )
                outcome_confidence = (
                    confidence_outcomes.get(outcome)
                    if confidence_outcomes is not None
                    else value["confidence"]["rating"]
                )
                outcome_safety_failure = (
                    safety_failure_outcomes.get(outcome)
                    if safety_failure_outcomes is not None
                    else value["materialSafetyFailure"]["established"]
                )
                effective_applicability = (
                    outcome_applicability
                    if outcome_applicability is not None
                    else value["applicability"]["status"]
                )
                if effective_applicability not in NON_APPLICABLE:
                    if (
                        value["regressionLikelihood"]["rating"] == "critical"
                        and outcome_likelihood != "critical"
                    ):
                        errors.append(
                            f"evidencePlan.{index}: established critical regression likelihood must remain critical until a non-applicable disposition"
                        )
                    if (
                        value["materialSafetyFailure"]["established"]
                        and outcome_safety_failure is not True
                    ):
                        errors.append(
                            f"evidencePlan.{index}: an established material safety failure must remain established until a non-applicable disposition"
                        )
                for unknown_id in outcome_remaining_unknowns:
                    if unknown_id not in decision_critical_unknowns:
                        errors.append(
                            f"evidencePlan.{index}: remaining unknown {unknown_id!r} is not decision-critical"
                        )
                if outcome_boundaries is not None and set(outcome_boundaries) != set(
                    resolved_boundaries
                ):
                    errors.append(
                        f"evidencePlan.{index}: boundaryOutcomes.{outcome} must name exactly the resolved material boundaries"
                    )
                if (
                    outcome_recommendation == "merge"
                    and outcome_boundaries is not None
                    and any(
                        result != "supported"
                        for result in outcome_boundaries.values()
                    )
                ):
                    errors.append(
                        f"evidencePlan.{index}: a merge outcome requires every resolved material boundary to be supported"
                    )
                if (
                    value["applicability"]["status"] == "unknown"
                    and outcome_recommendation != "hold_for_evidence"
                    and outcome_applicability is None
                ):
                    errors.append(
                        f"evidencePlan.{index}: a terminal outcome must resolve unknown applicability"
                    )
                if outcome_recommendation == "no_op" and (
                    value["applicability"]["status"] != "unknown"
                    or outcome_applicability not in NON_APPLICABLE
                ):
                    errors.append(
                        f"evidencePlan.{index}: a no_op outcome requires a non-applicable applicability outcome from the same action"
                    )
                if (
                    outcome_applicability in NON_APPLICABLE
                    and outcome_recommendation != "no_op"
                ):
                    errors.append(
                        f"evidencePlan.{index}: a non-applicable applicability outcome requires no_op"
                    )
                if (
                    outcome_recommendation == "merge"
                    and outcome_applicability is not None
                    and outcome_applicability != "confirmed"
                ):
                    errors.append(
                        f"evidencePlan.{index}: a merge outcome requires confirmed applicability"
                    )
                if (
                    outcome_applicability == "unknown"
                    and outcome_recommendation != "hold_for_evidence"
                ):
                    errors.append(
                        f"evidencePlan.{index}: unknown applicability requires hold_for_evidence"
                    )
                if (
                    outcome_recommendation != "hold_for_evidence"
                    and outcome_likelihood == "unknown"
                ):
                    errors.append(
                        f"evidencePlan.{index}: a terminal outcome cannot retain unknown regression likelihood"
                    )
                branch_contradiction = any(
                    boundary["result"] == "contradicted" for boundary in boundaries
                ) or (
                    outcome_boundaries is not None
                    and any(
                        result == "contradicted"
                        for result in outcome_boundaries.values()
                    )
                )
                branch_patch_failure = any(
                    validation["status"] == "failed"
                    and validation.get("failureAttribution") == "patch_caused"
                    for validation in validations
                ) or (
                    outcome == "patch_caused"
                    and bool(item.get("resolvesFailedValidation", []))
                )
                branch_defect = (
                    outcome_likelihood == "critical"
                    or outcome_safety_failure is True
                    or branch_contradiction
                    or branch_patch_failure
                )
                if (
                    branch_defect
                    and effective_applicability == "confirmed"
                    and outcome_recommendation not in {"revise", "block"}
                ):
                    errors.append(
                        f"evidencePlan.{index}: confirmed applicability with an established defect requires revise or block"
                    )
                if branch_defect and outcome_recommendation == "merge":
                    errors.append(
                        f"evidencePlan.{index}: a merge outcome cannot retain an established defect"
                    )
                branch_failed_validation_resolved = outcome in {
                    "patch_caused",
                    "not_patch_caused",
                }
                if (
                    item.get("resolvesFailedValidation", [])
                    and not branch_failed_validation_resolved
                    and outcome_recommendation != "hold_for_evidence"
                ):
                    errors.append(
                        f"evidencePlan.{index}: an inconclusive failed-validation outcome must remain on hold"
                    )
                if outcome_recommendation == "revise" and not branch_defect:
                    errors.append(
                        f"evidencePlan.{index}: a revise outcome requires branch evidence of a defect"
                    )
                if (
                    branch_contradiction
                    and effective_applicability == "confirmed"
                    and outcome_recommendation not in {"revise", "block"}
                ):
                    errors.append(
                        f"evidencePlan.{index}: a contradicted boundary outcome requires revise or block"
                    )
                if (
                    outcome_recommendation == "revise"
                    and outcome_likelihood == "critical"
                    and outcome_safety_failure is True
                ):
                    errors.append(
                        f"evidencePlan.{index}: critical regression likelihood with an established material safety failure requires block"
                    )
                if (
                    outcome_safety_failure is True
                    and outcome_likelihood != "critical"
                ):
                    errors.append(
                        f"evidencePlan.{index}: an established material safety failure requires critical regression likelihood"
                    )
                if outcome_recommendation == "block" and not (
                    outcome_likelihood == "critical"
                    and outcome_safety_failure is True
                ):
                    errors.append(
                        f"evidencePlan.{index}: a block outcome requires critical regression likelihood and an established material safety failure"
                    )
                if (
                    outcome_recommendation not in {"no_op", "hold_for_evidence"}
                    and not outcome_changed_files
                ):
                    errors.append(
                        f"evidencePlan.{index}: a terminal outcome requires a complete changed-file inventory"
                    )
                if (
                    outcome_recommendation == "no_op"
                    and outcome_confidence == "low"
                ):
                    errors.append(
                        f"evidencePlan.{index}: a no_op outcome cannot retain low confidence"
                    )
                if (
                    outcome_recommendation == "hold_for_evidence"
                    and outcome_confidence != "low"
                ):
                    errors.append(
                        f"evidencePlan.{index}: a hold outcome requires low confidence"
                    )
                if (
                    value["regressionProtection"]["rating"] == "unknown"
                    and outcome_confidence == "high"
                ):
                    errors.append(
                        f"evidencePlan.{index}: unknown regression protection cannot support high confidence"
                    )
                if noncritical_unknowns and outcome_confidence == "high":
                    errors.append(
                        f"evidencePlan.{index}: high confidence cannot retain an explicit unknown"
                    )
                if outcome_impact == "unknown" and outcome_confidence == "high":
                    errors.append(
                        f"evidencePlan.{index}: unknown impact cannot support high confidence"
                    )
                if effective_unresolved_boundaries and outcome_confidence == "high":
                    errors.append(
                        f"evidencePlan.{index}: an unresolved material boundary cannot support high confidence"
                    )
                if (
                    effective_unknown_failed_validations
                    and effective_applicability == "confirmed"
                    and outcome_confidence == "high"
                ):
                    errors.append(
                        f"evidencePlan.{index}: a failed validation with unknown attribution cannot support high confidence"
                    )
                if outcome_recommendation == "merge":
                    if outcome_confidence == "low":
                        errors.append(
                            f"evidencePlan.{index}: a merge outcome cannot retain low confidence"
                        )
                    if outcome_likelihood == "critical":
                        errors.append(
                            f"evidencePlan.{index}: a merge outcome cannot establish critical regression likelihood"
                        )
                    if outcome_safety_failure is True:
                        errors.append(
                            f"evidencePlan.{index}: a merge outcome cannot establish a material safety failure"
                        )
                    if outcome_likelihood == "low" and (
                        value["regressionProtection"]["rating"]
                        in {"none", "unknown"}
                        or not any(
                            validation["status"] == "passed"
                            for validation in validations
                        )
                    ):
                        errors.append(
                            f"evidencePlan.{index}: a low-likelihood merge outcome requires passing protection"
                        )
                if (
                    outcome_recommendation == "hold_for_evidence"
                    and effective_applicability != "unknown"
                ):
                    if branch_patch_failure:
                        errors.append(
                            f"evidencePlan.{index}: an applicable patch-caused failure requires revise or block"
                        )
                    if outcome_likelihood == "critical":
                        errors.append(
                            f"evidencePlan.{index}: an applicable hold outcome cannot establish critical regression likelihood"
                        )
                    if outcome_safety_failure is True:
                        errors.append(
                            f"evidencePlan.{index}: an applicable hold outcome cannot establish a material safety failure"
                        )
                remaining_decision_unknowns = (
                    decision_critical_unknowns - set(item["resolvesUnknowns"])
                ) | outcome_remaining_unknowns
                if (
                    outcome_recommendation == "hold_for_evidence"
                    and not outcome_remaining_unknowns
                ):
                    errors.append(
                        f"evidencePlan.{index}: a hold outcome must retain a decision-critical unknown in remainingUnknowns"
                    )
                if (
                    outcome_recommendation != "hold_for_evidence"
                    and remaining_decision_unknowns
                    and not (
                        outcome_recommendation == "no_op"
                        and outcome_applicability in NON_APPLICABLE
                    )
                ):
                    errors.append(
                        f"evidencePlan.{index}: a terminal outcome cannot retain a decision-critical unknown"
                    )
                if outcome_recommendation == "merge":
                    if outcome_impact == "unknown":
                        errors.append(
                            f"evidencePlan.{index}: a merge outcome cannot retain unknown impact"
                        )
                    if outcome_likelihood == "unknown":
                        errors.append(
                            f"evidencePlan.{index}: a merge outcome cannot retain unknown regression likelihood"
                        )
                    unresolved_unknowns = decision_critical_unknowns - set(
                        item["resolvesUnknowns"]
                    )
                    unresolved_failures = unknown_failed_validations - set(
                        item.get("resolvesFailedValidation", [])
                    )
                    unresolved_boundary_ids = unresolved_boundaries - set(
                        item.get("resolvesBoundaries", [])
                    )
                    if unresolved_unknowns:
                        errors.append(
                            f"evidencePlan.{index}: a merge outcome must resolve every decision-critical unknown"
                        )
                    if unresolved_failures:
                        errors.append(
                            f"evidencePlan.{index}: a merge outcome must resolve every failed validation with unknown attribution"
                        )
                    if unresolved_boundary_ids:
                        errors.append(
                            f"evidencePlan.{index}: a merge outcome must resolve every unresolved material boundary"
                        )
                    if (
                        value["applicability"]["status"] == "unknown"
                        and outcome_applicability != "confirmed"
                    ):
                        errors.append(
                            f"evidencePlan.{index}: a merge outcome must resolve unknown applicability as confirmed"
                        )
            for unknown_id in item["resolvesUnknowns"]:
                if unknown_id not in decision_critical_unknowns:
                    errors.append(
                        f"evidencePlan.{index}: {unknown_id!r} is not a decision-critical unknown"
                    )
                    continue
                if remaining_unknown_outcomes is not None and all(
                    unknown_id in remaining_unknown_outcomes.get(outcome, [])
                    for outcome in item["outcomes"]
                ):
                    errors.append(
                        f"evidencePlan.{index}: {unknown_id!r} remains unresolved in every outcome"
                    )
                    continue
                planned_unknowns.add(unknown_id)
            for boundary_id in resolved_boundaries:
                if boundary_id not in unresolved_boundaries:
                    errors.append(
                        f"evidencePlan.{index}: {boundary_id!r} is not an unresolved material boundary"
                    )
                    continue
                if boundary_outcomes is None or all(
                    outcome.get(boundary_id) == "unresolved"
                    for outcome in boundary_outcomes.values()
                ):
                    errors.append(
                        f"evidencePlan.{index}: {boundary_id!r} remains unresolved in every outcome"
                    )
                    continue
                planned_boundaries.add(boundary_id)
            for name in item.get("resolvesFailedValidation", []):
                if name not in unknown_failed_validations:
                    errors.append(
                        f"evidencePlan.{index}: {name!r} is not a failed validation with unknown attribution"
                    )
                    continue
                planned_failed_validations.add(name)
                if not {"patch_caused", "not_patch_caused"}.issubset(
                    item["outcomes"]
                ):
                    errors.append(
                        f"evidencePlan.{index}: failed-validation attribution requires patch_caused and not_patch_caused outcomes"
                    )
                elif item["outcomes"]["patch_caused"] not in {
                    "revise",
                    "block",
                    "no_op",
                    "hold_for_evidence",
                }:
                    errors.append(
                        f"evidencePlan.{index}: a patch_caused outcome must recommend revise, block, or no_op unless another pivot requires hold_for_evidence"
                    )
        for name in sorted(unknown_failed_validations - planned_failed_validations):
            errors.append(
                f"failed validation {name!r} with unknown attribution requires a matching evidence plan"
            )
        for unknown_id in sorted(decision_critical_unknowns - planned_unknowns):
            errors.append(
                f"decision-critical unknown {unknown_id!r} requires a matching evidence plan"
            )
        for boundary_id in sorted(unresolved_boundaries - planned_boundaries):
            errors.append(
                f"unresolved material boundary {boundary_id!r} requires a matching evidence plan"
            )
        if (
            value["applicability"]["status"] == "unknown"
            and not planned_applicability
        ):
            errors.append(
                "unknown applicability requires a matching applicability evidence plan"
            )
        if not planned_impact:
            errors.append("unknown impact requires a matching impact evidence plan")
        if not planned_likelihood:
            errors.append(
                "unknown regression likelihood requires a matching likelihood evidence plan"
            )
        if not planned_changed_files:
            errors.append(
                "empty patch.changedFiles requires a matching changedFilesOutcomes evidence plan"
            )
    elif evidence_plan:
        errors.append("only hold_for_evidence may include an evidence plan")

    if recommendation == "no_op":
        if value["applicability"]["status"] not in NON_APPLICABLE:
            errors.append("no_op requires an established non-applicable disposition")
        if value["confidence"]["rating"] == "low":
            errors.append("no_op cannot have low confidence")

    if (
        recommendation == "revise"
        and value["regressionLikelihood"]["rating"] != "critical"
        and not value["materialSafetyFailure"]["established"]
        and not any(item["result"] == "contradicted" for item in boundaries)
        and not any(
            item["status"] == "failed"
            and item.get("failureAttribution") == "patch_caused"
            for item in value["validation"]
        )
    ):
        errors.append(
            "revise requires critical regression likelihood, an established material safety failure, a contradicted material boundary, or a patch-caused validation failure"
        )

    if (
        recommendation == "revise"
        and value["regressionLikelihood"]["rating"] == "critical"
        and value["materialSafetyFailure"]["established"]
    ):
        errors.append(
            "critical regression likelihood with an established material safety failure requires block"
        )

    if (
        value["materialSafetyFailure"]["established"]
        and value["regressionLikelihood"]["rating"] != "critical"
    ):
        errors.append(
            "an established material safety failure requires critical regression likelihood"
        )

    if recommendation == "block" and not (
        value["regressionLikelihood"]["rating"] == "critical"
        and value["materialSafetyFailure"]["established"]
    ):
        errors.append(
            "block requires critical regression likelihood and an established material safety failure"
        )

    if value["regressionProtection"]["rating"] == "strong":
        if not value["regressionProtection"]["exactHeadChecksPassed"]:
            errors.append("strong regression protection requires exact-head checks to pass")
        if not any(item["status"] in {"passed", "failed"} for item in validations):
            errors.append("strong regression protection requires an executed validation")
    required_validations = [item for item in validations if item["requiredForMerge"]]
    if value["regressionProtection"]["exactHeadChecksPassed"] and (
        not any(item["status"] == "passed" for item in validations)
        or not all(item["status"] == "passed" for item in required_validations)
    ):
        errors.append(
            "exact-head checks passed requires every required validation to pass"
        )

    if workflow_label == "auto_merge_candidate":
        auto_merge_requirements = {
            "impact.rating": value["impact"]["rating"] == "low",
            "regressionLikelihood.rating": value["regressionLikelihood"]["rating"]
            == "low",
            "regressionProtection.rating": value["regressionProtection"]["rating"]
            == "strong",
            "regressionProtection.exactHeadChecksPassed": value["regressionProtection"][
                "exactHeadChecksPassed"
            ],
            "recoverability.rating": value["recoverability"]["rating"] == "easy",
            "confidence.rating": value["confidence"]["rating"] == "high",
            "applicability.status": value["applicability"]["status"] == "confirmed",
            "affectedRuntimeRoots": bool(value["affectedRuntimeRoots"]),
            "statusQuoRisk.rating": value["statusQuoRisk"]["rating"] != "unknown",
            "autoMergeExclusions": not value["autoMergeExclusions"],
            "unknowns": not unknowns,
            "validation": all(
                not item["requiredForMerge"] or item["status"] == "passed"
                for item in validations
            )
            and not any(item["status"] == "failed" for item in validations),
        }
        for field, passed in auto_merge_requirements.items():
            if not passed:
                errors.append(f"auto_merge_candidate gate failed: {field}")

    return errors


def validate(value: dict[str, Any]) -> list[str]:
    errors = schema_errors(value)
    if errors:
        return errors
    return semantic_errors(value)


def emit_error(error: object) -> None:
    message = f"{error}\n".encode("utf-8", errors="backslashreplace")
    stream = getattr(sys.stderr, "buffer", None)
    if stream is not None:
        stream.write(message)
        stream.flush()
        return
    sys.stderr.write(message.decode("utf-8"))
    sys.stderr.flush()


def main() -> int:
    args = parse_args()
    try:
        value = read_json_object(args.assessment, label="assessment")
        errors = validate(value)
    except ValueError as error:
        emit_error(error)
        return 1
    if errors:
        for error in errors:
            emit_error(error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
