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
            sys.stdin.buffer.read().decode("utf-8")
            if path == "-"
            else Path(path).read_text(encoding="utf-8")
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
    decision_critical_unknowns = {
        item["id"] for item in unknowns if item["decisionCritical"]
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
                    "a patch-caused validation failure requires revise, block, or an established no-op disposition"
                )
        elif attribution is not None:
            errors.append(
                f"validation.{index}: only failed validation may set failureAttribution"
            )

    if (
        value["patch"]["sourceType"] in {"pull_request_diff", "commit_range"}
        and recommendation != "no_op"
        and value["patch"]["base"].strip() == value["patch"]["head"].strip()
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

    if recommendation == "merge":
        if workflow_label not in {"auto_merge_candidate", "human_review_required"}:
            errors.append("merge requires an auto-merge or human-review workflow label")
        if value["applicability"]["status"] != "confirmed":
            errors.append("merge requires confirmed applicability")
        if any(item["result"] != "supported" for item in boundaries):
            errors.append("merge requires every material boundary to be supported")
        if value["regressionLikelihood"]["rating"] == "critical":
            errors.append("merge cannot have critical regression likelihood")
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
        planned_failed_validations: set[str] = set()
        planned_unknowns: set[str] = set()
        established_defect = (
            value["regressionLikelihood"]["rating"] == "critical"
            or any(item["result"] == "contradicted" for item in boundaries)
            or any(
                item["status"] == "failed"
                and item.get("failureAttribution") == "patch_caused"
                for item in validations
            )
        )
        for index, item in enumerate(evidence_plan):
            if len(set(item["outcomes"].values())) < 2:
                errors.append(
                    f"evidencePlan.{index}: requires at least two distinct outcome recommendations"
                )
            if established_defect and "merge" in item["outcomes"].values():
                errors.append(
                    f"evidencePlan.{index}: a merge outcome cannot retain an established defect"
                )
            resolves_applicability = item.get("resolvesApplicability") is True
            if (
                resolves_applicability
                and value["applicability"]["status"] != "unknown"
            ):
                errors.append(
                    f"evidencePlan.{index}: resolvesApplicability requires unknown applicability"
                )
            if "no_op" in item["outcomes"].values() and not (
                resolves_applicability
                and value["applicability"]["status"] == "unknown"
            ):
                errors.append(
                    f"evidencePlan.{index}: a no_op outcome requires the same action to resolve unknown applicability"
                )
            for unknown_id in item["resolvesUnknowns"]:
                if unknown_id not in decision_critical_unknowns:
                    errors.append(
                        f"evidencePlan.{index}: {unknown_id!r} is not a decision-critical unknown"
                    )
                    continue
                planned_unknowns.add(unknown_id)
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
                }:
                    errors.append(
                        f"evidencePlan.{index}: a patch_caused outcome must recommend revise, block, or no_op"
                    )
        for name in sorted(unknown_failed_validations - planned_failed_validations):
            errors.append(
                f"failed validation {name!r} with unknown attribution requires a matching evidence plan"
            )
        for unknown_id in sorted(decision_critical_unknowns - planned_unknowns):
            errors.append(
                f"decision-critical unknown {unknown_id!r} requires a matching evidence plan"
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
        and not any(item["result"] == "contradicted" for item in boundaries)
        and not any(
            item["status"] == "failed"
            and item.get("failureAttribution") == "patch_caused"
            for item in value["validation"]
        )
    ):
        errors.append(
            "revise requires critical regression likelihood, a contradicted material boundary, or a patch-caused validation failure"
        )

    if (
        recommendation == "block"
        and value["regressionLikelihood"]["rating"] != "critical"
        and not any(item["result"] == "contradicted" for item in boundaries)
    ):
        errors.append(
            "block requires critical regression likelihood or a contradicted material boundary"
        )

    if value["regressionProtection"]["rating"] == "strong":
        if not value["regressionProtection"]["exactHeadChecksPassed"]:
            errors.append("strong regression protection requires exact-head checks to pass")

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
            "validation": all(item["status"] == "passed" for item in value["validation"]),
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


def main() -> int:
    args = parse_args()
    try:
        value = read_json_object(args.assessment, label="assessment")
        errors = validate(value)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
