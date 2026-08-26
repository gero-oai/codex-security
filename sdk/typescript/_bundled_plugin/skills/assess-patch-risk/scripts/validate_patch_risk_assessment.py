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
            for index, item in enumerate(value):
                if any(json_equal(item, earlier) for earlier in value[:index]):
                    yield f"{location}: array items must be unique"
                    break
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
    errors: list[str] = []

    if recommendation != "no_op" and not value["patch"]["changedFiles"]:
        errors.append("patch.changedFiles must be non-empty unless recommendation is no_op")

    if recommendation != "hold_for_evidence":
        if value["impact"]["rating"] == "unknown":
            errors.append("only hold_for_evidence may use impact.rating=unknown")
        if value["regressionLikelihood"]["rating"] == "unknown":
            errors.append(
                "only hold_for_evidence may use regressionLikelihood.rating=unknown"
            )

    if recommendation == "merge":
        if workflow_label not in {"auto_merge_candidate", "human_review_required"}:
            errors.append("merge requires an auto-merge or human-review workflow label")
        if value["applicability"]["status"] != "confirmed":
            errors.append("merge requires confirmed applicability")
        if any(item["decisionCritical"] for item in unknowns):
            errors.append("merge cannot retain a decision-critical unknown")
        if any(item["result"] != "supported" for item in boundaries):
            errors.append("merge requires every material boundary to be supported")
        if value["regressionLikelihood"]["rating"] == "critical":
            errors.append("merge cannot have critical regression likelihood")
        if value["confidence"]["rating"] == "low":
            errors.append("merge cannot have low confidence")
        if evidence_plan:
            errors.append("merge cannot retain an evidence plan")
    elif workflow_label != recommendation:
        errors.append("non-merge workflow label must match the recommendation")

    if value["applicability"]["status"] in NON_APPLICABLE and recommendation != "no_op":
        errors.append("an established non-applicable disposition requires no_op")

    if recommendation == "hold_for_evidence":
        if not any(item["decisionCritical"] for item in unknowns):
            errors.append("hold_for_evidence requires a decision-critical unknown")
        if value["confidence"]["rating"] != "low":
            errors.append("hold_for_evidence requires low confidence")
        if not evidence_plan:
            errors.append("hold_for_evidence requires a bounded evidence plan")
        if value["regressionLikelihood"]["rating"] == "critical":
            errors.append("hold_for_evidence cannot have critical regression likelihood")
        if any(item["result"] == "contradicted" for item in boundaries):
            errors.append("hold_for_evidence cannot retain a contradicted material boundary")
        for index, item in enumerate(evidence_plan):
            if len(set(item["outcomes"].values())) < 2:
                errors.append(
                    f"evidencePlan.{index}: requires at least two distinct outcome recommendations"
                )
    elif evidence_plan:
        errors.append("only hold_for_evidence may include an evidence plan")

    if recommendation == "no_op":
        if value["applicability"]["status"] not in NON_APPLICABLE:
            errors.append("no_op requires an established non-applicable disposition")
        if any(item["decisionCritical"] for item in unknowns):
            errors.append("no_op cannot retain a decision-critical unknown")
        if value["confidence"]["rating"] == "low":
            errors.append("no_op cannot have low confidence")

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
        if not all(item["status"] == "passed" for item in value["validation"]):
            errors.append(
                "strong regression protection requires every validation item to pass"
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
