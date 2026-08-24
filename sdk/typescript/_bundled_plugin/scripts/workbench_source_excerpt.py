"""Read bounded finding source excerpts from sealed Git revisions."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
import sys
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any
from unicodedata import normalize

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_target import (
    clean_worktree_content_digest,
    git_bytes,
    git_worktree_context,
)

CONTEXT_LINES = 3
MAX_BYTES = 16_000
MAX_LINES = 60
OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")

TreeEntry = tuple[str, str, str]
SourceScope = dict[str, str]


def normalized_path_component(value: str) -> str:
    return normalize("NFC", normalize("NFD", value).casefold())


def relative_path(value: str) -> PurePosixPath | None:
    path = PurePosixPath(value)
    if not value or "\\" in value or path.is_absolute() or ".." in path.parts:
        return None
    return path


def safe_source_path(target: Path, value: str) -> Path | None:
    path = relative_path(value)
    if path is None:
        return None
    try:
        root = target.resolve()
        selected = (root / path.as_posix()).resolve()
        selected.relative_to(root)
        return selected
    except (OSError, RuntimeError, ValueError):
        return None


def local_git_bytes(repository: Path, *arguments: str) -> bytes | None:
    return git_bytes(
        repository,
        "--no-replace-objects",
        *arguments,
        local_objects_only=True,
    )


@cache
def tree_entries(repository: Path, tree: str) -> dict[str, tuple[TreeEntry, ...]] | None:
    content = local_git_bytes(repository, "ls-tree", "-z", tree)
    if content is None:
        return None
    entries: dict[str, list[TreeEntry]] = {}
    for record in content.split(b"\0"):
        if not record:
            continue
        metadata, separator, name = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            return None
        mode, object_type, raw_object = fields
        try:
            object_id = raw_object.decode("ascii")
        except UnicodeDecodeError:
            return None
        if not OBJECT_ID.fullmatch(object_id):
            return None
        kind = (
            "directory"
            if mode == b"040000" and object_type == b"tree"
            else "file"
            if mode in {b"100644", b"100755"} and object_type == b"blob"
            else "other"
        )
        decoded_name = os.fsdecode(name)
        entries.setdefault(normalized_path_component(decoded_name), []).append(
            (decoded_name, kind, object_id)
        )
    return {name: tuple(matches) for name, matches in entries.items()}


def tree_path(repository: Path, tree: str, value: str) -> TreeEntry | None:
    path = relative_path(value)
    if path is None:
        return None
    kind, object_id = "directory", tree
    for name in path.parts:
        if kind != "directory":
            return None
        aliases = (tree_entries(repository, object_id) or {}).get(
            normalized_path_component(name), ()
        )
        # The normalized name must be unique before an exact spelling can win.
        if len(aliases) != 1:
            return None
        entry = next((candidate for candidate in aliases if candidate[0] == name), None)
        if entry is None:
            return None
        _, kind, object_id = entry
    return path.as_posix(), kind, object_id


def target_tree(target: Path, revision: str) -> tuple[Path, str] | None:
    if not OBJECT_ID.fullmatch(revision):
        return None
    repository, prefix = git_worktree_context(target)
    if local_git_bytes(repository, "replace", "--list") != b"":
        return None
    raw_tree = local_git_bytes(
        repository,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{revision}^{{tree}}",
    )
    try:
        tree = raw_tree.decode("ascii").strip() if raw_tree is not None else ""
    except UnicodeDecodeError:
        return None
    if not OBJECT_ID.fullmatch(tree):
        return None
    if prefix == ".":
        return repository, tree
    selected = tree_path(repository, tree, prefix)
    if selected is None or selected[1] != "directory":
        return None
    return repository, selected[2]


def capture_source_scopes(
    target: Path,
    target_identity: tuple[str, str | None, int | str, int | str],
    paths: list[str],
    *,
    diff_target_kind: str | None = None,
) -> dict[str, Any]:
    revision, snapshot = target_identity[:2]
    authority: dict[str, Any] = {"version": 1, "revision": revision, "scopes": []}
    if (
        (diff_target_kind is not None and diff_target_kind not in {"commit", "range"})
        or revision == "unversioned"
        or (snapshot is not None and snapshot != clean_worktree_content_digest())
    ):
        return authority
    try:
        context = target_tree(target, revision)
        if context is None:
            return authority
        repository, tree = context
        authority["targetTree"] = tree
        captured: set[tuple[str, str, str]] = set()
        for requested in paths:
            parsed = relative_path(requested)
            selected_path = safe_source_path(target, requested)
            if parsed is None or selected_path is None:
                continue
            entry = tree_path(repository, tree, requested)
            if entry is None or entry[1] not in {"file", "directory"}:
                continue
            raw_selected = target / parsed.as_posix()
            try:
                metadata = raw_selected.lstat()
            except OSError:
                continue
            ordinary = stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
            if not ordinary or (entry[1] == "directory") != stat.S_ISDIR(
                metadata.st_mode
            ):
                continue
            scope = {
                "path": parsed.as_posix(),
                "kind": entry[1],
                "objectId": entry[2],
            }
            key = tuple(scope.values())
            if key not in captured:
                captured.add(key)
                authority["scopes"].append(scope)
    except (OSError, RuntimeError, SystemExit, UnicodeError, ValueError):
        return {"version": 1, "revision": revision, "scopes": []}
    return authority


def load_source_scopes(
    scan: sqlite3.Row, target: Path
) -> tuple[Path, tuple[SourceScope, ...]] | None:
    try:
        saved = scan["source_scopes_json"]
    except (IndexError, KeyError):
        return None
    if not isinstance(saved, str):
        return None
    metadata = json.loads(saved)
    tree = metadata.get("targetTree") if isinstance(metadata, dict) else None
    records = metadata.get("scopes") if isinstance(metadata, dict) else None
    if (
        not isinstance(metadata, dict)
        or metadata.get("version") != 1
        or metadata.get("revision") != scan["target_revision"]
        or not isinstance(tree, str)
        or not OBJECT_ID.fullmatch(tree)
        or not isinstance(records, list)
        or not records
    ):
        return None
    context = target_tree(target, scan["target_revision"])
    if context is None or context[1] != tree:
        return None
    repository, _ = context
    scopes: list[SourceScope] = []
    for record in records:
        if not isinstance(record, dict):
            return None
        path = record.get("path")
        kind = record.get("kind")
        object_id = record.get("objectId")
        requested_path = relative_path(path) if isinstance(path, str) else None
        if (
            requested_path is None
            or kind not in {"file", "directory"}
            or not isinstance(object_id, str)
            or not OBJECT_ID.fullmatch(object_id)
        ):
            return None
        scope = {
            "path": path,
            "kind": kind,
            "objectId": object_id,
        }
        if tree_path(repository, tree, path) != (path, kind, object_id):
            return None
        scopes.append(scope)
    return repository, tuple(scopes)


def source_object_for_path(
    repository: Path,
    target: Path,
    value: str,
    scope: SourceScope,
) -> str | None:
    path = relative_path(value)
    if path is None or safe_source_path(target, value) is None:
        return None
    scope_path = PurePosixPath(scope["path"])
    scope_length = len(scope_path.parts)
    if len(path.parts) < scope_length:
        return None
    if path.parts[:scope_length] != scope_path.parts:
        return None
    suffix = path.parts[scope_length:]
    if scope["kind"] == "file":
        return scope["objectId"] if not suffix else None
    if not suffix:
        return None
    entry = tree_path(
        repository,
        scope["objectId"],
        PurePosixPath(*suffix).as_posix(),
    )
    return entry[2] if entry is not None and entry[1] == "file" else None


def finding_source_excerpt(
    scan: sqlite3.Row,
    target: Path | None,
    locations: list[dict[str, Any]],
) -> str | None:
    if scan["mode"] == "diff" and scan["diff_target_kind"] not in {"commit", "range"}:
        return None
    if target is None or not locations or scan["target_revision"] == "unversioned":
        return None
    snapshot = scan["target_snapshot_digest"]
    if snapshot is not None and snapshot != clean_worktree_content_digest():
        return None
    try:
        context = load_source_scopes(scan, target)
    except (OSError, RuntimeError, SystemExit, UnicodeError, ValueError):
        return None
    if context is None:
        return None
    repository, scopes = context

    def priority(location: dict[str, Any]) -> int:
        role = location.get("role")
        if role == "root_control":
            return 0
        return 1 if "root_control" in str(role or "").lower() else 2

    selected_location = None
    object_id = None
    for location in sorted(locations, key=priority):
        path = location.get("path")
        if not isinstance(path, str) or not isinstance(location.get("startLine"), int):
            continue
        try:
            object_id = next(
                (
                    candidate
                    for scope in scopes
                    if (
                        candidate := source_object_for_path(
                            repository, target, path, scope
                        )
                    )
                    is not None
                ),
                None,
            )
        except (OSError, RuntimeError, SystemExit, UnicodeError, ValueError):
            object_id = None
        if object_id is not None:
            selected_location = location
            break
    if selected_location is None or object_id is None:
        return None
    source = scanned_source_text(repository, object_id)
    if not source or "\0" in source:
        return None
    start_line = selected_location["startLine"]
    lines = source.splitlines()
    if start_line < 1 or start_line > len(lines):
        return None
    end_line = selected_location.get("endLine")
    last_affected_line = end_line if isinstance(end_line, int) else start_line
    excerpt_start = max(1, start_line - CONTEXT_LINES)
    excerpt_end = min(
        len(lines),
        max(start_line, last_affected_line) + CONTEXT_LINES,
        excerpt_start + MAX_LINES - 1,
    )
    width = len(str(excerpt_end))
    excerpt = "\n".join(
        f"{line_number:>{width}}  {lines[line_number - 1]}"
        for line_number in range(excerpt_start, excerpt_end + 1)
    )
    return excerpt.encode("utf-8")[:MAX_BYTES].decode("utf-8", errors="ignore")


def scanned_source_text(repository: Path, object_id: str) -> str | None:
    try:
        content = local_git_bytes(repository, "cat-file", "blob", object_id)
    except (OSError, RuntimeError, SystemExit):
        return None
    return content.decode("utf-8", errors="replace") if content is not None else None


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
