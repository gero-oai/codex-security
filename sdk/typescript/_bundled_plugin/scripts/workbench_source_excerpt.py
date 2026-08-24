"""Read bounded finding source excerpts from sealed Git revisions."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, Any
from unicodedata import normalize

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_constants import GIT_REPOSITORY_ENVIRONMENT
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


@dataclass
class SourceScopeIndex:
    kind: str | None = None
    children: dict[str, SourceScopeIndex] = field(default_factory=dict)


SourceContext = tuple[Path, str, SourceScopeIndex]


def normalized_path_component(value: str) -> str:
    return normalize("NFC", normalize("NFD", value).casefold()).rstrip(" .")


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


def matching_tree_entries(
    requests: IO[bytes], responses: IO[bytes], object_id: str, name: str
) -> tuple[TreeEntry, ...]:
    encoded_object = object_id.encode("ascii")
    requests.write(encoded_object + b"\0")
    requests.flush()
    header = responses.readline()
    if not header.endswith(b"\n"):
        raise ValueError("unterminated batch header")
    fields = header[:-1].split(b" ")
    if (
        len(fields) != 3
        or fields[0] != encoded_object
        or fields[1] != b"tree"
        or not fields[2].isdigit()
    ):
        raise ValueError("invalid tree response")
    unread = int(fields[2])
    buffered = bytearray()

    def read_more() -> None:
        nonlocal unread
        chunk = responses.read(min(64 * 1024, unread))
        if not chunk:
            raise ValueError("truncated tree response")
        buffered.extend(chunk)
        unread -= len(chunk)

    def read_field(delimiter: int) -> bytearray:
        field = bytearray()
        while True:
            try:
                end = buffered.index(delimiter)
            except ValueError:
                field.extend(buffered)
                buffered.clear()
                if not unread:
                    raise ValueError("unterminated tree entry") from None
                read_more()
                continue
            field.extend(buffered[:end])
            del buffered[: end + 1]
            return field

    def read_object_id(size: int) -> bytes:
        while len(buffered) < size:
            if not unread:
                raise ValueError("truncated tree entry")
            read_more()
        value = bytes(buffered[:size])
        del buffered[:size]
        return value

    object_id_bytes = len(object_id) // 2
    expected_name = normalized_path_component(name)
    matches = []
    while buffered or unread:
        mode = bytes(read_field(ord(" ")))
        decoded_name = read_field(0).decode(
            sys.getfilesystemencoding(), errors="surrogateescape"
        )
        entry_object = read_object_id(object_id_bytes).hex()
        kind = (
            "directory"
            if mode in {b"40000", b"040000"}
            else "file"
            if mode in {b"100644", b"100755"}
            else "other"
        )
        if normalized_path_component(decoded_name) == expected_name:
            matches.append((decoded_name, kind, entry_object))
    if responses.read(1) != b"\n":
        raise ValueError("missing tree terminator")
    return tuple(matches)


def tree_path(
    repository: Path,
    tree: str,
    value: str,
    *,
    selected_kinds: dict[int, str] | None = None,
) -> TreeEntry | None:
    path = relative_path(value)
    if path is None:
        return None
    if selected_kinds is not None and selected_kinds.get(0, "directory") != "directory":
        return None
    kind, object_id = "directory", tree
    if not path.parts:
        return path.as_posix(), kind, object_id

    environment = os.environ.copy()
    for variable in GIT_REPOSITORY_ENVIRONMENT:
        environment.pop(variable, None)
    environment["GIT_ALLOW_PROTOCOL"] = ""
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    command = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "i18n.logOutputEncoding=UTF-8",
        "-C",
        str(repository),
        "--no-replace-objects",
        "cat-file",
        "--batch",
        "-z",
    ]
    try:
        with subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as process:
            if process.stdin is None or process.stdout is None:
                return None
            for depth, name in enumerate(path.parts, start=1):
                if kind != "directory":
                    return None
                aliases = matching_tree_entries(
                    process.stdin, process.stdout, object_id, name
                )
                # The normalized name must be unique before an exact spelling can win.
                if len(aliases) != 1:
                    return None
                entry = next(
                    (candidate for candidate in aliases if candidate[0] == name),
                    None,
                )
                if entry is None:
                    return None
                _, kind, object_id = entry
                if (
                    selected_kinds is not None
                    and (expected_kind := selected_kinds.get(depth)) is not None
                    and kind != expected_kind
                ):
                    return None
            process.stdin.close()
            if process.wait() != 0:
                return None
    except (MemoryError, OSError, ValueError):
        return None
    return path.as_posix(), kind, object_id


def target_tree(target: Path, revision: str) -> tuple[Path, str] | None:
    if not isinstance(revision, str) or not OBJECT_ID.fullmatch(revision):
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
    authority: dict[str, Any] = {"version": 1, "paths": []}
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
        _, tree = context
        authority["targetTree"] = tree
        captured: set[str] = set()
        for requested in paths:
            parsed = relative_path(requested)
            selected_path = safe_source_path(target, requested)
            if parsed is None or selected_path is None:
                continue
            raw_selected = target / parsed.as_posix()
            try:
                metadata = raw_selected.lstat()
            except OSError:
                continue
            kind = (
                "directory"
                if stat.S_ISDIR(metadata.st_mode)
                else "file"
                if stat.S_ISREG(metadata.st_mode)
                else None
            )
            if kind is None:
                continue
            selected = parsed.as_posix()
            if selected not in captured:
                captured.add(selected)
                authority["paths"].append({"kind": kind, "path": selected})
    except (OSError, RuntimeError, SystemExit, UnicodeError, ValueError):
        return {"version": 1, "paths": []}
    return authority


def load_source_scopes(
    scan: sqlite3.Row, target: Path, selected_paths: list[str]
) -> SourceContext | None:
    try:
        saved = scan["source_scopes_json"]
    except (IndexError, KeyError):
        return None
    if not isinstance(saved, str):
        return None
    metadata = json.loads(saved)
    records = metadata.get("paths") if isinstance(metadata, dict) else None
    expected_tree = metadata.get("targetTree") if isinstance(metadata, dict) else None
    if (
        not isinstance(metadata, dict)
        or metadata.get("version") != 1
        or not isinstance(records, list)
        or not records
        or not isinstance(expected_tree, str)
        or not OBJECT_ID.fullmatch(expected_tree)
    ):
        return None
    expected = {
        parsed.as_posix()
        for value in selected_paths
        if (parsed := relative_path(value)) is not None
    }
    if not expected:
        return None
    context = target_tree(target, scan["target_revision"])
    if context is None:
        return None
    repository, tree = context
    if tree != expected_tree:
        return None
    index = SourceScopeIndex()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"kind", "path"}:
            return None
        kind = record.get("kind")
        saved_path = record.get("path")
        path = relative_path(saved_path) if isinstance(saved_path, str) else None
        if path is None:
            return None
        selected = path.as_posix()
        if (
            kind not in {"directory", "file"}
            or selected != saved_path
            or selected not in expected
        ):
            return None
        node = index
        for component in path.parts:
            node = node.children.setdefault(component, SourceScopeIndex())
        if node.kind is not None:
            return None
        node.kind = kind
    return repository, tree, index


def selected_source_kinds(
    index: SourceScopeIndex, value: str
) -> dict[int, str] | None:
    path = relative_path(value)
    if path is None:
        return None
    node = index
    kinds = {0: node.kind} if node.kind is not None else {}
    authorized = node.kind == "directory"
    for depth, component in enumerate(path.parts, start=1):
        child = node.children.get(component)
        if child is None:
            return kinds if authorized else None
        node = child
        if node.kind is not None:
            kinds[depth] = node.kind
        if node.kind == "directory" or (
            node.kind == "file" and depth == len(path.parts)
        ):
            authorized = True
    return kinds if authorized else None


def source_excerpt_context(
    scan: sqlite3.Row,
    target: Path,
    selected_paths: list[str],
) -> SourceContext | None:
    if scan["mode"] == "diff" and scan["diff_target_kind"] not in {"commit", "range"}:
        return None
    if scan["target_revision"] == "unversioned":
        return None
    snapshot = scan["target_snapshot_digest"]
    if snapshot is not None and snapshot != clean_worktree_content_digest():
        return None
    try:
        context = load_source_scopes(scan, target, selected_paths)
    except (OSError, RuntimeError, SystemExit, UnicodeError, ValueError):
        return None
    return context


def finding_source_excerpt_from_context(
    context: SourceContext | None,
    locations: list[dict[str, Any]],
) -> str | None:
    if context is None or not locations:
        return None
    repository, tree, scopes = context

    location = locations[0]
    path = location.get("path")
    start_line = location.get("startLine")
    if not isinstance(path, str) or not isinstance(start_line, int):
        return None
    try:
        selected_kinds = selected_source_kinds(scopes, path)
        selected = (
            tree_path(repository, tree, path, selected_kinds=selected_kinds)
            if selected_kinds is not None
            else None
        )
        object_id = (
            selected[2]
            if selected is not None and selected[1] == "file"
            else None
        )
    except (OSError, RuntimeError, SystemExit, UnicodeError, ValueError):
        return None
    if object_id is None:
        return None
    source = scanned_source_text(repository, object_id)
    if not source or "\0" in source:
        return None
    lines = source.splitlines()
    if start_line < 1 or start_line > len(lines):
        return None
    end_line = location.get("endLine")
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
