"""Read bounded finding source excerpts from sealed Git revisions."""

from __future__ import annotations

import argparse
import codecs
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
LINE_BREAK = re.compile(r"\r\n|[\n\v\f\r\x1c-\x1e\x85\u2028\u2029]")

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
    requests: IO[bytes],
    responses: IO[bytes],
    object_id: str,
    name: str,
) -> TreeEntry | None:
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
    cursor = 0

    def read_more() -> None:
        nonlocal cursor, unread
        if cursor:
            del buffered[:cursor]
            cursor = 0
        chunk = responses.read(min(64 * 1024, unread))
        if not chunk:
            raise ValueError("truncated tree response")
        buffered.extend(chunk)
        unread -= len(chunk)

    def read_field(delimiter: int, maximum_bytes: int | None = None) -> bytearray:
        nonlocal cursor
        field = bytearray()
        while True:
            try:
                end = buffered.index(delimiter, cursor)
            except ValueError:
                available = len(buffered) - cursor
                if maximum_bytes is not None and len(field) + available > maximum_bytes:
                    raise ValueError("oversized tree field") from None
                field.extend(buffered[cursor:])
                cursor = len(buffered)
                if not unread:
                    raise ValueError("unterminated tree entry") from None
                read_more()
                continue
            if maximum_bytes is not None and len(field) + end - cursor > maximum_bytes:
                raise ValueError("oversized tree field")
            field.extend(buffered[cursor:end])
            cursor = end + 1
            return field

    def read_object_id(size: int) -> bytes:
        nonlocal cursor
        while len(buffered) - cursor < size:
            if not unread:
                raise ValueError("truncated tree entry")
            read_more()
        value = bytes(buffered[cursor : cursor + size])
        cursor += size
        return value

    object_id_bytes = len(object_id) // 2
    expected_name = normalized_path_component(name)
    selected = None
    ambiguous = False
    while cursor < len(buffered) or unread:
        mode = bytes(read_field(ord(" "), 6))
        decoded_name = read_field(0).decode(
            sys.getfilesystemencoding(), errors="surrogateescape"
        )
        entry_object = read_object_id(object_id_bytes)
        if not ambiguous and normalized_path_component(decoded_name) == expected_name:
            if selected is not None:
                selected = None
                ambiguous = True
            else:
                kind = (
                    "directory"
                    if mode in {b"40000", b"040000"}
                    else "file"
                    if mode in {b"100644", b"100755"}
                    else "other"
                )
                selected = (decoded_name, kind, entry_object.hex())
    if responses.read(1) != b"\n":
        raise ValueError("missing tree terminator")
    return selected


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
                    process.stdin,
                    process.stdout,
                    object_id,
                    name,
                )
                # The normalized name must be unique before an exact spelling can win.
                if aliases is None or aliases[0] != name:
                    return None
                _, kind, object_id = aliases
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


def replacement_refs_absent(repository: Path) -> bool:
    replacement_ref_base = os.environ.get("GIT_REPLACE_REF_BASE", "refs/replace/")
    environment = os.environ.copy()
    for variable in GIT_REPOSITORY_ENVIRONMENT:
        environment.pop(variable, None)
    environment["GIT_ALLOW_PROTOCOL"] = ""
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    git_command = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "i18n.logOutputEncoding=UTF-8",
        "-C",
        str(repository),
        "--no-replace-objects",
    ]
    try:
        if (
            subprocess.run(
                [
                    *git_command,
                    "check-ref-format",
                    f"{replacement_ref_base}{'0' * 64}",
                ],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            != 0
        ):
            return False
        command = [
            *git_command,
            "for-each-ref",
            "--count=1",
            "--format=",
            f"{replacement_ref_base}*",
        ]
        with subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as process:
            if process.stdout is None:
                return False
            if process.stdout.read(1):
                if process.poll() is None:
                    process.kill()
                return False
            return process.wait() == 0
    except (MemoryError, OSError):
        return False


def target_tree(target: Path, revision: str) -> tuple[Path, str] | None:
    if not isinstance(revision, str) or not OBJECT_ID.fullmatch(revision):
        return None
    repository, prefix = git_worktree_context(target)
    if not replacement_refs_absent(repository):
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
            if parsed is None or safe_source_path(target, requested) is None:
                continue
            try:
                raw_selected = target
                components = parsed.parts
                if not components:
                    metadata = raw_selected.lstat()
                for index, component in enumerate(components):
                    raw_selected /= component
                    metadata = raw_selected.lstat()
                    if (
                        stat.S_ISLNK(metadata.st_mode)
                        or getattr(metadata, "st_reparse_tag", 0) & 0x20000000
                        or (
                            index < len(components) - 1
                            and not stat.S_ISDIR(metadata.st_mode)
                        )
                    ):
                        metadata = None
                        break
            except OSError:
                continue
            if metadata is None:
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
        if object_id is None:
            return None
        end_line = location.get("endLine")
        last_affected_line = end_line if isinstance(end_line, int) else start_line
        return scanned_source_excerpt(
            repository,
            object_id,
            start_line,
            last_affected_line,
        )
    except (
        MemoryError,
        OSError,
        RuntimeError,
        SystemExit,
        UnicodeError,
        ValueError,
    ):
        return None


def scanned_source_excerpt(
    repository: Path,
    object_id: str,
    start_line: int,
    last_affected_line: int,
) -> str | None:
    if start_line < 1 or OBJECT_ID.fullmatch(object_id) is None:
        return None
    excerpt_start = max(1, start_line - CONTEXT_LINES)
    excerpt_limit = min(
        max(start_line, last_affected_line) + CONTEXT_LINES,
        excerpt_start + MAX_LINES - 1,
    )

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
        "blob",
        object_id,
    ]

    captured_lines: list[tuple[int, str]] = []
    fragments: list[str] = []
    captured_bytes = 0
    line_number = 1
    last_line = 0
    line_has_content = False
    pending_carriage_return = False

    def capture(value: str) -> None:
        nonlocal captured_bytes, line_has_content
        if not value:
            return
        line_has_content = True
        if (
            line_number < excerpt_start
            or line_number > excerpt_limit
            or captured_bytes >= MAX_BYTES
        ):
            return
        remaining = MAX_BYTES - captured_bytes
        selected = value.encode("utf-8")[:remaining]
        fragments.append(selected.decode("utf-8", errors="ignore"))
        captured_bytes += len(selected)

    def finish_line() -> None:
        nonlocal fragments, last_line, line_has_content, line_number
        if excerpt_start <= line_number <= excerpt_limit:
            captured_lines.append((line_number, "".join(fragments)))
        last_line = line_number
        line_number += 1
        fragments = []
        line_has_content = False

    def consume(value: str, *, final: bool = False) -> None:
        nonlocal pending_carriage_return
        if pending_carriage_return:
            value = "\r" + value
            pending_carriage_return = False
        if not final and value.endswith("\r"):
            value = value[:-1]
            pending_carriage_return = True
        cursor = 0
        for match in LINE_BREAK.finditer(value):
            capture(value[cursor : match.start()])
            finish_line()
            cursor = match.end()
        capture(value[cursor:])

    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    invalid = False
    with subprocess.Popen(
        command,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        if process.stdout is None:
            return None
        while chunk := process.stdout.read(64 * 1024):
            if b"\0" in chunk:
                invalid = True
            if not invalid:
                consume(decoder.decode(chunk))
        if not invalid:
            consume(decoder.decode(b"", final=True), final=True)
            if line_has_content:
                finish_line()
        if process.wait() != 0:
            return None

    if invalid or last_line < start_line or not captured_lines:
        return None
    width = len(str(captured_lines[-1][0]))
    excerpt = "\n".join(
        f"{number:>{width}}  {line}" for number, line in captured_lines
    )
    return excerpt.encode("utf-8")[:MAX_BYTES].decode("utf-8", errors="ignore")


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
