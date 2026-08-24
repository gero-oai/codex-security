"""Target inspection and content-integrity helpers for the security workbench."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import IO, Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_identity import stored_filesystem_identity_matches
from workbench_constants import (
    EMPTY_GIT_TREES,
    GIT_REPOSITORY_ENVIRONMENT,
)


def git_output(
    target: Path,
    *args: str,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
    local_objects_only: bool = False,
    object_directory: Path | None = None,
) -> str | None:
    completed = git_command(
        target,
        *args,
        text=False,
        git_dir=git_dir,
        work_tree=work_tree,
        local_objects_only=local_objects_only,
        object_directory=object_directory,
    )
    output = os.fsdecode(completed.stdout).strip()
    return output if completed.returncode == 0 and output else None


def git_bytes(
    target: Path,
    *args: str,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
    local_objects_only: bool = False,
) -> bytes | None:
    completed = git_command(
        target,
        *args,
        text=False,
        git_dir=git_dir,
        work_tree=work_tree,
        local_objects_only=local_objects_only,
    )
    return completed.stdout if completed.returncode == 0 else None


def read_stream_nul_field(stream: IO[bytes]) -> bytes | None:
    """Read one NUL-terminated field, returning ``None`` only at clean EOF."""
    field = bytearray()
    while character := stream.read(1):
        if character == b"\0":
            return bytes(field)
        field.extend(character)
    if field:
        raise ValueError("missing NUL terminator")
    return None


def write_committed_diff_object_requests(
    metadata: IO[bytes],
    requests: IO[bytes],
) -> None:
    """Write ordered changed-blob requests from NUL-framed raw diff records."""
    seen: set[bytes] = set()
    while (header := read_stream_nul_field(metadata)) is not None:
        if not header or not read_stream_nul_field(metadata):
            raise ValueError("invalid raw Git diff record")
        fields = header.split()
        if len(fields) != 5 or not fields[0].startswith(b":"):
            raise ValueError("invalid raw Git diff record")
        for mode, object_name in (
            (fields[0][1:], fields[2]),
            (fields[1], fields[3]),
        ):
            if mode in {b"000000", b"160000"}:
                continue
            if (
                len(object_name) not in {40, 64}
                or any(
                    character not in b"0123456789abcdef"
                    for character in object_name
                )
            ):
                raise ValueError("invalid raw Git diff record")
            if object_name in seen:
                continue
            seen.add(object_name)
            requests.write(object_name + b"\0")


def validate_git_batch_blob_stream(
    requests: IO[bytes],
    output: IO[bytes],
) -> None:
    """Require one exact, ordered blob response for every object request."""
    while (expected_object := read_stream_nul_field(requests)) is not None:
        if not expected_object:
            raise ValueError("invalid empty object request")
        if _read_git_batch_blob(output, expected_object, require_object_match=True) is None:
            raise ValueError("missing batch object")
    if output.read(1):
        raise ValueError("unexpected batch response")


def _read_git_batch_blob(
    output: IO[bytes],
    expected_request: bytes,
    *,
    require_object_match: bool,
    collect: bool = False,
) -> bytes | None:
    """Read one strict newline-framed response for a NUL-terminated request."""
    start = output.tell()
    missing = expected_request + b" missing\n"
    if output.read(len(missing)) == missing:
        return None
    output.seek(start)
    header = output.readline()
    if not header.endswith(b"\n"):
        raise ValueError("unterminated batch header")
    fields = header[:-1].split(b" ")
    if (
        len(fields) != 3
        or len(fields[0]) not in {40, 64}
        or any(character not in b"0123456789abcdef" for character in fields[0])
        or (require_object_match and fields[0] != expected_request)
        or fields[1] != b"blob"
        or not fields[2].isdigit()
    ):
        raise ValueError("invalid batch response")
    remaining = int(fields[2])
    chunks: list[bytes] = []
    while remaining:
        chunk = output.read(min(1024 * 1024, remaining))
        if not chunk:
            raise ValueError("truncated blob response")
        if collect:
            chunks.append(chunk)
        remaining -= len(chunk)
    if output.read(1) != b"\n":
        raise ValueError("missing blob terminator")
    return b"".join(chunks)


def git_blob_bytes(
    target: Path,
    object_names: list[str],
    *,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> list[bytes | None]:
    """Read ordered raw blobs with one NUL-request ``git cat-file --batch`` call."""
    if not object_names:
        return []

    encoded_names = [os.fsencode(name) for name in object_names]
    request = b"\0".join(encoded_names) + b"\0"
    completed = git_command(
        target,
        "cat-file",
        "--batch",
        "-z",
        text=False,
        input_data=request,
        git_dir=git_dir,
        work_tree=work_tree,
        local_objects_only=True,
    )
    if completed.returncode != 0:
        return [None] * len(object_names)

    try:
        return _decode_git_batch_blobs(completed.stdout, encoded_names)
    except ValueError:
        return [None] * len(object_names)


def _decode_git_batch_blobs(
    output: bytes,
    expected_requests: list[bytes],
) -> list[bytes | None]:
    """Decode exactly one strict newline-framed response per ordered request."""
    stream = io.BytesIO(output)
    blobs = [
        _read_git_batch_blob(stream, request, require_object_match=False, collect=True)
        for request in expected_requests
    ]
    if stream.read(1):
        raise ValueError("unexpected batch response")
    return blobs


def git_command(
    target: Path,
    *args: str,
    text: bool,
    input_data: str | bytes | None = None,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
    stdin: IO[bytes] | None = None,
    stdout: IO[bytes] | None = None,
    local_objects_only: bool = False,
    object_directory: Path | None = None,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    if (git_dir is None) != (work_tree is None):
        raise ValueError("git_dir and work_tree must be provided together")
    environment = os.environ.copy()
    for name in GIT_REPOSITORY_ENVIRONMENT:
        environment.pop(name, None)
    if object_directory is not None:
        environment["GIT_OBJECT_DIRECTORY"] = os.fspath(object_directory)
    if local_objects_only:
        environment["GIT_ALLOW_PROTOCOL"] = ""
        environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    # Repository-local config is untrusted; fsmonitor may name an executable hook.
    command = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "i18n.logOutputEncoding=UTF-8",
        "-C",
        str(target),
    ]
    if git_dir is not None and work_tree is not None:
        command.extend(["--git-dir", str(git_dir), "--work-tree", str(work_tree)])
    full_command = [*command, *args]
    try:
        return subprocess.run(
            full_command,
            check=False,
            stdin=stdin,
            stdout=subprocess.PIPE if stdout is None else stdout,
            stderr=subprocess.PIPE,
            env=environment,
            text=text,
            encoding="utf-8" if text else None,
            errors="surrogateescape" if text else None,
            input=input_data,
        )
    except FileNotFoundError:
        # Git is optional for Codebase scans. Treat an unavailable executable like
        # any other failed Git probe so the target falls back to a directory snapshot.
        empty_output = "" if text else b""
        return subprocess.CompletedProcess(full_command, 127, empty_output, empty_output)


def update_digest_field(digest: Any, label: bytes, value: bytes) -> None:
    digest.update(len(label).to_bytes(4, "big"))
    digest.update(label)
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def update_digest_stream_field(digest: Any, label: bytes, stream: IO[bytes]) -> None:
    """Hash a length-framed stream without loading it into memory."""
    digest.update(len(label).to_bytes(4, "big"))
    digest.update(label)
    digest.update(os.fstat(stream.fileno()).st_size.to_bytes(8, "big"))
    stream.seek(0)
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)


def worktree_content_digest(target: Path) -> str:
    require_clean_submodule_worktrees(target)
    repository, pathspec = git_worktree_context(target)
    return worktree_content_digest_for_context(repository, pathspec)


def empty_git_tree(target: Path) -> str:
    object_format = git_output(target, "rev-parse", "--show-object-format")
    return EMPTY_GIT_TREES.get(object_format or "", EMPTY_GIT_TREES["sha1"])


def _replacement_refs(
    repository: Path,
    *,
    object_id_length: int,
    object_directory: Path | None = None,
) -> bytes:
    replacement_ref_base = os.fsencode(
        os.environ.get("GIT_REPLACE_REF_BASE", "refs/replace/")
    )
    replacements = git_command(
        repository,
        "for-each-ref",
        "--sort=refname",
        "--format=%(refname)%00%(objectname)",
        text=False,
        local_objects_only=True,
        object_directory=object_directory,
    )
    if replacements.returncode != 0:
        raise SystemExit("Could not inspect the selected committed changes.")
    selected = bytearray()
    for record in replacements.stdout.splitlines():
        fields = record.split(b"\0")
        if len(fields) != 2:
            raise SystemExit("Could not inspect the selected committed changes.")
        if not fields[0].startswith(replacement_ref_base):
            continue
        original_object_id = fields[0][len(replacement_ref_base) :].rsplit(b"/", 1)[-1]
        if (
            len(original_object_id) != object_id_length
            or any(
                character not in b"0123456789abcdefABCDEF"
                for character in original_object_id
            )
        ):
            continue
        selected.extend(record)
        selected.extend(b"\n")
    return bytes(selected)


def _replacement_refs_enabled(
    repository: Path,
    *,
    object_directory: Path | None = None,
) -> bool:
    if "GIT_NO_REPLACE_OBJECTS" in os.environ:
        return False
    configured = git_command(
        repository,
        "config",
        "--bool",
        "--get",
        "core.useReplaceRefs",
        text=False,
        local_objects_only=True,
        object_directory=object_directory,
    )
    value = configured.stdout.strip()
    if configured.returncode == 1 and not value:
        return True
    if configured.returncode == 0 and value in {b"true", b"false"}:
        return value == b"true"
    raise SystemExit("Could not inspect the selected committed changes.")


def _create_committed_diff_view(repository: Path, view: Path) -> Path:
    object_format = git_output(
        repository,
        "rev-parse",
        "--show-object-format",
        local_objects_only=True,
    )
    object_directory_value = git_output(
        repository,
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "objects",
        local_objects_only=True,
    )
    if object_format not in {"sha1", "sha256"} or object_directory_value is None:
        raise SystemExit("Could not snapshot the selected committed changes.")
    object_directory = Path(object_directory_value)
    if not object_directory.is_dir():
        raise SystemExit("Could not snapshot the selected committed changes.")

    object_id_length = 40 if object_format == "sha1" else 64
    replacements = _replacement_refs(
        repository,
        object_id_length=object_id_length,
    )
    replacements_enabled = _replacement_refs_enabled(repository)
    parsed_replacements: list[tuple[list[str], bytes]] = []
    for record in replacements.splitlines():
        fields = record.split(b"\0")
        if (
            len(fields) != 2
            or len(fields[1]) != object_id_length
            or any(character not in b"0123456789abcdef" for character in fields[1])
        ):
            raise SystemExit("Could not snapshot the selected committed changes.")
        refname = os.fsdecode(fields[0])
        parts = refname.split("/")
        if (
            len(parts) < 2
            or parts[0] != "refs"
            or "\\" in refname
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise SystemExit("Could not snapshot the selected committed changes.")
        parsed_replacements.append((parts, fields[1]))

    try:
        view.mkdir(mode=0o700)
        (view / "objects" / "info").mkdir(parents=True)
        (view / "objects" / "pack").mkdir()
        (view / "refs" / "heads").mkdir(parents=True)
        repository_format_version = 0 if object_format == "sha1" else 1
        config = (
            (
                b"[extensions]\n\tobjectformat = sha256\n"
                if object_format == "sha256"
                else b""
            )
            + b"[core]\n\trepositoryformatversion = "
            + str(repository_format_version).encode("ascii")
            + b"\n\tfilemode = false\n\tbare = true\n\tuseReplaceRefs = "
            + (b"true" if replacements_enabled else b"false")
            + b"\n"
        )
        (view / "config").write_bytes(config)
        (view / "HEAD").write_bytes(b"ref: refs/heads/codex-security-snapshot\n")
        for parts, object_id in parsed_replacements:
            ref = view.joinpath(*parts)
            ref.parent.mkdir(parents=True, exist_ok=True)
            ref.write_bytes(object_id + b"\n")
    except OSError as exc:
        raise SystemExit("Could not snapshot the selected committed changes.") from exc
    return object_directory


def committed_diff_content_snapshot(
    target: Path,
    base: str,
    head: str,
) -> tuple[str, str]:
    """Return a digest and identity from one frozen replacement view."""
    repository, pathspec = git_worktree_context(target)
    configured_state = os.environ.get("CODEX_SECURITY_STATE_DIR")
    if configured_state:
        state_directory = Path(configured_state).expanduser().resolve()
        state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="codex-security-committed-view-",
            dir=state_directory,
        ) as directory:
            return _committed_diff_content_snapshot(
                repository,
                pathspec,
                base,
                head,
                Path(directory),
            )
    with tempfile.TemporaryDirectory(prefix="codex-security-committed-diff-") as directory:
        return _committed_diff_content_snapshot(
            repository,
            pathspec,
            base,
            head,
            Path(directory),
        )


def committed_diff_content_digest(target: Path, base: str, head: str) -> str:
    """Bind normalized committed-diff metadata to every changed blob byte."""
    return committed_diff_content_snapshot(target, base, head)[0]


def _committed_diff_object_identity(
    repository: Path,
    pathspec: str,
    base: str,
    head: str,
    *,
    object_directory: Path | None = None,
) -> str:
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-committed-objects/v1")
    update_digest_field(
        digest,
        b"pathspec",
        pathspec.encode("utf-8", errors="surrogateescape"),
    )
    for label, revision in ((b"base", base), (b"head", head)):
        if revision in EMPTY_GIT_TREES.values():
            tree = revision
        else:
            tree = git_output(
                repository,
                "rev-parse",
                "--verify",
                "--end-of-options",
                f"{revision}^{{tree}}",
                local_objects_only=True,
                object_directory=object_directory,
            )
            if tree is None:
                raise SystemExit("Could not inspect the selected committed changes.")
        update_digest_field(digest, label, os.fsencode(revision))
        update_digest_field(digest, label + b"-tree", os.fsencode(tree))

    replacement_ref_base = os.environ.get("GIT_REPLACE_REF_BASE", "refs/replace/")
    object_format = git_output(
        repository,
        "rev-parse",
        "--show-object-format",
        local_objects_only=True,
        object_directory=object_directory,
    )
    if object_format not in {"sha1", "sha256"}:
        raise SystemExit("Could not inspect the selected committed changes.")
    replacements_enabled = _replacement_refs_enabled(
        repository,
        object_directory=object_directory,
    )
    replacements = _replacement_refs(
        repository,
        object_id_length=40 if object_format == "sha1" else 64,
        object_directory=object_directory,
    )
    update_digest_field(
        digest,
        b"replacement-ref-base",
        os.fsencode(replacement_ref_base),
    )
    update_digest_field(
        digest,
        b"replacement-objects-disabled",
        os.fsencode(os.environ.get("GIT_NO_REPLACE_OBJECTS", "")),
    )
    update_digest_field(
        digest,
        b"replacement-refs-enabled",
        b"true" if replacements_enabled else b"false",
    )
    update_digest_field(digest, b"replacement-refs", replacements)
    return f"codex-security-committed-objects/v1:sha256:{digest.hexdigest()}"


def committed_diff_object_identity(target: Path, base: str, head: str) -> str:
    """Bind immutable commit trees to the replacement view used by Git."""
    repository, pathspec = git_worktree_context(target)
    return _committed_diff_object_identity(repository, pathspec, base, head)


def _committed_diff_content_snapshot(
    repository: Path,
    pathspec: str,
    base: str,
    head: str,
    operation_directory: Path,
) -> tuple[str, str]:
    view = operation_directory / "repository.git"
    object_directory = _create_committed_diff_view(repository, view)
    before = _committed_diff_object_identity(
        view,
        pathspec,
        base,
        head,
        object_directory=object_directory,
    )
    content_digest = _committed_diff_content_digest(
        view,
        pathspec,
        base,
        head,
        operation_directory,
        object_directory=object_directory,
    )
    after = _committed_diff_object_identity(
        view,
        pathspec,
        base,
        head,
        object_directory=object_directory,
    )
    if before != after:
        raise SystemExit("Could not snapshot the selected committed changes.")
    return content_digest, after


def _committed_diff_content_digest(
    repository: Path,
    pathspec: str,
    base: str,
    head: str,
    state_directory: Path,
    *,
    object_directory: Path | None = None,
) -> str:
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-snapshot/v1")
    with (
        tempfile.TemporaryFile(dir=state_directory) as metadata,
        tempfile.TemporaryFile(dir=state_directory) as requests,
        tempfile.TemporaryFile(dir=state_directory) as objects,
    ):
        diff = git_command(
            repository,
            "-c",
            f"diff.orderFile={os.devnull}",
            "diff",
            "--raw",
            "-z",
            "--no-abbrev",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-relative",
            "--no-renames",
            "--ignore-submodules=none",
            base,
            head,
            "--",
            pathspec,
            text=False,
            stdout=metadata,
            local_objects_only=True,
            object_directory=object_directory,
        )
        if diff.returncode != 0:
            raise SystemExit("Could not snapshot the selected committed changes.")
        metadata.seek(0)
        try:
            write_committed_diff_object_requests(metadata, requests)
        except ValueError as exc:
            raise SystemExit("Could not snapshot the selected committed changes.") from exc
        update_digest_stream_field(digest, b"tracked-diff", metadata)

        requests.seek(0, os.SEEK_END)
        if requests.tell():
            requests.seek(0)
            batch = git_command(
                repository,
                "cat-file",
                "--batch",
                "-z",
                text=False,
                stdin=requests,
                stdout=objects,
                local_objects_only=True,
                object_directory=object_directory,
            )
            if batch.returncode != 0:
                raise SystemExit("Could not snapshot the selected committed changes.")
        requests.seek(0)
        objects.seek(0)
        try:
            validate_git_batch_blob_stream(requests, objects)
        except ValueError as exc:
            raise SystemExit("Could not snapshot the selected committed changes.") from exc
        update_digest_stream_field(digest, b"tracked-objects", objects)
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def remediation_checkout_snapshot(
    scan: sqlite3.Row, *, expected_revision: str | None = None
) -> tuple[str, str | None]:
    target = require_scan_target_identity(scan)
    revision = git_revision(target)
    required_revision = expected_revision or scan["target_revision"]
    if revision != required_revision:
        raise SystemExit(
            "Repository HEAD changed. Regenerate the remediation patch against the current checkout."
        )
    content_digest = (
        worktree_content_digest(target)
        if revision != "unversioned"
        else directory_content_digest(target, excluded=(Path(scan["scan_dir"]),))
    )
    return revision, content_digest


def worktree_content_digest_for_context(
    repository: Path,
    pathspec: str,
    *,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> str:
    tracked = git_bytes(
        repository,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "HEAD",
        "--",
        pathspec,
        git_dir=git_dir,
        work_tree=work_tree,
    )
    untracked = git_bytes(
        repository,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        pathspec,
        git_dir=git_dir,
        work_tree=work_tree,
    )
    if tracked is None or untracked is None:
        raise SystemExit("Could not snapshot the selected working-tree changes.")
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-snapshot/v1")
    update_digest_field(digest, b"tracked-diff", tracked)
    for raw_path in sorted(path for path in untracked.split(b"\0") if path):
        relative_path = os.fsdecode(raw_path)
        path = (work_tree or repository) / relative_path
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not read untracked file: {relative_path}") from exc
        update_digest_field(digest, b"untracked-path", raw_path)
        update_digest_field(
            digest,
            b"untracked-mode",
            str(stat.S_IMODE(metadata.st_mode)).encode(),
        )
        if stat.S_ISLNK(metadata.st_mode):
            update_digest_field(digest, b"untracked-kind", b"symlink")
            update_digest_field(
                digest,
                b"untracked-content",
                os.fsencode(os.readlink(path)),
            )
        elif stat.S_ISDIR(metadata.st_mode):
            update_digest_field(digest, b"untracked-kind", b"directory")
            update_digest_field(
                digest,
                b"untracked-content",
                directory_content_digest(path.resolve()).encode(),
            )
        elif stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256()
            content_size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        content_size += len(chunk)
            except OSError as exc:
                raise SystemExit(f"Could not read untracked file: {relative_path}") from exc
            update_digest_field(digest, b"untracked-kind", b"file")
            update_digest_field(
                digest,
                b"untracked-size",
                str(content_size).encode(),
            )
            update_digest_field(
                digest,
                b"untracked-content-sha256",
                content_digest.digest(),
            )
        else:
            raise SystemExit(f"Unsupported untracked file type: {relative_path}")
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def git_worktree_context(target: Path) -> tuple[Path, str]:
    root = git_output(target, "rev-parse", "--show-toplevel")
    if root is None:
        raise SystemExit("Could not inspect the selected Git working tree.")
    repository = Path(root).resolve()
    try:
        relative = target.resolve().relative_to(repository)
    except ValueError as exc:
        raise SystemExit("Scan target must stay inside its Git working tree.") from exc
    return repository, relative.as_posix() or "."


def git_submodule_entries(target: Path) -> tuple[tuple[Path, str], ...]:
    repository, pathspec = git_worktree_context(target)
    staged = git_bytes(repository, "ls-files", "--stage", "-z", "--", pathspec)
    if staged is None:
        raise SystemExit("Could not inspect Git submodules in the selected working tree.")
    entries = []
    for record in (item for item in staged.split(b"\0") if item):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, _ = metadata.split(b" ", 2)
        except ValueError as exc:
            raise SystemExit(
                "Could not inspect Git submodules in the selected working tree."
            ) from exc
        if mode != b"160000":
            continue
        entries.append((repository / os.fsdecode(raw_path), object_id.decode("ascii")))
    return tuple(entries)


def git_submodule_paths(target: Path) -> tuple[Path, ...]:
    return tuple(path for path, _ in git_submodule_entries(target))


def require_clean_submodule_worktrees(target: Path) -> None:
    for submodule, expected_revision in git_submodule_entries(target):
        relative_path = str(submodule.relative_to(target))
        if not submodule.exists():
            continue
        try:
            (submodule / ".git").lstat()
        except FileNotFoundError:
            continue
        root = git_output(submodule, "rev-parse", "--show-toplevel")
        try:
            is_initialized = root is not None and Path(root).resolve() == submodule.resolve()
        except OSError:
            is_initialized = False
        if not is_initialized:
            raise SystemExit(
                f"Could not inspect initialized Git submodule contents: {relative_path}"
            )
        if git_output(submodule, "rev-parse", "HEAD") != expected_revision:
            raise SystemExit(
                "Initialized Git submodules must be checked out at the revision recorded "
                f"by the parent repository: {relative_path}"
            )
        status = git_bytes(
            submodule,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        )
        if status is None:
            raise SystemExit(f"Could not inspect Git submodule contents: {relative_path}")
        if status:
            raise SystemExit(
                f"Dirty Git submodules are not supported for remediation integrity checks: {relative_path}"
            )
        require_clean_submodule_worktrees(submodule)


def clean_worktree_content_digest() -> str:
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-snapshot/v1")
    update_digest_field(digest, b"tracked-diff", b"")
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def git_directory_snapshot_paths(target: Path) -> list[Path] | None:
    repository_root = git_output(target, "rev-parse", "--show-toplevel")
    if repository_root is None:
        return None
    repository, pathspec = git_worktree_context(target)
    listed = git_bytes(
        repository,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        pathspec,
    )
    if listed is None:
        raise SystemExit("Could not inspect files in the selected Git working tree.")
    paths: list[Path] = []
    for raw_path in (raw_path for raw_path in listed.split(b"\0") if raw_path):
        path = repository / os.fsdecode(raw_path)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            # The index can retain a path that was staged and then deleted.
            continue
        paths.append(path)
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        nested_repository_root = git_output(path, "rev-parse", "--show-toplevel")
        if (
            nested_repository_root is not None
            and Path(nested_repository_root).resolve() == path.resolve()
        ):
            nested_paths = git_directory_snapshot_paths(path)
            if nested_paths is not None:
                paths.extend(nested_paths)
                continue
        paths.extend(
            nested_path
            for nested_path in path.rglob("*")
            if ".git" not in nested_path.relative_to(path).parts
        )
    return sorted(set(paths))


def directory_content_digest(target: Path, *, excluded: tuple[Path, ...] = ()) -> str:
    excluded_relative = []
    for path in excluded:
        try:
            excluded_relative.append(path.relative_to(target))
        except ValueError:
            continue
    paths = git_directory_snapshot_paths(target)
    if paths is None:
        paths = sorted(target.rglob("*"))
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-directory/v1")
    for path in paths:
        relative_path = path.relative_to(target)
        if any(
            relative_path == excluded_path or excluded_path in relative_path.parents
            for excluded_path in excluded_relative
        ):
            continue
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not read local file: {relative_path}") from exc
        raw_path = os.fsencode(relative_path.as_posix())
        update_digest_field(digest, b"path", raw_path)
        update_digest_field(digest, b"mode", str(stat.S_IMODE(metadata.st_mode)).encode())
        if stat.S_ISLNK(metadata.st_mode):
            update_digest_field(digest, b"kind", b"symlink")
            update_digest_field(digest, b"content", os.fsencode(os.readlink(path)))
        elif stat.S_ISDIR(metadata.st_mode):
            update_digest_field(digest, b"kind", b"directory")
        elif stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256()
            content_size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        content_size += len(chunk)
            except OSError as exc:
                raise SystemExit(f"Could not read local file: {relative_path}") from exc
            update_digest_field(digest, b"kind", b"file")
            update_digest_field(digest, b"size", str(content_size).encode())
            update_digest_field(digest, b"content-sha256", content_digest.digest())
        else:
            raise SystemExit(f"Unsupported local file type: {relative_path}")
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def directory_snapshot_regular_file_count(target: Path) -> int:
    paths = git_directory_snapshot_paths(target)
    if paths is None:
        paths = sorted(target.rglob("*"))
    count = 0
    for path in paths:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not inspect local file: {path.relative_to(target)}") from exc
        if stat.S_ISREG(metadata.st_mode):
            count += 1
    return count


def copy_directory_excluding(source: Path, destination: Path, excluded: tuple[Path, ...]) -> None:
    excluded_relative = []
    for path in excluded:
        try:
            excluded_relative.append(path.relative_to(source))
        except ValueError:
            continue

    def ignored(directory: str, names: list[str]) -> list[str]:
        relative = Path(directory).relative_to(source)
        return [
            path.name
            for path in excluded_relative
            if path.parent == relative and path.name in names
        ]

    shutil.copytree(source, destination, symlinks=True, ignore=ignored)


def copy_git_worktree_files(source: Path, destination: Path, excluded: tuple[Path, ...]) -> Path:
    repository, pathspec = git_worktree_context(source)
    listed = git_bytes(
        repository,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        pathspec,
    )
    if listed is None:
        raise SystemExit("Could not inspect files in the selected Git working tree.")
    excluded_relative = []
    for path in excluded:
        try:
            excluded_relative.append(path.relative_to(repository))
        except ValueError:
            continue
    destination.mkdir()
    for raw_path in sorted(path for path in listed.split(b"\0") if path):
        relative = Path(os.fsdecode(raw_path))
        if any(
            relative == excluded_path or excluded_path in relative.parents
            for excluded_path in excluded_relative
        ):
            continue
        source_path = repository / relative
        try:
            metadata = source_path.lstat()
        except FileNotFoundError:
            continue
        destination_path = destination / relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if stat.S_ISLNK(metadata.st_mode):
            destination_path.symlink_to(os.readlink(source_path))
        elif stat.S_ISREG(metadata.st_mode):
            shutil.copy2(source_path, destination_path, follow_symlinks=False)
        elif stat.S_ISDIR(metadata.st_mode):
            nested_git_dir = git_output(source_path, "rev-parse", "--absolute-git-dir")
            if nested_git_dir is None:
                raise SystemExit(f"Could not inspect nested Git working tree: {relative}")
            copy_git_worktree_files(source_path, destination_path, excluded)
            (destination_path / ".git").write_text(
                f"gitdir: {nested_git_dir}\n", encoding="utf-8"
            )
        else:
            raise SystemExit(f"Unsupported Git working-tree file type: {relative}")
    copied_target = destination if pathspec == "." else destination / pathspec
    copied_target.mkdir(parents=True, exist_ok=True)
    return copied_target


def git_revision(target: Path) -> str:
    return git_output(target, "rev-parse", "HEAD") or "unversioned"


def git_target_metadata(target: Path) -> dict[str, Any]:
    is_git = git_output(target, "rev-parse", "--git-dir") is not None
    is_worktree = git_output(target, "rev-parse", "--is-inside-work-tree") == "true"
    revision = git_output(target, "rev-parse", "--verify", "HEAD")
    repository_root = git_output(target, "rev-parse", "--show-toplevel") if is_worktree else None
    supported = (
        is_git
        and is_worktree
        and revision is not None
        and repository_root is not None
        and Path(repository_root).resolve() == target
    )
    metadata: dict[str, Any] = {
        "hasHead": revision is not None,
        "isGit": is_git,
        "isWorktree": is_worktree,
        "reviewChangesSupported": supported,
    }
    if not is_git:
        return metadata
    branch = git_output(target, "symbolic-ref", "--quiet", "--short", "HEAD")
    metadata.update({"branch": branch, "detachedHead": revision is not None and branch is None})
    if revision is not None:
        subject = git_bytes(target, "show", "-s", "--format=%s", "HEAD")
        metadata.update(
            {
                "commitSubject": (subject or b"").decode("utf-8").strip() or None,
                "revision": revision,
                "shortRevision": revision[:7],
            }
        )
    return metadata


def require_remediation_target(value: str) -> Path:
    stored = Path(value).expanduser()
    if not stored.is_absolute():
        raise SystemExit("Remediation target must be an absolute local directory path.")
    try:
        resolved = stored.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise SystemExit(
            "Remediation is unavailable because the selected checkout is no longer accessible."
        ) from exc
    if resolved != stored or not stored.is_dir():
        raise SystemExit(
            "Remediation is unavailable because the selected checkout path was replaced. Start a new scan."
        )
    return stored


def require_scan_target_identity(scan: sqlite3.Row) -> Path:
    target = require_remediation_target(scan["target_path"])
    expected_inode = scan["target_inode"]
    if expected_inode is None:
        raise SystemExit(
            "Remediation is unavailable because this scan does not record checkout identity. "
            "Start a new scan."
        )
    try:
        metadata = target.stat()
    except OSError as exc:
        raise SystemExit(
            "Remediation is unavailable because the selected checkout is no longer accessible."
        ) from exc
    if not stored_filesystem_identity_matches(expected_inode, metadata.st_ino):
        raise SystemExit(
            "Remediation is unavailable because the selected checkout path was replaced. "
            "Start a new scan."
        )
    return target


def require_git_worktree_head(target: Path) -> str:
    metadata = git_target_metadata(target)
    if not metadata["isGit"] or not metadata["isWorktree"] or not metadata["hasHead"]:
        raise SystemExit("Review changes requires a non-bare Git worktree with a resolvable HEAD.")
    return str(metadata["revision"])


def scan_target_warning(scan: sqlite3.Row) -> str | None:
    committed_diff = scan["diff_target_kind"] in {"commit", "range"}
    if (
        not committed_diff
        and scan["diff_target_kind"] != "working_tree"
        and not scan["target_snapshot_digest"]
    ):
        return None
    if committed_diff and not scan["diff_content_digest"]:
        return None
    try:
        target = require_scan_target_identity(scan)
        if committed_diff:
            if (
                committed_diff_content_digest(
                    target,
                    scan["diff_base_revision"],
                    scan["diff_head_revision"],
                )
                != scan["diff_content_digest"]
            ):
                return (
                    "Committed changes changed while the scan was running; "
                    "results were saved for the original snapshot."
                )
            return None
        if scan["target_revision"] == "unversioned":
            if (
                directory_content_digest(target, excluded=(Path(scan["scan_dir"]),))
                != scan["target_snapshot_digest"]
            ):
                return (
                    "Directory contents changed while the scan was running; "
                    "results were saved for the original snapshot."
                )
            return None
        if git_revision(target) == "unversioned":
            return (
                "The scanned Git repository became unavailable while the scan was running; "
                "results were saved for the original revision."
            )
        working_tree = scan["diff_target_kind"] == "working_tree"
        expected_head = scan["diff_head_revision"] if working_tree else scan["target_revision"]
        if require_git_worktree_head(target) != expected_head:
            return (
                "Repository HEAD changed while the scan was running; "
                "results were saved for the original revision."
            )
        expected_digest = (
            scan["diff_content_digest"] if working_tree else scan["target_snapshot_digest"]
        )
        if worktree_content_digest(target) != expected_digest:
            return (
                "Working-tree contents changed while the scan was running; "
                "results were saved for the original snapshot."
            )
    except (OSError, SystemExit):
        return (
            "The scan target became unavailable while the scan was running; "
            "results were saved for the original revision or snapshot."
        )
    return None


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
