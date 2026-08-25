import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { BUNDLED_PLUGIN_VERSION, bootstrapPlugin } from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function python(): string {
  const command =
    process.env["PYTHON"] ??
    Bun.which("python3") ??
    Bun.which("python") ??
    Bun.which("py");
  expect(command).not.toBeNull();
  return command!;
}

function git(
  repository: string,
  args: string[],
  input?: Buffer | string,
): string {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=Synthetic Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      ...args,
    ],
    { cwd: repository, encoding: "utf8", input },
  ).trim();
}

function collisionRepository(root: string): {
  caseSensitive: boolean;
  deepPath: string;
  repository: string;
  replacement: string;
  revision: string;
} {
  const repository = join(root, "repository");
  mkdirSync(repository);
  git(repository, ["init", "-q"]);
  const blob = (content: string) =>
    git(repository, ["hash-object", "-w", "--stdin"], content);
  const tree = (
    entries: Array<[mode: string, type: string, oid: string, name: string]>,
  ) => {
    const records = entries
      .toSorted((left, right) =>
        Buffer.from(left[3]).compare(Buffer.from(right[3])),
      )
      .map(([mode, type, oid, name]) =>
        Buffer.concat([
          Buffer.from(`${mode} ${type} ${oid}\t`),
          Buffer.from(name),
          Buffer.from([0]),
        ]),
      );
    return git(repository, ["mktree", "-z"], Buffer.concat(records));
  };
  const sourceTree = tree([
    ["100644", "blob", blob("allowed = True\n"), "allowed.py"],
    ["100644", "blob", blob("x".repeat(256 * 1024)), "large.py"],
    ["100644", "blob", blob("case_upper = True\n"), "LOWER.py"],
    ["100644", "blob", blob("case_lower = True\n"), "lower.py"],
    ["100644", "blob", blob("unicode_composed = True\n"), "é.py"],
    ["100644", "blob", blob("unicode_decomposed = True\n"), "é.py"],
    ["100644", "blob", blob("plain_name = True\n"), "trailing.py"],
    ["100644", "blob", blob("trailing_dot = True\n"), "trailing.py."],
    ["100644", "blob", blob("uncheckoutable = True\n"), "z".repeat(2048)],
  ]);
  const upperScope = tree([
    ["100644", "blob", blob("selected_scope = True\n"), "selected.py"],
  ]);
  const lowerScope = tree([
    ["100644", "blob", blob("colliding_scope = True\n"), "sibling.py"],
  ]);
  const mismatchTree = tree([
    ["100644", "blob", blob("unscanned = True\n"), "secret.py"],
  ]);
  const linkedSubtree = tree([
    ["100644", "blob", blob("linked_secret = True\n"), "secret.py"],
  ]);
  const linkedTree = tree([["040000", "tree", linkedSubtree, "subdir"]]);
  const deepComponents = Array.from({ length: 128 }, (_, index) => `d${index}`);
  let deepTree = tree([["100644", "blob", blob("deep = True\n"), "source.py"]]);
  for (const component of deepComponents.toReversed()) {
    deepTree = tree([["040000", "tree", deepTree, component]]);
  }
  const deepPath = ["deep", ...deepComponents, "source.py"].join("/");
  const rootTree = tree([
    ["040000", "tree", upperScope, "Scope"],
    ["040000", "tree", linkedTree, "alias"],
    ["040000", "tree", deepTree, "deep"],
    ["040000", "tree", mismatchTree, "mismatch"],
    ["040000", "tree", lowerScope, "scope"],
    ["100644", "blob", blob("outside = True\n"), "outside.py"],
    ["040000", "tree", sourceTree, "src"],
  ]);
  const revision = git(repository, [
    "commit-tree",
    rootTree,
    "-m",
    "synthetic source tree",
  ]);
  const replacementTree = tree([
    ["100644", "blob", blob("replacement = True\n"), "replacement.py"],
  ]);
  const replacement = git(repository, [
    "commit-tree",
    replacementTree,
    "-m",
    "synthetic replacement tree",
  ]);
  git(repository, ["symbolic-ref", "HEAD", "refs/heads/main"]);
  git(repository, ["update-ref", "refs/heads/main", revision]);
  mkdirSync(join(repository, "src"));
  mkdirSync(join(repository, "Scope"));
  mkdirSync(join(repository, "deep"));
  mkdirSync(join(repository, "real", "subdir"), { recursive: true });
  symlinkSync(join(repository, "real"), join(repository, "alias"), "junction");
  writeFileSync(
    join(repository, "real", "subdir", "allowed.py"),
    "linked_allowed = True\n",
  );
  writeFileSync(join(repository, "src", "allowed.py"), "allowed = True\n");
  writeFileSync(join(repository, "src", "LOWER.py"), "case_upper = True\n");
  const lowercasePath = join(repository, "src", "lower.py");
  const caseSensitive = !existsSync(lowercasePath);
  if (caseSensitive) {
    writeFileSync(lowercasePath, "case_lower = True\n");
  }
  writeFileSync(join(repository, "src", "é.py"), "unicode_composed = True\n");
  writeFileSync(join(repository, "src", "trailing.py"), "plain_name = True\n");
  writeFileSync(join(repository, "mismatch"), "selected_file = True\n");
  writeFileSync(
    join(repository, "Scope", "selected.py"),
    "selected_scope = True\n",
  );
  return { caseSensitive, deepPath, repository, replacement, revision };
}

function ordinaryRepository(root: string): {
  repository: string;
  revision: string;
} {
  const repository = join(root, "ordinary-repository");
  mkdirSync(join(repository, "src"), { recursive: true });
  mkdirSync(join(repository, "other"));
  writeFileSync(join(repository, "src", "allowed.py"), "allowed = True\n");
  writeFileSync(join(repository, "other", "example.py"), "example = True\n");
  git(repository, ["init", "-q"]);
  git(repository, ["add", "."]);
  git(repository, ["commit", "-qm", "synthetic source tree"]);
  return { repository, revision: git(repository, ["rev-parse", "HEAD"]) };
}

async function upgradedPlugin(root: string) {
  expect(BUNDLED_PLUGIN_VERSION).toBe("0.1.47");
  const previous = join(root, "previous-plugin");
  cpSync(PLUGIN_ROOT, previous, { recursive: true });
  const manifestPath = join(previous, ".codex-plugin", "plugin.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    version: string;
  };
  manifest.version = "0.1.46";
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");

  const home = join(root, "codex-home");
  const marketplace = join(home, "sdk-marketplace");
  mkdirSync(home, { mode: 0o700 });
  const runCodex = async (_command: unknown, args: readonly string[]) => {
    if (args[1] === "marketplace") {
      writeFileSync(
        join(home, "config.toml"),
        `[marketplaces.codex-security-sdk]\nsource_type = "local"\nsource = ${JSON.stringify(marketplace)}\n`,
      );
      return "";
    }
    const selected = join(marketplace, "plugins", "codex-security");
    const selectedManifest = JSON.parse(
      readFileSync(join(selected, ".codex-plugin", "plugin.json"), "utf8"),
    ) as { version: string };
    const installed = join(home, "installed", selectedManifest.version);
    rmSync(installed, { recursive: true, force: true });
    mkdirSync(join(home, "installed"), { recursive: true });
    cpSync(selected, installed, { recursive: true });
    return JSON.stringify({
      installedPath: installed,
      version: selectedManifest.version,
    });
  };
  const options = {
    codexCommand: { command: "/synthetic-codex" },
    runCodex,
  };
  const predecessor = await bootstrapPlugin(home, previous, options);
  const upgraded = await bootstrapPlugin(home, PLUGIN_ROOT, options);
  const installedMcp = JSON.parse(
    readFileSync(join(upgraded.installedRoot, ".mcp.json"), "utf8"),
  ) as { mcpServers: Record<string, { env_vars?: string[] }> };
  expect(predecessor.version).toBe("0.1.46");
  expect(upgraded.version).toBe("0.1.47");
  expect(upgraded.installedRoot).not.toBe(predecessor.installedRoot);
  expect(
    installedMcp.mcpServers["codex-security"]?.env_vars?.find(
      (name) => name === "CODEX_SAFETY_IDENTIFIER",
    ),
  ).toBe("CODEX_SAFETY_IDENTIFIER");
  expect(
    readFileSync(
      join(upgraded.installedRoot, "scripts", "workbench_source_excerpt.py"),
    ),
  ).toEqual(
    readFileSync(join(PLUGIN_ROOT, "scripts", "workbench_source_excerpt.py")),
  );
  return { predecessor, upgraded };
}

function collisionProbe(
  pluginRoot: string,
  fixture: {
    deepPath: string;
    repository: string;
    replacement: string;
    revision: string;
  },
) {
  const program = String.raw`
import io, json, os, subprocess, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import workbench_source_excerpt as excerpts
from workbench_target import clean_worktree_content_digest

repository = Path(sys.argv[2]).resolve()
revision = sys.argv[3]
replacement = sys.argv[4]
deep_path = sys.argv[5]
metadata = repository.stat()
identity = (revision, clean_worktree_content_digest(), metadata.st_dev, metadata.st_ino)
authority = excerpts.capture_source_scopes(repository, identity, ["src", "src"])
authority_json = json.dumps(authority)
scan = {
    "mode": "standard",
    "diff_target_kind": None,
    "target_revision": revision,
    "target_snapshot_digest": clean_worktree_content_digest(),
    "source_scopes_json": authority_json,
}
ordered_excerpt = excerpts.finding_source_excerpt_from_context(
    excerpts.source_excerpt_context(scan, repository, ["src"]),
    [
        {"path": "src/allowed.py", "startLine": 1, "role": "evidence"},
        {"path": "outside.py", "startLine": 1, "role": "not_root_control"},
    ],
)
def excerpt(path, saved=scan, selected_paths=None):
    if selected_paths is None:
        selected_paths = ["src"]
    context = excerpts.source_excerpt_context(saved, repository, selected_paths)
    return excerpts.finding_source_excerpt_from_context(
        context,
        [{"path": path, "startLine": 1, "endLine": 1, "role": "root_control"}],
    )
original_git = excerpts.local_git_bytes
original_popen = subprocess.Popen
blob_reads = []
blob_read_sizes = []
replacement_probe_commands = []
replacement_probe_read_sizes = []
watch_replacement_probe = False
class WatchedBlobOutput:
    def __init__(self, output):
        self.output = output
    def read(self, size=-1):
        if size < 0 or size > 64 * 1024:
            raise AssertionError("blob response was buffered")
        blob_read_sizes.append(size)
        return self.output.read(size)
    def __getattr__(self, name):
        return getattr(self.output, name)
class WatchedReplacementOutput:
    def __init__(self, output):
        self.output = output
    def read(self, size=-1):
        replacement_probe_read_sizes.append(size)
        return self.output.read(size)
    def __getattr__(self, name):
        return getattr(self.output, name)
def watched_popen(arguments, *positional, **keywords):
    process = original_popen(arguments, *positional, **keywords)
    if len(arguments) >= 3 and arguments[-3:-1] == ["cat-file", "blob"]:
        blob_reads.append(arguments[-1])
        process.stdout = WatchedBlobOutput(process.stdout)
    if watch_replacement_probe and "for-each-ref" in arguments:
        start = arguments.index("for-each-ref")
        replacement_probe_commands.append(arguments[start:])
        process.stdout = WatchedReplacementOutput(process.stdout)
    return process
subprocess.Popen = watched_popen
allowed = excerpt("src/allowed.py")
linked_authority = excerpts.capture_source_scopes(
    repository, identity, ["alias/subdir"]
)
linked_scan = {**scan, "source_scopes_json": json.dumps(linked_authority)}
before = len(blob_reads)
linked_excerpt = excerpt(
    "alias/subdir/secret.py", linked_scan, ["alias/subdir"]
)
linked_blob_reads = blob_reads[before:]
before = len(blob_read_sizes)
large_blob_excerpt = excerpt("src/large.py")
large_blob_sizes = blob_read_sizes[before:]
original_excerpt_reader = excerpts.scanned_source_excerpt
def exhausted_blob(*arguments, **keywords):
    raise MemoryError("synthetic blob exhaustion")
excerpts.scanned_source_excerpt = exhausted_blob
try:
    blob_memory_error = excerpt("src/allowed.py")
finally:
    excerpts.scanned_source_excerpt = original_excerpt_reader
before = len(blob_reads)
collisions = {
    path: excerpt(path)
    for path in (
        "src/LOWER.py",
        "src/lower.py",
        "src/é.py",
        "src/é.py",
        "src/trailing.py",
        "src/trailing.py.",
    )
}
collision_blob_reads = blob_reads[before:]
original_samefile = Path.samefile
def distinct_case_samefile(left, right):
    right = Path(right)
    if left.parent == right.parent and {left.name, right.name} == {"LOWER.py", "lower.py"}:
        return False
    return original_samefile(left, right)
Path.samefile = distinct_case_samefile
before = len(blob_reads)
try:
    distinct_case_excerpts = {
        path: excerpt(path)
        for path in ("src/LOWER.py", "src/lower.py")
    }
finally:
    Path.samefile = original_samefile
distinct_case_blob_reads = blob_reads[before:]
outside = excerpt("outside.py")
file_authority = excerpts.capture_source_scopes(repository, identity, ["mismatch"])
file_scan = {**scan, "source_scopes_json": json.dumps(file_authority)}
before = len(blob_reads)
file_descendant_excerpt = excerpt(
    "mismatch/secret.py", file_scan, ["mismatch"]
)
file_descendant_blob_reads = blob_reads[before:]
before = len(blob_reads)
broadened = excerpt(
    "outside.py",
    {
        **scan,
        "source_scopes_json": json.dumps(
            {**authority, "paths": [{"kind": "directory", "path": "."}]}
        ),
    },
)
broadened_blob_reads = blob_reads[before:]
scope_collision_authority = excerpts.capture_source_scopes(
    repository, identity, ["Scope"]
)
scope_collision_scan = {
    **scan,
    "source_scopes_json": json.dumps(scope_collision_authority),
}
before = len(blob_reads)
scope_collision_excerpt = excerpt(
    "Scope/selected.py", scope_collision_scan, ["Scope"]
)
scope_collision_blob_reads = blob_reads[before:]
subtarget = repository / "src"
subtarget_metadata = subtarget.stat()
subtarget_authority = excerpts.capture_source_scopes(
    subtarget,
    (
        revision,
        clean_worktree_content_digest(),
        subtarget_metadata.st_dev,
        subtarget_metadata.st_ino,
    ),
    ["."],
)
subprocess.run(["git", "-C", str(subtarget), "init", "-q"], check=True)
outer_git_dir = Path(
    subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "--absolute-git-dir"],
        text=True,
    ).strip()
)
alternates = subtarget / ".git" / "objects" / "info" / "alternates"
alternates.write_bytes((str(outer_git_dir / "objects") + "\n").encode())
subprocess.run(
    ["git", "-C", str(subtarget), "update-ref", "refs/heads/main", revision],
    check=True,
)
subtarget_scan = {
    **scan,
    "source_scopes_json": json.dumps(subtarget_authority),
}
nested_context = excerpts.source_excerpt_context(subtarget_scan, subtarget, ["."])
before = len(blob_reads)
nested_excerpt = excerpts.finding_source_excerpt_from_context(
    nested_context,
    [{"path": "outside.py", "startLine": 1, "endLine": 1, "role": "root_control"}],
)
nested_blob_reads = blob_reads[before:]
subprocess.run(
    ["git", "-C", str(repository), "update-ref", f"refs/replace/{revision}", replacement],
    check=True,
)
before = len(blob_reads)
try:
    replaced = excerpt("src/allowed.py")
finally:
    subprocess.run(
        ["git", "-C", str(repository), "update-ref", "-d", f"refs/replace/{revision}"],
        check=True,
    )
replacement_blob_reads = blob_reads[before:]
custom_replacement_base = "refs/synthetic-replacements/"
custom_replacement_ref = f"{custom_replacement_base}{revision}"
subprocess.run(
    ["git", "-C", str(repository), "update-ref", custom_replacement_ref, replacement],
    check=True,
)
original_replacement_base = os.environ.get("GIT_REPLACE_REF_BASE")
before = len(blob_reads)
try:
    os.environ["GIT_REPLACE_REF_BASE"] = custom_replacement_base
    custom_replacement_paths = excerpts.capture_source_scopes(
        repository, identity, ["src"]
    )["paths"]
    custom_replaced = excerpt("src/allowed.py")
    os.environ["GIT_REPLACE_REF_BASE"] = "--count=0"
    invalid_replacement_base_paths = excerpts.capture_source_scopes(
        repository, identity, ["src"]
    )["paths"]
finally:
    if original_replacement_base is None:
        os.environ.pop("GIT_REPLACE_REF_BASE", None)
    else:
        os.environ["GIT_REPLACE_REF_BASE"] = original_replacement_base
    subprocess.run(
        ["git", "-C", str(repository), "update-ref", "-d", custom_replacement_ref],
        check=True,
    )
custom_replacement_blob_reads = blob_reads[before:]
replace_directory = outer_git_dir / "refs" / "replace"
replace_directory.mkdir(parents=True, exist_ok=True)
broken_replacements = []
for index in range(128):
    broken = replace_directory / f"r{index:04d}"
    broken.write_text("not-an-object\n")
    broken_replacements.append(broken)
watch_replacement_probe = True
try:
    malformed_replacement_paths = excerpts.capture_source_scopes(
        repository, identity, ["src"]
    )["paths"]
finally:
    watch_replacement_probe = False
    for broken in broken_replacements:
        broken.unlink()
def exhausted_popen(arguments, *positional, **keywords):
    if "for-each-ref" in arguments:
        raise MemoryError("synthetic replacement probe exhaustion")
    return original_popen(arguments, *positional, **keywords)
subprocess.Popen = exhausted_popen
try:
    replacement_memory_paths = excerpts.capture_source_scopes(
        repository, identity, ["src"]
    )["paths"]
finally:
    subprocess.Popen = watched_popen
subprocess.Popen = original_popen
legacy_scan = dict(scan)
legacy_scan.pop("source_scopes_json")
legacy = excerpt("src/allowed.py", legacy_scan)
invalid = excerpt("src/allowed.py", {**scan, "source_scopes_json": "{"})
malformed_revision = excerpt("src/allowed.py", {**scan, "target_revision": 42})

original_context = excerpts.git_worktree_context
git_calls = []
def forbidden_git(*arguments, **kwargs):
    git_calls.append(arguments)
    raise AssertionError("ineligible diff mode reached Git")
excerpts.local_git_bytes = forbidden_git
excerpts.git_worktree_context = forbidden_git
try:
    mutable = {
        str(kind): excerpt(
            "src/allowed.py", {**scan, "mode": "diff", "diff_target_kind": kind}
        )
        for kind in ("working_tree", None)
    }
finally:
    excerpts.local_git_bytes = original_git
    excerpts.git_worktree_context = original_context
immutable = {
    kind: excerpt(
        "src/allowed.py", {**scan, "mode": "diff", "diff_target_kind": kind}
    )
    for kind in ("commit", "range")
}
deep_authority = excerpts.capture_source_scopes(repository, identity, ["deep"])
deep_scan = {**scan, "source_scopes_json": json.dumps(deep_authority)}
batch_processes = 0
tree_reads = 0
original_popen = subprocess.Popen
def watched_popen(arguments, *positional, **keywords):
    global batch_processes
    if "cat-file" in arguments and "--batch" in arguments:
        batch_processes += 1
    return original_popen(arguments, *positional, **keywords)
def counted_git(*arguments, **keywords):
    global tree_reads
    if len(arguments) >= 3 and arguments[1:3] == ("ls-tree", "-z"):
        tree_reads += 1
    return original_git(*arguments, **keywords)
subprocess.Popen = watched_popen
excerpts.local_git_bytes = counted_git
try:
    deep_excerpt = excerpt(deep_path, deep_scan, ["deep"])
finally:
    excerpts.local_git_bytes = original_git
    subprocess.Popen = original_popen
batch_object = "1" * 40
entry_object = b"\1" * 20
wide_tree = b"".join(
    b"100644 f%04d\0" % index + entry_object for index in range(5_000)
)
wide_tree += b"100644 target.py\0" + entry_object
class CappedRead(io.BytesIO):
    largest = 0
    def read(self, size=-1):
        if size < 0 or size > 64 * 1024:
            raise AssertionError("tree response was buffered")
        self.largest = max(self.largest, size)
        return super().read(size)
stream_requests = io.BytesIO()
stream_responses = CappedRead(
    f"{batch_object} tree {len(wide_tree)}\n".encode()
    + wide_tree
    + b"\n"
)
streamed_aliases = excerpts.matching_tree_entries(
    stream_requests, stream_responses, batch_object, "target.py"
)
alias_tree = (b"100644 target.py\0" + entry_object) * 20_000
alias_responses = CappedRead(
    f"{batch_object} tree {len(alias_tree)}\n".encode()
    + alias_tree
    + b"\n"
)
ambiguous_alias = excerpts.matching_tree_entries(
    io.BytesIO(), alias_responses, batch_object, "target.py"
)
oversized_name = b"x" * (64 * 1024 + 1)
oversized_tree = (
    b"100644 " + oversized_name + b"\0" + entry_object
    + b"100644 target.py\0" + entry_object
)
oversized_responses = CappedRead(
    f"{batch_object} tree {len(oversized_tree)}\n".encode()
    + oversized_tree
    + b"\n"
)
oversized_sibling = excerpts.matching_tree_entries(
    io.BytesIO(), oversized_responses, batch_object, "target.py"
)
oversized_alias_tree = (
    b"100644 target.py\0" + entry_object
    + b"100644 target.py" + b"." * (64 * 1024 + 1) + b"\0" + entry_object
)
oversized_alias_responses = CappedRead(
    f"{batch_object} tree {len(oversized_alias_tree)}\n".encode()
    + oversized_alias_tree
    + b"\n"
)
oversized_alias = excerpts.matching_tree_entries(
    io.BytesIO(), oversized_alias_responses, batch_object, "target.py"
)
streamed_wide_tree = (
    streamed_aliases == ("target.py", "file", entry_object.hex())
    and stream_requests.getvalue() == batch_object.encode() + b"\0"
    and stream_responses.largest == 64 * 1024
    and ambiguous_alias is None
    and alias_responses.largest == 64 * 1024
    and oversized_sibling == ("target.py", "file", entry_object.hex())
    and oversized_responses.largest == 64 * 1024
    and oversized_alias is None
    and oversized_alias_responses.largest == 64 * 1024
)
large_paths = [str(index) for index in range(20_000)]
large_tree = "0" * 40
large_scan = {
    **scan,
    "source_scopes_json": json.dumps(
        {
            "version": 1,
            "paths": [
                {"kind": "file", "path": path} for path in large_paths
            ],
            "targetTree": large_tree,
        }
    ),
}
large_recipe_bytes = len(
    json.dumps(
        {"target": {"kind": "paths", "paths": large_paths}}, separators=(",", ":")
    ).encode()
)
original_target_tree = excerpts.target_tree
original_tree_path = excerpts.tree_path
tree_path_checks = 0
def counted_tree_path(_, __, value):
    global tree_path_checks
    tree_path_checks += 1
    return (value, "file", "1" * 40)
excerpts.target_tree = lambda *_: (repository, large_tree)
excerpts.tree_path = counted_tree_path
try:
    large_context = excerpts.source_excerpt_context(
        large_scan, repository, large_paths
    )
    original_pure_path = excerpts.PurePosixPath
    path_parses = 0
    def one_path_parse(*arguments):
        global path_parses
        path_parses += 1
        if path_parses > 1:
            raise RuntimeError("source scope lookup rebuilt the path")
        return original_pure_path(*arguments)
    excerpts.PurePosixPath = one_path_parse
    try:
        excerpts.selected_source_kinds(
            large_context[2],
            "/".join(["nested"] * 20_000 + ["file.py"]),
        )
    finally:
        excerpts.PurePosixPath = original_pure_path
    large_excerpt = excerpts.finding_source_excerpt_from_context(
        large_context, [{"path": "unmatched/path.py", "startLine": 1}]
    )
finally:
    excerpts.target_tree = original_target_tree
    excerpts.tree_path = original_tree_path
print(json.dumps({
    "allowed": allowed,
    "broadened": broadened,
    "broadenedBlobReads": broadened_blob_reads,
    "collisionBlobReads": collision_blob_reads,
    "collisions": collisions,
    "customReplaced": custom_replaced,
    "customReplacementBlobReads": custom_replacement_blob_reads,
    "customReplacementPaths": custom_replacement_paths,
    "deepBatchProcesses": batch_processes,
    "deepExcerpt": deep_excerpt,
    "deepPathParses": path_parses,
    "deepTreeReads": tree_reads,
    "distinctCaseBlobReads": distinct_case_blob_reads,
    "distinctCaseExcerpts": distinct_case_excerpts,
    "duplicatePaths": len(authority["paths"]),
    "fileAuthorityPaths": file_authority["paths"],
    "fileDescendantBlobReads": file_descendant_blob_reads,
    "fileDescendantExcerpt": file_descendant_excerpt,
    "invalidReplacementBasePaths": invalid_replacement_base_paths,
    "immutable": immutable,
    "largeExcerpt": large_excerpt,
    "largeBlobStreamed": (
        len(large_blob_excerpt.encode()) == 16_000
        and len(large_blob_sizes) >= 4
        and max(large_blob_sizes) == 64 * 1024
    ),
    "blobMemoryError": blob_memory_error,
    "largeRecipeFits": large_recipe_bytes < 256 * 1024,
    "largeTreePathChecks": tree_path_checks,
    "linkedAuthorityPaths": linked_authority["paths"],
    "linkedBlobReads": linked_blob_reads,
    "linkedExcerpt": linked_excerpt,
    "malformedReplacementPaths": malformed_replacement_paths,
    "invalid": invalid,
    "legacy": legacy,
    "malformedRevision": malformed_revision,
    "mutable": {"excerpts": mutable, "gitCalls": len(git_calls)},
    "nestedBlobReads": nested_blob_reads,
    "nestedExcerpt": nested_excerpt,
    "orderedExcerpt": ordered_excerpt,
    "subtargetPaths": subtarget_authority["paths"],
    "outside": outside,
    "pathCollisionBlobReads": scope_collision_blob_reads,
    "pathCollisionExcerpt": scope_collision_excerpt,
    "pathCollisionPaths": len(scope_collision_authority["paths"]),
    "replaced": replaced,
    "replacementBlobReads": replacement_blob_reads,
    "replacementMemoryPaths": replacement_memory_paths,
    "replacementProbeCommands": replacement_probe_commands,
    "replacementProbeReadSizes": replacement_probe_read_sizes,
    "streamedWideTree": streamed_wide_tree,
}))
`;
  const result = spawnSync(
    python(),
    [
      "-I",
      "-B",
      "-c",
      program,
      join(pluginRoot, "scripts"),
      fixture.repository,
      fixture.revision,
      fixture.replacement,
      fixture.deepPath,
    ],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

describe("workbench source excerpts", () => {
  test("fails closed on normalized collisions after a cached upgrade", async () => {
    const root = realpathSync(
      mkdtempSync(join(tmpdir(), "codex-security-source-collision-")),
    );
    temporaryRoots.push(root);
    const fixture = collisionRepository(root);
    const installation = await upgradedPlugin(root);
    const fixed = collisionProbe(installation.upgraded.installedRoot, fixture);

    expect(fixed).toEqual({
      allowed: expect.stringContaining("allowed = True"),
      broadened: null,
      broadenedBlobReads: [],
      collisionBlobReads: fixture.caseSensitive
        ? [expect.any(String), expect.any(String)]
        : [],
      collisions: {
        "src/LOWER.py": fixture.caseSensitive
          ? expect.stringContaining("case_upper = True")
          : null,
        "src/lower.py": fixture.caseSensitive
          ? expect.stringContaining("case_lower = True")
          : null,
        "src/é.py": null,
        "src/é.py": null,
        "src/trailing.py": null,
        "src/trailing.py.": null,
      },
      customReplaced: null,
      customReplacementBlobReads: [],
      customReplacementPaths: [],
      deepBatchProcesses: 1,
      deepExcerpt: expect.stringContaining("deep = True"),
      deepPathParses: 1,
      deepTreeReads: 0,
      distinctCaseBlobReads: [expect.any(String), expect.any(String)],
      distinctCaseExcerpts: {
        "src/LOWER.py": expect.stringContaining("case_upper = True"),
        "src/lower.py": expect.stringContaining("case_lower = True"),
      },
      duplicatePaths: 1,
      fileAuthorityPaths: [{ kind: "file", path: "mismatch" }],
      fileDescendantBlobReads: [],
      fileDescendantExcerpt: null,
      invalidReplacementBasePaths: [],
      immutable: {
        commit: expect.stringContaining("allowed = True"),
        range: expect.stringContaining("allowed = True"),
      },
      largeExcerpt: null,
      largeBlobStreamed: true,
      blobMemoryError: null,
      largeRecipeFits: true,
      largeTreePathChecks: 0,
      linkedAuthorityPaths: [],
      linkedBlobReads: [],
      linkedExcerpt: null,
      malformedReplacementPaths: [],
      invalid: null,
      legacy: null,
      malformedRevision: null,
      mutable: {
        excerpts: { working_tree: null, None: null },
        gitCalls: 0,
      },
      nestedBlobReads: [],
      nestedExcerpt: null,
      orderedExcerpt: expect.stringContaining("allowed = True"),
      subtargetPaths: [{ kind: "directory", path: "." }],
      outside: null,
      pathCollisionBlobReads: [],
      pathCollisionExcerpt: null,
      pathCollisionPaths: 1,
      replaced: null,
      replacementBlobReads: [],
      replacementMemoryPaths: [],
      replacementProbeCommands: [
        ["for-each-ref", "--count=1", "--format=", "refs/replace/*"],
      ],
      replacementProbeReadSizes: [1],
      streamedWideTree: true,
    });
  }, 60_000);

  test("persists source authority outside every writer transaction", () => {
    const root = realpathSync(
      mkdtempSync(join(tmpdir(), "codex-security-source-writers-")),
    );
    temporaryRoots.push(root);
    const { repository } = ordinaryRepository(root);
    const scanRoot = join(root, "scans");
    const cliScanDirectory = join(root, "cli-scan");
    mkdirSync(cliScanDirectory, { mode: 0o700 });
    const workspaceId = randomUUID();
    const program = String.raw`
import contextlib, io, json, os, sqlite3, sys
from pathlib import Path
os.environ["CODEX_SECURITY_STATE_DIR"] = sys.argv[2]
sys.path.insert(0, sys.argv[1])
import workbench_db

active_connection = None
current_command = None
race_mutation = False
transaction_states = []
original_connect = workbench_db.connect
original_capture = workbench_db.capture_source_scopes
original_deep_capture = workbench_db.deep_scan.capture_source_scopes
def connect():
    global active_connection
    active_connection = original_connect()
    return active_connection
def capture(*arguments, **keywords):
    transaction_states.append([current_command, active_connection.in_transaction])
    return original_capture(*arguments, **keywords)
def deep_capture(*arguments, **keywords):
    transaction_states.append([current_command, active_connection.in_transaction])
    authority = original_deep_capture(*arguments, **keywords)
    if race_mutation:
        (Path(repository) / "src" / "allowed.py").write_text("changed_after_capture = True\n")
    return authority
def run(arguments):
    global current_command
    current_command = arguments[0]
    sys.argv = ["workbench_db.py", *arguments]
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        workbench_db.main()
    return json.loads(output.getvalue())
workbench_db.connect = connect
workbench_db.capture_source_scopes = capture
workbench_db.deep_scan.capture_source_scopes = deep_capture

repository, scan_root, cli_scan_dir, workspace_id = sys.argv[3:7]
run(["create-workspace", "--workspace-id", workspace_id, "--thread-id", "workspace-writer"])
run(["save-workspace", "--workspace-id", workspace_id, "--target-path", repository, "--scope", "src", "--mode", "standard"])
workspace = run(["start-scan", "--workspace-id", workspace_id, "--scan-root", scan_root])
prompt = run(["start-prompt-only-scan", "--thread-id", "prompt-writer", "--target-path", repository, "--scope", "src", "--mode", "standard", "--scan-root", scan_root])
headless = run(["start-headless-standard-scan", "--thread-id", "headless-writer", "--target-path", repository, "--scope", "src", "--scan-root", scan_root])
recipe = json.dumps({"config": {}, "mode": "standard", "repository": repository, "target": {"kind": "paths", "paths": ["src/allowed.py", "other"]}})
cli = run(["register-cli-scan", "--repository", repository, "--scan-dir", cli_scan_dir, "--recipe-json", recipe])
deep = run(["begin-deep-scan", "--thread-id", "deep-writer", "--target-path", repository, "--scan-root", scan_root, "--available-parallelism", "4"])
race_mutation = True
try:
    run(["begin-deep-scan", "--thread-id", "raced-deep-writer", "--target-path", repository, "--scan-root", scan_root, "--available-parallelism", "4"])
except SystemExit as error:
    race_error = str(error)
else:
    race_error = None
(Path(repository) / "src" / "allowed.py").write_text("allowed = True\n")
with sqlite3.connect(workbench_db.database_path()) as connection:
    authorities = {row[0]: json.loads(row[1]) for row in connection.execute("SELECT id, source_scopes_json FROM scans")}
print(json.dumps({"authorities": authorities, "cli": cli, "deep": deep, "headless": headless, "prompt": prompt, "raceError": race_error, "transactionStates": transaction_states, "workspace": workspace}))
`;
    const result = spawnSync(
      python(),
      [
        "-I",
        "-B",
        "-c",
        program,
        join(PLUGIN_ROOT, "scripts"),
        join(root, "state"),
        repository,
        scanRoot,
        cliScanDirectory,
        workspaceId,
      ],
      { encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    const writers = JSON.parse(result.stdout) as Record<string, unknown>;
    expect(writers["transactionStates"]).toEqual([
      ["start-scan", false],
      ["start-prompt-only-scan", false],
      ["start-headless-standard-scan", false],
      ["register-cli-scan", false],
      ["begin-deep-scan", false],
      ["begin-deep-scan", false],
    ]);
    expect(writers["raceError"]).toBe(
      "The selected scan target changed while the scan was starting. Try again.",
    );
    const authorities = writers["authorities"] as Record<
      string,
      {
        paths: Array<{ kind: "directory" | "file"; path: string }>;
        targetTree: string;
        version: number;
      }
    >;
    const workspace = writers["workspace"] as Record<string, unknown>;
    const prompt = writers["prompt"] as Record<string, unknown>;
    const headless = writers["headless"] as Record<string, unknown>;
    const cli = writers["cli"] as Record<string, unknown>;
    const deep = writers["deep"] as Record<string, unknown>;
    const workspaceResults = workspace["results"] as Record<string, unknown>;
    const promptScan = prompt["scan"] as Record<string, unknown>;
    const headlessScan = headless["scan"] as Record<string, unknown>;
    const deepScan = deep["deepScan"] as Record<string, unknown>;
    const expected = [
      [
        "workspace",
        workspaceResults["scanId"],
        [{ kind: "directory", path: "src" }],
      ],
      ["prompt", promptScan["scanId"], [{ kind: "directory", path: "src" }]],
      [
        "headless",
        headlessScan["scanId"],
        [{ kind: "directory", path: "src" }],
      ],
      [
        "CLI",
        cli["scanId"],
        [
          { kind: "file", path: "src/allowed.py" },
          { kind: "directory", path: "other" },
        ],
      ],
      ["deep", deepScan["scanId"], [{ kind: "directory", path: "." }]],
    ] as const;
    expect(Object.keys(authorities)).toHaveLength(expected.length);
    for (const [writer, scanId, paths] of expected) {
      const authority = authorities[String(scanId)];
      expect(authority?.version, writer).toBe(1);
      expect(authority?.targetTree, writer).toMatch(/^[0-9a-f]{40,64}$/);
      expect(authority?.paths, writer).toEqual([...paths]);
    }
  }, 60_000);

  test("migration 33 appends once over the exact predecessor", () => {
    const program = String.raw`
import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
from workbench_schema import MIGRATIONS, apply_migrations

connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
counter = 0
def now():
    global counter
    counter += 1
    return f"2026-08-24T00:00:{counter:02d}Z"
def rows():
    return [tuple(row) for row in connection.execute(
        "SELECT version, name, applied_at FROM schema_migrations WHERE version >= 29 ORDER BY version"
    )]

predecessor = MIGRATIONS[:-1]
apply_migrations(connection, predecessor, now, lambda database: None)
before = rows()
apply_migrations(connection, MIGRATIONS, now, lambda database: None)
once = rows()
column_count = sum(
    row[1] == "source_scopes_json"
    for row in connection.execute("PRAGMA table_info(scans)")
)
apply_migrations(connection, MIGRATIONS, now, lambda database: None)
twice = rows()
print(json.dumps({
    "predecessorMax": predecessor[-1][0],
    "beforeVersions": [row[0] for row in before],
    "onceVersions": [row[0] for row in once],
    "oldRowsPreserved": once[:-1] == before,
    "secondApplyUnchanged": twice == once,
    "columnCount": column_count,
    "newName": once[-1][1],
}))
`;
    const result = spawnSync(
      python(),
      ["-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts")],
      { encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      predecessorMax: 32,
      beforeVersions: [29, 30, 31, 32],
      onceVersions: [29, 30, 31, 32, 33],
      oldRowsPreserved: true,
      secondApplyUnchanged: true,
      columnCount: 1,
      newName: "persist selected source excerpt authority",
    });
  });

  test("authorizes raw finding paths before bounding display output", () => {
    const program = String.raw`
import json, sqlite3, sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import workbench_db

raw_path = "segment/" * 300 + "source.py"
connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
connection.execute("CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, start_line INTEGER, end_line INTEGER, role TEXT, sort_order INTEGER)")
connection.execute("INSERT INTO finding_locations VALUES ('occurrence', ?, 1, 1, 'root_control', 0)", (raw_path,))
target = Path(tempfile.mkdtemp()).resolve()
workbench_db.require_scan_target_identity = lambda scan: target
workbench_db.safe_source_path = lambda selected, value: None
workbench_db.finding_remediation_result = lambda database, occurrence_id: None
workbench_db.finding_triage_result = lambda database, occurrence_id: None
workbench_db.scan_history.finding_matches = lambda *arguments: ([], None, [])
seen = []
selected_paths_seen = []
authority_context = (target, ())
def prepare_context(scan, selected, selected_paths):
    selected_paths_seen.append(selected_paths)
    return authority_context if selected_paths else None
def source_excerpt(context, locations):
    seen.append([location["path"] for location in locations])
    if context is authority_context and locations[0]["path"] == raw_path:
        return "1  raw_path_authorized = True"
    return None
workbench_db.source_excerpt_context = prepare_context
workbench_db.finding_source_excerpt_from_context = source_excerpt
scan = {"id": "scan", "started_at": "now", "scan_dir": str(target), "scope": "."}
occurrence = {"id": "occurrence", "details_json": "{}", "confidence": "high", "severity": "high", "created_at": "now", "finding_id": "finding", "remediation": "fix", "summary": "summary", "title": "title"}
findings = workbench_db.finding_results(connection, scan, [occurrence, occurrence])
finding = findings[0]
malformed = workbench_db.finding_results(
    connection,
    {**scan, "recipe_json": json.dumps({"target": {"kind": "paths", "paths": 42}})},
    [occurrence],
)[0]
display_path = finding["locations"][0]["path"]
print(json.dumps({
    "displayBytes": len(display_path.encode()),
    "displayDiffers": display_path != raw_path,
    "excerpt": finding.get("sourceExcerpt"),
    "malformedExcerpt": malformed.get("sourceExcerpt"),
    "malformedTitle": malformed.get("title"),
    "reusedExcerpt": findings[1].get("sourceExcerpt"),
    "sawRawPath": seen == [[raw_path], [raw_path], [raw_path]],
    "sawSelectedPaths": selected_paths_seen == [["."], []],
}))
`;
    const result = spawnSync(
      python(),
      ["-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts")],
      { encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      displayBytes: 2_048,
      displayDiffers: true,
      excerpt: "1  raw_path_authorized = True",
      malformedExcerpt: null,
      malformedTitle: "title",
      reusedExcerpt: "1  raw_path_authorized = True",
      sawRawPath: true,
      sawSelectedPaths: true,
    });
  });
});
