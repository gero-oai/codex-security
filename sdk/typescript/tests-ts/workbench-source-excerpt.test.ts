import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
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
    ["100644", "blob", blob("case_upper = True\n"), "LOWER.py"],
    ["100644", "blob", blob("case_lower = True\n"), "lower.py"],
    ["100644", "blob", blob("unicode_composed = True\n"), "é.py"],
    ["100644", "blob", blob("unicode_decomposed = True\n"), "é.py"],
    ["100644", "blob", blob("plain_name = True\n"), "trailing.py"],
    ["100644", "blob", blob("trailing_dot = True\n"), "trailing.py."],
  ]);
  const upperScope = tree([
    ["100644", "blob", blob("selected_scope = True\n"), "selected.py"],
  ]);
  const lowerScope = tree([
    ["100644", "blob", blob("colliding_scope = True\n"), "sibling.py"],
  ]);
  const rootTree = tree([
    ["040000", "tree", upperScope, "Scope"],
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
  writeFileSync(join(repository, "src", "allowed.py"), "allowed = True\n");
  writeFileSync(join(repository, "src", "LOWER.py"), "case_upper = True\n");
  writeFileSync(join(repository, "src", "é.py"), "unicode_composed = True\n");
  writeFileSync(join(repository, "src", "trailing.py"), "plain_name = True\n");
  writeFileSync(
    join(repository, "Scope", "selected.py"),
    "selected_scope = True\n",
  );
  return { repository, replacement, revision };
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
  expect(BUNDLED_PLUGIN_VERSION).toBe("0.1.28");
  const previous = join(root, "previous-plugin");
  cpSync(PLUGIN_ROOT, previous, { recursive: true });
  const manifestPath = join(previous, ".codex-plugin", "plugin.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    version: string;
  };
  manifest.version = "0.1.27";
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
  expect(predecessor.version).toBe("0.1.27");
  expect(upgraded.version).toBe("0.1.28");
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
  fixture: { repository: string; replacement: string; revision: string },
) {
  const program = String.raw`
import json, subprocess, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import workbench_source_excerpt as excerpts
from workbench_target import clean_worktree_content_digest

repository = Path(sys.argv[2]).resolve()
revision = sys.argv[3]
replacement = sys.argv[4]
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
def excerpt(path, saved=scan, selected_paths=None):
    if selected_paths is None:
        selected_paths = ["src"]
    context = excerpts.source_excerpt_context(saved, repository, selected_paths)
    return excerpts.finding_source_excerpt_from_context(
        context,
        [{"path": path, "startLine": 1, "endLine": 1, "role": "root_control"}],
    )
original_git = excerpts.local_git_bytes
blob_reads = []
def watched_git(*arguments, **kwargs):
    if len(arguments) >= 4 and arguments[1:3] == ("cat-file", "blob"):
        blob_reads.append(arguments[3])
    return original_git(*arguments, **kwargs)
excerpts.local_git_bytes = watched_git
allowed = excerpt("src/allowed.py")
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
outside = excerpt("outside.py")
before = len(blob_reads)
broadened = excerpt(
    "outside.py",
    {**scan, "source_scopes_json": json.dumps({**authority, "paths": ["."]})},
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
alternates.write_text(str(outer_git_dir / "objects") + "\n")
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
excerpts.local_git_bytes = original_git
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
large_paths = [str(index) for index in range(20_000)]
large_tree = "0" * 40
large_scan = {
    **scan,
    "source_scopes_json": json.dumps(
        {"version": 1, "paths": large_paths, "targetTree": large_tree}
    ),
}
large_recipe_bytes = len(
    json.dumps(
        {"target": {"kind": "paths", "paths": large_paths}}, separators=(",", ":")
    ).encode()
)
original_target_tree = excerpts.target_tree
original_tree_path = excerpts.tree_path
original_source_object = excerpts.source_object_for_path
scope_checks = 0
tree_path_checks = 0
def counted_source_object(*arguments, **kwargs):
    global scope_checks
    scope_checks += 1
    return original_source_object(*arguments, **kwargs)
def counted_tree_path(_, __, value):
    global tree_path_checks
    tree_path_checks += 1
    return (value, "file", "1" * 40)
excerpts.target_tree = lambda *_: (repository, large_tree)
excerpts.tree_path = counted_tree_path
excerpts.source_object_for_path = counted_source_object
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
        excerpts.source_scopes_for_path(
            large_context[2],
            "/".join(["nested"] * 20_000 + ["file.py"]),
        )
        deep_lookup_linear = True
    except RuntimeError:
        deep_lookup_linear = False
    finally:
        excerpts.PurePosixPath = original_pure_path
    large_excerpt = excerpts.finding_source_excerpt_from_context(
        large_context, [{"path": "unmatched/path.py", "startLine": 1}]
    )
finally:
    excerpts.target_tree = original_target_tree
    excerpts.tree_path = original_tree_path
    excerpts.source_object_for_path = original_source_object
print(json.dumps({
    "allowed": allowed,
    "broadened": broadened,
    "broadenedBlobReads": broadened_blob_reads,
    "collisionBlobReads": collision_blob_reads,
    "collisions": collisions,
    "deepLookupLinear": deep_lookup_linear,
    "deepPathParses": path_parses,
    "duplicatePaths": len(authority["paths"]),
    "immutable": immutable,
    "largeExcerpt": large_excerpt,
    "largeRecipeFits": large_recipe_bytes < 256 * 1024,
    "largeScopeChecks": scope_checks,
    "largeTreePathChecks": tree_path_checks,
    "invalid": invalid,
    "legacy": legacy,
    "malformedRevision": malformed_revision,
    "mutable": {"excerpts": mutable, "gitCalls": len(git_calls)},
    "nestedBlobReads": nested_blob_reads,
    "nestedExcerpt": nested_excerpt,
    "subtargetPaths": subtarget_authority["paths"],
    "outside": outside,
    "pathCollisionBlobReads": scope_collision_blob_reads,
    "pathCollisionExcerpt": scope_collision_excerpt,
    "pathCollisionPaths": len(scope_collision_authority["paths"]),
    "replaced": replaced,
    "replacementBlobReads": replacement_blob_reads,
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
      collisionBlobReads: [],
      collisions: {
        "src/LOWER.py": null,
        "src/lower.py": null,
        "src/é.py": null,
        "src/é.py": null,
        "src/trailing.py": null,
        "src/trailing.py.": null,
      },
      deepLookupLinear: true,
      deepPathParses: 1,
      duplicatePaths: 1,
      immutable: {
        commit: expect.stringContaining("allowed = True"),
        range: expect.stringContaining("allowed = True"),
      },
      largeExcerpt: null,
      largeRecipeFits: true,
      largeScopeChecks: 0,
      largeTreePathChecks: 0,
      invalid: null,
      legacy: null,
      malformedRevision: null,
      mutable: {
        excerpts: { working_tree: null, None: null },
        gitCalls: 0,
      },
      nestedBlobReads: [],
      nestedExcerpt: null,
      subtargetPaths: ["."],
      outside: null,
      pathCollisionBlobReads: [],
      pathCollisionExcerpt: null,
      pathCollisionPaths: 1,
      replaced: null,
      replacementBlobReads: [],
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
      { paths: string[]; targetTree: string; version: number }
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
      ["workspace", workspaceResults["scanId"], ["src"]],
      ["prompt", promptScan["scanId"], ["src"]],
      ["headless", headlessScan["scanId"], ["src"]],
      ["CLI", cli["scanId"], ["src/allowed.py", "other"]],
      ["deep", deepScan["scanId"], ["."]],
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
