import { execFileSync, spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { BUNDLED_PLUGIN_VERSION, bootstrapPlugin } from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryRoots: string[] = [];

function supportsFileSymlinks(): boolean {
  const root = mkdtempSync(join(tmpdir(), "codex-security-symlink-probe-"));
  try {
    symlinkSync("missing.py", join(root, "broken.py"), "file");
    return true;
  } catch (error) {
    if (
      process.platform === "win32" &&
      (error as NodeJS.ErrnoException).code === "EPERM"
    ) {
      return false;
    }
    throw error;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const fileSymlinksAvailable = supportsFileSymlinks();

function pythonExecutable(): string | null {
  return (
    process.env["PYTHON"] ??
    Bun.which("python3") ??
    Bun.which("python") ??
    Bun.which("py")
  );
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function git(repository: string, ...args: string[]): string {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...args,
    ],
    { cwd: repository, encoding: "utf8" },
  ).trim();
}

async function upgradeBundledPlugin(root: string): Promise<string> {
  expect(BUNDLED_PLUGIN_VERSION).toBe("0.1.46");
  const previous = join(root, "previous-plugin");
  cpSync(PLUGIN_ROOT, previous, { recursive: true });
  const previousManifestPath = join(previous, ".codex-plugin", "plugin.json");
  const previousManifest = JSON.parse(
    readFileSync(previousManifestPath, "utf8"),
  ) as { version: string };
  previousManifest.version = "0.1.44";
  writeFileSync(previousManifestPath, JSON.stringify(previousManifest));

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
    const manifest = JSON.parse(
      readFileSync(join(selected, ".codex-plugin", "plugin.json"), "utf8"),
    ) as { version: string };
    const installed = join(home, "installed", manifest.version);
    rmSync(installed, { recursive: true, force: true });
    mkdirSync(join(home, "installed"), { recursive: true });
    cpSync(selected, installed, { recursive: true });
    return JSON.stringify({
      installedPath: installed,
      version: manifest.version,
    });
  };
  const options = {
    codexCommand: { command: "/synthetic-codex" },
    runCodex,
  };

  const predecessor = await bootstrapPlugin(home, previous, options);
  const upgraded = await bootstrapPlugin(home, PLUGIN_ROOT, options);
  expect(predecessor.version).toBe("0.1.44");
  expect(upgraded.version).toBe(BUNDLED_PLUGIN_VERSION);
  expect(upgraded.installedRoot).not.toBe(predecessor.installedRoot);
  expect(
    readFileSync(
      join(upgraded.installedRoot, "scripts", "generate_rank_input.py"),
      "utf8",
    ),
  ).toBe(
    readFileSync(
      join(PLUGIN_ROOT, "scripts", "generate_rank_input.py"),
      "utf8",
    ),
  );
  return upgraded.installedRoot;
}

function stagedBrokenSymlinkFixture(): {
  root: string;
  repository: string;
  base: string;
} {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-diff-broken-link-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  mkdirSync(repository);
  git(repository, "init", "-q");
  writeFileSync(join(repository, "base.py"), "value = 1\n");
  git(repository, "add", "base.py");
  git(repository, "commit", "-qm", "base");
  const base = git(repository, "rev-parse", "HEAD");
  symlinkSync(
    "../synthetic-fixture/missing-target.py",
    join(repository, "broken.py"),
    "file",
  );
  git(repository, "add", "broken.py");
  return { root, repository, base };
}

test.skipIf(!fileSymlinksAvailable)(
  "diff inventory omits a broken symlink leaf",
  () => {
    const { root, repository, base } = stagedBrokenSymlinkFixture();
    const python = pythonExecutable();
    expect(python).not.toBeNull();
    const output = join(root, "in-scope-files.txt");
    const result = spawnSync(
      python!,
      [
        "-B",
        join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
        "--repo",
        repository,
        "--scope",
        ".",
        "--out",
        output,
        "--diff-base",
        base,
        "--diff-mode",
        "local-patch",
      ],
      { encoding: "utf8" },
    );

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(output, "utf8")).toBe("");
  },
);

test.skipIf(!fileSymlinksAvailable)(
  "diff rank input keeps a broken symlink leaf without a preview",
  () => {
    const { root, repository, base } = stagedBrokenSymlinkFixture();
    const python = pythonExecutable();
    expect(python).not.toBeNull();
    const output = join(root, "rank-input.jsonl");
    const result = spawnSync(
      python!,
      [
        "-B",
        join(PLUGIN_ROOT, "scripts", "generate_rank_input.py"),
        "make-diff-rank-input",
        "--repo",
        repository,
        "--base",
        base,
        "--mode",
        "local-patch",
        "--out",
        output,
      ],
      { encoding: "utf8" },
    );

    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(output, "utf8"))).toEqual({
      path: "broken.py",
      area: "diff",
      preview: "",
    });
  },
);

test("rejects parents replaced after local-diff confinement is checked", () => {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-diff-parent-race-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  const parent = join(repository, "src");
  const filename =
    process.platform === "win32" ? "handler.py" : "handler:local.py";
  mkdirSync(parent, { recursive: true });
  git(repository, "init", "-q");
  writeFileSync(join(parent, filename), "inside = 1\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "base");
  const base = git(repository, "rev-parse", "HEAD");
  writeFileSync(join(parent, filename), "inside = 2\n");

  const python = pythonExecutable();
  expect(python).not.toBeNull();
  const scripts = join(PLUGIN_ROOT, "scripts");
  const probe = [
    "import os, sys",
    "scripts, repository, base, external, parked, output, generator = sys.argv[1:]",
    "sys.path.insert(0, scripts)",
    "import generate_rank_input as ranking",
    "checked_parent = ranking.changed_path_parent_is_within_target",
    "def swap_parent(path, target):",
    "    accepted = checked_parent(path, target)",
    "    os.replace(path.parent, parked)",
    "    if os.name == 'nt':",
    "        import _winapi",
    "        _winapi.CreateJunction(external, str(path.parent))",
    "    else:",
    "        os.symlink(external, path.parent, target_is_directory=True)",
    "    return accepted",
    "if generator.startswith('safe-'):",
    "    generator = generator.removeprefix('safe-')",
    "else:",
    "    ranking.changed_path_parent_is_within_target = swap_parent",
    "if generator == 'ranking':",
    "    sys.argv = ['ranking', 'make-diff-rank-input', '--repo', repository, '--base', base, '--mode', 'local-patch', '--out', output]",
    "    ranking.main()",
    "else:",
    "    import generate_in_scope_files as inventory",
    "    sys.argv = ['inventory', '--repo', repository, '--scope', '.', '--out', output, '--diff-base', base, '--diff-mode', 'local-patch']",
    "    inventory.main()",
  ].join("\n");

  for (const generator of ["ranking", "inventory"]) {
    const external = join(root, `external-${generator}`);
    const parked = join(root, `parked-${generator}`);
    const output = join(root, `${generator}.output`);
    mkdirSync(external);
    writeFileSync(
      join(external, filename),
      generator === "ranking"
        ? "outside = 'SYNTHETIC_EXTERNAL_MARKER'\n"
        : Buffer.from("\0SYNTHETIC_EXTERNAL_MARKER"),
    );

    const runGenerator = (selected: string, destination: string) =>
      spawnSync(
        python!,
        [
          "-I",
          "-B",
          "-c",
          probe,
          scripts,
          repository,
          base,
          external,
          parked,
          destination,
          selected,
        ],
        { encoding: "utf8" },
      );
    const safeOutput = `${output}.safe`;
    const safe = runGenerator(`safe-${generator}`, safeOutput);
    expect(safe.status, `${generator}: ${safe.stderr}`).toBe(0);
    if (generator === "ranking") {
      expect(JSON.parse(readFileSync(safeOutput, "utf8"))).toMatchObject({
        path: `src/${filename}`,
        preview: "inside = 2",
      });
    } else {
      expect(readFileSync(safeOutput, "utf8")).toBe(`src/${filename}\n`);
    }

    const result = runGenerator(generator, output);

    expect(
      result.status,
      `${generator}: ${result.stdout}\n${result.stderr}`,
    ).toBe(generator === "ranking" ? 1 : 2);
    expect(result.stderr.toLowerCase()).toContain("inside the selected target");

    if (generator === "ranking") {
      unlinkSync(parent);
      renameSync(parked, parent);
    }
  }
});

test("diff inventory and previews stay inside the selected repository", async () => {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-diff-rank-")),
  );
  temporaryRoots.push(root);
  const installedPluginRoot = await upgradeBundledPlugin(root);
  const repository = join(root, "repository");
  const nested = join(repository, "src", "nested");
  const removedParent = join(repository, "removed");
  mkdirSync(nested, { recursive: true });
  mkdirSync(removedParent);
  git(repository, "init", "-q");
  writeFileSync(join(repository, "src", "handler.py"), "value = 1\n");
  writeFileSync(join(repository, "src", "deleted.py"), "removed = True\n");
  writeFileSync(join(repository, "src", "entry.py"), "handler.py");
  writeFileSync(join(nested, "linked.py"), "value = 1\n");
  writeFileSync(join(removedParent, "deleted.py"), "removed = True\n");
  git(repository, "add", ".");
  const originalLink = git(repository, "hash-object", "src/entry.py");
  git(
    repository,
    "update-index",
    "--cacheinfo",
    `120000,${originalLink},src/entry.py`,
  );
  git(repository, "commit", "-qm", "base");
  const base = git(repository, "rev-parse", "HEAD");

  writeFileSync(join(repository, "src", "handler.py"), "value = 2\n");
  writeFileSync(join(repository, "src", "entry.py"), "nested/linked.py");
  writeFileSync(join(nested, "linked.py"), "value = 2\n");
  rmSync(join(repository, "src", "deleted.py"));
  rmSync(removedParent, { recursive: true });
  git(repository, "add", ".");
  const updatedLink = git(repository, "hash-object", "src/entry.py");
  git(
    repository,
    "update-index",
    "--cacheinfo",
    `120000,${updatedLink},src/entry.py`,
  );
  git(repository, "commit", "-qm", "selected changes");
  const head = git(repository, "rev-parse", "HEAD");

  const python = pythonExecutable();
  expect(python).not.toBeNull();
  const output = join(root, "rank-input.jsonl");
  const args = [
    "-B",
    join(installedPluginRoot, "scripts", "generate_rank_input.py"),
    "make-diff-rank-input",
    "--repo",
    repository,
    "--base",
    base,
    "--head",
    head,
    "--mode",
    "local-patch",
    "--out",
    output,
  ];
  const inventoryOutput = join(root, "in-scope-files.txt");
  const inventoryArgs = [
    "-B",
    join(installedPluginRoot, "scripts", "generate_in_scope_files.py"),
    "--repo",
    repository,
    "--scope",
    ".",
    "--out",
    inventoryOutput,
    "--diff-base",
    base,
    "--diff-head",
    head,
    "--diff-mode",
    "local-patch",
  ];
  const result = spawnSync(python!, args, { encoding: "utf8" });
  const safeInventory = spawnSync(python!, inventoryArgs, {
    encoding: "utf8",
  });

  expect(result.status, result.stderr).toBe(0);
  expect(safeInventory.status, safeInventory.stderr).toBe(0);
  expect(readFileSync(inventoryOutput, "utf8")).toContain(
    "removed/deleted.py\n",
  );
  const rows = readFileSync(output, "utf8")
    .trim()
    .split("\n")
    .map((row) => JSON.parse(row) as { path: string; preview: string });
  expect(rows.map((row) => row.path)).toEqual([
    "removed/deleted.py",
    "src/deleted.py",
    "src/entry.py",
    "src/handler.py",
    "src/nested/linked.py",
  ]);
  expect(rows.find((row) => row.path === "src/handler.py")?.preview).toBe(
    "value = 2",
  );
  expect(rows.find((row) => row.path === "src/nested/linked.py")?.preview).toBe(
    "value = 2",
  );

  const externalFixture = join(root, "synthetic-fixture");
  mkdirSync(externalFixture);
  writeFileSync(join(externalFixture, "deleted.py"), "external = True\n");
  writeFileSync(join(externalFixture, "linked.py"), "synthetic = True\n");
  symlinkSync(externalFixture, removedParent, "junction");

  const escapedDeletion = spawnSync(python!, args, { encoding: "utf8" });
  const deletionInventory = spawnSync(python!, inventoryArgs, {
    encoding: "utf8",
  });
  expect([escapedDeletion.status, deletionInventory.status]).toEqual([1, 2]);
  expect(escapedDeletion.stderr).toContain(
    "Changed Git working-tree paths must stay inside the selected target.",
  );
  expect(deletionInventory.stderr).toContain(
    "changed Git working-tree paths must stay inside the selected target",
  );

  unlinkSync(removedParent);
  git(repository, "update-index", "--skip-worktree", "src/nested/linked.py");
  rmSync(nested, { recursive: true });
  symlinkSync(externalFixture, nested, "junction");

  const escaped = spawnSync(python!, args, { encoding: "utf8" });
  const inventory = spawnSync(python!, inventoryArgs, { encoding: "utf8" });
  expect([escaped.status, inventory.status]).toEqual([1, 2]);
  expect(escaped.stderr).toContain(
    "Changed Git working-tree paths must stay inside the selected target.",
  );
  expect(inventory.stderr).toContain(
    "changed Git working-tree paths must stay inside the selected target",
  );
});

test("preserves Unicode Git paths and legacy-encoded commit metadata", () => {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-diff-rank-unicode-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository-漢字");
  const source = join(repository, "src", "変更.py");
  mkdirSync(join(repository, "src"), { recursive: true });
  git(repository, "init", "-q");
  writeFileSync(source, "value = 1\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "base");
  const base = git(repository, "rev-parse", "HEAD");
  writeFileSync(source, "value = 2\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "変更");
  const head = git(repository, "rev-parse", "HEAD");
  const legacyMessage = join(root, "legacy-message");
  writeFileSync(legacyMessage, Buffer.from("café\n", "latin1"));
  git(
    repository,
    "-c",
    "i18n.commitEncoding=ISO-8859-1",
    "commit",
    "--allow-empty",
    "-q",
    "-F",
    legacyMessage,
  );
  const legacyHead = git(repository, "rev-parse", "HEAD");

  const python = pythonExecutable();
  expect(python).not.toBeNull();
  const output = join(root, "rank-input.jsonl");
  const rank = spawnSync(
    python!,
    [
      "-I",
      "-B",
      join(PLUGIN_ROOT, "scripts", "generate_rank_input.py"),
      "make-diff-rank-input",
      "--repo",
      repository,
      "--base",
      base,
      "--head",
      head,
      "--out",
      output,
    ],
    { encoding: "utf8" },
  );
  const probeSource = [
    "import json, pathlib, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_target as target",
    "import workbench_db as db",
    "repo = pathlib.Path(sys.argv[2])",
    "root, pathspec = target.git_worktree_context(repo)",
    "metadata = target.git_target_metadata(repo)",
    "diff = db.require_diff_target(repo, 'commit', None, sys.argv[3], None)",
    "print(json.dumps({'root': str(root), 'pathspec': pathspec, 'subject': metadata['commitSubject'], 'diff': diff}))",
  ].join("\n");
  const probe = spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      probeSource,
      join(PLUGIN_ROOT, "scripts"),
      repository,
      legacyHead,
    ],
    { encoding: "utf8" },
  );

  expect(rank.status, `${rank.stderr}\n${String(rank.error ?? "")}`).toBe(0);
  expect(
    readFileSync(output, "utf8")
      .trimEnd()
      .split("\n")
      .map((row) => JSON.parse(row) as { path: string; preview: string })
      .map(({ path, preview }) => ({ path, preview })),
  ).toEqual([{ path: "src/変更.py", preview: "value = 2" }]);
  expect(probe.status, probe.stderr).toBe(0);
  const target = JSON.parse(probe.stdout) as {
    root: string;
    pathspec: string;
    subject: string;
    diff: { kind: string; baseRevision: string; headRevision: string };
  };
  expect(basename(target.root)).toBe("repository-漢字");
  expect(target).toMatchObject({
    pathspec: ".",
    subject: "café",
    diff: { kind: "commit", baseRevision: head, headRevision: legacyHead },
  });
});
