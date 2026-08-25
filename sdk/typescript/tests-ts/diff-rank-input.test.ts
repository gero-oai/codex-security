import { execFileSync, spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
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
  const previous = join(root, "previous-plugin");
  cpSync(PLUGIN_ROOT, previous, { recursive: true });
  const previousManifestPath = join(previous, ".codex-plugin", "plugin.json");
  const previousManifest = JSON.parse(
    readFileSync(previousManifestPath, "utf8"),
  ) as { version: string };
  previousManifest.version = "0.1.38";
  writeFileSync(previousManifestPath, JSON.stringify(previousManifest));
  writeFileSync(
    join(previous, "scripts", "generate_rank_input.py"),
    "# synthetic previous plugin\n",
  );
  const previousMcpPath = join(previous, ".mcp.json");
  const previousMcp = JSON.parse(readFileSync(previousMcpPath, "utf8")) as {
    mcpServers: Record<string, { env_vars?: string[] }>;
  };
  const previousEnvironment =
    previousMcp.mcpServers["codex-security"]?.env_vars ?? [];
  previousMcp.mcpServers["codex-security"] = {
    ...previousMcp.mcpServers["codex-security"],
    env_vars: previousEnvironment.filter(
      (name) => name !== "CODEX_SAFETY_IDENTIFIER",
    ),
  };
  writeFileSync(previousMcpPath, JSON.stringify(previousMcp));

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
  expect(predecessor.version).toBe("0.1.38");
  expect(upgraded.version).toBe(BUNDLED_PLUGIN_VERSION);
  expect(upgraded.installedRoot).not.toBe(predecessor.installedRoot);
  const installedMcp = JSON.parse(
    readFileSync(join(upgraded.installedRoot, ".mcp.json"), "utf8"),
  ) as { mcpServers: Record<string, { env_vars?: string[] }> };
  expect(installedMcp.mcpServers["codex-security"]?.env_vars).toContain(
    "CODEX_SAFETY_IDENTIFIER",
  );
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

for (const kind of ["staged", "untracked"] as const) {
  test.skipIf(!fileSymlinksAvailable)(
    `local diff accepts ${kind} broken in-repository symlinks`,
    () => {
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
      symlinkSync("missing.py", join(repository, "broken.py"), "file");
      if (kind === "staged") {
        git(repository, "add", "broken.py");
      }

      const python = pythonExecutable();
      expect(python).not.toBeNull();
      const inventoryOutput = join(root, "in-scope-files.txt");
      const inventory = spawnSync(
        python!,
        [
          "-B",
          join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
          "--repo",
          repository,
          "--scope",
          ".",
          "--out",
          inventoryOutput,
          "--diff-base",
          base,
          "--diff-mode",
          "local-patch",
        ],
        { encoding: "utf8" },
      );
      expect(inventory.status, inventory.stderr).toBe(0);
      expect(readFileSync(inventoryOutput, "utf8")).toBe("");

      const rankingOutput = join(root, "rank-input.jsonl");
      const ranking = spawnSync(
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
          rankingOutput,
        ],
        { encoding: "utf8" },
      );
      expect(ranking.status, ranking.stderr).toBe(0);
      expect(JSON.parse(readFileSync(rankingOutput, "utf8"))).toEqual({
        path: "broken.py",
        area: "diff",
        preview: "",
      });
    },
  );
}

test("diff inventory and previews stay inside the selected repository", async () => {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-diff-rank-")),
  );
  temporaryRoots.push(root);
  const installedPluginRoot = await upgradeBundledPlugin(root);
  const repository = join(root, "repository");
  const nested = join(repository, "src", "nested");
  mkdirSync(nested, { recursive: true });
  mkdirSync(join(repository, "removed"));
  git(repository, "init", "-q");
  writeFileSync(join(repository, "src", "handler.py"), "value = 1\n");
  writeFileSync(join(repository, "removed", "deleted.py"), "removed = True\n");
  writeFileSync(join(repository, "src", "entry.py"), "handler.py");
  writeFileSync(join(nested, "linked.py"), "value = 1\n");
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
  rmSync(join(repository, "removed"), { recursive: true });
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
  const vanished = join(repository, "vanished");
  mkdirSync(vanished);
  writeFileSync(join(vanished, "added.py"), "vanished = True\n");
  git(repository, "add", "vanished/added.py");
  rmSync(vanished, { recursive: true });

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
  writeFileSync(join(externalFixture, "linked.py"), "synthetic = True\n");
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
