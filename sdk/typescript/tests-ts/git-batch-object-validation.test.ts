import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { BUNDLED_PLUGIN_VERSION, bootstrapPlugin } from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryRoots: string[] = [];
const scripts = join(PLUGIN_ROOT, "scripts");
const python =
  process.env["PYTHON"] ?? Bun.which("python3") ?? Bun.which("python");

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function git(repository: string, ...args: string[]): string {
  const result = spawnSync("git", ["-C", repository, ...args], {
    encoding: "utf8",
  });
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}

function commit(repository: string, message: string): void {
  git(
    repository,
    "-c",
    "user.name=synthetic-test",
    "-c",
    "user.email=synthetic-test@example.invalid",
    "commit",
    "--quiet",
    "-m",
    message,
  );
}

function runPython(
  source: string[],
  args: string[],
  state?: string,
  environment: NodeJS.ProcessEnv = {},
  scriptRoot = scripts,
): string {
  expect(python).not.toBeNull();
  const result = spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      ["import sys", "sys.path.insert(0, sys.argv[1])", ...source].join("\n"),
      scriptRoot,
      ...args,
    ],
    {
      encoding: "utf8",
      env: {
        PATH: process.env["PATH"],
        ...environment,
        ...(state === undefined ? {} : { CODEX_SECURITY_STATE_DIR: state }),
      },
    },
  );
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}

function runPythonJson<T>(
  source: string[],
  args: string[],
  state?: string,
  environment: NodeJS.ProcessEnv = {},
  scriptRoot = scripts,
): T {
  return JSON.parse(
    runPython(source, args, state, environment, scriptRoot),
  ) as T;
}

function createRepository(): {
  base: string;
  head: string;
  repository: string;
  root: string;
  state: string;
} {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-git-batch-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  const state = join(root, "state");
  mkdirSync(repository);
  mkdirSync(state, { mode: 0o700 });
  git(repository, "init", "--quiet");
  writeFileSync(join(repository, "fixture.txt"), "base\n");
  git(repository, "add", "fixture.txt");
  commit(repository, "base");
  const base = git(repository, "rev-parse", "HEAD");
  writeFileSync(join(repository, "fixture.txt"), "head\n");
  git(repository, "add", "fixture.txt");
  commit(repository, "head");
  return {
    base,
    head: git(repository, "rev-parse", "HEAD"),
    repository,
    root,
    state,
  };
}

async function upgradeBundledPlugin(root: string): Promise<string> {
  const previous = join(root, "previous-plugin");
  cpSync(PLUGIN_ROOT, previous, { recursive: true });
  const previousManifestPath = join(previous, ".codex-plugin", "plugin.json");
  const previousManifest = JSON.parse(
    readFileSync(previousManifestPath, "utf8"),
  ) as { version: string };
  previousManifest.version = "0.1.22";
  writeFileSync(previousManifestPath, JSON.stringify(previousManifest));
  const previousMcpPath = join(previous, ".mcp.json");
  const previousMcp = JSON.parse(readFileSync(previousMcpPath, "utf8")) as {
    mcpServers: Record<string, { env_vars?: string[] }>;
  };
  for (const server of Object.values(previousMcp.mcpServers)) {
    server.env_vars = server.env_vars?.filter(
      (name) => name !== "CODEX_SAFETY_IDENTIFIER",
    );
  }
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

  expect((await bootstrapPlugin(home, previous, options)).version).toBe(
    "0.1.22",
  );
  const upgraded = await bootstrapPlugin(home, PLUGIN_ROOT, options);
  expect(upgraded.version).not.toBe("0.1.22");
  expect(upgraded.version).toBe(BUNDLED_PLUGIN_VERSION);
  const installedMcp = JSON.parse(
    readFileSync(join(upgraded.installedRoot, ".mcp.json"), "utf8"),
  ) as { mcpServers: Record<string, { env_vars?: string[] }> };
  expect(installedMcp.mcpServers["codex-security"]?.env_vars).toContain(
    "CODEX_SAFETY_IDENTIFIER",
  );
  return upgraded.installedRoot;
}

function batchRecord(
  objectId: string,
  type: string,
  payload: Buffer,
  declaredSize = payload.length,
): Buffer {
  return Buffer.concat([
    Buffer.from(`${objectId} ${type} ${declaredSize}\n`),
    payload,
    Buffer.from("\n"),
  ]);
}

function validateBatch(requests: Buffer, output: Buffer) {
  return runPythonJson<{ accepted: boolean; error?: string }>(
    [
      "import io, json",
      "from workbench_target import validate_git_batch_blob_stream",
      "try:",
      "    validate_git_batch_blob_stream(io.BytesIO(bytes.fromhex(sys.argv[2])), io.BytesIO(bytes.fromhex(sys.argv[3])))",
      "except ValueError as error:",
      "    print(json.dumps({'accepted': False, 'error': str(error)}))",
      "else:",
      "    print(json.dumps({'accepted': True}))",
    ],
    [requests.toString("hex"), output.toString("hex")],
  );
}

function committedDigest(
  repository: string,
  state: string | undefined,
  base: string,
  head: string,
  environment: NodeJS.ProcessEnv = {},
  scriptRoot = scripts,
): string {
  return runPython(
    [
      "from pathlib import Path",
      "from workbench_target import committed_diff_content_digest",
      "print(committed_diff_content_digest(Path(sys.argv[2]), sys.argv[3], sys.argv[4]))",
    ],
    [repository, base, head],
    state,
    environment,
    scriptRoot,
  );
}

function committedObjectIdentity(
  repository: string,
  base: string,
  head: string,
  environment: NodeJS.ProcessEnv = {},
): string {
  return runPython(
    [
      "from pathlib import Path",
      "from workbench_target import committed_diff_object_identity",
      "print(committed_diff_object_identity(Path(sys.argv[2]), sys.argv[3], sys.argv[4]))",
    ],
    [repository, base, head],
    undefined,
    environment,
  );
}

describe("committed diff Git batch validation", () => {
  const firstObject = "1".repeat(40);
  const secondObject = "2".repeat(40);
  const firstRecord = batchRecord(
    firstObject,
    "blob",
    Buffer.from([0, 10, 255]),
  );
  const secondRecord = batchRecord(
    secondObject,
    "blob",
    Buffer.from("second\n"),
  );
  const firstRequest = Buffer.from(`${firstObject}\0`);
  const bothRequests = Buffer.from(`${firstObject}\0${secondObject}\0`);

  test("accepts exactly ordered, size-framed blob responses", () => {
    expect(
      validateBatch(bothRequests, Buffer.concat([firstRecord, secondRecord])),
    ).toEqual({ accepted: true });
  });

  test.each([
    ["missing", Buffer.from(`${firstObject} missing\n`), firstRequest],
    [
      "non-blob",
      batchRecord(firstObject, "tree", Buffer.from("tree")),
      firstRequest,
    ],
    ["malformed size", Buffer.from(`${firstObject} blob nope\n`), firstRequest],
    ["negative size", Buffer.from(`${firstObject} blob -1\n`), firstRequest],
    [
      "uppercase object ID",
      batchRecord("A".repeat(40), "blob", Buffer.from("blob")),
      firstRequest,
    ],
    [
      "short object ID",
      batchRecord(firstObject.slice(1), "blob", Buffer.from("blob")),
      firstRequest,
    ],
    ["unterminated header", Buffer.from(`${firstObject} blob 3`), firstRequest],
    [
      "truncated payload",
      Buffer.concat([
        Buffer.from(`${firstObject} blob 4\n`),
        Buffer.from("abc"),
      ]),
      firstRequest,
    ],
    [
      "missing payload terminator",
      Buffer.concat([
        Buffer.from(`${firstObject} blob 3\n`),
        Buffer.from("abc"),
      ]),
      firstRequest,
    ],
    ["out-of-order", Buffer.concat([secondRecord, firstRecord]), bothRequests],
    ["missing response", firstRecord, bothRequests],
    [
      "extra response",
      Buffer.concat([firstRecord, secondRecord]),
      firstRequest,
    ],
    [
      "trailing data",
      Buffer.concat([firstRecord, Buffer.from("x")]),
      firstRequest,
    ],
  ] as const)("rejects %s batch transcripts", (_name, output, requests) => {
    expect(validateBatch(requests, output)).toMatchObject({ accepted: false });
  });

  test("reads newline-bearing revision paths and binary blobs", () => {
    const { head, repository, state } = createRepository();
    const path = "line\nname.bin";
    const payload = Buffer.from([0, 10, 255, 13, 10]);
    const hashed = spawnSync(
      "git",
      ["-C", repository, "hash-object", "-w", "--stdin"],
      { encoding: "utf8", input: payload },
    );
    expect(hashed.status, hashed.stderr).toBe(0);
    git(
      repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `100644,${hashed.stdout.trim()},${path}`,
    );
    expect(existsSync(join(repository, path))).toBe(false);
    commit(repository, "binary path");
    const revision = git(repository, "rev-parse", "HEAD");
    const result = runPythonJson<{
      blobs: Array<string | null>;
      empty: unknown[];
    }>(
      [
        "import base64, json",
        "from pathlib import Path",
        "from workbench_target import git_blob_bytes",
        "requests = [sys.argv[3], sys.argv[4]]",
        "blobs = git_blob_bytes(Path(sys.argv[2]), requests)",
        "print(json.dumps({'blobs': [None if blob is None else base64.b64encode(blob).decode() for blob in blobs], 'empty': git_blob_bytes(Path(sys.argv[2]), [])}))",
      ],
      [repository, `${revision}:${path}`, `${head}:missing\npath.bin`],
      state,
    );

    expect(result).toEqual({
      blobs: [payload.toString("base64"), null],
      empty: [],
    });
  });

  test("hashes modified, added, and deleted blobs while skipping gitlinks", () => {
    const { repository, state } = createRepository();
    writeFileSync(join(repository, "modified.bin"), Buffer.from("old\n"));
    writeFileSync(join(repository, "deleted.txt"), "deleted\n");
    git(repository, "add", ".");
    commit(repository, "matrix base");
    const matrixBase = git(repository, "rev-parse", "HEAD");
    const earlierCommit = git(repository, "rev-parse", "HEAD~1");
    writeFileSync(
      join(repository, "modified.bin"),
      Buffer.from([0, 10, 255, 13, 10]),
    );
    writeFileSync(join(repository, "added.txt"), "added\n");
    rmSync(join(repository, "deleted.txt"));
    git(
      repository,
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${matrixBase},linked`,
    );
    git(repository, "add", "modified.bin", "added.txt", "deleted.txt");
    commit(repository, "matrix head");
    const matrixHead = git(repository, "rev-parse", "HEAD");
    git(
      repository,
      "update-index",
      "--cacheinfo",
      `160000,${earlierCommit},linked`,
    );
    commit(repository, "gitlink only");
    const gitlinkHead = git(repository, "rev-parse", "HEAD");

    const result = runPythonJson<{
      batchArguments: string[][];
      digests: string[];
      requestCounts: number[];
    }>(
      [
        "import json",
        "from pathlib import Path",
        "import workbench_target as target",
        "original = target.git_command",
        "request_counts, batch_arguments = [], []",
        "def tracked_git_command(repository, *args, **kwargs):",
        "    if args[:2] == ('cat-file', '--batch'):",
        "        stream = kwargs['stdin']",
        "        requests = stream.read()",
        "        stream.seek(0)",
        "        request_counts.append(requests.count(b'\\0'))",
        "        batch_arguments.append(list(args))",
        "    return original(repository, *args, **kwargs)",
        "target.git_command = tracked_git_command",
        "repository = Path(sys.argv[2])",
        "digests = [target.committed_diff_content_digest(repository, base, head) for base, head in ((sys.argv[3], sys.argv[4]), (sys.argv[4], sys.argv[5]))]",
        "print(json.dumps({'batchArguments': batch_arguments, 'digests': digests, 'requestCounts': request_counts}))",
      ],
      [repository, matrixBase, matrixHead, gitlinkHead],
      state,
    );

    expect(result.requestCounts).toEqual([4]);
    expect(result.batchArguments).toEqual([["cat-file", "--batch", "-z"]]);
    expect(result.digests).toEqual([
      expect.stringMatching(
        /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
      ),
      expect.stringMatching(
        /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
      ),
    ]);
  });

  test("materializes each distinct changed blob once while binding raw paths", () => {
    const { repository, state } = createRepository();
    const paths = Array.from(
      { length: 32 },
      (_, index) => "shared-" + index.toString().padStart(2, "0") + ".bin",
    );
    const oldPayload = Buffer.alloc(64 * 1024, 0x41);
    const newPayload = Buffer.alloc(64 * 1024, 0x42);
    for (const path of paths) writeFileSync(join(repository, path), oldPayload);
    git(repository, "add", ".");
    commit(repository, "shared blob base");
    const base = git(repository, "rev-parse", "HEAD");
    for (const path of paths) writeFileSync(join(repository, path), newPayload);
    git(repository, "add", ".");
    commit(repository, "shared blob head");
    const head = git(repository, "rev-parse", "HEAD");
    const oldObject = git(repository, "rev-parse", base + ":" + paths[0]);
    const newObject = git(repository, "rev-parse", head + ":" + paths[0]);

    const result = runPythonJson<{
      digest: string;
      objectBytes: number;
      rawNewOccurrences: number;
      rawOldOccurrences: number;
      rawPaths: string[];
      requests: string[];
    }>(
      [
        "import json, os",
        "from pathlib import Path",
        "import workbench_target as target",
        "original = target.git_command",
        "capture = {}",
        "old_object = os.fsencode(sys.argv[5])",
        "new_object = os.fsencode(sys.argv[6])",
        "def tracked_git_command(repository, *args, **kwargs):",
        "    if args[:2] == ('cat-file', '--batch'):",
        "        stream = kwargs['stdin']",
        "        position = stream.tell()",
        "        stream.seek(0)",
        "        capture['requests'] = [os.fsdecode(value) for value in stream.read().split(b'\\0') if value]",
        "        stream.seek(position)",
        "    result = original(repository, *args, **kwargs)",
        "    if '--raw' in args and '-z' in args:",
        "        stream = kwargs['stdout']",
        "        position = stream.tell()",
        "        stream.seek(0)",
        "        fields = stream.read().split(b'\\0')",
        "        stream.seek(position)",
        "        headers = fields[:-1:2]",
        "        capture['rawPaths'] = [os.fsdecode(value) for value in fields[1:-1:2]]",
        "        capture['rawOldOccurrences'] = sum(header.split()[2] == old_object for header in headers)",
        "        capture['rawNewOccurrences'] = sum(header.split()[3] == new_object for header in headers)",
        "    if args[:2] == ('cat-file', '--batch'):",
        "        stream = kwargs['stdout']",
        "        position = stream.tell()",
        "        stream.seek(0, os.SEEK_END)",
        "        capture['objectBytes'] = stream.tell()",
        "        stream.seek(position)",
        "    return result",
        "target.git_command = tracked_git_command",
        "capture['digest'] = target.committed_diff_content_digest(Path(sys.argv[2]), sys.argv[3], sys.argv[4])",
        "print(json.dumps(capture))",
      ],
      [repository, base, head, oldObject, newObject],
      state,
    );

    const { repository: singleRepository, state: singleState } =
      createRepository();
    writeFileSync(join(singleRepository, "single.bin"), oldPayload);
    git(singleRepository, "add", ".");
    commit(singleRepository, "single blob base");
    const singleBase = git(singleRepository, "rev-parse", "HEAD");
    writeFileSync(join(singleRepository, "single.bin"), newPayload);
    git(singleRepository, "add", ".");
    commit(singleRepository, "single blob head");
    const singleHead = git(singleRepository, "rev-parse", "HEAD");
    expect(git(singleRepository, "rev-parse", singleBase + ":single.bin")).toBe(
      oldObject,
    );
    expect(git(singleRepository, "rev-parse", singleHead + ":single.bin")).toBe(
      newObject,
    );
    const singleDigest = runPythonJson<{ digest: string }>(
      [
        "import json",
        "from pathlib import Path",
        "import workbench_target as target",
        "print(json.dumps({'digest': target.committed_diff_content_digest(Path(sys.argv[2]), sys.argv[3], sys.argv[4])}))",
      ],
      [singleRepository, singleBase, singleHead],
      singleState,
    ).digest;

    expect(result.rawPaths).toEqual(paths);
    expect(result.rawOldOccurrences).toBe(paths.length);
    expect(result.rawNewOccurrences).toBe(paths.length);
    expect(result.requests).toEqual([oldObject, newObject]);
    expect(result.objectBytes).toBeLessThan(newPayload.length * 3);
    expect(result.digest).not.toBe(singleDigest);
    expect(result.digest).toMatch(
      /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
    );
  });

  test("preserves trusted Git selectors while forcing local-only controls", () => {
    const { repository } = createRepository();
    const configParameters = "'safe.directory'='/synthetic/repository'";
    const result = runPythonJson<Record<string, string | null>>(
      [
        "import json, subprocess",
        "from pathlib import Path",
        "import workbench_target as target",
        "captured = {}",
        "def fake_run(command, **kwargs):",
        "    captured.update(kwargs['env'])",
        "    captured['COMMAND'] = '\\0'.join(command)",
        "    return subprocess.CompletedProcess(command, 0, b'', b'')",
        "target.subprocess.run = fake_run",
        "target.git_command(Path(sys.argv[2]), 'status', text=False, local_objects_only=True)",
        "names = ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_NO_REPLACE_OBJECTS', 'GIT_REPLACE_REF_BASE', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_ALLOW_PROTOCOL', 'GIT_NO_LAZY_FETCH', 'GIT_LITERAL_PATHSPECS', 'COMMAND')",
        "print(json.dumps({name: captured.get(name) for name in names}))",
      ],
      [repository],
      undefined,
      {
        GIT_ALLOW_PROTOCOL: "ext",
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_GLOBAL: "/synthetic/global-config",
        GIT_CONFIG_KEY_0: "safe.directory",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_PARAMETERS: configParameters,
        GIT_CONFIG_SYSTEM: "/synthetic/system-config",
        GIT_CONFIG_VALUE_0: repository,
        GIT_DIR: "/synthetic/git-dir",
        GIT_LITERAL_PATHSPECS: "0",
        GIT_NO_REPLACE_OBJECTS: "1",
        GIT_REPLACE_REF_BASE: "refs/synthetic-replacements/",
        GIT_WORK_TREE: "/synthetic/work-tree",
      },
    );

    expect(result).toMatchObject({
      GIT_DIR: null,
      GIT_WORK_TREE: null,
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_REPLACE_REF_BASE: "refs/synthetic-replacements/",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "safe.directory",
      GIT_CONFIG_VALUE_0: repository,
      GIT_CONFIG_PARAMETERS: configParameters,
      GIT_CONFIG_SYSTEM: "/synthetic/system-config",
      GIT_CONFIG_GLOBAL: "/synthetic/global-config",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_ALLOW_PROTOCOL: "",
      GIT_NO_LAZY_FETCH: "1",
      GIT_LITERAL_PATHSPECS: "1",
    });
    expect(result["COMMAND"]?.split("\0")).toContain("core.fsmonitor=false");
  });

  test("matches trusted Git replacement views", () => {
    const { base, head, repository, state } = createRepository();
    const selectedDigest = committedDigest(repository, state, base, head);
    const selectedIdentity = committedObjectIdentity(repository, base, head);
    const originalBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
    const replacement = spawnSync(
      "git",
      ["-C", repository, "hash-object", "-w", "--stdin"],
      { encoding: "utf8", input: "replacement view\n" },
    );
    expect(replacement.status, replacement.stderr).toBe(0);
    const replacementBlob = replacement.stdout.trim();
    git(
      repository,
      "update-ref",
      `refs/synthetic-replacements/${originalBlob}`,
      replacementBlob,
    );

    const replacementEnvironment = {
      GIT_REPLACE_REF_BASE: "refs/synthetic-replacements/",
    };
    expect(
      committedDigest(repository, state, base, head, replacementEnvironment),
    ).not.toBe(selectedDigest);
    expect(
      committedObjectIdentity(repository, base, head, replacementEnvironment),
    ).not.toBe(selectedIdentity);
    git(repository, "replace", "-f", originalBlob, replacementBlob);
    for (const value of ["1", ""]) {
      expect(
        committedDigest(repository, state, base, head, {
          GIT_NO_REPLACE_OBJECTS: value,
        }),
      ).toBe(selectedDigest);
    }
  });

  test("binds raw-prefix replacement refs in SHA-1 and supported SHA-256 repositories", () => {
    const { root, state } = createRepository();
    const environment = { GIT_REPLACE_REF_BASE: "refs/repl-" };

    for (const objectFormat of ["sha1", "sha256"] as const) {
      const repository = join(root, `replacement-${objectFormat}`);
      const initialized = spawnSync(
        "git",
        ["init", "--quiet", `--object-format=${objectFormat}`, repository],
        { encoding: "utf8" },
      );
      if (objectFormat === "sha256" && initialized.status !== 0) continue;
      expect(initialized.status, initialized.stderr).toBe(0);
      writeFileSync(join(repository, "fixture.txt"), "base\n");
      git(repository, "add", "fixture.txt");
      commit(repository, "base");
      const base = git(repository, "rev-parse", "HEAD");
      writeFileSync(join(repository, "fixture.txt"), "head\n");
      git(repository, "add", "fixture.txt");
      commit(repository, "head");
      const head = git(repository, "rev-parse", "HEAD");
      const originalBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
      const before = [
        committedDigest(repository, state, base, head, environment),
        committedObjectIdentity(repository, base, head, environment),
      ];
      const firstReplacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "first raw-prefix replacement\n" },
      );
      const finalReplacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "final raw-prefix replacement\n" },
      );
      expect(firstReplacement.status, firstReplacement.stderr).toBe(0);
      expect(finalReplacement.status, finalReplacement.stderr).toBe(0);
      const firstBlob = firstReplacement.stdout.trim();
      const finalBlob = finalReplacement.stdout.trim();
      git(repository, "update-ref", `refs/repl-${originalBlob}`, firstBlob);
      git(repository, "update-ref", `refs/repl-${firstBlob}`, finalBlob);
      const selected = spawnSync(
        "git",
        ["-C", repository, "cat-file", "blob", originalBlob],
        {
          encoding: "utf8",
          env: { ...process.env, ...environment },
        },
      );
      expect(selected.status, selected.stderr).toBe(0);
      expect(selected.stdout).toBe("final raw-prefix replacement\n");

      expect(
        committedDigest(repository, state, base, head, environment),
      ).not.toBe(before[0]);
      expect(
        committedObjectIdentity(repository, base, head, environment),
      ).not.toBe(before[1]);
    }
  });

  test("binds nested uppercase replacement refs in SHA-1 and supported SHA-256 repositories", () => {
    const { root, state } = createRepository();
    const replacementRefBase = "refs/synthetic-replacements/";
    const environment = { GIT_REPLACE_REF_BASE: replacementRefBase };

    for (const objectFormat of ["sha1", "sha256"] as const) {
      const repository = join(root, `nested-replacement-${objectFormat}`);
      const initialized = spawnSync(
        "git",
        ["init", "--quiet", `--object-format=${objectFormat}`, repository],
        { encoding: "utf8" },
      );
      if (objectFormat === "sha256" && initialized.status !== 0) continue;
      expect(initialized.status, initialized.stderr).toBe(0);
      writeFileSync(join(repository, "fixture.txt"), "base\n");
      git(repository, "add", "fixture.txt");
      commit(repository, "base");
      const base = git(repository, "rev-parse", "HEAD");
      writeFileSync(join(repository, "fixture.txt"), "head\n");
      git(repository, "add", "fixture.txt");
      commit(repository, "head");
      const head = git(repository, "rev-parse", "HEAD");
      const originalBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
      const before = [
        committedDigest(repository, state, base, head, environment),
        committedObjectIdentity(repository, base, head, environment),
      ];
      const replacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "nested uppercase replacement\n" },
      );
      expect(replacement.status, replacement.stderr).toBe(0);
      const replacementBlob = replacement.stdout.trim();
      git(
        repository,
        "update-ref",
        `${replacementRefBase}nested/${originalBlob.toUpperCase()}`,
        replacementBlob,
      );
      const selected = spawnSync(
        "git",
        ["-C", repository, "cat-file", "blob", originalBlob],
        {
          encoding: "utf8",
          env: { ...process.env, ...environment },
        },
      );
      expect(selected.status, selected.stderr).toBe(0);
      expect(selected.stdout).toBe("nested uppercase replacement\n");

      expect(
        committedDigest(repository, state, base, head, environment),
      ).not.toBe(before[0]);
      expect(
        committedObjectIdentity(repository, base, head, environment),
      ).not.toBe(before[1]);
    }
  });

  test("freezes packed replacement refs without Windows-reserved loose paths", () => {
    const { root, state } = createRepository();
    const replacementRefBase = "refs/replace/AUX/";
    const environment = { GIT_REPLACE_REF_BASE: replacementRefBase };

    for (const objectFormat of ["sha1", "sha256"] as const) {
      const repository = join(root, `packed-replacement-${objectFormat}`);
      const initialized = spawnSync(
        "git",
        ["init", "--quiet", `--object-format=${objectFormat}`, repository],
        { encoding: "utf8" },
      );
      if (objectFormat === "sha256" && initialized.status !== 0) continue;
      expect(initialized.status, initialized.stderr).toBe(0);
      writeFileSync(join(repository, "fixture.txt"), "base\n");
      git(repository, "add", "fixture.txt");
      commit(repository, "base");
      const base = git(repository, "rev-parse", "HEAD");
      writeFileSync(join(repository, "fixture.txt"), "head\n");
      git(repository, "add", "fixture.txt");
      commit(repository, "head");
      const head = git(repository, "rev-parse", "HEAD");
      const originalBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
      const originalDigest = committedDigest(
        repository,
        state,
        base,
        head,
        environment,
      );
      const replacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "packed replacement\n" },
      );
      expect(replacement.status, replacement.stderr).toBe(0);
      const replacementBlob = replacement.stdout.trim();
      const replacementRef = `${replacementRefBase}${originalBlob}`;
      const gitDirectory = git(repository, "rev-parse", "--absolute-git-dir");
      const packedRefs = join(gitDirectory, "packed-refs");
      expect(existsSync(packedRefs)).toBeFalse();
      writeFileSync(
        packedRefs,
        `# pack-refs with: sorted\n${replacementBlob} ${replacementRef}\n`,
      );
      expect(
        existsSync(join(gitDirectory, ...replacementRef.split("/"))),
      ).toBeFalse();
      expect(readFileSync(packedRefs, "utf8")).toContain(
        `${replacementBlob} ${replacementRef}\n`,
      );

      const selected = spawnSync(
        "git",
        ["-C", repository, "cat-file", "blob", originalBlob],
        {
          encoding: "utf8",
          env: { ...process.env, ...environment },
        },
      );
      expect(selected.status, selected.stderr).toBe(0);
      expect(selected.stdout).toBe("packed replacement\n");
      const expectedDigest = committedDigest(
        repository,
        state,
        base,
        head,
        environment,
      );
      expect(expectedDigest).not.toBe(originalDigest);

      const result = runPythonJson<{ digest: string }>(
        [
          "import json",
          "from pathlib import Path",
          "import workbench_target as target",
          "reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}",
          "original_mkdir = Path.mkdir",
          "original_write_bytes = Path.write_bytes",
          "def reject_reserved(path):",
          "    for part in path.parts:",
          "        if part.rstrip(' .').split('.', 1)[0].upper() in reserved:",
          "            raise OSError('synthetic Windows-reserved path')",
          "def windows_mkdir(path, *args, **kwargs):",
          "    reject_reserved(path)",
          "    return original_mkdir(path, *args, **kwargs)",
          "def windows_write_bytes(path, data):",
          "    reject_reserved(path)",
          "    return original_write_bytes(path, data)",
          "Path.mkdir = windows_mkdir",
          "Path.write_bytes = windows_write_bytes",
          "try:",
          "    digest = target.committed_diff_content_digest(Path(sys.argv[2]), sys.argv[3], sys.argv[4])",
          "finally:",
          "    Path.mkdir = original_mkdir",
          "    Path.write_bytes = original_write_bytes",
          "print(json.dumps({'digest': digest}))",
        ],
        [repository, base, head],
        state,
        environment,
      );
      expect(result.digest).toBe(expectedDigest);
    }
  });

  test.each([
    ["a repository-local disable", false, false],
    ["a repository-local enable over a global disable", true, true],
  ] as const)(
    "preserves %s of replacement refs in the frozen view",
    (_label, localReplacementSetting, expectsReplacement) => {
      const { base, head, repository, root, state } = createRepository();
      const originalDigest = committedDigest(repository, state, base, head);
      const originalBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
      const replacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "replacement policy\n" },
      );
      expect(replacement.status, replacement.stderr).toBe(0);
      git(repository, "replace", "-f", originalBlob, replacement.stdout.trim());
      const replacementDigest = committedDigest(repository, state, base, head);
      expect(replacementDigest).not.toBe(originalDigest);

      git(
        repository,
        "config",
        "core.useReplaceRefs",
        String(localReplacementSetting),
      );
      const globalConfig = join(root, "global.gitconfig");
      writeFileSync(globalConfig, "[core]\n\tuseReplaceRefs = false\n");
      const environment = expectsReplacement
        ? { GIT_CONFIG_GLOBAL: globalConfig }
        : {};

      expect(committedDigest(repository, state, base, head, environment)).toBe(
        expectsReplacement ? replacementDigest : originalDigest,
      );
    },
  );

  test("opens frozen committed views explicitly", () => {
    const { base, head, repository, root, state } = createRepository();
    const globalConfig = join(root, "global.gitconfig");
    writeFileSync(globalConfig, "[safe]\n\tbareRepository = explicit\n");

    expect(
      committedDigest(repository, state, base, head, {
        GIT_CONFIG_GLOBAL: globalConfig,
        GIT_CONFIG_NOSYSTEM: "1",
      }),
    ).toMatch(/^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u);
  });

  test.skipIf(process.platform === "win32")(
    "supports line-break-bearing quoted repository paths",
    () => {
      for (const separator of ["\n", "\r"]) {
        const { base, head, repository, root, state } = createRepository();
        const expected = committedDigest(repository, state, base, head);
        const relocated = join(root, `repository${separator}"quoted`);
        renameSync(repository, relocated);

        expect(committedDigest(relocated, state, base, head)).toBe(expected);
      }
    },
  );

  test("preserves the source repository's supported alternates depth", () => {
    const { base, head, repository, root, state } = createRepository();
    const objectDirectory = git(
      repository,
      "rev-parse",
      "--path-format=absolute",
      "--git-path",
      "objects",
    );
    const alternateDirectories = Array.from({ length: 6 }, (_, index) =>
      join(root, `alternate-${index}`),
    );
    for (const directory of alternateDirectories) {
      mkdirSync(join(directory, "info"), { recursive: true });
      mkdirSync(join(directory, "pack"));
    }
    const deepest = alternateDirectories.at(-1)!;
    for (const entry of readdirSync(objectDirectory)) {
      if (entry !== "info" && entry !== "pack") {
        renameSync(join(objectDirectory, entry), join(deepest, entry));
      }
    }
    const chain = [objectDirectory, ...alternateDirectories];
    for (let index = 0; index < chain.length - 1; index += 1) {
      writeFileSync(
        join(chain[index]!, "info", "alternates"),
        `${chain[index + 1]}\n`,
      );
    }

    git(repository, "cat-file", "-e", `${head}^{commit}`);
    expect(committedDigest(repository, state, base, head)).toMatch(
      /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
    );
  });

  test("binds a replacement chain while the source view toggles at every boundary", () => {
    const { base, head, repository, state } = createRepository();
    const originalDigest = committedDigest(repository, state, base, head);
    const originalIdentity = committedObjectIdentity(repository, base, head);
    const originalBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
    const firstReplacement = spawnSync(
      "git",
      ["-C", repository, "hash-object", "-w", "--stdin"],
      { encoding: "utf8", input: "first replacement\n" },
    );
    const finalReplacement = spawnSync(
      "git",
      ["-C", repository, "hash-object", "-w", "--stdin"],
      { encoding: "utf8", input: "final replacement\n" },
    );
    expect(firstReplacement.status, firstReplacement.stderr).toBe(0);
    expect(finalReplacement.status, finalReplacement.stderr).toBe(0);
    const firstBlob = firstReplacement.stdout.trim();
    const finalBlob = finalReplacement.stdout.trim();
    git(repository, "replace", "-f", originalBlob, firstBlob);
    git(repository, "replace", "-f", firstBlob, finalBlob);

    const result = runPythonJson<{
      expected: [string, string];
      final: [string, string];
      identityCalls: number;
      pair: [string, string];
      privateView: boolean;
      residue: string[];
      viewCount: number;
    }>(
      [
        "import json, os, stat, subprocess",
        "from pathlib import Path",
        "import workbench_target as target",
        "repository, state = Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve()",
        "base, head, original_blob, first_blob, final_blob = sys.argv[4:9]",
        "original_ref = f'refs/replace/{original_blob}'",
        "first_ref = f'refs/replace/{first_blob}'",
        "def update(ref, object_id=None):",
        "    command = ['git', '-C', str(repository), 'update-ref']",
        "    command.extend(['-d', ref] if object_id is None else [ref, object_id])",
        "    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)",
        "def set_replacements(view):",
        "    update(original_ref)",
        "    update(first_ref)",
        "    if view in {'first', 'chain'}:",
        "        update(original_ref, first_blob)",
        "    if view == 'chain':",
        "        update(first_ref, final_blob)",
        "expected = target.committed_diff_content_snapshot(repository, base, head)",
        "original_create = target._create_committed_diff_view",
        "original_digest = target._committed_diff_content_digest",
        "original_identity = target._committed_diff_object_identity",
        "views, modes = [], []",
        "identity_calls = 0",
        "def tracked_create(source, view):",
        "    object_directory = original_create(source, view)",
        "    views.append(view)",
        "    modes.append(stat.S_IMODE(view.parent.stat().st_mode))",
        "    set_replacements('none')",
        "    return object_directory",
        "def tracked_identity(*args, **kwargs):",
        "    global identity_calls",
        "    set_replacements('first' if identity_calls == 0 else 'none')",
        "    identity_calls += 1",
        "    result = original_identity(*args, **kwargs)",
        "    set_replacements('none' if identity_calls == 1 else 'first')",
        "    return result",
        "def tracked_digest(*args, **kwargs):",
        "    set_replacements('none')",
        "    result = original_digest(*args, **kwargs)",
        "    set_replacements('first')",
        "    return result",
        "target._create_committed_diff_view = tracked_create",
        "target._committed_diff_content_digest = tracked_digest",
        "target._committed_diff_object_identity = tracked_identity",
        "try:",
        "    pair = target.committed_diff_content_snapshot(repository, base, head)",
        "finally:",
        "    target._create_committed_diff_view = original_create",
        "    target._committed_diff_content_digest = original_digest",
        "    target._committed_diff_object_identity = original_identity",
        "    set_replacements('chain')",
        "final = target.committed_diff_content_snapshot(repository, base, head)",
        "def outside_source(path):",
        "    try:",
        "        path.resolve().relative_to(repository)",
        "    except ValueError:",
        "        return True",
        "    return False",
        "private_view = all(outside_source(view) for view in views) and (os.name == 'nt' or modes == [0o700])",
        "print(json.dumps({'expected': expected, 'final': final, 'identityCalls': identity_calls, 'pair': pair, 'privateView': private_view, 'residue': sorted(entry.name for entry in state.iterdir()), 'viewCount': len(views)}))",
      ],
      [repository, state, base, head, originalBlob, firstBlob, finalBlob],
      state,
    );

    expect(result.pair).toEqual(result.expected);
    expect(result.final).toEqual(result.expected);
    expect(result.expected[0]).not.toBe(originalDigest);
    expect(result.expected[1]).not.toBe(originalIdentity);
    expect(result).toMatchObject({
      identityCalls: 2,
      privateView: true,
      residue: [],
      viewCount: 1,
    });
  });

  test("cleans private views without mutating target Git metadata", () => {
    const { base, head, repository, state } = createRepository();
    const result = runPythonJson<{
      error: string;
      privateViews: boolean;
      residue: string[];
      sourceUnchanged: boolean;
      viewsRemoved: boolean;
    }>(
      [
        "import hashlib, json, subprocess",
        "from pathlib import Path",
        "import workbench_target as target",
        "repository, state = Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve()",
        "base, head = sys.argv[4:6]",
        "git_dir = Path(subprocess.check_output(['git', '-C', str(repository), 'rev-parse', '--absolute-git-dir'], text=True).strip()).resolve()",
        "def fingerprint():",
        "    result = {}",
        "    for name in ('HEAD', 'config', 'index', 'packed-refs', 'shallow'):",
        "        path = git_dir / name",
        "        result[name] = None if not path.is_file() else hashlib.sha256(path.read_bytes()).hexdigest()",
        "    for root_name in ('refs', 'logs', 'objects'):",
        "        root = git_dir / root_name",
        "        if root.is_dir():",
        "            for path in sorted(entry for entry in root.rglob('*') if entry.is_file()):",
        "                result[path.relative_to(git_dir).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()",
        "    return result",
        "before = fingerprint()",
        "original_create = target._create_committed_diff_view",
        "views = []",
        "def tracked_create(source, view):",
        "    views.append(view)",
        "    return original_create(source, view)",
        "target._create_committed_diff_view = tracked_create",
        "target.committed_diff_content_snapshot(repository, base, head)",
        "after_success = fingerprint()",
        "original_digest = target._committed_diff_content_digest",
        "def unavailable(*args, **kwargs):",
        "    raise SystemExit('synthetic snapshot failure')",
        "target._committed_diff_content_digest = unavailable",
        "try:",
        "    target.committed_diff_content_snapshot(repository, base, head)",
        "except SystemExit as exc:",
        "    error = str(exc)",
        "finally:",
        "    target._create_committed_diff_view = original_create",
        "    target._committed_diff_content_digest = original_digest",
        "after_failure = fingerprint()",
        "def outside_source(path):",
        "    try:",
        "        path.resolve().relative_to(repository)",
        "    except ValueError:",
        "        return True",
        "    return False",
        "print(json.dumps({'error': error, 'privateViews': len(views) == 2 and all(outside_source(view) for view in views), 'residue': sorted(entry.name for entry in state.iterdir()), 'sourceUnchanged': before == after_success == after_failure, 'viewsRemoved': all(not view.exists() for view in views)}))",
      ],
      [repository, state, base, head],
      state,
    );

    expect(result).toEqual({
      error: "synthetic snapshot failure",
      privateViews: true,
      residue: [],
      sourceUnchanged: true,
      viewsRemoved: true,
    });
  });

  test.each([
    ["a non-HEAD working-tree base", "working_tree"],
    ["equal resolved refs", "range"],
  ] as const)(
    "accepts a CLI registration with %s behind a writer lock",
    (_label, selection) => {
      const { base, head, repository, root, state } = createRepository();
      const requestedBase = selection === "working_tree" ? "HEAD~1" : "HEAD~0";
      const expectedBase = selection === "working_tree" ? base : head;
      const scanDirectory = join(root, "compatible-cli-scan");
      mkdirSync(scanDirectory, { mode: 0o700 });

      const result = runPythonJson<{
        beginAttempted: boolean;
        counts: { scans: number; workspaces: number };
        error: string | null;
        inTransaction: boolean;
        persisted: {
          baseRevision: string;
          contentDigest: string;
          headRevision: string;
          kind: string;
        } | null;
        started: boolean;
      }>(
        [
          "import argparse, json, threading",
          "import workbench_db as workbench",
          "selection, repository, scan_directory, selected_base, selected_head = sys.argv[2:7]",
          "recipe_kind = 'working_tree' if selection == 'working_tree' else 'refs'",
          "recipe = {'config': {}, 'mode': 'standard', 'repository': repository, 'target': {'kind': recipe_kind, 'paths': [], 'base': selected_base, 'head': selected_head}}",
          "arguments = argparse.Namespace(repository=repository, scan_dir=scan_directory, registration_json_stdin=False, recipe_json_stdin=False, recipe_json=json.dumps(recipe), archive_existing=False, archived_scan_dir=None, parent_scan_id=None)",
          "begin_attempted = threading.Event()",
          "connection_ready = threading.Event()",
          "start_worker = threading.Event()",
          "outcome = {'error': None, 'inTransaction': None, 'started': False}",
          "class TrackedConnection:",
          "    def __init__(self, delegate):",
          "        self.delegate = delegate",
          "    def execute(self, sql, *args):",
          "        if sql.strip().upper() == 'BEGIN IMMEDIATE':",
          "            begin_attempted.set()",
          "        return self.delegate.execute(sql, *args)",
          "    def __getattr__(self, name):",
          "        return getattr(self.delegate, name)",
          "def worker():",
          "    with workbench.connect() as connection:",
          "        connection_ready.set()",
          "        if not start_worker.wait(5):",
          "            outcome['error'] = 'worker start timed out'",
          "            return",
          "        try:",
          "            workbench.register_cli_scan(TrackedConnection(connection), arguments)",
          "        except SystemExit as error:",
          "            outcome['error'] = str(error)",
          "        else:",
          "            outcome['started'] = True",
          "        outcome['inTransaction'] = connection.in_transaction",
          "thread = threading.Thread(target=worker)",
          "thread.start()",
          "if not connection_ready.wait(5):",
          "    raise RuntimeError('worker connection timed out')",
          "with workbench.connect() as blocker:",
          "    blocker.execute('BEGIN IMMEDIATE')",
          "    start_worker.set()",
          "    if not begin_attempted.wait(5):",
          "        raise RuntimeError('registration did not reach writer lock')",
          "    blocker.commit()",
          "thread.join(10)",
          "if thread.is_alive():",
          "    raise RuntimeError('registration worker did not finish')",
          "with workbench.connect() as connection:",
          "    counts = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('workspaces', 'scans')}",
          "    row = connection.execute('SELECT diff_target_kind, diff_base_revision, diff_head_revision, diff_content_digest FROM workspaces').fetchone()",
          "    persisted = None if row is None else {'kind': row['diff_target_kind'], 'baseRevision': row['diff_base_revision'], 'headRevision': row['diff_head_revision'], 'contentDigest': row['diff_content_digest']}",
          "print(json.dumps({'beginAttempted': begin_attempted.is_set(), 'counts': counts, 'persisted': persisted, **outcome}))",
        ],
        [selection, repository, scanDirectory, requestedBase, "HEAD"],
        state,
      );

      expect(result.beginAttempted).toBe(true);
      expect(result.counts).toEqual({ scans: 1, workspaces: 1 });
      expect(result.error).toBeNull();
      expect(result.inTransaction).toBe(false);
      expect(result.persisted).toEqual({
        baseRevision: expectedBase,
        contentDigest: expect.stringMatching(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        ),
        headRevision: head,
        kind: selection,
      });
      expect(result.started).toBe(true);
    },
  );

  test.each([
    ["submitted", "progress"],
    ["prompt", "progress"],
    ["cli", "progress"],
    ["prompt", "completion"],
  ] as const)(
    "does not hold the SQLite writer lock during a slow %s committed snapshot while an unrelated %s is written",
    (operation, writeOperation) => {
      const { base, head, repository, root, state } = createRepository();
      const result = runPythonJson<{
        identityTransactions: boolean[];
        scanCount: number;
        unrelatedStatus: string;
        writeError: string | null;
        writeSucceeded: boolean;
        snapshotCalls: number;
        snapshotTransactions: boolean[];
        startError: string | null;
        started: boolean;
      }>(
        [
          "import argparse, json, os, shutil, threading, uuid",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "operation, write_operation, repository, base, head, root, plugin_root = sys.argv[2:9]",
          "root_path = Path(root)",
          "unrelated_scan_root = root_path / 'unrelated-scans'",
          "unrelated_scan_root.mkdir(mode=0o700)",
          "unrelated_args = argparse.Namespace(thread_id=f'unrelated-{operation}', target_path=repository, scope='.', mode='standard', target_summary=None, user_context=None, user_context_stdin=False, diff_target_kind=None, diff_base_revision=None, diff_head_revision=None, diff_content_digest=None, scan_root=str(unrelated_scan_root), model=None, reasoning_effort=None)",
          "with workbench.connect() as connection:",
          "    unrelated = workbench.start_prompt_only_scan(connection, unrelated_args)",
          "    unrelated_scan_id = unrelated['scan']['scanId']",
          "completion_args = argparse.Namespace(scan_id=unrelated_scan_id, claim_token=None, cost_json=None, thread_id=None)",
          "if write_operation == 'completion':",
          "    with workbench.connect() as connection:",
          "        scan = workbench.require_scan(connection, unrelated_scan_id)",
          "        scan_dir = Path(scan['scan_dir'])",
          "        shutil.copytree(Path(plugin_root) / 'examples' / 'completed-scan', scan_dir, dirs_exist_ok=True)",
          "        if os.name != 'nt':",
          "            scan_dir.parent.chmod(0o700)",
          "            scan_dir.chmod(0o700)",
          "        manifest_path = scan_dir / 'scan-manifest.json'",
          "        manifest = json.loads(manifest_path.read_text())",
          "        manifest['scan']['id'] = unrelated_scan_id",
          "        manifest['scan']['target']['kind'] = workbench.expected_target_kinds(scan)[0]",
          "        manifest['scan'].pop('sealedAt', None)",
          "        manifest['scan'].pop('artifacts', None)",
          "        manifest_path.write_text(json.dumps(manifest))",
          "        for name in ('findings.json', 'coverage.json'):",
          "            path = scan_dir / name",
          "            document = json.loads(path.read_text())",
          "            document['scanId'] = unrelated_scan_id",
          "            path.write_text(json.dumps(document))",
          "        workbench.complete_scan(connection, completion_args, prepare_only=True)",
          "        prepared_completed_at = json.loads(manifest_path.read_text())['scan']['completedAt']",
          "    workbench.now = lambda: prepared_completed_at",
          "workspace_id = str(uuid.uuid4())",
          "if operation == 'submitted':",
          "    create_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=None, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='standard', diff_target_kind=None, diff_base_revision=None, diff_head_revision=None, diff_content_digest=None)",
          "    save_args = argparse.Namespace(workspace_id=workspace_id, target_path=repository, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='range', diff_base_revision=base, diff_head_revision=head, diff_content_digest=None)",
          "    with workbench.connect() as connection:",
          "        workbench.create_workspace(connection, create_args)",
          "        workbench.save_workspace(connection, save_args)",
          "prompt_args = argparse.Namespace(thread_id=f'slow-{operation}', target_path=repository, scope='.', mode='diff', target_summary=None, user_context=None, user_context_stdin=False, diff_target_kind='range', diff_base_revision=base, diff_head_revision=head, diff_content_digest=None, scan_root=str(root_path / 'prompt-scans'), model=None, reasoning_effort=None)",
          "(root_path / 'prompt-scans').mkdir(mode=0o700)",
          "scan_directory = root_path / 'cli-scan'",
          "scan_directory.mkdir(mode=0o700)",
          "recipe = {'config': {}, 'mode': 'standard', 'repository': repository, 'target': {'kind': 'refs', 'paths': [], 'base': base, 'head': head}}",
          "cli_args = argparse.Namespace(repository=repository, scan_dir=str(scan_directory), registration_json_stdin=False, recipe_json_stdin=False, recipe_json=json.dumps(recipe), archive_existing=False, archived_scan_dir=None, parent_scan_id=None)",
          "submitted_args = argparse.Namespace(workspace_id=workspace_id, scan_root=str(root_path / 'submitted-scans'), model=None, reasoning_effort=None)",
          "original_snapshot = workbench.committed_diff_content_snapshot",
          "original_identity = workbench.committed_diff_object_identity",
          "snapshot_started = threading.Event()",
          "release_snapshot = threading.Event()",
          "worker_connection = None",
          "identity_transactions = []",
          "snapshot_calls = 0",
          "snapshot_transactions = []",
          "def slow_snapshot(*args):",
          "    global snapshot_calls",
          "    snapshot_calls += 1",
          "    snapshot_transactions.append(bool(worker_connection and worker_connection.in_transaction))",
          "    snapshot = original_snapshot(*args)",
          "    if snapshot_calls == 2:",
          "        snapshot_started.set()",
          "        if not release_snapshot.wait(5):",
          "            raise RuntimeError('slow snapshot release timed out')",
          "    return snapshot",
          "def counted_identity(*args):",
          "    identity_transactions.append(bool(worker_connection and worker_connection.in_transaction))",
          "    return original_identity(*args)",
          "workbench.committed_diff_content_snapshot = slow_snapshot",
          "workbench.committed_diff_object_identity = counted_identity",
          "outcome = {'startError': None, 'started': False}",
          "def worker():",
          "    global worker_connection",
          "    with workbench.connect() as connection:",
          "        worker_connection = connection",
          "        try:",
          "            if operation == 'submitted':",
          "                workbench.start_scan(connection, submitted_args)",
          "            elif operation == 'prompt':",
          "                workbench.start_prompt_only_scan(connection, prompt_args)",
          "            else:",
          "                workbench.register_cli_scan(connection, cli_args)",
          "        except BaseException as error:",
          "            outcome['startError'] = f'{type(error).__name__}: {error}'",
          "        else:",
          "            outcome['started'] = True",
          "progress_args = argparse.Namespace(scan_id=unrelated_scan_id, model=None, reasoning_effort=None, preflight_issues_json_stdin=False, preflight_issues_json=None, coordinator_generation=None, claim_token=None, deep_review_pass=None, phase=None, phase_items_total=None, phase_items_completed=None, phase_progress_unit=None, review_items_total=None, review_items_completed=None, reportable_findings_count=None)",
          "thread = threading.Thread(target=worker)",
          "with workbench.connect() as write_connection:",
          "    write_connection.execute('PRAGMA busy_timeout = 200')",
          "    thread.start()",
          "    if not snapshot_started.wait(5):",
          "        raise RuntimeError('slow snapshot did not start')",
          "    try:",
          "        if write_operation == 'progress':",
          "            workbench.progress.update_progress(write_connection, progress_args, now=workbench.now, require_scan=workbench.require_scan, scan_context=workbench.scan_context)",
          "        else:",
          "            workbench.complete_scan(write_connection, completion_args, prepare_only=False)",
          "    except BaseException as error:",
          "        write_error = f'{type(error).__name__}: {error}'",
          "        write_succeeded = False",
          "    else:",
          "        write_error = None",
          "        write_succeeded = True",
          "release_snapshot.set()",
          "thread.join(10)",
          "if thread.is_alive():",
          "    raise RuntimeError('start worker did not finish')",
          "with workbench.connect() as connection:",
          "    scan_count = connection.execute('SELECT COUNT(*) FROM scans').fetchone()[0]",
          "    unrelated_status = workbench.require_scan(connection, unrelated_scan_id)['status']",
          "print(json.dumps({'identityTransactions': identity_transactions, 'scanCount': scan_count, 'snapshotCalls': snapshot_calls, 'snapshotTransactions': snapshot_transactions, 'unrelatedStatus': unrelated_status, 'writeError': write_error, 'writeSucceeded': write_succeeded, **outcome}))",
        ],
        [operation, writeOperation, repository, base, head, root, PLUGIN_ROOT],
        state,
      );

      expect(result).toMatchObject({
        identityTransactions: [true],
        scanCount: 2,
        snapshotCalls: 2,
        snapshotTransactions: [false, false],
        startError: null,
        started: true,
        unrelatedStatus:
          writeOperation === "completion" ? "complete" : "running",
        writeError: null,
        writeSucceeded: true,
      });
    },
  );

  test.each(["working_tree", "commit"] as const)(
    "rejoins an active submitted %s scan before revalidating an unavailable target",
    (kind) => {
      const { base, head, repository, root, state } = createRepository();
      const result = runPythonJson<{
        activeMatchesCreated: boolean;
        beginAttempted: boolean;
        error: string | null;
        inTransaction: boolean;
        scanCount: number;
        started: boolean;
        targetExists: boolean;
      }>(
        [
          "import argparse, json, threading, uuid",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "kind, repository, base, head, root = sys.argv[2:7]",
          "workspace_id = str(uuid.uuid4())",
          "selected_base = head if kind == 'working_tree' else base",
          "create_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=repository, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind=kind, diff_base_revision=selected_base, diff_head_revision=head, diff_content_digest=None)",
          "start_args = argparse.Namespace(workspace_id=workspace_id, scan_root=str(Path(root) / 'submitted-scans'), model=None, reasoning_effort=None)",
          "with workbench.connect() as connection:",
          "    workbench.create_workspace(connection, create_args)",
          "    workbench.save_workspace(connection, create_args)",
          "begin_attempted = threading.Event()",
          "connection_ready = threading.Event()",
          "start_worker = threading.Event()",
          "outcome = {'error': None, 'inTransaction': None, 'started': False}",
          "class TrackedConnection:",
          "    def __init__(self, delegate):",
          "        self.delegate = delegate",
          "    def execute(self, sql, *args):",
          "        if sql.strip().upper() == 'BEGIN IMMEDIATE':",
          "            begin_attempted.set()",
          "        return self.delegate.execute(sql, *args)",
          "    def __getattr__(self, name):",
          "        return getattr(self.delegate, name)",
          "def worker():",
          "    with workbench.connect() as delegate:",
          "        connection_ready.set()",
          "        if not start_worker.wait(5):",
          "            outcome['error'] = 'worker start timed out'",
          "            return",
          "        try:",
          "            workbench.start_scan(TrackedConnection(delegate), start_args)",
          "        except BaseException as error:",
          "            outcome['error'] = f'{type(error).__name__}: {error}'",
          "        else:",
          "            outcome['started'] = True",
          "        outcome['inTransaction'] = delegate.in_transaction",
          "thread = threading.Thread(target=worker)",
          "thread.start()",
          "if not connection_ready.wait(5):",
          "    raise RuntimeError('worker connection timed out')",
          "with workbench.connect() as blocker:",
          "    blocker.execute('BEGIN IMMEDIATE')",
          "    start_worker.set()",
          "    if not begin_attempted.wait(5):",
          "        raise RuntimeError('scan did not reach writer lock')",
          "    workbench.start_scan(blocker, start_args)",
          "    created_scan_id = blocker.execute('SELECT active_scan_id FROM workspaces WHERE id = ?', (workspace_id,)).fetchone()['active_scan_id']",
          "    Path(repository).rename(Path(root) / 'parked-repository')",
          "    blocker.commit()",
          "thread.join(10)",
          "if thread.is_alive():",
          "    raise RuntimeError('scan worker did not finish')",
          "with workbench.connect() as connection:",
          "    active_scan_id = connection.execute('SELECT active_scan_id FROM workspaces WHERE id = ?', (workspace_id,)).fetchone()['active_scan_id']",
          "    scan_count = connection.execute('SELECT COUNT(*) FROM scans WHERE workspace_id = ?', (workspace_id,)).fetchone()[0]",
          "print(json.dumps({'activeMatchesCreated': active_scan_id == created_scan_id, 'beginAttempted': begin_attempted.is_set(), 'scanCount': scan_count, 'targetExists': Path(repository).exists(), **outcome}))",
        ],
        [kind, repository, base, head, root],
        state,
      );

      expect(result).toEqual({
        activeMatchesCreated: true,
        beginAttempted: true,
        error: null,
        inTransaction: false,
        scanCount: 1,
        started: true,
        targetExists: false,
      });
    },
  );

  test.each(["commit", "range"] as const)(
    "rejoins an active submitted %s scan when external inspection fails after another start",
    (kind) => {
      const { base, head, repository, root, state } = createRepository();
      const result = runPythonJson<{
        activeMatchesCreated: boolean;
        error: string | null;
        inTransaction: boolean;
        scanCount: number;
        started: boolean;
        targetExists: boolean;
        workerSnapshotCalls: number;
      }>(
        [
          "import argparse, json, threading, uuid",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "kind, repository, base, head, root = sys.argv[2:7]",
          "workspace_id = str(uuid.uuid4())",
          "create_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=repository, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind=kind, diff_base_revision=base, diff_head_revision=head, diff_content_digest=None)",
          "start_args = argparse.Namespace(workspace_id=workspace_id, scan_root=str(Path(root) / 'submitted-scans'), model=None, reasoning_effort=None)",
          "with workbench.connect() as connection:",
          "    workbench.create_workspace(connection, create_args)",
          "    workbench.save_workspace(connection, create_args)",
          "inspection_started = threading.Event()",
          "release_inspection = threading.Event()",
          "worker_identifier = None",
          "worker_snapshot_calls = 0",
          "original_snapshot = workbench.committed_diff_content_snapshot",
          "def delayed_snapshot(*args):",
          "    global worker_snapshot_calls",
          "    if threading.get_ident() == worker_identifier:",
          "        worker_snapshot_calls += 1",
          "        if worker_snapshot_calls == 2:",
          "            inspection_started.set()",
          "            if not release_inspection.wait(5):",
          "                raise RuntimeError('inspection release timed out')",
          "    return original_snapshot(*args)",
          "workbench.committed_diff_content_snapshot = delayed_snapshot",
          "outcome = {'error': None, 'inTransaction': None, 'started': False}",
          "def worker():",
          "    global worker_identifier",
          "    worker_identifier = threading.get_ident()",
          "    with workbench.connect() as connection:",
          "        try:",
          "            workbench.start_scan(connection, start_args)",
          "        except BaseException as error:",
          "            outcome['error'] = f'{type(error).__name__}: {error}'",
          "        else:",
          "            outcome['started'] = True",
          "        outcome['inTransaction'] = connection.in_transaction",
          "thread = threading.Thread(target=worker)",
          "thread.start()",
          "if not inspection_started.wait(5):",
          "    raise RuntimeError('worker did not begin its second snapshot')",
          "with workbench.connect() as creator:",
          "    workbench.start_scan(creator, start_args)",
          "    created_scan_id = creator.execute('SELECT active_scan_id FROM workspaces WHERE id = ?', (workspace_id,)).fetchone()['active_scan_id']",
          "    Path(repository).rename(Path(root) / 'parked-repository')",
          "release_inspection.set()",
          "thread.join(10)",
          "if thread.is_alive():",
          "    raise RuntimeError('scan worker did not finish')",
          "with workbench.connect() as connection:",
          "    active_scan_id = connection.execute('SELECT active_scan_id FROM workspaces WHERE id = ?', (workspace_id,)).fetchone()['active_scan_id']",
          "    scan_count = connection.execute('SELECT COUNT(*) FROM scans WHERE workspace_id = ?', (workspace_id,)).fetchone()[0]",
          "print(json.dumps({'activeMatchesCreated': active_scan_id == created_scan_id, 'scanCount': scan_count, 'targetExists': Path(repository).exists(), 'workerSnapshotCalls': worker_snapshot_calls, **outcome}))",
        ],
        [kind, repository, base, head, root],
        state,
      );

      expect(result).toEqual({
        activeMatchesCreated: true,
        error: null,
        inTransaction: false,
        scanCount: 1,
        started: true,
        targetExists: false,
        workerSnapshotCalls: 2,
      });
    },
  );

  test("rejoins an active submitted commit scan after waiting on post-inspection contention", () => {
    const { base, head, repository, root, state } = createRepository();
    const result = runPythonJson<{
      activeMatchesCreated: boolean;
      beginAttempts: number;
      error: string | null;
      inTransaction: boolean;
      restoreTimeoutReached: boolean;
      scanCount: number;
      started: boolean;
      targetExists: boolean;
      zeroTimeoutReached: boolean;
    }>(
      [
        "import argparse, json, threading, uuid",
        "from pathlib import Path",
        "import workbench_db as workbench",
        "repository, base, head, root = sys.argv[2:6]",
        "workspace_id = str(uuid.uuid4())",
        "create_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=repository, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='commit', diff_base_revision=base, diff_head_revision=head, diff_content_digest=None)",
        "start_args = argparse.Namespace(workspace_id=workspace_id, scan_root=str(Path(root) / 'submitted-scans'), model=None, reasoning_effort=None)",
        "with workbench.connect() as connection:",
        "    workbench.create_workspace(connection, create_args)",
        "    workbench.save_workspace(connection, create_args)",
        "connection_ready = threading.Event()",
        "zero_timeout_reached = threading.Event()",
        "writer_ready = threading.Event()",
        "restore_timeout_reached = threading.Event()",
        "writer_committed = threading.Event()",
        "outcome = {'beginAttempts': 0, 'error': None, 'inTransaction': None, 'started': False}",
        "class TrackedConnection:",
        "    def __init__(self, delegate):",
        "        self.delegate = delegate",
        "    def execute(self, sql, *args):",
        "        normalized = sql.strip().upper()",
        "        if normalized == 'BEGIN IMMEDIATE':",
        "            outcome['beginAttempts'] += 1",
        "        elif normalized == 'PRAGMA BUSY_TIMEOUT = 0':",
        "            zero_timeout_reached.set()",
        "            if not writer_ready.wait(5):",
        "                raise RuntimeError('writer did not acquire the post-inspection lock')",
        "        elif normalized.startswith('PRAGMA BUSY_TIMEOUT = '):",
        "            restore_timeout_reached.set()",
        "            if not writer_committed.wait(5):",
        "                raise RuntimeError('writer did not commit before blocking retry')",
        "        return self.delegate.execute(sql, *args)",
        "    def __getattr__(self, name):",
        "        return getattr(self.delegate, name)",
        "def worker():",
        "    with workbench.connect() as delegate:",
        "        connection_ready.set()",
        "        try:",
        "            workbench.start_scan(TrackedConnection(delegate), start_args)",
        "        except BaseException as error:",
        "            outcome['error'] = f'{type(error).__name__}: {error}'",
        "        else:",
        "            outcome['started'] = True",
        "        outcome['inTransaction'] = delegate.in_transaction",
        "thread = threading.Thread(target=worker)",
        "thread.start()",
        "if not connection_ready.wait(5):",
        "    raise RuntimeError('worker connection timed out')",
        "if not zero_timeout_reached.wait(5):",
        "    raise RuntimeError('worker did not complete its external inspection')",
        "with workbench.connect() as blocker:",
        "    blocker.execute('BEGIN IMMEDIATE')",
        "    workbench.start_scan(blocker, start_args)",
        "    created_scan_id = blocker.execute('SELECT active_scan_id FROM workspaces WHERE id = ?', (workspace_id,)).fetchone()['active_scan_id']",
        "    Path(repository).rename(Path(root) / 'parked-repository')",
        "    writer_ready.set()",
        "    if not restore_timeout_reached.wait(5):",
        "        raise RuntimeError('worker did not reach its blocking retry')",
        "    blocker.commit()",
        "    writer_committed.set()",
        "thread.join(10)",
        "if thread.is_alive():",
        "    raise RuntimeError('scan worker did not finish')",
        "with workbench.connect() as connection:",
        "    active_scan_id = connection.execute('SELECT active_scan_id FROM workspaces WHERE id = ?', (workspace_id,)).fetchone()['active_scan_id']",
        "    scan_count = connection.execute('SELECT COUNT(*) FROM scans WHERE workspace_id = ?', (workspace_id,)).fetchone()[0]",
        "print(json.dumps({'activeMatchesCreated': active_scan_id == created_scan_id, 'restoreTimeoutReached': restore_timeout_reached.is_set(), 'scanCount': scan_count, 'targetExists': Path(repository).exists(), 'zeroTimeoutReached': zero_timeout_reached.is_set(), **outcome}))",
      ],
      [repository, base, head, root],
      state,
    );

    expect(result).toEqual({
      activeMatchesCreated: true,
      beginAttempts: 3,
      error: null,
      inTransaction: false,
      restoreTimeoutReached: true,
      scanCount: 1,
      started: true,
      targetExists: false,
      zeroTimeoutReached: true,
    });
  });

  test.each([
    ["submitted", "before-begin"],
    ["prompt", "before-begin"],
    ["cli", "before-begin"],
    ["submitted", "after-digest"],
    ["prompt", "after-digest"],
    ["cli", "after-digest"],
  ] as const)(
    "rejects a %s committed target when a lock-only writer finishes %s",
    (operation, timing) => {
      const { base, head, repository, root, state } = createRepository();
      const selectedBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
      const replacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "changed in completed gap\n" },
      );
      expect(replacement.status, replacement.stderr).toBe(0);

      const result = runPythonJson<{
        counts: { scans: number; workspaces: number };
        currentDigest: string;
        error: string | null;
        identityCalls: number;
        identityTransactions: boolean[];
        raceCommitted: boolean;
        inTransaction: boolean;
        snapshotCalls: number;
        snapshotTransactions: boolean[];
        started: boolean;
        storedDigest: string | null;
        storedMatchesCurrent: boolean | null;
      }>(
        [
          "import argparse, json, sqlite3, subprocess, uuid",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "operation, timing, repository, base, head, root, selected_blob, replacement_blob = sys.argv[2:10]",
          "root_path = Path(root)",
          "workspace_id = str(uuid.uuid4())",
          "if operation == 'submitted':",
          "    create_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=None, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='standard', diff_target_kind=None, diff_base_revision=None, diff_head_revision=None, diff_content_digest=None)",
          "    save_args = argparse.Namespace(workspace_id=workspace_id, target_path=repository, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='range', diff_base_revision=base, diff_head_revision=head, diff_content_digest=None)",
          "    with workbench.connect() as connection:",
          "        workbench.create_workspace(connection, create_args)",
          "        workbench.save_workspace(connection, save_args)",
          "prompt_args = argparse.Namespace(thread_id='completed-gap-prompt', target_path=repository, scope='.', mode='diff', target_summary=None, user_context=None, user_context_stdin=False, diff_target_kind='range', diff_base_revision=base, diff_head_revision=head, diff_content_digest=None, scan_root=str(root_path / 'prompt-scans'), model=None, reasoning_effort=None)",
          "submitted_args = argparse.Namespace(workspace_id=workspace_id, scan_root=str(root_path / 'submitted-scans'), model=None, reasoning_effort=None)",
          "scan_directory = root_path / 'cli-scan'",
          "scan_directory.mkdir(mode=0o700)",
          "recipe = {'config': {}, 'mode': 'standard', 'repository': repository, 'target': {'kind': 'refs', 'paths': [], 'base': base, 'head': head}}",
          "cli_args = argparse.Namespace(repository=repository, scan_dir=str(scan_directory), registration_json_stdin=False, recipe_json_stdin=False, recipe_json=json.dumps(recipe), archive_existing=False, archived_scan_dir=None, parent_scan_id=None)",
          "original_snapshot = workbench.committed_diff_content_snapshot",
          "original_identity = workbench.committed_diff_object_identity",
          "worker_connection = None",
          "identity_calls = 0",
          "identity_transactions = []",
          "snapshot_calls = 0",
          "snapshot_transactions = []",
          "race_armed = False",
          "race_committed = False",
          "def commit_race():",
          "    global race_committed",
          "    if race_committed:",
          "        return",
          "    race_committed = True",
          "    with sqlite3.connect(workbench.database_path(), timeout=1) as writer:",
          "        writer.execute('BEGIN IMMEDIATE')",
          "        subprocess.run(['git', '-C', repository, 'replace', '-f', selected_blob, replacement_blob], check=True)",
          "        writer.commit()",
          "class RacedConnection:",
          "    def __init__(self, delegate):",
          "        self.delegate = delegate",
          "    def execute(self, sql, *args):",
          "        global race_armed, race_committed",
          "        normalized = ' '.join(sql.upper().split())",
          "        if timing == 'before-begin' and normalized == 'PRAGMA BUSY_TIMEOUT = 0':",
          "            race_armed = True",
          "        elif normalized == 'BEGIN IMMEDIATE' and race_armed:",
          "            race_armed = False",
          "            commit_race()",
          "        return self.delegate.execute(sql, *args)",
          "    def __getattr__(self, name):",
          "        return getattr(self.delegate, name)",
          "def raced_snapshot(*args):",
          "    global snapshot_calls",
          "    snapshot_calls += 1",
          "    snapshot_transactions.append(bool(worker_connection and worker_connection.in_transaction))",
          "    snapshot = original_snapshot(*args)",
          "    if timing == 'after-digest' and snapshot_calls == 2:",
          "        commit_race()",
          "    return snapshot",
          "def raced_identity(*args):",
          "    global identity_calls",
          "    identity_calls += 1",
          "    identity_transactions.append(bool(worker_connection and worker_connection.in_transaction))",
          "    return original_identity(*args)",
          "workbench.committed_diff_content_snapshot = raced_snapshot",
          "workbench.committed_diff_object_identity = raced_identity",
          "outcome = {'error': None, 'started': False}",
          "with workbench.connect() as connection:",
          "    worker_connection = connection",
          "    raced_connection = RacedConnection(connection)",
          "    try:",
          "        if operation == 'submitted':",
          "            workbench.start_scan(raced_connection, submitted_args)",
          "        elif operation == 'prompt':",
          "            workbench.start_prompt_only_scan(raced_connection, prompt_args)",
          "        else:",
          "            workbench.register_cli_scan(raced_connection, cli_args)",
          "    except SystemExit as error:",
          "        outcome['error'] = str(error)",
          "    else:",
          "        outcome['started'] = True",
          "    outcome['inTransaction'] = connection.in_transaction",
          "current_digest = original_snapshot(Path(repository), base, head)[0]",
          "with workbench.connect() as connection:",
          "    counts = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('workspaces', 'scans')}",
          "    row = connection.execute('SELECT diff_content_digest FROM scans ORDER BY created_at DESC LIMIT 1').fetchone()",
          "stored_digest = None if row is None else row['diff_content_digest']",
          "print(json.dumps({'counts': counts, 'currentDigest': current_digest, 'identityCalls': identity_calls, 'identityTransactions': identity_transactions, 'raceCommitted': race_committed, 'snapshotCalls': snapshot_calls, 'snapshotTransactions': snapshot_transactions, 'storedDigest': stored_digest, 'storedMatchesCurrent': None if stored_digest is None else stored_digest == current_digest, **outcome}))",
        ],
        [
          operation,
          timing,
          repository,
          base,
          head,
          root,
          selectedBlob,
          replacement.stdout.trim(),
        ],
        state,
      );

      expect(result).toEqual({
        counts:
          operation === "submitted"
            ? { scans: 0, workspaces: 1 }
            : { scans: 0, workspaces: 0 },
        currentDigest: expect.stringMatching(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        ),
        error:
          "The selected scan target changed while the scan was starting. Try again.",
        identityCalls: 1,
        identityTransactions: [true],
        inTransaction: false,
        raceCommitted: true,
        snapshotCalls: 2,
        snapshotTransactions: [false, false],
        started: false,
        storedDigest: null,
        storedMatchesCurrent: null,
      });
    },
  );

  test.each(["submitted", "prompt", "cli"] as const)(
    "never accepts a stale %s digest when every snapshot is paired with a restored replacement view",
    (operation) => {
      const { base, head, repository, root, state } = createRepository();
      const selectedBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
      const replacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "repeatable replacement view\n" },
      );
      expect(replacement.status, replacement.stderr).toBe(0);

      const result = runPythonJson<{
        counts: { scans: number; workspaces: number };
        currentDigest: string;
        error: string | null;
        inTransaction: boolean;
        mutationEpochs: number;
        snapshotCalls: number;
        snapshotTransactions: boolean[];
        started: boolean;
        storedDigest: string | null;
        storedMatchesCurrent: boolean | null;
      }>(
        [
          "import argparse, json, sqlite3, subprocess, uuid",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "operation, repository, base, head, root, selected_blob, replacement_blob = sys.argv[2:9]",
          "root_path = Path(root)",
          "workspace_id = str(uuid.uuid4())",
          "if operation == 'submitted':",
          "    create_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=None, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='standard', diff_target_kind=None, diff_base_revision=None, diff_head_revision=None, diff_content_digest=None)",
          "    save_args = argparse.Namespace(workspace_id=workspace_id, target_path=repository, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='range', diff_base_revision=base, diff_head_revision=head, diff_content_digest=None)",
          "    with workbench.connect() as connection:",
          "        workbench.create_workspace(connection, create_args)",
          "        workbench.save_workspace(connection, save_args)",
          "prompt_args = argparse.Namespace(thread_id='repeatable-pair-prompt', target_path=repository, scope='.', mode='diff', target_summary=None, user_context=None, user_context_stdin=False, diff_target_kind='range', diff_base_revision=base, diff_head_revision=head, diff_content_digest=None, scan_root=str(root_path / 'prompt-scans'), model=None, reasoning_effort=None)",
          "submitted_args = argparse.Namespace(workspace_id=workspace_id, scan_root=str(root_path / 'submitted-scans'), model=None, reasoning_effort=None)",
          "scan_directory = root_path / 'cli-scan'",
          "scan_directory.mkdir(mode=0o700)",
          "recipe = {'config': {}, 'mode': 'standard', 'repository': repository, 'target': {'kind': 'refs', 'paths': [], 'base': base, 'head': head}}",
          "cli_args = argparse.Namespace(repository=repository, scan_dir=str(scan_directory), registration_json_stdin=False, recipe_json_stdin=False, recipe_json=json.dumps(recipe), archive_existing=False, archived_scan_dir=None, parent_scan_id=None)",
          "original_snapshot = workbench.committed_diff_content_snapshot",
          "worker_connection = None",
          "mutation_epochs = 0",
          "snapshot_calls = 0",
          "snapshot_transactions = []",
          "subprocess.run(['git', '-C', repository, 'replace', '-f', selected_blob, replacement_blob], check=True)",
          "def mutate_replacement(action):",
          "    global mutation_epochs",
          "    mutation_epochs += 1",
          "    with sqlite3.connect(workbench.database_path(), timeout=1) as writer:",
          "        writer.execute('BEGIN IMMEDIATE')",
          "        command = ['git', '-C', repository, 'replace']",
          "        if action == 'remove':",
          "            command.extend(['-d', selected_blob])",
          "        else:",
          "            command.extend(['-f', selected_blob, replacement_blob])",
          "        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)",
          "        writer.commit()",
          "def split_snapshot(snapshot, *args):",
          "    global snapshot_calls",
          "    snapshot_calls += 1",
          "    snapshot_transactions.append(bool(worker_connection and worker_connection.in_transaction))",
          "    mutate_replacement('remove')",
          "    try:",
          "        return snapshot(*args)",
          "    finally:",
          "        mutate_replacement('restore')",
          "def raced_snapshot(*args):",
          "    return split_snapshot(original_snapshot, *args)",
          "workbench.committed_diff_content_snapshot = raced_snapshot",
          "outcome = {'error': None, 'started': False}",
          "with workbench.connect() as connection:",
          "    worker_connection = connection",
          "    try:",
          "        if operation == 'submitted':",
          "            workbench.start_scan(connection, submitted_args)",
          "        elif operation == 'prompt':",
          "            workbench.start_prompt_only_scan(connection, prompt_args)",
          "        else:",
          "            workbench.register_cli_scan(connection, cli_args)",
          "    except SystemExit as error:",
          "        outcome['error'] = str(error)",
          "    else:",
          "        outcome['started'] = True",
          "    outcome['inTransaction'] = connection.in_transaction",
          "workbench.committed_diff_content_snapshot = original_snapshot",
          "current_digest = original_snapshot(Path(repository), base, head)[0]",
          "with workbench.connect() as connection:",
          "    counts = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('workspaces', 'scans')}",
          "    row = connection.execute('SELECT diff_content_digest FROM scans ORDER BY created_at DESC LIMIT 1').fetchone()",
          "stored_digest = None if row is None else row['diff_content_digest']",
          "print(json.dumps({'counts': counts, 'currentDigest': current_digest, 'mutationEpochs': mutation_epochs, 'snapshotCalls': snapshot_calls, 'snapshotTransactions': snapshot_transactions, 'storedDigest': stored_digest, 'storedMatchesCurrent': None if stored_digest is None else stored_digest == current_digest, **outcome}))",
        ],
        [
          operation,
          repository,
          base,
          head,
          root,
          selectedBlob,
          replacement.stdout.trim(),
        ],
        state,
      );

      expect(result).toEqual({
        counts:
          operation === "submitted"
            ? { scans: 0, workspaces: 1 }
            : { scans: 0, workspaces: 0 },
        currentDigest: expect.stringMatching(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        ),
        error:
          "The selected scan target changed while the scan was starting. Try again.",
        inTransaction: false,
        mutationEpochs: 4,
        snapshotCalls: 2,
        snapshotTransactions: [false, false],
        started: false,
        storedDigest: null,
        storedMatchesCurrent: null,
      });
    },
  );

  test.each(["working_tree", "commit", "range"] as const)(
    "rejects a %s CLI registration when the target changes behind a writer lock",
    (selection) => {
      const { base, head, repository, root, state } = createRepository();
      writeFileSync(join(repository, "fixture.txt"), "range head\n");
      git(repository, "add", "fixture.txt");
      commit(repository, "range head");
      const rangeHead = git(repository, "rev-parse", "HEAD");
      const selectedBase = selection === "working_tree" ? rangeHead : base;
      const selectedHead = selection === "commit" ? head : rangeHead;
      const selectedBlob = git(
        repository,
        "rev-parse",
        `${selectedHead}:fixture.txt`,
      );
      const replacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "changed behind lock\n" },
      );
      expect(replacement.status, replacement.stderr).toBe(0);
      const scanDirectory = join(root, "cli-scan");
      mkdirSync(scanDirectory, { mode: 0o700 });

      const result = runPythonJson<{
        beginAttempted: boolean;
        counts: { scans: number; workspaces: number };
        error: string | null;
        inTransaction: boolean;
        scanDirectoryEntries: string[];
        snapshotTransactions: boolean[];
        started: boolean;
      }>(
        [
          "import argparse, json, subprocess, threading",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "selection, repository, scan_directory, selected_base, selected_head, selected_blob, replacement_blob = sys.argv[2:9]",
          "recipe_kind = 'working_tree' if selection == 'working_tree' else 'refs'",
          "recipe = {'config': {}, 'mode': 'standard', 'repository': repository, 'target': {'kind': recipe_kind, 'paths': [], 'base': selected_base, 'head': selected_head}}",
          "arguments = argparse.Namespace(repository=repository, scan_dir=scan_directory, registration_json_stdin=False, recipe_json_stdin=False, recipe_json=json.dumps(recipe), archive_existing=False, archived_scan_dir=None, parent_scan_id=None)",
          "snapshot_name = 'worktree_content_digest' if selection == 'working_tree' else 'committed_diff_content_snapshot'",
          "original_snapshot = getattr(workbench, snapshot_name)",
          "snapshot_transactions = []",
          "worker_connection = None",
          "def counted_snapshot(*args, **kwargs):",
          "    snapshot_transactions.append(bool(worker_connection and worker_connection.in_transaction))",
          "    return original_snapshot(*args, **kwargs)",
          "setattr(workbench, snapshot_name, counted_snapshot)",
          "begin_attempted = threading.Event()",
          "connection_ready = threading.Event()",
          "start_worker = threading.Event()",
          "outcome = {'error': None, 'inTransaction': None, 'started': False}",
          "class TrackedConnection:",
          "    def __init__(self, delegate):",
          "        self.delegate = delegate",
          "    def execute(self, sql, *args):",
          "        if sql.strip().upper() == 'BEGIN IMMEDIATE':",
          "            begin_attempted.set()",
          "        return self.delegate.execute(sql, *args)",
          "    def __getattr__(self, name):",
          "        return getattr(self.delegate, name)",
          "def worker():",
          "    global worker_connection",
          "    with workbench.connect() as delegate:",
          "        worker_connection = delegate",
          "        connection_ready.set()",
          "        if not start_worker.wait(5):",
          "            outcome['error'] = 'worker start timed out'",
          "            return",
          "        try:",
          "            workbench.register_cli_scan(TrackedConnection(delegate), arguments)",
          "        except SystemExit as error:",
          "            outcome['error'] = str(error)",
          "        else:",
          "            outcome['started'] = True",
          "        outcome['inTransaction'] = delegate.in_transaction",
          "thread = threading.Thread(target=worker)",
          "thread.start()",
          "if not connection_ready.wait(5):",
          "    raise RuntimeError('worker connection timed out')",
          "with workbench.connect() as blocker:",
          "    blocker.execute('BEGIN IMMEDIATE')",
          "    start_worker.set()",
          "    if not begin_attempted.wait(5):",
          "        raise RuntimeError('registration did not reach writer lock')",
          "    if selection == 'working_tree':",
          "        (Path(repository) / 'fixture.txt').write_text('changed behind lock\\n')",
          "    else:",
          "        subprocess.run(['git', '-C', repository, 'replace', '-f', selected_blob, replacement_blob], check=True)",
          "    blocker.commit()",
          "thread.join(10)",
          "if thread.is_alive():",
          "    raise RuntimeError('registration worker did not finish')",
          "with workbench.connect() as connection:",
          "    counts = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('workspaces', 'scans')}",
          "print(json.dumps({'beginAttempted': begin_attempted.is_set(), 'counts': counts, 'scanDirectoryEntries': sorted(entry.name for entry in Path(scan_directory).iterdir()), 'snapshotTransactions': snapshot_transactions, **outcome}))",
        ],
        [
          selection,
          repository,
          scanDirectory,
          selectedBase,
          selectedHead,
          selectedBlob,
          replacement.stdout.trim(),
        ],
        state,
      );

      expect(result).toEqual({
        beginAttempted: true,
        counts: { scans: 0, workspaces: 0 },
        error:
          selection === "working_tree"
            ? "Working-tree contents changed after they were selected. Select Uncommitted changes again."
            : "The committed changes selected for review no longer produce the same diff. Select the changes to review again.",
        inTransaction: false,
        scanDirectoryEntries: [],
        snapshotTransactions:
          selection === "working_tree" ? [false, true] : [false, false],
        started: false,
      });
    },
  );

  test("rejects a status-zero missing blob from an upgraded cache before insertion", async () => {
    expect(python).not.toBeNull();
    const { base, head, repository, root, state } = createRepository();
    const installedRoot = await upgradeBundledPlugin(root);
    const blob = git(repository, "rev-parse", `${head}:fixture.txt`);
    const objectPath = join(
      repository,
      ".git",
      "objects",
      blob.slice(0, 2),
      blob.slice(2),
    );
    const backupPath = `${objectPath}.backup`;
    const scanDirectory = join(root, "scan");
    mkdirSync(scanDirectory, { mode: 0o700 });
    renameSync(objectPath, backupPath);
    try {
      const missing = spawnSync("git", ["cat-file", "--batch", "-z"], {
        cwd: repository,
        input: Buffer.from(`${blob}\0`),
      });
      expect(missing.status, missing.stderr.toString()).toBe(0);
      expect(missing.stdout).toEqual(Buffer.from(`${blob} missing\n`));
    } finally {
      renameSync(backupPath, objectPath);
    }

    const probe = runPythonJson<{
      digestTransactions: boolean[];
      error: string | null;
      inserted: { scans: number; workspaces: number };
    }>(
      [
        "import argparse, json",
        "from pathlib import Path",
        "import workbench_db as workbench",
        "repository, scan_directory, base, head = sys.argv[2:6]",
        "object_path, backup_path = Path(sys.argv[6]), Path(sys.argv[7])",
        "recipe = {'config': {}, 'mode': 'standard', 'repository': repository, 'target': {'kind': 'refs', 'paths': [], 'base': base, 'head': head}}",
        "arguments = argparse.Namespace(repository=repository, scan_dir=scan_directory, registration_json_stdin=False, recipe_json_stdin=False, recipe_json=json.dumps(recipe), archive_existing=False, archived_scan_dir=None, parent_scan_id=None)",
        "original_digest = workbench.committed_diff_content_snapshot",
        "digest_transactions = []",
        "def tracked_digest(*args):",
        "    digest_transactions.append(connection.in_transaction)",
        "    return original_digest(*args)",
        "workbench.committed_diff_content_snapshot = tracked_digest",
        "original_count = workbench.directory_snapshot_regular_file_count",
        "def remove_blob_during_count(path):",
        "    count = original_count(path)",
        "    object_path.rename(backup_path)",
        "    return count",
        "workbench.directory_snapshot_regular_file_count = remove_blob_during_count",
        "with workbench.connect() as connection:",
        "    before = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('workspaces', 'scans')}",
        "    try:",
        "        workbench.register_cli_scan(connection, arguments)",
        "    except SystemExit as error:",
        "        message = str(error)",
        "    else:",
        "        message = None",
        "    finally:",
        "        if backup_path.exists():",
        "            backup_path.rename(object_path)",
        "    after = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('workspaces', 'scans')}",
        "print(json.dumps({'digestTransactions': digest_transactions, 'error': message, 'inserted': {table: after[table] - before[table] for table in before}}))",
      ],
      [repository, scanDirectory, base, head, objectPath, backupPath],
      state,
      {},
      join(installedRoot, "scripts"),
    );

    expect(probe).toEqual({
      digestTransactions: [false, false],
      error: "Could not snapshot the selected committed changes.",
      inserted: { scans: 0, workspaces: 0 },
    });
  });

  test("rejects substituted committed blob bytes during reselection", () => {
    const { base, head, repository, state } = createRepository();
    const selectedDigest = committedDigest(repository, state, base, head);
    const originalBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
    const replacement = spawnSync(
      "git",
      ["-C", repository, "hash-object", "-w", "--stdin"],
      { encoding: "utf8", input: "substituted\n" },
    );
    expect(replacement.status, replacement.stderr).toBe(0);
    git(repository, "replace", "-f", originalBlob, replacement.stdout.trim());
    expect(committedDigest(repository, state, base, head)).not.toBe(
      selectedDigest,
    );
    expect(
      runPython(
        [
          "from workbench_db import inspect_setup_values",
          "try:",
          "    inspect_setup_values(sys.argv[2], '.', 'diff', 'range', sys.argv[3], sys.argv[4], sys.argv[5])",
          "except SystemExit as error:",
          "    print(error)",
        ],
        [repository, base, head, selectedDigest],
        state,
      ),
    ).toBe(
      "The committed changes selected for review no longer produce the same diff. " +
        "Select the changes to review again.",
    );
  });

  test.each([
    ["commit", "symbolic"],
    ["range", "symbolic"],
    ["range", "abbreviated"],
  ] as const)(
    "binds a failed %s snapshot to its %s revision identity",
    (kind, aliasStyle) => {
      const { base, head, repository, state } = createRepository();
      const selectedBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
      const objectPath = join(
        repository,
        ".git",
        "objects",
        selectedBlob.slice(0, 2),
        selectedBlob.slice(2),
      );
      const backupPath = `${objectPath}.backup`;
      const nextHead = git(
        repository,
        "-c",
        "user.name=synthetic-test",
        "-c",
        "user.email=synthetic-test@example.invalid",
        "commit-tree",
        `${head}^{tree}`,
        "-p",
        head,
        "-m",
        "different clean selection",
      );
      const replacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "substituted after recovery\n" },
      );
      expect(replacement.status, replacement.stderr).toBe(0);
      renameSync(objectPath, backupPath);

      const result = runPythonJson<{
        afterRejectedSave: Record<string, unknown>;
        differentSelection: Record<string, unknown>;
        persistedAfterFailure: Record<string, unknown>;
        sameSelectionError: string | null;
        setupValidation: { error: string | null; valid: boolean };
      }>(
        [
          "import argparse, json, subprocess, uuid",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "kind, alias_style, repository, base, head, next_head, selected_blob, replacement_blob = sys.argv[2:10]",
          "object_path, backup_path = Path(sys.argv[10]), Path(sys.argv[11])",
          "requested_base = None if kind == 'commit' else ('HEAD~1' if alias_style == 'symbolic' else base[:8])",
          "requested_head = 'HEAD' if alias_style == 'symbolic' else head[:8]",
          "workspace_id = str(uuid.uuid4())",
          "def arguments(base_revision, head_revision):",
          "    return argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=repository, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind=kind, diff_base_revision=base_revision, diff_head_revision=head_revision, diff_content_digest=None)",
          "with workbench.connect() as connection:",
          "    created = workbench.create_workspace(connection, arguments(requested_base, requested_head))",
          "    persisted_after_failure = dict(connection.execute('SELECT diff_base_revision, diff_head_revision, diff_content_digest, submitted FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
          "    backup_path.rename(object_path)",
          "    if kind == 'range' and alias_style == 'symbolic':",
          "        subprocess.run(['git', '-C', repository, 'replace', '-f', selected_blob, replacement_blob], check=True)",
          "    try:",
          "        workbench.save_workspace(connection, arguments(None if kind == 'commit' else base, head))",
          "    except SystemExit as error:",
          "        same_selection_error = str(error)",
          "    else:",
          "        same_selection_error = None",
          "    after_rejected_save = dict(connection.execute('SELECT diff_base_revision, diff_head_revision, diff_content_digest, submitted FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
          "    if kind == 'range' and alias_style == 'symbolic':",
          "        subprocess.run(['git', '-C', repository, 'replace', '-d', selected_blob], check=True, stdout=subprocess.DEVNULL)",
          "    workbench.save_workspace(connection, arguments(None if kind == 'commit' else head, next_head))",
          "    different_selection = dict(connection.execute('SELECT diff_base_revision, diff_head_revision, diff_content_digest, submitted FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
          "print(json.dumps({'setupValidation': created['setupValidation'], 'persistedAfterFailure': persisted_after_failure, 'sameSelectionError': same_selection_error, 'afterRejectedSave': after_rejected_save, 'differentSelection': different_selection}))",
        ],
        [
          kind,
          aliasStyle,
          repository,
          base,
          head,
          nextHead,
          selectedBlob,
          replacement.stdout.trim(),
          objectPath,
          backupPath,
        ],
        state,
      );

      const failedSelection = {
        diff_base_revision: kind === "commit" ? null : base,
        diff_content_digest: null,
        diff_head_revision: head,
        submitted: 0,
      };
      expect(result.setupValidation).toEqual({
        error: "Could not snapshot the selected committed changes.",
        valid: false,
      });
      expect(result.persistedAfterFailure).toEqual(failedSelection);
      expect(result.sameSelectionError).toBe(
        "The committed changes selected for review no longer produce the same " +
          "diff. Select the changes to review again.",
      );
      expect(result.afterRejectedSave).toEqual(failedSelection);
      expect(result.differentSelection).toEqual({
        diff_base_revision: head,
        diff_content_digest: expect.stringMatching(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        ),
        diff_head_revision: nextHead,
        submitted: 1,
      });
    },
  );

  test.each(["commit", "range"] as const)(
    "allows correcting an unresolved %s selection before submission",
    (kind) => {
      const { base, head, repository, state } = createRepository();
      const typoRef = "refs/heads/typoed-selection";

      const result = runPythonJson<{
        correctedSelection: Record<string, unknown>;
        persistedAfterFailure: Record<string, unknown>;
        saveError: string | null;
        setupValidation: { error: string | null; valid: boolean };
      }>(
        [
          "import argparse, json, uuid",
          "import workbench_db as workbench",
          "kind, repository, base, head, typo_ref = sys.argv[2:7]",
          "workspace_id = str(uuid.uuid4())",
          "def arguments(base_revision, head_revision):",
          "    return argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=repository, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind=kind, diff_base_revision=base_revision, diff_head_revision=head_revision, diff_content_digest=None)",
          "initial_base = None if kind == 'commit' else 'HEAD~1'",
          "corrected_base = None if kind == 'commit' else base",
          "with workbench.connect() as connection:",
          "    created = workbench.create_workspace(connection, arguments(initial_base, typo_ref))",
          "    persisted_after_failure = dict(connection.execute('SELECT diff_base_revision, diff_head_revision, diff_content_digest, submitted FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
          "    try:",
          "        workbench.save_workspace(connection, arguments(corrected_base, head))",
          "    except SystemExit as error:",
          "        save_error = str(error)",
          "    else:",
          "        save_error = None",
          "    corrected_selection = dict(connection.execute('SELECT diff_base_revision, diff_head_revision, diff_content_digest, submitted FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
          "print(json.dumps({'setupValidation': created['setupValidation'], 'persistedAfterFailure': persisted_after_failure, 'saveError': save_error, 'correctedSelection': corrected_selection}))",
        ],
        [kind, repository, base, head, typoRef],
        state,
      );

      expect(result.setupValidation).toEqual({
        error: `${kind === "commit" ? "Commit" : "Head revision"} does not resolve to a local Git commit: ${typoRef}`,
        valid: false,
      });
      expect(result.persistedAfterFailure).toEqual({
        diff_base_revision: kind === "commit" ? null : "HEAD~1",
        diff_content_digest: null,
        diff_head_revision: typoRef,
        submitted: 0,
      });
      expect(result.saveError).toBeNull();
      expect(result.correctedSelection).toEqual({
        diff_base_revision: base,
        diff_content_digest: expect.stringMatching(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        ),
        diff_head_revision: head,
        submitted: 1,
      });
    },
  );

  test("rejects legacy same-commit initialization when its retained base changes", () => {
    const { base, head, repository, state } = createRepository();
    const baseTree = git(repository, "rev-parse", `${base}^{tree}`);
    const headTree = git(repository, "rev-parse", `${head}^{tree}`);
    const alternateParent = git(
      repository,
      "-c",
      "user.name=synthetic-test",
      "-c",
      "user.email=synthetic-test@example.invalid",
      "commit-tree",
      baseTree,
      "-m",
      "alternate same-tree parent",
    );
    const replacementHead = git(
      repository,
      "-c",
      "user.name=synthetic-test",
      "-c",
      "user.email=synthetic-test@example.invalid",
      "commit-tree",
      headTree,
      "-p",
      alternateParent,
      "-m",
      "replacement head",
    );
    expect(git(repository, "rev-parse", `${alternateParent}^{tree}`)).toBe(
      baseTree,
    );
    expect(git(repository, "rev-parse", `${replacementHead}^{tree}`)).toBe(
      headTree,
    );

    const result = runPythonJson<{
      after: Record<string, unknown>;
      before: Record<string, unknown>;
      currentDigest: string;
      error: string | null;
      observedHead: string;
      observedParent: string;
    }>(
      [
        "import argparse, json, subprocess, uuid",
        "from pathlib import Path",
        "import workbench_db as workbench",
        "repository, head, replacement_head = sys.argv[2:5]",
        "workspace_id = str(uuid.uuid4())",
        "create_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=repository, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='commit', diff_base_revision=None, diff_head_revision=head, diff_content_digest=None)",
        "save_args = argparse.Namespace(workspace_id=workspace_id, target_path=repository, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='commit', diff_base_revision=None, diff_head_revision=head, diff_content_digest=None)",
        "with workbench.connect() as connection:",
        "    workbench.create_workspace(connection, create_args)",
        "    connection.execute('UPDATE workspaces SET diff_content_digest = NULL WHERE id = ?', (workspace_id,))",
        "    connection.commit()",
        "    before = dict(connection.execute('SELECT diff_base_revision, diff_head_revision, diff_content_digest, submitted FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
        "    subprocess.run(['git', '-C', repository, 'replace', '-f', head, replacement_head], check=True)",
        "    observed_head = subprocess.check_output(['git', '-C', repository, 'rev-parse', head], text=True).strip()",
        "    observed_parent = subprocess.check_output(['git', '-C', repository, 'rev-parse', f'{head}^'], text=True).strip()",
        "    current_digest = workbench.committed_diff_content_snapshot(Path(repository), observed_parent, observed_head)[0]",
        "    save_args.diff_content_digest = current_digest",
        "    try:",
        "        workbench.save_workspace(connection, save_args)",
        "    except SystemExit as error:",
        "        message = str(error)",
        "    else:",
        "        message = None",
        "    after = dict(connection.execute('SELECT diff_base_revision, diff_head_revision, diff_content_digest, submitted FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
        "print(json.dumps({'before': before, 'after': after, 'currentDigest': current_digest, 'error': message, 'observedHead': observed_head, 'observedParent': observed_parent}))",
      ],
      [repository, head, replacementHead],
      state,
    );

    expect(result.observedHead).toBe(head);
    expect(result.observedParent).toBe(alternateParent);
    expect(result.currentDigest).toMatch(
      /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
    );
    expect(result.before).toEqual({
      diff_base_revision: base,
      diff_content_digest: null,
      diff_head_revision: head,
      submitted: 0,
    });
    expect(result.error).toBe(
      "The committed changes selected for review no longer produce the same " +
        "diff. Select the changes to review again.",
    );
    expect(result.after).toEqual(result.before);
  });

  test("confines configured digest spools to one private directory", () => {
    const { base, head, repository, state } = createRepository();
    const result = runPythonJson<{
      allConfined: boolean;
      digest: string;
      privateMode: boolean;
      residue: string[];
      rootRemoved: boolean;
      roots: number;
      spools: number;
    }>(
      [
        "import json, os",
        "from pathlib import Path",
        "import workbench_target as target",
        "temporary_directory = target.tempfile.TemporaryDirectory",
        "temporary_file = target.tempfile.TemporaryFile",
        "roots, modes, directories = [], [], []",
        "class TrackedTemporaryDirectory:",
        "    def __init__(self, *args, **kwargs):",
        "        self.inner = temporary_directory(*args, **kwargs)",
        "    def __enter__(self):",
        "        directory = self.inner.__enter__()",
        "        root = Path(directory).resolve()",
        "        roots.append(root)",
        "        modes.append(root.stat().st_mode & 0o777)",
        "        return directory",
        "    def __exit__(self, *args):",
        "        return self.inner.__exit__(*args)",
        "def tracked_temporary_file(*args, **kwargs):",
        "    directories.append(Path(kwargs['dir']).resolve())",
        "    return temporary_file(*args, **kwargs)",
        "target.tempfile.TemporaryDirectory = TrackedTemporaryDirectory",
        "target.tempfile.TemporaryFile = tracked_temporary_file",
        "digest = target.committed_diff_content_digest(Path(sys.argv[2]), sys.argv[3], sys.argv[4])",
        "configured = Path(os.environ['CODEX_SECURITY_STATE_DIR']).resolve()",
        "print(json.dumps({'allConfined': len(roots) == 1 and all(directory == roots[0] for directory in directories) and roots[0].parent == configured, 'digest': digest, 'privateMode': modes == [0o700], 'residue': [entry.name for entry in configured.iterdir()], 'rootRemoved': len(roots) == 1 and not roots[0].exists(), 'roots': len(roots), 'spools': len(directories)}))",
      ],
      [repository, base, head],
      state,
    );

    expect(result).toMatchObject({
      allConfined: true,
      privateMode: true,
      residue: [],
      rootRemoved: true,
      roots: 1,
      spools: 3,
    });
    expect(result.digest).toMatch(
      /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
    );
  });

  test("does not require the persistent state root for setup inspection", () => {
    const { base, head, repository, root } = createRepository();
    const blockedHome = join(root, "codex-home-file");
    writeFileSync(blockedHome, "not a directory\n");

    expect(
      committedDigest(repository, undefined, base, head, {
        CODEX_HOME: blockedHome,
      }),
    ).toMatch(/^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u);
    expect(existsSync(join(blockedHome, "state"))).toBe(false);
  });

  test("confines state-free digest spools to one disposable directory", () => {
    const { base, head, repository, root } = createRepository();
    const temporaryRoot = join(root, "temporary");
    mkdirSync(temporaryRoot, { mode: 0o700 });
    const result = runPythonJson<{
      allConfined: boolean;
      digest: string;
      residue: string[];
      rootRemoved: boolean;
      roots: number;
      spools: number;
    }>(
      [
        "import json",
        "from pathlib import Path",
        "import workbench_target as target",
        "temporary_directory = target.tempfile.TemporaryDirectory",
        "temporary_file = target.tempfile.TemporaryFile",
        "roots, directories = [], []",
        "class TrackedTemporaryDirectory:",
        "    def __init__(self, *args, **kwargs):",
        "        self.inner = temporary_directory(*args, **kwargs)",
        "    def __enter__(self):",
        "        directory = self.inner.__enter__()",
        "        roots.append(Path(directory).resolve())",
        "        return directory",
        "    def __exit__(self, *args):",
        "        return self.inner.__exit__(*args)",
        "def tracked_temporary_file(*args, **kwargs):",
        "    directories.append(Path(kwargs['dir']).resolve())",
        "    return temporary_file(*args, **kwargs)",
        "target.tempfile.TemporaryDirectory = TrackedTemporaryDirectory",
        "target.tempfile.TemporaryFile = tracked_temporary_file",
        "digest = target.committed_diff_content_digest(Path(sys.argv[2]), sys.argv[3], sys.argv[4])",
        "temporary_root = Path(sys.argv[5]).resolve()",
        "print(json.dumps({'allConfined': len(roots) == 1 and all(directory == roots[0] for directory in directories) and roots[0].parent == temporary_root, 'digest': digest, 'residue': [entry.name for entry in temporary_root.iterdir() if entry.name.startswith('codex-security-committed-diff-')], 'rootRemoved': len(roots) == 1 and not roots[0].exists(), 'roots': len(roots), 'spools': len(directories)}))",
      ],
      [repository, base, head, temporaryRoot],
      undefined,
      { TEMP: temporaryRoot, TMP: temporaryRoot, TMPDIR: temporaryRoot },
    );

    expect(result).toMatchObject({
      allConfined: true,
      residue: [],
      rootRemoved: true,
      roots: 1,
      spools: 3,
    });
    expect(result.digest).toMatch(
      /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
    );
  });

  test("removes the state-free spool directory after snapshot failure", () => {
    const { base, head, repository, root } = createRepository();
    const temporaryRoot = join(root, "temporary-failure");
    mkdirSync(temporaryRoot, { mode: 0o700 });
    const blob = git(repository, "rev-parse", `${head}:fixture.txt`);
    const objectPath = join(
      repository,
      ".git",
      "objects",
      blob.slice(0, 2),
      blob.slice(2),
    );
    const backupPath = `${objectPath}.backup`;
    renameSync(objectPath, backupPath);
    try {
      expect(
        runPython(
          [
            "from pathlib import Path",
            "from workbench_target import committed_diff_content_digest",
            "try:",
            "    committed_diff_content_digest(Path(sys.argv[2]), sys.argv[3], sys.argv[4])",
            "except SystemExit as error:",
            "    print(error)",
          ],
          [repository, base, head],
          undefined,
          { TEMP: temporaryRoot, TMP: temporaryRoot, TMPDIR: temporaryRoot },
        ),
      ).toBe("Could not snapshot the selected committed changes.");
    } finally {
      renameSync(backupPath, objectPath);
    }
    expect(
      readdirSync(temporaryRoot).filter((entry) =>
        entry.startsWith("codex-security-committed-diff-"),
      ),
    ).toEqual([]);
  });

  test("keeps both batch helpers from launching repository promisor helpers", () => {
    const { base, head, repository, root, state } = createRepository();
    const helper = join(root, "promisor-helper.mjs");
    const started = join(root, "promisor-started");
    const leaked = join(root, "promisor-environment");
    const blob = git(repository, "rev-parse", `${head}:fixture.txt`);
    writeFileSync(
      helper,
      [
        'import { writeFileSync } from "node:fs";',
        `writeFileSync(${JSON.stringify(started)}, "started");`,
        `if (process.env.GIT_CONFIG_VALUE_0) writeFileSync(${JSON.stringify(leaked)}, process.env.GIT_CONFIG_VALUE_0);`,
        "process.exit(1);",
      ].join("\n"),
      { mode: 0o600 },
    );
    git(repository, "config", "extensions.partialClone", "unsafe");
    git(repository, "config", "remote.unsafe.promisor", "true");
    git(repository, "config", "protocol.ext.allow", "always");
    git(
      repository,
      "config",
      "remote.unsafe.url",
      `ext::${process.execPath.replaceAll("\\", "/")} ${helper.replaceAll("\\", "/")}`,
    );
    const objectPath = join(
      repository,
      ".git",
      "objects",
      blob.slice(0, 2),
      blob.slice(2),
    );
    renameSync(objectPath, `${objectPath}.missing`);

    const result = runPythonJson<{
      blobMissing: boolean;
      digestError: string | null;
    }>(
      [
        "import json",
        "from pathlib import Path",
        "import workbench_target as target",
        "try:",
        "    target.committed_diff_content_digest(Path(sys.argv[2]), sys.argv[3], sys.argv[4])",
        "except SystemExit as error:",
        "    digest_error = str(error)",
        "else:",
        "    digest_error = None",
        "blobs = target.git_blob_bytes(Path(sys.argv[2]), [sys.argv[5]])",
        "print(json.dumps({'blobMissing': blobs == [None], 'digestError': digest_error}))",
      ],
      [repository, base, head, blob],
      state,
      {
        GIT_ALLOW_PROTOCOL: "ext",
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "http.extraHeader",
        GIT_CONFIG_VALUE_0: "SYNTHETIC_GIT_CREDENTIAL",
      },
    );

    expect(result).toEqual({
      blobMissing: true,
      digestError: "Could not snapshot the selected committed changes.",
    });
    expect(existsSync(started)).toBe(false);
    expect(existsSync(leaked)).toBe(false);
  });

  test("reuses the inspected committed digest when creating a workspace", () => {
    const { base, head, repository, state } = createRepository();
    const result = runPythonJson<{ digestCalls: number; valid: boolean }>(
      [
        "import argparse, json, uuid",
        "import workbench_db as workbench",
        "original_digest = workbench.committed_diff_content_snapshot",
        "digest_calls = 0",
        "def counted_digest(*args):",
        "    global digest_calls",
        "    digest_calls += 1",
        "    return original_digest(*args)",
        "workbench.committed_diff_content_snapshot = counted_digest",
        "arguments = argparse.Namespace(workspace_id=str(uuid.uuid4()), thread_id=None, target_path=sys.argv[2], target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='range', diff_base_revision=sys.argv[3], diff_head_revision=sys.argv[4], diff_content_digest=None)",
        "with workbench.connect() as connection:",
        "    result = workbench.create_workspace(connection, arguments)",
        "print(json.dumps({'digestCalls': digest_calls, 'valid': result['setupValidation']['valid']}))",
      ],
      [repository, base, head],
      state,
    );

    expect(result).toEqual({ digestCalls: 1, valid: true });
  });

  test("reuses the stored digest when saving the same committed selection", () => {
    const { base, head, repository, state } = createRepository();
    const result = runPythonJson<{
      after: string;
      before: string;
      submitted: boolean;
    }>(
      [
        "import argparse, json, uuid",
        "import workbench_db as workbench",
        "workspace_id = str(uuid.uuid4())",
        "create_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=sys.argv[2], target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='range', diff_base_revision=sys.argv[3], diff_head_revision=sys.argv[4], diff_content_digest=None)",
        "save_args = argparse.Namespace(workspace_id=workspace_id, target_path=sys.argv[2], target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='range', diff_base_revision=sys.argv[3], diff_head_revision=sys.argv[4], diff_content_digest=None)",
        "with workbench.connect() as connection:",
        "    workbench.create_workspace(connection, create_args)",
        "    before = connection.execute('SELECT diff_content_digest FROM workspaces WHERE id = ?', (workspace_id,)).fetchone()['diff_content_digest']",
        "    workbench.save_workspace(connection, save_args)",
        "    row = connection.execute('SELECT diff_content_digest, submitted FROM workspaces WHERE id = ?', (workspace_id,)).fetchone()",
        "print(json.dumps({'before': before, 'after': row['diff_content_digest'], 'submitted': bool(row['submitted'])}))",
      ],
      [repository, base, head],
      state,
    );

    expect(result.after).toBe(result.before);
    expect(result.before).toMatch(
      /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
    );
    expect(result.submitted).toBe(true);
  });

  test.each(["create", "save"] as const)(
    "returns a %s response atomically despite a competing SQLite writer",
    (operation) => {
      const { base, head, repository, state } = createRepository();
      const result = runPythonJson<{
        blockerAcquired: boolean;
        blockerAttempted: boolean;
        error: string | null;
        resultId: string | null;
        rowCount: number;
        submitted: boolean;
      }>(
        [
          "import argparse, json, threading, uuid",
          "import workbench_db as workbench",
          "operation, repository, base, head = sys.argv[2:6]",
          "workspace_id = str(uuid.uuid4())",
          "blank_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=None, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='standard', diff_target_kind=None, diff_base_revision=None, diff_head_revision=None, diff_content_digest=None)",
          "selected_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=repository, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='range', diff_base_revision=base, diff_head_revision=head, diff_content_digest=None)",
          "if operation == 'save':",
          "    with workbench.connect() as setup_connection:",
          "        workbench.create_workspace(setup_connection, blank_args)",
          "blocker_ready = threading.Event()",
          "start_blocker = threading.Event()",
          "blocker_attempted = threading.Event()",
          "blocker_acquired = threading.Event()",
          "release_blocker = threading.Event()",
          "def block_writer():",
          "    with workbench.connect() as blocker:",
          "        blocker_ready.set()",
          "        if not start_blocker.wait(5):",
          "            raise RuntimeError('blocker start timed out')",
          "        blocker_attempted.set()",
          "        blocker.execute('BEGIN IMMEDIATE')",
          "        blocker_acquired.set()",
          "        if not release_blocker.wait(5):",
          "            raise RuntimeError('blocker release timed out')",
          "        blocker.rollback()",
          "thread = threading.Thread(target=block_writer)",
          "thread.start()",
          "if not blocker_ready.wait(5):",
          "    raise RuntimeError('blocker connection timed out')",
          "original_inspected_state = workbench.inspected_workspace_state",
          "def contended_inspected_state(connection, selected_workspace_id, **kwargs):",
          "    start_blocker.set()",
          "    expected_event = blocker_attempted if connection.in_transaction else blocker_acquired",
          "    if not expected_event.wait(5):",
          "        raise RuntimeError('blocker did not reach expected state')",
          "    return original_inspected_state(connection, selected_workspace_id, **kwargs)",
          "workbench.inspected_workspace_state = contended_inspected_state",
          "with workbench.connect() as connection:",
          "    connection.execute('PRAGMA busy_timeout = 200')",
          "    try:",
          "        response = workbench.create_workspace(connection, selected_args) if operation == 'create' else workbench.save_workspace(connection, selected_args)",
          "    except BaseException as error:",
          "        message = f'{type(error).__name__}: {error}'",
          "        result_id = None",
          "    else:",
          "        message = None",
          "        result_id = response['id']",
          "if not blocker_acquired.wait(5):",
          "    raise RuntimeError('blocker did not acquire the writer lock')",
          "release_blocker.set()",
          "thread.join(10)",
          "if thread.is_alive():",
          "    raise RuntimeError('blocker thread did not finish')",
          "with workbench.connect() as connection:",
          "    row_count = connection.execute('SELECT COUNT(*) FROM workspaces WHERE id = ?', (workspace_id,)).fetchone()[0]",
          "    submitted = bool(connection.execute('SELECT submitted FROM workspaces WHERE id = ?', (workspace_id,)).fetchone()['submitted'])",
          "print(json.dumps({'blockerAcquired': blocker_acquired.is_set(), 'blockerAttempted': blocker_attempted.is_set(), 'error': message, 'resultId': result_id, 'rowCount': row_count, 'submitted': submitted}))",
        ],
        [operation, repository, base, head],
        state,
      );

      expect(result).toEqual({
        blockerAcquired: true,
        blockerAttempted: true,
        error: null,
        resultId: expect.any(String),
        rowCount: 1,
        submitted: operation === "save",
      });
    },
  );

  test("does not repeat a failed setup digest inside SQLite", () => {
    const { base, head, repository, state } = createRepository();
    const selectedDigest = committedDigest(repository, state, base, head);
    const selectedBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
    const replacement = spawnSync(
      "git",
      ["-C", repository, "hash-object", "-w", "--stdin"],
      { encoding: "utf8", input: "substituted\n" },
    );
    expect(replacement.status, replacement.stderr).toBe(0);
    git(repository, "replace", "-f", selectedBlob, replacement.stdout.trim());

    const result = runPythonJson<{
      digestTransactions: boolean[];
      setupValidation: { error: string | null; valid: boolean };
    }>(
      [
        "import argparse, json, uuid",
        "import workbench_db as workbench",
        "original_digest = workbench.committed_diff_content_snapshot",
        "digest_transactions = []",
        "with workbench.connect() as connection:",
        "    def tracked_digest(*args):",
        "        digest_transactions.append(connection.in_transaction)",
        "        return original_digest(*args)",
        "    workbench.committed_diff_content_snapshot = tracked_digest",
        "    arguments = argparse.Namespace(workspace_id=str(uuid.uuid4()), thread_id=None, target_path=sys.argv[2], target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='range', diff_base_revision=sys.argv[3], diff_head_revision=sys.argv[4], diff_content_digest=sys.argv[5])",
        "    result = workbench.create_workspace(connection, arguments)",
        "print(json.dumps({'digestTransactions': digest_transactions, 'setupValidation': result['setupValidation']}))",
      ],
      [repository, base, head, selectedDigest],
      state,
    );

    expect(result).toEqual({
      digestTransactions: [false],
      setupValidation: {
        error:
          "The committed changes selected for review no longer produce the same diff. " +
          "Select the changes to review again.",
        valid: false,
      },
    });
  });

  test("rolls back a create rejected during rendering", () => {
    const { base, head, repository, state } = createRepository();
    writeFileSync(join(repository, "fixture.txt"), "new head\n");
    git(repository, "add", "fixture.txt");
    commit(repository, "new head");
    const newHead = git(repository, "rev-parse", "HEAD");
    const newDigest = committedDigest(repository, state, head, newHead);

    const result = runPythonJson<{
      digestCalls: number;
      persisted: {
        baseRevision: string;
        contentDigest: string;
        headRevision: string;
      } | null;
      error: string | null;
    }>(
      [
        "import argparse, json, uuid",
        "import workbench_db as workbench",
        "repository, base, head, new_head, new_digest = sys.argv[2:7]",
        "original_digest = workbench.committed_diff_content_snapshot",
        "digest_calls = 0",
        "def counted_digest(*args):",
        "    global digest_calls",
        "    digest_calls += 1",
        "    return original_digest(*args)",
        "workbench.committed_diff_content_snapshot = counted_digest",
        "original_inspected_state = workbench.inspected_workspace_state",
        "def raced_inspected_state(connection, workspace_id, **kwargs):",
        "    connection.execute('UPDATE workspaces SET diff_base_revision = ?, diff_head_revision = ?, diff_content_digest = ?, updated_at = ? WHERE id = ?', (head, new_head, new_digest, '2099-01-01T00:00:00Z', workspace_id))",
        "    return original_inspected_state(connection, workspace_id, **kwargs)",
        "workbench.inspected_workspace_state = raced_inspected_state",
        "arguments = argparse.Namespace(workspace_id=str(uuid.uuid4()), thread_id=None, target_path=repository, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='range', diff_base_revision=base, diff_head_revision=head, diff_content_digest=None)",
        "with workbench.connect() as connection:",
        "    try:",
        "        workbench.create_workspace(connection, arguments)",
        "    except SystemExit as error:",
        "        message = str(error)",
        "    else:",
        "        message = None",
        "    persisted = connection.execute('SELECT diff_base_revision, diff_head_revision, diff_content_digest FROM workspaces WHERE id = ?', (arguments.workspace_id,)).fetchone()",
        "persisted_json = None if persisted is None else {'baseRevision': persisted['diff_base_revision'], 'headRevision': persisted['diff_head_revision'], 'contentDigest': persisted['diff_content_digest']}",
        "print(json.dumps({'digestCalls': digest_calls, 'error': message, 'persisted': persisted_json}))",
      ],
      [repository, base, head, newHead, newDigest],
      state,
    );

    expect(result).toEqual({
      digestCalls: 1,
      error:
        "Codex Security setup changed while it was being saved. Try again.",
      persisted: null,
    });
  });

  test("rolls back a save rejected during rendering", () => {
    const { base, head, repository, state } = createRepository();
    const selectedDigest = committedDigest(repository, state, base, head);
    const result = runPythonJson<{
      error: string | null;
      unchanged: boolean;
    }>(
      [
        "import argparse, json, uuid",
        "import workbench_db as workbench",
        "workspace_id = str(uuid.uuid4())",
        "create_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=None, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='standard', diff_target_kind=None, diff_base_revision=None, diff_head_revision=None, diff_content_digest=None)",
        "with workbench.connect() as connection:",
        "    workbench.create_workspace(connection, create_args)",
        "save_args = argparse.Namespace(workspace_id=workspace_id, target_path=sys.argv[2], target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind='range', diff_base_revision=sys.argv[3], diff_head_revision=sys.argv[4], diff_content_digest=sys.argv[5])",
        "original_inspected_state = workbench.inspected_workspace_state",
        "def raced_inspected_state(connection, selected_workspace_id, **kwargs):",
        "    connection.execute('UPDATE workspaces SET updated_at = ? WHERE id = ?', ('2099-01-01T00:00:00Z', selected_workspace_id))",
        "    return original_inspected_state(connection, selected_workspace_id, **kwargs)",
        "workbench.inspected_workspace_state = raced_inspected_state",
        "with workbench.connect() as connection:",
        "    before = dict(connection.execute('SELECT target_path, submitted, updated_at FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
        "    try:",
        "        workbench.save_workspace(connection, save_args)",
        "    except SystemExit as error:",
        "        message = str(error)",
        "    else:",
        "        message = None",
        "    after = dict(connection.execute('SELECT target_path, submitted, updated_at FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
        "print(json.dumps({'error': message, 'unchanged': before == after}))",
      ],
      [repository, base, head, selectedDigest],
      state,
    );

    expect(result).toEqual({
      error:
        "Codex Security setup changed while it was being saved. Try again.",
      unchanged: true,
    });
  });

  test.each(["working_tree", "commit", "range"] as const)(
    "rejects a submitted %s start when the target changes behind a writer lock",
    (kind) => {
      const { base, head, repository, root, state } = createRepository();
      const selectedBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
      const replacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "changed behind lock\n" },
      );
      expect(replacement.status, replacement.stderr).toBe(0);
      const replacementBlob = replacement.stdout.trim();

      const result = runPythonJson<{
        after: {
          activeScanId: string | null;
          contentDigest: string;
          submitted: number;
          updatedAt: string;
        };
        before: {
          activeScanId: string | null;
          contentDigest: string;
          submitted: number;
          updatedAt: string;
        };
        beginAttempted: boolean;
        error: string | null;
        inTransaction: boolean;
        scanCount: number;
        snapshotCalls: number;
        started: boolean;
      }>(
        [
          "import argparse, json, subprocess, threading, uuid",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "kind, repository, base, head, root, selected_blob, replacement_blob = sys.argv[2:9]",
          "workspace_id = str(uuid.uuid4())",
          "selected_base = head if kind == 'working_tree' else base",
          "create_args = argparse.Namespace(workspace_id=workspace_id, thread_id=None, target_path=repository, target_title=None, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind=kind, diff_base_revision=selected_base, diff_head_revision=head, diff_content_digest=None)",
          "save_args = argparse.Namespace(workspace_id=workspace_id, target_path=repository, target_summary=None, user_context=None, user_context_stdin=False, scope='.', mode='diff', diff_target_kind=kind, diff_base_revision=selected_base, diff_head_revision=head, diff_content_digest=None)",
          "start_args = argparse.Namespace(workspace_id=workspace_id, scan_root=str(Path(root) / 'submitted-scans'), model=None, reasoning_effort=None)",
          "with workbench.connect() as connection:",
          "    workbench.create_workspace(connection, create_args)",
          "    workbench.save_workspace(connection, save_args)",
          "    before = dict(connection.execute('SELECT active_scan_id AS activeScanId, diff_content_digest AS contentDigest, submitted, updated_at AS updatedAt FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
          "snapshot_name = 'worktree_content_digest' if kind == 'working_tree' else 'committed_diff_content_snapshot'",
          "original_snapshot = getattr(workbench, snapshot_name)",
          "snapshot_calls = 0",
          "def counted_snapshot(*args, **kwargs):",
          "    global snapshot_calls",
          "    snapshot_calls += 1",
          "    return original_snapshot(*args, **kwargs)",
          "setattr(workbench, snapshot_name, counted_snapshot)",
          "begin_attempted = threading.Event()",
          "connection_ready = threading.Event()",
          "start_worker = threading.Event()",
          "outcome = {'error': None, 'inTransaction': None, 'started': False}",
          "class TrackedConnection:",
          "    def __init__(self, delegate):",
          "        self.delegate = delegate",
          "    def execute(self, sql, *args):",
          "        if sql.strip().upper() == 'BEGIN IMMEDIATE':",
          "            begin_attempted.set()",
          "        return self.delegate.execute(sql, *args)",
          "    def __getattr__(self, name):",
          "        return getattr(self.delegate, name)",
          "def worker():",
          "    with workbench.connect() as delegate:",
          "        connection_ready.set()",
          "        if not start_worker.wait(5):",
          "            outcome['error'] = 'worker start timed out'",
          "            return",
          "        try:",
          "            workbench.start_scan(TrackedConnection(delegate), start_args)",
          "        except SystemExit as error:",
          "            outcome['error'] = str(error)",
          "        else:",
          "            outcome['started'] = True",
          "        outcome['inTransaction'] = delegate.in_transaction",
          "thread = threading.Thread(target=worker)",
          "thread.start()",
          "if not connection_ready.wait(5):",
          "    raise RuntimeError('worker connection timed out')",
          "with workbench.connect() as blocker:",
          "    blocker.execute('BEGIN IMMEDIATE')",
          "    start_worker.set()",
          "    if not begin_attempted.wait(5):",
          "        raise RuntimeError('scan did not reach writer lock')",
          "    if kind == 'working_tree':",
          "        (Path(repository) / 'fixture.txt').write_text('changed behind lock\\n')",
          "    else:",
          "        subprocess.run(['git', '-C', repository, 'replace', '-f', selected_blob, replacement_blob], check=True)",
          "    blocker.commit()",
          "thread.join(10)",
          "if thread.is_alive():",
          "    raise RuntimeError('scan worker did not finish')",
          "with workbench.connect() as connection:",
          "    after = dict(connection.execute('SELECT active_scan_id AS activeScanId, diff_content_digest AS contentDigest, submitted, updated_at AS updatedAt FROM workspaces WHERE id = ?', (workspace_id,)).fetchone())",
          "    scan_count = connection.execute('SELECT COUNT(*) FROM scans WHERE workspace_id = ?', (workspace_id,)).fetchone()[0]",
          "print(json.dumps({'after': after, 'before': before, 'beginAttempted': begin_attempted.is_set(), 'scanCount': scan_count, 'snapshotCalls': snapshot_calls, **outcome}))",
        ],
        [kind, repository, base, head, root, selectedBlob, replacementBlob],
        state,
      );

      expect(result).toMatchObject({
        beginAttempted: true,
        error:
          kind === "working_tree"
            ? "Working-tree contents changed after they were selected. Select Uncommitted changes again."
            : "The committed changes selected for review no longer produce the same diff. Select the changes to review again.",
        inTransaction: false,
        scanCount: 0,
        snapshotCalls: 2,
        started: false,
      });
      expect(result.after).toEqual(result.before);
      expect(result.before).toMatchObject({
        activeScanId: null,
        submitted: 1,
      });
      expect(result.before.contentDigest).toMatch(
        /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
      );
    },
  );

  test.each([
    ["create", "working_tree"],
    ["rejoin", "working_tree"],
    ["create", "commit"],
    ["rejoin", "commit"],
  ] as const)(
    "rejects a %s %s start when the target changes behind a writer lock",
    (action, kind) => {
      const { base, head, repository, root, state } = createRepository();
      const result = runPythonJson<{
        beginAttempted: boolean;
        counts: { scans: number; workspaces: number };
        disposition: string | null;
        error: string | null;
        snapshotCalls: number;
      }>(
        [
          "import argparse, json, shutil, threading",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "action, kind, repository, base, head, root = sys.argv[2:8]",
          "scan_root = Path(root) / 'locked-scans'",
          "scan_root.mkdir(mode=0o700)",
          "def arguments():",
          "    return argparse.Namespace(thread_id=f'locked-{action}-{kind}', target_path=repository, scope='.', mode='diff', target_summary=None, user_context=None, user_context_stdin=False, diff_target_kind=kind, diff_base_revision=head if kind == 'working_tree' else base, diff_head_revision=head, diff_content_digest=None, scan_root=str(scan_root), model=None, reasoning_effort=None)",
          "if action == 'rejoin':",
          "    with workbench.connect() as connection:",
          "        workbench.start_prompt_only_scan(connection, arguments())",
          "original_require_diff_target = workbench.require_diff_target_snapshot",
          "snapshot_calls = 0",
          "def counted_require_diff_target(*args):",
          "    global snapshot_calls",
          "    snapshot_calls += 1",
          "    return original_require_diff_target(*args)",
          "workbench.require_diff_target_snapshot = counted_require_diff_target",
          "begin_attempted = threading.Event()",
          "connection_ready = threading.Event()",
          "start_worker = threading.Event()",
          "outcome = {'disposition': None, 'error': None}",
          "class TrackedConnection:",
          "    def __init__(self, delegate):",
          "        self.delegate = delegate",
          "    def execute(self, sql, *args):",
          "        if sql.strip().upper() == 'BEGIN IMMEDIATE':",
          "            begin_attempted.set()",
          "        return self.delegate.execute(sql, *args)",
          "    def __getattr__(self, name):",
          "        return getattr(self.delegate, name)",
          "def worker():",
          "    with workbench.connect() as delegate:",
          "        connection_ready.set()",
          "        if not start_worker.wait(5):",
          "            outcome['error'] = 'worker start timed out'",
          "            return",
          "        try:",
          "            started = workbench.start_prompt_only_scan(TrackedConnection(delegate), arguments())",
          "        except SystemExit as error:",
          "            outcome['error'] = str(error)",
          "        else:",
          "            outcome['disposition'] = started['startDisposition']",
          "thread = threading.Thread(target=worker)",
          "thread.start()",
          "if not connection_ready.wait(5):",
          "    raise RuntimeError('worker connection timed out')",
          "with workbench.connect() as blocker:",
          "    blocker.execute('BEGIN IMMEDIATE')",
          "    start_worker.set()",
          "    if not begin_attempted.wait(5):",
          "        raise RuntimeError('scan did not reach writer lock')",
          "    target = Path(repository)",
          "    if kind == 'working_tree':",
          "        (target / 'fixture.txt').write_text('changed behind lock\\n')",
          "    else:",
          "        parked = Path(root) / 'parked-repository'",
          "        target.rename(parked)",
          "        shutil.copytree(parked, target)",
          "    blocker.commit()",
          "thread.join(10)",
          "if thread.is_alive():",
          "    raise RuntimeError('scan worker did not finish')",
          "with workbench.connect() as connection:",
          "    counts = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('workspaces', 'scans')}",
          "print(json.dumps({'beginAttempted': begin_attempted.is_set(), 'counts': counts, 'snapshotCalls': snapshot_calls, **outcome}))",
        ],
        [action, kind, repository, base, head, root],
        state,
      );

      expect(result).toEqual({
        beginAttempted: true,
        counts: {
          scans: action === "rejoin" ? 1 : 0,
          workspaces: action === "rejoin" ? 1 : 0,
        },
        disposition: null,
        error:
          "The selected scan target changed while the scan was starting. Try again.",
        snapshotCalls: 2,
      });
    },
  );

  test.each(["commit", "range"] as const)(
    "rejoins a legacy active %s scan only when both stored digests are null",
    (kind) => {
      const { base, head, repository, root, state } = createRepository();
      const result = runPythonJson<{
        disposition: string;
        scanCount: number;
        scanDigest: string | null;
        sameScan: boolean;
        workspaceCount: number;
        workspaceDigest: string | null;
      }>(
        [
          "import argparse, json",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "kind, repository, base, head, scan_root = sys.argv[2:7]",
          "Path(scan_root).mkdir(mode=0o700)",
          "def arguments():",
          "    return argparse.Namespace(thread_id=f'legacy-{kind}', target_path=repository, scope='.', mode='diff', target_summary=None, user_context=None, user_context_stdin=False, diff_target_kind=kind, diff_base_revision=base, diff_head_revision=head, diff_content_digest=None, scan_root=scan_root, model=None, reasoning_effort=None)",
          "with workbench.connect() as connection:",
          "    first = workbench.start_prompt_only_scan(connection, arguments())",
          "    first_scan_id = first['scan']['scanId']",
          "    workspace_id = connection.execute('SELECT workspace_id FROM scans WHERE id = ?', (first_scan_id,)).fetchone()['workspace_id']",
          "    connection.execute('UPDATE workspaces SET diff_content_digest = NULL WHERE id = ?', (workspace_id,))",
          "    connection.execute('UPDATE scans SET diff_content_digest = NULL WHERE id = ?', (first_scan_id,))",
          "    connection.commit()",
          "    joined = workbench.start_prompt_only_scan(connection, arguments())",
          "    row = connection.execute('SELECT workspaces.diff_content_digest AS workspace_digest, scans.diff_content_digest AS scan_digest FROM scans JOIN workspaces ON workspaces.id = scans.workspace_id WHERE scans.id = ?', (first_scan_id,)).fetchone()",
          "    counts = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('workspaces', 'scans')}",
          "print(json.dumps({'disposition': joined['startDisposition'], 'sameScan': joined['scan']['scanId'] == first_scan_id, 'workspaceDigest': row['workspace_digest'], 'scanDigest': row['scan_digest'], 'workspaceCount': counts['workspaces'], 'scanCount': counts['scans']}))",
        ],
        [kind, repository, base, head, join(root, "legacy-scans")],
        state,
      );

      expect(result).toEqual({
        disposition: "joined",
        sameScan: true,
        workspaceDigest: null,
        scanDigest: null,
        workspaceCount: 1,
        scanCount: 1,
      });
    },
  );

  test.each(["commit", "range"] as const)(
    "does not rejoin a legacy active %s scan with an explicit digest",
    (kind) => {
      const { base, head, repository, root, state } = createRepository();
      const selectedDigest = committedDigest(repository, state, base, head);
      const result = runPythonJson<{
        createdScanDigest: string | null;
        createdWorkspaceDigest: string | null;
        disposition: string;
        legacyScanDigest: string | null;
        legacyWorkspaceDigest: string | null;
        sameScan: boolean;
        scanCount: number;
        workspaceCount: number;
      }>(
        [
          "import argparse, json",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "kind, repository, base, head, selected_digest, scan_root = sys.argv[2:8]",
          "Path(scan_root).mkdir(mode=0o700)",
          "def arguments(content_digest):",
          "    return argparse.Namespace(thread_id=f'explicit-legacy-{kind}', target_path=repository, scope='.', mode='diff', target_summary=None, user_context=None, user_context_stdin=False, diff_target_kind=kind, diff_base_revision=base, diff_head_revision=head, diff_content_digest=content_digest, scan_root=scan_root, model=None, reasoning_effort=None)",
          "with workbench.connect() as connection:",
          "    legacy = workbench.start_prompt_only_scan(connection, arguments(None))",
          "    legacy_scan_id = legacy['scan']['scanId']",
          "    legacy_workspace_id = connection.execute('SELECT workspace_id FROM scans WHERE id = ?', (legacy_scan_id,)).fetchone()['workspace_id']",
          "    connection.execute('UPDATE workspaces SET diff_content_digest = NULL WHERE id = ?', (legacy_workspace_id,))",
          "    connection.execute('UPDATE scans SET diff_content_digest = NULL WHERE id = ?', (legacy_scan_id,))",
          "    connection.commit()",
          "    started = workbench.start_prompt_only_scan(connection, arguments(selected_digest))",
          "    created_scan_id = started['scan']['scanId']",
          "    created = connection.execute('SELECT workspaces.diff_content_digest AS workspace_digest, scans.diff_content_digest AS scan_digest FROM scans JOIN workspaces ON workspaces.id = scans.workspace_id WHERE scans.id = ?', (created_scan_id,)).fetchone()",
          "    legacy_row = connection.execute('SELECT workspaces.diff_content_digest AS workspace_digest, scans.diff_content_digest AS scan_digest FROM scans JOIN workspaces ON workspaces.id = scans.workspace_id WHERE scans.id = ?', (legacy_scan_id,)).fetchone()",
          "    counts = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('workspaces', 'scans')}",
          "print(json.dumps({'disposition': started['startDisposition'], 'sameScan': created_scan_id == legacy_scan_id, 'createdWorkspaceDigest': created['workspace_digest'], 'createdScanDigest': created['scan_digest'], 'legacyWorkspaceDigest': legacy_row['workspace_digest'], 'legacyScanDigest': legacy_row['scan_digest'], 'workspaceCount': counts['workspaces'], 'scanCount': counts['scans']}))",
        ],
        [
          kind,
          repository,
          base,
          head,
          selectedDigest,
          join(root, "explicit-legacy-scans"),
        ],
        state,
      );

      expect(result).toEqual({
        disposition: "created",
        sameScan: false,
        createdWorkspaceDigest: selectedDigest,
        createdScanDigest: selectedDigest,
        legacyWorkspaceDigest: null,
        legacyScanDigest: null,
        workspaceCount: 2,
        scanCount: 2,
      });
    },
  );

  test("prefers an exact digested active scan over a newer legacy row", () => {
    const { base, head, repository, root, state } = createRepository();
    const result = runPythonJson<{
      disposition: string;
      exactSelected: boolean;
      legacyScanDigest: string | null;
      legacyWorkspaceDigest: string | null;
      scanCount: number;
      workspaceCount: number;
    }>(
      [
        "import argparse, json",
        "from pathlib import Path",
        "import workbench_db as workbench",
        "repository, base, head, scan_root = sys.argv[2:6]",
        "Path(scan_root).mkdir(mode=0o700)",
        "thread_id = 'exact-digest-preference'",
        "def arguments():",
        "    return argparse.Namespace(thread_id=thread_id, target_path=repository, scope='.', mode='diff', target_summary=None, user_context=None, user_context_stdin=False, diff_target_kind='range', diff_base_revision=base, diff_head_revision=head, diff_content_digest=None, scan_root=scan_root, model=None, reasoning_effort=None)",
        "with workbench.connect() as connection:",
        "    legacy = workbench.start_prompt_only_scan(connection, arguments())",
        "    legacy_scan_id = legacy['scan']['scanId']",
        "    legacy_workspace_id = connection.execute('SELECT workspace_id FROM scans WHERE id = ?', (legacy_scan_id,)).fetchone()['workspace_id']",
        "    connection.execute('UPDATE workspaces SET thread_id = ?, diff_content_digest = NULL WHERE id = ?', ('temporary-owner', legacy_workspace_id))",
        "    connection.execute('UPDATE scans SET diff_content_digest = NULL WHERE id = ?', (legacy_scan_id,))",
        "    connection.commit()",
        "    exact = workbench.start_prompt_only_scan(connection, arguments())",
        "    exact_scan_id = exact['scan']['scanId']",
        "    connection.execute('UPDATE workspaces SET thread_id = ? WHERE id = ?', (thread_id, legacy_workspace_id))",
        "    connection.execute(\"UPDATE scans SET updated_at = '2099-01-01T00:00:00Z' WHERE id = ?\", (legacy_scan_id,))",
        "    connection.commit()",
        "    joined = workbench.start_prompt_only_scan(connection, arguments())",
        "    legacy_row = connection.execute('SELECT workspaces.diff_content_digest AS workspace_digest, scans.diff_content_digest AS scan_digest FROM scans JOIN workspaces ON workspaces.id = scans.workspace_id WHERE scans.id = ?', (legacy_scan_id,)).fetchone()",
        "    counts = {table: connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('workspaces', 'scans')}",
        "print(json.dumps({'disposition': joined['startDisposition'], 'exactSelected': joined['scan']['scanId'] == exact_scan_id, 'legacyWorkspaceDigest': legacy_row['workspace_digest'], 'legacyScanDigest': legacy_row['scan_digest'], 'workspaceCount': counts['workspaces'], 'scanCount': counts['scans']}))",
      ],
      [repository, base, head, join(root, "preference-scans")],
      state,
    );

    expect(result).toEqual({
      disposition: "joined",
      exactSelected: true,
      legacyWorkspaceDigest: null,
      legacyScanDigest: null,
      workspaceCount: 2,
      scanCount: 2,
    });
  });

  test.each(["commit", "range"] as const)(
    "hashes outside SQLite once per %s completion phase and warns on finalization drift",
    (kind) => {
      const { base, head, repository, root, state } = createRepository();
      const selectedBlob = git(repository, "rev-parse", `${head}:fixture.txt`);
      const replacement = spawnSync(
        "git",
        ["-C", repository, "hash-object", "-w", "--stdin"],
        { encoding: "utf8", input: "completion replacement\n" },
      );
      expect(replacement.status, replacement.stderr).toBe(0);
      const result = runPythonJson<{
        completedWarnings: string[];
        completedTargetWarnings: string[];
        genericWarning: string;
        phaseBatchCounts: number[];
        transactions: boolean[];
        preparedTargetWarnings: string[];
      }>(
        [
          "import argparse, json, os, shutil, subprocess",
          "from pathlib import Path",
          "import workbench_db as workbench",
          "import workbench_target as target",
          "kind, repository, base, head, scan_root, plugin_root, selected_blob, replacement_blob = sys.argv[2:10]",
          "Path(scan_root).mkdir(mode=0o700)",
          "start_args = argparse.Namespace(thread_id=f'completion-{kind}', target_path=repository, scope='.', mode='diff', target_summary=None, user_context=None, user_context_stdin=False, diff_target_kind=kind, diff_base_revision=base, diff_head_revision=head, diff_content_digest=None, scan_root=scan_root, model=None, reasoning_effort=None)",
          "completion_args = argparse.Namespace(scan_id=None, claim_token=None, cost_json=None, thread_id=None)",
          "with workbench.connect() as connection:",
          "    started = workbench.start_prompt_only_scan(connection, start_args)",
          "    scan_id = started['scan']['scanId']",
          "    completion_args.scan_id = scan_id",
          "    scan = workbench.require_scan(connection, scan_id)",
          "    scan_dir = Path(scan['scan_dir'])",
          "    shutil.copytree(Path(plugin_root) / 'examples' / 'completed-scan', scan_dir, dirs_exist_ok=True)",
          "    if os.name != 'nt':",
          "        scan_dir.parent.chmod(0o700)",
          "        scan_dir.chmod(0o700)",
          "    manifest_path = scan_dir / 'scan-manifest.json'",
          "    manifest = json.loads(manifest_path.read_text())",
          "    manifest['scan']['id'] = scan_id",
          "    manifest['scan']['target']['kind'] = 'git_diff'",
          "    manifest['scan'].pop('sealedAt', None)",
          "    manifest['scan'].pop('artifacts', None)",
          "    manifest_path.write_text(json.dumps(manifest))",
          "    for name in ('findings.json', 'coverage.json'):",
          "        path = scan_dir / name",
          "        document = json.loads(path.read_text())",
          "        document['scanId'] = scan_id",
          "        if name == 'coverage.json': document['inventoryStrategy'] = 'diff'",
          "        path.write_text(json.dumps(document))",
          "    original_digest = target.committed_diff_content_digest",
          "    def unavailable(*args): raise SystemExit('synthetic failure')",
          "    target.committed_diff_content_digest = unavailable",
          "    generic_warning = workbench.scan_target_warning(scan)",
          "    target.committed_diff_content_digest = original_digest",
          "    original_git = target.git_command",
          "    transactions = []",
          "    def tracked_git_command(path, *args, **kwargs):",
          "        if args[:2] == ('cat-file', '--batch'): transactions.append(connection.in_transaction)",
          "        return original_git(path, *args, **kwargs)",
          "    target.git_command = tracked_git_command",
          "    original_prepare = workbench._prepare_scan_finalization",
          "    def prepare_then_replace(*args, **kwargs):",
          "        prepared = original_prepare(*args, **kwargs)",
          "        subprocess.run(['git', '-C', repository, 'replace', '-f', selected_blob, replacement_blob], check=True, stdout=subprocess.DEVNULL)",
          "        return prepared",
          "    workbench._prepare_scan_finalization = prepare_then_replace",
          "    prepared = workbench.complete_scan(connection, completion_args, prepare_only=True)",
          "    phase_batch_counts = [len(transactions)]",
          "    prepared_completed_at = json.loads(manifest_path.read_text())['scan']['completedAt']",
          "    subprocess.run(['git', '-C', repository, 'replace', '-d', selected_blob], check=True, stdout=subprocess.DEVNULL)",
          "    workbench._prepare_scan_finalization = original_prepare",
          "    workbench.now = lambda: prepared_completed_at",
          "    completed = workbench.complete_scan(connection, completion_args, prepare_only=False)",
          "    phase_batch_counts.append(len(transactions) - phase_batch_counts[0])",
          "print(json.dumps({'genericWarning': generic_warning, 'preparedTargetWarnings': prepared['targetWarnings'], 'completedTargetWarnings': completed['targetWarnings'], 'completedWarnings': completed['scan']['warnings'], 'phaseBatchCounts': phase_batch_counts, 'transactions': transactions}))",
        ],
        [
          kind,
          repository,
          base,
          head,
          join(root, "completion-scans"),
          PLUGIN_ROOT,
          selectedBlob,
          replacement.stdout.trim(),
        ],
        state,
      );
      const driftWarning =
        "Committed changes changed while the scan was running; results were saved for the original snapshot.";

      expect(result).toEqual({
        genericWarning:
          "The scan target became unavailable while the scan was running; results were saved for the original revision or snapshot.",
        preparedTargetWarnings: [driftWarning],
        completedTargetWarnings: [],
        completedWarnings: expect.arrayContaining([driftWarning]),
        phaseBatchCounts: [1, 1],
        transactions: [false, false],
      });
    },
  );

  test("selects root commits in SHA-1 and supported SHA-256 repositories", () => {
    expect(python).not.toBeNull();
    const { root, state } = createRepository();
    const emptyTrees = {
      sha1: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
      sha256:
        "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321",
    };

    for (const objectFormat of ["sha1", "sha256"] as const) {
      const repository = join(root, `root-${objectFormat}`);
      const initialized = spawnSync(
        "git",
        ["init", "--quiet", `--object-format=${objectFormat}`, repository],
        { encoding: "utf8" },
      );
      if (objectFormat === "sha256" && initialized.status !== 0) continue;
      expect(initialized.status, initialized.stderr).toBe(0);
      writeFileSync(join(repository, "source.txt"), "root fixture\n");
      git(repository, "add", "source.txt");
      commit(repository, "root");
      const head = git(repository, "rev-parse", "HEAD");
      const diffTarget = runPythonJson<{
        baseRevision: string;
        contentDigest: string;
        headRevision: string;
        kind: string;
      }>(
        [
          "import json",
          "from workbench_db import inspect_setup_values",
          "result = inspect_setup_values(sys.argv[2], '.', 'diff', 'commit', sys.argv[3], sys.argv[4], None)",
          "print(json.dumps(result['diffTarget']))",
        ],
        [repository, emptyTrees[objectFormat], head],
        state,
      );

      expect(diffTarget).toEqual({
        kind: "commit",
        baseRevision: emptyTrees[objectFormat],
        headRevision: head,
        contentDigest: expect.stringMatching(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        ),
      });
    }
  });
});
