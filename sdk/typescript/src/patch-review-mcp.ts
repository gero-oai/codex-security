#!/usr/bin/env node

import { execFile as execFileCallback } from "node:child_process";
import { realpathSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { isAbsolute, win32 } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { promisify, stripVTControlCharacters } from "node:util";

const execFile = promisify(execFileCallback);

interface GitTreeEntry {
  mode: string;
  type: "blob" | "commit" | "tree";
  object: string;
  path: string;
  rawPath: Buffer;
}

type JsonValue = string | number | boolean | null | JsonObject | JsonValue[];
interface JsonObject {
  [key: string]: JsonValue;
}

function safeMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return stripVTControlCharacters(message).replaceAll(
    /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/gu,
    " ",
  );
}

function treePath(path: string, allowRoot = false): string {
  const normalized =
    process.platform === "win32" ? path.replaceAll("\\", "/") : path;
  if (
    (!allowRoot && normalized.length === 0) ||
    isAbsolute(path) ||
    (process.platform === "win32" &&
      (win32.isAbsolute(path) || /^[A-Za-z]:/u.test(path))) ||
    normalized.split("/").some((part) => part === "..")
  ) {
    throw new Error("Repository inspection requires a confined relative path.");
  }
  const confined = normalized.replace(/^\.\//u, "").replace(/\/$/u, "");
  return allowRoot && confined === "." ? "" : confined;
}

const RAW_TREE_PATH_PREFIX = "$git-path-base64:";

function splitRawTreePath(path: Buffer, allowRoot = false): Buffer[] {
  if (path.length === 0) {
    if (allowRoot) return [];
    throw new Error("Repository inspection requires a confined relative path.");
  }
  const parts: Buffer[] = [];
  let start = 0;
  for (let index = 0; index <= path.length; index += 1) {
    if (index !== path.length && path[index] !== 0x2f) continue;
    const part = path.subarray(start, index);
    if (
      part.length === 0 ||
      part.equals(Buffer.from(".")) ||
      part.equals(Buffer.from(".."))
    ) {
      throw new Error(
        "Repository inspection requires a confined relative path.",
      );
    }
    parts.push(part);
    start = index + 1;
  }
  return parts;
}

function publicTreePath(path: Buffer): string {
  const decoded = path.toString("utf8");
  return Buffer.from(decoded, "utf8").equals(path) &&
    !decoded.startsWith(RAW_TREE_PATH_PREFIX)
    ? decoded
    : `${RAW_TREE_PATH_PREFIX}${path.toString("base64url")}`;
}

function rawTreePath(path: string, allowRoot = false): Buffer {
  if (!path.startsWith(RAW_TREE_PATH_PREFIX)) {
    return Buffer.from(treePath(path, allowRoot), "utf8");
  }
  const encoded = path.slice(RAW_TREE_PATH_PREFIX.length);
  const decoded = Buffer.from(encoded, "base64url");
  if (
    encoded.length === 0 ||
    decoded.toString("base64url") !== encoded ||
    publicTreePath(decoded) !== path
  ) {
    throw new Error("Repository inspection requires a confined relative path.");
  }
  splitRawTreePath(decoded, allowRoot);
  return decoded;
}

function splitNulRecords(output: Buffer): Buffer[] {
  const records: Buffer[] = [];
  let start = 0;
  for (;;) {
    const end = output.indexOf(0, start);
    if (end < 0) {
      if (start < output.length) records.push(output.subarray(start));
      return records;
    }
    records.push(output.subarray(start, end));
    start = end + 1;
    if (start === output.length) return records;
  }
}

function parseTreeEntries(output: Buffer): GitTreeEntry[] {
  const records = splitNulRecords(output);
  return records.map((record) => {
    const separator = record.indexOf(0x09);
    const metadata =
      separator < 0
        ? []
        : record.subarray(0, separator).toString("ascii").split(" ");
    const [mode, type, object] = metadata;
    if (
      separator < 0 ||
      mode === undefined ||
      !/^[0-7]{6}$/u.test(mode) ||
      (type !== "blob" && type !== "commit" && type !== "tree") ||
      object === undefined ||
      !/^[0-9a-f]+$/u.test(object)
    ) {
      throw new Error("The baseline repository tree is unreadable.");
    }
    const rawPath = record.subarray(separator + 1);
    return {
      mode,
      type,
      object,
      path: publicTreePath(rawPath),
      rawPath,
    };
  });
}

function gitEnvironment(
  overrides: Readonly<Record<string, string>>,
): NodeJS.ProcessEnv {
  const environment = Object.fromEntries(
    [
      "PATH",
      "Path",
      "PATHEXT",
      "SystemRoot",
      "SYSTEMROOT",
      "WINDIR",
      "TMP",
      "TEMP",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "LC_CTYPE",
    ]
      .filter((name) => process.env[name] !== undefined)
      .map((name) => [name, process.env[name]]),
  );
  return {
    ...environment,
    GIT_ALLOW_PROTOCOL: "",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0",
    GCM_INTERACTIVE: "never",
    ...overrides,
  };
}

async function runGitBytes(
  executable: string,
  repository: string,
  args: readonly string[],
  environment: Readonly<Record<string, string>>,
): Promise<Buffer> {
  const { stdout } = await execFile(
    executable,
    [
      "-c",
      "core.fsmonitor=false",
      "-c",
      "credential.helper=",
      "-c",
      "credential.interactive=never",
      ...args,
    ],
    {
      cwd: repository,
      encoding: null,
      env: gitEnvironment(environment),
      maxBuffer: Number.POSITIVE_INFINITY,
      windowsHide: true,
    },
  );
  return Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
}

export async function runPatchReviewRepositoryMcp(
  args: readonly string[],
): Promise<number> {
  const [git, repository, tree, objectDirectory] = args;
  if (
    git === undefined ||
    repository === undefined ||
    tree === undefined ||
    objectDirectory === undefined ||
    args.length !== 4 ||
    !isAbsolute(git)
  ) {
    return 2;
  }
  const [canonicalGit, canonicalRepository] = await Promise.all([
    realpath(git),
    realpath(repository),
  ]);
  const environment = {
    GIT_OBJECT_DIRECTORY: objectDirectory,
  };
  await runGitBytes(
    canonicalGit,
    canonicalRepository,
    ["cat-file", "-e", `${tree}^{tree}`],
    environment,
  );

  const readTree = async (object: string): Promise<GitTreeEntry[]> =>
    parseTreeEntries(
      await runGitBytes(
        canonicalGit,
        canonicalRepository,
        ["ls-tree", "-z", object],
        environment,
      ),
    );
  const treeEntry = async (path: Buffer): Promise<GitTreeEntry | undefined> => {
    const parts = splitRawTreePath(path);
    let object = tree;
    for (const [index, part] of parts.entries()) {
      const entry = (await readTree(object)).find((candidate) =>
        candidate.rawPath.equals(part),
      );
      if (entry === undefined) return undefined;
      if (index === parts.length - 1) return entry;
      if (entry.type !== "tree") return undefined;
      object = entry.object;
    }
    return undefined;
  };
  const treeEntries = async (
    directory: string,
  ): Promise<{ prefix: Buffer; entries: GitTreeEntry[] }> => {
    const path = rawTreePath(directory, true);
    let object = tree;
    if (path.length > 0) {
      const entry = await treeEntry(path);
      if (entry?.type !== "tree") {
        throw new Error("The requested baseline path is not a directory.");
      }
      object = entry.object;
    }
    return { prefix: path, entries: await readTree(object) };
  };

  const send = (value: JsonObject): void => {
    process.stdout.write(`${JSON.stringify(value)}\n`);
  };
  const result = (
    id: JsonValue,
    text: string,
    isError = false,
  ): JsonObject => ({
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text }],
      ...(isError ? { isError: true } : {}),
    },
  });
  const tools: JsonObject[] = [
    {
      name: "read_file",
      description:
        "Read one file from the immutable review baseline tree. Non-UTF-8 bytes are returned as base64 JSON.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["path"],
        properties: { path: { type: "string" } },
      },
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
    },
    {
      name: "list_directory",
      description:
        "List one directory from the immutable review baseline tree.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: { path: { type: "string" } },
      },
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
    },
    {
      name: "search",
      description:
        "Search text in the immutable review baseline tree using a literal query.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["query"],
        properties: {
          query: { type: "string" },
          path: { type: "string" },
        },
      },
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
    },
  ];

  for await (const line of createInterface({ input: process.stdin })) {
    if (line.trim().length === 0) continue;
    let request: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(line);
      if (typeof parsed !== "object" || parsed === null) throw new Error();
      request = parsed as Record<string, unknown>;
    } catch {
      send({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      });
      continue;
    }
    const id = (request["id"] ?? null) as JsonValue;
    const method = request["method"];
    if (method === "notifications/initialized") continue;
    if (method === "initialize") {
      send({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-11-25",
          capabilities: { tools: {} },
          serverInfo: { name: "codex-security-patch-review", version: "1" },
        },
      });
      continue;
    }
    if (method === "tools/list") {
      send({ jsonrpc: "2.0", id, result: { tools } });
      continue;
    }
    if (method !== "tools/call") {
      if (request["id"] !== undefined) {
        send({
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: "Method not found" },
        });
      }
      continue;
    }

    const params = request["params"];
    const name =
      typeof params === "object" && params !== null && "name" in params
        ? params.name
        : undefined;
    const arguments_ =
      typeof params === "object" && params !== null && "arguments" in params
        ? params.arguments
        : undefined;
    const values =
      typeof arguments_ === "object" && arguments_ !== null
        ? (arguments_ as Record<string, unknown>)
        : {};
    try {
      if (name === "read_file") {
        if (typeof values["path"] !== "string") {
          throw new Error("read_file requires a path.");
        }
        const path = rawTreePath(values["path"]);
        const entry = await treeEntry(path);
        if (entry?.type !== "blob") {
          throw new Error("The requested baseline path is not a file.");
        }
        const contents = await runGitBytes(
          canonicalGit,
          canonicalRepository,
          ["cat-file", "blob", entry.object],
          environment,
        );
        const decoded = contents.toString("utf8");
        const text = Buffer.from(decoded, "utf8").equals(contents)
          ? decoded
          : JSON.stringify({
              encoding: "base64",
              data: contents.toString("base64"),
            });
        send(
          result(
            id,
            entry.mode === "120000"
              ? `Symbolic link target (not followed):\n${text}`
              : text,
          ),
        );
        continue;
      }
      if (name === "list_directory") {
        if (
          values["path"] !== undefined &&
          typeof values["path"] !== "string"
        ) {
          throw new Error("list_directory path must be a string.");
        }
        const { prefix, entries } = await treeEntries(
          (values["path"] as string | undefined) ?? "",
        );
        send(
          result(
            id,
            JSON.stringify(
              entries.map((entry) => ({
                path: publicTreePath(
                  prefix.length === 0
                    ? entry.rawPath
                    : Buffer.concat([prefix, Buffer.from("/"), entry.rawPath]),
                ),
                type:
                  entry.type === "tree"
                    ? "directory"
                    : entry.type === "commit"
                      ? "submodule"
                      : entry.mode === "120000"
                        ? "symlink"
                        : "file",
              })),
            ),
          ),
        );
        continue;
      }
      if (name === "search") {
        if (
          typeof values["query"] !== "string" ||
          values["query"].length === 0 ||
          (values["path"] !== undefined && typeof values["path"] !== "string")
        ) {
          throw new Error("search requires a non-empty query.");
        }
        const rawPath = rawTreePath(
          (values["path"] as string | undefined) ?? "",
          true,
        );
        const path = publicTreePath(rawPath);
        if (path.startsWith(RAW_TREE_PATH_PREFIX)) {
          throw new Error(
            "Search requires a UTF-8 directory path; use list_directory and read_file for encoded paths.",
          );
        }
        let matches = "";
        try {
          const output = await runGitBytes(
            canonicalGit,
            canonicalRepository,
            [
              "grep",
              "--full-name",
              "-n",
              "--text",
              "-F",
              "-e",
              values["query"],
              tree,
              ...(path.length === 0 ? [] : ["--", `:(top,literal)${path}`]),
            ],
            environment,
          );
          matches = output.toString("utf8");
          if (!Buffer.from(matches, "utf8").equals(output)) {
            throw new Error(
              "Search results contain a path or content that is not UTF-8; use list_directory and read_file instead.",
            );
          }
        } catch (error) {
          if (
            typeof error !== "object" ||
            error === null ||
            !("code" in error) ||
            error.code !== 1
          ) {
            throw error;
          }
        }
        send(
          result(
            id,
            matches
              .split("\n")
              .map((match) =>
                match.startsWith(`${tree}:`)
                  ? match.slice(tree.length + 1)
                  : match,
              )
              .join("\n"),
          ),
        );
        continue;
      }
      send(result(id, "Unknown repository inspection tool.", true));
    } catch (error) {
      send(result(id, safeMessage(error), true));
    }
  }
  return 0;
}

function invokedAsMain(): boolean {
  const entrypoint = process.argv[1];
  if (entrypoint === undefined) return false;
  if (import.meta.url === pathToFileURL(entrypoint).href) return true;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entrypoint)).href;
  } catch {
    return false;
  }
}

if (invokedAsMain()) {
  void runPatchReviewRepositoryMcp(process.argv.slice(2)).then(
    (exitCode) => {
      process.exitCode = exitCode;
    },
    (error: unknown) => {
      process.stderr.write(`codex-security: ${safeMessage(error)}\n`);
      process.exitCode = 2;
    },
  );
}
