import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { describe, expect, test } from "bun:test";

const { regularTarListingLines } = (await import(
  new URL("../scripts/package-tar-listing.mjs", import.meta.url).href
)) as { regularTarListingLines: (listing: string) => string[] };

const blockSize = 512;
const distModules = [
  "api",
  "auth",
  "bulk-scan-discovery",
  "cli",
  "codex-prompt",
  "component-plan",
  "component-scan",
  "config",
  "contract",
  "cost",
  "cost-model",
  "custom-validation",
  "custom-validation-prompt",
  "errors",
  "index",
  "knowledge-base",
  "linear",
  "models",
  "multiscan",
  "patch-tui",
  "publication",
  "publication-events",
  "publication-store",
  "publish",
  "result",
  "runtime",
  "scan-activity",
  "scan-comparison",
  "scan-dashboard",
  "scan-history-renderer",
  "scan-logs",
  "scan-sessions",
  "targets",
  "trusted-executable",
  "version",
  "windows-path",
  "worker-progress",
];

function octal(value: number, width: number, terminator = "\0"): Buffer {
  return Buffer.from(
    value.toString(8).padStart(width - terminator.length, "0") + terminator,
  );
}

function tarRecord(path: string, contents: Buffer, mode = 0o644): Buffer {
  const header = Buffer.alloc(blockSize);
  header.write(path, 0, 100, "utf8");
  octal(mode, 8).copy(header, 100);
  octal(0, 8).copy(header, 108);
  octal(0, 8).copy(header, 116);
  octal(contents.length, 12, " ").copy(header, 124);
  octal(0, 12).copy(header, 136);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  header.write("ustar\0", 257, "binary");
  header.write("00", 263, "binary");
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  Buffer.from(checksum.toString(8).padStart(6, "0") + "\0 ").copy(header, 148);
  return Buffer.concat([
    header,
    contents,
    Buffer.alloc(
      Math.ceil(contents.length / blockSize) * blockSize - contents.length,
    ),
  ]);
}

function packageTar(trailingZeroBytes = 0): Buffer {
  const paths = [
    "package/package.json",
    "package/README.md",
    "package/LICENSE",
    "package/bin/codex-security.mjs",
    ...distModules.flatMap((module) =>
      ["js", "js.map", "d.ts", "d.ts.map"].map(
        (extension) => `package/dist/${module}.${extension}`,
      ),
    ),
    "package/_bundled_plugin/.codex-plugin/plugin.json",
  ];
  const records = paths.map((path) => {
    const contents =
      path === "package/package.json"
        ? Buffer.from(
            JSON.stringify({
              license: "Apache-2.0",
              name: "@openai/codex-security",
            }),
          )
        : path.endsWith(".json") || path.endsWith(".map")
          ? Buffer.from("{}\n")
          : Buffer.from("fixture\n");
    return tarRecord(
      path,
      contents,
      path === "package/bin/codex-security.mjs" ? 0o755 : 0o644,
    );
  });
  return Buffer.concat([
    ...records,
    Buffer.alloc(blockSize * 2 + trailingZeroBytes),
  ]);
}

function commandPath(command: string): string {
  const lookup = spawnSync(
    process.platform === "win32" ? "where.exe" : "which",
    [command],
    { encoding: "utf8", windowsHide: true },
  );
  if (lookup.error !== undefined) throw lookup.error;
  const path = lookup.stdout.split(/\r?\n/u).find(Boolean);
  if (lookup.status !== 0 || path === undefined) {
    throw new Error(`Could not resolve ${command}.`);
  }
  return path;
}

describe("npm package tar listings", () => {
  test("accepts regular entries with Unix or Windows line endings", () => {
    const file = "-rw-r--r-- package/package.json";
    const directory = "drwxr-xr-x package/dist/";

    expect(regularTarListingLines(`${file}\n${directory}\n`)).toEqual([
      file,
      directory,
    ]);
    expect(regularTarListingLines(`${file}\r\n${directory}\r\n`)).toEqual([
      file,
      directory,
    ]);
  });

  test("rejects symbolic links and other non-regular entries", () => {
    expect(() =>
      regularTarListingLines("lrwxrwxrwx package/link -> target\r\n"),
    ).toThrow("npm tarball contains a non-regular entry");
  });

  test("accepts equivalent bounded gzip representations", () => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-gzip-test-"));
    try {
      const tarBytes = packageTar(31 * 1024 * 1024);
      const archives = [
        ["default", gzipSync(tarBytes)],
        ["level-0", gzipSync(tarBytes, { level: 0 })],
      ] as const;
      expect(archives[0][1].length).toBeLessThan(1024 * 1024);
      expect(archives[1][1].length).toBeGreaterThan(31 * 1024 * 1024);

      const contractPath = join(root, "plugin contract.json");
      writeFileSync(
        contractPath,
        JSON.stringify({
          externalOwnedExact: [".codex-plugin/plugin.json"],
          shippedExact: [],
        }),
      );
      const environment: NodeJS.ProcessEnv = { ...process.env };
      delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
      for (const [representation, contents] of archives) {
        const archivePath = join(root, `${representation}.tgz`);
        writeFileSync(archivePath, contents);
        const result = spawnSync(
          commandPath("node"),
          [
            fileURLToPath(
              new URL("../scripts/check-package.mjs", import.meta.url),
            ),
            archivePath,
            contractPath,
          ],
          {
            cwd: root,
            encoding: "utf8",
            env: environment,
            timeout: 30_000,
            windowsHide: true,
          },
        );
        expect({
          representation,
          status: result.status,
          stderr: result.stderr,
        }).toEqual({ representation, status: 0, stderr: "" });
      }
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test("streams each archive without resolving tar from its directory", () => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-tar-test-"));
    try {
      const archiveDirectory = join(
        root,
        process.platform === "win32" ? "package archive" : "D: package archive",
      );
      mkdirSync(archiveDirectory, { recursive: true });
      const archivePath = join(
        archiveDirectory,
        process.platform === "win32"
          ? "-fixture package.tgz"
          : "-fixture: package.tgz",
      );
      const contractPath = join(root, "plugin contract.json");
      const logPath = join(root, "tar calls.jsonl");
      const adjacentTarMarker = join(root, "archive tar ran");
      const tarBytes = packageTar();
      const archiveContents = gzipSync(tarBytes, { level: 0 });
      writeFileSync(archivePath, archiveContents);
      writeFileSync(
        contractPath,
        JSON.stringify({
          externalOwnedExact: [".codex-plugin/plugin.json"],
          shippedExact: [],
        }),
      );

      const nodePath = commandPath("node");
      const environment: NodeJS.ProcessEnv = { ...process.env };
      delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
      environment["PATH"] = `.${delimiter}${process.env["PATH"] ?? ""}`;
      if (process.platform === "win32") {
        for (const name of ["tar.com", "tar.exe"]) {
          writeFileSync(join(archiveDirectory, name), "not an executable");
        }
      } else {
        const adjacentTar = join(archiveDirectory, "tar");
        writeFileSync(
          adjacentTar,
          `#!/usr/bin/env node
require("node:fs").writeFileSync(process.env.ADJACENT_TAR_MARKER, "ran");
process.exit(99);
`,
        );
        chmodSync(adjacentTar, 0o755);

        const proxySource = `#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { appendFileSync, readFileSync } = require("node:fs");
const input = readFileSync(0);
appendFileSync(
  process.env.TAR_PROXY_LOG,
  JSON.stringify({
    args: process.argv.slice(2),
    cwd: process.cwd(),
    inputLength: input.length,
    inputSha256: createHash("sha256").update(input).digest("hex"),
  }) + "\\n",
);
const result = spawnSync(process.env.REAL_TAR, process.argv.slice(2), {
  env: process.env,
  input,
  stdio: ["pipe", "inherit", "inherit"],
  windowsHide: true,
});
if (result.error !== undefined) throw result.error;
process.exit(result.status ?? 1);
`;
        const proxyPath = join(root, "tar");
        writeFileSync(proxyPath, proxySource);
        chmodSync(proxyPath, 0o755);
        environment["ADJACENT_TAR_MARKER"] = adjacentTarMarker;
        environment["REAL_TAR"] = commandPath("tar");
        environment["TAR_PROXY_LOG"] = logPath;
      }

      const result = spawnSync(
        nodePath,
        [
          fileURLToPath(
            new URL("../scripts/check-package.mjs", import.meta.url),
          ),
          archivePath,
          contractPath,
        ],
        {
          cwd: root,
          encoding: "utf8",
          env: environment,
          timeout: 30_000,
          windowsHide: true,
        },
      );
      expect(existsSync(adjacentTarMarker)).toBe(false);
      expect({ status: result.status, stderr: result.stderr }).toEqual({
        status: 0,
        stderr: "",
      });
      if (process.platform === "win32") return;

      const calls = readFileSync(logPath, "utf8")
        .trim()
        .split(/\r?\n/u)
        .map(
          (line) =>
            JSON.parse(line) as {
              args: string[];
              cwd: string;
              inputLength: number;
              inputSha256: string;
            },
        );
      const archiveSha256 = createHash("sha256")
        .update(archiveContents)
        .digest("hex");
      expect(calls).toHaveLength(3);
      for (const call of calls) {
        expect(call.args.filter((arg) => arg === "-")).toEqual(["-"]);
        expect(call.args).not.toContain(archivePath);
        expect(realpathSync(call.cwd)).toBe(realpathSync(root));
        expect(call.inputLength).toBe(archiveContents.length);
        expect(call.inputSha256).toBe(archiveSha256);
      }
      expect(calls[0]?.args).toEqual(["--ignore-zeros", "-tzf", "-"]);
      expect(calls[1]?.args).toEqual(["--ignore-zeros", "-tvzf", "-"]);
      expect(calls[2]?.args.slice(0, 9)).toEqual([
        "--ignore-zeros",
        "--keep-old-files",
        "--no-same-owner",
        "--no-same-permissions",
        "--no-acls",
        "--no-xattrs",
        "-xzf",
        "-",
        "-C",
      ]);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });
});
