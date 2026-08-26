import { spawn } from "node:child_process";
import { mkdir, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { partitionTestFiles } from "./test-shards.mjs";

const packageDirectory = fileURLToPath(new URL("../", import.meta.url));
const args = process.argv.slice(2);
// Unix jobs run four independent Bun processes. Each selected Windows shard
// uses up to two processes; the machine-wide policy test runs separately.
const selection =
  args[0] !== undefined && !args[0].startsWith("-") ? args.shift() : undefined;
const [requestedShard, count] = selection?.split("/").map(Number) ?? [0, 4];
if (
  (selection !== undefined && !/^\d+\/\d+$/u.test(selection)) ||
  !Number.isSafeInteger(count) ||
  count < 1 ||
  !Number.isSafeInteger(requestedShard) ||
  requestedShard < (selection === undefined ? 0 : 1) ||
  requestedShard > count
) {
  throw new Error(
    "Usage: node scripts/run-ci-tests.mjs [shard/count] [Bun test options]",
  );
}
const files = (
  await readdir(new URL("../tests-ts/", import.meta.url), { recursive: true })
).filter(
  (file) =>
    file.endsWith(".test.ts") &&
    (process.platform !== "win32" || file !== "windows-machine-policy.test.ts"),
);
const shards = partitionTestFiles(files, count);
const selectedShards = shards
  .map((files, index) => ({ files, shard: index + 1 }))
  .filter(({ shard }) => requestedShard === 0 || requestedShard === shard);
if (selectedShards.some(({ files }) => files.length === 0)) {
  throw new Error("CI test shards must not be empty.");
}
const workers = selectedShards.flatMap(({ files, shard }) =>
  process.platform === "win32" && selection !== undefined
    ? partitionTestFiles(files, 2)
        .filter((files) => files.length > 0)
        .map((files, index) => ({ files, shard: `${shard}-${index + 1}` }))
    : [{ files, shard: String(shard) }],
);
await mkdir(new URL("../reports/", import.meta.url), { recursive: true });

const results = await Promise.all(
  workers.map(async ({ files, shard }) => {
    console.log(`CI test shard ${shard}/${count}: ${files.join(" ")}`);
    return await new Promise((resolve) => {
      const child = spawn(
        "bun",
        [
          "test",
          "--timeout",
          process.platform === "win32" ? "120000" : "30000",
          ...files.map((file) => "./tests-ts/" + file),
          ...args,
          "--reporter=junit",
          `--reporter-outfile=reports/junit-${shard}.xml`,
          `--coverage-dir=coverage/shard-${shard}`,
        ],
        { cwd: packageDirectory, stdio: "inherit", windowsHide: true },
      );
      child.once("error", (error) => {
        console.error(error);
        resolve(1);
      });
      child.once("close", (code) => resolve(code ?? 1));
    });
  }),
);
if (results.some((code) => code !== 0)) process.exitCode = 1;
