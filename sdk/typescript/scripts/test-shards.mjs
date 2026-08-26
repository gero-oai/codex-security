// Rounded file timings [Unix, Windows] in seconds from node-ci on 2026-08-25.
// These affect only scheduling: new files automatically get a small default.
const timings = {
  "api-credentials.test.ts": [1, 48],
  "api.test.ts": [9, 77],
  "api-attribution-concurrency.test.ts": [1, 14],
  "cli-authentication.test.ts": [5, 50],
  "cli-launcher.test.ts": [8, 10],
  "compact-diff-scan.test.ts": [13, 33],
  "contract.test.ts": [8, 10],
  "custom-validation.test.ts": [8, 19],
  "deep-scan-workbench.test.ts": [14, 41],
  "multiscan.test.ts": [3, 30],
  "patch-tui.test.ts": [5, 6],
  "publication-integration.test.ts": [9, 19],
  "publication-store.test.ts": [17, 30],
  "release-automation.test.ts": [7, 50],
  "runtime.test.ts": [20, 121],
  "scan-comparison.test.ts": [1, 11],
  "scan-recovery.test.ts": [24, 83],
  "stopped-scan-results.test.ts": [7, 17],
};

export function partitionTestFiles(files, count, platform = process.platform) {
  const timingIndex = platform === "win32" ? 1 : 0;
  const estimate = (file) => timings[file]?.[timingIndex] ?? 2;
  const shards = Array.from({ length: count }, () => []);
  const totals = Array(count).fill(0);
  // Place slow files first, then give each remaining file to the lightest shard.
  for (const file of [...files]
    .sort()
    .sort((a, b) => estimate(b) - estimate(a))) {
    const index = totals.indexOf(Math.min(...totals));
    shards[index].push(file);
    totals[index] += estimate(file);
  }
  return shards;
}
