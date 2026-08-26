// Rounded file timings [Unix, Windows] in seconds from CI and local runs.
// These affect only scheduling: new files automatically get a small default.
const timings = {
  "api-credentials.test.ts": [2, 48],
  "api.test.ts": [19, 77],
  "api-attribution-concurrency.test.ts": [1, 14],
  "cli-authentication.test.ts": [11, 50],
  "cli-launcher.test.ts": [15, 10],
  "compact-diff-scan.test.ts": [24, 33],
  "contract.test.ts": [15, 10],
  "custom-validation.test.ts": [19, 19],
  "deep-scan-workbench.test.ts": [27, 41],
  "multiscan.test.ts": [10, 30],
  "patch-tui.test.ts": [4, 6],
  "publication-integration.test.ts": [17, 19],
  "publication-store.test.ts": [31, 30],
  "release-automation.test.ts": [18, 50],
  "runtime-credentials.test.ts": [11, 87],
  "runtime.test.ts": [16, 60],
  "scan-comparison.test.ts": [1, 11],
  "scan-recovery.test.ts": [55, 83],
  "stopped-scan-results.test.ts": [15, 17],
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
