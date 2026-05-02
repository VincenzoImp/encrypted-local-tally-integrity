import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(new URL("..", import.meta.url).pathname);
const logsDir = resolve(root, "logs");
const expectedDir = resolve(root, "expected");

function runCommand(command, args, logPath) {
  const result = spawnSync(command, args, {
    cwd: root,
    env: process.env,
    encoding: "utf8",
  });

  return writeFile(logPath, `${result.stdout ?? ""}${result.stderr ?? ""}`).then(() => {
    if (result.status !== 0) {
      throw new Error(`Command failed: ${command} ${args.join(" ")}`);
    }
  });
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function deepEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

async function main() {
  await mkdir(logsDir, { recursive: true });

  await runCommand("node", ["scripts/buildCircuits.mjs"], resolve(logsDir, "circuit-build.log"));
  await runCommand("npx", ["hardhat", "test"], resolve(logsDir, "contracts-test.log"));
  await runCommand("npx", ["hardhat", "run", "scripts/replayScenario.js"], resolve(logsDir, "replay.log"));

  const actual = await readJson(resolve(logsDir, "replay-summary.json"));
  const expected = await readJson(resolve(expectedDir, "replay-summary.expected.json"));

  const summary = {
    circuitBuildPassed: true,
    contractTestsPassed: true,
    replayMatchedExpected: deepEqual(actual, expected),
    generatedFiles: {
      circuitBuildLog: "logs/circuit-build.log",
      contractsLog: "logs/contracts-test.log",
      replayLog: "logs/replay.log",
      replaySummary: "logs/replay-summary.json",
    }
  };

  await writeFile(resolve(logsDir, "validation-summary.json"), JSON.stringify(summary, null, 2));

  if (!summary.replayMatchedExpected) {
    throw new Error("Replay summary does not match expected invariants");
  }

  process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
