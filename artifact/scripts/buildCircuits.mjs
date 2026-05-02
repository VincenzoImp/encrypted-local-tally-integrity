import { copyFile, mkdir, access, stat, readFile, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(new URL("..", import.meta.url).pathname);
const circuitsRoot = resolve(root, "circuits");
const buildRoot = resolve(circuitsRoot, "build");
const ptauSource = resolve(circuitsRoot, "ptau", "pot15.ptau");
const buildScript = resolve(root, "scripts", "buildCircuits.mjs");

const circuits = [
  {
    circuitName: "EncryptedLocalTally",
    contractName: "EncryptedLocalTallyVerifier",
  },
  {
    circuitName: "PartialDecryptionShare",
    contractName: "PartialDecryptionShareVerifier",
  },
  {
    circuitName: "TrusteeRegistry2of3",
    contractName: "TrusteeRegistry2of3Verifier",
  },
];

function run(command, args, cwd = root) {
  const result = spawnSync(command, args, {
    cwd,
    env: process.env,
    encoding: "utf8",
    stdio: "pipe",
  });

  if (result.status !== 0) {
    throw new Error(
      `Command failed: ${command} ${args.join(" ")}\n${result.stdout ?? ""}\n${result.stderr ?? ""}`,
    );
  }
}

async function exists(path) {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function mtimeMs(path) {
  return (await stat(path)).mtimeMs;
}

function contractSourcePath(contractName) {
  return resolve(root, "contracts", `${contractName}.sol`);
}

function metadataFor(circuitName, contractName) {
  const circuitPath = resolve(circuitsRoot, `${circuitName}.circom`);
  const buildDir = resolve(buildRoot, circuitName);
  const ptauTarget = resolve(buildDir, "pot15.ptau");
  const r1csPath = resolve(buildDir, `${circuitName}.r1cs`);
  const wasmPath = resolve(buildDir, `${circuitName}_js`, `${circuitName}.wasm`);
  const symPath = resolve(buildDir, `${circuitName}.sym`);
  const zkeyInitial = resolve(buildDir, "circuit_0000.zkey");
  const zkeyFinal = resolve(buildDir, "circuit_final.zkey");
  const verifierJson = resolve(buildDir, "verification_key.json");
  const verifierSol = resolve(buildDir, `${contractName}.sol`);
  const targetContract = contractSourcePath(contractName);
  return {
    circuitName,
    contractName,
    circuitPath,
    buildDir,
    ptauTarget,
    r1csPath,
    wasmPath,
    symPath,
    zkeyInitial,
    zkeyFinal,
    verifierJson,
    verifierSol,
    targetContract,
  };
}

async function shouldRebuild(meta) {
  const requiredOutputs = [
    meta.r1csPath,
    meta.wasmPath,
    meta.symPath,
    meta.zkeyFinal,
    meta.verifierJson,
    meta.verifierSol,
    meta.targetContract,
  ];

  for (const output of requiredOutputs) {
    if (!(await exists(output))) {
      return true;
    }
  }

  const newestInput = Math.max(
    await mtimeMs(meta.circuitPath),
    await mtimeMs(ptauSource),
    await mtimeMs(buildScript),
  );

  let oldestOutput = Number.POSITIVE_INFINITY;
  for (const output of requiredOutputs) {
    oldestOutput = Math.min(oldestOutput, await mtimeMs(output));
  }

  return oldestOutput < newestInput;
}

async function renameVerifierContract(sourcePath, contractName) {
  const raw = await readFile(sourcePath, "utf8");
  const renamed = raw.replace(/contract\s+Groth16Verifier\b/, `contract ${contractName}`);
  if (renamed === raw) {
    throw new Error(`Failed to rename verifier contract in ${sourcePath}`);
  }
  await writeFile(sourcePath, renamed);
}

async function buildOne(circuit) {
  const meta = metadataFor(circuit.circuitName, circuit.contractName);
  await mkdir(meta.buildDir, { recursive: true });

  if (!(await exists(ptauSource))) {
    throw new Error(`Missing local ptau file: ${ptauSource}`);
  }

  if (!(await exists(meta.ptauTarget))) {
    await copyFile(ptauSource, meta.ptauTarget);
  }

  if (!(await shouldRebuild(meta))) {
    process.stdout.write(`${meta.circuitName}: up to date.\n`);
    return;
  }

  await copyFile(ptauSource, meta.ptauTarget);

  run("circom", [meta.circuitPath, "--r1cs", "--wasm", "--sym", "-o", meta.buildDir]);
  run("npx", ["snarkjs", "groth16", "setup", meta.r1csPath, meta.ptauTarget, meta.zkeyInitial]);
  run("npx", ["snarkjs", "zkey", "contribute", meta.zkeyInitial, meta.zkeyFinal, "--name=artifact", `-e=${meta.circuitName}`]);
  run("npx", ["snarkjs", "zkey", "export", "verificationkey", meta.zkeyFinal, meta.verifierJson]);
  run("npx", ["snarkjs", "zkey", "export", "solidityverifier", meta.zkeyFinal, meta.verifierSol]);
  await renameVerifierContract(meta.verifierSol, meta.contractName);
  await copyFile(meta.verifierSol, meta.targetContract);

  process.stdout.write(`${meta.circuitName}: generated.\n`);
}

async function main() {
  await mkdir(buildRoot, { recursive: true });

  for (const circuit of circuits) {
    await buildOne(circuit);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
