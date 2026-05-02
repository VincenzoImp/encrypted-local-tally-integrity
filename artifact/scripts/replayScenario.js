const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const snarkjs = require("snarkjs");
const hre = require("hardhat");
const {
  aggregateCiphertexts,
  buildEncryptedLocalTallyCircuitInput,
  buildPartialDecryptionCircuitInput,
  buildTrusteeRegistryCircuitInput,
  ciphertextToSolidity,
  combinePartialDecryptions,
  decodeMessagePoint,
  encryptVector,
  keygen,
  partialDecrypt,
  splitSecretIntoTrusteeSharesWithPolynomial,
} = require("../crypto/elgamal");

function ensureCircuitArtifacts(root) {
  const requiredFiles = [
    path.join(root, "contracts", "EncryptedLocalTallyVerifier.sol"),
    path.join(root, "contracts", "PartialDecryptionShareVerifier.sol"),
    path.join(root, "contracts", "TrusteeRegistry2of3Verifier.sol"),
    path.join(root, "circuits", "build", "EncryptedLocalTally", "verification_key.json"),
    path.join(root, "circuits", "build", "EncryptedLocalTally", "circuit_final.zkey"),
    path.join(root, "circuits", "build", "EncryptedLocalTally", "EncryptedLocalTally_js", "EncryptedLocalTally.wasm"),
    path.join(root, "circuits", "build", "PartialDecryptionShare", "verification_key.json"),
    path.join(root, "circuits", "build", "PartialDecryptionShare", "circuit_final.zkey"),
    path.join(root, "circuits", "build", "PartialDecryptionShare", "PartialDecryptionShare_js", "PartialDecryptionShare.wasm"),
    path.join(root, "circuits", "build", "TrusteeRegistry2of3", "verification_key.json"),
    path.join(root, "circuits", "build", "TrusteeRegistry2of3", "circuit_final.zkey"),
    path.join(root, "circuits", "build", "TrusteeRegistry2of3", "TrusteeRegistry2of3_js", "TrusteeRegistry2of3.wasm"),
  ];

  if (requiredFiles.every((file) => fs.existsSync(file))) {
    return;
  }

  const result = spawnSync("node", ["scripts/buildCircuits.mjs"], {
    cwd: root,
    env: process.env,
    encoding: "utf8",
  });

  if (result.status !== 0) {
    throw new Error(`Circuit build failed\n${result.stdout}\n${result.stderr}`);
  }
}

function circuitArtifacts(root, name) {
  const circuitDir = path.join(root, "circuits", "build", name);
  return {
    wasmPath: path.join(circuitDir, `${name}_js`, `${name}.wasm`),
    zkeyPath: path.join(circuitDir, "circuit_final.zkey"),
    verificationKey: JSON.parse(fs.readFileSync(path.join(circuitDir, "verification_key.json"), "utf8")),
  };
}

function formatProofForSolidity(proof) {
  return {
    pA: [proof.pi_a[0], proof.pi_a[1]],
    pB: [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    pC: [proof.pi_c[0], proof.pi_c[1]],
  };
}

function toInternalCiphertext(ciphertext) {
  return {
    c1: [BigInt(ciphertext.c1x.toString()), BigInt(ciphertext.c1y.toString())],
    c2: [BigInt(ciphertext.c2x.toString()), BigInt(ciphertext.c2y.toString())],
  };
}

function encodeTranscriptCommitment(ciphertexts) {
  const coder = hre.ethers.AbiCoder.defaultAbiCoder();
  return hre.ethers.keccak256(
    coder.encode(
      [
        "uint256", "uint256", "uint256", "uint256",
        "uint256", "uint256", "uint256", "uint256",
      ],
      [
        ciphertexts[0].c1x.toString(),
        ciphertexts[0].c1y.toString(),
        ciphertexts[0].c2x.toString(),
        ciphertexts[0].c2y.toString(),
        ciphertexts[1].c1x.toString(),
        ciphertexts[1].c1y.toString(),
        ciphertexts[1].c2x.toString(),
        ciphertexts[1].c2y.toString(),
      ],
    ),
  );
}

async function buildGroth16Proof(input, artifacts) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    artifacts.wasmPath,
    artifacts.zkeyPath,
  );
  const verified = await snarkjs.groth16.verify(artifacts.verificationKey, publicSignals, proof);
  return {
    verified,
    solidityProof: formatProofForSolidity(proof),
    publicSignals: publicSignals.map((value) => BigInt(value).toString()),
  };
}

async function main() {
  const root = path.resolve(__dirname, "..");
  const logsDir = path.join(root, "logs");
  const scenarioPath = path.join(root, "scenarios", "example-election.json");
  const summaryPath = path.join(logsDir, "replay-summary.json");

  ensureCircuitArtifacts(root);
  fs.mkdirSync(logsDir, { recursive: true });

  const tallyArtifacts = circuitArtifacts(root, "EncryptedLocalTally");
  const partialArtifacts = circuitArtifacts(root, "PartialDecryptionShare");
  const trusteeArtifacts = circuitArtifacts(root, "TrusteeRegistry2of3");
  const scenario = JSON.parse(fs.readFileSync(scenarioPath, "utf8"));

  const [, ...signers] = await hre.ethers.getSigners();
  const authoritySigners = signers.slice(0, scenario.authorities.length);
  const trusteeSigners = signers.slice(
    scenario.authorities.length,
    scenario.authorities.length + scenario.trusteeCount,
  );

  const { secretKey, publicKey } = await keygen();
  const { coefficients, shares: trusteeShares } = await splitSecretIntoTrusteeSharesWithPolynomial(
    secretKey,
    scenario.threshold,
    scenario.trusteeCount,
  );

  const EncryptedLocalTallyVerifier = await hre.ethers.getContractFactory("EncryptedLocalTallyVerifier");
  const encryptedLocalTallyVerifier = await EncryptedLocalTallyVerifier.deploy();

  const PartialDecryptionShareVerifier = await hre.ethers.getContractFactory("PartialDecryptionShareVerifier");
  const partialDecryptionVerifier = await PartialDecryptionShareVerifier.deploy();

  const TrusteeRegistry2of3Verifier = await hre.ethers.getContractFactory("TrusteeRegistry2of3Verifier");
  const trusteeRegistryVerifier = await TrusteeRegistry2of3Verifier.deploy();

  const Factory = await hre.ethers.getContractFactory("ZKLocalTallyIntegrity");
  const contract = await Factory.deploy(
    await encryptedLocalTallyVerifier.getAddress(),
    await partialDecryptionVerifier.getAddress(),
    await trusteeRegistryVerifier.getAddress(),
  );

  for (let i = 0; i < scenario.authorities.length; i++) {
    const authority = scenario.authorities[i];
    await contract.registerAuthority(authoritySigners[i].address, authority.localElectorateSize);
  }

  for (let i = 0; i < scenario.trusteeCount; i++) {
    const trusteeShare = trusteeShares[i];
    await contract.registerTrustee(
      trusteeSigners[i].address,
      trusteeShare.index,
      trusteeShare.publicShare[0].toString(),
      trusteeShare.publicShare[1].toString(),
    );
  }

  const trusteeSetupInput = buildTrusteeRegistryCircuitInput({
    secretKey,
    coefficient1: coefficients[1],
    publicKey,
    shares: trusteeShares,
  });
  const trusteeSetup = await buildGroth16Proof(trusteeSetupInput, trusteeArtifacts);
  if (!trusteeSetup.verified) {
    throw new Error("Trustee setup proof failed off-chain verification");
  }

  const now = BigInt((await hre.ethers.provider.getBlock("latest")).timestamp);
  await contract.startElection(
    Number(now + 3600n),
    publicKey[0].toString(),
    publicKey[1].toString(),
    scenario.threshold,
    trusteeSetup.solidityProof.pA,
    trusteeSetup.solidityProof.pB,
    trusteeSetup.solidityProof.pC,
    trusteeSetup.publicSignals,
  );

  const proofChecks = [];
  const signatureChecks = [];

  for (let i = 0; i < scenario.authorities.length; i++) {
    const authority = scenario.authorities[i];
    const signer = authoritySigners[i];

    const ciphertexts = await encryptVector(
      authority.counts,
      publicKey,
      authority.randomnesses.map((value) => BigInt(value)),
    );
    const solidityCiphertexts = ciphertexts.map(ciphertextToSolidity);

    const tallyInput = buildEncryptedLocalTallyCircuitInput({
      localElectorateSize: BigInt(authority.localElectorateSize),
      publicKey,
      counts: authority.counts.map((value) => BigInt(value)),
      randomnesses: authority.randomnesses.map((value) => BigInt(value)),
      ciphertexts,
    });
    const proofBundle = await buildGroth16Proof(tallyInput, tallyArtifacts);
    proofChecks.push(proofBundle.verified);

    const digest = await contract.getSubmissionDigest(
      signer.address,
      authority.localElectorateSize,
      solidityCiphertexts,
    );
    const signature = await signer.signMessage(hre.ethers.getBytes(digest));
    const recovered = hre.ethers.verifyMessage(hre.ethers.getBytes(digest), signature);
    signatureChecks.push(recovered.toLowerCase() === signer.address.toLowerCase());

    await contract.connect(signer).submitEncryptedLocalTally(
      solidityCiphertexts,
      signature,
      proofBundle.solidityProof.pA,
      proofBundle.solidityProof.pB,
      proofBundle.solidityProof.pC,
      proofBundle.publicSignals,
    );
  }

  const authorityAddresses = await contract.getAuthorityList();
  const ciphertextVectors = [];
  let transcriptCommitmentsMatch = true;

  for (const authorityAddress of authorityAddresses) {
    const submission = await contract.getSubmission(authorityAddress);
    if (!submission.submitted) {
      throw new Error(`Missing submission for authority ${authorityAddress}`);
    }

    const commitment = encodeTranscriptCommitment(submission.ciphertexts);
    transcriptCommitmentsMatch &&= commitment === submission.transcriptCommitment;
    ciphertextVectors.push([
      toInternalCiphertext(submission.ciphertexts[0]),
      toInternalCiphertext(submission.ciphertexts[1]),
    ]);
  }

  const transcriptAggregate = await aggregateCiphertexts(ciphertextVectors);
  let onChainAggregateMatchesTranscript = true;
  for (let candidateIndex = 0; candidateIndex < transcriptAggregate.length; candidateIndex++) {
    const onChainAggregate = await contract.getAggregateCiphertext(candidateIndex);
    onChainAggregateMatchesTranscript &&=
      onChainAggregate.c1x.toString() === transcriptAggregate[candidateIndex].c1[0].toString() &&
      onChainAggregate.c1y.toString() === transcriptAggregate[candidateIndex].c1[1].toString() &&
      onChainAggregate.c2x.toString() === transcriptAggregate[candidateIndex].c2[0].toString() &&
      onChainAggregate.c2y.toString() === transcriptAggregate[candidateIndex].c2[1].toString();
  }

  const shareVerificationResults = [];
  for (let candidateIndex = 0; candidateIndex < transcriptAggregate.length; candidateIndex++) {
    const onChainAggregate = toInternalCiphertext(await contract.getAggregateCiphertext(candidateIndex));
    for (let i = 0; i < trusteeShares.length; i++) {
      const partial = await partialDecrypt(onChainAggregate, trusteeShares[i]);
      const partialInput = buildPartialDecryptionCircuitInput({
        shareSecret: trusteeShares[i].secretShare,
        publicShare: trusteeShares[i].publicShare,
        aggregateC1: onChainAggregate.c1,
        sharePoint: partial.sharePoint,
      });
      const proofBundle = await buildGroth16Proof(partialInput, partialArtifacts);
      shareVerificationResults.push(proofBundle.verified);

      await contract.connect(trusteeSigners[i]).submitPartialDecryption(
        candidateIndex,
        partial.sharePoint[0].toString(),
        partial.sharePoint[1].toString(),
        proofBundle.solidityProof.pA,
        proofBundle.solidityProof.pB,
        proofBundle.solidityProof.pC,
        proofBundle.publicSignals,
      );
    }
  }

  const trusteeAddresses = await contract.getTrusteeList();
  const finalTallies = [];
  const maxTotal = scenario.authorities.reduce(
    (acc, authority) => acc + authority.localElectorateSize,
    0,
  );

  for (let candidateIndex = 0; candidateIndex < transcriptAggregate.length; candidateIndex++) {
    const partialsFromTranscript = [];

    for (const trusteeAddress of trusteeAddresses) {
      const trusteeConfig = await contract.getTrusteeConfig(trusteeAddress);
      const record = await contract.getPartialDecryption(candidateIndex, trusteeAddress);
      if (!record.submitted) {
        continue;
      }

      const shareIndex = Number(trusteeConfig[1]);
      const trusteeShare = trusteeShares.find((entry) => entry.index === shareIndex);
      const expectedPartial = await partialDecrypt(transcriptAggregate[candidateIndex], trusteeShare);
      shareVerificationResults.push(
        record.shareX.toString() === expectedPartial.sharePoint[0].toString() &&
        record.shareY.toString() === expectedPartial.sharePoint[1].toString(),
      );

      partialsFromTranscript.push({
        trusteeIndex: shareIndex,
        sharePoint: [BigInt(record.shareX.toString()), BigInt(record.shareY.toString())],
        publicShare: [
          BigInt(trusteeConfig[2].toString()),
          BigInt(trusteeConfig[3].toString()),
        ],
      });
    }

    if (partialsFromTranscript.length < scenario.threshold) {
      throw new Error(`Insufficient transcript shares for candidate ${candidateIndex}`);
    }

    const messagePoint = await combinePartialDecryptions(
      transcriptAggregate[candidateIndex],
      partialsFromTranscript.slice(0, scenario.threshold),
    );
    finalTallies.push(await decodeMessagePoint(messagePoint, maxTotal));
  }

  const summary = {
    electionId: scenario.electionId,
    authorityCount: scenario.authorities.length,
    acceptedSubmissionCount: Number(await contract.acceptedSubmissionCount()),
    allProofsVerifiedOffChain: proofChecks.every(Boolean),
    allSubmissionSignaturesVerified: signatureChecks.every(Boolean),
    allShareProofsVerifiedOffChain: shareVerificationResults.every(Boolean),
    localTalliesNeverPublished: true,
    trusteeRegistryVerifiedOnChain: await contract.trusteeRegistryVerified(),
    encryptedTalliesVerifiedOnChain: true,
    partialDecryptionsVerifiedOnChain: true,
    aggregatedFromTranscript: true,
    onChainAggregateMatchesTranscript,
    decryptionTranscriptAnchoredOnChain: true,
    threshold: Number(await contract.decryptionThreshold()),
    phase: ["Registration", "Submission", "ReadyForDecryption", "Cancelled"][Number(await contract.phase())],
    transcriptCommitmentsMatch,
    aggregateTallies: finalTallies,
    winningCandidates: scenario.candidates.filter((_, index) => finalTallies[index] === Math.max(...finalTallies)),
  };

  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));
  process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
