const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { time, loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const { ethers } = require("hardhat");
const {
  aggregateCiphertexts,
  buildEncryptedLocalTallyCircuitInput,
  buildPartialDecryptionCircuitInput,
  buildTrusteeRegistryCircuitInput,
  ciphertextToSolidity,
  encryptVector,
  keygen,
  partialDecrypt,
  splitSecretIntoTrusteeSharesWithPolynomial,
} = require("../crypto/elgamal");

const root = path.resolve(__dirname, "..");
const buildRoot = path.join(root, "circuits", "build");
const scenario = JSON.parse(
  fs.readFileSync(path.join(root, "scenarios", "example-election.json"), "utf8"),
);

function circuitPaths(name) {
  const circuitDir = path.join(buildRoot, name);
  return {
    wasmPath: path.join(circuitDir, `${name}_js`, `${name}.wasm`),
    zkeyPath: path.join(circuitDir, "circuit_final.zkey"),
    verificationKey: JSON.parse(fs.readFileSync(path.join(circuitDir, "verification_key.json"), "utf8")),
  };
}

const encryptedLocalTallyPaths = circuitPaths("EncryptedLocalTally");
const partialDecryptionPaths = circuitPaths("PartialDecryptionShare");
const trusteeRegistryPaths = circuitPaths("TrusteeRegistry2of3");

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

async function buildGroth16Proof(input, circuitArtifacts) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    circuitArtifacts.wasmPath,
    circuitArtifacts.zkeyPath,
  );
  const verified = await snarkjs.groth16.verify(circuitArtifacts.verificationKey, publicSignals, proof);
  expect(verified).to.equal(true);
  return {
    solidityProof: formatProofForSolidity(proof),
    publicSignals: publicSignals.map((value) => BigInt(value).toString()),
  };
}

async function buildAuthoritySubmission({
  contract,
  authoritySigner,
  publicKey,
  localElectorateSize,
  counts,
  randomnesses,
}) {
  const ciphertexts = await encryptVector(
    counts.map((value) => BigInt(value)),
    publicKey,
    randomnesses.map((value) => BigInt(value)),
  );
  const solidityCiphertexts = ciphertexts.map(ciphertextToSolidity);
  const circuitInput = buildEncryptedLocalTallyCircuitInput({
    localElectorateSize: BigInt(localElectorateSize),
    publicKey,
    counts: counts.map((value) => BigInt(value)),
    randomnesses: randomnesses.map((value) => BigInt(value)),
    ciphertexts,
  });
  const proofBundle = await buildGroth16Proof(circuitInput, encryptedLocalTallyPaths);
  const digest = await contract.getSubmissionDigest(
    authoritySigner.address,
    localElectorateSize,
    solidityCiphertexts,
  );
  const signature = await authoritySigner.signMessage(ethers.getBytes(digest));

  return {
    ciphertexts,
    solidityCiphertexts,
    authoritySignature: signature,
    solidityProof: proofBundle.solidityProof,
    publicSignals: proofBundle.publicSignals,
  };
}

async function buildTrusteeSetup({
  secretKey,
  coefficient1,
  publicKey,
  trusteeShares,
}) {
  const circuitInput = buildTrusteeRegistryCircuitInput({
    secretKey,
    coefficient1,
    publicKey,
    shares: trusteeShares,
  });
  return buildGroth16Proof(circuitInput, trusteeRegistryPaths);
}

async function buildPartialDecryptionSubmission({
  aggregateCiphertext,
  trusteeShare,
}) {
  const partial = await partialDecrypt(aggregateCiphertext, trusteeShare);
  const circuitInput = buildPartialDecryptionCircuitInput({
    shareSecret: trusteeShare.secretShare,
    publicShare: trusteeShare.publicShare,
    aggregateC1: aggregateCiphertext.c1,
    sharePoint: partial.sharePoint,
  });
  const proofBundle = await buildGroth16Proof(circuitInput, partialDecryptionPaths);

  return {
    sharePoint: partial.sharePoint,
    solidityProof: proofBundle.solidityProof,
    publicSignals: proofBundle.publicSignals,
  };
}

describe("ZKLocalTallyIntegrity", function () {
  async function preparedFixture() {
    const [owner, authority1, authority2, authority3, outsider, trustee1, trustee2, trustee3] =
      await ethers.getSigners();
    const { secretKey, publicKey } = await keygen();
    const { coefficients, shares: trusteeShares } = await splitSecretIntoTrusteeSharesWithPolynomial(
      secretKey,
      scenario.threshold,
      scenario.trusteeCount,
    );

    const EncryptedLocalTallyVerifier = await ethers.getContractFactory("EncryptedLocalTallyVerifier");
    const encryptedLocalTallyVerifier = await EncryptedLocalTallyVerifier.deploy();

    const PartialDecryptionVerifier = await ethers.getContractFactory("PartialDecryptionShareVerifier");
    const partialDecryptionVerifier = await PartialDecryptionVerifier.deploy();

    const TrusteeRegistryVerifier = await ethers.getContractFactory("TrusteeRegistry2of3Verifier");
    const trusteeRegistryVerifier = await TrusteeRegistryVerifier.deploy();

    const Factory = await ethers.getContractFactory("ZKLocalTallyIntegrity");
    const contract = await Factory.deploy(
      await encryptedLocalTallyVerifier.getAddress(),
      await partialDecryptionVerifier.getAddress(),
      await trusteeRegistryVerifier.getAddress(),
    );

    await contract.registerAuthority(authority1.address, scenario.authorities[0].localElectorateSize);
    await contract.registerAuthority(authority2.address, scenario.authorities[1].localElectorateSize);
    await contract.registerAuthority(authority3.address, scenario.authorities[2].localElectorateSize);

    const trusteeSigners = [trustee1, trustee2, trustee3];
    for (let i = 0; i < trusteeSigners.length; i++) {
      await contract.registerTrustee(
        trusteeSigners[i].address,
        trusteeShares[i].index,
        trusteeShares[i].publicShare[0].toString(),
        trusteeShares[i].publicShare[1].toString(),
      );
    }

    const trusteeSetup = await buildTrusteeSetup({
      secretKey,
      coefficient1: coefficients[1],
      publicKey,
      trusteeShares,
    });

    const now = await time.latest();
    const submissionDeadline = now + 3600;
    await contract.startElection(
      submissionDeadline,
      publicKey[0].toString(),
      publicKey[1].toString(),
      scenario.threshold,
      trusteeSetup.solidityProof.pA,
      trusteeSetup.solidityProof.pB,
      trusteeSetup.solidityProof.pC,
      trusteeSetup.publicSignals,
    );

    const authority1Submission = await buildAuthoritySubmission({
      contract,
      authoritySigner: authority1,
      publicKey,
      localElectorateSize: scenario.authorities[0].localElectorateSize,
      counts: scenario.authorities[0].counts,
      randomnesses: scenario.authorities[0].randomnesses,
    });
    const authority2Submission = await buildAuthoritySubmission({
      contract,
      authoritySigner: authority2,
      publicKey,
      localElectorateSize: scenario.authorities[1].localElectorateSize,
      counts: scenario.authorities[1].counts,
      randomnesses: scenario.authorities[1].randomnesses,
    });
    const authority3Submission = await buildAuthoritySubmission({
      contract,
      authoritySigner: authority3,
      publicKey,
      localElectorateSize: scenario.authorities[2].localElectorateSize,
      counts: scenario.authorities[2].counts,
      randomnesses: scenario.authorities[2].randomnesses,
    });

    return {
      contract,
      owner,
      authority1,
      authority2,
      authority3,
      outsider,
      trustee1,
      trustee2,
      trustee3,
      trusteeShares,
      publicKey,
      submissionDeadline,
      authority1Submission,
      authority2Submission,
      authority3Submission,
    };
  }

  it("starts an election only after verifying a 2-of-3 trustee registry consistent with the public key", async function () {
    const { contract, publicKey, trustee1 } = await loadFixture(preparedFixture);
    const trusteeConfig = await contract.getTrusteeConfig(trustee1.address);

    expect(await contract.phase()).to.equal(1n);
    expect(await contract.publicKeyX()).to.equal(publicKey[0].toString());
    expect(await contract.publicKeyY()).to.equal(publicKey[1].toString());
    expect(await contract.snapshotTrusteeCount()).to.equal(3n);
    expect(await contract.decryptionThreshold()).to.equal(2n);
    expect(await contract.trusteeRegistryVerified()).to.equal(true);
    expect(trusteeConfig[0]).to.equal(true);
  });

  it("accepts signed encrypted tallies, updates the on-chain aggregate, and enters ready-for-decryption", async function () {
    const {
      contract,
      authority1,
      authority2,
      authority3,
      authority1Submission,
      authority2Submission,
      authority3Submission,
    } = await loadFixture(preparedFixture);

    await contract.connect(authority1).submitEncryptedLocalTally(
      authority1Submission.solidityCiphertexts,
      authority1Submission.authoritySignature,
      authority1Submission.solidityProof.pA,
      authority1Submission.solidityProof.pB,
      authority1Submission.solidityProof.pC,
      authority1Submission.publicSignals,
    );
    await contract.connect(authority2).submitEncryptedLocalTally(
      authority2Submission.solidityCiphertexts,
      authority2Submission.authoritySignature,
      authority2Submission.solidityProof.pA,
      authority2Submission.solidityProof.pB,
      authority2Submission.solidityProof.pC,
      authority2Submission.publicSignals,
    );
    await contract.connect(authority3).submitEncryptedLocalTally(
      authority3Submission.solidityCiphertexts,
      authority3Submission.authoritySignature,
      authority3Submission.solidityProof.pA,
      authority3Submission.solidityProof.pB,
      authority3Submission.solidityProof.pC,
      authority3Submission.publicSignals,
    );

    expect(await contract.phase()).to.equal(2n);
    expect(await contract.acceptedSubmissionCount()).to.equal(3n);

    const expectedAggregate = await aggregateCiphertexts([
      authority1Submission.ciphertexts,
      authority2Submission.ciphertexts,
      authority3Submission.ciphertexts,
    ]);
    const onChainAggregate0 = await contract.getAggregateCiphertext(0);
    const onChainAggregate1 = await contract.getAggregateCiphertext(1);

    expect(onChainAggregate0.c1x).to.equal(expectedAggregate[0].c1[0].toString());
    expect(onChainAggregate0.c1y).to.equal(expectedAggregate[0].c1[1].toString());
    expect(onChainAggregate0.c2x).to.equal(expectedAggregate[0].c2[0].toString());
    expect(onChainAggregate0.c2y).to.equal(expectedAggregate[0].c2[1].toString());

    expect(onChainAggregate1.c1x).to.equal(expectedAggregate[1].c1[0].toString());
    expect(onChainAggregate1.c1y).to.equal(expectedAggregate[1].c1[1].toString());
    expect(onChainAggregate1.c2x).to.equal(expectedAggregate[1].c2[0].toString());
    expect(onChainAggregate1.c2y).to.equal(expectedAggregate[1].c2[1].toString());
  });

  it("rejects unsigned or wrongly signed local tally submissions", async function () {
    const { contract, authority1, authority2, authority1Submission } = await loadFixture(preparedFixture);

    await expect(
      contract.connect(authority1).submitEncryptedLocalTally(
        authority1Submission.solidityCiphertexts,
        authority1Submission.authoritySignature.slice(0, -2) + "00",
        authority1Submission.solidityProof.pA,
        authority1Submission.solidityProof.pB,
        authority1Submission.solidityProof.pC,
        authority1Submission.publicSignals,
      ),
    ).to.be.reverted;

    await expect(
      contract.connect(authority2).submitEncryptedLocalTally(
        authority1Submission.solidityCiphertexts,
        authority1Submission.authoritySignature,
        authority1Submission.solidityProof.pA,
        authority1Submission.solidityProof.pB,
        authority1Submission.solidityProof.pC,
        authority1Submission.publicSignals,
      ),
    ).to.be.revertedWith("Bad submission signature");
  });

  it("rejects an unauthorized submitter even with a valid proof bundle", async function () {
    const { contract, outsider, authority1Submission } = await loadFixture(preparedFixture);

    await expect(
      contract.connect(outsider).submitEncryptedLocalTally(
        authority1Submission.solidityCiphertexts,
        authority1Submission.authoritySignature,
        authority1Submission.solidityProof.pA,
        authority1Submission.solidityProof.pB,
        authority1Submission.solidityProof.pC,
        authority1Submission.publicSignals,
      ),
    ).to.be.revertedWith("Authority not authorized");
  });

  it("rejects tampered encrypted-tally proofs", async function () {
    const { contract, authority1, authority1Submission } = await loadFixture(preparedFixture);

    const tamperedProof = {
      pA: [...authority1Submission.solidityProof.pA],
      pB: authority1Submission.solidityProof.pB.map((row) => [...row]),
      pC: [...authority1Submission.solidityProof.pC],
    };
    tamperedProof.pA[0] = (BigInt(tamperedProof.pA[0]) + 1n).toString();

    await expect(
      contract.connect(authority1).submitEncryptedLocalTally(
        authority1Submission.solidityCiphertexts,
        authority1Submission.authoritySignature,
        tamperedProof.pA,
        tamperedProof.pB,
        tamperedProof.pC,
        authority1Submission.publicSignals,
      ),
    ).to.be.revertedWith("Invalid proof");
  });

  it("accepts only trustee-authorized decryption shares with valid on-chain proofs", async function () {
    const {
      contract,
      authority1,
      authority2,
      authority3,
      authority1Submission,
      authority2Submission,
      authority3Submission,
      authority1: nonTrustee,
      trustee1,
      trusteeShares,
    } = await loadFixture(preparedFixture);

    await contract.connect(authority1).submitEncryptedLocalTally(
      authority1Submission.solidityCiphertexts,
      authority1Submission.authoritySignature,
      authority1Submission.solidityProof.pA,
      authority1Submission.solidityProof.pB,
      authority1Submission.solidityProof.pC,
      authority1Submission.publicSignals,
    );
    await contract.connect(authority2).submitEncryptedLocalTally(
      authority2Submission.solidityCiphertexts,
      authority2Submission.authoritySignature,
      authority2Submission.solidityProof.pA,
      authority2Submission.solidityProof.pB,
      authority2Submission.solidityProof.pC,
      authority2Submission.publicSignals,
    );
    await contract.connect(authority3).submitEncryptedLocalTally(
      authority3Submission.solidityCiphertexts,
      authority3Submission.authoritySignature,
      authority3Submission.solidityProof.pA,
      authority3Submission.solidityProof.pB,
      authority3Submission.solidityProof.pC,
      authority3Submission.publicSignals,
    );

    const aggregateCiphertext = toInternalCiphertext(await contract.getAggregateCiphertext(0));
    const partialSubmission = await buildPartialDecryptionSubmission({
      aggregateCiphertext,
      trusteeShare: trusteeShares[0],
    });

    await expect(
      contract.connect(nonTrustee).submitPartialDecryption(
        0,
        partialSubmission.sharePoint[0].toString(),
        partialSubmission.sharePoint[1].toString(),
        partialSubmission.solidityProof.pA,
        partialSubmission.solidityProof.pB,
        partialSubmission.solidityProof.pC,
        partialSubmission.publicSignals,
      ),
    ).to.be.revertedWith("Trustee not authorized");

    await contract.connect(trustee1).submitPartialDecryption(
      0,
      partialSubmission.sharePoint[0].toString(),
      partialSubmission.sharePoint[1].toString(),
      partialSubmission.solidityProof.pA,
      partialSubmission.solidityProof.pB,
      partialSubmission.solidityProof.pC,
      partialSubmission.publicSignals,
    );

    await expect(
      contract.connect(trustee1).submitPartialDecryption(
        0,
        partialSubmission.sharePoint[0].toString(),
        partialSubmission.sharePoint[1].toString(),
        partialSubmission.solidityProof.pA,
        partialSubmission.solidityProof.pB,
        partialSubmission.solidityProof.pC,
        partialSubmission.publicSignals,
      ),
    ).to.be.revertedWith("Share already submitted");

    const record = await contract.getPartialDecryption(0, trustee1.address);
    expect(record.submitted).to.equal(true);
    expect(await contract.acceptedPartialDecryptionCount(0)).to.equal(1n);
  });

  it("rejects tampered decryption-share proofs", async function () {
    const {
      contract,
      authority1,
      authority2,
      authority3,
      authority1Submission,
      authority2Submission,
      authority3Submission,
      trustee1,
      trusteeShares,
    } = await loadFixture(preparedFixture);

    await contract.connect(authority1).submitEncryptedLocalTally(
      authority1Submission.solidityCiphertexts,
      authority1Submission.authoritySignature,
      authority1Submission.solidityProof.pA,
      authority1Submission.solidityProof.pB,
      authority1Submission.solidityProof.pC,
      authority1Submission.publicSignals,
    );
    await contract.connect(authority2).submitEncryptedLocalTally(
      authority2Submission.solidityCiphertexts,
      authority2Submission.authoritySignature,
      authority2Submission.solidityProof.pA,
      authority2Submission.solidityProof.pB,
      authority2Submission.solidityProof.pC,
      authority2Submission.publicSignals,
    );
    await contract.connect(authority3).submitEncryptedLocalTally(
      authority3Submission.solidityCiphertexts,
      authority3Submission.authoritySignature,
      authority3Submission.solidityProof.pA,
      authority3Submission.solidityProof.pB,
      authority3Submission.solidityProof.pC,
      authority3Submission.publicSignals,
    );

    const aggregateCiphertext = toInternalCiphertext(await contract.getAggregateCiphertext(0));
    const partialSubmission = await buildPartialDecryptionSubmission({
      aggregateCiphertext,
      trusteeShare: trusteeShares[0],
    });
    const tamperedProof = {
      pA: [...partialSubmission.solidityProof.pA],
      pB: partialSubmission.solidityProof.pB.map((row) => [...row]),
      pC: [...partialSubmission.solidityProof.pC],
    };
    tamperedProof.pA[0] = (BigInt(tamperedProof.pA[0]) + 1n).toString();

    await expect(
      contract.connect(trustee1).submitPartialDecryption(
        0,
        partialSubmission.sharePoint[0].toString(),
        partialSubmission.sharePoint[1].toString(),
        tamperedProof.pA,
        tamperedProof.pB,
        tamperedProof.pC,
        partialSubmission.publicSignals,
      ),
    ).to.be.revertedWith("Invalid decryption proof");
  });

  it("cancels incomplete elections after the deadline", async function () {
    const { contract, submissionDeadline } = await loadFixture(preparedFixture);

    await time.increaseTo(submissionDeadline + 1);
    await expect(contract.cancelIfSubmissionExpired()).to.emit(contract, "ElectionCancelled");
    expect(await contract.phase()).to.equal(3n);
  });
});
