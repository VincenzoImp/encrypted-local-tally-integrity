const { randomBytes, createHash } = require("crypto");
const circomlibjs = require("circomlibjs");

let babyjubPromise = null;

async function getBabyJub() {
  if (!babyjubPromise) {
    babyjubPromise = circomlibjs.buildBabyjub();
  }
  return babyjubPromise;
}

async function getContext() {
  const babyjub = await getBabyJub();
  const F = babyjub.F;
  const toBigInt = (value) => BigInt(F.toObject(value));
  const normalizePoint = (point) => [toBigInt(point[0]), toBigInt(point[1])];
  const fromPoint = (point) => [F.e(point[0]), F.e(point[1])];
  return {
    babyjub,
    F,
    order: babyjub.subOrder,
    basePoint: normalizePoint(babyjub.Base8),
    identity: [0n, 1n],
    toBigInt,
    normalizePoint,
    fromPoint,
  };
}

function mod(value, order) {
  const reduced = value % order;
  return reduced >= 0n ? reduced : reduced + order;
}

function bigintToBuffer(value) {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }
  return Buffer.from(hex, "hex");
}

function randomScalar(order, bits = 128) {
  const bytes = Math.ceil(bits / 8);
  const candidate = BigInt(`0x${randomBytes(bytes).toString("hex")}`);
  return mod(candidate, order - 1n) + 1n;
}

async function scalarMul(point, scalar) {
  const { babyjub, normalizePoint, fromPoint } = await getContext();
  return normalizePoint(babyjub.mulPointEscalar(fromPoint(point), scalar));
}

async function pointAdd(left, right) {
  const { babyjub, normalizePoint, fromPoint } = await getContext();
  return normalizePoint(babyjub.addPoint(fromPoint(left), fromPoint(right)));
}

async function pointNeg(point) {
  const { F, normalizePoint, fromPoint } = await getContext();
  const asPoint = fromPoint(point);
  return normalizePoint([F.neg(asPoint[0]), asPoint[1]]);
}

async function pointSub(left, right) {
  return pointAdd(left, await pointNeg(right));
}

function pointEq(left, right) {
  return left[0] === right[0] && left[1] === right[1];
}

function hashToScalar(order, items) {
  const hash = createHash("sha256");
  for (const item of items) {
    hash.update(bigintToBuffer(item));
  }
  return mod(BigInt(`0x${hash.digest("hex")}`), order);
}

async function keygen() {
  const { order, basePoint } = await getContext();
  const secretKey = randomScalar(order, 192);
  const publicKey = await scalarMul(basePoint, secretKey);
  return { secretKey, publicKey };
}

async function splitSecretIntoTrusteeShares(secretKey, threshold, trusteeCount) {
  const { order, basePoint } = await getContext();
  const coefficients = [mod(secretKey, order)];
  for (let i = 1; i < threshold; i++) {
    coefficients.push(randomScalar(order, 192));
  }

  const shares = [];
  for (let i = 1n; i <= BigInt(trusteeCount); i++) {
    let value = 0n;
    let power = 1n;
    for (const coefficient of coefficients) {
      value = mod(value + coefficient * power, order);
      power = mod(power * i, order);
    }
    shares.push({
      index: Number(i),
      secretShare: value,
      publicShare: await scalarMul(basePoint, value),
    });
  }

  return shares;
}

async function splitSecretIntoTrusteeSharesWithPolynomial(secretKey, threshold, trusteeCount) {
  const { order, basePoint } = await getContext();
  const coefficients = [mod(secretKey, order)];
  for (let i = 1; i < threshold; i++) {
    coefficients.push(randomScalar(order, 192));
  }

  const shares = [];
  for (let i = 1n; i <= BigInt(trusteeCount); i++) {
    let value = 0n;
    let power = 1n;
    for (const coefficient of coefficients) {
      value = mod(value + coefficient * power, order);
      power = mod(power * i, order);
    }
    shares.push({
      index: Number(i),
      secretShare: value,
      publicShare: await scalarMul(basePoint, value),
    });
  }

  return {
    coefficients,
    shares,
  };
}

async function encryptCount(count, publicKey, randomness) {
  const { basePoint } = await getContext();
  const c1 = await scalarMul(basePoint, randomness);
  const messagePoint = await scalarMul(basePoint, BigInt(count));
  const shared = await scalarMul(publicKey, randomness);
  const c2 = await pointAdd(messagePoint, shared);
  return { c1, c2 };
}

async function encryptVector(counts, publicKey, randomnesses) {
  const ciphertexts = [];
  for (let i = 0; i < counts.length; i++) {
    ciphertexts.push(await encryptCount(counts[i], publicKey, randomnesses[i]));
  }
  return ciphertexts;
}

async function aggregateCiphertexts(ciphertextVectors) {
  const { identity } = await getContext();
  if (ciphertextVectors.length === 0) {
    return [];
  }

  const candidateCount = ciphertextVectors[0].length;
  const aggregate = [];
  for (let i = 0; i < candidateCount; i++) {
    let c1 = identity;
    let c2 = identity;
    for (const vector of ciphertextVectors) {
      c1 = await pointAdd(c1, vector[i].c1);
      c2 = await pointAdd(c2, vector[i].c2);
    }
    aggregate.push({ c1, c2 });
  }
  return aggregate;
}

function lagrangeAtZero(currentIndex, indices, order) {
  let numerator = 1n;
  let denominator = 1n;
  const current = BigInt(currentIndex);
  for (const rawIndex of indices) {
    const index = BigInt(rawIndex);
    if (index === current) {
      continue;
    }
    numerator = mod(numerator * (-index), order);
    denominator = mod(denominator * (current - index), order);
  }
  return mod(numerator * modInverse(denominator, order), order);
}

function modInverse(value, order) {
  let a = mod(value, order);
  let b = order;
  let x0 = 1n;
  let x1 = 0n;

  while (b !== 0n) {
    const q = a / b;
    [a, b] = [b, a % b];
    [x0, x1] = [x1, x0 - q * x1];
  }

  if (a !== 1n) {
    throw new Error("Inverse does not exist");
  }

  return mod(x0, order);
}

async function provePartialDecryption(shareSecret, publicShare, c1, sharePoint) {
  const { order, basePoint } = await getContext();
  const witness = randomScalar(order, 192);
  const a1 = await scalarMul(basePoint, witness);
  const a2 = await scalarMul(c1, witness);
  const challenge = hashToScalar(order, [
    basePoint[0], basePoint[1],
    publicShare[0], publicShare[1],
    c1[0], c1[1],
    sharePoint[0], sharePoint[1],
    a1[0], a1[1],
    a2[0], a2[1],
  ]);
  const response = mod(witness + challenge * shareSecret, order);
  return {
    challenge,
    response,
    a1,
    a2,
  };
}

async function verifyPartialDecryption(publicShare, c1, sharePoint, proof) {
  const { order, basePoint } = await getContext();
  const recomputed = hashToScalar(order, [
    basePoint[0], basePoint[1],
    publicShare[0], publicShare[1],
    c1[0], c1[1],
    sharePoint[0], sharePoint[1],
    proof.a1[0], proof.a1[1],
    proof.a2[0], proof.a2[1],
  ]);

  if (recomputed !== proof.challenge) {
    return false;
  }

  const left1 = await scalarMul(basePoint, proof.response);
  const right1 = await pointAdd(proof.a1, await scalarMul(publicShare, proof.challenge));
  const left2 = await scalarMul(c1, proof.response);
  const right2 = await pointAdd(proof.a2, await scalarMul(sharePoint, proof.challenge));

  return pointEq(left1, right1) && pointEq(left2, right2);
}

async function partialDecrypt(ciphertext, trusteeShare) {
  const sharePoint = await scalarMul(ciphertext.c1, trusteeShare.secretShare);
  const proof = await provePartialDecryption(
    trusteeShare.secretShare,
    trusteeShare.publicShare,
    ciphertext.c1,
    sharePoint,
  );

  return {
    trusteeIndex: trusteeShare.index,
    sharePoint,
    proof,
    publicShare: trusteeShare.publicShare,
  };
}

async function combinePartialDecryptions(ciphertext, partials) {
  const { order, identity } = await getContext();
  const indices = partials.map((partial) => partial.trusteeIndex);
  let aggregateShare = identity;
  for (const partial of partials) {
    const coefficient = lagrangeAtZero(partial.trusteeIndex, indices, order);
    aggregateShare = await pointAdd(
      aggregateShare,
      await scalarMul(partial.sharePoint, coefficient),
    );
  }
  return pointSub(ciphertext.c2, aggregateShare);
}

async function decodeMessagePoint(point, maxValue) {
  const { basePoint, identity } = await getContext();
  let current = identity;
  for (let i = 0; i <= maxValue; i++) {
    if (pointEq(current, point)) {
      return i;
    }
    current = await pointAdd(current, basePoint);
  }
  throw new Error(`Discrete-log recovery failed up to ${maxValue}`);
}

function pointToSolidity(point) {
  return [point[0].toString(), point[1].toString()];
}

function ciphertextToSolidity(ciphertext) {
  return {
    c1x: ciphertext.c1[0].toString(),
    c1y: ciphertext.c1[1].toString(),
    c2x: ciphertext.c2[0].toString(),
    c2y: ciphertext.c2[1].toString(),
  };
}

function buildEncryptedLocalTallyCircuitInput({
  localElectorateSize,
  publicKey,
  counts,
  randomnesses,
  ciphertexts,
}) {
  return {
    counts: counts.map((value) => value.toString()),
    randomness: randomnesses.map((value) => value.toString()),
    localElectorateSize: localElectorateSize.toString(),
    pkx: publicKey[0].toString(),
    pky: publicKey[1].toString(),
    c1x: ciphertexts.map((ciphertext) => ciphertext.c1[0].toString()),
    c1y: ciphertexts.map((ciphertext) => ciphertext.c1[1].toString()),
    c2x: ciphertexts.map((ciphertext) => ciphertext.c2[0].toString()),
    c2y: ciphertexts.map((ciphertext) => ciphertext.c2[1].toString()),
  };
}

function buildPartialDecryptionCircuitInput({
  shareSecret,
  publicShare,
  aggregateC1,
  sharePoint,
}) {
  return {
    shareSecret: shareSecret.toString(),
    publicShareX: publicShare[0].toString(),
    publicShareY: publicShare[1].toString(),
    aggregateC1X: aggregateC1[0].toString(),
    aggregateC1Y: aggregateC1[1].toString(),
    shareX: sharePoint[0].toString(),
    shareY: sharePoint[1].toString(),
  };
}

function buildTrusteeRegistryCircuitInput({
  secretKey,
  coefficient1,
  publicKey,
  shares,
}) {
  return {
    secretKey: secretKey.toString(),
    coefficient1: coefficient1.toString(),
    pkx: publicKey[0].toString(),
    pky: publicKey[1].toString(),
    shareIndex: shares.map((share) => BigInt(share.index).toString()),
    publicShareX: shares.map((share) => share.publicShare[0].toString()),
    publicShareY: shares.map((share) => share.publicShare[1].toString()),
  };
}

module.exports = {
  buildEncryptedLocalTallyCircuitInput,
  buildPartialDecryptionCircuitInput,
  buildTrusteeRegistryCircuitInput,
  ciphertextToSolidity,
  combinePartialDecryptions,
  decodeMessagePoint,
  encryptCount,
  encryptVector,
  aggregateCiphertexts,
  getContext,
  keygen,
  lagrangeAtZero,
  partialDecrypt,
  pointAdd,
  pointEq,
  pointSub,
  pointToSolidity,
  randomScalar,
  scalarMul,
  splitSecretIntoTrusteeShares,
  splitSecretIntoTrusteeSharesWithPolynomial,
  verifyPartialDecryption,
};
