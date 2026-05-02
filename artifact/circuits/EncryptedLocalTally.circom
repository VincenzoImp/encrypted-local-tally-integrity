pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";
include "../node_modules/circomlib/circuits/escalarmulfix.circom";

template CiphertextConsistency(randomnessBits, countBits) {
    signal input count;
    signal input randomness;
    signal input pk[2];
    signal input c1[2];
    signal input c2[2];

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component countRange = Num2Bits(countBits);
    countRange.in <== count;

    component randomnessRange = Num2Bits(randomnessBits);
    randomnessRange.in <== randomness;

    component messageMul = EscalarMulFix(countBits, BASE8);
    for (var i = 0; i < countBits; i++) {
        messageMul.e[i] <== countRange.out[i];
    }

    component c1Mul = EscalarMulFix(randomnessBits, BASE8);
    for (var j = 0; j < randomnessBits; j++) {
        c1Mul.e[j] <== randomnessRange.out[j];
    }

    component sharedMul = EscalarMulAny(randomnessBits);
    for (var k = 0; k < randomnessBits; k++) {
        sharedMul.e[k] <== randomnessRange.out[k];
    }
    sharedMul.p[0] <== pk[0];
    sharedMul.p[1] <== pk[1];

    component c2Add = BabyAdd();
    c2Add.x1 <== messageMul.out[0];
    c2Add.y1 <== messageMul.out[1];
    c2Add.x2 <== sharedMul.out[0];
    c2Add.y2 <== sharedMul.out[1];

    c1[0] === c1Mul.out[0];
    c1[1] === c1Mul.out[1];
    c2[0] === c2Add.xout;
    c2[1] === c2Add.yout;
}

template EncryptedLocalTally(randomnessBits, countBits, candidates) {
    signal input counts[candidates];
    signal input randomness[candidates];

    signal input localElectorateSize;
    signal input pkx;
    signal input pky;
    signal input c1x[candidates];
    signal input c1y[candidates];
    signal input c2x[candidates];
    signal input c2y[candidates];

    signal partialTotals[candidates + 1];
    partialTotals[0] <== 0;

    component candidateProofs[candidates];

    for (var i = 0; i < candidates; i++) {
        partialTotals[i + 1] <== partialTotals[i] + counts[i];

        candidateProofs[i] = CiphertextConsistency(randomnessBits, countBits);
        candidateProofs[i].count <== counts[i];
        candidateProofs[i].randomness <== randomness[i];
        candidateProofs[i].pk[0] <== pkx;
        candidateProofs[i].pk[1] <== pky;
        candidateProofs[i].c1[0] <== c1x[i];
        candidateProofs[i].c1[1] <== c1y[i];
        candidateProofs[i].c2[0] <== c2x[i];
        candidateProofs[i].c2[1] <== c2y[i];
    }

    partialTotals[candidates] === localElectorateSize;
}

component main {public [localElectorateSize, pkx, pky, c1x, c1y, c2x, c2y]} =
    EncryptedLocalTally(128, 16, 2);
