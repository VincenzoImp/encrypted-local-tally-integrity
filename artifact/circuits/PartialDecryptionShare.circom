pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";
include "../node_modules/circomlib/circuits/escalarmulfix.circom";

template PartialDecryptionShare(scalarBits) {
    signal input shareSecret;

    signal input publicShareX;
    signal input publicShareY;
    signal input aggregateC1X;
    signal input aggregateC1Y;
    signal input shareX;
    signal input shareY;

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component shareBits = Num2Bits(scalarBits);
    shareBits.in <== shareSecret;

    component publicShareMul = EscalarMulFix(scalarBits, BASE8);
    for (var i = 0; i < scalarBits; i++) {
        publicShareMul.e[i] <== shareBits.out[i];
    }

    component partialShareMul = EscalarMulAny(scalarBits);
    for (var j = 0; j < scalarBits; j++) {
        partialShareMul.e[j] <== shareBits.out[j];
    }
    partialShareMul.p[0] <== aggregateC1X;
    partialShareMul.p[1] <== aggregateC1Y;

    publicShareX === publicShareMul.out[0];
    publicShareY === publicShareMul.out[1];
    shareX === partialShareMul.out[0];
    shareY === partialShareMul.out[1];
}

component main {public [publicShareX, publicShareY, aggregateC1X, aggregateC1Y, shareX, shareY]} =
    PartialDecryptionShare(253);
