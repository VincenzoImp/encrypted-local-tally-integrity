pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/escalarmulfix.circom";

template TrusteeRegistry2of3(scalarBits) {
    signal input secretKey;
    signal input coefficient1;

    signal input pkx;
    signal input pky;
    signal input shareIndex[3];
    signal input publicShareX[3];
    signal input publicShareY[3];

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component secretBits = Num2Bits(scalarBits);
    secretBits.in <== secretKey;

    component publicKeyMul = EscalarMulFix(scalarBits, BASE8);
    for (var i = 0; i < scalarBits; i++) {
        publicKeyMul.e[i] <== secretBits.out[i];
    }

    pkx === publicKeyMul.out[0];
    pky === publicKeyMul.out[1];

    signal shareSecret[3];
    component shareBits[3];
    component shareMuls[3];

    for (var j = 0; j < 3; j++) {
        shareSecret[j] <== secretKey + coefficient1 * shareIndex[j];

        shareBits[j] = Num2Bits(scalarBits);
        shareBits[j].in <== shareSecret[j];

        shareMuls[j] = EscalarMulFix(scalarBits, BASE8);
        for (var k = 0; k < scalarBits; k++) {
            shareMuls[j].e[k] <== shareBits[j].out[k];
        }

        publicShareX[j] === shareMuls[j].out[0];
        publicShareY[j] === shareMuls[j].out[1];
    }
}

component main {public [pkx, pky, shareIndex, publicShareX, publicShareY]} =
    TrusteeRegistry2of3(253);
