pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// Recomputes the ZK-JWT disclosure digest (matches `createDigestFromArray` in
// `lib/src/core.dart`: Poseidon([claimNameDigest, salt, value])) and proves
// that the disclosed `value` satisfies a public `minThreshold`, without
// revealing `value` or `salt`.
//
// Public inputs:
//   claimNameDigest - SHA-256(claimName) reduced into the BN254 field
//                     (see `hashClaimName` / `fieldReduce` in core.dart)
//   minThreshold    - predicate parameter (e.g. minimum balance)
//
// Private inputs:
//   salt  - per-disclosure random salt, field-reduced
//   value - the claim value, field-reduced
//
// Public outputs:
//   digest    - Poseidon([claimNameDigest, salt, value]); must equal the
//               disclosure digest published in the ZK-JWT `_sd` array.
//   satisfies - 1 if value >= minThreshold, else 0.
template ClaimThreshold(valueBits) {
    signal input claimNameDigest;
    signal input minThreshold;
    signal input salt;
    signal input value;

    signal output digest;
    signal output satisfies;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== claimNameDigest;
    hasher.inputs[1] <== salt;
    hasher.inputs[2] <== value;
    digest <== hasher.out;

    component gte = GreaterEqThan(valueBits);
    gte.in[0] <== value;
    gte.in[1] <== minThreshold;
    satisfies <== gte.out;
}

// 64 bits comfortably covers realistic claim values (ages, balances, dates)
// while keeping the comparator circuit small.
component main { public [claimNameDigest, minThreshold] } = ClaimThreshold(64);
