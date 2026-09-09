/// ZK-JWT (Zero-Knowledge JWT) with Poseidon hash.
///
/// ZK-JWT is SD-JWT (Selective Disclosure JWT) with a ZK-friendly Poseidon
/// hash, making digests usable inside zero-knowledge proof circuits.
library;

export 'src/core.dart'
    show
        createDigest,
        createDigestFromArray,
        createDisclosure,
        decodeDisclosure,
        fieldReduce,
        generateSalt,
        hashClaimName,
        prepareCircuitInputs,
        processClaims,
        saltToFieldElement,
        valueToFieldElement;
export 'src/hash.dart'
    show base64urlDecode, base64urlEncode, poseidonHash, stringToBits;
export 'src/holder.dart' show createPresentation, extractDisclosedClaims;
export 'src/issuer.dart' show SignFunction, createZKJWT;
export 'src/rust_eddsa_helper_ffi.dart' show RustEddsaHelperFfi;
export 'src/verifier.dart'
    show
        PullVkeyFunction,
        VerifyFunction,
        VerifyZkproofFunction,
        verifyPresentation;
