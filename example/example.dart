// Run from the repository root:
//   dart run example/example.dart
//
// This example walks through the full ZK-JWT lifecycle:
//   1. Issuer   - creates a Selective Disclosure JWT with Poseidon digests.
//   2. Holder   - builds a presentation that discloses only chosen claims.
//   3. Verifier - validates the presentation and recovers disclosed claims.
//   4. Zero-knowledge proof - builds circuit inputs for a claim predicate
//      ("balance >= minThreshold") without revealing the claim value.
//
// The Poseidon hashing is performed by the prebuilt `affinidi-zkp-crypto-rs`
// native library, loaded automatically through the Dart build hook.
//
// Reference Circom sources for step 4's circuit live under:
//   example/circuits/
//
// For in-app proof generation on mobile, you can combine witness calculation with a
// fast Groth16 prover, for example:
//   - https://github.com/iden3/flutter-rapidsnark - Flutter wrapper around rapidsnark
//   - https://github.com/iden3/circom-witnesscalc - witness calculator (CVM / native)
//   - https://github.com/iden3/rapidsnark - C++ Groth16 prover for circom/snarkjs artifacts
//
// Typical flow: compile circuits → trusted setup → generate witness (circom-witnesscalc
// or WASM calculator) → prove (rapidsnark / snarkjs) → verify off-device or on-chain.
//
// E2E boundary note:
// - This example covers credential issuance, presentation, verification, and
//   deterministic circuit input preparation.
// - Next step is to generate a ZKP against your Circom circuit using external tooling
//   (for Dart/Flutter apps, see the libraries listed above).
// - Verifier then verifies the resulting proof with the same proving stack/tooling.

// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:zk_jwt/zk_jwt.dart';

// Demo-only signing: replace with a real ES256/EdDSA signer in production.
Future<Uint8List> _mockSign(String data) async {
  return Uint8List.fromList(sha256.convert(utf8.encode(data)).bytes);
}

// Demo-only verification: a real verifier checks the issuer signature.
Future<bool> _mockVerify(String jwt) async => jwt.split('.').length == 3;

Future<void> main() async {
  final payload = <String, dynamic>{
    'iss': 'https://example.com/issuer',
    'sub': 'did:example:123',
    'given_name': 'John',
    'family_name': 'Doe',
    'email': 'john.doe@example.com',
    'birthdate': '1990-01-01',
  };

  // 1. Issuer creates the credential.
  final issued = await createZKJWT(payload, _mockSign);
  final zkJwt = issued['zkJwt'] as String;
  print(
    'Issued ZK-JWT with ${(issued['disclosures'] as List).length} '
    'disclosures.',
  );

  // 2. Holder discloses only given_name and email.
  final presentation = await createPresentation(zkJwt, <String>[
    'given_name',
    'email',
  ]);

  // 3. Verifier validates and extracts disclosed claims.
  final result = await verifyPresentation(presentation, _mockVerify);
  print('Presentation valid: ${result['valid']}');
  print('Disclosed claims: ${result['claims']}');

  // 4. Zero-knowledge proof: build inputs for the `ClaimThreshold` circuit
  // (example/circuits/ClaimThreshold.circom) to prove a claim satisfies a
  // threshold -- e.g. "balance >= 1000" - without revealing the balance.
  //
  // The circuit recomputes the same digest as `createDigestFromArray`:
  //   digest = Poseidon([claimNameDigest, salt, value])
  const claimName = 'balance';
  const claimValue = 5000;
  const minThreshold = 1000;

  final salt = generateSalt();
  final claimNameDigest = fieldReduce(hashClaimName(claimName));
  final digest = await createDigestFromArray(<dynamic>[
    claimNameDigest,
    salt,
    claimValue,
  ]);

  final claimThresholdCircuitInputs = <String, Object?>{
    // Public circuit inputs.
    'claimNameDigest': claimNameDigest.toString(),
    'minThreshold': minThreshold.toString(),
    // Private circuit inputs.
    'salt': saltToFieldElement(salt).toString(),
    'value': valueToFieldElement(claimValue).toString(),
  };

  print(
    'ClaimThreshold circuit inputs '
    '(expected outputs: digest=$digest, satisfies=1):',
  );
  print(
    const JsonEncoder.withIndent('  ').convert(claimThresholdCircuitInputs),
  );
}
