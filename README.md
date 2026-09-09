# Affinidi ZK-JWT

The Affinidi ZK-JWT package provides a Dart SDK for **ZK-JWT**, a Selective Disclosure JWT format that replaces SHA-256 with the ZK-friendly **Poseidon hash**. This makes disclosure digests directly usable as inputs to zero-knowledge proof circuits, so a holder can prove properties about a claim (e.g. *balance ≥ 1000*) without revealing the claim value itself, while still supporting classic SD-JWT-style selective disclosure.

> **⚠️ IMPORTANT SECURITY AND PRIVACY NOTE:**
> This package is a cryptographic tool and does not process personal data outside of the structured data defined by the user. When integrated into a broader system that handles personally identifiable information (PII), users are solely responsible for ensuring that the entire use case complies with all applicable privacy laws and data protection obligations (e.g., GDPR).

**Specification:**
Before integrating, we encourage you to read the **[ZK-JWT Specification](doc/SPEC.md)**. It documents the credential format, the `poseidon-v1` digest algorithm, the presentation protocol, and the zero-knowledge proof extension in detail.

## Table of Contents

- [Core Concepts](#core-concepts)
- [ZK-JWT Workflow Overview](#zk-jwt-workflow-overview)
- [Supported Crypto](#supported-crypto)
- [Disclosure & Digest Format](#disclosure--digest-format)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Testing & Native Symbols](#testing--native-symbols)
- [Support & Feedback](#support--feedback)
- [Contributing](#contributing)

## Core Concepts

ZK-JWT extends the SD-JWT (Selective Disclosure JWT) model with a ZKP-friendly digest algorithm.

- **Selective Disclosure JWT (SD-JWT):** A JWT whose claims are individually hidden behind digests in a `_sd` array; the holder discloses only the claims (and their salts) a verifier needs to see.
- **Poseidon Hash:** A permutation-based hash function optimized for algebraic circuit mathematics, used here instead of SHA-256 so digests can be recomputed cheaply inside a Circom/Groth16 circuit.
- **Disclosure:** A base64url-encoded `[salt, claimName, claimValue]` array (or `[salt, claimValue]` for array elements). Its Poseidon digest is what appears in `_sd`.
- **Zero-Knowledge Proof (zk-proof):** An optional, additional proof attached to a presentation that shows a disclosed claim satisfies a predicate (e.g. a threshold) without revealing the claim value.

## ZK-JWT Workflow Overview

The lifecycle of a ZK-JWT credential involves three roles:

1. **Issuer Flow (`createZKJWT`):** The issuer processes the payload's claims into Poseidon-hashed disclosures, builds the `_sd` array and `poseidon-v1`-tagged JWT payload, and signs it with a caller-supplied signing function.
2. **Holder Flow (`createPresentation` / `extractDisclosedClaims`):** The holder selects which disclosures to reveal for a given verifier, optionally attaches zero-knowledge proofs, and produces the presentation string.
3. **Verifier Flow (`verifyPresentation`):** The verifier checks the JWT signature, validates every disclosed digest against `_sd`, optionally validates attached zk-proofs against a verification key, and returns the recovered claims.

## Supported Crypto

- **Hash:** **Poseidon**, computed over the BN254 scalar field.
- **Crypto Engine:** Poseidon hashing is performed via a **Rust Foreign Function Interface (FFI)** bridge (`affinidi-zkp-crypto-rs`), the same native engine used by [`affinidi-vc-zkp-dart`](https://github.com/affinidi/affinidi-vc-zkp-dart). This ensures optimal performance, memory safety, and reliable integration into Dart/Flutter applications.
- **JWT signing:** Left to the caller via `SignFunction` / `VerifyFunction` callbacks - ZK-JWT does not mandate a specific signature algorithm.

## Disclosure & Digest Format

Every claim disclosure is hashed deterministically so digests are stable across languages and runtimes:

`digest = Poseidon([claimNameDigest, salt, value])`

Where:

| Component | Description |
| :--- | :--- |
| `claimNameDigest` | SHA-256(`claimName`), used to bind the digest to a specific claim name. |
| `salt` | Random per-disclosure salt (base64url), converted to a field element. |
| `value` | The claim value, converted to a field element (numbers/booleans map directly; strings and structured values are SHA-256 hashed). |

The resulting decimal-string digest is what appears in the JWT payload's `_sd` array, and is exactly what a Circom circuit recomputes to validate a disclosure or zero-knowledge predicate.

## Requirements

- Dart SDK version `^3.10.0` (required for native-asset build hooks).

## Installation

Add the package to your `pubspec.yaml` file:

```yaml
dependencies:
  zk_jwt: ^<version_number>
```

Then run the command below to install the package:

```bash
dart pub get
```

## Usage

### 1. Issuer: Create a ZK-JWT Credential

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:zk_jwt/zk_jwt.dart';

Future<Uint8List> signJwt(String data) async {
  // Replace with a real signer (ES256, EdDSA, ...).
  return Uint8List.fromList(sha256.convert(utf8.encode(data)).bytes);
}

final payload = <String, dynamic>{
  'iss': 'https://example.com/issuer',
  'given_name': 'John',
  'family_name': 'Doe',
  'email': 'john.doe@example.com',
};

final issued = await createZKJWT(payload, signJwt);
final zkJwt = issued['zkJwt'] as String; // '<jwt>~<disclosure1>~<disclosure2>~...'
```

### 2. Holder: Create a Presentation

The holder discloses only the claims a specific verifier needs.

```dart
final presentation = await createPresentation(zkJwt, <String>[
  'given_name',
  'email',
]);
```

Zero-knowledge proofs can be attached alongside disclosures:

```dart
final presentationWithProof = await createPresentation(
  zkJwt,
  <String>[], // no plain disclosures
  <Map<String, dynamic>>[
    <String, dynamic>{
      'proof': proof,
      'publicSignals': publicSignals, // [digest, claimNameDigest, ...]
      'verificationKeyRefernce': 'vkey-balance-threshold',
      'claimName': 'balance',
    },
  ],
);
```

### 3. Verifier: Verify a Presentation

```dart
Future<bool> verifyJwt(String jwt) async {
  // Replace with real signature verification.
  return jwt.split('.').length == 3;
}

final result = await verifyPresentation(presentation, verifyJwt);

if (result['valid'] == true) {
  final claims = result['claims'] as Map<String, dynamic>;
  print(claims['given_name']); // John
}
```

To also validate attached zero-knowledge proofs, supply `pullVkeyFunction` and `verifyZkproof`:

```dart
final result = await verifyPresentation(
  presentation,
  verifyJwt,
  pullVkeyFunction: (reference) async => loadVerificationKey(reference),
  verifyZkproof: (vkey, publicSignals, proof) async =>
      myGroth16Verifier.verify(vkey, publicSignals, proof),
);
```

## Testing & Native Symbols

This project includes two test suites:

- **Unit tests:** Pure-Dart tests for encoding, field-element conversion, and disclosure/digest logic.
- **Integration tests:** Exercise the real Rust Poseidon FFI bridge end to end (hashing, full issuer → holder → verifier flow, zk-proof validation).

Run unit tests:
```bash
dart test
```

Run all tests (unit + integration):
```bash
dart test --run-skipped
```

Run with coverage:
```bash
dart run coverage:test_with_coverage -- --run-skipped
```

**Debugging Native Crashes:** If your application crashes within the native Rust code, download the necessary debug symbols for your specific build triple:

```bash
./tool/download_prebuild_symbols.sh --output-dir ./.native-symbols
```

See [`doc/native_build_and_hooks.md`](doc/native_build_and_hooks.md) for details on how the native library is resolved, verified, and bundled by `hook/build.dart`.


## Support & Feedback

If you encounter any technical issues or have suggestions regarding the specification or implementation, please don't hesitate to contact us using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting Technical Issues
For issues with the codebase, please open a detailed issue on GitHub. Include a title, clear description, and, ideally, an executable code sample demonstrating the failure.

## Contributing

Want to contribute?

Please review our [CONTRIBUTING](CONTRIBUTING.md) guidelines. We welcome contributions to improving the ZK-JWT specification and tooling.
