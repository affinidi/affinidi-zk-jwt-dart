# ZK-JWT Specification
## Zero-Knowledge JSON Web Token with Poseidon Hash

**Version:** 1.0  
**Status:** Draft Specification  
**Date:** 2026

---

## Abstract

ZK-JWT (Zero-Knowledge JSON Web Token) is a credential format that extends the SD-JWT (Selective Disclosure JWT) concept to enable compatibility with zero-knowledge proof systems. By replacing SHA-256 with Poseidon hash, ZK-JWT allows credential holders to not only selectively disclose claims but also provide zero-knowledge proofs about claim properties without revealing the actual claim values. This specification defines the format, algorithms, and protocols for creating, presenting, and verifying ZK-JWT credentials.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Overview](#3-overview)
4. [Format Specification](#4-format-specification)
5. [Algorithms](#5-algorithms)
6. [Protocol Flow](#6-protocol-flow)
7. [Zero-Knowledge Proofs](#7-zero-knowledge-proofs)
8. [Security Considerations](#8-security-considerations)
9. [Implementation Requirements](#9-implementation-requirements)
10. [Examples](#10-examples)
11. [References](#11-references)

---

## 1. Introduction

### 1.1 Motivation

Traditional JWT credentials require full disclosure of all claims to verify properties. SD-JWT (RFC 9901) enables selective disclosure but uses SHA-256, which is not optimized for zero-knowledge proof circuits. ZK-JWT addresses this limitation by:

- Using Poseidon hash, which is ZKP-friendly and efficient in zero-knowledge proof circuits
- Enabling zero-knowledge proofs about claim properties without revealing claim values
- Maintaining compatibility with SD-JWT structure and concepts
- Supporting both selective disclosure and zero-knowledge proofs simultaneously

### 1.2 Relationship to SD-JWT

ZK-JWT extends SD-JWT concepts but is not a direct implementation of RFC 9901. Key differences:

- **Hash Algorithm**: Uses Poseidon instead of SHA-256
- **Algorithm Identifier**: Uses `poseidon-v1` instead of standard hash algorithms
- **Zero-Knowledge Proofs**: Adds support for zk-proofs via `*` separator
- **Field Elements**: Digests are BN254 field elements rather than arbitrary byte strings

### 1.3 Use Cases

- **Age Verification**: Prove age is above threshold without revealing exact age
- **Financial Proofs**: Prove balance is sufficient without revealing amount
- **Membership Proofs**: Prove membership in a set without revealing which element
- **Range Proofs**: Prove value is within a range without revealing the value
- **Selective Disclosure**: Traditional SD-JWT functionality with ZKP compatibility

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Terms:**

- **Issuer**: Entity that creates and signs ZK-JWT credentials
- **Holder**: Entity that possesses a ZK-JWT credential and creates presentations
- **Verifier**: Entity that verifies ZK-JWT presentations
- **Claim**: A key-value pair in the credential payload
- **Disclosure**: A base64url-encoded JSON array containing `[salt, claimName, claimValue]`
- **Digest**: Poseidon hash of a disclosure, represented as a field element string
- **Presentation**: A ZK-JWT with selected disclosures and optional zero-knowledge proofs
- **Zero-Knowledge Proof (zk-proof)**: A cryptographic proof that demonstrates knowledge of a claim property without revealing the claim value
- **Public Signals**: Values that are publicly visible in a zero-knowledge proof
- **Verification Key (vkey)**: Public key used to verify zero-knowledge proofs

---

## 3. Overview

### 3.1 Architecture

ZK-JWT follows a three-party model:

1. **Issuer** creates credentials with selective disclosure support
2. **Holder** creates presentations with selected disclosures and optional zk-proofs
3. **Verifier** validates presentations and verifies zk-proofs

### 3.2 Key Components

- **Issuer-Signed JWT**: Standard JWT containing payload with `_sd` array and `_sd_alg` identifier
- **Disclosures**: Base64url-encoded arrays containing salted claim data
- **Zero-Knowledge Proofs**: Groth16 proofs with public signals and claim name binding

### 3.3 Design Principles

- **Privacy**: Minimize information disclosure through selective disclosure and zk-proofs
- **Verifiability**: Enable cryptographic verification of credential authenticity and claim properties
- **ZKP Compatibility**: Use ZKP-friendly primitives (Poseidon hash, BN254 field)
- **Interoperability**: Maintain structural compatibility with SD-JWT concepts

---

## 4. Format Specification

### 4.1 ZK-JWT Format


A ZK-JWT presentation with zero-knowledge proofs has the format:

```
<issuer-signed-jwt>~<disclosure1>~<disclosure2>~...*<zkproof1>*<zkproof2>*...
```

**Separators:**
- `~` (tilde): Separates disclosures from the JWT and from each other
- `*` (asterisk): Separates zero-knowledge proofs from disclosures and from each other

### 4.2 Issuer-Signed JWT

The issuer-signed JWT is a standard JWT (RFC 7519) with the following structure:

**Header:**
```json
{
  "alg": "ES256",
  "typ": "zk+jwt"
}
```

**Payload:**
```json
{
  "iss": "https://example.com/issuer",
  "sub": "did:example:123",
  "_sd": [
    "digest1",
    "digest2",
    ...
  ],
  "_sd_alg": "poseidon-v1",
  ...other_claims
}
```

**Fields:**
- `_sd`: Array of digests (field element strings) for claims with selective disclosure
- `_sd_alg`: Algorithm identifier, MUST be `"poseidon-v1"` for ZK-JWT
- Other claims: Non-disclosed claims appear directly in the payload

### 4.3 Disclosure Format

A disclosure is a base64url-encoded JSON array:

**With Claim Name:**
```json
[salt, claimName, claimValue]
```

**Without Claim Name (for array elements):**
```json
[salt, claimValue]
```

**Encoding:**
1. Create JSON array `[salt, claimName, claimValue]` or `[salt, claimValue]`
2. Encode array as UTF-8 JSON string
3. Base64url encode the UTF-8 bytes

**Example:**
```javascript
// Original: ["salt123", "age", 25]
// JSON: '["salt123","age",25]'
// Base64url: WyJzYWx0MTIzIiwiYWdlIiwyNV0
```

### 4.4 Zero-Knowledge Proof Format

A zero-knowledge proof is a base64url-encoded JSON object:

```json
{
  "proof": {
    "pi_a": ["...", "...", "..."],
    "pi_b": [["...", "..."], ["...", "..."], ["...", "..."]],
    "pi_c": ["...", "...", "..."],
    "protocol": "groth16",
    "curve": "bn128"
  },
  "publicSignals": [
    "digest",
    "claimNameDigest",
    "additionalSignal1",
    "additionalSignal2",
    ...
  ],
  "verificationKeyRefernce": "path/to/vkey.json",
  "claimName": "balance"
}
```

**Fields:**
- `proof`: Groth16 proof object (as per snarkjs format)
- `publicSignals`: Array of public signals from the circuit
  - `publicSignals[0]`: Digest (Poseidon hash of the disclosure)
  - `publicSignals[1]`: ClaimNameDigest (SHA-256 hash of claimName, field-reduced)
  - `publicSignals[2+]`: Additional public signals from the circuit
- `verificationKeyRefernce`: Reference to the verification key (path, URI, or identifier)
- `claimName`: The claim name this proof is for (REQUIRED)

**Encoding:**
1. Create JSON object with all required fields
2. Encode object as UTF-8 JSON string
3. Base64url encode the UTF-8 bytes

---

## 5. Algorithms

### 5.1 Poseidon Hash

ZK-JWT uses Poseidon hash with the following parameters:

- **Field**: BN254 (Baby Jubjub curve scalar field)
- **Field Prime**: `21888242871839275222246405745257275088548364400416034343698204186575808495617`
- **Chunk Size**: 248 bits per chunk (to stay under 254-bit field size)
- **Implementation**: circomlibjs Poseidon

**Hash Process for Disclosure String:**

1. Convert disclosure string to UTF-8 bytes
2. Convert bytes to bits (little-endian, 8 bits per byte)
3. Chunk bits into 248-bit pieces
4. Pad last chunk with zeros if needed
5. Convert each chunk to BigInt (little-endian bit order)
6. Hash chunks with Poseidon (batched if >16 inputs)
7. Convert result to field element string

**Hash Process for Digest Creation:**

1. Hash claim name with SHA-256: `claimNameDigest = SHA256(claimName)`
2. Convert salt to BigInt: `saltBigInt = BigInt(0x<salt_hex>)`
3. Convert value to BigInt: `valueBigInt = valueToFieldElement(value)`
4. Apply field reduction to claimNameDigest: `claimNameDigestField = claimNameDigest mod field_prime`
5. Hash with Poseidon: `digest = Poseidon([claimNameDigestField, saltBigInt, valueBigInt])`
6. Return as field element string

### 5.2 Salt Generation

Salts MUST be generated using a cryptographically secure random number generator.

**Requirements:**
- Minimum length: 16 bytes (128 bits)
- Encoding: Base64url
- Uniqueness: Each disclosure MUST have a unique salt

### 5.3 Claim Name Hashing

Claim names are hashed using SHA-256 for use in circuits:

```
claimNameDigest = SHA256(claimName)
claimNameDigestField = claimNameDigest mod BN254_field_prime
```

The field-reduced value is used in:
- Digest creation (as input to Poseidon)
- Zero-knowledge proof public signals (as `publicSignals[1]`)
- Claim name validation during verification

### 5.4 Value Conversion

Values are converted to BigInt for Poseidon hashing:

- **Integers**: Direct conversion to BigInt
- **Strings**: SHA-256 hash, then convert to BigInt
- **Booleans**: `true` → `1`, `false` → `0`
- **Objects/Arrays**: JSON stringify, then SHA-256 hash, then convert to BigInt
- **Null/Undefined**: `0`

### 5.5 Base64url Encoding

Base64url encoding follows RFC 4648 Section 5:

- Replace `+` with `-`
- Replace `/` with `_`
- Remove padding `=`

---

## 6. Protocol Flow

### 6.1 Issuance

**Input:**
- Payload object with claims
- Signing function for JWT

**Process:**
1. For each claim to be selectively disclosed:
   - Generate random salt (16+ bytes)
   - Create disclosure: `[salt, claimName, claimValue]`
   - Compute digest: `Poseidon([SHA256(claimName) mod p, salt, value])`
   - Replace claim in payload with `"..."`
   - Add digest to `_sd` array
2. Add `_sd_alg: "poseidon-v1"` to payload
3. Create JWT header with `typ: "zk+jwt"`
4. Sign JWT: `header.payload` → signature
5. Combine: `issuerSignedJWT~disclosure1~disclosure2~...`

**Output:**
- ZK-JWT credential string
- Array of disclosures

### 6.2 Presentation Creation

**Input:**
- ZK-JWT credential
- Array of claim names to disclose (optional, empty = all)
- Array of zero-knowledge proofs (optional)

**Process:**
1. Parse issuer-signed JWT to extract `_sd` array
2. For each disclosure in credential:
   - Compute digest
   - If claim name matches disclosed claims OR all claims requested:
     - Include disclosure in presentation
3. If zk-proofs provided:
   - Validate each zk-proof structure
   - Encode each zk-proof as base64url
   - Append with `*` separator
4. Combine: `issuerSignedJWT~disclosure1~...*zkproof1*zkproof2*...`

**Output:**
- Presentation string

### 6.3 Verification

**Input:**
- Presentation string
- JWT verification function
- Optional: vkey pull function, zk-proof verification function

**Process:**
1. Parse presentation:
   - Split by `*` to separate disclosures and zk-proofs
   - Split disclosure part by `~` to get JWT and disclosures
2. Verify JWT:
   - Decode header and payload
   - Check `_sd_alg === "poseidon-v1"`
   - Verify JWT signature
3. Verify disclosures:
   - For each disclosure, compute digest
   - Verify digest is in `_sd` array
4. Verify zk-proofs (if present):
   - For each zk-proof:
     - Decode base64url to get zk-proof object
     - Validate structure (proof, publicSignals, verificationKeyRefernce, claimName)
     - Verify `publicSignals[0]` (digest) is in `_sd` array
     - Validate claimName:
       - Hash claimName with SHA-256
       - Apply field reduction
       - Compare with `publicSignals[1]`
     - Retrieve verification key using `pullVkeyFunction`
     - Verify proof using verification key
5. Extract disclosed claims

**Output:**
- Verification result: `{ valid, claims, error, zkproofs, zkproofsValidatedAgainstVkey }`

---

## 7. Zero-Knowledge Proofs

### 7.1 Overview

Zero-knowledge proofs in ZK-JWT allow holders to prove properties about claims without revealing the actual claim values. This enables use cases such as:
- Proving age ≥ 18 without revealing exact age
- Proving balance > threshold without revealing amount
- Proving membership without revealing which element

### 7.2 Proof Structure

Each zk-proof MUST contain:

1. **proof**: Groth16 proof object
   - Format: snarkjs Groth16 proof format
   - Contains: `pi_a`, `pi_b`, `pi_c`, `protocol`, `curve`

2. **publicSignals**: Array of public signals
   - **MUST** have at least 2 elements
   - `publicSignals[0]`: Digest (Poseidon hash of disclosure)
   - `publicSignals[1]`: ClaimNameDigest (SHA-256 hash of claimName, field-reduced)
   - `publicSignals[2+]`: Additional public signals from circuit

3. **verificationKeyRefernce**: Reference to verification key
   - Format: String (path, URI, or identifier)
   - Used by verifier to retrieve verification key

4. **claimName**: Claim name this proof is for
   - Format: String
   - **REQUIRED** field
   - Used for validation during verification

### 7.3 Public Signals Order

The public signals array MUST follow this order:

```
[digest, claimNameDigest, ...additionalSignals]
```

Where:
- `digest`: Poseidon hash of `[claimNameDigest, salt, value]`
- `claimNameDigest`: SHA-256 hash of `claimName`, reduced modulo BN254 field prime
- `additionalSignals`: Circuit-specific public signals (e.g., comparison values)

### 7.4 Claim Name Validation

During verification, the `claimName` is validated as follows:

1. Compute: `claimNameHash = SHA256(claimName)`
2. Apply field reduction: `claimNameHashReduced = claimNameHash mod BN254_field_prime`
3. Compare: `claimNameHashReduced === BigInt(publicSignals[1])`

This ensures the proof is cryptographically bound to the correct claim name.

### 7.5 Proof Verification

The verifier MUST:

1. Validate zk-proof structure
2. Verify digest is in `_sd` array
3. Validate claim name matches `publicSignals[1]`
4. Retrieve verification key using `pullVkeyFunction(verificationKeyRefernce)`
5. Verify proof using Groth16 verification:
   ```
   isValid = groth16.verify(vkey, publicSignals, proof)
   ```

### 7.6 Circuit Requirements

Circuits used with ZK-JWT MUST:

1. Accept `claimNameDigest` as a public input
2. Accept `salt` and `value` as private inputs
3. Compute digest: `Poseidon([claimNameDigest, salt, value])`
4. Output digest as first public signal
5. Output `claimNameDigest` as second public signal
6. Output any additional public signals after these two

**Example Circuit Structure:**
```circom
component main {public [claimNameDigest, compareValue]} = GreaterThen(32);

signal input claimNameDigest;  // Public
signal input salt;              // Private
signal input value;             // Private
signal input compareValue;      // Public

signal output digest;

// Compute digest
component digestCreator = DisclosureDigest();
digestCreator.claimNameDigest <== claimNameDigest;
digestCreator.salt <== salt;
digestCreator.value <== value;
digest <== digestCreator.digest;

// Circuit-specific logic
// ...
```

---

## 8. Security Considerations

### 8.1 Cryptographic Security

**Poseidon Hash:**
- Poseidon is a cryptographic hash function designed for zero-knowledge proofs
- Security level: 128 bits (for BN254 field)
- Resistant to collision attacks within the field

**Salt Requirements:**
- Salts MUST be cryptographically random
- Minimum 16 bytes (128 bits) recommended
- Each disclosure MUST have a unique salt
- Salts prevent rainbow table attacks and ensure uniqueness

**JWT Signing:**
- Issuers MUST use cryptographically secure signing algorithms (e.g., ES256, RS256)
- Private keys MUST be kept secure
- Signature verification MUST be performed by verifiers

### 8.2 Privacy Considerations

**Selective Disclosure:**
- Only disclosed claims are revealed to verifiers
- Non-disclosed claims remain hidden (only digests in `_sd` array)
- Salts prevent correlation between presentations

**Zero-Knowledge Proofs:**
- Zk-proofs reveal only public signals, not private inputs
- Claim values remain hidden when using zk-proofs
- Multiple zk-proofs can be combined in a single presentation

**Replay Attacks:**
- Presentations are not signed by holders (by design)
- Applications SHOULD implement replay protection (e.g., nonces, timestamps)
- Verifiers SHOULD track used presentations if replay prevention is required

### 8.3 Implementation Security

**Field Reduction:**
- All values MUST be reduced modulo BN254 field prime before hashing
- Field reduction MUST be applied consistently across implementations
- Inconsistencies in field reduction can lead to verification failures

**Input Validation:**
- Verifiers MUST validate all inputs (JWT format, disclosure format, zk-proof structure)
- Verifiers MUST check algorithm identifier (`_sd_alg === "poseidon-v1"`)
- Verifiers MUST verify all digests are in `_sd` array

**Key Management:**
- Verification keys MUST be retrieved from trusted sources
- `pullVkeyFunction` SHOULD validate key authenticity
- Keys SHOULD be cached to reduce network requests

### 8.4 Known Limitations

- **Field Size**: BN254 field limits values to ~254 bits
- **Hash Collisions**: Within-field collisions are possible but computationally infeasible
- **Implementation Variance**: Field element encoding may vary; implementations MUST use consistent encoding
- **Circuit Dependency**: Zk-proofs depend on specific circuit implementations

---

## 9. Implementation Requirements

### 9.1 Mandatory Features

Implementations MUST support:

1. **Issuance:**
   - Creating ZK-JWT credentials with selective disclosure
   - Generating cryptographically secure salts
   - Computing Poseidon digests
   - JWT signing

2. **Presentation:**
   - Creating presentations with selective disclosure
   - Including zero-knowledge proofs
   - Encoding disclosures and zk-proofs as base64url

3. **Verification:**
   - Verifying JWT signatures
   - Validating disclosure digests
   - Validating zk-proof structures
   - Verifying claim name binding
   - Verifying Groth16 proofs

### 9.2 Optional Features

Implementations MAY support:

- Custom verification key retrieval mechanisms
- Custom zk-proof verification functions
- Extended claim processing (nested objects, arrays)
- Presentation caching
- Batch verification

### 9.3 Algorithm Requirements

**Poseidon:**
- MUST use BN254 field
- MUST use 248-bit chunking for string hashing
- MUST handle field reduction correctly

**SHA-256:**
- MUST be used for claim name hashing
- MUST produce consistent results across implementations

**Base64url:**
- MUST follow RFC 4648 Section 5
- MUST remove padding

### 9.4 Error Handling

Implementations MUST:

- Return clear error messages for invalid inputs
- Validate all required fields before processing
- Handle edge cases (empty arrays, missing fields, etc.)
- Not leak sensitive information in error messages

---

## 10. Examples

### 10.1 Basic Credential Creation

```javascript
const payload = {
  iss: 'https://example.com/issuer',
  sub: 'did:example:123',
  given_name: 'John',
  family_name: 'Doe',
  email: 'john.doe@example.com',
  age: 25
}

const { zkJwt, disclosures } = await createZKJWT(payload, signJWT)

// Result:
// zkJwt: "eyJ...~WyJzYWx0MSIsImdpdmVuX25hbWUiLCJKb2huIl0~WyJzYWx0MiIsImZhbWlseV9uYW1lIiwiRG9lIl0~..."
// disclosures: ["WyJzYWx0MSIsImdpdmVuX25hbWUiLCJKb2huIl0", ...]
```

### 10.2 Presentation with Selective Disclosure

```javascript
const presentation = await createPresentation(
  zkJwt,
  ['given_name', 'email'] // Only disclose these
)

// Result:
// "eyJ...~WyJzYWx0MSIsImdpdmVuX25hbWUiLCJKb2huIl0~WyJzYWx0NCIsImVtYWlsIiwiam9obi5kb2VAZXhhbXBsZS5jb20iXQ"
```

### 10.3 Presentation with Zero-Knowledge Proof

```javascript
const zkproof = {
  proof: {
    pi_a: ['194960509067826594842909015762938800656128661956813787429235573866377670176', ...],
    pi_b: [['17271319050943568090665522672784284099131305875079731782474227113555049592180', ...], ...],
    pi_c: ['45948229917916183680908913100424834312105996810185084628498107742585659562', ...],
    protocol: 'groth16',
    curve: 'bn128'
  },
  publicSignals: [
    '297541618719244367262625955654059640273712174337110758994468353198051', // digest
    '17607637524244224956629064735546113560149173604247052441849176260111677124046', // claimNameDigest
    '500000' // compareValue
  ],
  verificationKeyRefernce: '/path/to/GreaterThen.groth16.vkey.json',
  claimName: 'balance'
}

const presentation = await createPresentation(
  zkJwt,
  ['timestamp', 'status'],
  [zkproof]
)

// Result:
// "eyJ...~WyJzYWx0NSIsInRpbWVzdGFtcCIsMTc2ODU1ODcyNDk3OV0~WyJzYWx0NiIsInN0YXR1cyIsMV0*eyJwcm9vZiI6ey4uLn0sInB1YmxpY1NpZ25hbHMiOlsuLi5dLCJ2ZXJpZmljYXRpb25LZXlSZWZlcm5jZSI6Ii9wYXRoL3RvL0dyZWF0ZXJUaGVuLmdyb3RoMTYudmtleS5qc29uIiwiY2xhaW1OYW1lIjoiYmFsYW5jZSJ9"
```

### 10.4 Verification

```javascript
const pullVkeyFunction = async (vkeyPath) => {
  const vkeyContent = fs.readFileSync(vkeyPath, 'utf8')
  return JSON.parse(vkeyContent)
}

const verification = await verifyPresentation(presentation, verifyJWT, {
  pullVkeyFunction
})

// Result:
// {
//   valid: true,
//   claims: {
//     timestamp: 1768558724979,
//     status: 1
//   },
//   zkproofs: [{ proof: {...}, publicSignals: [...], ... }],
//   zkproofsValidatedAgainstVkey: true
// }
```

---

## 11. References

### 11.1 Normative References

- **RFC 2119**: Key words for use in RFCs to Indicate Requirement Levels
- **RFC 4648**: The Base16, Base32, and Base64 Data Encodings
- **RFC 7519**: JSON Web Token (JWT)
- **RFC 9901**: SD-JWT (Selective Disclosure for JWTs)

### 11.2 Informative References

- **Poseidon Hash**: https://www.poseidon-hash.info/
- **circomlibjs**: https://github.com/iden3/circomlibjs
- **Groth16**: "On the Size of Pairing-based Non-interactive Arguments" by Jens Groth
- **BN254 Curve**: Barreto-Naehrig curve with embedding degree 12

### 11.3 Related Specifications

- **SD-JWT (RFC 9901)**: Selective Disclosure for JWTs
- **W3C Verifiable Credentials**: https://www.w3.org/TR/vc-data-model/
- **DID Core**: https://www.w3.org/TR/did-core/

---

## Appendix A: Field Element Encoding

BN254 field elements are represented as decimal strings of BigInt values modulo the field prime:

```
field_prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

All field operations MUST be performed modulo this prime.

---

## Appendix B: Disclosure Digest Algorithm

The disclosure digest is computed as follows:

```
1. claimNameDigest = SHA256(claimName)
2. claimNameDigestField = claimNameDigest mod field_prime
3. saltBigInt = BigInt(0x<salt_hex>)
4. valueBigInt = valueToFieldElement(value)
5. digest = Poseidon([claimNameDigestField, saltBigInt, valueBigInt])
6. Return digest as decimal string
```

---

## Appendix C: Claim Name Validation Algorithm

Claim name validation during zk-proof verification:

```
1. claimNameHash = SHA256(claimName)
2. claimNameHashReduced = claimNameHash mod field_prime
3. expectedDigest = BigInt(publicSignals[1])
4. If claimNameHashReduced !== expectedDigest:
     Return error: "Claim name hash mismatch"
```

---

## Document History

- **Version 1.0** (2024): Initial specification draft

---

**Copyright Notice**

This specification is provided as-is for standardization purposes.

