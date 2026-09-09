/// ZK-JWT verifier: validates presentations, disclosures, and optional
/// zero-knowledge proofs.
library;

import 'dart:convert';

import 'core.dart';
import 'hash.dart';

/// Verifies the signature of an issuer-signed JWT string.
typedef VerifyFunction = Future<bool> Function(String jwt);

/// Resolves a verification key from a `verificationKeyRefernce`.
typedef PullVkeyFunction =
    Future<Map<String, dynamic>> Function(String reference);

/// Verifies a zero-knowledge proof against a verification key and public
/// signals.
typedef VerifyZkproofFunction =
    Future<bool> Function(
      Map<String, dynamic> vkey,
      List<String> publicSignals,
      Map<String, dynamic> proof,
    );

Map<String, dynamic> _invalid(String error) => <String, dynamic>{
  'valid': false,
  'error': error,
};

/// Verifies a ZK-JWT [presentation].
///
/// [verifyFunction] checks the issuer JWT signature. When the presentation
/// carries zero-knowledge proofs, provide [pullVkeyFunction] and
/// [verifyZkproof] to validate them against their verification keys.
///
/// The `verificationKeyRefernce` inside a zk-proof is chosen by the holder, so
/// a malicious holder could point it at a vkey for a trivial circuit that
/// accepts any input. To defend against this, pass [trustedVkeys]: a map from
/// claim name to the set of `verificationKeyRefernce` values the verifier
/// trusts for that claim. When provided, any zk-proof whose claim name is
/// absent from the map, or whose reference is not in the allowed set, is
/// rejected before the key is pulled. When omitted, no allowlist is enforced
/// (backwards compatible) and trust is delegated entirely to
/// [pullVkeyFunction]/[verifyZkproof].
///
/// Returns a map with `valid`; on success it also includes `claims`,
/// `payload`, `header`, `zkproofs`, and `zkproofsValidatedAgainstVkey`. On
/// failure it includes an `error` message.
Future<Map<String, dynamic>> verifyPresentation(
  String presentation,
  VerifyFunction verifyFunction, {
  PullVkeyFunction? pullVkeyFunction,
  VerifyZkproofFunction? verifyZkproof,
  Map<String, Set<String>>? trustedVkeys,
}) async {
  var zkproofsValidatedAgainstVkey = false;

  if (presentation.trim().isEmpty) {
    return _invalid('Invalid ZK-JWT format: empty presentation');
  }

  final String issuerSignedJWT;
  var disclosures = <String>[];
  var zkproofs = <String>[];

  if (presentation.contains('*')) {
    final asteriskParts = presentation.split('*');
    final disclosureParts = asteriskParts[0].split('~');
    issuerSignedJWT = disclosureParts[0];
    if (disclosureParts.length > 1) {
      disclosures = disclosureParts.sublist(1);
    }
    if (asteriskParts.length > 1) {
      zkproofs = asteriskParts.sublist(1);
    }
  } else {
    final parts = presentation.split('~');
    issuerSignedJWT = parts[0];
    if (parts.length > 1) {
      disclosures = parts.sublist(1);
    }
  }

  final jwtParts = issuerSignedJWT.split('.');
  if (jwtParts.length != 3) {
    return _invalid('Invalid JWT format');
  }

  final Map<String, dynamic> header;
  final Map<String, dynamic> payload;
  try {
    header =
        jsonDecode(utf8.decode(base64urlDecode(jwtParts[0])))
            as Map<String, dynamic>;
    payload =
        jsonDecode(utf8.decode(base64urlDecode(jwtParts[1])))
            as Map<String, dynamic>;
  } on Object catch (e) {
    return _invalid('Failed to decode JWT: $e');
  }

  final hashAlg = payload['_sd_alg'] as String?;
  if (hashAlg != 'poseidon-v1') {
    return _invalid(
      'Unsupported or missing hash algorithm. '
      'Expected: poseidon-v1 in payload',
    );
  }

  if (!await verifyFunction(issuerSignedJWT)) {
    return _invalid('JWT signature verification failed');
  }

  final sdArray =
      (payload['_sd'] as List<dynamic>?)?.map((e) => e.toString()).toList() ??
      <String>[];

  for (final disclosure in disclosures) {
    try {
      final digest = await createDigest(disclosure);
      if (!sdArray.contains(digest)) {
        return _invalid('Disclosure digest not found in _sd array: $digest');
      }
    } on Object catch (e) {
      return _invalid('Failed to process disclosure: $e');
    }
  }

  final decodedZkproofs = <Map<String, dynamic>>[];
  for (final encodedZkproof in zkproofs) {
    if (encodedZkproof.trim().isEmpty) {
      continue;
    }
    try {
      final zkproof =
          jsonDecode(utf8.decode(base64urlDecode(encodedZkproof)))
              as Map<String, dynamic>;

      if (!zkproof.containsKey('proof') ||
          !zkproof.containsKey('publicSignals') ||
          !zkproof.containsKey('verificationKeyRefernce') ||
          !zkproof.containsKey('claimName')) {
        return _invalid(
          'Invalid zkproof structure. Expected: { proof: {}, '
          'publicSignals: [], verificationKeyRefernce, claimName }',
        );
      }

      final publicSignals = zkproof['publicSignals'] as List<dynamic>;
      if (publicSignals.length < 2) {
        return _invalid(
          'Zkproof publicSignals array must have at least 2 elements: '
          '[digest, claimNameDigest, ...]',
        );
      }

      final digest = publicSignals[0].toString();
      final digestClaim = publicSignals[1].toString();

      if (!sdArray.contains(digest)) {
        return _invalid('Zkproof digest not found in _sd array: $digest');
      }

      final claimName = zkproof['claimName'] as String;
      final claimNameHashReduced = fieldReduce(hashClaimName(claimName));
      final digestClaimBigInt = BigInt.parse(digestClaim);

      if (claimNameHashReduced != digestClaimBigInt) {
        return _invalid(
          'Claim name hash mismatch. Expected: $digestClaimBigInt, '
          'got: $claimNameHashReduced',
        );
      }

      if (trustedVkeys != null) {
        final reference = zkproof['verificationKeyRefernce'] as String;
        final allowed = trustedVkeys[claimName];
        if (allowed == null || !allowed.contains(reference)) {
          return _invalid(
            'Untrusted verification key reference "$reference" for claim '
            '"$claimName"',
          );
        }
      }

      decodedZkproofs.add(zkproof);
    } on Object catch (e) {
      return _invalid('Failed to decode zkproof: $e');
    }
  }

  final claims = <String, dynamic>{};
  for (final disclosure in disclosures) {
    final decoded = decodeDisclosure(disclosure);
    final name = decoded['name'] as String?;
    if (name != null) {
      _setNested(claims, name, decoded['value']);
    }
  }

  for (final entry in payload.entries) {
    final key = entry.key;
    if (key != '_sd' && key != '_sd_alg' && !claims.containsKey(key)) {
      claims[key] = entry.value;
    }
  }

  if (decodedZkproofs.isNotEmpty &&
      pullVkeyFunction != null &&
      verifyZkproof != null) {
    for (final decodedZkproof in decodedZkproofs) {
      final reference = decodedZkproof['verificationKeyRefernce'] as String;
      final Map<String, dynamic> vkey;
      try {
        vkey = await pullVkeyFunction(reference);
      } on Object catch (e) {
        return _invalid(
          'Failed to pull verification key $reference for zkproof: error: $e',
        );
      }

      final proof = decodedZkproof['proof'] as Map<String, dynamic>;
      final publicSignals = (decodedZkproof['publicSignals'] as List<dynamic>)
          .map((e) => e.toString())
          .toList();
      if (await verifyZkproof(vkey, publicSignals, proof)) {
        zkproofsValidatedAgainstVkey = true;
      } else {
        return _invalid('Failed to validate zkproof $reference');
      }
    }
  }

  return <String, dynamic>{
    'valid': true,
    'claims': claims,
    'payload': payload,
    'header': header,
    'zkproofs': decodedZkproofs.isNotEmpty ? decodedZkproofs : null,
    'zkproofsValidatedAgainstVkey': zkproofsValidatedAgainstVkey,
  };
}

void _setNested(Map<String, dynamic> root, String dottedName, Object? value) {
  final nameParts = dottedName.split('.');
  var current = root;
  for (var i = 0; i < nameParts.length - 1; i++) {
    current =
        current.putIfAbsent(nameParts[i], () => <String, dynamic>{})
            as Map<String, dynamic>;
  }
  current[nameParts.last] = value;
}
