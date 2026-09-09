/// ZK-JWT holder: creates presentations with selective disclosure and optional
/// zero-knowledge proofs.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'core.dart';
import 'hash.dart';

/// Creates a presentation of [sdJwt] disclosing only [disclosedClaims].
///
/// When [disclosedClaims] is empty every disclosure present in the credential
/// is included. [zkproofs] entries, when provided, must each contain `proof`,
/// `publicSignals`, `verificationKeyRefernce`, and `claimName`; they are
/// appended base64url-encoded after a `*` separator.
Future<String> createPresentation(
  String sdJwt,
  List<String> disclosedClaims, [
  List<Map<String, dynamic>> zkproofs = const <Map<String, dynamic>>[],
]) async {
  final parts = sdJwt.split('~');
  final issuerSignedJWT = parts[0];
  final disclosures = parts.sublist(1);

  final digestMap = <String, String>{};
  final disclosureToDigest = <String, String>{};

  for (final disclosure in disclosures) {
    final digest = await createDigest(disclosure);
    digestMap[digest] = disclosure;
    disclosureToDigest[disclosure] = digest;
  }

  final jwtParts = issuerSignedJWT.split('.');
  if (jwtParts.length != 3) {
    throw const FormatException('Invalid JWT format');
  }
  final payload =
      jsonDecode(utf8.decode(base64urlDecode(jwtParts[1])))
          as Map<String, dynamic>;
  final sdArray =
      (payload['_sd'] as List<dynamic>?)?.map((e) => e.toString()).toList() ??
      <String>[];

  final presentationDisclosures = <String>[];

  if (disclosedClaims.isEmpty) {
    for (final digest in sdArray) {
      final disclosure = digestMap[digest];
      if (disclosure != null) {
        presentationDisclosures.add(disclosure);
      }
    }
  } else {
    for (final claimPath in disclosedClaims) {
      for (final disclosure in disclosures) {
        final decoded = decodeDisclosure(disclosure);
        final claimName = decoded['name'] as String? ?? '';

        if (claimName == claimPath || claimName.endsWith('.$claimPath')) {
          final digest = disclosureToDigest[disclosure];
          if (digest != null && sdArray.contains(digest)) {
            presentationDisclosures.add(disclosure);
          }
        }
      }
    }
  }

  var presentation = <String>[
    issuerSignedJWT,
    ...presentationDisclosures,
  ].join('~');

  if (zkproofs.isNotEmpty) {
    final encodedZkproofs = zkproofs.map((zkproof) {
      if (!zkproof.containsKey('proof') ||
          !zkproof.containsKey('publicSignals') ||
          !zkproof.containsKey('verificationKeyRefernce') ||
          !zkproof.containsKey('claimName')) {
        throw const FormatException(
          'Invalid zkproof structure. Expected: { proof: {}, '
          'publicSignals: [], verificationKeyRefernce, claimName }',
        );
      }
      return base64urlEncode(
        Uint8List.fromList(utf8.encode(jsonEncode(zkproof))),
      );
    }).toList();

    presentation = '$presentation*${encodedZkproofs.join('*')}';
  }

  return presentation;
}

/// Extracts the disclosed claims from a ZK-JWT [presentation].
Future<Map<String, dynamic>> extractDisclosedClaims(String presentation) async {
  // Strip any appended zero-knowledge proofs (separated by `*`) before parsing
  // disclosures, mirroring the verifier. Splitting on `~` alone would fold the
  // proofs into the final disclosure and corrupt it.
  final disclosurePart = presentation.split('*').first;
  final parts = disclosurePart.split('~');
  final issuerSignedJWT = parts[0];
  final disclosures = parts.sublist(1);

  final jwtParts = issuerSignedJWT.split('.');
  if (jwtParts.length != 3) {
    throw const FormatException('Invalid JWT format');
  }
  final payloadObj =
      jsonDecode(utf8.decode(base64urlDecode(jwtParts[1])))
          as Map<String, dynamic>;
  final sdArray =
      (payloadObj['_sd'] as List<dynamic>?)
          ?.map((e) => e.toString())
          .toList() ??
      <String>[];

  final digestMap = <String, Map<String, dynamic>>{};
  for (final disclosure in disclosures) {
    final digest = await createDigest(disclosure);
    digestMap[digest] = decodeDisclosure(disclosure);
  }

  final claims = <String, dynamic>{};

  for (final digest in sdArray) {
    final decoded = digestMap[digest];
    if (decoded == null) {
      continue;
    }
    final name = decoded['name'] as String?;
    if (name != null) {
      _setNested(claims, name, decoded['value']);
    } else {
      claims[digest] = decoded['value'];
    }
  }

  for (final entry in payloadObj.entries) {
    final key = entry.key;
    if (key != '_sd' && key != '_sd_alg' && !claims.containsKey(key)) {
      claims[key] = entry.value;
    }
  }

  return claims;
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
