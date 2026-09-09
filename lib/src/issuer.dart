/// ZK-JWT issuer: creates Selective Disclosure JWT credentials with Poseidon
/// digests.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'core.dart';
import 'hash.dart';

/// Signs the `header.payload` portion of a JWT and returns the raw signature
/// bytes.
typedef SignFunction = Future<Uint8List> Function(String data);

/// Creates a ZK-JWT credential from [payload].
///
/// [signFunction] signs the encoded `header.payload` string. When
/// [selectiveDisclosure] is `true` (default) each claim is replaced by a
/// Poseidon digest in the `_sd` array and returned as a disclosure.
///
/// Returns a map with `zkJwt` (the combined credential string), `disclosures`
/// (the list of disclosures), and `payload` (the signed JWT payload).
Future<Map<String, dynamic>> createZKJWT(
  Map<String, dynamic> payload,
  SignFunction signFunction, {
  bool selectiveDisclosure = true,
}) async {
  final processed = await processClaims(payload, <String, dynamic>{
    'selectiveDisclosure': selectiveDisclosure,
    'disclosures': <String>[],
  });

  final jwtPayload = <String, dynamic>{
    ...processed['claims'] as Map<String, dynamic>,
    '_sd': processed['_sd'] as List<String>,
    '_sd_alg': 'poseidon-v1',
  };

  final header = <String, String>{'alg': 'ES256', 'typ': 'zk+jwt'};

  final encodedHeader = base64urlEncode(
    Uint8List.fromList(utf8.encode(jsonEncode(header))),
  );
  final encodedPayload = base64urlEncode(
    Uint8List.fromList(utf8.encode(jsonEncode(jwtPayload))),
  );

  final signature = await signFunction('$encodedHeader.$encodedPayload');
  final encodedSignature = base64urlEncode(signature);

  final issuerSignedJWT = '$encodedHeader.$encodedPayload.$encodedSignature';

  final allDisclosures = processed['disclosures'] as List<String>;
  final zkJwt = <String>[issuerSignedJWT, ...allDisclosures].join('~');

  return <String, dynamic>{
    'zkJwt': zkJwt,
    'disclosures': allDisclosures,
    'payload': jwtPayload,
  };
}
