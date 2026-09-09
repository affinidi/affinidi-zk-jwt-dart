/// Core ZK-JWT primitives: disclosures, digests, and field-element encoding.
///
/// ZK-JWT is SD-JWT (Selective Disclosure JWT) with a Poseidon hash, making it
/// ZKP-friendly for use inside zero-knowledge proof circuits.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'hash.dart';
import 'rust_eddsa_helper_ffi.dart';

RustEddsaHelperFfi? _poseidonHelper;

RustEddsaHelperFfi _getPoseidonHelper() {
  return _poseidonHelper ??= RustEddsaHelperFfi();
}

/// BN254 scalar field prime; commitments and digests are reduced modulo this.
final BigInt _bn254FieldPrime = BigInt.parse(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);

/// Generates a cryptographically random base64url-encoded salt.
///
/// [length] is the salt size in bytes (default `16`).
String generateSalt({int length = 16}) {
  final random = Random.secure();
  final salt = Uint8List(length);
  for (var i = 0; i < length; i++) {
    salt[i] = random.nextInt(256);
  }
  return base64urlEncode(salt);
}

/// Creates a disclosure for a claim.
///
/// The disclosure is the base64url encoding of `[salt, claimName, claimValue]`,
/// or `[salt, claimValue]` when [claimName] is `null` (array elements).
String createDisclosure(String salt, String? claimName, Object? claimValue) {
  final disclosure = claimName != null
      ? <Object?>[salt, claimName, claimValue]
      : <Object?>[salt, claimValue];
  return base64urlEncode(
    Uint8List.fromList(utf8.encode(jsonEncode(disclosure))),
  );
}

/// Decodes a disclosure into its `salt`, optional `name`, and `value` parts.
Map<String, dynamic> decodeDisclosure(String disclosure) {
  final json = utf8.decode(base64urlDecode(disclosure));
  final arr = jsonDecode(json) as List<dynamic>;

  if (arr.length == 2) {
    return <String, dynamic>{'salt': arr[0], 'value': arr[1]};
  } else if (arr.length == 3) {
    return <String, dynamic>{'salt': arr[0], 'name': arr[1], 'value': arr[2]};
  }
  throw const FormatException('Invalid disclosure format');
}

/// Hashes a claim name with SHA-256 and returns it as a [BigInt].
BigInt hashClaimName(String claimName) => _sha256ToBigInt(claimName);

BigInt _sha256ToBigInt(String input) {
  final hash = sha256.convert(utf8.encode(input));
  return BigInt.parse('0x$hash');
}

/// Reduces [value] modulo the BN254 field prime.
///
/// Matches the behaviour of `babyJub.F.e()` in the JavaScript reference.
BigInt fieldReduce(BigInt value) => value % _bn254FieldPrime;

/// Converts a base64url string or raw bytes salt to a [BigInt].
BigInt saltToFieldElement(Object salt) {
  final Uint8List saltBytes;
  if (salt is String) {
    saltBytes = base64urlDecode(salt);
  } else if (salt is Uint8List) {
    saltBytes = salt;
  } else {
    throw ArgumentError('Salt must be String or Uint8List');
  }
  final hex = saltBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return BigInt.parse('0x$hex');
}

/// Converts an arbitrary claim [value] to a field-element [BigInt].
///
/// Numbers, [BigInt], and booleans map directly; numeric strings parse to
/// integers; other strings and structured values are SHA-256 hashed; `null`
/// maps to zero. The result is always reduced modulo the BN254 field prime so
/// it falls within `[0, p)` (per SPEC section 8.3), which also normalises
/// negative integers into the field.
BigInt valueToFieldElement(Object? value) {
  final BigInt raw;
  if (value is int) {
    raw = BigInt.from(value);
  } else if (value is BigInt) {
    raw = value;
  } else if (value is bool) {
    raw = BigInt.from(value ? 1 : 0);
  } else if (value is String) {
    final parsed = int.tryParse(value);
    raw = parsed != null ? BigInt.from(parsed) : _sha256ToBigInt(value);
  } else if (value == null) {
    raw = BigInt.zero;
  } else {
    raw = _sha256ToBigInt(jsonEncode(value));
  }
  return fieldReduce(raw);
}

/// Prepares circuit inputs (`claimNameDigest`, `salt`, `value`) as strings.
Future<Map<String, String>> prepareCircuitInputs(
  String claimName,
  String salt,
  Object? value,
) async {
  // All inputs MUST be reduced modulo the BN254 field prime before hashing
  // (SPEC sections 5.3 and 8.3) so they match the values the verifier and the
  // circuit compute.
  final claimNameDigest = fieldReduce(hashClaimName(claimName));
  final saltBigInt = fieldReduce(saltToFieldElement(salt));
  final valueBigInt = valueToFieldElement(value);
  return <String, String>{
    'claimNameDigest': claimNameDigest.toString(),
    'salt': saltBigInt.toString(),
    'value': valueBigInt.toString(),
  };
}

/// Creates a Poseidon digest from `[claimNameDigest, salt, value]`.
///
/// Mirrors the circuit's `DisclosureDigest` component. [inputs] must contain
/// exactly three elements.
Future<String> createDigestFromArray(List<dynamic> inputs) async {
  if (inputs.length != 3) {
    throw ArgumentError(
      'Input array must have exactly 3 elements: '
      '[claimNameDigest, salt, value]',
    );
  }

  final poseidon = _getPoseidonHelper();

  final claimNameDigest = inputs[0];
  final salt = inputs[1] as Object;
  final value = inputs[2];

  final BigInt claimNameDigestBigInt;
  if (claimNameDigest is String) {
    claimNameDigestBigInt = BigInt.parse(claimNameDigest);
  } else if (claimNameDigest is BigInt) {
    claimNameDigestBigInt = claimNameDigest;
  } else {
    throw ArgumentError('claimNameDigest must be String or BigInt');
  }

  // Reduce every input modulo the BN254 field prime before hashing (SPEC
  // sections 5.1 step 4 and 8.3). Relying on the native Poseidon helper to
  // auto-reduce is undocumented and would diverge from a spec-literal
  // implementation or the verifier's reduced comparison.
  final claimNameDigestField = fieldReduce(claimNameDigestBigInt);
  final saltValue = fieldReduce(saltToFieldElement(salt));
  final valueBigInt = valueToFieldElement(value);

  return poseidon.poseidonHashFieldElements(<String>[
    claimNameDigestField.toString(),
    saltValue.toString(),
    valueBigInt.toString(),
  ]);
}

/// Creates the Poseidon digest for a base64url-encoded [disclosure].
Future<String> createDigest(String disclosure) async {
  final json = utf8.decode(base64urlDecode(disclosure));
  final arr = jsonDecode(json) as List<dynamic>;

  if (arr.length == 3) {
    final salt = arr[0] as String;
    final claimName = arr[1] as String;
    final claimValue = arr[2];
    final claimNameDigest = hashClaimName(claimName);
    return createDigestFromArray(<dynamic>[claimNameDigest, salt, claimValue]);
  } else if (arr.length == 2) {
    final salt = arr[0] as String;
    final claimValue = arr[1];
    final emptyClaimNameDigest = hashClaimName('');
    return createDigestFromArray(<dynamic>[
      emptyClaimNameDigest,
      salt,
      claimValue,
    ]);
  }
  throw const FormatException('Invalid disclosure format');
}

/// Recursively processes [claims] into payload claims, `_sd` digests, and
/// disclosures.
///
/// [options] recognises `selectiveDisclosure` (bool) and `disclosures`
/// (`List<String>`). [prefix] is used internally for nested claim names.
Future<Map<String, dynamic>> processClaims(
  Map<String, dynamic> claims,
  Map<String, dynamic> options, [
  String prefix = '',
]) async {
  final selectiveDisclosure = options['selectiveDisclosure'] as bool? ?? true;
  final disclosures = options['disclosures'] as List<String>? ?? <String>[];

  final result = <String, dynamic>{};
  final newSd = <String>[];
  final newDisclosures = <String>[];

  for (final entry in claims.entries) {
    final key = entry.key;
    final value = entry.value;
    final fullKey = prefix.isNotEmpty ? '$prefix.$key' : key;

    if (key == '_sd' || key == '_sd_alg' || key == '...') {
      continue;
    }

    if (value == null) {
      result[key] = value;
      continue;
    }

    if (value is Map) {
      final nestedOptions = <String, dynamic>{
        ...options,
        '_sd': <String>[],
        'disclosures': <String>[],
      };
      final nested = await processClaims(
        Map<String, dynamic>.from(value),
        nestedOptions,
        fullKey,
      );

      if (selectiveDisclosure && (nested['_sd'] as List).isNotEmpty) {
        final salt = generateSalt();
        final nestedClaims =
            nested['claims'] as Map<String, dynamic>? ?? <String, dynamic>{};
        final disclosure = createDisclosure(salt, fullKey, nestedClaims);
        final digest = await createDigest(disclosure);

        newDisclosures.add(disclosure);
        newSd.add(digest);

        newSd.addAll(nested['_sd'] as List<String>);
        newDisclosures.addAll(nested['disclosures'] as List<String>);
      } else {
        result[key] = nested['claims'];
        newSd.addAll(nested['_sd'] as List<String>);
        newDisclosures.addAll(nested['disclosures'] as List<String>);
      }
    } else if (value is List) {
      final arrayResult = <dynamic>[];
      final arrayDigests = <String>[];

      for (final item in value) {
        if (item is Map) {
          final salt = generateSalt();
          final disclosure = createDisclosure(salt, null, item);
          final digest = await createDigest(disclosure);
          arrayDigests.add(digest);
          newDisclosures.add(disclosure);
        } else {
          arrayResult.add(item);
        }
      }

      result[key] = arrayResult;
      if (arrayDigests.isNotEmpty) {
        result['${key}_sd'] = arrayDigests;
        newSd.addAll(arrayDigests);
      }
    } else {
      if (selectiveDisclosure) {
        final salt = generateSalt();
        final disclosure = createDisclosure(salt, fullKey, value);
        final digest = await createDigest(disclosure);

        newDisclosures.add(disclosure);
        newSd.add(digest);
      } else {
        result[key] = value;
      }
    }
  }

  return <String, dynamic>{
    'claims': result,
    '_sd': newSd,
    'disclosures': <String>[...disclosures, ...newDisclosures],
  };
}
