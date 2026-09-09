/// Poseidon hashing helpers for ZK-JWT.
///
/// Replaces SHA-256 with the ZK-friendly Poseidon hash so digests are usable
/// inside zero-knowledge proof circuits.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'rust_eddsa_helper_ffi.dart';

RustEddsaHelperFfi? _poseidonHelper;

RustEddsaHelperFfi _getPoseidonHelper() {
  return _poseidonHelper ??= RustEddsaHelperFfi();
}

/// Converts a string to a list of bits (`0` or `1`) using UTF-8 encoding.
///
/// Bits are emitted least-significant-first per byte to match the reference
/// `circomlibjs` behaviour.
List<int> stringToBits(String str) {
  final bytes = utf8.encode(str);
  final bits = <int>[];
  for (final byte in bytes) {
    for (var j = 0; j < 8; j++) {
      bits.add((byte >> j) & 1);
    }
  }
  return bits;
}

/// Hashes a disclosure string using Poseidon and returns a base64url digest.
///
/// The [disclosure] is a base64url-encoded `[salt, claimName, claimValue]`
/// JSON array. The returned value is the base64url encoding of the 32-byte
/// big-endian Poseidon field element.
Future<String> poseidonHash(String disclosure) async {
  final poseidon = _getPoseidonHelper();

  final bits = stringToBits(disclosure);
  final hashStr = await poseidon.poseidonHashBits(bits);

  final hashBigInt = BigInt.parse(hashStr);

  var hexStr = hashBigInt.toRadixString(16);
  if (hexStr.length.isOdd) {
    hexStr = '0$hexStr';
  }
  hexStr = hexStr.padLeft(64, '0');
  if (hexStr.length > 64) {
    hexStr = hexStr.substring(hexStr.length - 64);
  }

  final hashBytes = Uint8List.fromList(
    List<int>.generate(
      hexStr.length ~/ 2,
      (i) => int.parse(hexStr.substring(i * 2, i * 2 + 2), radix: 16),
    ),
  );

  return base64urlEncode(hashBytes);
}

/// Base64url-encodes [bytes] without padding (RFC 4648 section 5).
String base64urlEncode(Uint8List bytes) {
  return base64Encode(
    bytes,
  ).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

/// Base64url-decodes [str], tolerating missing padding (RFC 4648 section 5).
Uint8List base64urlDecode(String str) {
  var padded = str.replaceAll('-', '+').replaceAll('_', '/');
  while (padded.length % 4 != 0) {
    padded += '=';
  }
  return base64Decode(padded);
}
