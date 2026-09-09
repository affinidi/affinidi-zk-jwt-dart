import 'dart:convert';
import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart';

typedef _PoseidonHashNative =
    ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _PoseidonHashBitsNative =
    ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _PoseidonFreeStringNative = ffi.Void Function(ffi.Pointer<Utf8>);

@ffi.Native<_PoseidonHashNative>(symbol: 'poseidon_hash')
external int _rustPoseidonHash(
  ffi.Pointer<Utf8> inputJson,
  ffi.Pointer<ffi.Pointer<Utf8>> outputJson,
);

@ffi.Native<_PoseidonHashBitsNative>(symbol: 'poseidon_hash_bits_ffi')
external int _rustPoseidonHashBitsFfi(
  ffi.Pointer<Utf8> inputJson,
  ffi.Pointer<ffi.Pointer<Utf8>> outputJson,
);

@ffi.Native<_PoseidonFreeStringNative>(symbol: 'poseidon_free_string')
external void _rustPoseidonFreeString(ffi.Pointer<Utf8> ptr);

/// FFI wrapper around the Poseidon hash exported by `affinidi-zkp-crypto-rs`.
///
/// Native code is built and bundled via `hook/build.dart` (Dart native-asset
/// hooks). Supported targets: macOS, iOS, Android, Linux, and Windows.
class RustEddsaHelperFfi {
  /// Creates the helper; symbols resolve against the bundled
  /// `rust_eddsa_helper` dynamic library from the build hook.
  RustEddsaHelperFfi();

  /// Runs Poseidon hash over field elements represented as decimal strings.
  Future<String> poseidonHashFieldElements(List<String> inputs) async {
    if (inputs.isEmpty) {
      throw ArgumentError('Poseidon inputs cannot be empty.');
    }
    final requestJson = jsonEncode(<String, Object?>{'inputs': inputs});
    final requestPtr = requestJson.toNativeUtf8();
    final responsePtr = malloc<ffi.Pointer<Utf8>>();

    try {
      final code = _rustPoseidonHash(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        operationName: 'poseidon_hash',
      );
      final result = response['result']?.toString();
      if (result == null || result.isEmpty) {
        throw StateError('poseidon_hash returned empty result.');
      }
      return result;
    } finally {
      malloc.free(responsePtr);
      malloc.free(requestPtr);
    }
  }

  /// Runs Poseidon hash over raw bits (`0` or `1`).
  Future<String> poseidonHashBits(List<int> bits) async {
    for (final bit in bits) {
      if (bit != 0 && bit != 1) {
        throw ArgumentError('Bits must be either 0 or 1.');
      }
    }
    final requestJson = jsonEncode(<String, Object?>{'bits': bits});
    final requestPtr = requestJson.toNativeUtf8();
    final responsePtr = malloc<ffi.Pointer<Utf8>>();

    try {
      final code = _rustPoseidonHashBitsFfi(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        operationName: 'poseidon_hash_bits_ffi',
      );
      final result = response['result']?.toString();
      if (result == null || result.isEmpty) {
        throw StateError('poseidon_hash_bits_ffi returned empty result.');
      }
      return result;
    } finally {
      malloc.free(responsePtr);
      malloc.free(requestPtr);
    }
  }

  Map<String, dynamic> _parseRustJson({
    required int code,
    required ffi.Pointer<Utf8> responsePtr,
    required String operationName,
  }) {
    if (responsePtr == ffi.nullptr) {
      throw StateError('$operationName returned null response pointer.');
    }

    final responseString = responsePtr.toDartString();
    _rustPoseidonFreeString(responsePtr);

    final decoded = jsonDecode(responseString);
    if (decoded is! Map<String, dynamic>) {
      throw StateError('$operationName returned malformed JSON.');
    }
    if (decoded['success'] != true || code != 0) {
      throw StateError(
        '$operationName failed: ${decoded['error'] ?? 'unknown error'}',
      );
    }
    return decoded;
  }
}
