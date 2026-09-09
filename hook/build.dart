import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';
import 'package:path/path.dart' as p;

/// Dart library that declares `@Native` bindings for this artifact.
const String _ffiLibraryAssetName = 'src/rust_eddsa_helper_ffi.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) {
      return;
    }

    final pref = input.config.code.linkModePreference;
    if (pref == LinkModePreference.static) {
      throw BuildError(
        message:
            'zk_jwt only ships a bundled dynamic library; '
            'LinkModePreference.static is not supported.',
      );
    }

    final code = input.config.code;
    final triple = _rustTriple(code);
    if (triple == null) {
      throw BuildError(
        message:
            'Unsupported native target: ${code.targetOS} '
            '${code.targetArchitecture}. '
            'Supported: macOS (arm64, x64), iOS (device + simulator), '
            'Android, Linux (x64, arm64), Windows (x64).',
      );
    }

    final libName = code.targetOS.dylibFileName('rust_eddsa_helper');
    final manifestUri = input.packageRoot.resolve('prebuilds/manifest.json');
    final manifest = _parseManifestFile(File.fromUri(manifestUri));
    final entry = manifest[triple];
    if (entry == null) {
      final keys = manifest.keys.toList()..sort();
      throw BuildError(
        message:
            'No prebuild entry for Rust triple "$triple" in prebuilds/manifest.json. '
            'Known triples: $keys. '
            'Maintainers: add a slice (vendored file under prebuilds/ and/or a '
            'download URL); see doc/native_build_and_hooks.md.',
      );
    }

    output.dependencies.add(manifestUri);

    final trustUri = input.packageRoot.resolve('prebuilds/.zk_jwt_trust_local');
    if (File.fromUri(trustUri).existsSync()) {
      output.dependencies.add(trustUri);
    }
    final overrideRootFileUri = input.packageRoot.resolve(
      'prebuilds/.zk_jwt_prebuilds_root',
    );
    if (File.fromUri(overrideRootFileUri).existsSync()) {
      output.dependencies.add(overrideRootFileUri);
    }

    final (bytes: loaded, fromNetwork: fromNetwork) = await _loadPrebuildBytes(
      packageRoot: input.packageRoot,
      triple: triple,
      libName: libName,
      entry: entry,
      onDependency: output.dependencies.add,
    );

    final mustVerify = fromNetwork || !_trustLocalPrebuilds(input.packageRoot);
    if (mustVerify) {
      _assertSha256(loaded, entry.sha256, triple);
    }

    final outFile = input.outputDirectory.resolve(libName);
    await File.fromUri(outFile).writeAsBytes(loaded, flush: true);

    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: _ffiLibraryAssetName,
        linkMode: DynamicLoadingBundled(),
        file: outFile,
      ),
    );
  });
}

class _PrebuildEntry {
  _PrebuildEntry({required this.sha256, this.url});

  final String sha256;
  final String? url;
}

Map<String, _PrebuildEntry> _parseManifestFile(File manifestFile) {
  if (!manifestFile.existsSync()) {
    throw BuildError(
      message:
          'Missing prebuilds/manifest.json. This package distributes native code '
          'as prebuilt binaries only (no Rust required on consumer machines).',
    );
  }
  final decoded = jsonDecode(manifestFile.readAsStringSync());
  if (decoded is! Map<String, dynamic>) {
    throw BuildError(message: 'prebuilds/manifest.json must be a JSON object.');
  }
  final out = <String, _PrebuildEntry>{};
  for (final MapEntry(:key, :value) in decoded.entries) {
    if (value is! Map<String, dynamic>) {
      throw BuildError(
        message: 'prebuilds/manifest.json entry "$key" must be an object.',
      );
    }
    final sha = value['sha256'];
    if (sha is! String || sha.isEmpty) {
      throw BuildError(
        message:
            'prebuilds/manifest.json entry "$key" needs a non-empty "sha256" string.',
      );
    }
    final url = value['url'];
    out[key] = _PrebuildEntry(
      sha256: sha.toLowerCase(),
      url: url is String && url.isNotEmpty ? url : null,
    );
  }
  return out;
}

/// **Hooks run in a semi-hermetic environment**; most env vars are not passed
/// through. Prefer marker files: `prebuilds/.zk_jwt_trust_local` and
/// `prebuilds/.zk_jwt_prebuilds_root` (see docs).
bool _trustLocalPrebuilds(Uri packageRoot) {
  if (File.fromUri(
    packageRoot.resolve('prebuilds/.zk_jwt_trust_local'),
  ).existsSync()) {
    return true;
  }
  final v = Platform.environment['ZK_JWT_PREBUILDS_TRUST_LOCAL']?.toLowerCase();
  return v == '1' || v == 'true' || v == 'yes';
}

/// Optional prebuilds root: each subfolder is a Rust triple with the dynamic
/// library (e.g. `librust_eddsa_helper.dylib`). First line of
/// `prebuilds/.zk_jwt_prebuilds_root` (absolute or relative to package), else
/// env `ZK_JWT_PREBUILDS_ROOT` if visible (rare in hooks).
String? _prebuildsOverrideDirPath(Uri packageRoot) {
  final marker = File.fromUri(
    packageRoot.resolve('prebuilds/.zk_jwt_prebuilds_root'),
  );
  if (marker.existsSync()) {
    for (final line in marker.readAsLinesSync()) {
      final raw = line.trim();
      if (raw.isEmpty || raw.startsWith('#')) {
        continue;
      }
      if (p.isAbsolute(raw)) {
        return p.normalize(raw);
      }
      return p.normalize(p.join(p.fromUri(packageRoot), raw));
    }
  }
  final raw = Platform.environment['ZK_JWT_PREBUILDS_ROOT']?.trim();
  if (raw == null || raw.isEmpty) {
    return null;
  }
  if (p.isAbsolute(raw)) {
    return p.normalize(raw);
  }
  return p.normalize(p.join(p.fromUri(packageRoot), raw));
}

Future<({Uint8List bytes, bool fromNetwork})> _loadPrebuildBytes({
  required Uri packageRoot,
  required String triple,
  required String libName,
  required _PrebuildEntry entry,
  required void Function(Uri) onDependency,
}) async {
  final overrideDir = _prebuildsOverrideDirPath(packageRoot);
  if (overrideDir != null) {
    final overrideFile = File(p.join(overrideDir, triple, libName));
    if (overrideFile.existsSync()) {
      onDependency(overrideFile.uri);
      return (
        bytes: Uint8List.fromList(await overrideFile.readAsBytes()),
        fromNetwork: false,
      );
    }
  }

  final localUri = packageRoot
      .resolve('prebuilds/')
      .resolve('$triple/')
      .resolve(libName);
  final localFile = File.fromUri(localUri);
  if (localFile.existsSync()) {
    onDependency(localUri);
    return (
      bytes: Uint8List.fromList(await localFile.readAsBytes()),
      fromNetwork: false,
    );
  }

  final url = entry.url;
  if (url == null || url.isEmpty) {
    final tried = <String>[];
    if (overrideDir != null) {
      tried.add(p.join(overrideDir, triple, libName));
    }
    tried.add(localFile.path);
    throw BuildError(
      message:
          'No local prebuild for triple "$triple" (tried ${tried.join(", ")}), '
          'and no "url" in the manifest. Add a library, set'
          ' ZK_JWT_PREBUILDS_ROOT, or add a download URL in prebuilds/manifest.json.',
    );
  }

  return (bytes: await _downloadVerified(url, triple), fromNetwork: true);
}

Future<Uint8List> _downloadVerified(String url, String triple) async {
  final uri = Uri.tryParse(url);
  if (uri == null ||
      !uri.hasScheme ||
      (uri.scheme != 'http' && uri.scheme != 'https')) {
    throw BuildError(
      message: 'Invalid prebuild download URL for "$triple": $url',
    );
  }

  final client = HttpClient();
  try {
    final request = await client.getUrl(uri);
    final response = await request.close().timeout(const Duration(minutes: 5));
    if (response.statusCode != HttpStatus.ok) {
      throw InfraError(
        message:
            'Prebuild download failed for "$triple" (HTTP ${response.statusCode}): $url',
      );
    }
    final builder = BytesBuilder(copy: false);
    await for (final chunk in response) {
      builder.add(chunk);
    }
    return builder.takeBytes();
  } on SocketException catch (e, st) {
    throw InfraError(
      message: 'Network error while downloading prebuild for "$triple": $e',
      wrappedException: e,
      wrappedTrace: st,
    );
  } on TimeoutException catch (e, st) {
    throw InfraError(
      message: 'Timeout while downloading prebuild for "$triple": $e',
      wrappedException: e,
      wrappedTrace: st,
    );
  } finally {
    client.close(force: true);
  }
}

void _assertSha256(Uint8List bytes, String expectedHexLower, String triple) {
  final digest = sha256.convert(bytes).toString();
  if (digest != expectedHexLower) {
    throw BuildError(
      message:
          'SHA-256 mismatch for prebuild triple "$triple": '
          'expected $expectedHexLower, got $digest. '
          'Refuse to load a tampered or corrupted binary.',
    );
  }
}

String? _rustTriple(CodeConfig code) {
  final os = code.targetOS;
  final arch = code.targetArchitecture;
  switch (os) {
    case OS.macOS:
      return switch (arch) {
        Architecture.arm64 => 'aarch64-apple-darwin',
        Architecture.x64 => 'x86_64-apple-darwin',
        _ => null,
      };
    case OS.iOS:
      final sdk = code.iOS.targetSdk;
      return switch ((arch, sdk)) {
        (Architecture.arm64, IOSSdk.iPhoneOS) => 'aarch64-apple-ios',
        (Architecture.arm64, IOSSdk.iPhoneSimulator) => 'aarch64-apple-ios-sim',
        (Architecture.x64, IOSSdk.iPhoneSimulator) => 'x86_64-apple-ios',
        _ => null,
      };
    case OS.android:
      if (code.cCompiler == null) {
        return null;
      }
      return switch (arch) {
        Architecture.arm64 => 'aarch64-linux-android',
        Architecture.arm => 'armv7-linux-androideabi',
        Architecture.x64 => 'x86_64-linux-android',
        Architecture.ia32 => 'i686-linux-android',
        _ => null,
      };
    case OS.linux:
      return switch (arch) {
        Architecture.x64 => 'x86_64-unknown-linux-gnu',
        Architecture.arm64 => 'aarch64-unknown-linux-gnu',
        _ => null,
      };
    case OS.windows:
      return switch (arch) {
        Architecture.x64 => 'x86_64-pc-windows-gnu',
        _ => null,
      };
    default:
      return null;
  }
}
