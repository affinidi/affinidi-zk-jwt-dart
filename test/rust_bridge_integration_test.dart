import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';
import 'package:zk_jwt/zk_jwt.dart';

Future<Uint8List> _mockSign(String data) async {
  return Uint8List.fromList(sha256.convert(utf8.encode(data)).bytes);
}

Future<bool> _mockVerify(String jwt) async => jwt.split('.').length == 3;

void main() {
  group('Rust bridge integration', tags: 'integration', () {
    late RustEddsaHelperFfi crypto;

    setUpAll(() {
      // Requires the bundled Rust dynamic library (native assets / hooks).
      crypto = RustEddsaHelperFfi();
    });

    test('poseidon field-element hash is deterministic', () async {
      final a = await crypto.poseidonHashFieldElements(<String>['1', '2', '3']);
      final b = await crypto.poseidonHashFieldElements(<String>['1', '2', '3']);

      expect(a, equals(b));
      expect(BigInt.tryParse(a), isNotNull);
    });

    test('poseidon bit hash is deterministic', () async {
      final a = await crypto.poseidonHashBits(<int>[1, 0, 1, 1]);
      final b = await crypto.poseidonHashBits(<int>[1, 0, 1, 1]);

      expect(a, equals(b));
      expect(BigInt.tryParse(a), isNotNull);
    });

    test('poseidonHashFieldElements rejects empty input', () {
      expect(
        () => crypto.poseidonHashFieldElements(<String>[]),
        throwsArgumentError,
      );
    });

    test('poseidonHashBits rejects non-binary values', () {
      expect(
        () => crypto.poseidonHashBits(<int>[0, 2, 1]),
        throwsArgumentError,
      );
    });

    test('poseidonHash produces a stable base64url digest', () async {
      final digest = await poseidonHash('sample-disclosure');
      expect(digest, equals(await poseidonHash('sample-disclosure')));
      expect(base64urlDecode(digest).length, equals(32));
    });

    test('createDigest is stable for identical disclosures', () async {
      final salt = generateSalt();
      final disclosure = createDisclosure(salt, 'age', 28);

      expect(
        await createDigest(disclosure),
        equals(await createDigest(disclosure)),
      );
    });

    test(
      'full issuer -> holder -> verifier flow discloses chosen claims',
      () async {
        final payload = <String, dynamic>{
          'iss': 'https://example.com/issuer',
          'given_name': 'John',
          'family_name': 'Doe',
          'email': 'john.doe@example.com',
        };

        final issued = await createZKJWT(payload, _mockSign);
        final zkJwt = issued['zkJwt'] as String;
        expect(issued['disclosures'], isNotEmpty);

        final presentation = await createPresentation(zkJwt, <String>[
          'given_name',
          'email',
        ]);

        final result = await verifyPresentation(presentation, _mockVerify);

        expect(result['valid'], isTrue);
        final claims = result['claims'] as Map<String, dynamic>;
        expect(claims['given_name'], equals('John'));
        expect(claims['email'], equals('john.doe@example.com'));
        expect(claims.containsKey('family_name'), isFalse);
      },
    );

    test('nested claims are disclosed by dotted path', () async {
      final payload = <String, dynamic>{
        'name': 'John Doe',
        'address': <String, dynamic>{
          'street': '123 Main St',
          'city': 'Anytown',
        },
      };

      final issued = await createZKJWT(payload, _mockSign);
      final presentation = await createPresentation(
        issued['zkJwt'] as String,
        <String>['name', 'address.street'],
      );
      final result = await verifyPresentation(presentation, _mockVerify);

      expect(result['valid'], isTrue);
      final claims = result['claims'] as Map<String, dynamic>;
      expect(claims['name'], equals('John Doe'));
      expect(
        (claims['address'] as Map<String, dynamic>)['street'],
        equals('123 Main St'),
      );
    });

    test('extractDisclosedClaims returns the disclosed subset', () async {
      final issued = await createZKJWT(<String, dynamic>{
        'name': 'John Doe',
        'email': 'john@example.com',
      }, _mockSign);
      final presentation = await createPresentation(
        issued['zkJwt'] as String,
        <String>['name'],
      );

      final claims = await extractDisclosedClaims(presentation);
      expect(claims['name'], equals('John Doe'));
    });

    test('verifier rejects an unsupported hash algorithm', () async {
      final payload = base64Url
          .encode(
            utf8.encode(jsonEncode(<String, dynamic>{'_sd_alg': 'sha-256'})),
          )
          .replaceAll('=', '');
      final header = base64Url
          .encode(utf8.encode(jsonEncode(<String, dynamic>{'alg': 'ES256'})))
          .replaceAll('=', '');
      final bogus = '$header.$payload.sig';

      final result = await verifyPresentation(bogus, _mockVerify);
      expect(result['valid'], isFalse);
      expect(result['error'], contains('poseidon-v1'));
    });

    test('verifier validates zkproofs against a supplied vkey', () async {
      final payload = <String, dynamic>{'balance': 5000};
      final issued = await createZKJWT(payload, _mockSign);
      final zkJwt = issued['zkJwt'] as String;

      final disclosure = (issued['disclosures'] as List<String>).first;
      final digest = await createDigest(disclosure);
      final claimNameDigest = fieldReduce(hashClaimName('balance')).toString();

      final zkproof = <String, dynamic>{
        'proof': <String, dynamic>{'pi_a': <String>[]},
        'publicSignals': <String>[digest, claimNameDigest],
        'verificationKeyRefernce': 'vkey-1',
        'claimName': 'balance',
      };

      final presentation = await createPresentation(
        zkJwt,
        <String>[],
        <Map<String, dynamic>>[zkproof],
      );

      final result = await verifyPresentation(
        presentation,
        _mockVerify,
        pullVkeyFunction: (reference) async => <String, dynamic>{
          'ref': reference,
        },
        verifyZkproof: (vkey, publicSignals, proof) async => true,
      );

      expect(result['valid'], isTrue);
      expect(result['zkproofsValidatedAgainstVkey'], isTrue);
    });

    test('arrays of objects are individually disclosed with digests', () async {
      final payload = <String, dynamic>{
        'items': <Map<String, dynamic>>[
          <String, dynamic>{'id': 1},
          <String, dynamic>{'id': 2},
        ],
      };

      final issued = await createZKJWT(payload, _mockSign);
      expect(issued['disclosures'], hasLength(2));
      final claims = issued['payload'] as Map<String, dynamic>;
      expect(claims['items_sd'], hasLength(2));
    });

    test(
      'non-selective disclosure keeps claims in the plain payload',
      () async {
        final issued = await createZKJWT(
          <String, dynamic>{'name': 'John Doe'},
          _mockSign,
          selectiveDisclosure: false,
        );

        expect(issued['disclosures'], isEmpty);
        final payload = issued['payload'] as Map<String, dynamic>;
        expect(payload['name'], equals('John Doe'));
        expect(payload['_sd'], isEmpty);
      },
    );

    test('createDigestFromArray rejects wrong-sized input', () {
      expect(
        () => createDigestFromArray(<dynamic>['only-one']),
        throwsArgumentError,
      );
    });

    test('createPresentation rejects a malformed JWT', () async {
      expect(
        () => createPresentation('not-a-jwt', <String>[]),
        throwsFormatException,
      );
    });

    test('verifier rejects an empty presentation', () async {
      final result = await verifyPresentation('   ', _mockVerify);
      expect(result['valid'], isFalse);
      expect(result['error'], contains('empty presentation'));
    });

    test('verifier rejects an invalid JWT structure', () async {
      final result = await verifyPresentation('not-a-jwt', _mockVerify);
      expect(result['valid'], isFalse);
      expect(result['error'], contains('Invalid JWT format'));
    });

    test('verifier rejects a failing signature check', () async {
      final issued = await createZKJWT(<String, dynamic>{
        'name': 'John Doe',
      }, _mockSign);
      final result = await verifyPresentation(
        issued['zkJwt'] as String,
        (jwt) async => false,
      );
      expect(result['valid'], isFalse);
      expect(result['error'], contains('signature verification failed'));
    });

    test('verifier rejects a zkproof missing required fields', () async {
      final issued = await createZKJWT(<String, dynamic>{
        'balance': 5000,
      }, _mockSign);
      final badZkproof = base64urlEncode(
        Uint8List.fromList(
          utf8.encode(
            jsonEncode(<String, dynamic>{'proof': <String, dynamic>{}}),
          ),
        ),
      );
      final presentation = '${issued['zkJwt'] as String}*$badZkproof';

      final result = await verifyPresentation(presentation, _mockVerify);
      expect(result['valid'], isFalse);
      expect(result['error'], contains('Invalid zkproof structure'));
    });

    test('createDigestFromArray reduces claimNameDigest '
        '(raw and pre-reduced agree)', () async {
      // Regression guard: the library must field-reduce the claimNameDigest
      // itself rather than relying on the native helper to auto-reduce.
      // Passing the raw SHA-256 hash and the pre-reduced value must yield the
      // same digest, matching the verifier and a spec-literal implementation.
      const claimName = 'balance';
      const claimValue = 5000;
      final salt = generateSalt();

      final rawClaimNameDigest = hashClaimName(claimName);
      final reducedClaimNameDigest = fieldReduce(rawClaimNameDigest);
      // Sanity: this claim name exceeds the field prime, so reduction matters.
      expect(reducedClaimNameDigest, isNot(equals(rawClaimNameDigest)));

      final digestFromRaw = await createDigestFromArray(<dynamic>[
        rawClaimNameDigest,
        salt,
        claimValue,
      ]);
      final digestFromReduced = await createDigestFromArray(<dynamic>[
        reducedClaimNameDigest,
        salt,
        claimValue,
      ]);

      expect(digestFromRaw, equals(digestFromReduced));
    });

    test('extractDisclosedClaims ignores appended zkproofs', () async {
      final payload = <String, dynamic>{'balance': 5000};
      final issued = await createZKJWT(payload, _mockSign);
      final zkJwt = issued['zkJwt'] as String;

      final disclosure = (issued['disclosures'] as List<String>).first;
      final digest = await createDigest(disclosure);
      final claimNameDigest = fieldReduce(hashClaimName('balance')).toString();

      final zkproof = <String, dynamic>{
        'proof': <String, dynamic>{'pi_a': <String>[]},
        'publicSignals': <String>[digest, claimNameDigest],
        'verificationKeyRefernce': 'vkey-1',
        'claimName': 'balance',
      };

      final presentation = await createPresentation(
        zkJwt,
        <String>[],
        <Map<String, dynamic>>[zkproof],
      );
      // The presentation carries a `*`-separated zkproof after the disclosures.
      expect(presentation, contains('*'));

      final claims = await extractDisclosedClaims(presentation);
      expect(claims['balance'], equals(5000));
    });

    test('verifier enforces a trusted vkey allowlist', () async {
      final payload = <String, dynamic>{'balance': 5000};
      final issued = await createZKJWT(payload, _mockSign);
      final zkJwt = issued['zkJwt'] as String;

      final disclosure = (issued['disclosures'] as List<String>).first;
      final digest = await createDigest(disclosure);
      final claimNameDigest = fieldReduce(hashClaimName('balance')).toString();

      final zkproof = <String, dynamic>{
        'proof': <String, dynamic>{'pi_a': <String>[]},
        'publicSignals': <String>[digest, claimNameDigest],
        'verificationKeyRefernce': 'untrusted-vkey',
        'claimName': 'balance',
      };

      final presentation = await createPresentation(
        zkJwt,
        <String>[],
        <Map<String, dynamic>>[zkproof],
      );

      // Reference not in the allowlist for the claim -> rejected before pull.
      final rejected = await verifyPresentation(
        presentation,
        _mockVerify,
        pullVkeyFunction: (reference) async => <String, dynamic>{},
        verifyZkproof: (vkey, publicSignals, proof) async => true,
        trustedVkeys: <String, Set<String>>{
          'balance': <String>{'trusted-vkey'},
        },
      );
      expect(rejected['valid'], isFalse);
      expect(rejected['error'], contains('Untrusted verification key'));

      // Reference present in the allowlist -> accepted and validated.
      final accepted = await verifyPresentation(
        presentation,
        _mockVerify,
        pullVkeyFunction: (reference) async => <String, dynamic>{},
        verifyZkproof: (vkey, publicSignals, proof) async => true,
        trustedVkeys: <String, Set<String>>{
          'balance': <String>{'untrusted-vkey'},
        },
      );
      expect(accepted['valid'], isTrue);
      expect(accepted['zkproofsValidatedAgainstVkey'], isTrue);
    });
  });
}
