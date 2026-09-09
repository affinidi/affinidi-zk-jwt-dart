import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zk_jwt/src/core.dart';
import 'package:zk_jwt/src/hash.dart';

void main() {
  group('base64url', () {
    test('round-trips arbitrary bytes without padding', () {
      final bytes = Uint8List.fromList(<int>[0, 1, 2, 250, 251, 252, 253]);
      final encoded = base64urlEncode(bytes);

      expect(encoded, isNot(contains('=')));
      expect(encoded, isNot(contains('+')));
      expect(encoded, isNot(contains('/')));
      expect(base64urlDecode(encoded), equals(bytes));
    });

    test('decodes strings that are missing padding', () {
      final encoded = base64urlEncode(Uint8List.fromList(utf8.encode('hi')));
      expect(utf8.decode(base64urlDecode(encoded)), equals('hi'));
    });
  });

  group('stringToBits', () {
    test('emits 8 least-significant-first bits per byte', () {
      // 'A' == 0x41 == 0100 0001 -> LSB first: 1,0,0,0,0,0,1,0
      expect(stringToBits('A'), equals(<int>[1, 0, 0, 0, 0, 0, 1, 0]));
    });

    test('length is a multiple of 8', () {
      expect(stringToBits('hello').length, equals(5 * 8));
    });
  });

  group('generateSalt', () {
    test('produces base64url output of the requested byte length', () {
      final salt = generateSalt();
      expect(base64urlDecode(salt).length, equals(16));
    });

    test('honours a custom length', () {
      expect(base64urlDecode(generateSalt(length: 32)).length, equals(32));
    });

    test('is random across invocations', () {
      expect(generateSalt(), isNot(equals(generateSalt())));
    });
  });

  group('disclosure encode/decode', () {
    test('round-trips a named claim', () {
      final disclosure = createDisclosure('salt123', 'age', 28);
      final decoded = decodeDisclosure(disclosure);

      expect(decoded['salt'], equals('salt123'));
      expect(decoded['name'], equals('age'));
      expect(decoded['value'], equals(28));
    });

    test('round-trips an unnamed (array element) claim', () {
      final disclosure = createDisclosure('salt123', null, 'value');
      final decoded = decodeDisclosure(disclosure);

      expect(decoded['salt'], equals('salt123'));
      expect(decoded.containsKey('name'), isFalse);
      expect(decoded['value'], equals('value'));
    });

    test('rejects a malformed disclosure', () {
      final malformed = base64urlEncode(
        Uint8List.fromList(utf8.encode(jsonEncode(<int>[1]))),
      );
      expect(() => decodeDisclosure(malformed), throwsFormatException);
    });
  });

  group('valueToFieldElement', () {
    test('maps integers and BigInt directly', () {
      expect(valueToFieldElement(42), equals(BigInt.from(42)));
      expect(valueToFieldElement(BigInt.from(7)), equals(BigInt.from(7)));
    });

    test('maps booleans to 0/1', () {
      expect(valueToFieldElement(true), equals(BigInt.one));
      expect(valueToFieldElement(false), equals(BigInt.zero));
    });

    test('maps null to zero', () {
      expect(valueToFieldElement(null), equals(BigInt.zero));
    });

    test('parses numeric strings as integers', () {
      expect(valueToFieldElement('123'), equals(BigInt.from(123)));
    });

    test('hashes non-numeric strings deterministically', () {
      expect(valueToFieldElement('USA'), equals(valueToFieldElement('USA')));
      expect(
        valueToFieldElement('USA'),
        isNot(equals(valueToFieldElement('CAN'))),
      );
    });

    test('hashes maps and lists via their canonical JSON encoding', () {
      expect(
        valueToFieldElement(<String, dynamic>{'a': 1}),
        equals(valueToFieldElement(<String, dynamic>{'a': 1})),
      );
      expect(
        valueToFieldElement(<int>[1, 2, 3]),
        equals(valueToFieldElement(<int>[1, 2, 3])),
      );
    });

    test('reduces negative integers into the field [0, p)', () {
      final prime = BigInt.parse(
        '21888242871839275222246405745257275088548364400416034343698204186575808495617',
      );
      final reduced = valueToFieldElement(-1);
      expect(reduced, equals(prime - BigInt.one));
      expect(reduced.sign, isNot(-1));
      expect(reduced, greaterThanOrEqualTo(BigInt.zero));
      expect(reduced, lessThan(prime));
    });

    test('reduces negative numeric strings into the field', () {
      expect(valueToFieldElement('-1'), equals(valueToFieldElement(-1)));
    });

    test('always returns a value within the field for hashed strings', () {
      final prime = BigInt.parse(
        '21888242871839275222246405745257275088548364400416034343698204186575808495617',
      );
      final reduced = valueToFieldElement('a-long-non-numeric-claim-value');
      expect(reduced, greaterThanOrEqualTo(BigInt.zero));
      expect(reduced, lessThan(prime));
    });
  });

  group('fieldReduce', () {
    test('leaves small values unchanged', () {
      expect(fieldReduce(BigInt.from(5)), equals(BigInt.from(5)));
    });

    test('reduces values at or above the field prime', () {
      final prime = BigInt.parse(
        '21888242871839275222246405745257275088548364400416034343698204186575808495617',
      );
      expect(fieldReduce(prime), equals(BigInt.zero));
      expect(fieldReduce(prime + BigInt.one), equals(BigInt.one));
    });
  });

  group('hashClaimName', () {
    test('is deterministic and distinct per name', () {
      expect(hashClaimName('email'), equals(hashClaimName('email')));
      expect(hashClaimName('email'), isNot(equals(hashClaimName('name'))));
    });
  });

  group('saltToFieldElement', () {
    test('accepts base64url strings and raw bytes equivalently', () {
      final bytes = Uint8List.fromList(<int>[1, 2, 3, 4]);
      final asString = base64urlEncode(bytes);

      expect(saltToFieldElement(asString), equals(saltToFieldElement(bytes)));
    });

    test('rejects unsupported types', () {
      expect(() => saltToFieldElement(42), throwsArgumentError);
    });
  });

  group('prepareCircuitInputs', () {
    test('returns decimal string inputs for the circuit', () async {
      final inputs = await prepareCircuitInputs('balance', generateSalt(), 100);

      expect(inputs['value'], equals('100'));
      expect(BigInt.tryParse(inputs['claimNameDigest']!), isNotNull);
      expect(BigInt.tryParse(inputs['salt']!), isNotNull);
    });

    test('field-reduces claimNameDigest to match the verifier', () async {
      // The verifier compares against fieldReduce(hashClaimName(...)), and most
      // real claim names exceed the BN254 prime, so the digest must be reduced.
      const claimName = 'balance';
      final inputs = await prepareCircuitInputs(claimName, generateSalt(), 100);

      final expected = fieldReduce(hashClaimName(claimName));
      expect(inputs['claimNameDigest'], equals(expected.toString()));
      // Sanity: the raw (unreduced) hash differs for names that exceed p.
      expect(inputs['claimNameDigest'], isNot(hashClaimName(claimName)));
    });

    test('emits claimNameDigest within the field [0, p)', () async {
      final prime = BigInt.parse(
        '21888242871839275222246405745257275088548364400416034343698204186575808495617',
      );
      final inputs = await prepareCircuitInputs('email', generateSalt(), 1);
      final digest = BigInt.parse(inputs['claimNameDigest']!);
      expect(digest, greaterThanOrEqualTo(BigInt.zero));
      expect(digest, lessThan(prime));
    });
  });
}
