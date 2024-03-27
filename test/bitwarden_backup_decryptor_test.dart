// CLI tool to decrypt backup files exported from Bitwarden
// Copyright (C) 2024 Wu Tingfeng <wutingfeng@outlook.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:bitwarden_backup_decryptor/bitwarden_backup_decryptor.dart';
import 'package:bitwarden_backup_decryptor/src/create_test_vault.dart' as ctv;
import 'package:bitwarden_backup_decryptor/src/crypto.dart';
import 'package:mocktail/mocktail.dart';
import 'package:test/test.dart';

class MockStdin extends Mock implements Stdin {}

final Matcher throwsIncorrectPasswordException =
    throwsA(isA<IncorrectPasswordException>());

final Matcher throwsFileSystemException = throwsA(isA<FileSystemException>());

final Matcher throwsTypeError = throwsA(isA<TypeError>());

void main() {
  group('getPass', () {
    test('Captures passphrase correctly', () {
      final MockStdin stdin = MockStdin();

      when(() => stdin.readLineSync(encoding: utf8))
          .thenReturn(ctv.testPassphrase);
      when(() => stdin.echoMode).thenReturn(false);

      IOOverrides.runZoned(
        () {
          expect(getPass(), ctv.testPassphrase);
        },
        stdin: () => stdin,
      );
    });
  }, timeout: Timeout(Duration(seconds: 30)));

  group('getVault', () {
    test('Parses vault correctly', () {
      expect(getVault([ctv.testEncryptedVaultFileName['PBKDF2']!['default']!]),
          ctv.testEncryptedVault['PBKDF2']!['default']!);
      expect(() => getVault([]), throwsArgumentError); // args too short
      expect(
          () => getVault([
                ctv.testEncryptedVaultFileName['PBKDF2']!['default']!,
                ctv.testEncryptedVaultFileName['PBKDF2']!['default']!
              ]),
          throwsArgumentError); // args too long
    });
    test('Rejects invalid file path', () {
      expect(() => getVault(['']), throwsFileSystemException);
    });
    test('Rejects invalid JSON file', () {
      expect(() => getVault(['test/bitwarden_backup_decryptor_test.dart']),
          throwsFormatException);
    });
  }, timeout: Timeout(Duration(seconds: 30)));

  group('decryptVault', () {
    for (final String strength in ['default', 'maximum']) {
      test('Correct password -> Decryption success | KDF settings: $strength',
          () {
        expect(
            decryptVault(ctv.testEncryptedVault['PBKDF2']![strength]!,
                ctv.testPassphrase),
            ctv.testPlainTextVault);
        expect(
            decryptVault(ctv.testEncryptedVault['Argon2id']![strength]!,
                ctv.testPassphrase),
            ctv.testPlainTextVault);
      }, tags: strength);

      test('Wrong password -> Decryption failure | KDF settings: $strength',
          () {
        for (final String wrongPassphrase in ['', '${ctv.testPassphrase}A']) {
          expect(
              () => decryptVault(ctv.testEncryptedVault['PBKDF2']![strength]!,
                  wrongPassphrase),
              throwsIncorrectPasswordException);
          expect(
              () => decryptVault(ctv.testEncryptedVault['Argon2id']![strength]!,
                  wrongPassphrase),
              throwsIncorrectPasswordException);
        }
      }, tags: strength);
    }
    test('Wrong vault format -> Decryption failure', () {
      expect(() => decryptVault(jsonDecode(''), ''), throwsFormatException);
      expect(
          () => decryptVault(
              jsonDecode('{"salt":"","kdfType":1,"kdfIterations":1,'
                  '"kdfMemory":1,"kdfParallelism":1,'
                  '"encKeyValidation_DO_NOT_EDIT":""}'),
              ''),
          throwsFormatException);
      expect(
          () => decryptVault(
              jsonDecode('{"salt":null,"kdfType":null,"kdfIterations":null,'
                  '"kdfMemory":null,"kdfParallelism":null}'),
              ''),
          throwsTypeError);
      expect(
          () => decryptVault(
              jsonDecode('{"salt":"","kdfType":999,"kdfIterations":1,'
                  '"kdfMemory":1,"kdfParallelism":1}'),
              ''),
          throwsArgumentError);
    });
  }, timeout: Timeout(Duration(minutes: 15)));

  group('createTestVault', () {
    for (final String strength in ['default', 'maximum']) {
      test('Encrypts correctly | KDF settings: $strength', () {
        expect(jsonDecode(ctv.createTestVault(0, strength)),
            ctv.testEncryptedVault['PBKDF2']![strength]!);
        expect(jsonDecode(ctv.createTestVault(1, strength)),
            ctv.testEncryptedVault['Argon2id']![strength]!);

        expect(
            () => ctv.createTestVault(1, 'notAStrength'), throwsArgumentError);
        expect(() => ctv.createTestVault(2, strength), throwsArgumentError);
      }, tags: strength);
    }
  }, timeout: Timeout(Duration(minutes: 15)));

  group('aesCbc', () {
    test('Reject arguments with invalid lengths', () {
      expect(() => aesCbc(Uint8List(0), Uint8List(0), Uint8List(0), true),
          throwsArgumentError);
      expect(() => aesCbc(Uint8List(16), Uint8List(0), Uint8List(0), true),
          throwsArgumentError);
      expect(() => aesCbc(Uint8List(16), Uint8List(16), Uint8List(17), true),
          throwsArgumentError);
      expect(aesCbc(Uint8List(16), Uint8List(16), Uint8List(16), true),
          base64Url.decode('ZulL1O-KLDuITPpZyjQrLg=='));
    });
  }, timeout: Timeout(Duration(seconds: 30)));
}
