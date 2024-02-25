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

import 'package:bitwarden_backup_decryptor/bitwarden_backup_decryptor.dart';
import 'package:bitwarden_backup_decryptor/src/create_test_vault.dart' as ctv;
import 'package:mocktail/mocktail.dart';
import 'package:test/test.dart';

class MockStdin extends Mock implements Stdin {}

final Matcher throwsIncorrectPasswordException =
    throwsA(isA<IncorrectPasswordException>());

final Matcher throwsFileSystemException = throwsA(isA<FileSystemException>());

void main() {
  group('getInput', () {
    test('Captures input correctly', () {
      final MockStdin stdin = MockStdin();

      when(() => stdin.readLineSync(encoding: utf8))
          .thenReturn(ctv.testPassphrase);
      when(() => stdin.echoMode).thenReturn(true);

      IOOverrides.runZoned(
        () {
          expect(
              getInput([ctv.testEncryptedVaultFileName['PBKDF2']!['default']!]),
              (
                ctv.testEncryptedVault['PBKDF2']!['default']!,
                ctv.testPassphrase
              ));
          expect(() => getInput([]), throwsArgumentError); // args too short
          expect(
              () => getInput([
                    ctv.testEncryptedVaultFileName['PBKDF2']!['default']!,
                    ctv.testEncryptedVaultFileName['PBKDF2']!['default']!
                  ]),
              throwsArgumentError); // args too long
        },
        stdin: () => stdin,
      );
    });
    test('Rejects invalid file path', () {
      expect(() => getInput(['']), throwsFileSystemException);
    });
  }, timeout: Timeout(Duration(seconds: 10)));

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
      expect(() => decryptVault('', ''), throwsFormatException);
    });
  }, timeout: Timeout(Duration(minutes: 15)));

  group('createTestVault', () {
    for (final String strength in ['default', 'maximum']) {
      test('Encrypts correctly | KDF settings: $strength', () {
        expect(jsonDecode(ctv.createTestVault(0, strength)),
            jsonDecode(ctv.testEncryptedVault['PBKDF2']![strength]!));
        expect(jsonDecode(ctv.createTestVault(1, strength)),
            jsonDecode(ctv.testEncryptedVault['Argon2id']![strength]!));

        expect(
            () => ctv.createTestVault(1, 'notAStrength'), throwsArgumentError);
        expect(() => ctv.createTestVault(2, strength), throwsArgumentError);
      }, tags: strength);
    }
  }, timeout: Timeout(Duration(minutes: 15)));
}
