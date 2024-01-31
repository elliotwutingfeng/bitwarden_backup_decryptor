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
  final String pbkdf2VaultContent =
      File(ctv.testPbkdf2VaultFileName).readAsStringSync(encoding: utf8);
  final String argon2idVaultContent =
      File(ctv.testArgon2idVaultFileName).readAsStringSync(encoding: utf8);

  group('getInput', () {
    test('Captures input correctly', () {
      final MockStdin stdin = MockStdin();

      when(() => stdin.readLineSync(encoding: utf8))
          .thenReturn(ctv.testPassphrase);
      when(() => stdin.echoMode).thenReturn(true);

      IOOverrides.runZoned(
        () {
          expect(getInput([ctv.testPbkdf2VaultFileName]),
              (pbkdf2VaultContent, ctv.testPassphrase));

          expect(
              () => getInput(
                  [ctv.testPbkdf2VaultFileName, ctv.testPbkdf2VaultFileName]),
              throwsArgumentError);
        },
        stdin: () => stdin,
      );
    });
    test('Rejects invalid file path', () {
      expect(() => getInput(['']), throwsFileSystemException);
    });
  }, timeout: Timeout(Duration(seconds: 10)));

  group('decryptVault', () {
    test('Correct password -> Decryption success', () {
      expect(decryptVault(pbkdf2VaultContent, ctv.testPassphrase),
          ctv.testVaultBody);
      expect(decryptVault(argon2idVaultContent, ctv.testPassphrase),
          ctv.testVaultBody);
    });
    test('Wrong password -> Decryption failure', () {
      expect(() => decryptVault(pbkdf2VaultContent, ''),
          throwsIncorrectPasswordException);
      expect(() => decryptVault(argon2idVaultContent, ''),
          throwsIncorrectPasswordException);

      expect(() => decryptVault(pbkdf2VaultContent, '${ctv.testPassphrase}A'),
          throwsIncorrectPasswordException);
      expect(() => decryptVault(argon2idVaultContent, '${ctv.testPassphrase}A'),
          throwsIncorrectPasswordException);
    });
    test('Wrong vault format -> Decryption failure', () {
      expect(() => decryptVault('', ''), throwsFormatException);
    });
  }, timeout: Timeout(Duration(seconds: 300)));

  group('createTestVault', () {
    test('Encrypts correctly', () {
      expect(
          jsonDecode(ctv.createTestVault(0)), jsonDecode(pbkdf2VaultContent));
      expect(
          jsonDecode(ctv.createTestVault(1)), jsonDecode(argon2idVaultContent));
      expect(() => ctv.createTestVault(2), throwsArgumentError);
    });
  }, timeout: Timeout(Duration(seconds: 300)));
}
