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

import 'package:bitwarden_backup_decryptor/src/crypto.dart';

const String testPassphrase = 'passphrase';
const String testPassphraseSalt = 'rNYWSe/wFO1k+Qxia0A96A==';
const String testEncKeyValidationBody = 'df5d795f-ba0e-545a-625b-17e6cd33e0bd';
const String testEncKeyValidationSalt = 'BCUsoLRgNgqJeJxut3xweg==';
const String testVaultBody = '''{
  "encrypted": false,
  "folders": [],
  "items": []
}''';
const String testVaultSalt = 'ZWJYgGWulXafn/ABTx/Cuw==';
const String testPbkdf2VaultFileName = 'test/encrypted_test_pbkdf2.json';
const String testArgon2idVaultFileName = 'test/encrypted_test_argon2id.json';

/// Encrypt a Bitwarden [plaintext] vault,
/// given an initialization vector [ivB64],
/// an encryption key [encKey] and MAC key [macKey].
String _encrypt(
    String plaintext, String ivB64, Uint8List encKey, Uint8List macKey) {
  final Uint8List iv = base64.decode(ivB64);
  // ignore: unnecessary_cast
  final Uint8List encodedPlaintext = utf8.encode(plaintext) as Uint8List;
  final Uint8List padded = pad(encodedPlaintext, 128 ~/ 8);
  final Uint8List encryptor = aesCbc(encKey, iv, padded, true);

  final Uint8List b = (BytesBuilder()
        ..add(iv)
        ..add(encryptor))
      .toBytes();
  final Uint8List finalMac = hmacSHA256Digest(macKey, b);

  return '2.$ivB64|${base64.encode(encryptor)}|${base64.encode(finalMac)}';
}

/// Create an encrypted cyphertext vault of KDF type [testKdfType].
///
/// testKdfType 0 -> PBKDF2
///
/// testKdfType 1 -> Argon2id
String createTestVault(int testKdfType) {
  if (testKdfType != 0 && testKdfType != 1) {
    throw ArgumentError('`kdfType` must be 0 or 1');
  }
  final int testKdfIterations = (testKdfType == 1) ? 3 : 600000;
  final int? testKdfMemory = (testKdfType == 1) ? 64 : null;
  final int? testKdfParallelism = (testKdfType == 1) ? 4 : null;

  final (Uint8List encKey, Uint8List macKey) = getEncAndMacKeys(
    testPassphrase,
    testPassphraseSalt,
    testKdfType,
    testKdfIterations,
    testKdfMemory,
    testKdfParallelism,
  );

  final String encKeyValidation = _encrypt(
    testEncKeyValidationBody,
    testEncKeyValidationSalt,
    encKey,
    macKey,
  );
  final String data = _encrypt(
    testVaultBody,
    testVaultSalt,
    encKey,
    macKey,
  );

  final String encryptedVault = JsonEncoder.withIndent('  ').convert({
    for (final MapEntry entry in {
      'encrypted': true,
      'passwordProtected': true,
      'salt': testPassphraseSalt,
      'kdfType': testKdfType,
      'kdfIterations': testKdfIterations,
      'kdfMemory': testKdfMemory,
      'kdfParallelism': testKdfParallelism,
      'encKeyValidation_DO_NOT_EDIT': encKeyValidation,
      'data': data,
    }.entries)
      if (entry.value != null) entry.key: entry.value
  });

  return encryptedVault;
}

void main(List<String> args) {
  assert(args.length == 1);
  stdout.write(createTestVault(int.parse(args[0])));
}
