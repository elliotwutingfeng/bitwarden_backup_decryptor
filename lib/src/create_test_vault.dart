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
const String testVaultSalt = 'ZWJYgGWulXafn/ABTx/Cuw==';

// Sample vault JSON retrieved from
// https://bitwarden.com/help/condition-bitwarden-import/#condition-a-json
const String testPlainTextVaultFileName = 'test/individual.json';
final String testPlainTextVault = File(testPlainTextVaultFileName)
    .readAsStringSync(encoding: utf8)
    .replaceAll('\r\n', '\n'); // Windows compatibility

const Map<String, Map<String, String>> testEncryptedVaultFileName = {
  'PBKDF2': {
    'default': 'test/encrypted_test_pbkdf2.json',
    'maximum': 'test/encrypted_test_maximum_pbkdf2.json'
  },
  'Argon2id': {
    'default': 'test/encrypted_test_argon2id.json',
    'maximum': 'test/encrypted_test_maximum_argon2id.json'
  }
};
final Map<String, Map<String, Map<String, dynamic>>> testEncryptedVault = {
  'PBKDF2': {
    'default': jsonDecode(
        File(testEncryptedVaultFileName['PBKDF2']!['default']!)
            .readAsStringSync(encoding: utf8)),
    'maximum': jsonDecode(
        File(testEncryptedVaultFileName['PBKDF2']!['maximum']!)
            .readAsStringSync(encoding: utf8))
  },
  'Argon2id': {
    'default': jsonDecode(
        File(testEncryptedVaultFileName['Argon2id']!['default']!)
            .readAsStringSync(encoding: utf8)),
    'maximum': jsonDecode(
        File(testEncryptedVaultFileName['Argon2id']!['maximum']!)
            .readAsStringSync(encoding: utf8))
  }
};

// KDF settings at default and at maximum levels obtained from
// https://vault.bitwarden.com/#/settings/security/security-keys
const Map testKdfSettings = {
  0: {
    'default': {
      'kdfIterations': 600000,
      'kdfMemory': null,
      'kdfParallelism': null
    },
    'maximum': {
      'kdfIterations': 2000000,
      'kdfMemory': null,
      'kdfParallelism': null
    },
  },
  1: {
    'default': {'kdfIterations': 3, 'kdfMemory': 64, 'kdfParallelism': 4},
    'maximum': {'kdfIterations': 10, 'kdfMemory': 1024, 'kdfParallelism': 16},
  },
};

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

/// Create an encrypted cyphertext vault of KDF type [testKdfType] and
/// KDF settings strength level [testKdfStrength].
///
/// testKdfType 0 -> PBKDF2
///
/// testKdfType 1 -> Argon2id
String createTestVault(int testKdfType, String testKdfStrength) {
  if (testKdfType != 0 && testKdfType != 1) {
    throw ArgumentError('`kdfType` must be 0 or 1');
  }
  if (testKdfStrength != 'default' && testKdfStrength != 'maximum') {
    throw ArgumentError('`kdfStrength` must be default or maximum');
  }

  final Map settings = testKdfSettings[testKdfType][testKdfStrength];
  final int testKdfIterations = settings['kdfIterations'];
  final int? testKdfMemory = settings['kdfMemory'];
  final int? testKdfParallelism = settings['kdfParallelism'];

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
    testPlainTextVault,
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
  assert(args.length == 2);
  stdout.write(createTestVault(int.parse(args[0]), args[1]));
}
