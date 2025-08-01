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
import 'dart:typed_data';

import 'package:bitwarden_backup_decryptor/src/crypto.dart';

class IncorrectPasswordException implements Exception {
  final String message;
  const IncorrectPasswordException(this.message);
}

/// Decrypt a Bitwarden [encrypted] string, given an encryption key [encKey] and
/// MAC key [macKey].
String _decrypt(
  final String encrypted,
  final Uint8List encKey,
  final Uint8List macKey,
) {
  final List<String> params = encrypted.split('|');
  if (params.length != 3 ||
      params[0].length < 3 ||
      params[0].substring(0, 2) != '2.') {
    throw FormatException('Invalid vault format');
  }
  final Uint8List iv = base64.decode(params[0].substring(2));
  final Uint8List vault = base64.decode(params[1]);
  final Uint8List mac = base64.decode(params[2]);

  final Uint8List b =
      (BytesBuilder()
            ..add(iv)
            ..add(vault))
          .toBytes();
  final Uint8List finalMac = hmacSHA256Digest(macKey, b);
  if (!listEquals(mac, finalMac)) {
    throw IncorrectPasswordException('Password incorrect');
  }

  final Uint8List decryptor = aesCbc(encKey, iv, vault, false);
  final Uint8List unpadder = unpad(decryptor);
  return utf8.decode(unpadder);
}

/// Decrypt [vault] with [passphrase] and return result as plaintext.
String decryptVault(final Map<String, dynamic> vault, final String passphrase) {
  final (Uint8List encKey, Uint8List macKey) = getEncAndMacKeys(
    passphrase,
    vault['salt'] as String,
    vault['kdfType'] as int,
    vault['kdfIterations'] as int,
    vault['kdfMemory'] as int?,
    vault['kdfParallelism'] as int?,
  );

  _decrypt(
    vault['encKeyValidation_DO_NOT_EDIT'] as String,
    encKey,
    macKey,
  ); // throws exception if invalid
  final String plainTextVault = _decrypt(
    vault['data'] as String,
    encKey,
    macKey,
  );
  return plainTextVault;
}
