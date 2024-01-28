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

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/argon2.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/paddings/pkcs7.dart';

Uint8List hmacSHA256Digest(Uint8List key, Uint8List data) =>
    (HMac(SHA256Digest(), 64)..init(KeyParameter(key))).process(data);

/// Reference: https://en.wikipedia.org/wiki/HKDF
Uint8List hkdfExpand(Uint8List key, Uint8List info, int length) {
  Uint8List t = Uint8List(0);
  Uint8List okm = Uint8List(0);
  int i = 0;

  while (okm.length < length) {
    i++;
    final Uint8List input = Uint8List.fromList([...t, ...info, i]);
    t = hmacSHA256Digest(key, input);
    okm = Uint8List.fromList([...okm, ...t]);
  }

  return okm.sublist(0, length);
}

(Uint8List encKey, Uint8List macKey) getEncAndMacKeys(
  String passphrase,
  String passphraseSalt,
  int kdfType,
  int kdfIterations,
  int? kdfMemory,
  int? kdfParallelism,
) {
  final Uint8List salt = utf8.encode(passphraseSalt);

  late Uint8List key;
  if (kdfType == 0) {
    key = (PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
          ..init(Pbkdf2Parameters(salt, kdfIterations, 32)))
        .process(utf8.encode(passphrase));
  } else if (kdfType == 1) {
    key = (Argon2BytesGenerator()
          ..init(Argon2Parameters(
              Argon2Parameters.ARGON2_id, SHA256Digest().process(salt),
              desiredKeyLength: 32,
              iterations: kdfIterations,
              memory: (kdfMemory ?? 64) * 1024,
              lanes: kdfParallelism ?? 4)))
        .process(utf8.encode(passphrase));
  } else {
    throw ArgumentError('ERROR: unknown KDF!');
  }

  final Uint8List encKey = hkdfExpand(key, utf8.encode('enc'), 32);
  final Uint8List macKey = hkdfExpand(key, utf8.encode('mac'), 32);

  return (encKey, macKey);
}

/// PKCS7 padding before AES-CBC encryption.
Uint8List pad(Uint8List bytes, int blockSizeBytes) {
  final int padLength = blockSizeBytes - (bytes.length % blockSizeBytes);
  final Uint8List padded = Uint8List(bytes.length + padLength)
    ..setAll(0, bytes);
  PKCS7Padding().addPadding(padded, bytes.length);
  return padded;
}

/// PKCS7 unpadding after AES-CBC decryption.
Uint8List unpad(Uint8List bytes) {
  final int padLength = (PKCS7Padding()..init(null)).padCount(bytes);
  final int len = bytes.length - padLength;
  return Uint8List(len)..setRange(0, len, bytes);
}

/// Encrypts/Decrypts [sourceText] with symmetric [key] and initialization
/// vector [iv].
///
/// To encrypt, set [encrypt] to true. To decrypt, set [encrypt] to false.
Uint8List aesCbc(
    Uint8List key, Uint8List iv, Uint8List sourceText, bool encrypt) {
  assert([16, 24, 32].contains(key.length));
  assert(iv.length == 16);
  assert(sourceText.length % 16 == 0);
  final CBCBlockCipher cbc = CBCBlockCipher(AESEngine())
    ..init(encrypt, ParametersWithIV(KeyParameter(key), iv));

  final Uint8List targetText = Uint8List(sourceText.length);

  int offset = 0;
  while (offset < sourceText.length) {
    offset += cbc.processBlock(sourceText, offset, targetText, offset);
  }
  assert(offset == sourceText.length);

  return targetText;
}

/// Compare 2 lists element-by-element.
bool listEquals(List<dynamic> list1, List<dynamic> list2) {
  if (identical(list1, list2)) return true;
  if (list1.length != list2.length) return false;
  for (int i = 0; i < list1.length; i++) {
    if (list1[i] != list2[i]) return false;
  }
  return true;
}
