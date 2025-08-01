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

import 'package:bitwarden_backup_decryptor/src/decrypt_vault.dart';

export 'package:bitwarden_backup_decryptor/src/decrypt_vault.dart';

/// Prompt user for password.
String getPass({final String prompt = ''}) {
  stderr.write(prompt);
  final bool echoMode = stdin.echoMode;
  stdin.echoMode = false;
  final String passphrase = stdin.readLineSync(encoding: utf8) ?? '';
  stdin.echoMode = echoMode;
  stderr.writeln();
  return passphrase;
}

/// Read encrypted vault content from user prompt.
Map<String, dynamic> getVault(final List<String> args) {
  if (args.length != 1) {
    throw ArgumentError(
      'Usage: ${Platform.script.pathSegments.last} <filename>',
    );
  }
  final String filePath = args[0];
  late String vaultContent;
  try {
    vaultContent = File(filePath).readAsStringSync();
  } on FileSystemException catch (e) {
    throw FileSystemException('${e.message}: ${e.path}');
  }
  late Map<String, dynamic> vault;
  try {
    vault = jsonDecode(vaultContent) as Map<String, dynamic>;
  } on FormatException {
    throw FormatException('Failed to parse JSON file. Invalid JSON?');
  }
  final String passphraseSalt = // ignore: unused_local_variable
      vault['salt'] as String;
  final int kdfType = vault['kdfType'] as int; // ignore: unused_local_variable
  final int kdfIterations = // ignore: unused_local_variable
      vault['kdfIterations'] as int;
  final int? kdfMemory = // ignore: unused_local_variable
      vault['kdfMemory'] as int?;
  final int? kdfParallelism = // ignore: unused_local_variable
      vault['kdfParallelism'] as int?;
  final String encKeyValidation = // ignore: unused_local_variable
      vault['encKeyValidation_DO_NOT_EDIT'] as String;
  final String data = vault['data'] as String; // ignore: unused_local_variable

  return vault;
}

// coverage:ignore-start
void _terminate(final String message) {
  stderr.writeln(message);
  exit(1);
}

void main(final List<String> args) {
  try {
    final Map<String, dynamic> vault = getVault(args);
    final String passphrase = getPass(
      prompt: 'Enter Bitwarden encrypted backup password: ',
    );
    stdout.write(decryptVault(vault, passphrase));
  } on FormatException catch (e) {
    _terminate(e.message);
  } on IncorrectPasswordException catch (e) {
    _terminate(e.message);
  } on FileSystemException catch (e) {
    _terminate(e.message);
  } on ArgumentError catch (e) {
    _terminate(e.message as String);
  } on TypeError catch (e) {
    _terminate(e.toString());
  }
}

// coverage:ignore-end
