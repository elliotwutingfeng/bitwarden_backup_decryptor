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
String getPass({String prompt = ''}) {
  stderr.write(prompt);
  final bool echoMode = stdin.echoMode;
  stdin.echoMode = false;
  final String passphrase = stdin.readLineSync(encoding: utf8) ?? '';
  stdin.echoMode = echoMode;
  stderr.writeln();
  return passphrase;
}

/// Read encrypted vault content from user prompt.
Map<String, dynamic> getVault(List<String> args) {
  if (args.length != 1) {
    throw ArgumentError(
        'Usage: ${Platform.script.pathSegments.last} <filename>');
  }
  final String filePath = args[0];
  late String vaultContent;
  try {
    vaultContent = File(filePath).readAsStringSync(encoding: utf8);
  } on FileSystemException catch (e) {
    throw FileSystemException('${e.message}: ${e.path}');
  }
  late Map<String, dynamic> vault;
  try {
    vault = jsonDecode(vaultContent);
  } on FormatException {
    throw FormatException('Failed to parse JSON file. Invalid JSON?');
  }
  return vault;
}

void _terminate(String message) {
  stderr.writeln(message);
  exit(1);
}

void main(List<String> args) {
  try {
    final Map<String, dynamic> vault = getVault(args);
    final String passphrase =
        getPass(prompt: 'Enter Bitwarden encrypted backup password: ');
    stdout.write(decryptVault(vault, passphrase));
  } on FormatException catch (e) {
    _terminate(e.message);
  } on IncorrectPasswordException catch (e) {
    _terminate(e.message);
  } on FileSystemException catch (e) {
    _terminate(e.message);
  } on ArgumentError catch (e) {
    _terminate(e.message);
  }
}
