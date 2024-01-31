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
String _getPass({String prompt = ''}) {
  stderr.write(prompt);
  final bool echoMode = stdin.echoMode;
  stdin.echoMode = false;
  final String passphrase = stdin.readLineSync(encoding: utf8) ?? '';
  stdin.echoMode = echoMode;
  stderr.writeln();
  return passphrase;
}

/// Read encrypted vault content and read passphrase from user prompt.
Future<(String vaultContent, String passphrase, bool validArgs)> getInput(
    List<String> args) async {
  if (args.length != 1) {
    return ('', '', false);
  }
  final String filePath = args[0];
  final String vaultContent = await File(filePath).readAsString(encoding: utf8);
  final String passphrase =
      _getPass(prompt: 'Enter Bitwarden encrypted backup password: ');

  return (vaultContent, passphrase, true);
}

void main(List<String> args) async {
  final (String vaultContent, String passphrase, bool validArgs) =
      await getInput(args);
  if (!validArgs) {
    stderr.writeln('Usage: bitwarden_backup_decryptor.dart <filename>');
    exit(1);
  }
  stdout.write(decryptVault(vaultContent, passphrase));
}
