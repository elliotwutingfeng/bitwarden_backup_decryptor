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

import 'dart:io';

import 'package:bitwarden_backup_decryptor/src/decrypt_vault.dart';

export 'package:bitwarden_backup_decryptor/src/decrypt_vault.dart';

/// Prompt user for password.
String _getPass({String prompt = ''}) {
  stderr.write(prompt);
  final bool echoMode = stdin.echoMode;
  stdin.echoMode = false;
  final String passphrase = stdin.readLineSync() ?? '';
  stdin.echoMode = echoMode;
  stderr.write('\n');
  return passphrase;
}

/// Read encrypted vault content and read passphrase from user prompt.
Future<(String vaultContent, String passphrase)> getInput(
    List<String> args) async {
  if (args.length != 1) {
    throw ArgumentError('Usage: bitwarden_backup_decryptor.dart <filename>\n');
  }
  final String filePath = args[0];
  final String vaultContent = await File(filePath).readAsString();
  final String passphrase =
      _getPass(prompt: 'Enter Bitwarden encrypted backup password: ');

  return (vaultContent, passphrase);
}

void main(List<String> args) async {
  final (String vaultContent, String passphrase) = await getInput(args);
  stdout.write(decryptVault(vaultContent, passphrase));
}
