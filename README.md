# Bitwarden Backup Decryptor

[![Dart](https://img.shields.io/badge/Dart-0175C2?style=for-the-badge&logo=dart&logoColor=white)](https://dart.dev)
[![Coveralls](https://img.shields.io/coverallsCoverage/github/elliotwutingfeng/bitwarden_backup_decryptor?logo=coveralls&style=for-the-badge)](https://coveralls.io/github/elliotwutingfeng/bitwarden_backup_decryptor?branch=main)
[![LICENSE](https://img.shields.io/badge/LICENSE-GPLv3-GREEN?style=for-the-badge)](LICENSE)

CLI tool to decrypt backup files exported from [Bitwarden](https://bitwarden.com).

This application is not affiliated with Bitwarden, Inc.

**Note:** Bitwarden provides two [encrypted export types](https://bitwarden.com/help/encrypted-export), _account restricted exports_ and _password protected exports_. This tool can only decrypt _password protected exports_.

## Requirements

- **Dart:** 3.2.6+
- **OS:** Either Windows, macOS, or Linux

## Install dependencies

```bash
dart pub get
```

## Example

**File:** `test/encrypted_test_argon2id.json`

**Password:** `passphrase`

```bash
# Enter the above password when prompted
dart run lib/bitwarden_backup_decryptor.dart test/encrypted_test_argon2id.json
```

You should get the following plaintext output.

```json
{
  "encrypted": false,
  "folders": [],
  "items": []
}
```

## Testing

```bash
# Install dependencies
dart pub get

# Run tests and compute test coverage
dart test --coverage "coverage"

# Generate `.lcov` report from `coverage` folder
dart run coverage:format_coverage --lcov --in coverage --out coverage.lcov --report-on lib

# Generate HTML code coverage report from `.lcov` report
# Note: On macOS/Linux you need to have `lcov` installed on your system
genhtml coverage.lcov -o coverage/html
```
