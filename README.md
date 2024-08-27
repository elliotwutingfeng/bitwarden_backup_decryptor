# Bitwarden Backup Decryptor

[![Dart](https://img.shields.io/badge/Dart-0175C2?style=for-the-badge&logo=dart&logoColor=white)](https://dart.dev)
[![Coveralls](https://img.shields.io/coverallsCoverage/github/elliotwutingfeng/bitwarden_backup_decryptor?logo=coveralls&style=for-the-badge)](https://coveralls.io/github/elliotwutingfeng/bitwarden_backup_decryptor?branch=main)
[![LICENSE](https://img.shields.io/badge/LICENSE-GPLv3-GREEN?style=for-the-badge)](LICENSE)

CLI tool to decrypt backup files exported from [Bitwarden](https://bitwarden.com).

This application is not affiliated with Bitwarden, Inc.

**Note:** Bitwarden provides two [encrypted export types](https://bitwarden.com/help/encrypted-export), _account restricted exports_ and _password protected exports_. This tool can only decrypt _password protected exports_.

## Requirements

- **Minimum Dart SDK:** 3.5.0
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
  "folders": [
    {
      "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "My Folder"
    }
  ],
  "items": [
    {
      "passwordHistory": [
          {
            "lastUsedDate": "YYYY-MM-00T00:00:00.000Z",
            "password": "passwordValue"
          }
      ],
      "revisionDate": "YYYY-MM-00T00:00:00.000Z",
      "creationDate": "YYYY-MM-00T00:00:00.000Z",
      "deletedDate": null,
      "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa",
      "organizationId": null,
      "folderId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "type": 2,
      "name": "My Secure Note",
      "notes": "1st line of secure note\n2nd line of secure note\n3rd line of secure note",
      "favorite": false,
      "fields": [
        {
          "name": "Text Field",
          "value": "text-field-value",
          "type": 0
        },
        {
          "name": "Hidden Field",
          "value": "hidden-field-value",
          "type": 1
        },
        {
          "name": "Boolean Field",
          "value": "false",
          "type": 2
        }
      ],
      "secureNote": {
        "type": 0
      },
      "collectionIds": [
        null
      ]
    },
    {
      "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "organizationId": null,
      "folderId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "type": 3,
      "name": "Card Name",
      "notes": "1st line of note text\n2nd line of note text",
      "favorite": false,
      "fields": [
        {
          "name": "Text Field",
          "value": "text-field-value",
          "type": 0
        },
        {
          "name": "Hidden Field",
          "value": "hidden-field-value",
          "type": 1
        },
        {
          "name": "Boolean Field",
          "value": "false",
          "type": 2
        }
      ],
      "card": {
        "cardholderName": "Jane Doe",
        "brand": "Visa",
        "number": "1234567891011121",
        "expMonth": "10",
        "expYear": "2021",
        "code": "123"
      },
      "collectionIds": [
        null
      ]
    },
    {
      "id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
      "organizationId": null,
      "folderId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "type": 4,
      "name": "My Identity",
      "notes": "1st line of a note\n2nd line of a note",
      "favorite": false,
      "fields": [
        {
          "name": "Text Field",
          "value": "text-field-value",
          "type": 0
        },
        {
          "name": "Hidden Field",
          "value": "hidden-field-value",
          "type": 1
        },
        {
          "name": "Boolean Field",
          "value": "true",
          "type": 2
        }
      ],
      "identity": {
        "title": "Mrs",
        "firstName": "Jane",
        "middleName": "A",
        "lastName": "Doe",
        "address1": " 1 North Calle Cesar Chavez ",
        "address2": null,
        "address3": null,
        "city": "Santa Barbara",
        "state": "CA",
        "postalCode": "93103",
        "country": "United States ",
        "company": "My Employer",
        "email": "myemail@gmail.com",
        "phone": "123-123-1234",
        "ssn": "123-12-1234",
        "username": "myusername",
        "passportNumber": "123456789",
        "licenseNumber": "123456789"
      },
      "collectionIds": [
        null
      ]
    },
    {
      "id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
      "organizationId": null,
      "folderId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "type": 1,
      "name": "Login Name",
      "notes": "1st line of note text\n2nd Line of note text",
      "favorite": false,
      "fields": [
        {
          "name": "Text Field",
          "value": "text-field-valie",
          "type": 0
        },
        {
          "name": "Hidden Field",
          "value": "hidden-field-value",
          "type": 1
        },
        {
          "name": "Boolean Field",
          "value": "true",
          "type": 2
        }
      ],
      "login": {
        "uris": [
          {
            "match": null,
            "uri": "https://mail.google.com"
          }
        ],
        "username": "myusername@gmail.com",
        "password": "mypassword",
        "totp": "otpauth://totp/my-secret-key"
      },
      "collectionIds": [
        null
      ]
    }
  ]
}
```

## Testing

Tested on individual vaults as of Bitwarden Version 2024.8.1

### Default KDF settings

Either run

```bash
make tests_default
```

or

```bash
# Install dependencies
dart pub get

# Run tests using default KDF settings and compute test coverage
dart test --exclude-tags maximum --coverage "coverage"

# Generate `.lcov` report from `coverage` folder
dart run coverage:format_coverage --lcov --check-ignore --in coverage --out coverage.lcov --report-on lib

# Generate HTML code coverage report from `.lcov` report
# Note: On macOS/Linux you need to have `lcov` installed on your system
genhtml coverage.lcov -o coverage/html
```

### Maximum KDF settings

**Warning:** The following command uses the most resource-intensive KDF settings supported by Bitwarden and will take a long time to run.

**Recommended System Requirements:** 8-Core CPU and at least 8 GB available RAM.

```bash
make tests_maximum
```

### Further reading

- <https://bitwarden.com/help/export-your-data>
- <https://bitwarden.com/help/encrypted-export>
- <https://bitwarden.com/help/what-encryption-is-used>
