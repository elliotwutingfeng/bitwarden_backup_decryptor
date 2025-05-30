# WARNING
#
# Both encrypted_test_maximum_pbkdf2.json and encrypted_test_maximum_argon2id.json
# use the most resource-intensive KDF settings supported by Bitwarden.
#
# Ensure that you have at least 8 GB available RAM before running generate_test_files or tests_maximum.
#
# A fast CPU (at least 8 cores) is also highly recommended.

format:
	dart fix --apply
	dart format .

generate_test_files:
	dart run lib/src/create_test_vault.dart 0 default > test/encrypted_test_pbkdf2.json
	dart run lib/src/create_test_vault.dart 0 maximum > test/encrypted_test_maximum_pbkdf2.json
	dart run lib/src/create_test_vault.dart 1 default > test/encrypted_test_argon2id.json
	dart run lib/src/create_test_vault.dart 1 maximum > test/encrypted_test_maximum_argon2id.json

tests_default:
	dart pub get
	dart format --output none --set-exit-if-changed .
	dart analyze
	dart test --exclude-tags maximum --coverage "coverage"
	dart run coverage:format_coverage --lcov --check-ignore --in coverage --out coverage.lcov --report-on lib

tests_maximum:
	dart pub get
	dart format --output none --set-exit-if-changed .
	dart analyze
	dart test --exclude-tags default --coverage "coverage"
	dart run coverage:format_coverage --lcov --check-ignore --in coverage --out coverage.lcov --report-on lib
