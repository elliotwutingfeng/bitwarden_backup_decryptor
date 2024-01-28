generate_test_files:
	dart run lib/src/create_test_vault.dart 0 > test/encrypted_test_pbkdf2.json
	dart run lib/src/create_test_vault.dart 1 > test/encrypted_test_argon2id.json

tests:
	dart pub get
	dart format --output none --set-exit-if-changed .
	dart analyze
	dart test --coverage "coverage"
	dart run coverage:format_coverage --lcov --in coverage --out coverage.lcov --report-on lib
