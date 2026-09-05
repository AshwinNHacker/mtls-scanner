# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-08-13

### Added
- Initial release.
- Core checks: self-signed certificate acceptance, untrusted-CA certificate acceptance,
  expired certificate acceptance, not-yet-valid certificate acceptance, wrong Extended Key
  Usage acceptance, weak key size acceptance, legacy TLS version support, and a baseline
  "does this endpoint enforce mTLS at all" check.
- Text (ANSI-colored), JSON, and HTML report formats.
- CLI with single-target, multi-target (`--targets` file), and CI-friendly (`--fail-on`,
  exit codes) modes.
- Bundled example vulnerable/secure mTLS servers for demonstration and integration testing.
- Full test suite (unit + live integration tests against the bundled example servers).
- Post-handshake liveness probe to correctly handle TLS 1.3's asynchronous
  certificate-rejection alert delivery, avoiding false-positive findings against correctly
  configured TLS 1.3 servers.
