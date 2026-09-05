# Contributing to mtls-scanner

Thanks for considering a contribution. This is a small, focused security tool, and
contributions that keep it that way are especially welcome.

## Getting set up

```bash
git clone https://github.com/your-org/mtls-scanner.git
cd mtls-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Before opening a PR

- **Tests pass:** `pytest` (the integration tests spin up the example servers as real
  subprocesses on ephemeral ports — no network access or root privileges required).
- **Lint is clean:** `flake8 mtls_scanner/ examples/`
- **Format with black:** `black mtls_scanner/ examples/ tests/`
- Add or update tests for any behavioral change. New checks especially need an integration
  test proving both the vulnerable and secure example servers produce the expected verdict —
  see `tests/test_scanner_integration.py`.

## Adding a new check

1. Add a certificate-generation method to `CertificateTestSet` in `mtls_scanner/certs.py` if
   the check needs a new kind of defective certificate.
2. Add a `check_*` method to `MTLSScanner` in `mtls_scanner/scanner.py`, following the existing
   pattern: build/obtain the test certificate, call `self._handshake(...)`, and pass the result
   to `self._verdict(...)` with clear `vuln_detail`/`secure_detail`/`remediation` text.
3. Add the method name to `MTLSScanner.DEFAULT_CHECKS`.
4. Document it in `docs/CHECKS.md` following the existing structure (what it does, why it
   matters, what VULNERABLE proves, common root causes, fix, severity rationale).
5. Add an integration test asserting the check's verdict against both example servers.

## Reporting a bug

Please include: the command you ran, the target's TLS stack if known (nginx/Envoy/HAProxy/
custom/etc — not the target's hostname), and the full report output (`--format json` is most
useful). If the bug is a security issue in the scanner itself (not a finding it reports about
a target), please see below instead of opening a public issue.

## Security issues in this tool itself

If you find a bug in mtls-scanner that could cause it to *misreport* a target's security
posture (false negative especially), please open an issue — this is exactly the kind of
correctness bug we care most about fixing quickly, since people may use this tool's output to
sign off on a deployment.

## Code style

- Standard library `ssl`/`socket` for anything the scanner does against a *target* — this
  keeps the tool's own network behavior easy to audit line by line.
- `cryptography` for certificate generation (already a dependency).
- Type hints on public functions/methods; `from __future__ import annotations` at the top of
  new modules.
- Prefer explicit, narrow exception handling over broad `except Exception` outside of the
  top-level check-runner loop in `scanner.py` (which intentionally isolates one check's failure
  from the rest of the scan).
