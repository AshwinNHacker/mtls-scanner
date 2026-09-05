# mtls-scanner

**A scanner that finds mTLS endpoints accepting client certificates without proper chain-of-trust validation.**

Mutual TLS (mTLS) is only as strong as the certificate validation behind it. A server that
*requests* a client certificate but fails to properly validate its chain, expiry, issuer, or
key usage effectively has no client authentication at all — while still looking, on the surface,
like a hardened mTLS deployment. `mtls-scanner` connects to a target and presents a series of
deliberately invalid client certificates, then observes whether the handshake succeeds anyway.

```
$ mtls-scanner api.internal.example.com:8443

========================================================================
mTLS Misconfiguration Scan Report
Target : api.internal.example.com:8443
========================================================================

[VULNERABLE] Self-signed client certificate acceptance  (CRITICAL)
  detail : The server completed the TLS handshake and accepted a
           self-signed client certificate...
  fix    : Configure the TLS terminator to validate the full client
           certificate chain against a pinned, trusted CA bundle...

------------------------------------------------------------------------
Checks: 8  |  Vulnerable: 3  |  Secure: 5  |  Inconclusive: 0
RESULT: VULNERABLE (highest severity: CRITICAL)
------------------------------------------------------------------------
```

## Why this matters

mTLS misconfiguration is a recurring, high-impact class of bug that shows up in nginx,
Envoy, HAProxy, Node.js, Java, and hand-rolled TLS termination alike. The pattern is almost
always the same shape:

- A server is configured with `ssl_verify_client optional_no_ca` (nginx) instead of
  `on`/`strict`, which requests a cert but performs no chain validation.
- A custom Java `X509TrustManager` or Go `VerifyPeerCertificate` callback is written for
  debugging, logs a warning on failure, and returns success anyway — and the debug code
  ships to production.
- `rejectUnauthorized: false` (Node.js) is set globally, silently disabling verification for
  both server *and* client certificate checks.
- Client-cert validation is checked against the OS default trust store instead of a
  dedicated, pinned client CA — meaning *any* publicly-trusted certificate (e.g. one issued
  by Let's Encrypt for an unrelated domain) can authenticate as a client.
- Expiry / not-before checks are skipped because a chain-building library short-circuits on
  signature validity alone.

Each of these produces the same externally-observable symptom: **the TLS handshake succeeds
when it shouldn't.** That is exactly what this tool tests for, directly and empirically,
rather than trying to statically infer it from a config file.

## What it checks

| Check | Severity | What it proves when vulnerable |
|---|---|---|
| `self-signed-cert` | CRITICAL | Server accepts a client cert with no CA behind it at all |
| `untrusted-ca-cert` | CRITICAL | Server accepts a cert from a CA it has never been told to trust |
| `expired-cert` | HIGH | Server doesn't enforce certificate expiry |
| `not-yet-valid-cert` | MEDIUM | Server doesn't enforce the certificate's validity start date |
| `wrong-eku-cert` | MEDIUM | Server accepts certs lacking the `clientAuth` Extended Key Usage |
| `weak-key-cert` | LOW | Server accepts a client cert built on a 1024-bit RSA key |
| `legacy-tls-versions` | LOW | Server still negotiates TLS 1.0 / 1.1 |
| `baseline-no-cert` | INFO | Whether the server enforces mTLS at all (context for the rest) |

See [`docs/CHECKS.md`](docs/CHECKS.md) for a detailed writeup of each check, including the
X.509 fields involved and real-world root causes.

**Scope note:** this tool evaluates client-certificate chain validation as observed at the TLS
layer. It does not perform revocation checking (CRL/OCSP) — that generally can't be tested
black-box from outside — and it does not evaluate the target's *own* server certificate. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design rationale, including the
TLS 1.3 post-handshake-alert subtlety this tool specifically accounts for.

## Installation

```bash
pip install -e .
# or, once published:
pip install mtls-scanner
```

Requires Python 3.9+ and the `cryptography` package (installed automatically).

## Usage

```bash
# Basic scan
mtls-scanner api.example.com:8443

# Explicit port flag instead of host:port
mtls-scanner api.example.com -p 8443

# JSON output, written to a file (for CI pipelines / tooling)
mtls-scanner api.example.com:8443 --format json --output report.json

# HTML report
mtls-scanner api.example.com:8443 --format html --output report.html

# Scan a list of targets from a file (one host[:port] per line, # comments allowed)
mtls-scanner --targets targets.txt --format json --output results.json

# Only run specific checks
mtls-scanner api.example.com:8443 --checks check_self_signed_accepted,check_expired_cert_accepted

# Control CI/CD exit-code behavior
mtls-scanner api.example.com:8443 --fail-on critical   # only fail the build on CRITICAL findings
mtls-scanner api.example.com:8443 --fail-on never       # always exit 0 (informational scan)
```

Exit codes: `0` clean, `2` a finding met the `--fail-on` threshold, `3` the target could not be
reached at all.

### As a library

```python
from mtls_scanner import MTLSScanner

report = MTLSScanner("api.example.com", 8443, timeout=8).run()

if report.is_vulnerable:
    print(f"Vulnerable! Highest severity: {report.highest_severity.value}")
    for result in report.results:
        if result.status.value == "VULNERABLE":
            print(f"- {result.name}: {result.detail}")

print(report.to_json())
```

## Try it yourself: the bundled example servers

The repo ships two minimal example servers so you can see the scanner catch a real
misconfiguration and correctly clear a properly configured one, side by side:

```bash
pip install -e ".[dev]"   # pulls in pyOpenSSL, needed only for the vulnerable example

# Terminal 1: a server that requests a client cert but never validates it
python examples/vulnerable_server.py --port 8443

# Terminal 2: a server that requires AND correctly validates client certs
python examples/secure_server.py --port 8444

# Terminal 3
mtls-scanner localhost:8443   # -> VULNERABLE, multiple CRITICAL/HIGH findings
mtls-scanner localhost:8444   # -> NO MISCONFIGURATIONS DETECTED
```

See [`examples/README.md`](examples/README.md) for what each server is doing and why.

## How it works, in one paragraph

For each check, the scanner generates an in-memory X.509 certificate/key pair with one
specific defect (self-signed, wrong issuing CA, expired, not-yet-valid, wrong Extended Key
Usage, or a weak key), presents it during a real TLS handshake against the target, and
classifies the result: if the handshake — including a short post-handshake liveness probe that
correctly handles TLS 1.3's asynchronous certificate-rejection alerts — completes without the
server ever proving it rejected the certificate, that check is reported `VULNERABLE`. Nothing
is written to disk by default; test certificates live in temp files for the duration of a
single TLS connection and are deleted immediately after. Full details in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Development

```bash
git clone https://github.com/your-org/mtls-scanner.git
cd mtls-scanner
pip install -e ".[dev]"

pytest                 # run the test suite (spins up the example servers as subprocesses)
flake8 mtls_scanner/    # lint
black mtls_scanner/     # format
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution guidelines.

## Responsible use

Only scan systems you own or are explicitly authorized to test. `mtls-scanner` performs live
TLS handshakes against the target; while it does not exploit anything, running it against
third-party infrastructure without permission may violate acceptable-use policies or law
depending on jurisdiction. See [`docs/USAGE.md`](docs/USAGE.md) for authorized-use guidance
and CI/CD integration patterns.

## License

[MIT](LICENSE)
