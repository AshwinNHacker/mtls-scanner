# Architecture

## Goal

Determine, empirically, whether a target mTLS endpoint validates the client certificate chain
correctly — without relying on config-file access, source code, or any privileged vantage
point. The scanner behaves purely as a TLS client on the network.

## Component overview

```
mtls_scanner/
├── certs.py       Generates in-memory X.509 test certificates with specific defects
├── tls_utils.py   Raw TLS handshake + post-handshake liveness probing
├── scanner.py     MTLSScanner: orchestrates checks, turns handshake outcomes into verdicts
├── models.py      CheckResult / ScanReport dataclasses
├── report.py      text / JSON / HTML renderers
└── cli.py         argparse-based command-line entry point
```

Data flows in one direction: `certs` produces a certificate → `tls_utils` attempts a
handshake with it → `scanner` interprets the outcome against the check's expectations →
`models` accumulates results → `report`/`cli` present them.

## Certificate generation (`certs.py`)

Every check needs a client certificate with exactly one specific defect, so that a positive
result unambiguously implicates that one property. `CertificateTestSet` lazily builds and
caches:

- **A throwaway CA** (`untrusted_ca`), generated fresh per scan, used to sign the "otherwise
  valid" leaf certificates below. Reusing one CA across several leaves keeps every property
  except the one under test constant.
- **`self_signed_valid()`** — issuer == subject, normal validity window, correct EKU. The
  *only* defect is that nothing else in the world has signed it.
- **`signed_by_untrusted_ca()`** — signed by the scanner's own throwaway CA. Structurally a
  perfectly normal certificate; the only defect is that the target has no reason to trust
  this particular CA.
- **`expired()` / `not_yet_valid()`** — same throwaway CA, but with `notAfter` in the past or
  `notBefore` in the future.
- **`wrong_eku()`** — same throwaway CA, but the Extended Key Usage extension asserts
  `serverAuth` instead of `clientAuth`.
- **`weak_key()`** — same throwaway CA, but the leaf's RSA key is 1024 bits.

All key/cert material is generated with the `cryptography` library and written to files in
the OS temp directory only for the duration of a single TLS handshake (`ssl.SSLContext.
load_cert_chain` requires file paths); `GeneratedCert.cleanup()` deletes them immediately
after, and `MTLSScanner.run()` guarantees cleanup via `try`/`finally` even if a check raises.
Nothing is ever written to a permanent location, and no key material is logged or included in
reports.

## Handshake execution and the TLS 1.3 subtlety (`tls_utils.py`)

`attempt_handshake()` opens a TCP connection, wraps it in a `ssl.SSLContext` configured as a
pure TLS client (`check_hostname=False`, `verify_mode=CERT_NONE` — the scanner deliberately
does not evaluate the *server's* certificate, since that's an orthogonal concern from client
certificate validation), optionally loads the test cert/key pair, and performs the handshake.

**The subtlety this tool specifically accounts for:** in TLS 1.3, client authentication is
validated by the server *after* the server has already sent its own `Finished` message. A
client library's blocking handshake call can therefore return successfully even when the
server is about to reject the connection — the rejection alert (`bad_certificate`,
`unknown_ca`, `certificate_required`, etc.) may only arrive once the client attempts to read
or write on the now-established connection. Treating a completed client-side handshake alone
as "the server accepted this certificate" produces **false positives** against correctly
configured TLS 1.3 servers.

To avoid that, `_confirm_post_handshake()` performs a short, harmless read/write exchange
immediately after the handshake object reports completion:

1. A brief non-blocking-style read, in case the server sends its rejection alert (or any data)
   unprompted.
2. If nothing arrives, a single, protocol-agnostic `\r\n` is written — enough to prompt most
   request/response services (including the bundled example servers) to respond, without being
   interpretable as a meaningful request.
3. A second short read. A timeout here (no error, no data) is treated as acceptance — the
   server is alive and simply waiting for a well-formed request, and crucially, no TLS-level
   rejection occurred. Any `SSLError` or connection reset at any point in this sequence is
   treated as the server having rejected the (defective) client certificate — i.e., secure
   behavior.

This was validated empirically during development against both a broken (accepts everything)
and a correct (pyOpenSSL, real chain validation) example server; the fix changed the scanner
from misreporting the correct server as vulnerable to correctly clearing it.

## Verdict logic (`scanner.py`)

Each check method builds one test certificate, attempts a handshake, and passes the outcome
to `_verdict()`, a shared helper that maps handshake success/failure onto `CheckStatus`:

| Handshake outcome | Verdict |
|---|---|
| Completed (confirmed via post-handshake probe) | `VULNERABLE` — the server accepted a certificate it should have rejected |
| Rejected with a TLS/SSL error | `SECURE` — expected behavior |
| Network error (timeout, connection refused, reset) | `INCONCLUSIVE` — cannot be attributed to certificate validation |
| Local certificate load error (e.g. OpenSSL security level blocking a weak key) | `INCONCLUSIVE` |

`check_baseline_no_cert()` runs first and establishes whether the target enforces mTLS at
all; this doesn't gate the other checks (a server might make client certs optional but still
validate them incorrectly *when* one is presented, which is worth knowing), but its result is
included in the report as context.

A single check raising an unexpected exception is caught and converted to an `INCONCLUSIVE`
result rather than aborting the whole scan — one bad check should never prevent the rest of
the report from being produced.

## Reporting (`models.py`, `report.py`)

`ScanReport` accumulates `CheckResult`s and exposes summary properties (`vulnerable_count`,
`highest_severity`, `is_vulnerable`) used by both the CLI's exit-code logic and the renderers.
Three renderers are provided — plain/ANSI text for terminals, JSON for tooling/CI, and a
self-contained HTML file for sharing — all driven from the same `ScanReport.to_dict()`
representation, so adding a new output format doesn't require touching the scan logic.

## Explicit non-goals

- **Revocation checking (CRL/OCSP).** Whether a server checks revocation status generally
  cannot be tested black-box without a CA the server actually trusts issuing (and then
  revoking) a real certificate — outside the scope of an external scanner.
- **The server's own TLS certificate.** Plenty of existing tools (`sslyze`, `testssl.sh`)
  already do this well; duplicating that here would dilute the tool's focus.
- **Exploitation.** The scanner establishes TLS connections and immediately closes them; it
  never attempts to use an accepted (invalid) certificate to reach application data.
