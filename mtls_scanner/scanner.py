"""
Core scanning engine.

MTLSScanner drives a sequence of independent checks against a target
host:port. Each check presents a deliberately-flawed (or deliberately
absent) client certificate and observes whether the TLS handshake
completes. A handshake that succeeds when it should have been rejected
indicates a client-certificate-chain validation misconfiguration.
"""

from __future__ import annotations

import ssl
import time
from typing import Callable, List, Optional

from mtls_scanner import __version__
from mtls_scanner.certs import CertificateTestSet
from mtls_scanner.models import CheckResult, CheckStatus, ScanReport, Severity
from mtls_scanner.tls_utils import (
    HandshakeOutcome,
    attempt_handshake,
    check_port_open,
    probe_tls_version,
)


class MTLSScanner:
    """
    Scans a single target for mTLS client-certificate-validation
    misconfigurations.

    Usage:
        scanner = MTLSScanner("api.example.com", 8443, timeout=8)
        report = scanner.run()
        print(report.to_json())
    """

    #: Ordered list of (method_name, check_id) run by default.
    DEFAULT_CHECKS = [
        "check_baseline_no_cert",
        "check_self_signed_accepted",
        "check_untrusted_ca_accepted",
        "check_expired_cert_accepted",
        "check_not_yet_valid_accepted",
        "check_wrong_eku_accepted",
        "check_weak_key_accepted",
        "check_legacy_tls_versions",
    ]

    def __init__(
        self,
        host: str,
        port: int = 443,
        timeout: float = 8.0,
        checks: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.checks = checks or list(self.DEFAULT_CHECKS)
        self.progress_callback = progress_callback
        self._certs = CertificateTestSet()
        # Populated by check_baseline_no_cert(); other checks use it to
        # decide whether "mTLS enforced" framing applies.
        self._mtls_enforced: Optional[bool] = None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def run(self) -> ScanReport:
        report = ScanReport(target=self.host, port=self.port, scanner_version=__version__)

        if not check_port_open(self.host, self.port, timeout=self.timeout):
            report.errors.append(
                f"Could not open a TCP connection to {self.host}:{self.port} "
                "(host unreachable, port closed, or firewalled)."
            )
            report.finish()
            return report

        try:
            for method_name in self.checks:
                method = getattr(self, method_name, None)
                if method is None:
                    report.errors.append(f"Unknown check: {method_name}")
                    continue
                self._notify(method_name, "running")
                start = time.perf_counter()
                try:
                    result = method()
                except Exception as exc:  # defensive: one check must not kill the scan
                    result = CheckResult(
                        check_id=method_name,
                        name=method_name,
                        description="",
                        status=CheckStatus.INCONCLUSIVE,
                        severity=Severity.INFO,
                        detail=f"Check raised an unexpected error: {exc}",
                    )
                result.duration_ms = round((time.perf_counter() - start) * 1000, 1)
                report.add(result)
                self._notify(method_name, result.status.value)
        finally:
            self._certs.cleanup()

        report.finish()
        return report

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _notify(self, check_id: str, status: str) -> None:
        if self.progress_callback:
            try:
                self.progress_callback(check_id, status)
            except Exception:
                pass  # never let a UI callback break a scan

    def _handshake(self, cert_path: Optional[str] = None, key_path: Optional[str] = None, **kw) -> HandshakeOutcome:
        return attempt_handshake(
            self.host, self.port, cert_path=cert_path, key_path=key_path, timeout=self.timeout, **kw
        )

    def _handshake_weak_key(self, cert_path: str, key_path: str) -> HandshakeOutcome:
        return attempt_handshake(
            self.host, self.port, cert_path=cert_path, key_path=key_path,
            timeout=self.timeout, allow_weak_local_key=True,
        )

    # ------------------------------------------------------------------ #
    # Checks
    # ------------------------------------------------------------------ #

    def check_baseline_no_cert(self) -> CheckResult:
        """
        Establishes a baseline: does the server require *any* client
        certificate at all? This isn't itself a vulnerability (plenty of
        services legitimately make client certs optional), but it's
        important context reported alongside the other findings, and the
        other checks are only meaningful in an mTLS-enforcing context.
        """
        outcome = self._handshake()
        self._mtls_enforced = not outcome.success

        if outcome.success:
            return CheckResult(
                check_id="baseline-no-cert",
                name="Client certificate requirement",
                description="Checks whether the server enforces mTLS by requiring a client certificate.",
                status=CheckStatus.SECURE,
                severity=Severity.INFO,
                detail=(
                    "The TLS handshake completed without presenting a client certificate. "
                    "This server does not appear to enforce mutual TLS on this port "
                    "(client certificates may be optional or unused here). The remaining "
                    "checks in this scan are only meaningful if mTLS is actually enforced, "
                    "so treat findings below in that light."
                ),
                evidence={"negotiated_protocol": outcome.negotiated_protocol},
            )

        return CheckResult(
            check_id="baseline-no-cert",
            name="Client certificate requirement",
            description="Checks whether the server enforces mTLS by requiring a client certificate.",
            status=CheckStatus.SECURE,
            severity=Severity.INFO,
            detail=(
                "The server rejected the handshake when no client certificate was presented, "
                f"consistent with mTLS enforcement. ({outcome.error_type}: {outcome.error})"
            ),
        )

    def check_self_signed_accepted(self) -> CheckResult:
        gc = self._certs.self_signed_valid()
        outcome = self._handshake(gc.cert_path, gc.key_path)
        return self._verdict(
            outcome,
            check_id="self-signed-cert",
            name="Self-signed client certificate acceptance",
            description=(
                "Presents a freshly generated, self-signed client certificate that is not "
                "signed by any CA the server should trust."
            ),
            severity=Severity.CRITICAL,
            vuln_detail=(
                "The server completed the TLS handshake and accepted a self-signed client "
                "certificate. A properly configured mTLS server must reject client "
                "certificates that do not chain to a trusted CA -  this allows any "
                "attacker who can generate a keypair to authenticate as a client."
            ),
            secure_detail="The server correctly rejected the self-signed client certificate.",
            remediation=(
                "Configure the TLS terminator (nginx `ssl_client_certificate`/"
                "`ssl_verify_client strict`, Envoy `require_client_certificate` + validation "
                "context, HAProxy `verify required ca-file`, Java `TrustManager`, etc.) to "
                "validate the full client certificate chain against a pinned, trusted CA "
                "bundle, and to reject any certificate that does not chain to it."
            ),
        )

    def check_untrusted_ca_accepted(self) -> CheckResult:
        gc = self._certs.signed_by_untrusted_ca()
        outcome = self._handshake(gc.cert_path, gc.key_path)
        return self._verdict(
            outcome,
            check_id="untrusted-ca-cert",
            name="Untrusted CA-signed certificate acceptance",
            description=(
                "Presents a client certificate that is validly signed - but by a throwaway "
                "CA generated by the scanner, which the target has never seen or trusted."
            ),
            severity=Severity.CRITICAL,
            vuln_detail=(
                "The server accepted a client certificate issued by a CA it should have no "
                "reason to trust. This typically indicates the server is not validating the "
                "certificate chain against its configured trust store at all, or is trusting "
                "an overly broad set of CAs (e.g. the system default trust store instead of "
                "a pinned client-CA bundle)."
            ),
            secure_detail="The server correctly rejected the certificate signed by an untrusted CA.",
            remediation=(
                "Ensure the server validates client certificates against an explicit, "
                "pinned CA bundle dedicated to client authentication - never the system/"
                "public trust store, which contains hundreds of CAs with no relationship "
                "to your clients."
            ),
        )

    def check_expired_cert_accepted(self) -> CheckResult:
        gc = self._certs.expired()
        outcome = self._handshake(gc.cert_path, gc.key_path)
        return self._verdict(
            outcome,
            check_id="expired-cert",
            name="Expired certificate acceptance",
            description="Presents a client certificate whose validity period ended in the past.",
            severity=Severity.HIGH,
            vuln_detail=(
                "The server accepted a client certificate that expired 30+ days ago. "
                "Expiration checking is a basic and mandatory part of X.509 path validation; "
                "skipping it lets revoked or stale credentials (e.g. from an ex-employee's "
                "decommissioned service) continue to authenticate indefinitely."
            ),
            secure_detail="The server correctly rejected the expired client certificate.",
            remediation=(
                "Verify the TLS stack is actually performing full X.509 path validation "
                "(including `notAfter`/`notBefore` checks) rather than only checking the "
                "signature or skipping validation via a misconfigured flag such as "
                "`ssl_verify_client optional_no_ca` (nginx) or a custom TrustManager that "
                "returns unconditionally."
            ),
        )

    def check_not_yet_valid_accepted(self) -> CheckResult:
        gc = self._certs.not_yet_valid()
        outcome = self._handshake(gc.cert_path, gc.key_path)
        return self._verdict(
            outcome,
            check_id="not-yet-valid-cert",
            name="Not-yet-valid certificate acceptance",
            description="Presents a client certificate whose validity period starts 30 days in the future.",
            severity=Severity.MEDIUM,
            vuln_detail=(
                "The server accepted a client certificate that is not yet within its "
                "validity window. This further confirms that date-range validation is not "
                "being enforced during the handshake."
            ),
            secure_detail="The server correctly rejected the not-yet-valid client certificate.",
            remediation="Same as expired-certificate handling: ensure full date-range validation is enforced.",
        )

    def check_wrong_eku_accepted(self) -> CheckResult:
        gc = self._certs.wrong_eku()
        outcome = self._handshake(gc.cert_path, gc.key_path)
        return self._verdict(
            outcome,
            check_id="wrong-eku-cert",
            name="Incorrect Extended Key Usage acceptance",
            description=(
                "Presents a client certificate whose Extended Key Usage extension declares "
                "'serverAuth' only, omitting 'clientAuth'."
            ),
            severity=Severity.MEDIUM,
            vuln_detail=(
                "The server accepted a certificate that is not authorized for client "
                "authentication per its own Extended Key Usage extension. This can allow "
                "certificates issued for an unrelated purpose (e.g. a TLS server cert from "
                "the same PKI) to be repurposed for client authentication."
            ),
            secure_detail="The server correctly rejected the certificate lacking the clientAuth EKU.",
            remediation=(
                "Enforce Extended Key Usage checks so only certificates explicitly issued "
                "for client authentication (clientAuth OID 1.3.6.1.5.5.7.3.2) are accepted."
            ),
        )

    def check_weak_key_accepted(self) -> CheckResult:
        gc = self._certs.weak_key()
        outcome = self._handshake_weak_key(gc.cert_path, gc.key_path)
        return self._verdict(
            outcome,
            check_id="weak-key-cert",
            name="Weak key size acceptance",
            description="Presents a client certificate using a 1024-bit RSA key (signed by the untrusted test CA).",
            severity=Severity.LOW,
            vuln_detail=(
                "The server accepted a client certificate built on a 1024-bit RSA key, which "
                "is considered cryptographically weak by current standards (NIST/CA-Browser "
                "Forum guidance calls for 2048-bit minimum). Note this finding also implies "
                "the untrusted-CA check above, since the same throwaway CA was used."
            ),
            secure_detail="The server rejected the certificate (either for its weak key size or, more likely, its untrusted issuer).",
            remediation=(
                "Enforce a minimum key size policy (RSA >= 2048 bits, or EC P-256/P-384) as "
                "part of client certificate validation, in addition to full chain validation."
            ),
        )

    def check_legacy_tls_versions(self) -> CheckResult:
        """
        Not a client-certificate chain check per se, but a closely related
        mTLS hardening signal: legacy protocol versions widen the attack
        surface available to intercept or downgrade a client-authenticated
        session.
        """
        legacy = []
        for name, version in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            try:
                outcome = probe_tls_version(self.host, self.port, version, timeout=self.timeout)
            except (ssl.SSLError, ValueError):
                continue
            if outcome.success:
                legacy.append(name)

        if legacy:
            return CheckResult(
                check_id="legacy-tls-versions",
                name="Legacy TLS protocol support",
                description="Checks whether the server still negotiates deprecated TLS 1.0/1.1.",
                status=CheckStatus.VULNERABLE,
                severity=Severity.LOW,
                detail=(
                    f"The server negotiated the following deprecated protocol version(s): "
                    f"{', '.join(legacy)}. These lack modern cipher suites and AEAD-only "
                    "guarantees, and are disallowed by PCI-DSS and most modern compliance "
                    "frameworks."
                ),
                remediation="Disable TLS 1.0 and TLS 1.1; require TLS 1.2 as a minimum, prefer TLS 1.3.",
            )

        return CheckResult(
            check_id="legacy-tls-versions",
            name="Legacy TLS protocol support",
            description="Checks whether the server still negotiates deprecated TLS 1.0/1.1.",
            status=CheckStatus.SECURE,
            severity=Severity.INFO,
            detail="The server did not negotiate TLS 1.0 or TLS 1.1.",
        )

    # ------------------------------------------------------------------ #
    # Shared verdict logic
    # ------------------------------------------------------------------ #

    def _verdict(
        self,
        outcome: HandshakeOutcome,
        *,
        check_id: str,
        name: str,
        description: str,
        severity: Severity,
        vuln_detail: str,
        secure_detail: str,
        remediation: str,
    ) -> CheckResult:
        evidence = {
            "negotiated_protocol": outcome.negotiated_protocol,
            "negotiated_cipher": outcome.negotiated_cipher,
        }

        if outcome.error_type == "local_cert_error":
            return CheckResult(
                check_id=check_id, name=name, description=description,
                status=CheckStatus.INCONCLUSIVE, severity=Severity.INFO,
                detail=outcome.error or "Failed to prepare local test certificate.",
            )

        if outcome.success:
            return CheckResult(
                check_id=check_id, name=name, description=description,
                status=CheckStatus.VULNERABLE, severity=severity,
                detail=vuln_detail, remediation=remediation, evidence=evidence,
            )

        if outcome.error_type in ("timeout", "refused", "os_error"):
            return CheckResult(
                check_id=check_id, name=name, description=description,
                status=CheckStatus.INCONCLUSIVE, severity=Severity.INFO,
                detail=f"Could not complete this check due to a network error: {outcome.error}",
            )

        return CheckResult(
            check_id=check_id, name=name, description=description,
            status=CheckStatus.SECURE, severity=Severity.INFO,
            detail=f"{secure_detail} ({outcome.error_type}: {outcome.error})",
        )
