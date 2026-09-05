"""
mtls-scanner
============

A scanner that detects mutual TLS (mTLS) endpoints which accept client
certificates without performing proper chain-of-trust validation.

Public API:
    from mtls_scanner import MTLSScanner, ScanReport
"""

__version__ = "1.0.0"
__author__ = "mtls-scanner contributors"
__license__ = "MIT"

from mtls_scanner.models import CheckResult, ScanReport, Severity, CheckStatus
from mtls_scanner.scanner import MTLSScanner

__all__ = [
    "MTLSScanner",
    "ScanReport",
    "CheckResult",
    "Severity",
    "CheckStatus",
    "__version__",
]
