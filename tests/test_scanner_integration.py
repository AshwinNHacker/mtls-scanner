"""
End-to-end integration tests: spin up the bundled example servers as
subprocesses and run the real scanner against them over the loopback
interface. These are the tests that actually prove the tool detects (and
does not falsely flag) mTLS misconfigurations.

Requires pyOpenSSL (see requirements-dev.txt) for the vulnerable server.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mtls_scanner.models import CheckStatus
from mtls_scanner.scanner import MTLSScanner

REPO_ROOT = Path(__file__).resolve().parent.parent
pytest.importorskip("OpenSSL", reason="pyOpenSSL required for the vulnerable example server")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"{host}:{port} did not open in time")


@pytest.fixture
def vulnerable_server():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "examples" / "vulnerable_server.py"), "--port", str(port)],
        cwd=REPO_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port("127.0.0.1", port)
        yield "127.0.0.1", port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture
def secure_server():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "examples" / "secure_server.py"), "--port", str(port)],
        cwd=REPO_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port("127.0.0.1", port)
        yield "127.0.0.1", port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def _by_id(report, check_id):
    for r in report.results:
        if r.check_id == check_id:
            return r
    raise KeyError(check_id)


class TestVulnerableServer:
    def test_reports_vulnerable(self, vulnerable_server):
        host, port = vulnerable_server
        report = MTLSScanner(host, port, timeout=6).run()
        assert not report.errors
        assert report.is_vulnerable

    def test_flags_self_signed(self, vulnerable_server):
        host, port = vulnerable_server
        report = MTLSScanner(host, port, timeout=6).run()
        assert _by_id(report, "self-signed-cert").status == CheckStatus.VULNERABLE

    def test_flags_untrusted_ca(self, vulnerable_server):
        host, port = vulnerable_server
        report = MTLSScanner(host, port, timeout=6).run()
        assert _by_id(report, "untrusted-ca-cert").status == CheckStatus.VULNERABLE

    def test_flags_expired(self, vulnerable_server):
        host, port = vulnerable_server
        report = MTLSScanner(host, port, timeout=6).run()
        assert _by_id(report, "expired-cert").status == CheckStatus.VULNERABLE

    def test_flags_not_yet_valid(self, vulnerable_server):
        host, port = vulnerable_server
        report = MTLSScanner(host, port, timeout=6).run()
        assert _by_id(report, "not-yet-valid-cert").status == CheckStatus.VULNERABLE

    def test_flags_wrong_eku(self, vulnerable_server):
        host, port = vulnerable_server
        report = MTLSScanner(host, port, timeout=6).run()
        assert _by_id(report, "wrong-eku-cert").status == CheckStatus.VULNERABLE


class TestSecureServer:
    def test_reports_no_misconfiguration(self, secure_server):
        host, port = secure_server
        report = MTLSScanner(host, port, timeout=6).run()
        assert not report.errors
        assert not report.is_vulnerable

    def test_all_core_checks_secure(self, secure_server):
        host, port = secure_server
        report = MTLSScanner(host, port, timeout=6).run()
        for check_id in (
            "self-signed-cert", "untrusted-ca-cert", "expired-cert",
            "not-yet-valid-cert", "wrong-eku-cert",
        ):
            assert _by_id(report, check_id).status == CheckStatus.SECURE, check_id


def test_unreachable_host_produces_error_not_exception():
    report = MTLSScanner("127.0.0.1", _free_port(), timeout=2).run()
    assert report.errors
    assert report.results == []
