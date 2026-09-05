import pytest

from mtls_scanner.cli import _parse_target, _severity_threshold_met, build_parser
from mtls_scanner.models import CheckResult, CheckStatus, ScanReport, Severity


@pytest.mark.parametrize(
    "raw,default_port,expected",
    [
        ("example.com", 443, ("example.com", 443)),
        ("example.com:8443", 443, ("example.com", 8443)),
        ("10.0.0.5:9443", 443, ("10.0.0.5", 9443)),
        ("[::1]:8443", 443, ("::1", 8443)),
        ("[::1]", 443, ("::1", 443)),
    ],
)
def test_parse_target(raw, default_port, expected):
    assert _parse_target(raw, default_port) == expected


def test_build_parser_requires_target_or_targets_file():
    parser = build_parser()
    args = parser.parse_args(["example.com"])
    assert args.target == "example.com"
    assert args.port == 443


def test_build_parser_defaults():
    parser = build_parser()
    args = parser.parse_args(["host:1234"])
    assert args.format == "text"
    assert args.fail_on == "any"
    assert args.timeout == 8.0


def _report_with(severity, status=CheckStatus.VULNERABLE):
    report = ScanReport(target="t", port=1)
    report.add(CheckResult(check_id="x", name="n", description="d", status=status, severity=severity))
    return report


def test_severity_threshold_never():
    report = _report_with(Severity.CRITICAL)
    assert _severity_threshold_met(report, "never") is False


def test_severity_threshold_any():
    report = _report_with(Severity.LOW)
    assert _severity_threshold_met(report, "any") is True


def test_severity_threshold_specific_met():
    report = _report_with(Severity.CRITICAL)
    assert _severity_threshold_met(report, "high") is True


def test_severity_threshold_specific_not_met():
    report = _report_with(Severity.LOW)
    assert _severity_threshold_met(report, "critical") is False


def test_severity_threshold_no_vulns():
    report = ScanReport(target="t", port=1)
    report.add(CheckResult(check_id="x", name="n", description="d", status=CheckStatus.SECURE, severity=Severity.INFO))
    assert _severity_threshold_met(report, "any") is False
