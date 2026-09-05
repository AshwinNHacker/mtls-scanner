import json

from mtls_scanner.models import CheckResult, CheckStatus, ScanReport, Severity


def _make_result(status, severity, check_id="x"):
    return CheckResult(
        check_id=check_id, name="Test check", description="desc",
        status=status, severity=severity, detail="detail",
    )


def test_severity_rank_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank


def test_scan_report_counts_and_highest_severity():
    report = ScanReport(target="example.com", port=8443)
    report.add(_make_result(CheckStatus.VULNERABLE, Severity.MEDIUM, "a"))
    report.add(_make_result(CheckStatus.VULNERABLE, Severity.CRITICAL, "b"))
    report.add(_make_result(CheckStatus.SECURE, Severity.INFO, "c"))
    report.add(_make_result(CheckStatus.INCONCLUSIVE, Severity.INFO, "d"))
    report.finish()

    assert report.vulnerable_count == 2
    assert report.secure_count == 1
    assert report.inconclusive_count == 1
    assert report.is_vulnerable is True
    assert report.highest_severity == Severity.CRITICAL
    assert report.duration_seconds >= 0


def test_scan_report_no_vulnerabilities():
    report = ScanReport(target="example.com", port=443)
    report.add(_make_result(CheckStatus.SECURE, Severity.INFO))
    assert report.is_vulnerable is False
    assert report.highest_severity is None


def test_scan_report_to_json_round_trips():
    report = ScanReport(target="example.com", port=443, scanner_version="1.0.0")
    report.add(_make_result(CheckStatus.VULNERABLE, Severity.HIGH))
    report.finish()

    payload = json.loads(report.to_json())
    assert payload["target"] == "example.com"
    assert payload["port"] == 443
    assert payload["summary"]["vulnerable"] == 1
    assert payload["summary"]["is_vulnerable"] is True
    assert payload["results"][0]["status"] == "VULNERABLE"
    assert payload["results"][0]["severity"] == "HIGH"


def test_check_result_to_dict_serializes_enums():
    r = _make_result(CheckStatus.SECURE, Severity.LOW)
    d = r.to_dict()
    assert d["status"] == "SECURE"
    assert d["severity"] == "LOW"
