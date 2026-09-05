"""Data models used across the scanner."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Impact level of a finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]


class CheckStatus(str, Enum):
    """Outcome of a single check."""

    VULNERABLE = "VULNERABLE"      # Misconfiguration confirmed
    SECURE = "SECURE"              # Server behaved correctly
    INCONCLUSIVE = "INCONCLUSIVE"  # Could not determine (network/error)
    SKIPPED = "SKIPPED"            # Not applicable / not run


@dataclass
class CheckResult:
    """Result of a single security check against a target."""

    check_id: str
    name: str
    description: str
    status: CheckStatus
    severity: Severity
    detail: str = ""
    remediation: str = ""
    evidence: dict = field(default_factory=dict)
    duration_ms: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanReport:
    """Full report for a single host:port scan."""

    target: str
    port: int
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    results: list = field(default_factory=list)
    scanner_version: str = ""
    errors: list = field(default_factory=list)

    def add(self, result: CheckResult) -> None:
        self.results.append(result)

    def finish(self) -> None:
        self.finished_at = time.time()

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or time.time()
        return round(end - self.started_at, 3)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for r in self.results if r.status == CheckStatus.VULNERABLE)

    @property
    def secure_count(self) -> int:
        return sum(1 for r in self.results if r.status == CheckStatus.SECURE)

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for r in self.results if r.status == CheckStatus.INCONCLUSIVE)

    @property
    def highest_severity(self) -> Optional[Severity]:
        vulns = [r.severity for r in self.results if r.status == CheckStatus.VULNERABLE]
        if not vulns:
            return None
        return max(vulns, key=lambda s: s.rank)

    @property
    def is_vulnerable(self) -> bool:
        return self.vulnerable_count > 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "port": self.port,
            "scanner_version": self.scanner_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "total_checks": len(self.results),
                "vulnerable": self.vulnerable_count,
                "secure": self.secure_count,
                "inconclusive": self.inconclusive_count,
                "highest_severity": self.highest_severity.value if self.highest_severity else None,
                "is_vulnerable": self.is_vulnerable,
            },
            "results": [r.to_dict() for r in self.results],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
