"""Data models for scan results and findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(Enum):
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    HEADER_ISSUE = "header_issue"
    SECRET_EXPOSED = "secret_exposed"
    SSL_ISSUE = "ssl_issue"
    CORS_MISCONFIG = "cors_misconfig"
    SECURITY_HEADER_MISSING = "security_header_missing"
    INFO_DISCLOSURE = "info_disclosure"
    HTTP_METHOD = "http_method"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    TEMPLATE_INJECTION = "template_injection"
    BYPASS_403 = "bypass_403"
    UPLOAD_ISSUE = "upload_issue"
    OTHER = "other"


@dataclass
class Finding:
    """A single security finding."""
    finding_type: FindingType
    severity: Severity
    title: str
    description: str
    url: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "type": self.finding_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "cvss": self.cvss,
        }


@dataclass
class ScanResult:
    """Aggregated result of a security scan."""
    target: str
    findings: list[Finding] = field(default_factory=list)
    urls_tested: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        self.errors.append(error)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)
