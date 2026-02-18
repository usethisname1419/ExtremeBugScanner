"""Information disclosure checks."""

import re
import requests

from ..models import Finding, FindingType, Severity


# Patterns that may indicate sensitive info in responses
DISCLOSURE_PATTERNS = [
    (re.compile(r"/var/www/[^\s\"'<>]+", re.I), "Web path disclosure"),
    (re.compile(r"\[Errno \d+\].*path.*['\"]([^'\"]+)['\"]", re.I), "Python path disclosure"),
    (re.compile(r"at \w+\.(\w+) \(([^:]+):(\d+):\d+\)", re.I), "JavaScript stack trace"),
    (re.compile(r"Exception in thread.*\n.*at .*\.(\w+)\(.*\.java:\d+\)", re.I), "Java stack trace"),
    (re.compile(r"Fatal error:.*in ([^\s]+) on line (\d+)", re.I), "PHP error disclosure"),
    (re.compile(r"<\?xml[^>]*\?>.*<.*Exception", re.I), "XML exception disclosure"),
    (re.compile(r"\"version\":\s*\"[\d.]+\"", re.I), "Version in JSON response"),
    (re.compile(r"internal server error", re.I), "Generic error message"),
    (re.compile(r"debug.*=.*true", re.I), "Debug mode indicator"),
]


def check_info_disclosure(url: str, response: requests.Response) -> list[Finding]:
    """Check response body for information disclosure."""
    findings = []
    text = response.text[:50000]  # Limit scan size

    for pattern, desc in DISCLOSURE_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(Finding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                title=desc,
                description=f"Response may contain sensitive information: {desc}",
                url=url,
                evidence=match.group(0)[:200] if match.group(0) else pattern.pattern,
                recommendation="Disable debug/stack traces in production. Sanitize error messages.",
                cwe_id="CWE-209",
            ))
            break  # One per type

    return findings
