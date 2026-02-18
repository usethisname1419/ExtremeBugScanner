"""Missing security headers check."""

import requests

from ..models import Finding, FindingType, Severity


RECOMMENDED_HEADERS = {
    "strict-transport-security": {
        "description": "HSTS not set. Enables browser to enforce HTTPS.",
        "recommendation": "Set Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "severity": Severity.MEDIUM,
    },
    "x-content-type-options": {
        "description": "X-Content-Type-Options not set. Risk of MIME sniffing.",
        "recommendation": "Set X-Content-Type-Options: nosniff",
        "severity": Severity.MEDIUM,
    },
    "x-frame-options": {
        "description": "X-Frame-Options not set. Risk of clickjacking.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN",
        "severity": Severity.MEDIUM,
    },
    "content-security-policy": {
        "description": "Content-Security-Policy not set. Reduces XSS impact.",
        "recommendation": "Define a restrictive CSP.",
        "severity": Severity.LOW,
    },
    "x-xss-protection": {
        "description": "X-XSS-Protection not set (legacy; CSP is preferred).",
        "recommendation": "Set X-XSS-Protection: 1; mode=block or rely on CSP",
        "severity": Severity.INFO,
    },
    "referrer-policy": {
        "description": "Referrer-Policy not set. May leak URLs in Referer.",
        "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin",
        "severity": Severity.LOW,
    },
    "permissions-policy": {
        "description": "Permissions-Policy not set. Browser features not restricted.",
        "recommendation": "Set Permissions-Policy to restrict features.",
        "severity": Severity.LOW,
    },
}


def check_security_headers(url: str, response: requests.Response) -> list[Finding]:
    """Report missing security headers."""
    findings = []
    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    for header, info in RECOMMENDED_HEADERS.items():
        if header not in headers_lower:
            findings.append(Finding(
                finding_type=FindingType.SECURITY_HEADER_MISSING,
                severity=info["severity"],
                title=f"Missing security header: {header}",
                description=info["description"],
                url=url,
                recommendation=info["recommendation"],
                cwe_id="CWE-693",
            ))

    return findings
