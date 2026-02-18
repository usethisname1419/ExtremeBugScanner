"""Dangerous HTTP methods and misconfigurations."""

import requests

from ..models import Finding, FindingType, Severity


# Methods that may be dangerous if enabled
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]


def check_http_methods(url: str, session: requests.Session | None = None) -> list[Finding]:
    """Check for allowed HTTP methods (e.g. TRACE, PUT)."""
    findings = []
    session = session or requests.Session()

    try:
        resp = session.options(url, timeout=10)
        allow = resp.headers.get("Allow") or resp.headers.get("Public")
        if not allow:
            return findings
        allowed = [m.strip().upper() for m in allow.split(",")]
        for method in DANGEROUS_METHODS:
            if method in allowed:
                sev = Severity.HIGH if method == "TRACE" else Severity.MEDIUM
                findings.append(Finding(
                    finding_type=FindingType.HTTP_METHOD,
                    severity=sev,
                    title=f"Dangerous HTTP method allowed: {method}",
                    description=f"Server allows {method}. TRACE can enable XST; PUT/DELETE may allow modification.",
                    url=url,
                    evidence=f"Allow: {allow}",
                    recommendation="Disable unnecessary methods. Use WAF or server config to restrict.",
                    cwe_id="CWE-16",
                ))
    except requests.RequestException:
        pass

    return findings
