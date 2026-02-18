"""HTTP response header analysis."""

import requests

from ..models import Finding, FindingType, Severity


def check_headers(url: str, response: requests.Response) -> list[Finding]:
    """Check for suspicious or informative headers."""
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    # Server disclosure
    if "server" in headers:
        findings.append(Finding(
            finding_type=FindingType.HEADER_ISSUE,
            severity=Severity.LOW,
            title="Server header disclosure",
            description=f"Server header exposes technology: {headers['server']}",
            url=url,
            evidence=headers["server"],
            recommendation="Remove or genericize the Server header.",
            cwe_id="CWE-200",
        ))

    # X-Powered-By
    if "x-powered-by" in headers:
        findings.append(Finding(
            finding_type=FindingType.HEADER_ISSUE,
            severity=Severity.LOW,
            title="X-Powered-By header disclosure",
            description=f"Framework/version exposed: {headers['x-powered-by']}",
            url=url,
            evidence=headers["x-powered-by"],
            recommendation="Remove X-Powered-By header.",
            cwe_id="CWE-200",
        ))

    # Debug / internal headers
    for name in ("x-debug", "x-aspnet-version", "x-aspnetmvc-version", "x-request-id", "x-runtime"):
        if name in headers:
            findings.append(Finding(
                finding_type=FindingType.INFO_DISCLOSURE,
                severity=Severity.INFO,
                title=f"Informative header: {name}",
                description=f"Header may leak internal info: {headers[name]}",
                url=url,
                evidence=headers[name],
                cwe_id="CWE-200",
            ))

    return findings
