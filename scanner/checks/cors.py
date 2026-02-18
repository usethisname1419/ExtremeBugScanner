"""CORS misconfiguration checks."""

import requests

from ..models import Finding, FindingType, Severity


def check_cors(url: str, response: requests.Response) -> list[Finding]:
    """Check CORS headers for misconfigurations."""
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials", "").lower() == "true"

    if not acao:
        return findings

    # Reflects any origin (common misconfig)
    if acao == "*" and acac:
        findings.append(Finding(
            finding_type=FindingType.CORS_MISCONFIG,
            severity=Severity.HIGH,
            title="CORS: Allow-Origin * with credentials",
            description="Access-Control-Allow-Origin is * while Allow-Credentials is true. Browsers block this; check for origin reflection.",
            url=url,
            evidence=f"ACAO: {acao}, ACAC: true",
            recommendation="Do not use * with credentials. Whitelist specific origins.",
            cwe_id="CWE-942",
        ))
    elif acao == "*":
        findings.append(Finding(
            finding_type=FindingType.CORS_MISCONFIG,
            severity=Severity.LOW,
            title="CORS: Allow-Origin *",
            description="Server allows any origin. Sensitive data may be readable by other sites if credentials are used.",
            url=url,
            evidence=f"ACAO: {acao}",
            recommendation="Restrict Access-Control-Allow-Origin to trusted origins.",
            cwe_id="CWE-942",
        ))

    # Check if server reflects Origin header (test with fake origin)
    return findings
