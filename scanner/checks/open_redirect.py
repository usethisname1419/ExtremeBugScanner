"""Open redirect detection (optionally using your OAST URL)."""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..models import Finding, FindingType, Severity


# Common redirect parameter names
REDIRECT_PARAMS = ("url", "redirect", "next", "return", "returnUrl", "redirect_uri", "destination", "redir", "link")
# Fallback payload when no OAST URL is provided
DEFAULT_REDIRECT_PAYLOAD = "https://evil.bounty-scanner.example.com/"


def check_open_redirect(
    url: str,
    session: requests.Session | None = None,
    oast_url: str | None = None,
) -> list[Finding]:
    """
    Check for open redirect via common parameters.
    If oast_url is provided (e.g. Burp Collaborator, Interactsh), use it as the redirect target
    so you can confirm the redirect in your OAST panel.
    """
    findings = []
    session = session or requests.Session()
    payload = (oast_url or DEFAULT_REDIRECT_PAYLOAD).strip()
    if not payload.startswith(("http://", "https://")):
        payload = "https://" + payload
    # For detection we need a hostname to look for in Location (OAST host or placeholder)
    payload_host = urlparse(payload).netloc or payload

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    for param in REDIRECT_PARAMS:
        if param not in params:
            continue
        try:
            test_params = params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            resp = session.get(test_url, timeout=10, allow_redirects=False)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if payload in location or payload_host in location:
                    findings.append(Finding(
                        finding_type=FindingType.OPEN_REDIRECT,
                        severity=Severity.MEDIUM,
                        title="Possible open redirect",
                        description=f"Parameter '{param}' may allow redirect to arbitrary URL.",
                        url=test_url,
                        evidence=f"Location: {location}",
                        recommendation="Validate redirect URLs against an allowlist.",
                        cwe_id="CWE-601",
                    ))
        except requests.RequestException:
            continue
    return findings
