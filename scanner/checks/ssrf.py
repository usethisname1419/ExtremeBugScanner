"""SSRF detection via OAST (out-of-band) callback URL."""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..models import Finding, FindingType, Severity


# Common parameter names that may trigger server-side requests
SSRF_PARAMS = (
    "url", "uri", "path", "dest", "destination", "redirect", "redirect_uri",
    "callback", "callback_url", "webhook", "feed", "data", "src", "source",
    "fetch", "request", "load", "document", "file", "page", "include",
    "target", "host", "endpoint", "api", "next", "return", "continue",
)


def check_ssrf(
    url: str,
    oast_url: str,
    session: requests.Session | None = None,
) -> list[Finding]:
    """
    Inject OAST URL into common SSRF parameters and send requests.
    If the target is vulnerable, the server will issue a request to oast_url;
    you must check your OAST server (Burp Collaborator, Interactsh, etc.) for callbacks.
    """
    findings = []
    if not oast_url or not oast_url.startswith(("http://", "https://")):
        return findings

    session = session or requests.Session()
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    probed = []

    for param in SSRF_PARAMS:
        try:
            test_params = params.copy()
            test_params[param] = [oast_url]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            session.get(test_url, timeout=10)
            probed.append(param)
        except requests.RequestException:
            continue

    if probed:
        findings.append(Finding(
            finding_type=FindingType.SSRF,
            severity=Severity.INFO,
            title="SSRF OAST probes sent",
            description=(
                f"OAST URL was submitted to {len(probed)} parameter(s): " + ", ".join(probed[:10])
                + (f" (+{len(probed) - 10} more)" if len(probed) > 10 else "")
                + ". Check your OAST server (Burp Collaborator, Interactsh, etc.) for HTTP/DNS callbacks. "
                "If you see a callback, the endpoint may be vulnerable to SSRF."
            ),
            url=url,
            evidence=f"OAST URL: {oast_url}",
            recommendation="Validate and allowlist URLs used for server-side fetches. Block access to internal and OAST domains.",
            cwe_id="CWE-918",
        ))

    return findings
