"""Server-Side Template Injection (SSTI) detection via {{7*7}}-style payloads."""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..models import Finding, FindingType, Severity


# Payload -> expected result if evaluated
SSTI_SIMPLE = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
    ("{{7*'7'}}", "49"),
    ("{{'7'*7}}", "7777777"),
    ("${7*7}", "49"),
    ("@(6+1)*7", "49"),
    ("{{ 7*7 }}", "49"),
    ("{{ 7 * 7 }}", "49"),
    ("${{7*7}}", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
]


def inject_payload(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def check_template_injection(url: str, session: requests.Session | None = None) -> list[Finding]:
    """Check for SSTI by injecting {{7*7}}-style payloads and looking for 49 (or expression result) in response."""
    findings = []
    session = session or requests.Session()
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # If no params, try POST body or single payload in common param names
    param_names = list(params.keys()) if params else ["q", "query", "search", "keyword", "name", "id", "input", "data", "template", "templateName", "preview", "content"]

    for param in param_names:
        if not params and param not in ("q", "query", "search", "keyword", "name", "id", "input", "data", "template", "templateName", "preview", "content"):
            continue
        for payload, expected in SSTI_SIMPLE:
            if not expected:
                continue
            try:
                if params:
                    test_url = inject_payload(url, param, payload)
                    resp = session.get(test_url, timeout=10)
                else:
                    # Try GET with param added
                    test_params = {param: payload}
                    resp = session.get(url, params=test_params, timeout=10)
                    test_url = resp.url
                text = resp.text
                # Expected value in response but payload not literally reflected -> likely evaluated
                if expected in text and payload not in text:
                    findings.append(Finding(
                        finding_type=FindingType.TEMPLATE_INJECTION,
                        severity=Severity.HIGH,
                        title="Possible Server-Side Template Injection (SSTI)",
                        description=f"Parameter '{param}' may be passed to a template engine. Payload was evaluated (saw '{expected}' in response).",
                        url=test_url,
                        evidence=f"Payload: {payload} -> expected '{expected}' found",
                        recommendation="Never pass user input into template engines. Use static templates and pass only safe data.",
                        cwe_id="CWE-1336",
                    ))
                    break
            except requests.RequestException:
                continue

    return findings
