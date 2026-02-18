"""403 Forbidden bypass attempts via path normalization and headers."""

import requests
from urllib.parse import urljoin

from ..models import Finding, FindingType, Severity


# Paths often restricted (we probe these; if 403, try bypasses)
RESTRICTED_PATHS = [
    "/admin", "/administrator", "/api", "/backend", "/config", "/dashboard",
    "/manage", "/manager", "/private", "/secret", "/admin/login", "/wp-admin",
    "/.git", "/.env", "/backup", "/debug", "/trace", "/server-status",
]

# (suffix to append to path, description)
BYPASS_SUFFIXES = [
    ("/", "trailing slash"),
    ("/.", "trailing dot"),
    ("/./", "./"),
    ("/..;/", "..;/"),
    ("/.;/", ".;/"),
    ("/%20", "space"),
    ("/%09", "tab"),
    ("/?", "query"),
    ("/#", "fragment"),
    ("/.json", ".json"),
    ("/.html", ".html"),
    ("/..%2f", "..%2f"),
    ("/%2e%2e/", "%2e%2e/"),
    ("/;/", "semicolon"),
    ("//", "double slash"),
    ("/..;/..;/", "double ..;/"),
    ("/admin/..;/", "..;/ after path"),
    ("%20", "space no slash"),
    ("%09", "tab no slash"),
    ("?", "query no slash"),
    ("#", "fragment no slash"),
    ("..;/", "..;/ only"),
    ("/Admin", "case Admin"),
    ("/ADMIN", "uppercase"),
    ("/admin%2f", "encoded slash"),
    ("/admin%252f", "double encoded slash"),
    ("/admin%00", "null byte"),
    ("/admin/./", "./"),
    ("/admin/../admin/", ".. then admin"),
    ("/admin;/", "semicolon"),
]

# Headers that may override path on some servers
BYPASS_HEADERS = [
    ("X-Original-URL", None),
    ("X-Rewrite-URL", None),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
]


def check_bypass_403(base_url: str, session: requests.Session | None = None) -> list[Finding]:
    """
    Probe restricted paths. If 403, try path variants and header overrides.
    Report when a variant returns 2xx or 3xx instead of 403.
    """
    findings = []
    session = session or requests.Session()
    base = base_url.rstrip("/").rsplit("/", 1)[0] if "/" in base_url.replace("://", "") else base_url
    if "://" in base_url:
        from urllib.parse import urlparse
        p = urlparse(base_url)
        base = f"{p.scheme}://{p.netloc}"
    timeout = 10

    for path in RESTRICTED_PATHS:
        path = path.rstrip("/")
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code != 403:
                continue
        except requests.RequestException:
            continue

        for suffix, desc in BYPASS_SUFFIXES:
            if suffix.startswith("/"):
                test_path = path + suffix
            else:
                test_path = path + "/" + suffix if not suffix.startswith(("?", "#")) else path + suffix
            test_url = urljoin(base + "/", test_path.lstrip("/"))
            try:
                resp = session.get(test_url, timeout=timeout, allow_redirects=False)
                if resp.status_code in (200, 201, 301, 302, 401):
                    findings.append(Finding(
                        finding_type=FindingType.BYPASS_403,
                        severity=Severity.HIGH,
                        title="Possible 403 bypass",
                        description=f"Path returned 403, but variant returned {resp.status_code}. Bypass: {desc}.",
                        url=test_url,
                        evidence=f"403: {url} -> variant -> {resp.status_code}",
                        recommendation="Enforce authorization for all path normalizations.",
                        cwe_id="CWE-285",
                    ))
                    break
            except requests.RequestException:
                continue

        for hname, hvalue in BYPASS_HEADERS:
            val = hvalue if hvalue is not None else path
            try:
                resp = session.get(base + "/", headers={hname: val}, timeout=timeout, allow_redirects=False)
                if resp.status_code in (200, 201, 301, 302, 401):
                    findings.append(Finding(
                        finding_type=FindingType.BYPASS_403,
                        severity=Severity.MEDIUM,
                        title="Possible 403 bypass via header",
                        description=f"{hname} returned {resp.status_code}. Server may use header for path.",
                        url=base + "/",
                        evidence=f"{hname}: {val}",
                        recommendation="Do not trust X-Original-URL / X-Rewrite-URL for authorization.",
                        cwe_id="CWE-285",
                    ))
                    break
            except requests.RequestException:
                continue

    return findings
