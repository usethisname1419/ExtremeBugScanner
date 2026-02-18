"""File upload vulnerability checks: dangerous extensions, content-type, and obfuscation."""

import requests
from urllib.parse import urlparse, urljoin

from ..models import Finding, FindingType, Severity


# Common upload paths to probe
UPLOAD_PATHS = [
    "/upload", "/file", "/fileupload", "/attachment", "/attach", "/import",
    "/api/upload", "/api/file", "/user/upload", "/media", "/image", "/images",
    "/avatar", "/profile/photo", "/documents", "/files", "/attachment/upload",
]

# Dangerous extensions / filenames (server might execute or mis-handle)
DANGEROUS_FILENAMES = [
    "shell.php", "shell.phtml", "shell.phar", "shell.php5", "shell.php7",
    "shell.jpg.php", "shell.php.jpg", "shell.phtml", "shell.htaccess",
    "shell.svg", "shell.xhtml", "shell.shtml", "shell.jsp", "shell.jspx",
    "shell.asa", "shell.cer", "shell.cdx", "shell.htr", "shell.asa",
    "bounty.svg", "test.html", "test.xhtml", "shell.asp", "shell.aspx",
    "shell.jsp", "file.phtml", "image.php.gif", "shell%00.jpg", "shell.jpg%00.php",
    "shell.php%00", "shell.php.", "shell.php ", "shell.php\n", "shell.phar",
    ".htaccess", "web.config", "crossdomain.xml",
]

# Polyglot / content-type tricks: (filename, content_type, body)
UPLOAD_POLYGLOTS = [
    ("test.svg", "image/svg+xml", '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'),
    ("test.svg", "image/svg+xml", '<svg><script>alert(1)</script></svg>'),
    ("test.html", "text/html", "<script>alert(1)</script>"),
    ("test.jpg", "image/jpeg", "GIF89a<script>alert(1)</script>"),
    ("test.gif", "image/gif", "GIF89a<script>alert(1)</script>"),
    ("test.png", "image/png", b"\x89PNG\r\n\x1a\n" + b"<script>alert(1)</script>".ljust(100)),
]

# Minimal file content to trigger "upload" (some endpoints need a body)
MINIMAL_BODY = b"bounty-scanner-upload-test"


def check_upload(base_url: str, session: requests.Session | None = None) -> list[Finding]:
    """
    Probe upload endpoints with dangerous filenames and content-type.
    Report if server accepts dangerous extension or reflects filename without sanitization.
    """
    findings = []
    session = session or requests.Session()
    p = urlparse(base_url)
    base = f"{p.scheme}://{p.netloc}"
    timeout = 10

    for up_path in UPLOAD_PATHS:
        url = urljoin(base + "/", up_path.lstrip("/"))
        for filename in DANGEROUS_FILENAMES[:20]:  # Limit requests
            try:
                files = {"file": (filename, MINIMAL_BODY, "application/octet-stream")}
                resp = session.post(url, files=files, timeout=timeout)
                if resp.status_code in (200, 201, 204):
                    # Check if filename appears in response (reflected without sanitization)
                    if filename in resp.text or filename.replace("%00", "") in resp.text:
                        findings.append(Finding(
                            finding_type=FindingType.UPLOAD_ISSUE,
                            severity=Severity.MEDIUM,
                            title="Upload accepted with dangerous filename",
                            description=f"Endpoint accepted filename '{filename}'. Verify if executable.",
                            url=url,
                            evidence=f"Filename: {filename}, Status: {resp.status_code}",
                            recommendation="Validate and sanitize file extensions; store with safe names; disable execution in upload dir.",
                            cwe_id="CWE-434",
                        ))
                        break
                    if resp.status_code in (200, 201):
                        findings.append(Finding(
                            finding_type=FindingType.UPLOAD_ISSUE,
                            severity=Severity.LOW,
                            title="Upload endpoint may accept files",
                            description=f"POST to {up_path} returned {resp.status_code}. Confirm extension validation.",
                            url=url,
                            evidence=f"Tried: {filename}",
                            recommendation="Restrict allowed extensions and content-type; scan for malware.",
                            cwe_id="CWE-434",
                        ))
                        break
            except requests.RequestException:
                continue

        for filename, content_type, body in UPLOAD_POLYGLOTS[:3]:
            try:
                if isinstance(body, bytes):
                    files = {"file": (filename, body, content_type)}
                else:
                    files = {"file": (filename, body.encode() if isinstance(body, str) else body, content_type)}
                resp = session.post(url, files=files, timeout=timeout)
                if resp.status_code in (200, 201):
                    findings.append(Finding(
                        finding_type=FindingType.UPLOAD_ISSUE,
                        severity=Severity.HIGH,
                        title="Polyglot/svg upload accepted",
                        description=f"Upload of {filename} with script content returned {resp.status_code}. Check if executable.",
                        url=url,
                        evidence=f"{filename} ({content_type})",
                        recommendation="Block SVG/HTML with script; validate content, not only extension.",
                        cwe_id="CWE-434",
                    ))
                    break
            except requests.RequestException:
                continue

    return findings
