"""Check for exposed secrets and sensitive files."""

import re
import requests
from urllib.parse import urljoin, urlparse

from ..models import Finding, FindingType, Severity


# Common paths that may leak secrets
SECRET_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/config.json",
    "/config.yml",
    "/web.config",
    "/.htpasswd",
    "/backup.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/info.php",
    "/.aws/credentials",
    "/api/key",
    "/api/keys",
    "/.docker/config.json",
]

# Patterns for secrets in response body
SECRET_PATTERNS = [
    (re.compile(r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{20,})"), "AWS credentials"),
    (re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})"), "API key"),
    (re.compile(r"(?i)(secret|password|passwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})"), "Secret/password"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key"),
    (re.compile(r"(?i)(mongodb(\+srv)?|postgres|mysql)://[^\s]+"), "DB connection string"),
]


def check_secrets(url: str, session: requests.Session | None = None) -> list[Finding]:
    """Check for exposed secrets in common paths and in page content."""
    findings = []
    session = session or requests.Session()
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    for path in SECRET_PATHS:
        try:
            target = urljoin(base_url, path)
            resp = session.get(target, timeout=5)
            if resp.status_code == 200 and len(resp.content) > 0:
                findings.append(Finding(
                    finding_type=FindingType.SECRET_EXPOSED,
                    severity=Severity.HIGH if "key" in path or "secret" in path or "credential" in path else Severity.MEDIUM,
                    title=f"Potentially sensitive path accessible: {path}",
                    description=f"Path returned 200 and may contain secrets.",
                    url=target,
                    evidence=f"Status: {resp.status_code}, Length: {len(resp.content)}",
                    recommendation="Restrict access to config and secret files. Use env vars and secrets manager.",
                    cwe_id="CWE-798",
                ))
        except requests.RequestException:
            continue

    # Scan page body for secret patterns
    try:
        resp = session.get(url, timeout=10)
        for pattern, name in SECRET_PATTERNS:
            if pattern.search(resp.text):
                findings.append(Finding(
                    finding_type=FindingType.SECRET_EXPOSED,
                    severity=Severity.CRITICAL if "PRIVATE KEY" in name or "password" in name.lower() else Severity.HIGH,
                    title=f"Possible exposed secret: {name}",
                    description=f"Response may contain {name}. Verify manually.",
                    url=url,
                    evidence=name,
                    recommendation="Remove secrets from client-visible content. Use server-side only storage.",
                    cwe_id="CWE-798",
                ))
                break
    except requests.RequestException:
        pass

    return findings
