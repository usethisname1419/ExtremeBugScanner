"""SSL/TLS configuration checks."""

import ssl
import socket
import requests

from ..models import Finding, FindingType, Severity


def check_ssl(url: str, session: requests.Session | None = None) -> list[Finding]:
    """Check SSL/TLS configuration of the host."""
    findings = []
    try:
        parsed = requests.utils.urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        port = parsed.port or (443 if parsed.scheme == "https" else 443)
        if ":" in hostname:
            hostname, _ = hostname.split(":", 1)
    except Exception:
        return findings

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()
    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            finding_type=FindingType.SSL_ISSUE,
            severity=Severity.HIGH,
            title="SSL certificate verification failed",
            description="Certificate is invalid or not trusted.",
            url=url,
            evidence=str(e),
            recommendation="Fix certificate chain and use a valid CA-signed cert.",
            cwe_id="CWE-295",
        ))
        return findings
    except (socket.timeout, OSError, ssl.SSLError) as e:
        findings.append(Finding(
            finding_type=FindingType.SSL_ISSUE,
            severity=Severity.INFO,
            title="SSL check failed",
            description="Could not complete TLS handshake.",
            url=url,
            evidence=str(e),
            cwe_id="CWE-295",
        ))
        return findings

    # Weak protocol
    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        findings.append(Finding(
            finding_type=FindingType.SSL_ISSUE,
            severity=Severity.MEDIUM,
            title="Weak TLS version",
            description=f"Server uses {version}. Prefer TLS 1.2+.",
            url=url,
            evidence=version,
            recommendation="Disable SSLv3 and TLS 1.0/1.1. Use TLS 1.2 or 1.3.",
            cwe_id="CWE-326",
        ))

    # Expired / soon to expire (basic check via cert dict)
    if cert:
        # cert is a dict with 'notAfter' etc.
        import datetime
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expire = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                if expire < datetime.datetime.now():
                    findings.append(Finding(
                        finding_type=FindingType.SSL_ISSUE,
                        severity=Severity.HIGH,
                        title="Expired SSL certificate",
                        description=f"Certificate expired on {not_after}.",
                        url=url,
                        evidence=not_after,
                        recommendation="Renew the SSL certificate.",
                        cwe_id="CWE-295",
                    ))
            except (ValueError, TypeError):
                pass

    return findings
