"""Main scan engine: orchestrate crawl and checks."""

import time
from typing import Any

import requests
import yaml

from .models import ScanResult, Finding, Severity
from .crawler import crawl
from .checks import (
    check_headers,
    check_xss,
    check_sqli,
    check_secrets,
    check_ssl,
    check_cors,
    check_security_headers,
    check_info_disclosure,
    check_http_methods,
    check_open_redirect,
    check_ssrf,
    check_template_injection,
    check_bypass_403,
    check_upload,
)


def load_config(path: str = "config.yaml") -> dict[str, Any]:
    """Load YAML config. Returns defaults if file missing or YAML unavailable."""
    defaults = {
        "scanner": {"timeout": 10, "max_redirects": 5, "user_agent": "BugBountyScanner/1.0", "delay_between_requests": 0.5},
        "crawl": {"max_depth": 2, "max_pages": 50, "follow_external": False},
        "checks": {
            "xss": True, "sqli": True, "headers": True, "secrets": True,
            "ssl": True, "cors": True, "security_headers": True,
            "info_disclosure": True, "http_methods": True, "open_redirect": True,
            "ssrf": True, "template_injection": True, "upload": True, "bypass_403": True,
        },
        "severity_threshold": "info",
        "oast_url": "",  # Burp Collaborator, Interactsh, etc. for open redirect + SSRF
    }
    try:
        import yaml
    except ImportError:
        return defaults
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            if data:
                for k, v in defaults.items():
                    if k not in data:
                        data[k] = v
                return data
    except FileNotFoundError:
        pass
    return defaults


def severity_from_string(s: str) -> Severity:
    return getattr(Severity, s.upper(), Severity.INFO)


def run_scan(
    target_url: str,
    *,
    crawl_site: bool = True,
    config: dict[str, Any] | None = None,
    config_path: str = "config.yaml",
    oast_url: str | None = None,
    extreme: bool = False,
) -> ScanResult:
    """Run full scan on target URL. oast_url overrides config. extreme=enables many more payloads, SSTI, 403 bypass, uploads."""
    config = config or load_config(config_path)
    oast = (oast_url or config.get("oast_url") or "").strip()
    scanner_cfg = config.get("scanner", {})
    crawl_cfg = config.get("crawl", {})
    checks_cfg = config.get("checks", {})
    threshold = severity_from_string(config.get("severity_threshold", "info"))

    result = ScanResult(target=target_url)
    timeout = scanner_cfg.get("timeout", 10)
    user_agent = scanner_cfg.get("user_agent", "BugBountyScanner/1.0")
    delay = scanner_cfg.get("delay_between_requests", 0.5)

    session = requests.Session()
    session.headers["User-Agent"] = user_agent
    session.max_redirects = scanner_cfg.get("max_redirects", 5)

    urls_to_scan = [target_url]
    if crawl_site:
        try:
            for u in crawl(
                target_url,
                max_depth=crawl_cfg.get("max_depth", 2),
                max_pages=crawl_cfg.get("max_pages", 50),
                follow_external=crawl_cfg.get("follow_external", False),
                timeout=timeout,
                user_agent=user_agent,
            ):
                if u not in urls_to_scan:
                    urls_to_scan.append(u)
        except Exception as e:
            result.add_error(f"Crawl error: {e}")

    seen_urls = set()
    for url in urls_to_scan:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        result.urls_tested.append(url)

        try:
            resp = session.get(url, timeout=timeout)
        except requests.RequestException as e:
            result.add_error(f"{url}: {e}")
            continue

        # Header / CORS / Security headers / Info disclosure (no extra request)
        if checks_cfg.get("headers", True):
            for f in check_headers(url, resp):
                if _severity_rank(f.severity) >= _severity_rank(threshold):
                    result.add_finding(f)
        if checks_cfg.get("cors", True):
            for f in check_cors(url, resp):
                result.add_finding(f)
        if checks_cfg.get("security_headers", True):
            for f in check_security_headers(url, resp):
                result.add_finding(f)
        if checks_cfg.get("info_disclosure", True):
            for f in check_info_disclosure(url, resp):
                result.add_finding(f)

        # Checks that need session
        if checks_cfg.get("xss", True):
            for f in check_xss(url, session, extreme=extreme):
                result.add_finding(f)
        if checks_cfg.get("sqli", True):
            for f in check_sqli(url, session, extreme=extreme):
                result.add_finding(f)
        if checks_cfg.get("secrets", True):
            for f in check_secrets(url, session):
                result.add_finding(f)
        if checks_cfg.get("http_methods", True):
            for f in check_http_methods(url, session):
                result.add_finding(f)
        if checks_cfg.get("open_redirect", True):
            for f in check_open_redirect(url, session, oast_url=oast or None):
                result.add_finding(f)
        if checks_cfg.get("ssrf", True) and oast:
            for f in check_ssrf(url, oast, session):
                result.add_finding(f)
        if extreme:
            if checks_cfg.get("template_injection", True):
                for f in check_template_injection(url, session):
                    result.add_finding(f)
            for f in check_upload(url, session):
                result.add_finding(f)

        time.sleep(delay)

    # 403 bypass (once per host, uses base URL)
    if extreme:
        for f in check_bypass_403(target_url, session):
            result.add_finding(f)

    # SSL once per host
    if checks_cfg.get("ssl", True):
        for f in check_ssl(target_url, session):
            result.add_finding(f)

    return result


def _severity_rank(s: Severity) -> int:
    order = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    try:
        return order.index(s)
    except ValueError:
        return 0
