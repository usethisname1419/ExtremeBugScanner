"""URL discovery and crawling for scan targets."""

import re
from urllib.parse import urljoin, urlparse
from typing import Generator

import requests
from bs4 import BeautifulSoup

from .models import ScanResult


def normalize_url(url: str) -> str:
    """Normalize URL for deduplication."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    path = path.rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def extract_links(
    base_url: str,
    html: str,
    follow_external: bool = False,
) -> set[str]:
    """Extract all links from HTML that belong to the same origin."""
    soup = BeautifulSoup(html, "lxml")
    base_domain = urlparse(base_url).netloc
    links = set()

    for tag, attr in [("a", "href"), ("form", "action"), ("link", "href"), ("script", "src"), ("img", "src")]:
        for el in soup.find_all(tag, **{attr: True}):
            href = el.get(attr, "").strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "data:")):
                continue
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.scheme not in ("http", "https"):
                continue
            if follow_external or parsed.netloc == base_domain:
                links.add(normalize_url(full_url))

    # Common path patterns for bug bounty
    for path in ["/admin", "/api", "/login", "/signup", "/config", "/.env", "/debug", "/backup"]:
        links.add(normalize_url(urljoin(base_url, path)))

    return links


def crawl(
    start_url: str,
    max_depth: int = 2,
    max_pages: int = 50,
    follow_external: bool = False,
    timeout: int = 10,
    user_agent: str | None = None,
) -> Generator[str, None, None]:
    """Crawl from start_url and yield URLs to scan."""
    headers = {"User-Agent": user_agent or "BugBountyScanner/1.0"} if user_agent else {}
    seen = {normalize_url(start_url)}
    queue = [(normalize_url(start_url), 0)]
    yielded = 0

    while queue and yielded < max_pages:
        url, depth = queue.pop(0)
        try:
            resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            resp.raise_for_status()
        except requests.RequestException:
            continue

        yield url
        yielded += 1

        if depth >= max_depth:
            continue

        try:
            new_links = extract_links(url, resp.text, follow_external=follow_external)
            for link in new_links:
                if link not in seen:
                    seen.add(link)
                    queue.append((link, depth + 1))
        except Exception:
            continue
