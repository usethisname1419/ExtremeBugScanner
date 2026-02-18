# Bug Bounty Security Scanner

A comprehensive, modular security scanner for bug bounty and penetration testing. It crawls a target (or scans a single URL), runs multiple checks, and outputs a detailed report.

## Features

- **Crawling**: Discovers links from the target page and common paths (e.g. `/admin`, `/api`, `/.env`) for in-scope scanning.
- **Vulnerability checks**:
  - **XSS**: Reflected XSS via parameter reflection (safe payloads for detection).
  - **SQL injection**: Error-based and basic boolean-based detection.
  - **Headers**: Server/X-Powered-By disclosure and other informative headers.
  - **Secrets**: Access to `/.env`, `/.git`, `/config`, etc., and patterns for API keys, credentials, private keys in responses.
  - **SSL/TLS**: Certificate validation, weak protocols, expiry.
  - **CORS**: Misconfigurations (e.g. `*` with credentials).
  - **Security headers**: Missing HSTS, X-Content-Type-Options, X-Frame-Options, CSP, etc.
  - **Info disclosure**: Stack traces, paths, debug info in responses.
  - **HTTP methods**: Allowed methods (TRACE, PUT, DELETE, etc.).

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt`

## Install

```bash
cd bugbounty-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Scan a target (crawl + all checks)
python main.py https://example.com

# Single URL only, no crawling
python main.py https://example.com --no-crawl

# Save JSON report
python main.py https://example.com -o report.json

# Custom config
python main.py https://example.com --config myconfig.yaml
```

## Configuration

Edit `config.yaml` to:

- Set **timeout**, **user-agent**, **delay** between requests.
- Tune **crawl** (max_depth, max_pages, follow_external).
- Enable/disable individual **checks** (xss, sqli, headers, secrets, ssl, cors, etc.).
- Set **severity_threshold** (info, low, medium, high, critical) to filter findings.

## Output

- **Console**: Summary counts and a table of findings, then detailed panels per finding (description, URL, evidence, recommendation, CWE).
- **JSON** (with `-o file.json`): Full result with `target`, `urls_tested`, `summary`, `findings`, `errors`.

## Responsible use

- Only scan targets you are **authorized** to test (e.g. bug bounty programs, your own assets).
- Respect **rate limits** and use `delay_between_requests` to avoid overloading servers.
- Findings are **indicative**; always verify manually before reporting.

## Extending

- Add new checks in `scanner/checks/` and register them in `scanner/checks/__init__.py` and `scanner/engine.py`.
- Use `Finding` and `FindingType` in `scanner/models.py` for consistent reporting.

## License

Use at your own risk. For authorized security testing only.
