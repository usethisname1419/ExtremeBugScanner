#!/usr/bin/env python3
"""
Bug Bounty Security Scanner - CLI entry point.

Usage:
  python main.py https://example.com
  python main.py https://example.com --no-crawl
  python main.py https://example.com -o report.json
  python main.py https://example.com --config myconfig.yaml
"""

import argparse
import sys
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner.engine import run_scan, load_config
from scanner.report import print_console, write_json


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bug Bounty Security Scanner - Check for common vulnerabilities and misconfigurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        help="Only scan the given URL, do not crawl links",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write JSON report to FILE",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        metavar="FILE",
        help="Path to config YAML (default: config.yaml)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Only print summary; no finding details",
    )
    parser.add_argument(
        "--oast-url",
        metavar="URL",
        help="OAST URL (Burp Collaborator, Interactsh, etc.) for open redirect payload and SSRF callback detection. Overrides config.",
    )
    parser.add_argument(
        "--extreme",
        action="store_true",
        help="Run extreme mode: many more payloads, obfuscation, template injection ({{7*7}}), 403 bypass, and upload tests. Slower and noisier.",
    )
    args = parser.parse_args()

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    config_path = Path(args.config)
    if not config_path.is_file():
        config_path = Path(__file__).parent / "config.yaml"

    print("Loading config...")
    config = load_config(str(config_path))
    print(f"Scanning: {url} (crawl={not args.no_crawl}, extreme={args.extreme})")
    print("This may take a few minutes. Be respectful of rate limits.\n")

    result = run_scan(
        url,
        crawl_site=not args.no_crawl,
        config_path=str(config_path),
        oast_url=args.oast_url,
        extreme=args.extreme,
    )

    print_console(result)
    if args.output:
        write_json(result, args.output)
        print(f"\nJSON report written to {args.output}")

    return 0 if result.critical_count == 0 and result.high_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
