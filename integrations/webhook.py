#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse


def _validate_url(url: str) -> str | None:
    """Return an error message if *url* is not a safe http/https URL, else None."""
    if not url or not url.strip():
        return "URL must not be empty"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return f"URL scheme must be http or https, got {parsed.scheme!r}"
    if not parsed.netloc:
        return "URL must include a host"
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="POST magicid JSON findings to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https).")
    ap.add_argument("--header", action="append", default=[], help="Key: Value header.")
    args = ap.parse_args(argv)

    url_error = _validate_url(args.url)
    if url_error:
        print(f"webhook: invalid URL — {url_error}", file=sys.stderr)
        return 2

    raw = sys.stdin.read()
    if not raw.strip():
        print("webhook: stdin is empty — nothing to post", file=sys.stderr)
        return 2

    # Validate that stdin is well-formed JSON before sending.
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"webhook: stdin is not valid JSON: {exc}", file=sys.stderr)
        return 2

    payload = raw.encode("utf-8")
    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        if not k.strip():
            print(f"webhook: malformed --header value (missing key): {h!r}", file=sys.stderr)
            return 2
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as exc:
        print(f"webhook: HTTP {exc.code} {exc.reason} from {args.url}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"webhook: connection error: {exc.reason}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"webhook: unexpected error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
