#!/usr/bin/env python3
"""Advisory external Markdown link checker.

Checks literal http(s) links outside fenced code blocks. It refuses local and private-network
literal IP targets, uses bounded concurrency, and writes a deterministic JSON report. It is for
scheduled CI maintenance, not for blocking releases or local repository validation.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import re
import socket
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
URL_RE = re.compile(r"https?://[^\s<>)\]}`\"']+", re.IGNORECASE)
USER_AGENT = "Secure-AI-Toolkit-link-checker/1.0"
REPORT_SCHEMA = 1


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Request | None:
        if not is_safe_url(newurl):
            raise URLError("redirect target is not a public hostname")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def markdown_files(root: Path | None = None) -> list[Path]:
    base = root or ROOT
    roots = [base / "README.md", base / "AI_INSTRUCTIONS.md", base / "CHANGELOG.md", base / "docs", base / "skills"]
    result: list[Path] = []
    for item in roots:
        if item.is_file():
            result.append(item)
        elif item.is_dir():
            result.extend(item.rglob("*.md"))
    return result


def extract_urls_with_sources(root: Path | None = None) -> dict[str, list[str]]:
    """Return URL -> sorted unique relative source paths."""
    base = root or ROOT
    found: dict[str, set[str]] = {}
    for path in markdown_files(base):
        prose = re.sub(r"```.*?```", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
        for match in URL_RE.findall(prose):
            url = match.rstrip(".,;:")
            rel = str(path.relative_to(base)).replace("\\", "/")
            found.setdefault(url, set()).add(rel)
    return {url: sorted(sources) for url, sources in sorted(found.items())}


def extract_urls(root: Path | None = None) -> list[str]:
    return list(extract_urls_with_sources(root))


def is_public_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    try:
        return is_public_ip(parsed.hostname)
    except ValueError:
        if parsed.hostname.lower() == "localhost":
            return False
        try:
            addresses = {
                record[4][0]
                for record in socket.getaddrinfo(parsed.hostname, None, type=socket.SOCK_STREAM)
            }
        except socket.gaierror:
            # Let the request classify a public DNS outage as transient rather than treat an
            # unresolved name as a trusted destination.
            return True
        return bool(addresses) and all(is_public_ip(address) for address in addresses)


def classify(url: str, timeout: float, retries: int) -> dict[str, Any]:
    if not is_safe_url(url):
        return {"url": url, "state": "blocked", "detail": "non-public or malformed target"}
    opener = build_opener(SafeRedirect)
    last: str = ""
    for attempt in range(retries + 1):
        for method in ("HEAD", "GET"):
            try:
                request = Request(url, method=method, headers={"User-Agent": USER_AGENT})
                with opener.open(request, timeout=timeout) as response:
                    status = response.status
                    if 200 <= status < 400:
                        return {"url": url, "state": "healthy", "status": status}
                    last = f"HTTP {status}"
            except HTTPError as exc:
                if method == "HEAD" and exc.code in {405, 501}:
                    continue
                if exc.code in {404, 410}:
                    return {"url": url, "state": "broken", "status": exc.code}
                last = f"HTTP {exc.code}"
            except (URLError, TimeoutError, socket.timeout) as exc:
                last = type(exc).__name__
                break
        if attempt < retries:
            time.sleep(0.5 * (attempt + 1))
    return {"url": url, "state": "transient", "detail": last or "request failed"}


def actionable_fingerprint(broken: list[dict[str, Any]], blocked: list[dict[str, Any]]) -> str:
    """Stable fingerprint of the failure set that should drive issue updates."""
    keys = sorted(
        f"{item['state']}:{item['url']}:{item.get('status', item.get('detail', ''))}"
        for item in broken + blocked
    )
    digest = hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()
    return digest


def build_report(
    results: list[dict[str, Any]],
    sources: dict[str, list[str]],
) -> dict[str, Any]:
    for item in results:
        item["sources"] = sources.get(item["url"], [])
    broken = [item for item in results if item["state"] == "broken"]
    transient = [item for item in results if item["state"] == "transient"]
    blocked = [item for item in results if item["state"] == "blocked"]
    healthy = [item for item in results if item["state"] == "healthy"]
    return {
        "schema_version": REPORT_SCHEMA,
        "checked": len(results),
        "healthy": healthy,
        "broken": broken,
        "transient": transient,
        "blocked": blocked,
        "actionable_fingerprint": actionable_fingerprint(broken, blocked),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("external-link-report.json"))
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Optional repository root for tests and local fixtures",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve() if args.root else ROOT
    sources = extract_urls_with_sources(root)
    urls = list(sources)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        results = list(executor.map(lambda url: classify(url, args.timeout, args.retries), urls))
    report = build_report(results, sources)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "schema_version": report["schema_version"],
                "checked": report["checked"],
                "healthy": len(report["healthy"]),
                "broken": len(report["broken"]),
                "transient": len(report["transient"]),
                "blocked": len(report["blocked"]),
                "actionable_fingerprint": report["actionable_fingerprint"],
            }
        )
    )
    # The workflow owns issue lifecycle. Link reachability never makes this command fail.
    return 0


if __name__ == "__main__":
    sys.exit(main())
