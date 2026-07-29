#!/usr/bin/env python3
"""Render the advisory external-link issue body from a link report.

Stdlib only. Kept as a file rather than an inline workflow heredoc: a Python
triple-quoted string has to start at column 0, which terminates a YAML block
scalar and makes the whole workflow unparseable.

Writes three files next to the report:
  external-link-issue.md    issue body
  has-actionable-failures   "yes" / "no"
  fingerprint               actionable fingerprint of the failure set
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

TEMPLATE = """# External link monitor

<!-- actionable-fingerprint: {fingerprint} -->

This is an advisory maintenance signal. It lists stable 404/410 failures and
blocked unsafe targets. Transient 429, 5xx, timeout, DNS, and bot-protection
results remain in the workflow artifact for human review and do not create
issue churn.

## Actionable failures
{actionable}

## Last observed transient results
{transient}

Checked {checked} links. [Workflow run]({run_url}).
"""


def lines(items: list[dict[str, Any]]) -> str:
    if not items:
        return "- None"
    return "\n".join(
        "- `{url}` - {state}: {detail} (sources: {sources})".format(
            url=item["url"],
            state=item["state"],
            detail=item.get("status", item.get("detail", "unknown")),
            sources=", ".join(item.get("sources", [])) or "unknown",
        )
        for item in items
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=Path("external-link-report.json"))
    parser.add_argument("--run-url", default="")
    parser.add_argument("--out-dir", type=Path, default=Path("."))
    args = parser.parse_args(argv)

    report = json.loads(args.report.read_text(encoding="utf-8"))
    actionable = report["broken"] + report["blocked"]
    body = TEMPLATE.format(
        fingerprint=report["actionable_fingerprint"],
        actionable=lines(actionable),
        transient=lines(report["transient"]),
        checked=report["checked"],
        run_url=args.run_url,
    )

    out = args.out_dir
    (out / "external-link-issue.md").write_text(body, encoding="utf-8", newline="\n")
    (out / "has-actionable-failures").write_text(
        "yes" if actionable else "no", encoding="utf-8", newline="\n"
    )
    (out / "fingerprint").write_text(
        report["actionable_fingerprint"], encoding="utf-8", newline="\n"
    )
    print(f"actionable={'yes' if actionable else 'no'} checked={report['checked']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
