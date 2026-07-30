#!/usr/bin/env python3
"""Generate a machine-readable `skill.yaml` next to each skill's SKILL.md.

The catalog (`catalog/skills.json`) stays the single source of truth. This
script projects the catalog into a small, flat manifest that a router can read
without opening the prose SKILL.md: id, name, version, category, priority,
estimated_tokens, and the typed relationship edges (owns / requires / suggests
/ conflicts / frameworks).

Regenerate after editing the catalog; do not hand-edit `skill.yaml`.
`validate_repository.py` fails if a manifest drifts from the catalog.

Stdlib only. Exit 0 on success.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog" / "skills.json"
MANIFEST_VERSION = "1.0.0"

# Load-order weight. Higher wins when a context budget forces a choice. Mirrors
# the AI_INSTRUCTIONS.md loading budget (five core, two advanced, one
# enterprise, one architecture per task).
CATEGORY_PRIORITY = {
    "core": 100,
    "advanced": 70,
    "enterprise": 50,
    "architecture": 40,
}

SIMPLE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")

GENERATED_HEADER = (
    "# Generated from catalog/skills.json by scripts/generate_skill_manifests.py\n"
    "# Machine-readable manifest for the skill router. Edit the catalog, then\n"
    "# regenerate; do not hand-edit this file.\n"
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def bare_name(ref: str) -> str:
    return ref.strip().strip("`").split("/")[-1]


def emit_scalar(value: str) -> str:
    if value != "" and SIMPLE_TOKEN.match(value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def emit_list(key: str, items: list[str]) -> list[str]:
    if not items:
        return [f"{key}: []"]
    lines = [f"{key}:"]
    for item in items:
        lines.append(f"  - {emit_scalar(item)}")
    return lines


def estimate_tokens(skill_dir: Path) -> int:
    """Rough token estimate: SKILL.md + checklist.md characters over four."""
    chars = 0
    for rel in ("SKILL.md", "checklist.md"):
        path = skill_dir / rel
        if path.is_file():
            chars += len(path.read_text(encoding="utf-8"))
    return max(1, round(chars / 4))


def compute_priority(skill: dict[str, Any]) -> int:
    """Load-order weight derived from the skill's category."""
    return CATEGORY_PRIORITY.get(skill["category"], 10)


def compute_estimated_tokens(skill: dict[str, Any]) -> int:
    """Freshly measured token estimate for the skill on disk."""
    return estimate_tokens(ROOT / skill["path"])


def manifest_priority(skill: dict[str, Any]) -> int:
    """Prefer the catalog value (single source); fall back to computing it."""
    value = skill.get("priority")
    return value if isinstance(value, int) else compute_priority(skill)


def manifest_estimated_tokens(skill: dict[str, Any]) -> int:
    value = skill.get("estimated_tokens")
    return value if isinstance(value, int) else compute_estimated_tokens(skill)


def owns_tokens(skill: dict[str, Any]) -> list[str]:
    ownership = skill.get("ownership")
    if isinstance(ownership, dict):
        assets = ownership.get("protected_assets")
        if isinstance(assets, list) and assets:
            return [str(a) for a in assets]
    return []


def manifest_lines(skill: dict[str, Any]) -> list[str]:
    name = skill["name"]
    category = skill["category"]
    skill_dir = ROOT / skill["path"]
    requires = [bare_name(d) for d in skill.get("depends_on", [])]
    suggests = [bare_name(r) for r in skill.get("related", [])]

    lines: list[str] = [GENERATED_HEADER.rstrip("\n")]
    lines.append(f"id: {name}")
    lines.append(f"name: {name}")
    lines.append(f"version: {MANIFEST_VERSION}")
    lines.append(f"category: {category}")
    lines.append(f"path: {skill['path']}")
    lines.append(f"status: {skill['status']}")
    lines.append(f"priority: {manifest_priority(skill)}")
    lines.append(f"estimated_tokens: {manifest_estimated_tokens(skill)}")
    lines.extend(emit_list("owns", owns_tokens(skill)))
    lines.extend(emit_list("requires", requires))
    lines.extend(emit_list("suggests", suggests))
    lines.extend(emit_list("conflicts", []))
    lines.extend(emit_list("frameworks", []))
    return lines


def render_manifest(skill: dict[str, Any]) -> str:
    return "\n".join(manifest_lines(skill)) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit 1 if any manifest is missing or stale",
    )
    args = parser.parse_args(argv)

    catalog = load_json(CATALOG_PATH)
    stale: list[str] = []
    written = 0
    for skill in catalog["skills"]:
        skill_dir = ROOT / skill["path"]
        if not skill_dir.is_dir():
            print(f"WARNING: {skill['name']} path missing on disk, skipped", file=sys.stderr)
            continue
        target = skill_dir / "skill.yaml"
        expected = render_manifest(skill)
        current = target.read_text(encoding="utf-8") if target.is_file() else None
        if current == expected:
            continue
        if args.check:
            stale.append(skill["name"])
            continue
        target.write_text(expected, encoding="utf-8", newline="\n")
        written += 1

    if args.check:
        if stale:
            print("stale or missing skill.yaml: " + ", ".join(sorted(stale)), file=sys.stderr)
            return 1
        print("OK: all skill.yaml manifests match the catalog")
        return 0
    print(f"Wrote {written} skill.yaml manifest(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
