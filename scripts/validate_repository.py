#!/usr/bin/env python3
"""Validate Secure AI Toolkit structure against catalog/skills.json.

Stdlib only. Exit 0 on success, 1 on validation failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog" / "skills.json"
SCHEMA_PATH = ROOT / "catalog" / "skills.schema.json"
CATEGORIES = ("core", "advanced", "enterprise", "architecture")
REQUIRED_FILES = (
    "SKILL.md",
    "README.md",
    "checklist.md",
    "best-practices.md",
    "common-mistakes.md",
    "troubleshooting.md",
    "prompts.md",
    "examples/README.md",
)
# New skills should ship references/README.md; legacy skills may only have
# pinned standard files under references/.
SCAFFOLD_PATH = ROOT / "skills" / "shared" / "templates" / "skill-scaffold"
# Only match authoring placeholders, not documentation that mentions angle-bracket
# tokens such as WSTG-<CATEGORY>-<NN>.
PLACEHOLDER_RE = re.compile(
    r"(?:^|\s)(?:name:\s*)?<skill-name>\b|<Skill Name>|<standard ID>|Lorem ipsum",
    re.IGNORECASE,
)
FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
FORBIDDEN_TOOLS = re.compile(r"\b(Write|Edit)\b")
PILOT_OWNERSHIP_SKILLS = {
    "redis-security",
    "api-security",
    "authentication",
    "ai-security",
    "email-security",
    "http-client-security",
}
OWNERSHIP_HEADING = "## Ownership Boundary"
GRAPH_START = "<!-- GENERATED SKILL GRAPH: START -->"
GRAPH_END = "<!-- GENERATED SKILL GRAPH: END -->"


def catalog_ref(ref: str) -> str:
    """Return the canonical catalog name from a human-readable graph reference."""
    return bare_name(ref)


def normalized_refs(refs: list[str]) -> list[str]:
    return [catalog_ref(ref) for ref in refs]


def section_after_heading(text: str, heading: str) -> str:
    match = re.search(
        rf"^{re.escape(heading)}\s*$\n(.*?)(?=^##\s|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(1) if match else ""


def ownership_owner_ids(section: str) -> set[str]:
    return set(re.findall(r"`([a-z0-9]+(?:-[a-z0-9]+)*)`", section))


def render_graph(catalog: dict[str, Any]) -> str:
    """Render the catalog-owned relationship tables deterministically."""
    lines = [GRAPH_START, ""]
    for category in CATEGORIES:
        title = category.title() if category != "architecture" else "Architecture"
        lines.extend([f"## {title}", "", "| Skill | depends_on | related | loads |", "|---|---|---|---|"])
        for skill in (s for s in catalog["skills"] if s["category"] == category):
            def cell(values: list[str]) -> str:
                return ", ".join(f"`{value}`" for value in values) if values else "—"
            lines.append(
                f"| `{skill['name']}` | {cell(skill['depends_on'])} | "
                f"{cell(skill['related'])} | {', '.join(skill['loads']) or '—'} |"
            )
        lines.extend([""])
    lines.append(GRAPH_END)
    return "\n".join(lines)


def graph_with_generated_region(text: str, catalog: dict[str, Any]) -> str:
    generated = render_graph(catalog)
    pattern = re.compile(
        rf"{re.escape(GRAPH_START)}.*?{re.escape(GRAPH_END)}",
        re.DOTALL,
    )
    if not pattern.search(text):
        raise ValueError("skill graph has no generated-region markers")
    return pattern.sub(generated, text, count=1)


def validate_skill_graph(catalog: dict[str, Any], report: Report, write: bool = False) -> None:
    path = ROOT / "skills" / "shared" / "references" / "skill-graph.md"
    if not path.is_file():
        report.err("missing skills/shared/references/skill-graph.md")
        return
    text = path.read_text(encoding="utf-8")
    try:
        expected = graph_with_generated_region(text, catalog)
    except ValueError as exc:
        report.err(str(exc))
        return
    if write:
        if expected != text:
            path.write_text(expected, encoding="utf-8", newline="\n")
        return
    if expected != text:
        report.err("skill graph generated region is stale; run --write-skill-graph")


def report_boundaries(skills: dict[str, dict[str, Any]]) -> None:
    print("ownership boundaries:")
    for name in sorted(skills):
        ownership = skills[name].get("ownership")
        if not ownership:
            continue
        assets = "; ".join(ownership["protected_assets"])
        handoffs = ", ".join(
            f"{item['owner']} ({item['concern']})" for item in ownership["non_goals"]
        )
        related = ", ".join(skills[name]["related"]) or "—"
        print(f"  {name}: {ownership['owner_boundary']}")
        print(f"    assets: {assets}")
        print(f"    hand-offs: {handoffs}")
        print(f"    related: {related}")




class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def err(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    @property
    def ok(self) -> bool:
        return not self.errors


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def bare_name(ref: str) -> str:
    return ref.strip().strip("`").split("/")[-1]


def validate_schema_lite(catalog: dict[str, Any], report: Report) -> None:
    """Minimal schema checks without external jsonschema dependency."""
    if catalog.get("version") != 1 and not isinstance(catalog.get("version"), int):
        report.err("catalog.version must be an integer")
    profiles = catalog.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        report.err("catalog.profiles must be a non-empty object")
    skills = catalog.get("skills")
    if not isinstance(skills, list) or not skills:
        report.err("catalog.skills must be a non-empty array")
        return
    required = {
        "name",
        "category",
        "path",
        "status",
        "description",
        "triggers",
        "allowed_tools_profile",
        "depends_on",
        "related",
        "loads",
        "standards",
        "routing_hints",
    }
    seen: set[str] = set()
    for i, skill in enumerate(skills):
        if not isinstance(skill, dict):
            report.err(f"skills[{i}] must be an object")
            continue
        missing = required - set(skill)
        if missing:
            report.err(f"skills[{i}] missing fields: {sorted(missing)}")
        name = skill.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name or ""):
            report.err(f"skills[{i}].name invalid: {name!r}")
        elif name in seen:
            report.err(f"duplicate skill name in catalog: {name}")
        else:
            seen.add(name)
        cat = skill.get("category")
        if cat not in CATEGORIES:
            report.err(f"{name}: invalid category {cat!r}")
        path = skill.get("path")
        if path != f"skills/{cat}/{name}":
            report.err(f"{name}: path {path!r} must be skills/{cat}/{name}")
        profile = skill.get("allowed_tools_profile")
        if profile not in (profiles or {}):
            report.err(f"{name}: unknown allowed_tools_profile {profile!r}")
        standards = skill.get("standards")
        if not isinstance(standards, dict):
            report.err(f"{name}: standards must be an object")
        else:
            for key in (
                "owasp_top10_2025",
                "owasp_api_top10_2023",
                "asvs_5_0",
                "other",
            ):
                if key not in standards or not isinstance(standards[key], list):
                    report.err(f"{name}: standards.{key} must be an array")
        ownership = skill.get("ownership")
        if ownership is None:
            if name in PILOT_OWNERSHIP_SKILLS:
                report.err(f"{name}: pilot skill must define ownership metadata")
            elif skill.get("status") == "Ready":
                report.warn(f"{name}: Ready legacy skill has no ownership metadata")
            continue
        if not isinstance(ownership, dict):
            report.err(f"{name}: ownership must be an object")
            continue
        expected = {"owner_boundary", "protected_assets", "non_goals"}
        missing_ownership = expected - set(ownership)
        extras = set(ownership) - expected
        if missing_ownership:
            report.err(f"{name}: ownership missing fields: {sorted(missing_ownership)}")
        if extras:
            report.err(f"{name}: ownership has unsupported fields: {sorted(extras)}")
        boundary = ownership.get("owner_boundary")
        if not isinstance(boundary, str) or len(boundary.strip()) < 20:
            report.err(f"{name}: ownership.owner_boundary must be a specific non-empty statement")
        assets = ownership.get("protected_assets")
        if not isinstance(assets, list) or not assets or any(
            not isinstance(asset, str) or not asset.strip() for asset in assets
        ):
            report.err(f"{name}: ownership.protected_assets must be a non-empty string array")
        non_goals = ownership.get("non_goals")
        if not isinstance(non_goals, list) or not non_goals:
            report.err(f"{name}: ownership.non_goals must be a non-empty array")
        elif any(
            not isinstance(item, dict)
            or set(item) != {"concern", "owner"}
            or not isinstance(item.get("concern"), str)
            or not item["concern"].strip()
            or not isinstance(item.get("owner"), str)
            or not item["owner"].strip()
            for item in non_goals
        ):
            report.err(f"{name}: each ownership.non_goals item needs only non-empty concern and owner")


def discover_production_dirs() -> dict[str, Path]:
    found: dict[str, Path] = {}
    for cat in CATEGORIES:
        base = ROOT / "skills" / cat
        if not base.is_dir():
            continue
        for child in sorted(base.iterdir()):
            if child.is_dir() and (child / "SKILL.md").is_file():
                found[child.name] = child
    return found


def parse_frontmatter(text: str) -> dict[str, str]:
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        if not line.strip() or line.strip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        meta[key.strip()] = value.strip().strip("'\"")
    return meta


def validate_filesystem(catalog: dict[str, Any], report: Report) -> dict[str, dict[str, Any]]:
    skills = {s["name"]: s for s in catalog["skills"]}
    discovered = discover_production_dirs()

    cat_names = set(skills)
    disk_names = set(discovered)
    for extra in sorted(disk_names - cat_names):
        report.err(f"production skill on disk missing from catalog: {extra}")
    for missing in sorted(cat_names - disk_names):
        report.err(f"catalog skill missing on disk: {missing}")

    # Scaffold must exist and must not be counted as production.
    if not (SCAFFOLD_PATH / "SKILL.md").is_file():
        report.err(f"scaffold missing: {SCAFFOLD_PATH.relative_to(ROOT)}")
    if "skill-scaffold" in cat_names:
        report.err("scaffold must not appear in production catalog")

    counts = Counter(s["category"] for s in catalog["skills"])
    for cat in CATEGORIES:
        disk_count = sum(
            1 for p in discovered.values() if p.parent.name == cat
        )
        if counts[cat] != disk_count and cat_names <= disk_names:
            # only emit when sets mostly align; still useful
            pass

    for name, skill in skills.items():
        path = ROOT / skill["path"]
        if not path.is_dir():
            continue
        for rel in REQUIRED_FILES:
            if not (path / rel).is_file():
                report.err(f"{name}: missing required file {rel}")

        refs_dir = path / "references"
        if not refs_dir.is_dir():
            report.err(f"{name}: missing references/ directory")
        else:
            ref_files = [p for p in refs_dir.iterdir() if p.is_file()]
            if not ref_files:
                report.err(f"{name}: references/ has no files")

        skill_md = path / "SKILL.md"
        if not skill_md.is_file():
            continue
        text = skill_md.read_text(encoding="utf-8")
        meta = parse_frontmatter(text)
        if not meta:
            report.err(f"{name}: SKILL.md missing YAML frontmatter")
            continue
        if meta.get("name") != name:
            report.err(
                f"{name}: frontmatter name {meta.get('name')!r} must match directory"
            )
        profile_name = skill["allowed_tools_profile"]
        expected_tools = catalog["profiles"][profile_name]
        actual_tools = meta.get("allowed-tools", "")
        if actual_tools != expected_tools:
            report.err(
                f"{name}: allowed-tools mismatch for profile {profile_name}\n"
                f"  expected: {expected_tools}\n"
                f"  actual:   {actual_tools}"
            )
        if FORBIDDEN_TOOLS.search(actual_tools):
            report.err(f"{name}: allowed-tools must not grant Write/Edit")

        # Placeholder scan on production skill tree
        for md in path.rglob("*.md"):
            body = md.read_text(encoding="utf-8")
            if PLACEHOLDER_RE.search(body):
                report.err(
                    f"{md.relative_to(ROOT)}: leftover scaffold placeholder text"
                )

    return skills


def validate_graph_edges(skills: dict[str, dict[str, Any]], report: Report) -> None:
    names = set(skills)
    for name, skill in skills.items():
        for dep in skill.get("depends_on", []):
            b = bare_name(dep)
            if b not in names:
                report.err(f"{name}: depends_on unknown skill {dep!r}")
            if b == name:
                report.err(f"{name}: depends_on self")
        for rel in skill.get("related", []):
            b = bare_name(rel)
            if b not in names:
                report.err(f"{name}: related unknown skill {rel!r}")
            if b == name:
                report.err(f"{name}: related self")

        ownership = skill.get("ownership")
        if isinstance(ownership, dict):
            for item in ownership.get("non_goals", []):
                if not isinstance(item, dict) or not isinstance(item.get("owner"), str):
                    continue
                owner = item["owner"]
                if owner not in names:
                    report.err(f"{name}: non-goal hand-off references unknown skill {owner!r}")
                elif owner == name:
                    report.err(f"{name}: non-goal hand-off must not route to itself")

    visited: set[str] = set()
    active: set[str] = set()

    def visit(name: str) -> None:
        if name in active:
            report.err(f"depends_on cycle detected at {name}")
            return
        if name in visited:
            return
        active.add(name)
        for dependency in skills[name].get("depends_on", []):
            target = bare_name(dependency)
            if target in skills:
                visit(target)
        active.remove(name)
        visited.add(name)

    for name in skills:
        visit(name)

    for name, skill in skills.items():
        ownership = skill.get("ownership")
        if not isinstance(ownership, dict):
            continue
        handoff_owners = {
            item["owner"]
            for item in ownership.get("non_goals", [])
            if isinstance(item, dict) and isinstance(item.get("owner"), str)
        }
        if name in PILOT_OWNERSHIP_SKILLS:
            skill_md = ROOT / skill["path"] / "SKILL.md"
            section = section_after_heading(skill_md.read_text(encoding="utf-8"), OWNERSHIP_HEADING)
            if not section:
                report.err(f"{name}: SKILL.md missing {OWNERSHIP_HEADING}")
                continue
            if "| Concern | Route to |" not in section:
                report.err(f"{name}: ownership section must contain '| Concern | Route to |' table")
            documented = ownership_owner_ids(section)
            missing = handoff_owners - documented
            if missing:
                report.err(
                    f"{name}: ownership table does not route to catalog non-goal owners: {sorted(missing)}"
                )
        elif handoff_owners:
            report.warn(f"{name}: ownership metadata is present but SKILL.md ownership section is not yet required")


def validate_counts_in_docs(catalog: dict[str, Any], report: Report) -> None:
    total = len(catalog["skills"])
    by_cat = Counter(s["category"] for s in catalog["skills"])
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    # Flexible: accept either generated markers or prose counts.
    if f"All {total} skills" not in readme and f"all {total} skills" not in readme.lower():
        # common pattern "All 39 skills"
        m = re.search(r"All (\d+) skills", readme)
        if m and int(m.group(1)) != total:
            report.err(
                f"README.md skill total {m.group(1)} != catalog total {total}"
            )
        elif not m:
            report.warn("README.md has no 'All N skills' total sentence to check")

    for cat, n in by_cat.items():
        # e.g. `core/*` (18)
        pat = rf"`{cat}/\*`\s*\((\d+)\)"
        m = re.search(pat, readme)
        if m and int(m.group(1)) != n:
            report.err(
                f"README.md {cat} count {m.group(1)} != catalog {n}"
            )


def validate_internal_links(report: Report) -> None:
    """Check relative markdown links that point inside the repo."""
    roots = [
        ROOT / "README.md",
        ROOT / "AI_INSTRUCTIONS.md",
        ROOT / "CHANGELOG.md",
        ROOT / "SECURITY.md",
        ROOT / "MAINTENANCE.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "docs",
        ROOT / "skills",
        ROOT / "scripts" / "README.md",
        ROOT / "catalog",
    ]
    files: list[Path] = []
    for r in roots:
        if r.is_file():
            files.append(r)
        elif r.is_dir():
            files.extend(r.rglob("*.md"))

    for path in files:
        text = path.read_text(encoding="utf-8")
        # Parenthesized expressions in fenced code (for example `handler[route](arg)`) are
        # not Markdown links. Validate prose links only; fenced snippets are examples.
        prose = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
        for _label, target in MD_LINK_RE.findall(prose):
            target = target.strip()
            if not target or target.startswith(
                ("http://", "https://", "mailto:", "#", "http:")
            ):
                continue
            # strip anchors
            file_part = target.split("#", 1)[0]
            if not file_part:
                continue
            # ignore absolute FS
            if re.match(r"^[A-Za-z]:\\\\", file_part) or file_part.startswith("/"):
                continue
            resolved = (path.parent / file_part).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                # outside repo
                continue
            if not resolved.exists():
                report.err(
                    f"{path.relative_to(ROOT)}: broken link -> {target}"
                )


def validate_scaffold_tools(catalog: dict[str, Any], report: Report) -> None:
    scaffold = SCAFFOLD_PATH / "SKILL.md"
    if not scaffold.is_file():
        return
    meta = parse_frontmatter(scaffold.read_text(encoding="utf-8"))
    tools = meta.get("allowed-tools", "")
    # Scaffold should not request Write/Edit either.
    if FORBIDDEN_TOOLS.search(tools):
        report.err("skill-scaffold allowed-tools must not grant Write/Edit")
    research = catalog["profiles"].get("research-only")
    if research and tools and tools != research:
        report.warn(
            f"scaffold allowed-tools differs from research-only profile:\n"
            f"  {tools}"
        )


def changelog_text() -> str:
    return (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def latest_changelog_version() -> str:
    """Return the first released CHANGELOG version after Unreleased."""
    text = changelog_text()
    for match in re.finditer(r"^## \[v?(\d+\.\d+\.\d+)\].*?$", text, re.MULTILINE):
        return match.group(1)
    raise SystemExit("CHANGELOG.md has no released version section")


def extract_changelog_section(version: str) -> str:
    """Return the CHANGELOG body for version X.Y.Z (without the heading)."""
    text = changelog_text()
    # Accept ## [1.0.1] or ## [v1.0.1]
    ver = version.lstrip("v")
    pattern = re.compile(
        rf"^## \[v?{re.escape(ver)}\].*?$(.*?)(?=^## |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(text)
    if not m:
        raise SystemExit(f"CHANGELOG.md has no section for version {ver}")
    body = m.group(1).strip() + "\n"
    if not body.strip():
        raise SystemExit(f"CHANGELOG section for {ver} is empty")
    return body


def apply_frontmatter_profiles(catalog: dict[str, Any], report: Report, write: bool) -> None:
    """Rewrite production + scaffold allowed-tools to match profiles."""
    research = catalog["profiles"]["research-only"]
    for skill in catalog["skills"]:
        path = ROOT / skill["path"] / "SKILL.md"
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        expected = catalog["profiles"][skill["allowed_tools_profile"]]
        new_text, n = re.subn(
            r"^allowed-tools:.*$",
            f"allowed-tools: {expected}",
            text,
            count=1,
            flags=re.MULTILINE,
        )
        if n == 0:
            report.err(f"{skill['name']}: no allowed-tools line to update")
            continue
        if write and new_text != text:
            path.write_text(new_text, encoding="utf-8", newline="\n")
    scaffold = SCAFFOLD_PATH / "SKILL.md"
    if scaffold.is_file():
        text = scaffold.read_text(encoding="utf-8")
        new_text, n = re.subn(
            r"^allowed-tools:.*$",
            f"allowed-tools: {research}",
            text,
            count=1,
            flags=re.MULTILINE,
        )
        if write and n and new_text != text:
            scaffold.write_text(new_text, encoding="utf-8", newline="\n")


def print_summary(catalog: dict[str, Any]) -> None:
    by_cat = Counter(s["category"] for s in catalog["skills"])
    print(f"catalog skills: {len(catalog['skills'])}")
    for cat in CATEGORIES:
        print(f"  {cat}: {by_cat[cat]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-frontmatter",
        action="store_true",
        help="Rewrite SKILL.md allowed-tools to match catalog profiles",
    )
    parser.add_argument(
        "--extract-changelog",
        metavar="VERSION",
        help="Print CHANGELOG section for VERSION (e.g. 1.0.1 or v1.0.1) and exit",
    )
    parser.add_argument(
        "--latest-changelog-version",
        action="store_true",
        help="Print the first released CHANGELOG version after Unreleased and exit",
    )
    parser.add_argument(
        "--skip-links",
        action="store_true",
        help="Skip internal markdown link checks",
    )
    parser.add_argument(
        "--write-skill-graph",
        action="store_true",
        help="Regenerate the marked skill-graph region from catalog relationships",
    )
    parser.add_argument(
        "--report-boundaries",
        action="store_true",
        help="Print ownership-boundary metadata after validation",
    )
    args = parser.parse_args(argv)

    if args.extract_changelog:
        sys.stdout.write(extract_changelog_section(args.extract_changelog))
        return 0
    if args.latest_changelog_version:
        sys.stdout.write(latest_changelog_version() + "\n")
        return 0

    report = Report()
    if not CATALOG_PATH.is_file():
        print(f"ERROR: missing {CATALOG_PATH.relative_to(ROOT)}", file=sys.stderr)
        return 1
    if not SCHEMA_PATH.is_file():
        report.warn(f"missing schema file {SCHEMA_PATH.relative_to(ROOT)}")

    catalog = load_json(CATALOG_PATH)
    validate_schema_lite(catalog, report)
    if report.errors:
        for e in report.errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if args.write_frontmatter:
        apply_frontmatter_profiles(catalog, report, write=True)
        print("Wrote allowed-tools frontmatter from catalog profiles")
    if args.write_skill_graph:
        validate_skill_graph(catalog, report, write=True)
        if report.errors:
            for e in report.errors:
                print(f"ERROR: {e}", file=sys.stderr)
            return 1
        print("Wrote generated skill graph from catalog relationships")

    skills = validate_filesystem(catalog, report)
    validate_graph_edges(skills, report)
    validate_skill_graph(catalog, report)
    validate_counts_in_docs(catalog, report)
    validate_scaffold_tools(catalog, report)
    if not args.skip_links:
        validate_internal_links(report)

    print_summary(catalog)
    if args.report_boundaries:
        report_boundaries(skills)
    for w in report.warnings:
        print(f"WARNING: {w}", file=sys.stderr)
    for e in report.errors:
        print(f"ERROR: {e}", file=sys.stderr)

    if report.ok:
        print("OK: repository validation passed")
        return 0
    print(f"FAIL: {len(report.errors)} error(s)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
