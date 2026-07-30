from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_repository", ROOT / "scripts" / "validate_repository.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_catalog():
    return {
        "version": 1,
        "profiles": {"research-only": "Read, Glob"},
        "skills": [
            {
                "name": "alpha",
                "category": "core",
                "path": "skills/core/alpha",
                "status": "Ready",
                "description": "A sample security skill with enough description.",
                "triggers": ["alpha"],
                "allowed_tools_profile": "research-only",
                "depends_on": [],
                "related": [],
                "loads": [],
                "standards": {
                    "owasp_top10_2025": [],
                    "owasp_api_top10_2023": [],
                    "asvs_5_0": [],
                    "other": [],
                },
                "routing_hints": ["Alpha surface"],
                "priority": 100,
                "estimated_tokens": 1234,
            }
        ],
    }


class ValidateRepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_module()

    def test_bare_name_handles_category_and_backticks(self):
        self.assertEqual(self.validator.bare_name("advanced/network-security"), "network-security")
        self.assertEqual(self.validator.bare_name("`api-security`"), "api-security")

    def test_schema_lite_rejects_missing_required_field(self):
        catalog = sample_catalog()
        del catalog["skills"][0]["routing_hints"]
        report = self.validator.Report()
        self.validator.validate_schema_lite(catalog, report)
        self.assertIn("missing fields", "\n".join(report.errors))

    def test_schema_lite_requires_pilot_ownership(self):
        catalog = sample_catalog()
        catalog["skills"][0]["name"] = "api-security"
        catalog["skills"][0]["path"] = "skills/core/api-security"
        report = self.validator.Report()
        self.validator.validate_schema_lite(catalog, report)
        self.assertIn("pilot skill must define ownership metadata", "\n".join(report.errors))

    def test_schema_lite_rejects_empty_non_goal_owner(self):
        catalog = sample_catalog()
        skill = catalog["skills"][0]
        skill["ownership"] = {
            "owner_boundary": "Sample service trust boundary for test validation.",
            "protected_assets": ["sample state"],
            "non_goals": [{"concern": "other concern", "owner": ""}],
        }
        report = self.validator.Report()
        self.validator.validate_schema_lite(catalog, report)
        self.assertIn("non-empty concern and owner", "\n".join(report.errors))

    def test_graph_rejects_self_handoff_and_depends_cycle(self):
        first = copy.deepcopy(sample_catalog()["skills"][0])
        second = copy.deepcopy(first)
        second["name"] = "beta"
        second["path"] = "skills/core/beta"
        first["depends_on"] = ["beta"]
        second["depends_on"] = ["alpha"]
        first["ownership"] = {
            "owner_boundary": "Alpha boundary with a specific ownership statement.",
            "protected_assets": ["alpha state"],
            "non_goals": [{"concern": "self handoff", "owner": "alpha"}],
        }
        report = self.validator.Report()
        self.validator.validate_graph_edges({"alpha": first, "beta": second}, report)
        messages = "\n".join(report.errors)
        self.assertIn("must not route to itself", messages)
        self.assertIn("depends_on cycle", messages)

    def test_graph_rejects_dangling_conflict_edge(self):
        first = copy.deepcopy(sample_catalog()["skills"][0])
        first["conflicts"] = ["ghost"]
        report = self.validator.Report()
        self.validator.validate_graph_edges({"alpha": first}, report)
        self.assertIn("conflicts unknown skill", "\n".join(report.errors))

    def test_graph_rejects_asymmetric_conflict(self):
        first = copy.deepcopy(sample_catalog()["skills"][0])
        second = copy.deepcopy(first)
        second["name"] = "beta"
        second["path"] = "skills/core/beta"
        first["conflicts"] = ["beta"]
        second["conflicts"] = []
        report = self.validator.Report()
        self.validator.validate_graph_edges({"alpha": first, "beta": second}, report)
        self.assertIn("conflicts must be symmetric", "\n".join(report.errors))

    def test_graph_accepts_symmetric_conflict(self):
        first = copy.deepcopy(sample_catalog()["skills"][0])
        second = copy.deepcopy(first)
        second["name"] = "beta"
        second["path"] = "skills/core/beta"
        first["conflicts"] = ["beta"]
        second["conflicts"] = ["alpha"]
        report = self.validator.Report()
        self.validator.validate_graph_edges({"alpha": first, "beta": second}, report)
        self.assertNotIn("conflicts must be symmetric", "\n".join(report.errors))

    def test_graph_warns_on_one_directional_related(self):
        first = copy.deepcopy(sample_catalog()["skills"][0])
        second = copy.deepcopy(first)
        second["name"] = "beta"
        second["path"] = "skills/core/beta"
        first["related"] = ["beta"]
        second["related"] = []
        report = self.validator.Report()
        self.validator.validate_graph_edges({"alpha": first, "beta": second}, report)
        self.assertIn("one-directional related edge", "\n".join(report.warnings))

    def test_generated_graph_changes_when_relationship_changes(self):
        catalog = sample_catalog()
        text = "before\n<!-- GENERATED SKILL GRAPH: START -->\nstale\n<!-- GENERATED SKILL GRAPH: END -->\nafter\n"
        generated = self.validator.graph_with_generated_region(text, catalog)
        self.assertIn("| `alpha` |", generated)
        self.assertNotIn("stale", generated)

    def test_section_after_heading_and_owner_ids(self):
        text = "## Ownership Boundary\n\n| Concern | Route to |\n|---|---|\n| A | `api-security` |\n\n## Next\n"
        section = self.validator.section_after_heading(text, "## Ownership Boundary")
        self.assertEqual(self.validator.ownership_owner_ids(section), {"api-security"})

    def test_latest_changelog_version_uses_first_released_section(self):
        original = self.validator.changelog_text
        self.validator.changelog_text = lambda: "# Changelog\n\n## [Unreleased]\n\n## [1.2.3] - 2026-07-29\n"
        try:
            self.assertEqual(self.validator.latest_changelog_version(), "1.2.3")
        finally:
            self.validator.changelog_text = original

    def test_parse_simple_yaml_round_trips_scalars_and_lists(self):
        text = (
            "# comment line, ignored\n"
            "id: alpha\n"
            "priority: 100\n"
            'owns:\n  - "Quoted, with comma"\n  - plain-token\n'
            "requires: []\n"
        )
        data = self.validator.parse_simple_yaml(text)
        self.assertEqual(data["id"], "alpha")
        self.assertEqual(data["priority"], "100")
        self.assertEqual(data["owns"], ["Quoted, with comma", "plain-token"])
        self.assertEqual(data["requires"], [])

    def test_parse_simple_yaml_unescapes_embedded_quotes(self):
        data = self.validator.parse_simple_yaml('name: "a \\"q\\" b"\n')
        self.assertEqual(data["name"], 'a "q" b')

    def test_parse_simple_yaml_rejects_dangling_list_item(self):
        with self.assertRaises(ValueError):
            self.validator.parse_simple_yaml("id: alpha\n  - orphan\n")

    def test_parse_simple_yaml_rejects_stray_indentation(self):
        with self.assertRaises(ValueError):
            self.validator.parse_simple_yaml("  unexpected: indent\n")

    def test_manifest_matches_generator_output_for_catalog(self):
        catalog = self.validator.load_json(self.validator.CATALOG_PATH)
        generator = self.validator.load_manifest_generator()
        for skill in catalog["skills"]:
            manifest_path = self.validator.ROOT / skill["path"] / "skill.yaml"
            self.assertTrue(
                manifest_path.is_file(), f"{skill['name']}: skill.yaml is missing"
            )
            expected = generator.render_manifest(skill)
            self.assertEqual(
                manifest_path.read_text(encoding="utf-8"),
                expected,
                f"{skill['name']}: skill.yaml drifted from the catalog",
            )
            parsed = self.validator.parse_simple_yaml(expected)
            self.assertEqual(parsed["id"], skill["name"])
            self.assertEqual(parsed["path"], skill["path"])
            self.assertEqual(
                parsed["requires"],
                [self.validator.bare_name(d) for d in skill["depends_on"]],
            )

    def test_compute_priority_maps_category_to_weight(self):
        generator = self.validator.load_manifest_generator()
        self.assertEqual(generator.compute_priority({"category": "core"}), 100)
        self.assertEqual(generator.compute_priority({"category": "advanced"}), 70)
        self.assertEqual(generator.compute_priority({"category": "enterprise"}), 50)
        self.assertEqual(generator.compute_priority({"category": "architecture"}), 40)

    def test_checklist_tier_regex_accepts_only_leading_tags(self):
        accept = self.validator.CHECKLIST_TIER_RE
        self.assertTrue(accept.match("[critical] Every object read is scoped"))
        self.assertTrue(accept.match("[recommended] Rate limiting on sensitive flows"))
        self.assertTrue(accept.match("[optional] Consider a WAF rule"))
        self.assertIsNone(accept.match("Every object read is scoped"))
        self.assertIsNone(accept.match("[urgent] not a real tier"))
        self.assertIsNone(accept.match("[critical]"))  # tag but no item text

    def test_validate_checklist_tiers_flags_untiered_item(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skills" / "core" / "alpha").mkdir(parents=True)
            checklist = root / "skills" / "core" / "alpha" / "checklist.md"
            checklist.write_text(
                "## Section\n\n"
                "- [ ] [critical] A tiered check the reviewer can answer\n"
                "- [ ] An untiered check that should be flagged\n",
                encoding="utf-8",
            )
            skill = copy.deepcopy(sample_catalog()["skills"][0])
            skill["path"] = "skills/core/alpha"
            original_root = self.validator.ROOT
            self.validator.ROOT = root
            try:
                report = self.validator.Report()
                self.validator.validate_checklist_tiers({"alpha": skill}, report)
            finally:
                self.validator.ROOT = original_root
            messages = "\n".join(report.errors)
            self.assertIn("checklist.md:4", messages)
            self.assertIn("not tiered", messages)
            self.assertNotIn("checklist.md:3", messages)

    # Glyph literals are written as \u escapes so this .py file itself stays
    # ASCII-clean and passes the glyph guard it is testing.
    def test_forbidden_glyph_flags_non_cp1252_symbols(self):
        forbidden = self.validator._is_forbidden_glyph
        self.assertTrue(forbidden(chr(0x2192)))  # arrow ->
        self.assertTrue(forbidden(chr(0x2500)))  # box drawing U+2500
        self.assertTrue(forbidden(chr(0xFFFD)))  # replacement character
        self.assertTrue(forbidden(chr(0x2265)))  # >= math operator

    def test_forbidden_glyph_allows_ascii_vietnamese_and_cp1252(self):
        forbidden = self.validator._is_forbidden_glyph
        self.assertFalse(forbidden("a"))
        self.assertFalse(forbidden("="))
        self.assertFalse(forbidden(chr(0x1EEB)))  # Vietnamese u with horn+hook (letter)
        self.assertFalse(forbidden(chr(0x00A7)))  # section sign (cp1252-safe)
        self.assertFalse(forbidden(chr(0x00D7)))  # multiplication sign (cp1252-safe)
        self.assertFalse(forbidden(chr(0x00B7)))  # middot (cp1252-safe)

    def test_validate_glyphs_flags_forbidden_and_ignores_allowed(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir(parents=True)
            (root / "docs" / "bad.md").write_text(
                "line one\nan arrow \u2192 here\n", encoding="utf-8"
            )
            (root / "docs" / "ok.md").write_text(
                "cp1252 fine: \u00a7 \u00d7 and Vietnamese t\u1eeb kho\u00e1\n",
                encoding="utf-8",
            )
            original_root = self.validator.ROOT
            self.validator.ROOT = root
            try:
                report = self.validator.Report()
                self.validator.validate_glyphs(report)
            finally:
                self.validator.ROOT = original_root
            messages = "\n".join(report.errors)
            self.assertIn("bad.md:2", messages)
            self.assertIn("U+2192", messages)
            self.assertNotIn("ok.md", messages)

    def test_catalog_budget_matches_computed_values(self):
        catalog = self.validator.load_json(self.validator.CATALOG_PATH)
        generator = self.validator.load_manifest_generator()
        for skill in catalog["skills"]:
            self.assertEqual(
                skill.get("priority"),
                generator.compute_priority(skill),
                f"{skill['name']}: catalog priority drifted from computed value",
            )
            self.assertEqual(
                skill.get("estimated_tokens"),
                generator.compute_estimated_tokens(skill),
                f"{skill['name']}: catalog estimated_tokens drifted; run --write-budget",
            )


if __name__ == "__main__":
    unittest.main()
