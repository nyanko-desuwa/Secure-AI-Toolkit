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


if __name__ == "__main__":
    unittest.main()
