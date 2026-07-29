from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "render_link_issue", ROOT / "scripts" / "render_link_issue.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_report(broken=None, blocked=None, transient=None):
    return {
        "schema_version": 1,
        "checked": 4,
        "healthy": [],
        "broken": broken if broken is not None else [],
        "transient": transient if transient is not None else [],
        "blocked": blocked if blocked is not None else [],
        "actionable_fingerprint": "fp-1",
    }


class RenderLinkIssueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.render = load_module()

    def run_render(self, report):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            report_path = out / "external-link-report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            code = self.render.main(
                [
                    "--report",
                    str(report_path),
                    "--run-url",
                    "https://example.invalid/run/1",
                    "--out-dir",
                    str(out),
                ]
            )
            self.assertEqual(code, 0)
            return (
                (out / "external-link-issue.md").read_text(encoding="utf-8"),
                (out / "has-actionable-failures").read_text(encoding="utf-8"),
                (out / "fingerprint").read_text(encoding="utf-8"),
            )

    def test_lines_reports_none_for_empty_set(self):
        self.assertEqual(self.render.lines([]), "- None")

    def test_lines_falls_back_to_detail_and_unknown_sources(self):
        rendered = self.render.lines(
            [{"url": "https://slow.example", "state": "transient", "detail": "timeout"}]
        )
        self.assertIn("transient: timeout", rendered)
        self.assertIn("sources: unknown", rendered)

    def test_clean_report_is_not_actionable(self):
        body, actionable, fingerprint = self.run_render(sample_report())
        self.assertEqual(actionable, "no")
        self.assertEqual(fingerprint, "fp-1")
        self.assertIn("<!-- actionable-fingerprint: fp-1 -->", body)
        self.assertIn("## Actionable failures\n- None", body)

    def test_broken_and_blocked_targets_are_actionable(self):
        report = sample_report(
            broken=[
                {
                    "url": "https://gone.example/x",
                    "state": "broken",
                    "status": 404,
                    "sources": ["README.md"],
                }
            ],
            blocked=[
                {
                    "url": "http://127.0.0.1/admin",
                    "state": "blocked",
                    "detail": "non-public or malformed target",
                    "sources": ["skills/x.md"],
                }
            ],
        )
        body, actionable, _ = self.run_render(report)
        self.assertEqual(actionable, "yes")
        self.assertIn("broken: 404 (sources: README.md)", body)
        self.assertIn("blocked: non-public or malformed target", body)

    def test_transient_only_report_stays_non_actionable(self):
        report = sample_report(
            transient=[{"url": "https://slow.example", "state": "transient", "detail": "timeout"}]
        )
        body, actionable, _ = self.run_render(report)
        self.assertEqual(actionable, "no")
        self.assertIn("## Actionable failures\n- None", body)
        self.assertIn("https://slow.example", body)


if __name__ == "__main__":
    unittest.main()
