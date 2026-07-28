from __future__ import annotations

import importlib.util
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "check_external_links", ROOT / "scripts" / "check_external_links.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExternalLinkCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checker = load_module()

    def test_extract_urls_ignores_fenced_code_and_keeps_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "docs").mkdir()
            (root / "README.md").write_text(
                "[one](https://example.com/one).\n```\nhttps://ignored.example/code\n```\n",
                encoding="utf-8",
            )
            (root / "docs" / "guide.md").write_text(
                "See https://example.com/one and https://example.org/two.\n",
                encoding="utf-8",
            )
            sources = self.checker.extract_urls_with_sources(root)

        self.assertEqual(
            sources,
            {
                "https://example.com/one": ["README.md", "docs/guide.md"],
                "https://example.org/two": ["docs/guide.md"],
            },
        )

    def test_private_and_loopback_targets_are_rejected(self):
        for url in (
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://localhost/",
        ):
            self.assertFalse(self.checker.is_safe_url(url), url)

    @patch("socket.getaddrinfo")
    def test_hostname_resolving_to_private_address_is_rejected(self, getaddrinfo):
        getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 0))]
        self.assertFalse(self.checker.is_safe_url("https://private.example/path"))

    def test_report_is_deterministic_and_fingerprint_ignores_transient_results(self):
        results = [
            {"url": "https://transient.example", "state": "transient", "detail": "HTTP 503"},
            {"url": "https://broken.example", "state": "broken", "status": 404},
            {"url": "http://127.0.0.1", "state": "blocked", "detail": "non-public"},
        ]
        report = self.checker.build_report(results, {item["url"]: ["README.md"] for item in results})
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["checked"], 3)
        self.assertEqual(report["broken"][0]["sources"], ["README.md"])
        expected = self.checker.actionable_fingerprint(report["broken"], report["blocked"])
        self.assertEqual(report["actionable_fingerprint"], expected)
        alternate = self.checker.build_report(
            [
                {"url": "https://different-transient.example", "state": "transient", "detail": "TimeoutError"},
                {"url": "https://broken.example", "state": "broken", "status": 404},
                {"url": "http://127.0.0.1", "state": "blocked", "detail": "non-public"},
            ],
            {},
        )
        self.assertEqual(report["actionable_fingerprint"], alternate["actionable_fingerprint"])

    def test_classify_blocks_unsafe_target_without_network(self):
        with patch.object(self.checker, "is_safe_url", return_value=False):
            result = self.checker.classify("http://127.0.0.1/", timeout=0.01, retries=0)
        self.assertEqual(result["state"], "blocked")

    def test_main_writes_json_report_without_network_for_local_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "README.md").write_text("https://127.0.0.1/\n", encoding="utf-8")
            output = root / "report.json"
            self.assertEqual(self.checker.main(["--root", str(root), "--output", str(output)]), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["blocked"][0]["url"], "https://127.0.0.1/")


if __name__ == "__main__":
    unittest.main()
