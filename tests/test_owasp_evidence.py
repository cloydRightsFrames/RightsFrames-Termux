import copy
import datetime as dt
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "tools" / "rf_owasp_evidence.py"
SPEC = importlib.util.spec_from_file_location("rf_owasp_evidence", PATH)
e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e)


class OwaspEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.time = dt.datetime(2026, 10, 28, 6, tzinfo=dt.timezone.utc)
        self.metadata = {"prepared_at": (self.time - dt.timedelta(minutes=40)).isoformat(),
                         "packages": {"httpx==0.28.1": [{"file": "core/requirements-test.txt", "line": 27}]}}
        self.report = {"scanInfo": {"dataSource": [
            {"name": "NVD API Last Checked", "timestamp": self.time.isoformat()},
            {"name": "NVD API Last Modified", "timestamp": self.time.isoformat()}]},
            "dependencies": [{"packages": [{"id": "pkg:pypi/httpx@0.28.1"}]}]}
        self.log = "[INFO] Check for updates complete (20 ms)"

    def verify(self):
        return e.verify_report(self.report, self.metadata, self.log, self.time)

    def test_fresh_complete_report_passes(self):
        self.assertIn("NVD API Last Checked", self.verify())

    def test_cached_fallback_rejected_even_with_recent_timestamp(self):
        self.log += "\n[WARN] Unable to update 1 or more Cached Web DataSource, using local data instead."
        with self.assertRaises(ValueError):
            self.verify()

    def test_old_database_rejected(self):
        self.report["scanInfo"]["dataSource"][1]["timestamp"] = (self.time - dt.timedelta(days=2)).isoformat()
        with self.assertRaises(ValueError):
            self.verify()

    def test_check_from_previous_invocation_rejected(self):
        self.report["scanInfo"]["dataSource"][0]["timestamp"] = (self.time - dt.timedelta(hours=2)).isoformat()
        with self.assertRaises(ValueError):
            self.verify()

    def test_future_timestamp_rejected(self):
        self.report["scanInfo"]["dataSource"][0]["timestamp"] = (self.time + dt.timedelta(hours=1)).isoformat()
        with self.assertRaises(ValueError):
            self.verify()

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            e.timestamp("2026-10-28T06:00:00")

    def test_missing_dependency_rejected(self):
        self.report["dependencies"] = []
        with self.assertRaisesRegex(ValueError, "httpx"):
            self.verify()

    def test_scanner_exception_rejected(self):
        self.report["scanInfo"]["analysisExceptions"] = [{"exception": "failed"}]
        with self.assertRaises(ValueError):
            self.verify()

    def test_missing_update_completion_rejected(self):
        self.log = "[INFO] Analysis Complete"
        with self.assertRaises(ValueError):
            self.verify()

    def test_sarif_findings_preserved_and_mapped_to_real_lock_line(self):
        uri = "file:///github/workspace/core/requirements.txt:httpx/0.28.1"
        sarif = {"version": "2.1.0", "runs": [{"artifacts": [{"location": {"uri": uri}}],
            "results": [{"ruleId": "CVE-example", "level": "error", "message": {"text": "finding"},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri, "index": 0}}}]}]}]}
        before = copy.deepcopy(sarif)
        e.normalize_sarif(sarif, self.metadata["packages"])
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], before["runs"][0]["results"][0]["ruleId"])
        self.assertEqual(result["message"], before["runs"][0]["results"][0]["message"])
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        physical = result["locations"][0]["physicalLocation"]
        self.assertEqual(physical["artifactLocation"]["uri"], "core/requirements-test.txt")
        self.assertEqual(physical["region"], {"startLine": 27})
        self.assertEqual(physical["artifactLocation"]["properties"]["rfOriginalUri"], uri)

    def test_unknown_virtual_package_rejected(self):
        sarif = {"version": "2.1.0", "runs": [{"artifacts": [{"location": {
            "uri": "file:///github/workspace/core/requirements.txt:bogus/1"}}]}]}
        with self.assertRaises(ValueError):
            e.normalize_sarif(sarif, self.metadata["packages"])

    def test_lockfiles_unchanged_and_markers_included(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "core").mkdir()
            runtime = "httpx==0.28.1 \\\n    --hash=sha256:" + "a" * 64 + "\n"
            tests = "colorama==0.4.6 ; sys_platform == 'win32' \\\n    --hash=sha256:" + "b" * 64 + "\n"
            (root / e.LOCKS[0]).write_text(runtime)
            (root / e.LOCKS[1]).write_text(tests)
            packages, _ = e.read_locks(root)
            self.assertEqual(set(packages), {"httpx==0.28.1", "colorama==0.4.6"})
            self.assertEqual((root / e.LOCKS[0]).read_text(), runtime)
            self.assertEqual((root / e.LOCKS[1]).read_text(), tests)

    def test_unhashed_requirement_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "core").mkdir()
            (root / e.LOCKS[0]).write_text("httpx==0.28.1\n")
            with self.assertRaises(ValueError):
                e.read_locks(root)

    def test_secret_redaction(self):
        with patch.dict(os.environ, {"NVD_API_KEY": "test-only-not-a-key", "OSS_INDEX_TOKEN": "test-only-token"}):
            self.assertEqual(e.redact("test-only-not-a-key test-only-token"), "*** ***")


if __name__ == "__main__":
    unittest.main()
