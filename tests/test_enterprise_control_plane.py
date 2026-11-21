"""The portable control-plane suite runs on Termux with the Python standard library."""
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from enterprise.control_plane.audit import AuditLog
from enterprise.control_plane.health import readiness
from enterprise.control_plane.policy import evaluate, load_policy
from enterprise.control_plane.provenance import sha256_file

ROOT = Path(__file__).resolve().parents[1]


class ControlPlaneTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def test_audit_round_trip(self):
        log = AuditLog(self.directory / "audit.jsonl")
        log.append("test", "runner", "allow", {"case": 1})
        log.append("test", "runner", "observe", {"case": 2})
        self.assertEqual(log.verify(), (True, "verified 2 events"))

    def test_audit_tamper(self):
        path = self.directory / "audit.jsonl"
        log = AuditLog(path)
        log.append("test", "runner", "allow")
        path.write_bytes(path.read_bytes().replace(b'"outcome":"allow"', b'"outcome":"deny"'))
        self.assertFalse(log.verify()[0])
        changed = path.read_bytes()
        with self.assertRaises(ValueError):
            log.append("later", "runner", "observe")
        self.assertEqual(path.read_bytes(), changed)

    def test_concurrent_audit_writers(self):
        path = self.directory / "audit.jsonl"
        start = Barrier(3)

        def write(worker):
            log = AuditLog(path)
            start.wait(timeout=10)
            return [log.append("measure", str(worker), "observe")["seq"] for _ in range(4)]

        with ThreadPoolExecutor(max_workers=3) as writers:
            sequences = list(writers.map(write, range(3)))
        self.assertEqual(sorted(n for batch in sequences for n in batch), list(range(1, 13)))
        self.assertEqual(AuditLog(path).verify(), (True, "verified 12 events"))

    def test_extend_a_complete_last_record_without_a_newline(self):
        path = self.directory / "audit.jsonl"
        log = AuditLog(path)
        log.append("first", "runner", "allow")
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
        log.append("second", "runner", "allow")
        self.assertEqual(log.verify(), (True, "verified 2 events"))

    def test_policy_fail_closed(self):
        policy = load_policy(ROOT / "enterprise/policy.json")
        facts = dict.fromkeys(policy["required"], True)
        facts["tests_pass"] = False
        result = evaluate(policy, facts)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["failures"], ["tests_pass"])

    def test_readiness(self):
        def unavailable():
            raise RuntimeError("unavailable")

        self.assertTrue(readiness({"available": lambda: True})["ready"])
        for probes in ({}, {"missing": lambda: False}, {"unknown": lambda: None},
                       {"available": lambda: True, "error": unavailable}):
            with self.subTest(probes=probes):
                self.assertFalse(readiness(probes)["ready"])

    def test_provenance_digest(self):
        artifact = self.directory / "artifact.bin"
        artifact.write_bytes(b"abc")
        self.assertEqual(sha256_file(artifact),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
