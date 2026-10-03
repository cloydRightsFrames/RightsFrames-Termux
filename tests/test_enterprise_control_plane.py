from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from enterprise.control_plane.audit import AuditLog
from enterprise.control_plane.health import readiness
from enterprise.control_plane.policy import evaluate, load_policy
from enterprise.control_plane.provenance import sha256_file

def test_audit_round_trip(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")

    log.append(
        "test",
        "pytest",
        "allow",
        {"case": 1},
    )

    log.append(
        "test",
        "pytest",
        "observe",
        {"case": 2},
    )

    assert log.verify() == (
        True,
        "verified 2 events",
    )

def test_audit_tamper(tmp_path):
    path = tmp_path / "audit.jsonl"

    log = AuditLog(path)
    log.append("test", "pytest", "allow")

    data = path.read_text()
    path.write_text(
        data.replace(
            '"outcome":"allow"',
            '"outcome":"deny"',
        )
    )

    assert log.verify()[0] is False

def test_policy_fail_closed():
    policy = load_policy(
        ROOT / "enterprise/policy.json"
    )

    result = evaluate(
        policy,
        {
            "clean_worktree": True,
            "immutable_actions": True,
            "pinned_dependencies": True,
            "tests_pass": False,
            "provenance_record": True,
        },
    )

    assert result["allowed"] is False
    assert result["failures"] == [
        "tests_pass"
    ]

def test_readiness():
    result = readiness(
        {
            "ok": lambda: "ready",
            "bad": lambda: (
                _ for _ in ()
            ).throw(
                RuntimeError("no")
            ),
        }
    )

    assert result["ready"] is False

def test_provenance_digest(tmp_path):
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"rightsframes")

    digest = sha256_file(artifact)

    assert len(digest) == 64
