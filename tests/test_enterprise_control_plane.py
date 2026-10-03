from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enterprise.control_plane.audit import AuditLog
from enterprise.control_plane.health import readiness
from enterprise.control_plane.policy import evaluate, load_policy

def test_audit_round_trip(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("test", "pytest", "allow", {"case": 1})
    log.append("test", "pytest", "observe", {"case": 2})
    assert log.verify() == (True, "verified 2 events")

def test_audit_tamper(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("test", "pytest", "allow")
    text = path.read_text()
    path.write_text(text.replace("\"case\": 1", "\"case\": 9"))
    assert log.verify()[0] is False

def test_policy_fail_closed():
    policy = load_policy(Path("enterprise/policy.json"))
    result = evaluate(policy, {"clean_worktree": True, "immutable_actions": True, "pinned_dependencies": True, "tests_pass": False, "provenance_record": True})
    assert result["allowed"] is False
    assert result["failures"] == ["tests_pass"]

def test_readiness():
    result = readiness({"ok": lambda: "ready", "bad": lambda: (_ for _ in ()).throw(RuntimeError("no"))})
    assert result["ready"] is False
