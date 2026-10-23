import base64
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core import rf_core
from enterprise.control_plane import audit as audit_module
from enterprise.control_plane import cli
from enterprise.control_plane.audit import AuditLog


class _AcceptAllKey:
    """Stand-in verification key for tests that exercise non-signature anchor paths."""

    def verify(self, signature, message):
        return None


def test_rf_core_verify_anchors_allows_longer_current_ledger():
    anchor = {
        "schema": "rightsframes.anchor.v1",
        "seq": 1,
        "created_at": "2026-10-05T00:00:00Z",
        "ledger_count": 1,
        "ledger_head": "a" * 64,
        "prev_anchor_hash": "0" * 64,
        "anchor_hash": "b" * 64,
        "signature": base64.b64encode(b"signature").decode("ascii"),
    }

    class FakePublicKey:
        def verify(self, signature, message):
            return None

    class FakeCursor:
        def fetchone(self):
            return (2, "c" * 64)

    class FakeConnection:
        def execute(self, *args, **kwargs):
            return FakeCursor()

        def close(self):
            pass

    with patch.object(
        rf_core,
        "load_verification_key",
        return_value=(_AcceptAllKey(), b"", "unused"),
    ), patch.object(
        rf_core,
        "_read_anchors",
        return_value=[anchor],
    ), patch.object(
        rf_core,
        "_legacy_anchor_hash",
        return_value=anchor["anchor_hash"],
    ), patch.object(
        rf_core.secrets,
        "compare_digest",
        return_value=True,
    ), patch.object(
        Path,
        "read_bytes",
        return_value=b"public",
    ), patch.object(
        rf_core.serialization,
        "load_pem_public_key",
        return_value=FakePublicKey(),
    ), patch.object(
        rf_core,
        "_connect",
        return_value=FakeConnection(),
    ):
        assert rf_core.verify_anchors() == (True, "verified 1 anchors")


def test_audit_invalid_append_and_cleanup(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")

    with pytest.raises(ValueError, match="invalid audit event"):
        log.append("", "actor", "allow")

    log.append("initial", "actor", "allow")

    with patch.object(
        audit_module.os.path,
        "exists",
        return_value=True,
    ), patch.object(
        audit_module.os,
        "unlink",
    ) as unlink:
        log.append("action", "actor", "allow")

    unlink.assert_called_once()


def test_cli_main_unsupported():
    class FakeParser:
        def add_argument(self, *args, **kwargs):
            pass

        def parse_args(self):
            return SimpleNamespace(
                command="unsupported",
                policy=cli._DEFAULT_POLICY,
                audit=cli._DEFAULT_AUDIT,
            )

        def error(self, message):
            raise SystemExit(2)

    with patch.object(
        cli.argparse,
        "ArgumentParser",
        return_value=FakeParser(),
    ):
        with pytest.raises(SystemExit, match="2"):
            cli.main()

import asyncio
from types import SimpleNamespace

from starlette.responses import Response


def test_app_security_middleware_rejects_oversized_content_length():
    from core import app

    async def call_next(request):
        return Response(content="ok")

    request = SimpleNamespace(
        headers={"content-length": str(app.MAX_REQUEST_BYTES + 1)}
    )
    response = asyncio.run(app.security_middleware(request, call_next))

    assert response.status_code == 413


def test_app_security_middleware_rejects_invalid_content_length():
    from core import app

    async def call_next(request):
        return Response(content="ok")

    request = SimpleNamespace(
        headers={"content-length": "not-an-integer"}
    )
    response = asyncio.run(app.security_middleware(request, call_next))

    assert response.status_code == 400


def test_app_security_middleware_sets_security_headers():
    from core import app

    async def call_next(request):
        return Response(content="ok")

    request = SimpleNamespace(headers={})
    response = asyncio.run(app.security_middleware(request, call_next))

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")
    assert response.headers["Content-Security-Policy"].startswith("default-src")
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_envelope_verify_rejects_wrong_schema():
    from core.evidence.envelope import verify_envelope

    assert verify_envelope({"schema": "wrong"}) == (False, "schema")


def test_merkle_empty_tree_root_is_rfc9162_empty_hash():
    import hashlib

    from core.evidence.merkle import merkle_root

    assert merkle_root([]) == hashlib.sha256(b"").hexdigest()


def test_merkle_verify_proof_rejects_invalid_tree_size():
    from core.evidence.merkle import MerkleProof, verify_proof

    proof = MerkleProof(
        leaf_hash="a" * 64,
        leaf_index=0,
        tree_size=0,
        siblings=[],
    )

    assert verify_proof(proof, "a" * 64) is False


def test_merkle_verify_proof_rejects_invalid_leaf_index():
    from core.evidence.merkle import MerkleProof, verify_proof

    proof = MerkleProof(
        leaf_hash="a" * 64,
        leaf_index=2,
        tree_size=2,
        siblings=[],
    )

    assert verify_proof(proof, "a" * 64) is False

def test_rf_core_init_db_rolls_back_and_closes_on_failure():
    from core import rf_core

    class FakeConnection:
        def __init__(self):
            self.rolled_back = False
            self.closed = False

        def execute(self, *args, **kwargs):
            raise RuntimeError("execute failure")

        def rollback(self):
            self.rolled_back = True

        def commit(self):
            raise AssertionError("commit must not run")

        def close(self):
            self.closed = True

    conn = FakeConnection()

    with patch.object(rf_core.sqlite3, "connect", return_value=conn):
        with pytest.raises(RuntimeError, match="execute failure"):
            rf_core.init_db()

    assert conn.rolled_back is True
    assert conn.closed is True


def test_rf_core_connect_closes_on_pragma_failure():
    from core import rf_core

    class FakeConnection:
        def __init__(self):
            self.closed = False
            self.calls = []

        def execute(self, statement, *args, **kwargs):
            self.calls.append(statement)
            raise RuntimeError("pragma failure")

        def close(self):
            self.closed = True

    conn = FakeConnection()

    with patch.object(rf_core, "init_db"), patch.object(
        rf_core.sqlite3,
        "connect",
        return_value=conn,
    ):
        with pytest.raises(RuntimeError, match="pragma failure"):
            rf_core._connect()

    assert conn.closed is True


def test_rf_core_verify_anchors_rejects_malformed_anchor():
    from core import rf_core

    with patch.object(
        rf_core,
        "load_verification_key",
        return_value=(_AcceptAllKey(), b"", "unused"),
    ), patch.object(
        rf_core,
        "_read_anchors",
        return_value=[{"seq": "not-an-integer"}],
    ):
        ok, reason = rf_core.verify_anchors()

    assert ok is False
    assert reason == "anchor 1 malformed"


def test_rf_core_verify_anchors_rejects_sequence_mismatch():
    from core import rf_core

    anchor = {
        "seq": 2,
        "ledger_count": 0,
        "ledger_head": "0" * 64,
        "prev_anchor_hash": "0" * 64,
        "anchor_hash": "a" * 64,
        "signature": base64.b64encode(b"signature").decode("ascii"),
    }

    with patch.object(
        rf_core,
        "load_verification_key",
        return_value=(_AcceptAllKey(), b"", "unused"),
    ), patch.object(
        rf_core,
        "_read_anchors",
        return_value=[anchor],
    ):
        ok, reason = rf_core.verify_anchors()

    assert ok is False
    assert reason == "anchor sequence mismatch at 1"


def test_rf_core_verify_anchors_rejects_broken_chain():
    from core import rf_core

    anchor = {
        "seq": 1,
        "ledger_count": 0,
        "ledger_head": "0" * 64,
        "prev_anchor_hash": "x" * 64,
        "anchor_hash": "a" * 64,
        "signature": base64.b64encode(b"signature").decode("ascii"),
    }

    with patch.object(
        rf_core,
        "load_verification_key",
        return_value=(_AcceptAllKey(), b"", "unused"),
    ), patch.object(
        rf_core,
        "_read_anchors",
        return_value=[anchor],
    ):
        ok, reason = rf_core.verify_anchors()

    assert ok is False
    assert reason == "anchor chain broken at 1"


def test_rf_core_verify_anchors_rejects_ledger_count_regression():
    from core import rf_core

    anchors = [
        {
            "schema": "rightsframes.anchor.v1",
            "seq": 1,
            "created_at": "2026-10-05T00:00:00Z",
            "ledger_count": 5,
            "ledger_head": "a" * 64,
            "prev_anchor_hash": "0" * 64,
            "anchor_hash": "b" * 64,
            "signature": base64.b64encode(b"signature").decode("ascii"),
        },
        {
            "schema": "rightsframes.anchor.v1",
            "seq": 2,
            "created_at": "2026-10-05T00:01:00Z",
            "ledger_count": 4,
            "ledger_head": "c" * 64,
            "prev_anchor_hash": "b" * 64,
            "anchor_hash": "d" * 64,
            "signature": base64.b64encode(b"signature").decode("ascii"),
        },
    ]

    with patch.object(
        rf_core,
        "load_verification_key",
        return_value=(_AcceptAllKey(), b"", "unused"),
    ), patch.object(
        rf_core,
        "_read_anchors",
        return_value=anchors,
    ), patch.object(
        rf_core,
        "_legacy_anchor_hash",
        side_effect=lambda core: (
            "b" * 64 if core["seq"] == 1 else "d" * 64
        ),
    ), patch.object(
        rf_core.secrets,
        "compare_digest",
        return_value=True,
    ), patch.object(
        rf_core.Path,
        "read_bytes",
        return_value=b"public",
    ), patch.object(
        rf_core.serialization,
        "load_pem_public_key",
    ) as load_key:
        class FakePublicKey:
            def verify(self, signature, message):
                return None

        load_key.return_value = FakePublicKey()

        ok, reason = rf_core.verify_anchors()

    assert ok is False
    assert reason == "ledger count regressed at anchor 2"

def test_audit_verify_empty_file():
    log = AuditLog(tmp_path := Path.cwd() / "artifacts" / "apex" / "empty-audit-test.jsonl")
    tmp_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path.write_bytes(b"")
    try:
        assert log.verify() == (True, "verified 0 events")
    finally:
        tmp_path.unlink(missing_ok=True)


def test_audit_verify_skips_blank_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("action", "actor", "allow")
    path.write_bytes(path.read_bytes() + b"\n\n")
    assert log.verify() == (True, "verified 1 events")


def test_audit_verify_rejects_sequence_mismatch(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("action", "actor", "allow")

    import json

    event = json.loads(path.read_text().splitlines()[0])
    event["seq"] = 2
    path.write_text(json.dumps(event) + "\n")

    ok, reason = log.verify()
    assert ok is False
    assert reason == "sequence mismatch at 1"


def test_audit_verify_rejects_previous_hash_mismatch(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("action", "actor", "allow")

    import json

    event = json.loads(path.read_text().splitlines()[0])
    event["prev_hash"] = "x" * 64
    path.write_text(json.dumps(event) + "\n")

    ok, reason = log.verify()
    assert ok is False
    assert reason == "previous hash mismatch at 1"


def test_audit_verify_rejects_hash_mismatch(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("action", "actor", "allow")

    import json

    event = json.loads(path.read_text().splitlines()[0])
    event["action"] = "tampered"
    path.write_text(json.dumps(event) + "\n")

    ok, reason = log.verify()
    assert ok is False
    assert reason == "hash mismatch at 1"


def test_audit_verify_rejects_malformed_json(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("{not-json}\n")

    log = AuditLog(path)
    ok, reason = log.verify()

    assert ok is False
    assert reason.startswith("invalid audit log:")


def test_audit_verify_handles_os_error(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("{}\n")

    log = AuditLog(path)

    with patch.object(Path, "open", side_effect=OSError("read failure")):
        ok, reason = log.verify()

    assert ok is False
    assert reason == "invalid audit log: read failure"

def test_audit_last_skips_blank_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("action", "actor", "allow")
    path.write_bytes(path.read_bytes() + b"\n\n")

    assert log._last()["action"] == "action"


def test_audit_append_rejects_invalid_outcome(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")

    with pytest.raises(ValueError, match="invalid audit event"):
        log.append("action", "actor", "invalid")

def test_audit_append_creates_new_log_without_existing_file(tmp_path):
    path = tmp_path / "new-audit.jsonl"
    log = AuditLog(path)

    event = log.append("action", "actor", "allow")

    assert path.exists()
    assert event["seq"] == 1
    assert log.verify() == (True, "verified 1 events")

def test_audit_verify_nonexistent_log_is_empty(tmp_path):
    log = AuditLog(tmp_path / "does-not-exist.jsonl")

    assert log.verify() == (True, "empty")


def test_cli_workflow_immutable_no_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli._workflow_actions_immutable() is False


def test_cli_workflow_immutable_read_error(tmp_path, monkeypatch):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / "test.yml"
    workflow.write_text("uses: actions/checkout@0000000000000000000000000000000000000000\n")
    monkeypatch.chdir(tmp_path)

    with patch.object(Path, "read_text", side_effect=OSError("read failed")):
        assert cli._workflow_actions_immutable() is False


def test_cli_workflow_immutable_ignores_non_uses_lines(tmp_path, monkeypatch):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "test.yml").write_text(
        "name: test\n"
        "on: push\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo test\n"
    )
    monkeypatch.chdir(tmp_path)
    assert cli._workflow_actions_immutable() is True


def test_cli_workflow_immutable_missing_at_reference(tmp_path, monkeypatch):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "test.yml").write_text(
        "uses: actions/checkout\n"
    )
    monkeypatch.chdir(tmp_path)
    assert cli._workflow_actions_immutable() is False


def test_cli_workflow_immutable_empty_reference(tmp_path, monkeypatch):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "test.yml").write_text(
        "uses: actions/checkout@\n"
    )
    monkeypatch.chdir(tmp_path)
    assert cli._workflow_actions_immutable() is False


def test_cli_workflow_immutable_rejects_moving_ref(tmp_path, monkeypatch):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "test.yml").write_text(
        "uses: actions/checkout@main\n"
    )
    monkeypatch.chdir(tmp_path)
    assert cli._workflow_actions_immutable() is False


def test_cli_workflow_immutable_rejects_refs_namespace(tmp_path, monkeypatch):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "test.yml").write_text(
        "uses: actions/checkout@refs/heads/main\n"
    )
    monkeypatch.chdir(tmp_path)
    assert cli._workflow_actions_immutable() is False


def test_cli_workflow_immutable_rejects_non_hex_sha(tmp_path, monkeypatch):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "test.yml").write_text(
        "uses: actions/checkout@" + ("g" * 40) + "\n"
    )
    monkeypatch.chdir(tmp_path)
    assert cli._workflow_actions_immutable() is False


def test_cli_evaluate_facts_git_failure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch.object(cli, "_git_clean", side_effect=OSError("git unavailable")):
        facts = cli._evaluate_facts()
    assert facts["clean_worktree"] is False


def test_cli_evaluate_facts_workflow_failure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch.object(
        cli,
        "_workflow_actions_immutable",
        side_effect=OSError("workflow inspection failed"),
    ):
        facts = cli._evaluate_facts()
    assert facts["immutable_actions"] is False



def test_cli_evaluate_exception_returns_one(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    with patch.object(
        cli,
        "load_policy",
        side_effect=RuntimeError("policy load failed"),
    ):
        assert cli._evaluate(str(policy)) == 1
    output = capsys.readouterr().out
    assert '"allowed": false' in output
    assert "evaluation_error" in output


def test_cli_main_unsupported_returns_two_when_parser_error_returns():
    class FakeParser:
        def add_argument(self, *args, **kwargs):
            pass

        def parse_args(self):
            return SimpleNamespace(
                command="unsupported",
                policy=cli._DEFAULT_POLICY,
                audit=cli._DEFAULT_AUDIT,
            )

        def error(self, message):
            return None

    with patch.object(
        cli.argparse,
        "ArgumentParser",
        return_value=FakeParser(),
    ):
        assert cli.main() == 2



def test_rf_core_verify_anchors_load_failure():
    with patch.object(
        rf_core,
        "_read_anchors",
        return_value=[{"seq": 1}],
    ), patch.object(
        rf_core,
        "load_verification_key",
        side_effect=RuntimeError("key load failed"),
    ):
        assert rf_core.verify_anchors() == (
            False,
            "anchor verification initialization failed",
        )


def test_cli_readiness_exception_returns_one(capsys):
    with patch.object(
        cli,
        "readiness",
        side_effect=RuntimeError("readiness failed"),
    ):
        assert cli._readiness(cli._DEFAULT_POLICY) == 1
    output = capsys.readouterr().out
    assert '"ready": false' in output
    assert "readiness failed" in output


def test_verifier_proof_file_uses_audit_path(tmp_path):
    from verifier import evidence_verifier as verifier

    proof = tmp_path / "proof.json"
    proof.write_text(
        '{'
        '"audit_path": [],'
        '"leaf_index": 0,'
        '"tree_size": 1,'
        '"leaf_hash": "' + ("a" * 64) + '",'
        '"root_hash": "' + ("a" * 64) + '"'
        '}',
        encoding="utf-8",
    )

    with patch.object(verifier, "verify_proof", return_value=True):
        assert verifier.verify_proof_file(proof) == (False, "untrusted_root")
        assert verifier.verify_proof_file(
            proof, verifier.TrustStore(roots=["a" * 64])
        ) == (True, "valid;leaf_hash_not_bound_to_record")


def test_verifier_proof_file_missing_siblings(tmp_path):
    from verifier import evidence_verifier as verifier

    proof = tmp_path / "proof.json"
    proof.write_text("{}", encoding="utf-8")

    assert verifier.verify_proof_file(proof) == (
        False,
        "missing_siblings",
    )


def test_verifier_proof_file_invalid_siblings(tmp_path):
    from verifier import evidence_verifier as verifier

    proof = tmp_path / "proof.json"
    proof.write_text(
        '{"siblings": "not-a-list"}',
        encoding="utf-8",
    )

    assert verifier.verify_proof_file(proof) == (
        False,
        "invalid_siblings",
    )


def test_verifier_proof_file_invalid_proof(tmp_path):
    from verifier import evidence_verifier as verifier

    proof = tmp_path / "proof.json"
    proof.write_text(
        '{"siblings": [], "leaf_index": "bad", "tree_size": 1, '
        '"leaf_hash": "' + ("a" * 64) + '", '
        '"root_hash": "' + ("a" * 64) + '"}',
        encoding="utf-8",
    )

    assert verifier.verify_proof_file(
        proof, verifier.TrustStore(roots=["a" * 64])
    ) == (
        False,
        "invalid_proof",
    )


def test_cli_module_main_guard_and_return_two():
    import runpy

    class FakeParser:
        def add_argument(self, *args, **kwargs):
            pass

        def parse_args(self):
            return SimpleNamespace(
                command="unsupported",
                policy=cli._DEFAULT_POLICY,
                audit=cli._DEFAULT_AUDIT,
            )

        def error(self, message):
            return None

    with patch.object(
        cli.argparse,
        "ArgumentParser",
        return_value=FakeParser(),
    ):
        with patch("sys.argv", ["rf-control", "unsupported"]):
            with pytest.raises(SystemExit) as exc:
                runpy.run_module(
                    "enterprise.control_plane.cli",
                    run_name="__main__",
                )

    assert exc.value.code == 2


def test_verifier_module_main_guard():
    import runpy

    with patch("sys.argv", ["evidence_verifier"]):
        with pytest.raises(SystemExit) as exc:
            runpy.run_module(
                "verifier.evidence_verifier",
                run_name="__main__",
            )

    assert isinstance(exc.value.code, int)
