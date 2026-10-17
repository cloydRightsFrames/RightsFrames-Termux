from __future__ import annotations

import asyncio
import json
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.requests import Request


def test_policy_load_paths(tmp_path):
    from enterprise.control_plane.policy import DEFAULT_POLICY, load_policy

    assert load_policy() == DEFAULT_POLICY

    good = tmp_path / "good.json"
    good.write_text(
        json.dumps(
            {
                "schema": "rf.policy.v1",
                "mode": "fail-closed",
                "rules": [],
            }
        ),
        encoding="utf-8",
    )
    assert load_policy(good)["schema"] == "rf.policy.v1"

    bad_schema = tmp_path / "bad-schema.json"
    bad_schema.write_text(
        json.dumps({"schema": "bad", "mode": "fail-closed"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported policy schema"):
        load_policy(bad_schema)

    bad_mode = tmp_path / "bad-mode.json"
    bad_mode.write_text(
        json.dumps({"schema": "rf.policy.v1", "mode": "fail-open"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="fail-closed"):
        load_policy(bad_mode)


def test_provenance_paths(monkeypatch, tmp_path):
    import enterprise.control_plane.provenance as p

    calls = []

    def fake_check_output(args, text=True):
        calls.append(args)
        values = {
            ("git", "rev-parse", "HEAD"): "abc123\n",
            ("git", "rev-parse", "HEAD^{tree}"): "tree123\n",
            ("git", "config", "--get", "remote.origin.url"):
                "https://github.com/cloydRightsFrames/RightsFrames-Termux.git\n",
        }
        return values[tuple(args)]

    monkeypatch.setattr(p.subprocess, "check_output", fake_check_output)

    identity = p.git_identity()
    assert identity == {"commit": "abc123", "tree": "tree123"}

    assert p._repo() == "cloydRightsFrames/RightsFrames-Termux"

    statement = p.statement(
        [{"name": "artifact", "digest": {"sha256": "deadbeef"}}],
        "https://example.invalid/artifact",
    )
    assert statement["_type"] == p.STATEMENT
    assert statement["subject"][0]["name"] == "artifact"
    assert statement["predicateType"] == "https://slsa.dev/provenance/v1"

    output = tmp_path / "statement.json"
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"rightsframes-apex-artifact")

    document = p.write_statement(
        output,
        artifact,
        "deadbeef",
    )
    assert output.exists()
    assert json.loads(output.read_text(encoding="utf-8")) == document
    assert calls


def test_provenance_repo_failure(monkeypatch):
    import enterprise.control_plane.provenance as p

    def fail(*args, **kwargs):
        raise RuntimeError("git unavailable")

    monkeypatch.setattr(p.subprocess, "check_output", fail)
    assert p._repo() == "unknown/unknown"


def _request(headers=None):
    raw_headers = []
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode(), str(value).encode()))

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/health",
        "raw_path": b"/health",
        "query_string": b"",
        "headers": raw_headers,
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "root_path": "",
    }
    return Request(scope)


def test_app_security_and_routes(monkeypatch):
    import core.app as appmod

    monkeypatch.setattr(appmod, "API_KEY", "apex-test-key")

    response = asyncio.run(
        appmod.security_middleware(
            _request({"content-length": "1"}),
            _next_ok,
        )
    )
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Permissions-Policy"]
    assert response.headers["Strict-Transport-Security"]
    assert response.headers["Content-Security-Policy"]
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"

    oversized = asyncio.run(
        appmod.security_middleware(
            _request({"content-length": str(appmod.MAX_REQUEST_BYTES + 1)}),
            _next_ok,
        )
    )
    assert oversized.status_code == 413

    invalid = asyncio.run(
        appmod.security_middleware(
            _request({"content-length": "not-a-number"}),
            _next_ok,
        )
    )
    assert invalid.status_code == 400

    monkeypatch.setattr(appmod, "health", lambda: {"status": "ok"})
    assert appmod.health_endpoint() == {"status": "ok"}

    monkeypatch.setattr(
        appmod,
        "append_entry",
        lambda entry_type, payload: {
            "entry_type": entry_type,
            "payload": payload,
        },
    )
    body = appmod.EntryRequest(entry_type="test", payload={"x": 1})
    assert appmod.create_entry(body, None, "apex-test-key") == {
        "entry_type": "test",
        "payload": {"x": 1},
    }

    monkeypatch.setattr(
        appmod,
        "create_anchor",
        lambda: {"anchor": "ok"},
    )
    assert appmod.anchor(None, "apex-test-key") == {"anchor": "ok"}


def _response():
    from starlette.responses import Response

    return Response("ok")


async def _next_ok(request):
    return _response()


def test_app_authentication_paths(monkeypatch):
    import core.app as appmod

    monkeypatch.setattr(appmod, "API_KEY", "")
    with pytest.raises(appmod.HTTPException) as exc:
        appmod._require_api_key(None, None)
    assert exc.value.status_code == 503

    monkeypatch.setattr(appmod, "API_KEY", "secret")

    with pytest.raises(appmod.HTTPException) as exc:
        appmod._require_api_key(None, None)
    assert exc.value.status_code == 401

    with pytest.raises(appmod.HTTPException) as exc:
        appmod._require_api_key("Basic secret", None)
    assert exc.value.status_code == 401

    appmod._require_api_key(None, "secret")
    appmod._require_api_key("Bearer secret", None)


def test_app_error_paths(monkeypatch):
    import core.app as appmod

    monkeypatch.setattr(appmod, "API_KEY", "secret")

    def bad_append(*args):
        raise ValueError("bad entry")

    monkeypatch.setattr(appmod, "append_entry", bad_append)

    with pytest.raises(appmod.HTTPException) as exc:
        appmod.create_entry(
            appmod.EntryRequest(entry_type="test", payload={}),
            None,
            "secret",
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "bad entry"

    def bad_anchor():
        raise ValueError("anchor conflict")

    monkeypatch.setattr(appmod, "create_anchor", bad_anchor)

    with pytest.raises(appmod.HTTPException) as exc:
        appmod.anchor(None, "secret")
    assert exc.value.status_code == 409


def test_cli_audit_verify(monkeypatch, capsys):
    import enterprise.control_plane.cli as cli

    monkeypatch.setattr(
        cli.AuditLog,
        "verify",
        lambda self: (True, "valid"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["rf-control", "audit-verify", "--audit", "audit.jsonl"],
    )
    assert cli.main() == 0
    assert '"ok": true' in capsys.readouterr().out

    monkeypatch.setattr(
        cli.AuditLog,
        "verify",
        lambda self: (False, "tampered"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["rf-control", "audit-verify", "--audit", "audit.jsonl"],
    )
    assert cli.main() == 1
    assert '"ok": false' in capsys.readouterr().out


def test_cli_readiness(monkeypatch, capsys):
    import enterprise.control_plane.cli as cli

    monkeypatch.setattr(
        cli,
        "readiness",
        lambda checks: {"ready": True, "checks": {"git": True}},
    )
    monkeypatch.setattr(sys, "argv", ["rf-control", "readiness"])
    assert cli.main() == 0
    assert '"ready": true' in capsys.readouterr().out

    monkeypatch.setattr(
        cli,
        "readiness",
        lambda checks: {"ready": False, "checks": {"git": False}},
    )
    monkeypatch.setattr(sys, "argv", ["rf-control", "readiness"])
    assert cli.main() == 1
    assert '"ready": false' in capsys.readouterr().out


def test_cli_evaluate_clean_and_immutable(monkeypatch, tmp_path, capsys):
    import enterprise.control_plane.cli as cli

    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "safe.yml").write_text("uses: actions/checkout@v4\n")

    monkeypatch.chdir(tmp_path)

    class Result:
        def __getitem__(self, key):
            if key == "allowed":
                return True
            raise KeyError(key)

    monkeypatch.setattr(cli, "evaluate", lambda policy, facts: Result())
    monkeypatch.setattr(
        cli,
        "load_policy",
        lambda path: {"schema": "rf.policy.v1", "mode": "fail-closed"},
    )
    monkeypatch.setattr(
        cli.subprocess,
        "check_output",
        lambda args, text=True: b"" if text is False else "",
    )
    monkeypatch.setattr(sys, "argv", ["rf-control", "evaluate"])
    assert cli.main() == 0
    assert "allowed" in capsys.readouterr().out


def test_cli_evaluate_detects_unpinned_workflow(monkeypatch, tmp_path, capsys):
    import enterprise.control_plane.cli as cli

    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "unsafe.yml").write_text(
        "uses: actions/checkout@main\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    seen = {}

    def fake_evaluate(policy, facts):
        seen.update(facts)
        return {"allowed": False, "reasons": ["immutable_actions"]}

    monkeypatch.setattr(cli, "evaluate", fake_evaluate)
    monkeypatch.setattr(
        cli,
        "load_policy",
        lambda path: {"schema": "rf.policy.v1", "mode": "fail-closed"},
    )
    monkeypatch.setattr(
        cli.subprocess,
        "check_output",
        lambda args, text=True: "",
    )
    monkeypatch.setattr(sys, "argv", ["rf-control", "evaluate"])
    assert cli.main() == 1
    assert seen["immutable_actions"] is False
    assert "allowed" in capsys.readouterr().out


def test_cli_evaluate_exception(monkeypatch, tmp_path, capsys):
    import enterprise.control_plane.cli as cli

    monkeypatch.chdir(tmp_path)

    def fail(*args, **kwargs):
        raise RuntimeError("git failure")

    monkeypatch.setattr(cli.subprocess, "check_output", fail)
    monkeypatch.setattr(
        cli,
        "evaluate",
        lambda policy, facts: {"allowed": False},
    )
    monkeypatch.setattr(
        cli,
        "load_policy",
        lambda path: {"schema": "rf.policy.v1", "mode": "fail-closed"},
    )
    monkeypatch.setattr(sys, "argv", ["rf-control", "evaluate"])
    assert cli.main() == 1
    assert "allowed" in capsys.readouterr().out


def test_verifier_file_wrappers(monkeypatch, tmp_path):
    import verifier.evidence_verifier as v

    envelope = tmp_path / "envelope.json"
    ledger = tmp_path / "ledger.json"
    proof = tmp_path / "proof.json"
    signature = tmp_path / "signature.json"

    envelope.write_text("{}", encoding="utf-8")
    ledger.write_text("[]", encoding="utf-8")
    proof.write_text(
        json.dumps(
            {
                "leaf_index": 0,
                "tree_size": 1,
                "leaf_hash": "00" * 32,
                "root_hash": "00" * 32,
                "audit_path": [],
            }
        ),
        encoding="utf-8",
    )
    signature.write_text(
        json.dumps(
            {
                "public_key": "00" * 32,
                "payload": "00",
                "signature": "00" * 64,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(v, "verify_envelope", lambda data: (True, "valid"))
    assert v.verify_envelope_file(envelope) == (True, "valid")

    monkeypatch.setattr(v, "verify_chain", lambda records: (True, "valid"))
    assert v.verify_ledger_file(ledger) == (True, "valid")

    monkeypatch.setattr(v, "verify_proof", lambda proof, root: True)
    assert v.verify_proof_file(proof) == (True, "valid")

    monkeypatch.setattr(v, "verify_signature", lambda *args: (True, "valid"))
    assert v.verify_signature_file(signature) == (True, "valid")


def test_verifier_main_all_targets(monkeypatch, tmp_path, capsys):
    import verifier.evidence_verifier as v

    files = {}
    for name in ("envelope", "ledger", "proof", "signature"):
        path = tmp_path / f"{name}.json"
        path.write_text("{}", encoding="utf-8")
        files[name] = path

    monkeypatch.setattr(
        v,
        "verify_envelope_file",
        lambda path: (True, "valid"),
    )
    monkeypatch.setattr(
        v,
        "verify_ledger_file",
        lambda path: (True, "valid"),
    )
    monkeypatch.setattr(
        v,
        "verify_proof_file",
        lambda path: (True, "valid"),
    )
    monkeypatch.setattr(
        v,
        "verify_signature_file",
        lambda path: (True, "valid"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evidence_verifier.py",
            "--envelope",
            str(files["envelope"]),
            "--ledger",
            str(files["ledger"]),
            "--proof",
            str(files["proof"]),
            "--signature",
            str(files["signature"]),
        ],
    )

    assert v.main() == 0
    output = capsys.readouterr().out
    assert "ENVELOPE_INTEGRITY=PASS:valid" in output
    assert "LEDGER_CONTINUITY=PASS:valid" in output
    assert "MERKLE_INCLUSION=PASS:valid" in output
    assert "SIGNATURE_VALIDITY=PASS:valid" in output
    assert "RIGHTSFRAMES_INDEPENDENT_VERIFIER=PASS" in output


def test_verifier_main_failure(monkeypatch, tmp_path, capsys):
    import verifier.evidence_verifier as v

    target = tmp_path / "x.json"
    target.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        v,
        "verify_envelope_file",
        lambda path: (False, "invalid"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["evidence_verifier.py", "--envelope", str(target)],
    )

    assert v.main() == 1
    output = capsys.readouterr().out
    assert "ENVELOPE_INTEGRITY=FAIL:invalid" in output
    assert "RIGHTSFRAMES_INDEPENDENT_VERIFIER=FAIL" in output


def test_verifier_main_requires_target(monkeypatch):
    import verifier.evidence_verifier as v

    monkeypatch.setattr(sys, "argv", ["evidence_verifier.py"])
    with pytest.raises(SystemExit) as exc:
        v.main()
    assert exc.value.code == 2


def test_repair_script(tmp_path, capsys):
    target = tmp_path / "workflow.sh"
    target.write_text(
        """#!/bin/sh
  enance/verify_release.sh &&
  printf '%s\\n' '=== STATUS ===' &&
  git status --short --branch
  mv \\
  "dist/RightsFrames-Termux-${GITHUB_REF_NAME}.tar.gz" \\
  "dist/RightsFrames-Termux-${GITHUB_REF_NAME}.tar.gz"
test "$(git rev-list -n1 "refs/tags/${TAG}")" = "${GITHUB_SHA}"
""",
        encoding="utf-8",
    )

    old_argv = sys.argv[:]
    try:
        sys.argv = ["rf_repair.py", str(target)]
        runpy.run_path("provenance/rf_repair.py", run_name="__main__")
    finally:
        sys.argv = old_argv

    result = target.read_text(encoding="utf-8")
    assert "enance/verify_release.sh" not in result
    assert "=== STATUS ===" not in result
    assert "git status --short --branch" not in result
    assert 'TAG_TARGET="$(git rev-parse "refs/tags/${TAG}^{commit}")"' in result
    assert "REPAIR=PASS" in capsys.readouterr().out

def test_evidence_envelope_production_paths():
    from core.evidence import envelope

    source = {"system": "apex", "component": "test"}
    observation = {"action": "allow", "value": 42}

    built = envelope.build_envelope(
        tenant_id="tenant-apex",
        event_id="event-apex-1",
        event_type="enterprise.test",
        source=source,
        observation=observation,
        subject={"id": "subject-1"},
        actor={"id": "actor-1"},
        authority={"id": "authority-1"},
        provenance={"source": "test"},
        sequence={"value": 1},
        classification={"level": "internal"},
        retention={"days": 30},
        observed_at="2026-10-04T00:00:00Z",
    )

    assert built["schema"] == envelope.SCHEMA
    assert built["integrity"]["hash_algorithm"] == envelope.HASH_ALGORITHM
    assert envelope.verify_envelope(built) == (True, "valid")

    tampered = dict(built)
    tampered["observation"] = dict(built["observation"])
    tampered["observation"]["action"] = "deny"
    assert envelope.verify_envelope(tampered) == (
        False,
        "payload_digest_mismatch",
    )

    missing_integrity = dict(built)
    missing_integrity.pop("integrity")
    assert envelope.verify_envelope(missing_integrity) == (False, "integrity")

    missing_digest = dict(built)
    missing_digest["integrity"] = dict(built["integrity"])
    missing_digest["integrity"].pop("payload_digest")
    assert envelope.verify_envelope(missing_digest) == (False, "payload_digest")

    bad_digest = dict(built)
    bad_digest["integrity"] = dict(built["integrity"])
    bad_digest["integrity"]["payload_digest"] = 123
    assert envelope.verify_envelope(bad_digest) == (False, "payload_digest")

    invalid_integrity = dict(built)
    invalid_integrity["integrity"] = "invalid"
    assert envelope.verify_envelope(invalid_integrity) == (False, "integrity")

    assert envelope.sha256(b"rightsframes") == envelope.sha256(b"rightsframes")
    assert envelope.utc_now().endswith("Z")


def test_evidence_envelope_normalization_paths():
    from core.evidence import envelope

    assert envelope.canonical_bytes(
        {
            "b": (3, 2),
            "a": {"z": None, "y": False},
            "n": 1,
            "f": 1.5,
        }
    )

    try:
        envelope.canonical_bytes({"unsupported": object()})
    except TypeError as exc:
        assert "object" in str(exc)


def test_evidence_ledger_production_paths():
    from core.evidence import ledger

    payload = "a" * 64

    first = ledger.build_record(
        ledger_sequence=0,
        event_id="event-0",
        payload_digest=payload,
    )
    second = ledger.build_record(
        ledger_sequence=1,
        event_id="event-1",
        payload_digest="b" * 64,
        previous_record_digest=first.record_digest,
    )

    assert first.record_digest
    assert second.previous_record_digest == first.record_digest
    assert ledger.verify_chain([first, second]) == (True, "valid")
    assert ledger.record_material(
        0,
        "event-0",
        payload,
        None,
    )["schema"] == ledger.LEDGER_SCHEMA

    invalid_builds = (
        lambda: ledger.build_record(-1, "event", payload),
        lambda: ledger.build_record(0, "", payload),
        lambda: ledger.build_record(0, "event", "bad"),
        lambda: ledger.build_record(0, "event", payload, "bad"),
    )

    for call in invalid_builds:
        try:
            call()
        except ValueError:
            pass

    assert ledger.verify_chain(
        [
            ledger.LedgerRecord(
                ledger_sequence=1,
                event_id="event-0",
                payload_digest=payload,
                previous_record_digest=None,
                record_digest=first.record_digest,
            )
        ]
    ) == (False, "sequence_gap")

    assert ledger.verify_chain(
        [
            ledger.LedgerRecord(
                ledger_sequence=0,
                event_id="event-0",
                payload_digest=payload,
                previous_record_digest="c" * 64,
                record_digest=first.record_digest,
            )
        ]
    ) == (False, "previous_digest_mismatch")

    assert ledger.verify_chain(
        [
            ledger.LedgerRecord(
                ledger_sequence=0,
                event_id="event-0",
                payload_digest="d" * 64,
                previous_record_digest=None,
                record_digest=first.record_digest,
            )
        ]
    ) == (False, "record_digest_mismatch")


def test_evidence_merkle_production_paths():
    from core.evidence import merkle

    digests = ["a" * 64, "b" * 64, "c" * 64]

    assert merkle.hash_leaf(digests[0])
    assert merkle.hash_node(
        merkle.hash_leaf(digests[0]),
        merkle.hash_leaf(digests[1]),
    )

    root = merkle.merkle_root(digests)
    assert root
    assert merkle.merkle_root([])

    for index in range(len(digests)):
        proof = merkle.build_proof(digests, index)
        assert proof.tree_size == len(digests)
        assert merkle.verify_proof(proof, root)

    invalid_proof = merkle.build_proof(digests, 0)
    assert not merkle.verify_proof(invalid_proof, "0" * 64)

    for call in (
        lambda: merkle.build_proof([], 0),
        lambda: merkle.build_proof(digests, -1),
        lambda: merkle.build_proof(digests, len(digests)),
    ):
        try:
            call()
        except (ValueError, IndexError):
            pass

    checkpoint = merkle.build_checkpoint(
        digests,
        previous_root="f" * 64,
    )
    assert checkpoint.schema == merkle.MERKLE_SCHEMA
    assert checkpoint.tree_size == 3
    assert checkpoint.root_hash == root
    assert checkpoint.previous_root == "f" * 64
    assert merkle.checkpoint_bytes(checkpoint)


def test_evidence_signing_production_paths():
    from core.evidence import signing

    private_key, public_key = signing.generate_keypair()
    payload = b"rightsframes-apex-production"

    signed = signing.sign(
        private_key,
        payload,
        "apex-production",
    )

    assert signed["schema"] == signing.SIGNATURE_SCHEMA
    assert signed["algorithm"] == signing.ALGORITHM
    assert signed["key_id"] == "apex-production"
    assert signing.verify(public_key, payload, signed) == (True, "valid")

    assert signing.verify(
        public_key,
        b"tampered",
        signed,
    ) == (False, "invalid_signature")

    assert signing.verify(
        public_key,
        payload,
        {**signed, "algorithm": "wrong"},
    ) == (False, "algorithm")

    assert signing.verify(
        public_key,
        payload,
        {**signed, "key_id": 123},
    ) == (False, "key_id")

    assert signing.verify(
        public_key,
        payload,
        {**signed, "signature": 123},
    ) == (False, "signature")

    assert signing.verify(
        b"short",
        payload,
        signed,
    ) == (False, "encoding")

    invalid_private_keys = (
        b"",
        b"short",
        b"x" * 31,
        b"x" * 33,
    )

    for key in invalid_private_keys:
        try:
            signing.sign(key, payload, "invalid")
        except ValueError:
            pass


def test_evidence_signing_decoding_paths():
    from core.evidence import signing

    private_key, public_key = signing.generate_keypair()
    payload = b"apex"

    signed = signing.sign(private_key, payload, "decode-test")

    malformed = dict(signed)
    malformed["signature"] = "!"
    assert signing.verify(
        public_key,
        payload,
        malformed,
    )[0] is False

    malformed = dict(signed)
    malformed["signature"] = ""
    assert signing.verify(
        public_key,
        payload,
        malformed,
    )[0] is False

    malformed = dict(signed)
    malformed["schema"] = "wrong"
    assert signing.verify(
        public_key,
        payload,
        malformed,
    ) == (False, "schema")
