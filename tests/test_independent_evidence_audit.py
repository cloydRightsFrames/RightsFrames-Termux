from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from core.evidence.envelope import canonical_bytes
from core.evidence.signing import generate_keypair, sign
from tools.rf_independent_evidence_audit import AuditFailure, audit


def _signed(document, private_key, key_id):
    document["signature"] = sign(
        private_key,
        canonical_bytes(document),
        key_id,
    )
    return document


@pytest.fixture
def bundle(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    artifact = root / "scan.json"
    artifact.write_text('{"observed":"test-only"}\n', encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    private, public = generate_keypair()
    key_id = "audit-test-key"
    policy = {
        "schema": "rightsframes.audit-policy.v1",
        "trusted_keys": {key_id: public.hex()},
        "trusted_manifest_signers": [key_id],
        "trusted_provenance_signers": [key_id],
        "expected_builder_id": "ci://rightsframes/test",
        "expected_source_commit": "a" * 40,
        "required_evidence": ["scan.json"],
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
    manifest = _signed({
        "schema": "rightsframes.audit-manifest.v1",
        "evidence": [{
            "path": "scan.json",
            "sha256": digest,
            "subject_id": "test-subject-1",
        }],
        "conclusions": [{
            "id": "C-1",
            "claim": "The test artifact was collected.",
            "evidence": ["scan.json"],
            "status": "UNVERIFIED",
        }],
    }, private, key_id)
    provenance = _signed({
        "schema": "rightsframes.audit-provenance.v1",
        "builder_id": "ci://rightsframes/test",
        "source_commit": "a" * 40,
        "subjects": [{"path": "scan.json", "sha256": digest}],
    }, private, key_id)
    manifest_path = tmp_path / "manifest.json"
    provenance_path = tmp_path / "provenance.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
    pin = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    return {
        "root": root, "policy_path": policy_path, "pin": pin,
        "manifest_path": manifest_path, "provenance_path": provenance_path,
        "manifest": manifest, "provenance": provenance,
        "private": private, "key_id": key_id,
    }


def _run(bundle):
    return audit(
        bundle["root"], bundle["policy_path"], bundle["pin"],
        bundle["manifest_path"], bundle["provenance_path"],
    )


def test_valid_signed_bundle_passes(bundle):
    report = _run(bundle)
    assert report["result"] == "PASS"
    assert report["evidence_count"] == 1
    assert report["conclusion_statuses"] == {"C-1": "UNVERIFIED"}


def test_forged_manifest_is_rejected(bundle):
    manifest = bundle["manifest"]
    manifest["conclusions"][0]["claim"] = "Forged conclusion."
    bundle["manifest_path"].write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(AuditFailure, match="signature invalid"):
        _run(bundle)


def test_altered_evidence_bytes_are_rejected(bundle):
    (bundle["root"] / "scan.json").write_text("altered\n", encoding="utf-8")
    with pytest.raises(AuditFailure, match="digest mismatch"):
        _run(bundle)


def test_missing_required_evidence_is_rejected(bundle):
    manifest = bundle["manifest"]
    manifest["evidence"] = []
    # Re-signing proves the failure is completeness, not a stale signature.
    unsigned = dict(manifest)
    unsigned.pop("signature")
    manifest = _signed(unsigned, bundle["private"], bundle["key_id"])
    bundle["manifest_path"].write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(AuditFailure, match="inventory mismatch"):
        _run(bundle)


def test_unmanifested_file_is_rejected(bundle):
    (bundle["root"] / "extra.txt").write_text("unexpected", encoding="utf-8")
    with pytest.raises(AuditFailure, match="inventory mismatch"):
        _run(bundle)


def test_untrusted_signer_is_rejected(bundle):
    manifest = bundle["manifest"]
    unsigned = dict(manifest)
    unsigned.pop("signature")
    manifest = _signed(unsigned, bundle["private"], "attacker-key")
    bundle["manifest_path"].write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(AuditFailure, match="untrusted signer"):
        _run(bundle)


def test_misattributed_builder_is_rejected(bundle):
    provenance = bundle["provenance"]
    unsigned = dict(provenance)
    unsigned.pop("signature")
    unsigned["builder_id"] = "ci://untrusted/builder"
    provenance = _signed(unsigned, bundle["private"], bundle["key_id"])
    bundle["provenance_path"].write_text(json.dumps(provenance), encoding="utf-8")
    with pytest.raises(AuditFailure, match="builder identity mismatch"):
        _run(bundle)


def test_misattributed_source_commit_is_rejected(bundle):
    provenance = bundle["provenance"]
    unsigned = dict(provenance)
    unsigned.pop("signature")
    unsigned["source_commit"] = "b" * 40
    provenance = _signed(unsigned, bundle["private"], bundle["key_id"])
    bundle["provenance_path"].write_text(json.dumps(provenance), encoding="utf-8")
    with pytest.raises(AuditFailure, match="source commit attribution mismatch"):
        _run(bundle)


def test_untraceable_conclusion_is_rejected(bundle):
    manifest = bundle["manifest"]
    unsigned = dict(manifest)
    unsigned.pop("signature")
    unsigned["conclusions"][0]["evidence"] = ["missing.bin"]
    manifest = _signed(unsigned, bundle["private"], bundle["key_id"])
    bundle["manifest_path"].write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(AuditFailure, match="lacks traceable evidence"):
        _run(bundle)


def test_policy_tampering_is_rejected(bundle):
    bundle["policy_path"].write_text('{"schema":"rightsframes.audit-policy.v1"}', encoding="utf-8")
    with pytest.raises(AuditFailure, match="policy SHA-256 pin mismatch"):
        _run(bundle)


def test_incomplete_provenance_subject_inventory_is_rejected(bundle):
    provenance = bundle["provenance"]
    unsigned = dict(provenance)
    unsigned.pop("signature")
    unsigned["subjects"] = []
    provenance = _signed(unsigned, bundle["private"], bundle["key_id"])
    bundle["provenance_path"].write_text(json.dumps(provenance), encoding="utf-8")
    with pytest.raises(AuditFailure, match="provenance subjects missing"):
        _run(bundle)
