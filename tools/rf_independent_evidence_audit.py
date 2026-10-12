#!/usr/bin/env python3
"""Fail-closed, read-only evidence audit with pinned policy and Ed25519 attestations."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from core.evidence.envelope import canonical_bytes
from core.evidence.signing import verify as verify_signature

MAX_JSON = 16 * 1024 * 1024
MAX_EVIDENCE = 64 * 1024 * 1024
MAX_FILES = 10000
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AuditFailure(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
        raise AuditFailure(f"unsafe, missing, or oversized JSON: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AuditFailure(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise AuditFailure(f"JSON root must be an object: {path}")
    return value


def signed_payload(document: dict[str, Any]) -> bytes:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    return canonical_bytes(unsigned)


def verify_signed(document: dict[str, Any], keys: dict[str, str], label: str) -> str:
    signature = document.get("signature")
    if not isinstance(signature, dict):
        raise AuditFailure(f"{label}: signature missing")
    key_id = signature.get("key_id")
    if not isinstance(key_id, str) or key_id not in keys:
        raise AuditFailure(f"{label}: untrusted signer")
    try:
        public_key = bytes.fromhex(keys[key_id])
    except (TypeError, ValueError) as exc:
        raise AuditFailure(f"{label}: malformed trusted public key") from exc
    valid, reason = verify_signature(public_key, signed_payload(document), signature)
    if not valid:
        raise AuditFailure(f"{label}: signature invalid ({reason})")
    return key_id


def evidence_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise AuditFailure("invalid evidence path")
    rel = Path(relative)
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        raise AuditFailure(f"path traversal rejected: {relative}")
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise AuditFailure(f"symlink rejected: {relative}")
    resolved = current.resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise AuditFailure(f"evidence path escapes root or is not a file: {relative}")
    if resolved.stat().st_size > MAX_EVIDENCE:
        raise AuditFailure(f"evidence exceeds size limit: {relative}")
    return resolved


def inventory(root: Path) -> set[str]:
    result: set[str] = set()
    count = 0
    for base, dirs, names in os.walk(root, followlinks=False):
        if any((Path(base) / d).is_symlink() for d in dirs):
            raise AuditFailure("symlink directory in evidence root")
        dirs[:] = sorted(dirs)
        for name in sorted(names):
            path = Path(base) / name
            if path.is_symlink():
                raise AuditFailure(f"symlink in evidence root: {path.relative_to(root)}")
            if not path.is_file():
                raise AuditFailure(f"non-regular entry in evidence root: {path.relative_to(root)}")
            count += 1
            if count > MAX_FILES:
                raise AuditFailure("evidence file count exceeds limit")
            result.add(path.relative_to(root).as_posix())
    return result


def audit(root: Path, policy_path: Path, policy_pin: str,
          manifest_path: Path, provenance_path: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise AuditFailure("evidence root must be a directory")
    if not HEX64.fullmatch(policy_pin) or sha256_file(policy_path) != policy_pin:
        raise AuditFailure("out-of-band policy SHA-256 pin mismatch")
    policy = load_object(policy_path)
    if policy.get("schema") != "rightsframes.audit-policy.v1":
        raise AuditFailure("unsupported policy schema")
    keys = policy.get("trusted_keys")
    if not isinstance(keys, dict) or not keys:
        raise AuditFailure("trusted_keys must map key IDs to Ed25519 public-key hex")
    manifest = load_object(manifest_path)
    provenance = load_object(provenance_path)
    if manifest.get("schema") != "rightsframes.audit-manifest.v1":
        raise AuditFailure("unsupported manifest schema")
    manifest_signer = verify_signed(manifest, keys, "manifest")
    if manifest_signer not in policy.get("trusted_manifest_signers", []):
        raise AuditFailure("manifest signer is not authorized by pinned policy")
    if provenance.get("schema") != "rightsframes.audit-provenance.v1":
        raise AuditFailure("unsupported provenance schema")
    provenance_signer = verify_signed(provenance, keys, "provenance")
    if provenance_signer not in policy.get("trusted_provenance_signers", []):
        raise AuditFailure("provenance signer is not authorized by pinned policy")
    if provenance.get("builder_id") != policy.get("expected_builder_id"):
        raise AuditFailure("builder identity mismatch")
    expected_commit = policy.get("expected_source_commit")
    if not isinstance(expected_commit, str) or not expected_commit:
        raise AuditFailure("policy must pin expected_source_commit")
    if provenance.get("source_commit") != expected_commit:
        raise AuditFailure("source commit attribution mismatch")

    entries = manifest.get("evidence")
    if not isinstance(entries, list):
        raise AuditFailure("manifest evidence must be a list")
    by_path: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise AuditFailure("malformed evidence entry")
        name, claimed = entry.get("path"), entry.get("sha256")
        if not isinstance(name, str) or name in by_path:
            raise AuditFailure("invalid or duplicate evidence path")
        if not isinstance(claimed, str) or not HEX64.fullmatch(claimed):
            raise AuditFailure(f"invalid SHA-256 for {name}")
        by_path[name] = entry
    required = policy.get("required_evidence")
    if not isinstance(required, list) or not all(isinstance(x, str) for x in required):
        raise AuditFailure("policy required_evidence must be a string list")
    if len(set(required)) != len(required):
        raise AuditFailure("duplicate path in required_evidence")
    if set(by_path) != set(required):
        raise AuditFailure(
            f"manifest inventory mismatch: missing={sorted(set(required)-set(by_path))}; "
            f"unexpected={sorted(set(by_path)-set(required))}"
        )
    if inventory(root) != set(required):
        raise AuditFailure(
            f"evidence directory inventory mismatch: missing={sorted(set(required)-inventory(root))}; "
            f"unmanifested={sorted(inventory(root)-set(required))}"
        )

    digests: dict[str, str] = {}
    for name, entry in by_path.items():
        path = evidence_path(root, name)
        actual = sha256_file(path)
        if actual != entry["sha256"]:
            raise AuditFailure(f"evidence digest mismatch: {name}")
        if not isinstance(entry.get("subject_id"), str) or not entry["subject_id"]:
            raise AuditFailure(f"missing subject attribution: {name}")
        digests[name] = actual

    subjects = provenance.get("subjects")
    if not isinstance(subjects, list) or not subjects:
        raise AuditFailure("provenance subjects missing")
    subject_paths = [s.get("path") for s in subjects if isinstance(s, dict)]
    if len(subject_paths) != len(subjects) or len(set(subject_paths)) != len(subject_paths):
        raise AuditFailure("malformed or duplicate provenance subjects")
    if set(subject_paths) != set(required):
        raise AuditFailure("provenance subject inventory is incomplete or unexpected")
    for subject in subjects:
        name = subject["path"]
        if name not in digests or subject.get("sha256") != digests[name]:
            raise AuditFailure("provenance subject does not match manifest evidence")

    conclusions = manifest.get("conclusions")
    if not isinstance(conclusions, list) or not conclusions:
        raise AuditFailure("conclusions missing")
    ids: set[str] = set()
    allowed = {"VERIFIED", "UNVERIFIED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE"}
    for claim in conclusions:
        if not isinstance(claim, dict):
            raise AuditFailure("malformed conclusion")
        cid, statement, refs = claim.get("id"), claim.get("claim"), claim.get("evidence")
        if not isinstance(cid, str) or not cid or cid in ids:
            raise AuditFailure("missing or duplicate conclusion ID")
        ids.add(cid)
        if not isinstance(statement, str) or not statement.strip():
            raise AuditFailure(f"empty conclusion: {cid}")
        if not isinstance(refs, list) or not refs or any(ref not in digests for ref in refs):
            raise AuditFailure(f"conclusion lacks traceable evidence: {cid}")
        if claim.get("status") not in allowed:
            raise AuditFailure(f"invalid conclusion status: {cid}")

    return {
        "schema": "rightsframes.evidence-audit-report.v1",
        "result": "PASS",
        "read_only": True,
        "policy_sha256": policy_pin,
        "manifest_signer_key_id": manifest_signer,
        "provenance_signer_key_id": provenance_signer,
        "builder_id": provenance["builder_id"],
        "source_commit": expected_commit,
        "evidence_count": len(digests),
        "conclusion_count": len(conclusions),
        "evidence_sha256": digests,
        "conclusion_statuses": {c["id"]: c["status"] for c in conclusions},
        "limitations": [
            "A valid signature proves possession of a trusted key, not that observations are truthful.",
            "Semantic correctness of each security conclusion requires independent technical review.",
            "Policy trust depends on the SHA-256 pin being provisioned independently."
        ]
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise AuditFailure("refusing to overwrite report")
        report = audit(args.evidence, args.policy, args.policy_sha256.lower(),
                       args.manifest, args.provenance)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print("RIGHTSFRAMES_EVIDENCE_AUDIT=PASS")
        return 0
    except (OSError, AuditFailure, TypeError, KeyError) as exc:
        print(f"RIGHTSFRAMES_EVIDENCE_AUDIT=FAIL:{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
