from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .merkle import compute_legacy_merkle_root, compute_merkle_root


SCHEMA = "rightsframes.manifest.v2"
LEGACY_SCHEMA = "rightsframes.manifest.v1"
SUPPORTED_SCHEMAS = (SCHEMA, LEGACY_SCHEMA)
ALGORITHM = "Ed25519+SHA-256"


def canonical_json(value) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_file(path) -> str:
    digest = hashlib.sha256()

    with Path(path).open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def build_manifest(file_paths, root=None):
    root_path = (
        Path(root).resolve()
        if root is not None
        else None
    )

    entries = []

    for item in file_paths:
        path = Path(item).resolve()

        if root_path is not None:
            relative = path.relative_to(root_path).as_posix()
        else:
            relative = str(path)

        entries.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )

    entries.sort(key=lambda value: value["path"])

    return {
        "schema": SCHEMA,
        "algorithm": ALGORITHM,
        "files": entries,
        "merkle_root": compute_merkle_root(
            [
                bytes.fromhex(entry["sha256"])
                for entry in entries
            ]
        ).hex(),
    }


def sign_manifest(manifest, private_key):
    signature = private_key.sign(
        canonical_json(manifest)
    )

    result = dict(manifest)
    result["signature"] = signature.hex()
    return result


def verify_manifest_signature(manifest, public_key):
    if not isinstance(manifest, dict):
        return False

    if manifest.get("schema") not in SUPPORTED_SCHEMAS:
        return False

    if manifest.get("algorithm") != ALGORITHM:
        return False

    signature = manifest.get("signature")

    if not isinstance(signature, str):
        return False

    try:
        signature_bytes = bytes.fromhex(signature)
    except ValueError:
        return False

    body = dict(manifest)
    body.pop("signature", None)

    try:
        public_key.verify(
            signature_bytes,
            canonical_json(body),
        )
    except Exception:
        return False

    return True


def verify_manifest(manifest, public_key, root=None):
    if not verify_manifest_signature(
        manifest,
        public_key,
    ):
        return False

    files = manifest.get("files")

    if not isinstance(files, list):
        return False

    if files != sorted(
        files,
        key=lambda value: value.get("path", ""),
    ):
        return False

    calculated = []

    root_path = (
        Path(root).resolve()
        if root is not None
        else None
    )

    for entry in files:
        if not isinstance(entry, dict):
            return False

        relative = entry.get("path")
        expected_hash = entry.get("sha256")
        expected_size = entry.get("size")

        if not isinstance(relative, str):
            return False

        if not isinstance(expected_hash, str):
            return False

        if not isinstance(expected_size, int) or isinstance(expected_size, bool):
            return False

        if root_path is not None:
            path = (root_path / relative).resolve()

            try:
                path.relative_to(root_path)
            except ValueError:
                return False
        else:
            path = Path(relative)

        if not path.is_file():
            return False

        actual = sha256_file(path)

        if actual != expected_hash:
            return False

        if path.stat().st_size != expected_size:
            return False

        try:
            calculated.append(bytes.fromhex(actual))
        except ValueError:
            return False

    if len({entry.get("path") for entry in files}) != len(files):
        return False

    root_function = (
        compute_merkle_root
        if manifest.get("schema") == SCHEMA
        else compute_legacy_merkle_root
    )
    calculated_root = root_function(calculated).hex()

    return calculated_root == manifest.get("merkle_root")
