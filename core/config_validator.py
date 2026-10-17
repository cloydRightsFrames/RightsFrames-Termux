from __future__ import annotations

import hashlib
import json
from pathlib import Path


def sha256_file(path) -> str:
    digest = hashlib.sha256()

    with Path(path).open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def validate_sha256(path, expected_hash):
    return (
        sha256_file(path).lower()
        == expected_hash.lower()
    )


def load_json_object(path):
    value = json.loads(
        Path(path).read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(value, dict):
        raise ValueError(
            "configuration root must be an object"
        )

    return value
