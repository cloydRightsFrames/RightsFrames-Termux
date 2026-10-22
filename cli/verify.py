from __future__ import annotations

import argparse
import json
import sys

from core.key_management import load_public_key
from core.manifest import verify_manifest


def main():
    parser = argparse.ArgumentParser(
        description="Verify a signed RightsFrames manifest."
    )

    parser.add_argument(
        "--manifest",
        required=True,
    )

    parser.add_argument(
        "--public-key",
        required=True,
    )

    parser.add_argument(
        "--root",
        default=None,
    )

    args = parser.parse_args()

    with open(
        args.manifest,
        "r",
        encoding="utf-8",
    ) as handle:
        manifest = json.load(handle)

    public_key = load_public_key(
        args.public_key
    )

    if verify_manifest(
        manifest,
        public_key,
        args.root,
    ):
        print("RIGHTSFRAMES_MANIFEST=PASS")
        return 0

    print("RIGHTSFRAMES_MANIFEST=FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
