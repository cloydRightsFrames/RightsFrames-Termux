import tempfile
import unittest
from pathlib import Path

from core.audit import AuditLog
from core.key_management import generate_keypair
from core.manifest import (
    build_manifest,
    sign_manifest,
    verify_manifest,
)
from core.merkle import compute_merkle_root
from core.signing import (
    sign_data,
    verify_signature,
)


class SecurityTests(unittest.TestCase):

    def test_ed25519(self):
        private, public = generate_keypair()

        message = b"RightsFrames"

        signature = sign_data(
            private,
            message,
        )

        self.assertTrue(
            verify_signature(
                public,
                signature,
                message,
            )
        )

        self.assertFalse(
            verify_signature(
                public,
                signature,
                b"tampered",
            )
        )

    def test_merkle(self):
        a = compute_merkle_root(
            [b"a", b"b", b"c"]
        )

        b = compute_merkle_root(
            [b"a", b"b", b"c"]
        )

        c = compute_merkle_root(
            [b"a", b"b", b"x"]
        )

        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_manifest(self):
        private, public = generate_keypair()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.txt"

            artifact.write_bytes(
                b"RightsFrames"
            )

            manifest = sign_manifest(
                build_manifest(
                    [artifact],
                    root=root,
                ),
                private,
            )

            self.assertTrue(
                verify_manifest(
                    manifest,
                    public,
                    root=root,
                )
            )

            artifact.write_bytes(
                b"TAMPERED"
            )

            self.assertFalse(
                verify_manifest(
                    manifest,
                    public,
                    root=root,
                )
            )

    def test_manifest_signature_tamper(self):
        private, public = generate_keypair()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.txt"
            artifact.write_bytes(b"RightsFrames")

            manifest = sign_manifest(
                build_manifest(
                    [artifact],
                    root=root,
                ),
                private,
            )

            manifest["files"][0]["size"] += 1

            self.assertFalse(
                verify_manifest(
                    manifest,
                    public,
                    root=root,
                )
            )

    def test_path_escape_rejected(self):
        private, public = generate_keypair()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact.txt"
            artifact.write_bytes(b"RightsFrames")

            manifest = sign_manifest(
                build_manifest(
                    [artifact],
                    root=root,
                ),
                private,
            )

            manifest["files"][0]["path"] = "../artifact.txt"

            self.assertFalse(
                verify_manifest(
                    manifest,
                    public,
                    root=root,
                )
            )

    def test_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = AuditLog(
                str(
                    Path(directory)
                    / "audit.db"
                )
            )

            audit.append(
                {
                    "type": "test",
                    "sequence": 1,
                }
            )

            audit.append(
                {
                    "type": "test",
                    "sequence": 2,
                }
            )

            self.assertTrue(
                audit.verify()
            )

            audit.close()


if __name__ == "__main__":
    unittest.main()
