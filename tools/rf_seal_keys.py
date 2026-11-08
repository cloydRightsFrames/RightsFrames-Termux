#!/usr/bin/env python3
"""Seal (encrypt at rest) or re-key the RightsFrames private signing keys.

    # status only: which keys are sealed, with which KDF
    python tools/rf_seal_keys.py --data-dir /data --status

    # seal plaintext keys with the passphrase in RF_KEY_PASSPHRASE_FILE
    RF_KEY_PASSPHRASE_FILE=/run/secrets/rf_key_passphrase \
        python tools/rf_seal_keys.py --data-dir /data

    # change the passphrase of already sealed keys
    RF_KEY_PASSPHRASE_FILE=/run/secrets/new python tools/rf_seal_keys.py --data-dir /data \
        --old-passphrase-file /run/secrets/old

Both keys (Ed25519 signing_key.pem and ML-DSA-65 signing_key_mldsa65.pem, when present)
are processed as one unit: every key is opened, re-sealed and round-trip checked in
memory, and its public key compared with the stored public key file, BEFORE anything is
written. Each file is then replaced atomically (temp file, fsync, rename, directory fsync)
with mode 0600 while holding the anchor lock, so no anchor is signed mid-rotation. Key
material never changes, so key ids, anchors and existing pins stay valid.

Configure the passphrase for the service BEFORE sealing: plaintext keys keep loading
while a passphrase is configured, sealed keys need it. Losing the passphrase loses the
keys; keep an offline copy.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from core import rf_keyseal  # noqa: E402

KEYS = (('ed25519', 'signing_key.pem', 'signing_key.pub.pem'),
        ('mldsa65', 'signing_key_mldsa65.pem', 'signing_key_mldsa65.pub.pem'))


class SealError(Exception):
    pass


def _public_raw(key: Any) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@contextlib.contextmanager
def _anchor_lock(data_dir: Path) -> Iterator[None]:
    lock_path = data_dir / 'anchors.lock'
    with lock_path.open('a+b') as handle:
        if os.name == 'nt':
            import msvcrt
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b'\x00')
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _atomic_replace(path: Path, data: bytes) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    tmp = Path(tmp_name)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        if os.name == 'posix':
            os.chmod(path, 0o600)
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if tmp.exists():
            tmp.unlink()


def status(data_dir: Path) -> dict[str, Any]:
    report: dict[str, Any] = {'data_dir': str(data_dir),
                              'argon2id_available': rf_keyseal.argon2_available(),
                              'sealing_required': rf_keyseal.sealing_required()}
    for role, private_name, _ in KEYS:
        path = data_dir / private_name
        report[role] = rf_keyseal.describe(path.read_bytes()) if path.exists() else {'absent': True}
    return report


def seal_keys(data_dir: Path, new_passphrase: bytes, old_passphrase: bytes | None = None,
              kdf: str | None = None) -> list[str]:
    """Seal every present private key under new_passphrase. Returns the roles sealed."""
    plan: list[tuple[Path, bytes]] = []
    roles: list[str] = []
    for role, private_name, public_name in KEYS:
        private_path, public_path = data_dir / private_name, data_dir / public_name
        if not private_path.exists():
            continue
        if not public_path.exists():
            raise SealError(f'{public_name} is missing; refusing to seal {private_name} '
                            'without a public key to check it against')
        current = private_path.read_bytes()
        try:
            if rf_keyseal.is_sealed(current):
                if old_passphrase is None:
                    raise SealError(f'{private_name} is already sealed; pass --old-passphrase-file '
                                    'to change its passphrase')
                der = rf_keyseal.unseal_der(current, old_passphrase, role)
                private = serialization.load_der_private_key(der, password=None)
            else:
                private = serialization.load_pem_private_key(current, password=None)
                der = private.private_bytes(serialization.Encoding.DER,
                                            serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption())
        except rf_keyseal.SealedKeyError as exc:
            raise SealError(f'{private_name}: {exc}') from None
        stored_public = serialization.load_pem_public_key(public_path.read_bytes())
        if _public_raw(stored_public) != _public_raw(private.public_key()):
            raise SealError(f'{private_name} does not match {public_name}; refusing to seal')
        sealed = rf_keyseal.seal_der(der, new_passphrase, role, kdf)
        reopened = serialization.load_der_private_key(
            rf_keyseal.unseal_der(sealed, new_passphrase, role), password=None)
        if _public_raw(reopened.public_key()) != _public_raw(private.public_key()):
            raise SealError(f'{private_name}: sealed copy failed its round-trip check')
        plan.append((private_path, sealed))
        roles.append(role)
    if not plan:
        raise SealError(f'no private signing keys found in {data_dir}')
    with _anchor_lock(data_dir):
        for path, sealed in plan:
            _atomic_replace(path, sealed)
    return roles


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Seal RightsFrames private signing keys at rest.')
    parser.add_argument('--data-dir', default=os.environ.get('RF_DATA_DIR'))
    parser.add_argument('--status', action='store_true', help='report key custody and exit')
    parser.add_argument('--old-passphrase-file', help='current passphrase of already sealed keys')
    parser.add_argument('--kdf', choices=('argon2id', 'scrypt'),
                        help='default: argon2id when available, else scrypt')
    args = parser.parse_args(argv)
    if not args.data_dir:
        parser.error('--data-dir or RF_DATA_DIR is required')
    data_dir = Path(args.data_dir).resolve()
    if not data_dir.is_dir():
        print(f'rf-seal-keys: data directory not found: {data_dir}', file=sys.stderr)
        return 1
    if args.status:
        print(json.dumps(status(data_dir), indent=2, sort_keys=True))
        return 0
    try:
        new_passphrase = rf_keyseal.passphrase_from_env()
        if new_passphrase is None:
            raise SealError(f'set {rf_keyseal.ENV_PASSPHRASE_FILE} (preferred) or '
                            f'{rf_keyseal.ENV_PASSPHRASE} to the new passphrase')
        old = (rf_keyseal.read_passphrase_file(args.old_passphrase_file)
               if args.old_passphrase_file else None)
        if args.kdf == 'argon2id' and not rf_keyseal.argon2_available():
            raise SealError('Argon2id is not available in this cryptography/OpenSSL build')
        roles = seal_keys(data_dir, new_passphrase, old, args.kdf)
    except (SealError, rf_keyseal.SealedKeyError, OSError, ValueError, TypeError) as exc:
        print(f'rf-seal-keys: {exc}', file=sys.stderr)
        return 1
    print(f"sealed {', '.join(roles)} signing key(s) in {data_dir}")
    print(json.dumps(status(data_dir), sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
