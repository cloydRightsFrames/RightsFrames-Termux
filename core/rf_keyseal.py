"""Sealed (passphrase-encrypted) private signing keys at rest: rf.sealed-key.v1.

Standard encrypted PKCS#8 from `cryptography` uses PBKDF2 with 2,048 iterations, which
is far too cheap to protect a long-lived signing key from offline guessing. A sealed
key instead wraps the PKCS#8 DER of the private key with:

  * KDF  : Argon2id (RFC 9106, t=3, p=4, m=64 MiB) when the OpenSSL backend provides it,
           otherwise scrypt (N=2^17, r=8, p=1);
  * AEAD : AES-256-GCM with a random 96-bit nonce;
  * AAD  : the canonical JSON header, which names the schema, the key role
           ("ed25519" or "mldsa65"), every KDF parameter and the nonce. Changing any
           header field, or swapping one role's file for the other's, fails decryption.

File format (PEM-style armour around one base64 JSON document):

    -----BEGIN RF SEALED PRIVATE KEY-----
    base64(canonical JSON {"header": {...}, "ciphertext": "<base64>"})
    -----END RF SEALED PRIVATE KEY-----

Passphrase sources, in order: RF_KEY_PASSPHRASE_FILE (a file readable by its owner only),
then RF_KEY_PASSPHRASE. Passphrases shorter than 16 characters are refused.
RF_REQUIRE_SEALED_KEYS=1 makes plaintext private keys a hard error (fail closed).

Decrypted key material lives in Python objects that cannot be reliably zeroised; sealing
protects keys at rest (stolen disks, backups, copies of the data directory), not against
an attacker who can read the running process's memory.

Imports nothing from RightsFrames.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SEAL_SCHEMA = 'rf.sealed-key.v1'
PEM_BEGIN = b'-----BEGIN RF SEALED PRIVATE KEY-----'
PEM_END = b'-----END RF SEALED PRIVATE KEY-----'
ROLES = ('ed25519', 'mldsa65')
MIN_PASSPHRASE_CHARS = 16
MAX_PASSPHRASE_BYTES = 4096
MAX_SEALED_BYTES = 65536

ARGON2_DEFAULT = {'name': 'argon2id', 'memory_cost': 65536, 'iterations': 3, 'lanes': 4}
SCRYPT_DEFAULT = {'name': 'scrypt', 'n': 1 << 17, 'r': 8, 'p': 1}
# Accepted parameter ranges when unsealing. Lower bounds stop a tampered header from
# silently downgrading the work factor; upper bounds stop a hostile file from making
# the loader allocate gigabytes or spin for minutes.
ARGON2_BOUNDS = {'memory_cost': (19456, 1048576), 'iterations': (2, 16), 'lanes': (1, 16)}
SCRYPT_BOUNDS = {'n': (1 << 15, 1 << 20), 'r': (8, 16), 'p': (1, 4)}

ENV_PASSPHRASE_FILE = 'RF_KEY_PASSPHRASE_FILE'
ENV_PASSPHRASE = 'RF_KEY_PASSPHRASE'
ENV_REQUIRE_SEALED = 'RF_REQUIRE_SEALED_KEYS'

_ARGON2_PROBE: dict[str, Any] = {}


class SealedKeyError(ValueError):
    """A sealed key could not be produced or opened; never carries secret material."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def _unb64(text: Any, what: str) -> bytes:
    if not isinstance(text, str):
        raise SealedKeyError(f'sealed key {what} is malformed')
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise SealedKeyError(f'sealed key {what} is not base64') from None


def argon2_available() -> bool:
    if 'ok' not in _ARGON2_PROBE:
        try:
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
            Argon2id(salt=b'\x00' * 16, length=32, iterations=1, lanes=1,
                     memory_cost=8).derive(b'probe')
            _ARGON2_PROBE['ok'] = True
        except Exception:
            _ARGON2_PROBE['ok'] = False
    return bool(_ARGON2_PROBE['ok'])


def sealing_required() -> bool:
    return os.environ.get(ENV_REQUIRE_SEALED, '').strip().lower() in ('1', 'true', 'yes', 'on')


def _check_passphrase(raw: bytes) -> bytes:
    if len(raw) > MAX_PASSPHRASE_BYTES:
        raise SealedKeyError('key passphrase is too long')
    try:
        chars = len(raw.decode('utf-8'))
    except UnicodeDecodeError:
        raise SealedKeyError('key passphrase is not valid UTF-8') from None
    if chars < MIN_PASSPHRASE_CHARS:
        raise SealedKeyError(f'key passphrase must be at least {MIN_PASSPHRASE_CHARS} characters')
    return raw


def read_passphrase_file(path: str | os.PathLike[str]) -> bytes:
    """Read a passphrase file, refusing files that group or others can read or write."""
    file_path = Path(path)
    try:
        info = file_path.stat()
    except OSError:
        raise SealedKeyError(f'key passphrase file is not readable: {file_path}') from None
    if not stat.S_ISREG(info.st_mode):
        raise SealedKeyError(f'key passphrase file is not a regular file: {file_path}')
    if os.name == 'posix' and info.st_mode & 0o077:
        raise SealedKeyError(f'key passphrase file must not be accessible to group/others '
                             f'(chmod 600 {file_path})')
    raw = file_path.read_bytes()
    if raw.endswith(b'\r\n'):
        raw = raw[:-2]
    elif raw.endswith(b'\n'):
        raw = raw[:-1]
    return _check_passphrase(raw)


def passphrase_from_env() -> bytes | None:
    """Return the configured key passphrase, or None when sealing is not configured."""
    file_name = os.environ.get(ENV_PASSPHRASE_FILE, '').strip()
    if file_name:
        return read_passphrase_file(file_name)
    value = os.environ.get(ENV_PASSPHRASE)
    if value:
        return _check_passphrase(value.encode('utf-8'))
    return None


def is_sealed(data: bytes) -> bool:
    return data.lstrip().startswith(PEM_BEGIN)


def _derive(passphrase: bytes, kdf: dict[str, Any], salt: bytes) -> bytes:
    if kdf['name'] == 'argon2id':
        if not argon2_available():
            raise SealedKeyError('key was sealed with Argon2id but this cryptography/OpenSSL '
                                 'build lacks Argon2id')
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        return Argon2id(salt=salt, length=32, iterations=kdf['iterations'],
                        lanes=kdf['lanes'], memory_cost=kdf['memory_cost']).derive(passphrase)
    return Scrypt(salt=salt, length=32, n=kdf['n'], r=kdf['r'], p=kdf['p']).derive(passphrase)


def _validate_kdf(kdf: Any) -> dict[str, Any]:
    if not isinstance(kdf, dict):
        raise SealedKeyError('sealed key KDF is malformed')
    name = kdf.get('name')
    bounds = {'argon2id': ARGON2_BOUNDS, 'scrypt': SCRYPT_BOUNDS}.get(name)
    if bounds is None:
        raise SealedKeyError(f'sealed key uses unsupported KDF {name!r}')
    if set(kdf) != {'name', 'salt', *bounds}:
        raise SealedKeyError('sealed key KDF has unexpected fields')
    for field, (low, high) in bounds.items():
        value = kdf[field]
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise SealedKeyError(f'sealed key KDF parameter {field} is out of range')
    if name == 'scrypt' and kdf['n'] & (kdf['n'] - 1):
        raise SealedKeyError('sealed key scrypt N must be a power of two')
    if len(_unb64(kdf['salt'], 'salt')) < 16:
        raise SealedKeyError('sealed key salt is too short')
    return kdf


def seal_der(private_der: bytes, passphrase: bytes, role: str, kdf_name: str | None = None) -> bytes:
    """Seal PKCS#8 DER private key bytes for `role`; returns the armoured file content."""
    if role not in ROLES:
        raise SealedKeyError(f'unknown key role {role!r}')
    _check_passphrase(passphrase)
    if kdf_name is None:
        kdf_name = 'argon2id' if argon2_available() else 'scrypt'
    template = {'argon2id': ARGON2_DEFAULT, 'scrypt': SCRYPT_DEFAULT}.get(kdf_name)
    if template is None:
        raise SealedKeyError(f'unsupported KDF {kdf_name!r}')
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    kdf = {**template, 'salt': _b64(salt)}
    header = {'schema': SEAL_SCHEMA, 'role': role, 'kdf': kdf,
              'aead': 'AES-256-GCM', 'nonce': _b64(nonce)}
    key = _derive(passphrase, kdf, salt)
    ciphertext = AESGCM(key).encrypt(nonce, private_der, _canonical(header))
    document = _canonical({'header': header, 'ciphertext': _b64(ciphertext)})
    body = base64.encodebytes(document)
    return PEM_BEGIN + b'\n' + body + PEM_END + b'\n'


def unseal_der(data: bytes, passphrase: bytes, role: str) -> bytes:
    """Open a sealed key for `role`; returns PKCS#8 DER. Fails closed on any anomaly."""
    if len(data) > MAX_SEALED_BYTES:
        raise SealedKeyError('sealed key file is too large')
    text = data.strip()
    if not (text.startswith(PEM_BEGIN) and text.endswith(PEM_END)):
        raise SealedKeyError('sealed key armour is malformed')
    body = b''.join(text[len(PEM_BEGIN):-len(PEM_END)].split())
    try:
        document = json.loads(base64.b64decode(body, validate=True).decode('ascii'))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise SealedKeyError('sealed key body is malformed') from None
    if not isinstance(document, dict) or set(document) != {'header', 'ciphertext'}:
        raise SealedKeyError('sealed key document has unexpected fields')
    header = document['header']
    if not isinstance(header, dict) or set(header) != {'schema', 'role', 'kdf', 'aead', 'nonce'}:
        raise SealedKeyError('sealed key header has unexpected fields')
    if header['schema'] != SEAL_SCHEMA or header['aead'] != 'AES-256-GCM':
        raise SealedKeyError('sealed key uses an unsupported schema or cipher')
    if header['role'] != role:
        raise SealedKeyError(f'sealed key is for role {header["role"]!r}, expected {role!r}')
    kdf = _validate_kdf(header['kdf'])
    nonce = _unb64(header['nonce'], 'nonce')
    if len(nonce) != 12:
        raise SealedKeyError('sealed key nonce has the wrong length')
    ciphertext = _unb64(document['ciphertext'], 'ciphertext')
    key = _derive(passphrase, kdf, _unb64(kdf['salt'], 'salt'))
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _canonical(header))
    except InvalidTag:
        raise SealedKeyError('wrong key passphrase, or the sealed key was tampered with') from None


def describe(data: bytes) -> dict[str, Any]:
    """Non-secret description of a private key file: sealed or plaintext, and with which KDF."""
    if not is_sealed(data):
        return {'sealed': False}
    try:
        text = data.strip()
        body = b''.join(text[len(PEM_BEGIN):-len(PEM_END)].split())
        header = json.loads(base64.b64decode(body, validate=True).decode('ascii'))['header']
        return {'sealed': True, 'role': header['role'], 'kdf': header['kdf']['name']}
    except Exception:
        return {'sealed': True, 'role': None, 'kdf': None, 'malformed': True}


def load_private_key(data: bytes, role: str, passphrase: bytes | None) -> Any:
    """Load a sealed or plaintext PEM private key, enforcing RF_REQUIRE_SEALED_KEYS."""
    if is_sealed(data):
        if passphrase is None:
            raise SealedKeyError(f'{role} signing key is sealed but no passphrase is configured '
                                 f'({ENV_PASSPHRASE_FILE} or {ENV_PASSPHRASE})')
        der = unseal_der(data, passphrase, role)
        return serialization.load_der_private_key(der, password=None)
    if sealing_required():
        raise SealedKeyError(f'{role} signing key is stored in plaintext and '
                             f'{ENV_REQUIRE_SEALED} is set; seal it with tools/rf_seal_keys.py')
    return serialization.load_pem_private_key(data, password=None)


def serialize_private_key(private_key: Any, role: str, passphrase: bytes | None) -> bytes:
    """Serialise a private key for storage: sealed when a passphrase is configured."""
    if passphrase is None:
        if sealing_required():
            raise SealedKeyError(f'{ENV_REQUIRE_SEALED} is set but no key passphrase is configured '
                                 f'({ENV_PASSPHRASE_FILE} or {ENV_PASSPHRASE})')
        return private_key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
    der = private_key.private_bytes(serialization.Encoding.DER,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    return seal_der(der, passphrase, role)
