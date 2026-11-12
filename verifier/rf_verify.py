#!/usr/bin/env python3
"""RightsFrames independent evidence-bundle verifier (rf.evidence.v1 and rf.evidence.v2).

Dependencies: Python 3.10+ and `cryptography` (Ed25519; ML-DSA-65 for v2 bundles).
Imports nothing from RightsFrames, so it can be reviewed or rewritten independently.

Post-quantum: rf.anchor.v3 anchors carry an Ed25519 signature AND an ML-DSA-65
(FIPS 204) signature over the same anchor hash; both must verify. Once a v3 anchor
appears, every later anchor must be v3 (downgrade = failure). Because each anchor
hash-chains to its predecessor and commits to a ledger head, the newest v3 anchor
protects the whole ledger prefix it covers. --require-pq fails unless the newest
anchor is v3; --pin-pq-key-id pins the ML-DSA-65 key.

Pin coverage: anchor pins prove history only up to the newest pinned anchor. Entries
after it are reported as entries_beyond_pin (warning); --require-full-pin fails then.

Trust levels reported (exit code 0 ONLY for anchor_pinned):
  internal_only : bundle is self-consistent. An attacker holding the operator's data
                  directory can regenerate a fully consistent bundle, so this alone
                  proves nothing about history.
  key_pinned    : internal_only AND the signing key id matches --pin-key-id.
  anchor_pinned : key_pinned/internal AND every --pin-anchor SEQ:HASH, held outside
                  the operator's infrastructure, matches. Each anchor hash chains to
                  its predecessor and commits to a ledger head, so pinning the newest
                  anchor pins the whole anchored ledger prefix.
Entries after the last anchor are NOT protected; they are reported as unanchored.

--receipt verifies an rf.receipt.v1 single-entry inclusion receipt. --consistency
verifies an rf.consistency.v1 append-only proof: the ledger signed by a later anchor
is the ledger signed by an earlier one with entries appended, shown with an RFC 9162
consistency path and no ledger entry. A holder of a pin for the earlier anchor learns
that nothing it covered was edited, removed or reordered, and gets the next pin.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
import zipfile
import zlib
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BUNDLE_SCHEMA = 'rf.evidence.v1'
BUNDLE_SCHEMA_V2 = 'rf.evidence.v2'
PQ_MEMBER = 'signing_key_mldsa65.pub.pem'
MEMBERS = ('manifest.json', 'ledger.jsonl', 'anchors.jsonl', 'signing_key.pub.pem')
MEMBERS_V2 = MEMBERS + (PQ_MEMBER,)
DATA_MEMBERS = MEMBERS[1:]
DATA_MEMBERS_V2 = MEMBERS_V2[1:]
SCHEMA_MEMBERS = {BUNDLE_SCHEMA: DATA_MEMBERS, BUNDLE_SCHEMA_V2: DATA_MEMBERS_V2}
PQ_SIGNATURE_CONTEXT = b'rf.anchor.v3'
PQ_KEY_PREFIX = 'mldsa65:'
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_PAYLOAD_BYTES = 262144
MAX_ENTRY_TYPE = 128
ZERO_HASH = '0' * 64
_HEX64 = re.compile(r'^[0-9a-f]{64}\Z')
_TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z')
LEDGER_KEYS = frozenset({'id', 'ts', 'entry_type', 'payload', 'prev_hash', 'entry_hash'})
ANCHOR_CORE_V2 = ('schema', 'seq', 'created_at', 'ledger_count', 'ledger_head',
                  'prev_anchor_hash', 'key_id')
ANCHOR_CORE_LEGACY = ANCHOR_CORE_V2[:-1]
ANCHOR_CORE_V3 = ANCHOR_CORE_V2 + ('pq_key_id',)
ANCHOR_CORE_V4 = ANCHOR_CORE_V3 + ('merkle_root',)
ANCHOR_SCHEMA_V2 = 'rf.anchor.v2'
ANCHOR_SCHEMA_V3 = 'rf.anchor.v3'
ANCHOR_SCHEMA_V4 = 'rf.anchor.v4'
HYBRID_SCHEMAS = (ANCHOR_SCHEMA_V3, ANCHOR_SCHEMA_V4)
PQ_CONTEXTS = {ANCHOR_SCHEMA_V3: b'rf.anchor.v3', ANCHOR_SCHEMA_V4: b'rf.anchor.v4'}
RECEIPT_SCHEMA = 'rf.receipt.v1'
RECEIPT_KEYS = frozenset({'schema', 'entry', 'leaf_index', 'tree_size', 'inclusion_path',
                          'anchor', 'signing_key_pem', 'pq_signing_key_pem'})
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
CONSISTENCY_SCHEMA = 'rf.consistency.v1'
CONSISTENCY_KEYS = frozenset({'schema', 'first_anchor', 'second_anchor', 'consistency_path',
                              'signing_key_pem', 'pq_signing_key_pem'})
EMPTY_MERKLE_ROOT = hashlib.sha256(b'').hexdigest()
MAX_PATH_LENGTH = 64


class VerificationError(Exception):
    """Raised on the first violated property. The verifier fails closed."""


def _fail(message: str) -> None:
    raise VerificationError(message)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f'duplicate JSON key {key!r}')
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    _fail(f'non-finite JSON constant {name}')


def _loads(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates,
                          parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        _fail(f'invalid JSON: {exc}')
        raise  # unreachable; keeps control flow explicit for static analysis


def _read_members(path: str) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or sorted(names) not in (sorted(MEMBERS),
                                                                     sorted(MEMBERS_V2)):
                _fail(f'unexpected archive members: {names}')
            members: dict[str, bytes] = {}
            for info in infos:
                if info.file_size > MAX_MEMBER_BYTES:
                    _fail(f'member {info.filename} exceeds size limit')
                with archive.open(info) as handle:
                    data = handle.read(MAX_MEMBER_BYTES + 1)
                if len(data) > MAX_MEMBER_BYTES:
                    _fail(f'member {info.filename} exceeds size limit')
                members[info.filename] = data
            return members
    except (zipfile.BadZipFile, OSError, NotImplementedError, RuntimeError,
            EOFError, zlib.error) as exc:
        _fail(f'cannot read bundle: {exc}')
    return {}


def _parse_lines(data: bytes, what: str) -> list[dict[str, Any]]:
    if not data:
        return []
    if not data.endswith(b'\n'):
        _fail(f'{what} is not newline-terminated')
    rows: list[dict[str, Any]] = []
    for number, raw in enumerate(data[:-1].split(b'\n'), 1):
        if not raw.strip():
            _fail(f'{what} line {number} is blank')
        if len(raw) > MAX_LINE_BYTES:
            _fail(f'{what} line {number} exceeds size limit')
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            _fail(f'{what} line {number} is not UTF-8')
        item = _loads(text)
        if not isinstance(item, dict):
            _fail(f'{what} line {number} is not an object')
        rows.append(item)
    return rows


def _load_public_key(pem: bytes) -> tuple[Ed25519PublicKey, str]:
    try:
        key = serialization.load_pem_public_key(pem)
    except Exception as exc:
        _fail(f'public key unreadable: {type(exc).__name__}')
    if not isinstance(key, Ed25519PublicKey):
        _fail('public key is not Ed25519')
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, 'ed25519:' + sha256_hex(raw)


def _load_pq_public_key(pem: bytes) -> tuple[Any, str]:
    try:
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
    except ImportError:
        _fail('bundle needs ML-DSA-65 verification but this cryptography build lacks it; '
              'upgrade cryptography')
    try:
        key = serialization.load_pem_public_key(pem)
    except Exception as exc:
        _fail(f'post-quantum public key unreadable: {type(exc).__name__}')
    if not isinstance(key, MLDSA65PublicKey):
        _fail('post-quantum public key is not ML-DSA-65')
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, PQ_KEY_PREFIX + sha256_hex(raw)


# --- RFC 9162 Merkle tree (independent implementation; leaves are raw entry hashes) ---

def _mt_leaf(entry_hash: str) -> bytes:
    return hashlib.sha256(b'\x00' + bytes.fromhex(entry_hash)).digest()


def _mt_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b'\x01' + left + right).digest()


def _merkle_roots(heads: list[str], sizes: set[int]) -> dict[int, str]:
    """Roots of the trees over entry hashes 1..size for every requested size, in one pass."""
    peaks: list[tuple[int, bytes]] = []
    roots: dict[int, str] = {}
    for size in range(0, max(sizes, default=0) + 1):
        if size:
            height, digest = 0, _mt_leaf(heads[size])
            while peaks and peaks[-1][0] == height:
                digest = _mt_node(peaks.pop()[1], digest)
                height += 1
            peaks.append((height, digest))
        if size in sizes:
            if not peaks:
                roots[size] = hashlib.sha256(b'').hexdigest()
            else:
                digest = peaks[-1][1]
                for _, left in reversed(peaks[:-1]):
                    digest = _mt_node(left, digest)
                roots[size] = digest.hex()
    return roots


def _root_from_path(entry_hash: str, index: int, size: int, path: list[Any]) -> str:
    """RFC 9162 section 2.1.3.2 inclusion verification; fails on any malformed proof."""
    if not 0 <= index < size:
        _fail('receipt leaf index is outside the tree')
    if len(path) > MAX_PATH_LENGTH:
        _fail('receipt inclusion path is too long')
    fn, sn, digest = index, size - 1, _mt_leaf(entry_hash)
    for item in path:
        if not isinstance(item, str) or not _HEX64.match(item):
            _fail('receipt inclusion path element is malformed')
        if sn == 0:
            _fail('receipt inclusion path is longer than the tree requires')
        sibling = bytes.fromhex(item)
        if fn & 1 or fn == sn:
            digest = _mt_node(sibling, digest)
            while not fn & 1 and fn:
                fn >>= 1
                sn >>= 1
        else:
            digest = _mt_node(digest, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        _fail('receipt inclusion path is shorter than the tree requires')
    return digest.hex()


def _roots_from_consistency_path(first_size: int, second_size: int, path: list[Any],
                                 first_root: str) -> tuple[str, str]:
    """RFC 9162 section 2.1.4.2 for 0 < first_size < second_size: the two roots a path implies."""
    if not path:
        _fail('consistency path is empty but the second anchor covers more entries')
    if len(path) > MAX_PATH_LENGTH:
        _fail('consistency path is too long')
    nodes: list[bytes] = []
    for item in path:
        if not isinstance(item, str) or not _HEX64.match(item):
            _fail('consistency path element is malformed')
        nodes.append(bytes.fromhex(item))
    if first_size & (first_size - 1) == 0:
        # The first tree is a complete subtree of the second; its root is not repeated.
        nodes.insert(0, bytes.fromhex(first_root))
    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    first = second = nodes[0]
    for sibling in nodes[1:]:
        if sn == 0:
            _fail('consistency path is longer than the trees require')
        if fn & 1 or fn == sn:
            first = _mt_node(sibling, first)
            second = _mt_node(sibling, second)
            while not fn & 1 and fn:
                fn >>= 1
                sn >>= 1
        else:
            second = _mt_node(second, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        _fail('consistency path is shorter than the trees require')
    return first.hex(), second.hex()


def _verify_manifest(members: dict[str, bytes]) -> dict[str, Any]:
    try:
        text = members['manifest.json'].decode('utf-8')
    except UnicodeDecodeError:
        _fail('manifest is not UTF-8')
    manifest = _loads(text)
    if not isinstance(manifest, dict):
        _fail('manifest is not an object')
    schema = manifest.get('schema')
    if schema not in SCHEMA_MEMBERS:
        _fail(f'unsupported bundle schema {schema!r}')
    data_members = SCHEMA_MEMBERS[schema]
    if set(members) != {'manifest.json', *data_members}:
        _fail(f'archive members do not match bundle schema {schema}')
    files = manifest.get('files')
    if not isinstance(files, dict) or set(files) != set(data_members):
        _fail('manifest file table is invalid')
    for name in data_members:
        entry = files[name]
        if not isinstance(entry, dict) or set(entry) != {'sha256', 'bytes'}:
            _fail(f'manifest entry for {name} is invalid')
        if entry['sha256'] != sha256_hex(members[name]):
            _fail(f'manifest sha256 mismatch for {name}')
        if not _is_int(entry['bytes']) or entry['bytes'] != len(members[name]):
            _fail(f'manifest size mismatch for {name}')
    return manifest


def _check_entry(entry: dict[str, Any], index: int) -> None:
    """Check one entry's format and that entry_hash is the hash of its content at `index`."""
    ts, entry_type, payload = entry['ts'], entry['entry_type'], entry['payload']
    prev_hash, entry_hash = entry['prev_hash'], entry['entry_hash']
    if not isinstance(ts, str) or not _TS.match(ts):
        _fail(f'bad timestamp at {index}')
    if not isinstance(entry_type, str) or not entry_type or len(entry_type) > MAX_ENTRY_TYPE:
        _fail(f'bad entry_type at {index}')
    if not isinstance(payload, str):
        _fail(f'payload is not a string at {index}')
    try:
        raw = payload.encode('utf-8')
    except UnicodeEncodeError:
        _fail(f'payload not encodable at {index}')
    if len(raw) > MAX_PAYLOAD_BYTES:
        _fail(f'payload too large at {index}')
    for value in (prev_hash, entry_hash):
        if not isinstance(value, str) or not _HEX64.match(value):
            _fail(f'malformed hash at {index}')
    parsed = _loads(payload)
    if not isinstance(parsed, dict):
        _fail(f'payload is not an object at {index}')
    if canonical_json(parsed) != payload:
        _fail(f'payload not canonical at {index}')
    expected = sha256_hex(f'{index}|{prev_hash}|{ts}|{entry_type}|{payload}'.encode('utf-8'))
    if not hmac.compare_digest(expected, entry_hash):
        _fail(f'hash mismatch at {index}')


def _verify_ledger(rows: list[dict[str, Any]]) -> list[str]:
    heads = [ZERO_HASH]
    previous = ZERO_HASH
    for index, entry in enumerate(rows, 1):
        if set(entry) != LEDGER_KEYS:
            _fail(f'ledger entry {index} has unexpected fields')
        entry_id = entry['id']
        if not _is_int(entry_id) or entry_id != index:
            _fail(f'id discontinuity at {entry_id!r}')
        prev_hash = entry['prev_hash']
        if not isinstance(prev_hash, str) or not _HEX64.match(prev_hash):
            _fail(f'malformed hash at {index}')
        if prev_hash != previous:
            _fail(f'previous hash mismatch at {index}')
        _check_entry(entry, index)
        previous = entry['entry_hash']
        heads.append(previous)
    return heads


def _check_anchor(anchor: dict[str, Any], index: int, public_key: Ed25519PublicKey,
                  key_id: str, pq: tuple[Any, str] | None, where: str = 'bundle',
                  chain: tuple[str, int, str] | None = None) -> tuple[bool, bool, bool]:
    """Validate one anchor's fields, hash and signature(s). Returns (legacy, hybrid, merkle).

    With `chain` = (previous anchor hash, previous ledger_count, previous created_at) the
    anchor is also checked as the index-th link of a chain, before any hashing.
    """
    legacy = 'key_id' not in anchor
    schema = anchor.get('schema')
    hybrid = schema in HYBRID_SCHEMAS
    merkle = schema == ANCHOR_SCHEMA_V4
    if legacy and hybrid:
        _fail(f'anchor {index} claims {schema} without a key identity')
    core_keys = (ANCHOR_CORE_LEGACY if legacy else ANCHOR_CORE_V4 if merkle
                 else ANCHOR_CORE_V3 if hybrid else ANCHOR_CORE_V2)
    signatures = {'anchor_hash', 'signature', 'pq_signature'} if hybrid else {'anchor_hash', 'signature'}
    if set(anchor) != set(core_keys) | signatures:
        _fail(f'anchor {index} has unexpected fields')
    if not _is_int(anchor['seq']) or anchor['seq'] < 1:
        _fail(f'anchor {index} has invalid seq')
    if chain is not None and anchor['seq'] != index:
        _fail(f'anchor sequence mismatch at {index}')
    if not _is_int(anchor['ledger_count']) or anchor['ledger_count'] < 0:
        _fail(f'anchor {index} has invalid ledger_count')
    for name in ('ledger_head', 'prev_anchor_hash', 'anchor_hash') + (('merkle_root',) if merkle else ()):
        value = anchor[name]
        if not isinstance(value, str) or not _HEX64.match(value):
            _fail(f'anchor {index} has malformed {name}')
    created = anchor['created_at']
    if not isinstance(created, str) or not _TS.match(created):
        _fail(f'anchor {index} has malformed created_at')
    if not isinstance(schema, str) or not isinstance(anchor['signature'], str):
        _fail(f'anchor {index} has malformed fields')
    if not legacy:
        if schema not in (ANCHOR_SCHEMA_V2,) + HYBRID_SCHEMAS:
            _fail(f'anchor {index} has unsupported schema')
        if anchor['key_id'] != key_id:
            _fail(f'key identity mismatch at anchor {index}')
    if chain is not None:
        previous_hash, previous_count, previous_ts = chain
        if anchor['prev_anchor_hash'] != previous_hash:
            _fail(f'anchor chain broken at {index}')
        if anchor['ledger_count'] < previous_count:
            _fail(f'ledger count regressed at anchor {index}')
        if created < previous_ts:
            _fail(f'anchor time regressed at {index}')
    core = {name: anchor[name] for name in core_keys}
    material = (json.dumps(core, sort_keys=True) if legacy else canonical_json(core)).encode('utf-8')
    if not hmac.compare_digest(sha256_hex(material), anchor['anchor_hash']):
        _fail(f'anchor hash mismatch at {index}')
    try:
        signature = base64.b64decode(anchor['signature'], validate=True)
    except ValueError:
        _fail(f'anchor {index} signature is not base64')
    try:
        public_key.verify(signature, anchor['anchor_hash'].encode('ascii'))
    except InvalidSignature:
        _fail(f'anchor signature invalid at {index}')
    if hybrid:
        if pq is None:
            _fail(f'anchor {index} is post-quantum but the {where} has no ML-DSA-65 key')
        if anchor['pq_key_id'] != pq[1]:
            _fail(f'post-quantum key identity mismatch at anchor {index}')
        if not isinstance(anchor['pq_signature'], str):
            _fail(f'anchor {index} has malformed pq_signature')
        try:
            pq_signature = base64.b64decode(anchor['pq_signature'], validate=True)
        except ValueError:
            _fail(f'anchor {index} pq_signature is not base64')
        try:
            pq[0].verify(pq_signature, anchor['anchor_hash'].encode('ascii'), PQ_CONTEXTS[schema])
        except InvalidSignature:
            _fail(f'post-quantum signature invalid at anchor {index}')
    return legacy, hybrid, merkle


def _verify_anchors(rows: list[dict[str, Any]], heads: list[str], total: int,
                    public_key: Ed25519PublicKey, key_id: str,
                    pq: tuple[Any, str] | None = None) -> dict[str, int]:
    previous_hash = ZERO_HASH
    previous_count = 0
    previous_ts = ''
    legacy_count = 0
    pq_count = 0
    pq_through = 0
    merkle_count = 0
    merkle_through = 0
    merkle_claims: list[tuple[int, int, str]] = []
    for index, anchor in enumerate(rows, 1):
        schema = anchor.get('schema')
        if pq_count and schema not in HYBRID_SCHEMAS:
            _fail(f'post-quantum downgrade at anchor {index}')
        if merkle_count and schema != ANCHOR_SCHEMA_V4:
            _fail(f'merkle commitment downgrade at anchor {index}')
        legacy, hybrid, merkle = _check_anchor(
            anchor, index, public_key, key_id, pq,
            chain=(previous_hash, previous_count, previous_ts))
        count, created = anchor['ledger_count'], anchor['created_at']
        legacy_count += legacy
        if count > total:
            _fail(f'ledger shorter than anchor {index}')
        if not hmac.compare_digest(heads[count], anchor['ledger_head']):
            _fail(f'anchor {index} ledger_head does not match ledger entry {count}')
        if hybrid:
            pq_count += 1
            pq_through = count
        if merkle:
            merkle_count += 1
            merkle_through = count
            merkle_claims.append((index, count, anchor['merkle_root']))
        previous_hash = anchor['anchor_hash']
        previous_count = count
        previous_ts = created
    roots = _merkle_roots(heads, {count for _, count, _ in merkle_claims})
    for index, count, claimed in merkle_claims:
        if not hmac.compare_digest(roots[count], claimed):
            _fail(f'merkle root mismatch at anchor {index}')
    return {'legacy': legacy_count, 'pq_anchors': pq_count, 'pq_through': pq_through,
            'merkle_anchors': merkle_count, 'merkle_through': merkle_through}


def verify_bundle(path: str, pin_key_id: str | None = None,
                  pin_anchors: Sequence[tuple[int, str]] = (),
                  min_anchors: int = 0,
                  pin_pq_key_id: str | None = None,
                  require_pq: bool = False,
                  require_full_pin: bool = False) -> dict[str, Any]:
    members = _read_members(path)
    manifest = _verify_manifest(members)
    public_key, key_id = _load_public_key(members['signing_key.pub.pem'])
    pq = _load_pq_public_key(members[PQ_MEMBER]) if PQ_MEMBER in members else None
    entries = _parse_lines(members['ledger.jsonl'], 'ledger')
    anchors = _parse_lines(members['anchors.jsonl'], 'anchors')
    heads = _verify_ledger(entries)
    total = len(entries)
    stats = _verify_anchors(anchors, heads, total, public_key, key_id, pq)
    head = heads[total]

    if manifest.get('ledger_count') != total or manifest.get('ledger_head') != head:
        _fail('manifest ledger summary does not match ledger')
    if manifest.get('anchor_count') != len(anchors) or manifest.get('key_id') != key_id:
        _fail('manifest anchor/key summary does not match bundle')
    if manifest.get('pq_key_id') != (pq[1] if pq else None):
        _fail('manifest post-quantum key summary does not match bundle')

    trust = 'internal_only'
    if pin_key_id is not None:
        if pin_key_id != key_id:
            _fail(f'bundle key {key_id} does not match pinned key {pin_key_id}')
        trust = 'key_pinned'
    if pin_pq_key_id is not None:
        if pq is None:
            _fail('post-quantum key pin supplied but the bundle has no ML-DSA-65 key')
        if pin_pq_key_id != pq[1]:
            _fail(f'bundle post-quantum key {pq[1]} does not match pinned key {pin_pq_key_id}')
    if require_pq and (not anchors or anchors[-1]['schema'] not in HYBRID_SCHEMAS):
        _fail('newest anchor carries no post-quantum signature (--require-pq)')
    if len(anchors) < min_anchors:
        _fail(f'bundle has {len(anchors)} anchors, fewer than required {min_anchors}')
    for seq, expected in pin_anchors:
        if seq < 1 or seq > len(anchors):
            _fail(f'pinned anchor {seq} is missing from bundle ({len(anchors)} anchors)')
        if anchors[seq - 1]['anchor_hash'] != expected:
            _fail(f'pinned anchor {seq} hash mismatch')
    pinned_through = max((anchors[seq - 1]['ledger_count'] for seq, _ in pin_anchors), default=0)
    beyond_pin = total - pinned_through if pin_anchors else None
    if require_full_pin:
        if not pin_anchors:
            _fail('--require-full-pin needs at least one --pin-anchor')
        if beyond_pin:
            _fail(f'{beyond_pin} entries after pinned anchor coverage (entry {pinned_through})')
    if pin_anchors:
        trust = 'anchor_pinned'

    anchored = anchors[-1]['ledger_count'] if anchors else 0
    unanchored = total - anchored
    warnings: list[str] = []
    if trust != 'anchor_pinned':
        warnings.append('No externally held anchor pin supplied: an attacker with the operator data '
                        'directory can regenerate a consistent bundle. Pin an anchor hash.')
    elif beyond_pin:
        warnings.append(f'{beyond_pin} entries after entry {pinned_through} are covered only by the '
                        'operator key, not by an external pin. Pin the newest anchor.')
    if not anchors:
        warnings.append('Bundle has no anchors: the ledger prefix carries no signature.')
    if unanchored:
        warnings.append(f'{unanchored} trailing entries are not covered by any anchor.')
    if stats['legacy']:
        warnings.append(f'{stats["legacy"]} legacy anchors use the pre-v2 hash encoding.')
    if anchors and not stats['pq_anchors']:
        warnings.append('No post-quantum anchor signatures: anchors rely on Ed25519 alone.')
    elif stats['pq_anchors'] and stats['pq_through'] < total:
        warnings.append(f'{total - stats["pq_through"]} entries are not yet covered by a '
                        'post-quantum anchor signature.')
    report = {'status': 'VERIFIED', 'trust_level': trust, 'ledger_entries': total,
              'ledger_head': head, 'anchors': len(anchors), 'unanchored_entries': unanchored,
              'key_id': key_id, 'post_quantum': 'hybrid' if stats['pq_anchors'] else 'none',
              'pq_anchors': stats['pq_anchors'], 'pq_protected_through_entry': stats['pq_through'],
              'merkle_anchors': stats['merkle_anchors'],
              'merkle_committed_through_entry': stats['merkle_through'],
              'warnings': warnings}
    if pq is not None:
        report['pq_key_id'] = pq[1]
    if pin_anchors:
        report['pinned_through_entry'] = pinned_through
        report['entries_beyond_pin'] = beyond_pin
    return report


def _receipt_key(pem: Any, loader: Any, what: str) -> tuple[Any, str]:
    if not isinstance(pem, str) or len(pem) > 65536:
        _fail(f'receipt {what} is malformed')
    try:
        data = pem.encode('ascii')
    except UnicodeEncodeError:
        _fail(f'receipt {what} is not ASCII PEM')
    return loader(data)


def _read_document(path: str, what: str) -> Any:
    """Read one size-limited, strictly parsed JSON document (a receipt or a consistency proof)."""
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(MAX_RECEIPT_BYTES + 1)
    except OSError as exc:
        _fail(f'cannot read {what}: {exc}')
    if len(raw) > MAX_RECEIPT_BYTES:
        _fail(f'{what} exceeds size limit')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        _fail(f'{what} is not UTF-8')
    return _loads(text)


def verify_receipt(path: str, pin_key_id: str | None = None,
                   pin_anchors: Sequence[tuple[int, str]] = (),
                   pin_pq_key_id: str | None = None) -> dict[str, Any]:
    """Verify an rf.receipt.v1 single-entry inclusion receipt offline.

    Proves that one entry, exactly as shown, is entry `id` of the ledger whose first
    `tree_size` entries are committed to by a hybrid-signed rf.anchor.v4 Merkle root,
    without disclosing any other entry. Trust levels match bundle verification; the
    receipt is anchor_pinned only when a --pin-anchor names its anchor's seq and hash.
    """
    receipt = _read_document(path, 'receipt')
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS:
        _fail('receipt has unexpected fields')
    if receipt['schema'] != RECEIPT_SCHEMA:
        _fail(f'unsupported receipt schema {receipt["schema"]!r}')

    public_key, key_id = _receipt_key(receipt['signing_key_pem'], _load_public_key, 'Ed25519 key')
    pq = _receipt_key(receipt['pq_signing_key_pem'], _load_pq_public_key, 'ML-DSA-65 key')

    entry = receipt['entry']
    if not isinstance(entry, dict):
        _fail('receipt entry is not an object')
    entry_id = entry.get('id')
    if not _is_int(entry_id) or entry_id < 1:
        _fail('receipt entry has an invalid id')
    if set(entry) != LEDGER_KEYS:
        _fail('receipt entry has unexpected fields')
    _check_entry(entry, entry_id)

    anchor = receipt['anchor']
    if not isinstance(anchor, dict):
        _fail('receipt anchor is not an object')
    if anchor.get('schema') != ANCHOR_SCHEMA_V4:
        _fail('receipt anchor is not a hybrid Merkle anchor (rf.anchor.v4)')
    seq = anchor.get('seq')
    _check_anchor(anchor, seq if _is_int(seq) else 0, public_key, key_id, pq, where='receipt')

    size, leaf_index, path_items = receipt['tree_size'], receipt['leaf_index'], receipt['inclusion_path']
    if not _is_int(size) or size != anchor['ledger_count']:
        _fail('receipt tree_size does not match the anchored ledger_count')
    if not _is_int(leaf_index) or leaf_index != entry_id - 1:
        _fail('receipt leaf_index does not match the entry id')
    if entry_id > size:
        _fail('receipt entry lies beyond the anchored tree')
    if not isinstance(path_items, list):
        _fail('receipt inclusion_path is not a list')
    root = _root_from_path(entry['entry_hash'], leaf_index, size, path_items)
    if not hmac.compare_digest(root, anchor['merkle_root']):
        _fail('receipt inclusion proof does not reach the signed merkle_root')
    if entry_id == size and not hmac.compare_digest(entry['entry_hash'], anchor['ledger_head']):
        _fail('receipt entry is the anchored head but differs from ledger_head')

    trust = 'internal_only'
    if pin_key_id is not None:
        if pin_key_id != key_id:
            _fail(f'receipt key {key_id} does not match pinned key {pin_key_id}')
        trust = 'key_pinned'
    if pin_pq_key_id is not None and pin_pq_key_id != pq[1]:
        _fail(f'receipt post-quantum key {pq[1]} does not match pinned key {pin_pq_key_id}')
    warnings: list[str] = []
    if pin_anchors:
        matching = [digest for pin_seq, digest in pin_anchors if pin_seq == anchor['seq']]
        if not matching:
            _fail(f'no --pin-anchor for receipt anchor {anchor["seq"]}; export the receipt '
                  'against an anchor you hold a pin for (--anchor-seq)')
        if any(digest != anchor['anchor_hash'] for digest in matching):
            _fail(f'pinned anchor {anchor["seq"]} hash mismatch')
        trust = 'anchor_pinned'
        ignored = sorted({pin_seq for pin_seq, _ in pin_anchors if pin_seq != anchor['seq']})
        if ignored:
            warnings.append(f'pins for anchors {ignored} do not apply to this receipt and were not checked.')
    else:
        warnings.append('No externally held anchor pin supplied: anyone holding the operator keys '
                        'can produce a consistent receipt. Pin the anchor hash.')
    return {'status': 'VERIFIED', 'type': RECEIPT_SCHEMA, 'trust_level': trust,
            'entry_id': entry_id, 'entry_hash': entry['entry_hash'], 'entry_type': entry['entry_type'],
            'anchor_seq': anchor['seq'], 'anchor_hash': anchor['anchor_hash'], 'tree_size': size,
            'merkle_root': anchor['merkle_root'], 'key_id': key_id, 'pq_key_id': pq[1],
            'post_quantum': 'hybrid', 'warnings': warnings}


def verify_consistency(path: str, pin_key_id: str | None = None,
                       pin_anchors: Sequence[tuple[int, str]] = (),
                       pin_pq_key_id: str | None = None) -> dict[str, Any]:
    """Verify an rf.consistency.v1 append-only proof between two anchors offline.

    Proves that the ledger of `second_anchor` is the ledger of `first_anchor` with
    entries appended: every entry the first anchor covered is still there, unchanged
    and in the same position. Both anchors must be hybrid-signed rf.anchor.v4 anchors
    under the same keys, and the RFC 9162 consistency path must reproduce BOTH signed
    Merkle roots. No ledger entry is needed or disclosed.

    The proof is anchor_pinned only when a --pin-anchor names one of its two anchors
    (normally the first, held since the last review); every pin naming either anchor
    must match. The report's next_pin is the second anchor, to hold from now on.
    """
    proof = _read_document(path, 'consistency proof')
    if not isinstance(proof, dict) or set(proof) != CONSISTENCY_KEYS:
        _fail('consistency proof has unexpected fields')
    if proof['schema'] != CONSISTENCY_SCHEMA:
        _fail(f'unsupported consistency proof schema {proof["schema"]!r}')

    public_key, key_id = _receipt_key(proof['signing_key_pem'], _load_public_key, 'Ed25519 key')
    pq = _receipt_key(proof['pq_signing_key_pem'], _load_pq_public_key, 'ML-DSA-65 key')

    first, second = proof['first_anchor'], proof['second_anchor']
    for name, anchor in (('first', first), ('second', second)):
        if not isinstance(anchor, dict):
            _fail(f'consistency proof {name}_anchor is not an object')
        if anchor.get('schema') != ANCHOR_SCHEMA_V4:
            _fail(f'consistency proof {name}_anchor is not a hybrid Merkle anchor (rf.anchor.v4)')
        seq = anchor.get('seq')
        _check_anchor(anchor, seq if _is_int(seq) else 0, public_key, key_id, pq,
                      where='consistency proof')

    if first['seq'] >= second['seq']:
        _fail('consistency proof second_anchor is not later than first_anchor')
    first_size, second_size = first['ledger_count'], second['ledger_count']
    if second_size < first_size:
        _fail('ledger count regressed between the two anchors')
    if second['created_at'] < first['created_at']:
        _fail('anchor time regressed between the two anchors')
    if second['seq'] == first['seq'] + 1 and \
            not hmac.compare_digest(second['prev_anchor_hash'], first['anchor_hash']):
        _fail('second_anchor does not chain to first_anchor')

    path_items = proof['consistency_path']
    if not isinstance(path_items, list):
        _fail('consistency_path is not a list')
    first_root, second_root = first['merkle_root'], second['merkle_root']
    if first_size == 0:
        # The empty ledger is a prefix of every ledger; nothing to prove beyond its form.
        if path_items:
            _fail('consistency path must be empty when the first anchor covers no entries')
        if first_root != EMPTY_MERKLE_ROOT or first['ledger_head'] != ZERO_HASH:
            _fail('first_anchor covers no entries but does not sign the empty ledger')
    elif first_size == second_size:
        if path_items:
            _fail('consistency path must be empty when both anchors cover the same entries')
        if not hmac.compare_digest(first_root, second_root) or \
                not hmac.compare_digest(first['ledger_head'], second['ledger_head']):
            _fail('anchors cover the same number of entries but sign different ledgers')
    else:
        computed_first, computed_second = _roots_from_consistency_path(
            first_size, second_size, path_items, first_root)
        if not hmac.compare_digest(computed_first, first_root):
            _fail('consistency proof does not reach the merkle_root signed by first_anchor')
        if not hmac.compare_digest(computed_second, second_root):
            _fail('consistency proof does not reach the merkle_root signed by second_anchor')

    trust = 'internal_only'
    if pin_key_id is not None:
        if pin_key_id != key_id:
            _fail(f'consistency proof key {key_id} does not match pinned key {pin_key_id}')
        trust = 'key_pinned'
    if pin_pq_key_id is not None and pin_pq_key_id != pq[1]:
        _fail(f'consistency proof post-quantum key {pq[1]} does not match pinned key '
              f'{pin_pq_key_id}')
    warnings: list[str] = []
    pinned: list[int] = []
    if pin_anchors:
        for anchor in (first, second):
            matching = [digest for pin_seq, digest in pin_anchors if pin_seq == anchor['seq']]
            if any(digest != anchor['anchor_hash'] for digest in matching):
                _fail(f'pinned anchor {anchor["seq"]} hash mismatch')
            if matching:
                pinned.append(anchor['seq'])
        if not pinned:
            _fail(f'no --pin-anchor for anchor {first["seq"]} or {second["seq"]}; export the '
                  'proof from an anchor you hold a pin for (--from-seq)')
        trust = 'anchor_pinned'
        ignored = sorted({pin_seq for pin_seq, _ in pin_anchors
                          if pin_seq not in (first['seq'], second['seq'])})
        if ignored:
            warnings.append(f'pins for anchors {ignored} do not apply to this proof and were not checked.')
    else:
        warnings.append('No externally held anchor pin supplied: anyone holding the operator keys '
                        'can produce two consistent anchors. Pin the first anchor hash.')
    return {'status': 'VERIFIED', 'type': CONSISTENCY_SCHEMA, 'trust_level': trust,
            'first_anchor_seq': first['seq'], 'first_anchor_hash': first['anchor_hash'],
            'first_tree_size': first_size, 'first_merkle_root': first_root,
            'second_anchor_seq': second['seq'], 'second_anchor_hash': second['anchor_hash'],
            'second_tree_size': second_size, 'second_merkle_root': second_root,
            'appended_entries': second_size - first_size, 'pinned_anchors': pinned,
            'next_pin': f'{second["seq"]}:{second["anchor_hash"]}',
            'key_id': key_id, 'pq_key_id': pq[1], 'post_quantum': 'hybrid', 'warnings': warnings}


def _parse_pin(text: str) -> tuple[int, str]:
    seq_text, _, digest = text.partition(':')
    if not seq_text.isdigit() or not _HEX64.match(digest):
        raise argparse.ArgumentTypeError('expected SEQ:SHA256HEX (lowercase, 64 hex chars)')
    return int(seq_text), digest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='Verify a RightsFrames evidence bundle, or with --receipt a single-entry '
                    'inclusion receipt, or with --consistency an append-only proof between '
                    'two anchors, offline.')
    parser.add_argument('bundle', help='evidence bundle (.zip), receipt (.json) with --receipt, '
                                       'or consistency proof (.json) with --consistency')
    parser.add_argument('--receipt', action='store_true',
                        help='verify an rf.receipt.v1 single-entry inclusion receipt')
    parser.add_argument('--consistency', action='store_true',
                        help='verify an rf.consistency.v1 append-only proof between two anchors')
    parser.add_argument('--pin-key-id')
    parser.add_argument('--pin-anchor', action='append', default=[], type=_parse_pin,
                        metavar='SEQ:HASH')
    parser.add_argument('--min-anchors', type=int, default=0)
    parser.add_argument('--pin-pq-key-id', metavar='mldsa65:HEX',
                        help='expected ML-DSA-65 key id (post-quantum key pin)')
    parser.add_argument('--require-pq', action='store_true',
                        help='fail unless the newest anchor carries a post-quantum signature')
    parser.add_argument('--require-full-pin', action='store_true',
                        help='fail if any entry lies beyond the newest pinned anchor')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.receipt and args.consistency:
            raise VerificationError('--receipt and --consistency cannot be combined')
        if (args.receipt or args.consistency) and (args.min_anchors or args.require_full_pin):
            raise VerificationError('--min-anchors and --require-full-pin apply to bundles only')
        if args.consistency:
            # Both anchors are always hybrid, so --require-pq holds by construction.
            report = verify_consistency(args.bundle, args.pin_key_id, args.pin_anchor,
                                        pin_pq_key_id=args.pin_pq_key_id)
        elif args.receipt:
            # A receipt is always hybrid, so --require-pq holds by construction.
            report = verify_receipt(args.bundle, args.pin_key_id, args.pin_anchor,
                                    pin_pq_key_id=args.pin_pq_key_id)
        else:
            report = verify_bundle(args.bundle, args.pin_key_id, args.pin_anchor, args.min_anchors,
                                   pin_pq_key_id=args.pin_pq_key_id, require_pq=args.require_pq,
                                   require_full_pin=args.require_full_pin)
        code = 0 if report['trust_level'] == 'anchor_pinned' else 10
    except VerificationError as exc:
        report, code = {'status': 'FAILED', 'error': str(exc)}, 1
    except Exception as exc:  # fail closed on anything unexpected
        report, code = {'status': 'FAILED', 'error': f'internal verifier error: {type(exc).__name__}: {exc}'}, 1
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        for key, value in report.items():
            if key == 'warnings':
                for warning in value:
                    print(f'WARNING: {warning}')
            else:
                print(f'{key}: {value}')
    return code


if __name__ == '__main__':
    sys.exit(main())