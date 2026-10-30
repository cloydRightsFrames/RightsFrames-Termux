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
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$')
LEDGER_KEYS = frozenset({'id', 'ts', 'entry_type', 'payload', 'prev_hash', 'entry_hash'})
ANCHOR_CORE_V2 = ('schema', 'seq', 'created_at', 'ledger_count', 'ledger_head',
                  'prev_anchor_hash', 'key_id')
ANCHOR_CORE_LEGACY = ANCHOR_CORE_V2[:-1]
ANCHOR_CORE_V3 = ANCHOR_CORE_V2 + ('pq_key_id',)
ANCHOR_SCHEMA_V2 = 'rf.anchor.v2'
ANCHOR_SCHEMA_V3 = 'rf.anchor.v3'


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


def _verify_ledger(rows: list[dict[str, Any]]) -> list[str]:
    heads = [ZERO_HASH]
    previous = ZERO_HASH
    for index, entry in enumerate(rows, 1):
        if set(entry) != LEDGER_KEYS:
            _fail(f'ledger entry {index} has unexpected fields')
        entry_id = entry['id']
        if not _is_int(entry_id) or entry_id != index:
            _fail(f'id discontinuity at {entry_id!r}')
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
        if prev_hash != previous:
            _fail(f'previous hash mismatch at {index}')
        parsed = _loads(payload)
        if not isinstance(parsed, dict):
            _fail(f'payload is not an object at {index}')
        if canonical_json(parsed) != payload:
            _fail(f'payload not canonical at {index}')
        expected = sha256_hex(f'{index}|{prev_hash}|{ts}|{entry_type}|{payload}'.encode('utf-8'))
        if not hmac.compare_digest(expected, entry_hash):
            _fail(f'hash mismatch at {index}')
        previous = entry_hash
        heads.append(entry_hash)
    return heads


def _verify_anchors(rows: list[dict[str, Any]], heads: list[str], total: int,
                    public_key: Ed25519PublicKey, key_id: str,
                    pq: tuple[Any, str] | None = None) -> dict[str, int]:
    previous_hash = ZERO_HASH
    previous_count = 0
    previous_ts = ''
    legacy_count = 0
    pq_count = 0
    pq_through = 0
    for index, anchor in enumerate(rows, 1):
        legacy = 'key_id' not in anchor
        hybrid = anchor.get('schema') == ANCHOR_SCHEMA_V3
        if legacy and hybrid:
            _fail(f'anchor {index} claims {ANCHOR_SCHEMA_V3} without a key identity')
        if pq_count and not hybrid:
            _fail(f'post-quantum downgrade at anchor {index}')
        core_keys = ANCHOR_CORE_LEGACY if legacy else (ANCHOR_CORE_V3 if hybrid else ANCHOR_CORE_V2)
        signatures = {'anchor_hash', 'signature', 'pq_signature'} if hybrid else {'anchor_hash', 'signature'}
        if set(anchor) != set(core_keys) | signatures:
            _fail(f'anchor {index} has unexpected fields')
        seq, count = anchor['seq'], anchor['ledger_count']
        if not _is_int(seq) or seq != index:
            _fail(f'anchor sequence mismatch at {index}')
        if not _is_int(count) or count < 0:
            _fail(f'anchor {index} has invalid ledger_count')
        for name in ('ledger_head', 'prev_anchor_hash', 'anchor_hash'):
            value = anchor[name]
            if not isinstance(value, str) or not _HEX64.match(value):
                _fail(f'anchor {index} has malformed {name}')
        created = anchor['created_at']
        if not isinstance(created, str) or not _TS.match(created):
            _fail(f'anchor {index} has malformed created_at')
        if not isinstance(anchor['schema'], str) or not isinstance(anchor['signature'], str):
            _fail(f'anchor {index} has malformed fields')
        if not legacy:
            if anchor['schema'] not in (ANCHOR_SCHEMA_V2, ANCHOR_SCHEMA_V3):
                _fail(f'anchor {index} has unsupported schema')
            if anchor['key_id'] != key_id:
                _fail(f'key identity mismatch at anchor {index}')
        else:
            legacy_count += 1
        if anchor['prev_anchor_hash'] != previous_hash:
            _fail(f'anchor chain broken at {index}')
        if count < previous_count:
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
                _fail(f'anchor {index} is post-quantum but the bundle has no ML-DSA-65 key')
            if anchor['pq_key_id'] != pq[1]:
                _fail(f'post-quantum key identity mismatch at anchor {index}')
            if not isinstance(anchor['pq_signature'], str):
                _fail(f'anchor {index} has malformed pq_signature')
            try:
                pq_signature = base64.b64decode(anchor['pq_signature'], validate=True)
            except ValueError:
                _fail(f'anchor {index} pq_signature is not base64')
            try:
                pq[0].verify(pq_signature, anchor['anchor_hash'].encode('ascii'),
                             PQ_SIGNATURE_CONTEXT)
            except InvalidSignature:
                _fail(f'post-quantum signature invalid at anchor {index}')
            pq_count += 1
        if count > total:
            _fail(f'ledger shorter than anchor {index}')
        if not hmac.compare_digest(heads[count], anchor['ledger_head']):
            _fail(f'anchor {index} ledger_head does not match ledger entry {count}')
        if hybrid:
            pq_through = count
        previous_hash = anchor['anchor_hash']
        previous_count = count
        previous_ts = created
    return {'legacy': legacy_count, 'pq_anchors': pq_count, 'pq_through': pq_through}


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
    if require_pq and (not anchors or anchors[-1]['schema'] != ANCHOR_SCHEMA_V3):
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
              'warnings': warnings}
    if pq is not None:
        report['pq_key_id'] = pq[1]
    if pin_anchors:
        report['pinned_through_entry'] = pinned_through
        report['entries_beyond_pin'] = beyond_pin
    return report


def _parse_pin(text: str) -> tuple[int, str]:
    seq_text, _, digest = text.partition(':')
    if not seq_text.isdigit() or not _HEX64.match(digest):
        raise argparse.ArgumentTypeError('expected SEQ:SHA256HEX (lowercase, 64 hex chars)')
    return int(seq_text), digest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Verify a RightsFrames evidence bundle offline.')
    parser.add_argument('bundle')
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