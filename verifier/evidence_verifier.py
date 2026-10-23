"""Independent verifier for rf.evidence.v1 envelopes, ledger records, Merkle proofs,
consistency proofs, signed checkpoints and detached signatures.

Trust model (fail closed):

* Nothing inside a file under verification is trusted to vouch for itself. A public key
  shipped next to a signature, or a root shipped inside a proof, proves nothing: an attacker
  who writes the file can choose both.
* Trust enters ONLY through command-line pins held outside the operator's infrastructure:
  --trusted-key / --trusted-key-id (signing keys) and --trusted-root (Merkle roots).
* A checkpoint signed by a pinned key makes its root trusted for the remaining checks.
* ENVELOPE_INTEGRITY is an unkeyed digest: it detects accidental or partial modification but
  is NOT authenticity. Authenticity comes from a pinned signature over a checkpoint whose
  tree contains the envelope's ledger record.

Exit codes: 0 every requested check passed, 1 at least one failed, 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

from core.evidence.envelope import loads_strict, verify_envelope
from core.evidence.ledger import LedgerRecord, verify_chain
from core.evidence.merkle import (
    MERKLE_SCHEMA,
    MerkleCheckpoint,
    MerkleProof,
    checkpoint_bytes,
    merkle_root,
    verify_consistency,
    verify_inclusion,
    verify_proof,
)
from core.evidence.signing import key_id_for
from core.evidence.signing import verify as verify_signature

MAX_INPUT_BYTES = 64 * 1024 * 1024
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_KEY_ID = re.compile(r'^ed25519:[0-9a-f]{64}$')

Result = tuple[bool, str]


class TrustStore:
    """Pins supplied by the relying party. Never populated from files under verification,
    except roots taken from checkpoints that verified against a pinned key."""

    def __init__(self, keys: Iterable[str] = (), key_ids: Iterable[str] = (),
                 roots: Iterable[str] = ()) -> None:
        self.keys: set[str] = set()
        self.key_ids: set[str] = set()
        self.roots: set[str] = set()
        for key in keys:
            if not isinstance(key, str) or not _HEX64.match(key):
                raise ValueError('trusted key must be 64 lowercase hex characters (raw Ed25519)')
            self.keys.add(key)
            self.key_ids.add(key_id_for(bytes.fromhex(key)))
        for key_id in key_ids:
            if not isinstance(key_id, str) or not _KEY_ID.match(key_id):
                raise ValueError('trusted key id must look like ed25519:<64 hex>')
            self.key_ids.add(key_id)
        for root in roots:
            if not isinstance(root, str) or not _HEX64.match(root):
                raise ValueError('trusted root must be 64 lowercase hex characters')
            self.roots.add(root)

    def key_trusted(self, public_key_hex: str) -> bool:
        if public_key_hex in self.keys:
            return True
        try:
            return key_id_for(bytes.fromhex(public_key_hex)) in self.key_ids
        except ValueError:
            return False


def load_json(path: Path) -> Any:
    path = Path(path)
    if not path.is_file():
        raise ValueError(f'not a regular file: {path}')
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f'input exceeds {MAX_INPUT_BYTES} bytes: {path}')
    return loads_strict(path.read_bytes())


def _guard(func):
    def wrapper(*args: Any, **kwargs: Any) -> Result:
        try:
            return func(*args, **kwargs)
        except (ValueError, TypeError, KeyError, OSError, UnicodeError, RecursionError):
            return False, 'malformed_input'
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


@_guard
def verify_envelope_file(path: Path) -> Result:
    data = load_json(path)
    if not isinstance(data, dict):
        return False, 'envelope'
    return verify_envelope(data)


def _records(data: Any) -> list[LedgerRecord]:
    if not isinstance(data, list):
        raise ValueError('ledger must be a JSON array')
    records: list[LedgerRecord] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError('ledger record must be an object')
        records.append(LedgerRecord(
            ledger_sequence=item['ledger_sequence'],
            event_id=item['event_id'],
            payload_digest=item['payload_digest'],
            previous_record_digest=item.get('previous_record_digest'),
            record_digest=item['record_digest'],
        ))
    return records


@_guard
def verify_ledger_file(path: Path) -> Result:
    return verify_chain(_records(load_json(path)))


@_guard
def verify_ledger_checkpoint_binding(path: Path, checkpoint: MerkleCheckpoint) -> Result:
    """The ledger prefix of checkpoint.tree_size records must hash to the checkpoint root.

    Detects truncation (fewer records than signed), and substitution or regeneration of any
    record inside the signed prefix. Records after the checkpoint are reported, not trusted.
    """
    records = _records(load_json(path))
    ok, reason = verify_chain(records)
    if not ok:
        return False, reason
    if checkpoint.tree_size > len(records):
        return False, 'ledger_truncated_below_checkpoint'
    prefix = [record.record_digest for record in records[:checkpoint.tree_size]]
    if merkle_root(prefix) != checkpoint.root_hash:
        return False, 'ledger_does_not_match_checkpoint'
    extra = len(records) - checkpoint.tree_size
    return True, 'valid' if extra == 0 else f'valid;{extra}_records_after_checkpoint_unverified'


@_guard
def verify_proof_file(path: Path, trust: TrustStore | None = None) -> Result:
    data = load_json(path)
    if not isinstance(data, dict):
        return False, 'invalid_json'
    siblings_key = 'siblings' if 'siblings' in data else 'audit_path'
    if siblings_key not in data:
        return False, 'missing_siblings'
    if not isinstance(data[siblings_key], list):
        return False, 'invalid_siblings'
    if 'leaf_index' not in data:
        return False, 'missing_leaf_index'

    trusted_roots = trust.roots if trust else set()
    claimed_root = data.get('root_hash')
    if claimed_root is not None and claimed_root not in trusted_roots:
        return False, 'untrusted_root'
    candidates = [claimed_root] if claimed_root is not None else sorted(trusted_roots)
    if not candidates:
        return False, 'untrusted_root'

    proof = MerkleProof(
        leaf_index=data['leaf_index'],
        tree_size=data['tree_size'],
        leaf_hash=data['leaf_hash'],
        siblings=tuple(data[siblings_key]),
    )
    record_digest = data.get('record_digest')
    for root in candidates:
        if record_digest is not None:
            if verify_inclusion(record_digest, proof, root):
                return True, 'valid'
        elif verify_proof(proof, root):
            return True, 'valid;leaf_hash_not_bound_to_record'
    return False, 'invalid_proof'


@_guard
def verify_signature_file(path: Path, trust: TrustStore | None = None) -> Result:
    data = load_json(path)
    if not isinstance(data, dict):
        return False, 'invalid_json'
    public_key_hex = data['public_key']
    if not isinstance(public_key_hex, str) or not _HEX64.match(public_key_hex):
        return False, 'public_key'
    if trust is None or not trust.key_trusted(public_key_hex):
        return False, 'untrusted_key'
    signature = data['signature']
    if not isinstance(signature, dict):
        return False, 'signature'
    declared = signature.get('key_id')
    if isinstance(declared, str) and declared.startswith('ed25519:'):
        if declared != key_id_for(bytes.fromhex(public_key_hex)):
            return False, 'key_id_mismatch'
    return verify_signature(bytes.fromhex(public_key_hex), bytes.fromhex(data['payload']), signature)


def parse_checkpoint(data: Any) -> MerkleCheckpoint:
    if not isinstance(data, dict) or not isinstance(data.get('checkpoint'), dict):
        raise ValueError('checkpoint document must contain a checkpoint object')
    body = data['checkpoint']
    if set(body) - {'schema', 'tree_algorithm', 'tree_size', 'root_hash', 'previous_root'}:
        raise ValueError('checkpoint has unexpected fields')
    size = body.get('tree_size')
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ValueError('checkpoint tree_size invalid')
    root = body.get('root_hash')
    if not isinstance(root, str) or not _HEX64.match(root):
        raise ValueError('checkpoint root invalid')
    previous = body.get('previous_root')
    if previous is not None and (not isinstance(previous, str) or not _HEX64.match(previous)):
        raise ValueError('checkpoint previous_root invalid')
    return MerkleCheckpoint(schema=body.get('schema'), tree_size=size, root_hash=root,
                            previous_root=previous)


def verify_checkpoint_document(data: Any, trust: TrustStore | None) -> tuple[Result, MerkleCheckpoint | None]:
    try:
        checkpoint = parse_checkpoint(data)
    except ValueError:
        return (False, 'malformed_checkpoint'), None
    if checkpoint.schema != MERKLE_SCHEMA:
        return (False, 'checkpoint_schema'), None
    public_key_hex = data.get('public_key')
    if not isinstance(public_key_hex, str) or not _HEX64.match(public_key_hex):
        return (False, 'public_key'), None
    if trust is None or not trust.key_trusted(public_key_hex):
        return (False, 'untrusted_key'), None
    signature = data.get('signature')
    if not isinstance(signature, dict):
        return (False, 'signature'), None
    if signature.get('key_id') != key_id_for(bytes.fromhex(public_key_hex)):
        return (False, 'key_id_mismatch'), None
    ok, reason = verify_signature(bytes.fromhex(public_key_hex), checkpoint_bytes(checkpoint),
                                  signature)
    if not ok:
        return (False, reason), None
    return (True, 'valid'), checkpoint


def verify_checkpoint_file(path: Path, trust: TrustStore | None = None) -> tuple[Result, MerkleCheckpoint | None]:
    try:
        data = load_json(path)
    except (ValueError, OSError, UnicodeError, RecursionError):
        return (False, 'malformed_input'), None
    return verify_checkpoint_document(data, trust)


@_guard
def verify_consistency_file(path: Path, trust: TrustStore | None = None) -> Result:
    data = load_json(path)
    if not isinstance(data, dict):
        return False, 'invalid_json'
    roots = trust.roots if trust else set()
    if data['new_root'] not in roots:
        return False, 'untrusted_new_root'
    if data['old_root'] not in roots:
        return False, 'untrusted_old_root'
    proof = data['proof']
    if not isinstance(proof, list):
        return False, 'invalid_proof'
    if verify_consistency(data['old_size'], data['new_size'], data['old_root'],
                          data['new_root'], proof):
        return True, 'valid'
    return False, 'inconsistent_history'


def run_checks(args: argparse.Namespace) -> dict[str, Result]:
    trust = TrustStore(args.trusted_key, args.trusted_key_id, args.trusted_root)
    checks: dict[str, Result] = {}
    checkpoint: MerkleCheckpoint | None = None

    if args.checkpoint:
        checks['CHECKPOINT_SIGNATURE'], checkpoint = verify_checkpoint_file(
            Path(args.checkpoint), trust)
        if checkpoint is not None:
            trust.roots.add(checkpoint.root_hash)

    if args.envelope:
        checks['ENVELOPE_INTEGRITY'] = verify_envelope_file(Path(args.envelope))

    if args.ledger:
        checks['LEDGER_CONTINUITY'] = verify_ledger_file(Path(args.ledger))
        if args.checkpoint:
            checks['LEDGER_CHECKPOINT_BINDING'] = (
                verify_ledger_checkpoint_binding(Path(args.ledger), checkpoint)
                if checkpoint is not None else (False, 'checkpoint_not_verified')
            )

    if args.proof:
        checks['MERKLE_INCLUSION'] = verify_proof_file(Path(args.proof), trust)

    if args.consistency:
        checks['MERKLE_CONSISTENCY'] = verify_consistency_file(Path(args.consistency), trust)

    if args.signature:
        checks['SIGNATURE_VALIDITY'] = verify_signature_file(Path(args.signature), trust)

    return checks


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Verify RightsFrames evidence offline against externally pinned trust.')
    parser.add_argument('--envelope', help='rf.evidence.v1 envelope JSON')
    parser.add_argument('--ledger', help='JSON array of rf.ledger.record.v1 records')
    parser.add_argument('--proof', help='Merkle inclusion proof JSON')
    parser.add_argument('--consistency', help='Merkle consistency proof JSON')
    parser.add_argument('--checkpoint', help='signed rf.merkle.checkpoint.v2 JSON')
    parser.add_argument('--signature', help='detached signature JSON')
    parser.add_argument('--trusted-key', action='append', default=[], metavar='HEX',
                        help='pinned raw Ed25519 public key (64 hex); repeatable')
    parser.add_argument('--trusted-key-id', action='append', default=[], metavar='ID',
                        help='pinned key id ed25519:<sha256 of raw key>; repeatable')
    parser.add_argument('--trusted-root', action='append', default=[], metavar='HEX',
                        help='pinned Merkle root (64 hex); repeatable')
    parser.add_argument('--json', action='store_true', help='machine-readable report')
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not any((args.envelope, args.ledger, args.proof, args.consistency, args.checkpoint,
                args.signature)):
        parser.error('at least one verification target required')
    try:
        checks = run_checks(args)
    except ValueError as exc:
        parser.error(str(exc))

    failed = any(not ok for ok, _ in checks.values())
    if args.json:
        print(json.dumps({
            'verifier': 'rightsframes-evidence-verifier',
            'result': 'FAIL' if failed else 'PASS',
            'checks': {name: {'ok': ok, 'reason': reason} for name, (ok, reason) in checks.items()},
            'pinned_keys': len(args.trusted_key) + len(args.trusted_key_id),
            'pinned_roots': len(args.trusted_root),
        }, sort_keys=True))
    else:
        for name, (ok, reason) in checks.items():
            print(f"{name}={'PASS' if ok else 'FAIL'}:{reason}")
        print('RIGHTSFRAMES_INDEPENDENT_VERIFIER=' + ('FAIL' if failed else 'PASS'))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
