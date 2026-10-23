"""Adversarial regression tests for the evidence layer.

Each test reproduces a concrete attack that succeeded against an earlier revision and asserts
it is now detected. If one of these starts passing for the attacker, treat it as a security
regression, not a flaky test.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))

from core.evidence import merkle  # noqa: E402
from core.evidence.checkpoint import sign_checkpoint  # noqa: E402
from core.evidence.envelope import (  # noqa: E402
    CanonicalizationError,
    build_envelope,
    canonical_bytes,
    loads_strict,
    verify_envelope,
)
from core.evidence.ledger import build_record  # noqa: E402
from core.evidence.signing import generate_keypair, key_id_for, sign, verify  # noqa: E402
from verifier import evidence_verifier as ev  # noqa: E402


def _digests(n: int, salt: str = 'rf') -> list[str]:
    return [hashlib.sha256(f'{salt}:{i}'.encode()).hexdigest() for i in range(n)]


def _ledger(n: int) -> list[dict]:
    records, previous = [], None
    for index in range(n):
        record = build_record(index, f'event-{index}',
                              hashlib.sha256(f'payload-{index}'.encode()).hexdigest(), previous)
        records.append({
            'ledger_sequence': record.ledger_sequence,
            'event_id': record.event_id,
            'payload_digest': record.payload_digest,
            'previous_record_digest': record.previous_record_digest,
            'record_digest': record.record_digest,
        })
        previous = record.record_digest
    return records


def _write(path: Path, value) -> Path:
    path.write_text(json.dumps(value), encoding='utf-8')
    return path


# --- Merkle tree ------------------------------------------------------------------------

def test_rfc6962_reference_vectors():
    data = [bytes.fromhex(x) for x in (
        '', '00', '10', '2021', '3031', '40414243', '5051525354555657',
        '606162636465666768696a6b6c6d6e6f')]
    leaves = [hashlib.sha256(b'\x00' + item).digest() for item in data]
    expected = {
        1: '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
        2: 'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
        3: 'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
        5: '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
        7: 'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
        8: '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
    }
    for size, root in expected.items():
        assert merkle._mth(leaves[:size]).hex() == root


@pytest.mark.parametrize('size', [1, 2, 3, 5, 7, 9, 31, 33])
def test_duplicate_last_leaf_does_not_collide(size):
    digests = _digests(size)
    assert merkle.merkle_root(digests) != merkle.merkle_root(digests + [digests[-1]])


def test_core_manifest_merkle_duplicate_leaf_does_not_collide():
    from core.merkle import compute_legacy_merkle_root, compute_merkle_root

    leaves = [b'a', b'b', b'c']
    assert compute_legacy_merkle_root(leaves) == compute_legacy_merkle_root(leaves + [b'c'])
    assert compute_merkle_root(leaves) != compute_merkle_root(leaves + [b'c'])


def test_inclusion_and_consistency_exhaustive_small_trees():
    for size in range(1, 40):
        digests = _digests(size)
        root = merkle.merkle_root(digests)
        for index in range(size):
            proof = merkle.build_proof(digests, index)
            assert merkle.verify_inclusion(digests[index], proof, root)
            if size > 1:
                assert not merkle.verify_inclusion(digests[(index + 1) % size], proof, root)
            padded = merkle.MerkleProof(index, size, proof.leaf_hash,
                                        proof.siblings + ('0' * 64,))
            assert not merkle.verify_proof(padded, root)
        for old in range(size + 1):
            proof = merkle.build_consistency_proof(digests, old)
            assert merkle.verify_consistency(old, size, merkle.merkle_root(digests[:old]),
                                             root, proof)


def test_forked_history_fails_consistency():
    honest = _digests(20)
    forked = honest[:12] + _digests(8, salt='fork')
    old_root = merkle.merkle_root(honest[:15])
    proof = merkle.build_consistency_proof(forked, 15)
    assert not merkle.verify_consistency(15, 20, old_root, merkle.merkle_root(forked), proof)


def test_proof_rejects_bool_and_out_of_range_indices():
    digests = _digests(4)
    root = merkle.merkle_root(digests)
    proof = merkle.build_proof(digests, 0)
    for leaf_index, tree_size in ((True, 4), (0, True), (-1, 4), (4, 4), (0, 0)):
        tampered = merkle.MerkleProof(leaf_index, tree_size, proof.leaf_hash, proof.siblings)
        assert not merkle.verify_proof(tampered, root)


# --- Canonical JSON and parsing ---------------------------------------------------------

def test_non_string_keys_cannot_collide_with_string_keys():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({1: 'x'})
    assert canonical_bytes({'1': 'x'}) == b'{"1":"x"}'


@pytest.mark.parametrize('value', [1.0, float('nan'), 2 ** 53, -(2 ** 53), '\ud800'])
def test_non_canonical_scalars_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonical_bytes({'v': value})


@pytest.mark.parametrize('text', [
    '{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"a":1.5}', '{"a":{"b":1,"b":1}}'])
def test_strict_parser_rejects_ambiguous_documents(text):
    with pytest.raises(ValueError):
        loads_strict(text)


def test_duplicate_key_envelope_file_fails_closed(tmp_path):
    env = build_envelope('t1', 'e1', 'login', {'collector': 'c1'}, {'ok': True})
    text = json.dumps(env)
    smuggled = text[:-1] + ',"event_type":"logout"}'
    path = tmp_path / 'env.json'
    path.write_text(smuggled, encoding='utf-8')
    assert ev.verify_envelope_file(path) == (False, 'malformed_input')


def test_envelope_with_float_fails_instead_of_crashing():
    env = build_envelope('t1', 'e1', 'login', {'collector': 'c1'}, {'ok': True})
    env['observation'] = {'score': 0.5}
    assert verify_envelope(env) == (False, 'non_canonical_value')


# --- Signatures -------------------------------------------------------------------------

def test_non_canonical_base64_signature_rejected():
    private, public = generate_keypair()
    signed = sign(private, b'payload', key_id_for(public))
    assert verify(public, b'payload', signed) == (True, 'valid')
    for mutated in (signed['signature'] + '=', signed['signature'] + '!',
                    ' ' + signed['signature']):
        assert verify(public, b'payload', {**signed, 'signature': mutated})[0] is False


# --- Independent verifier trust model ---------------------------------------------------

def test_attacker_key_inside_signature_file_is_not_trusted(tmp_path):
    attacker_private, attacker_public = generate_keypair()
    _, operator_public = generate_keypair()
    payload = b'transfer approved'
    path = _write(tmp_path / 'sig.json', {
        'public_key': attacker_public.hex(),
        'payload': payload.hex(),
        'signature': sign(attacker_private, payload, 'ceo-key'),
    })
    assert ev.main(['--signature', str(path)]) == 1
    assert ev.main(['--signature', str(path), '--trusted-key', operator_public.hex()]) == 1
    assert ev.main(['--signature', str(path), '--trusted-key', attacker_public.hex()]) == 0


def test_declared_key_id_must_match_key_material(tmp_path):
    private, public = generate_keypair()
    _, other = generate_keypair()
    payload = b'x'
    path = _write(tmp_path / 'sig.json', {
        'public_key': public.hex(), 'payload': payload.hex(),
        'signature': sign(private, payload, key_id_for(other)),
    })
    trust = ev.TrustStore(keys=[public.hex()])
    assert ev.verify_signature_file(path, trust) == (False, 'key_id_mismatch')


def test_attacker_root_inside_proof_file_is_not_trusted(tmp_path):
    leaf = merkle.hash_leaf('f' * 64)
    path = _write(tmp_path / 'proof.json', {
        'leaf_index': 0, 'tree_size': 1, 'leaf_hash': leaf, 'siblings': [],
        'root_hash': leaf, 'record_digest': 'f' * 64,
    })
    assert ev.main(['--proof', str(path)]) == 1
    assert ev.main(['--proof', str(path), '--trusted-root', '0' * 64]) == 1


def test_end_to_end_signed_checkpoint_flow(tmp_path):
    private, public = generate_keypair()
    records = _ledger(25)
    digests = [r['record_digest'] for r in records]
    checkpoint = sign_checkpoint(private, digests)
    ledger_path = _write(tmp_path / 'ledger.json', records)
    cp_path = _write(tmp_path / 'checkpoint.json', checkpoint)
    proof = merkle.build_proof(digests, 17)
    proof_path = _write(tmp_path / 'proof.json', {
        'leaf_index': proof.leaf_index, 'tree_size': proof.tree_size,
        'leaf_hash': proof.leaf_hash, 'siblings': list(proof.siblings),
        'record_digest': digests[17],
    })
    pin = ['--trusted-key-id', key_id_for(public)]
    args = ['--checkpoint', str(cp_path), '--ledger', str(ledger_path),
            '--proof', str(proof_path)] + pin
    assert ev.main(args) == 0

    # Without a pinned key nothing is trusted.
    assert ev.main(args[:-2]) == 1

    # Truncation below the signed size.
    _write(ledger_path, records[:20])
    assert ev.main(args) == 1

    # Regenerated, internally consistent ledger with one substituted record.
    forged = _ledger(25)
    forged[5]['event_id'] = 'event-forged'
    rebuilt, previous = [], None
    for item in forged:
        record = build_record(item['ledger_sequence'], item['event_id'],
                              item['payload_digest'], previous)
        rebuilt.append({**item, 'previous_record_digest': previous,
                        'record_digest': record.record_digest})
        previous = record.record_digest
    _write(ledger_path, rebuilt)
    assert ev.verify_ledger_file(ledger_path) == (True, 'valid')
    assert ev.main(args) == 1

    # Checkpoint re-signed by an attacker key.
    attacker_private, _ = generate_keypair()
    _write(ledger_path, records)
    _write(cp_path, sign_checkpoint(attacker_private, digests))
    assert ev.main(args) == 1


def test_checkpoint_tamper_matrix(tmp_path):
    private, public = generate_keypair()
    digests = [r['record_digest'] for r in _ledger(9)]
    good = sign_checkpoint(private, digests)
    trust = ev.TrustStore(keys=[public.hex()])
    assert ev.verify_checkpoint_document(good, trust)[0] == (True, 'valid')
    for field, value in (('tree_size', 8), ('root_hash', 'a' * 64), ('previous_root', 'b' * 64),
                         ('schema', 'rf.merkle.checkpoint.v1')):
        tampered = json.loads(json.dumps(good))
        tampered['checkpoint'][field] = value
        assert ev.verify_checkpoint_document(tampered, trust)[0][0] is False


def test_consistency_requires_both_roots_pinned(tmp_path):
    digests = _digests(30)
    old_root, new_root = merkle.merkle_root(digests[:10]), merkle.merkle_root(digests)
    path = _write(tmp_path / 'c.json', {
        'old_size': 10, 'new_size': 30, 'old_root': old_root, 'new_root': new_root,
        'proof': list(merkle.build_consistency_proof(digests, 10)),
    })
    assert ev.main(['--consistency', str(path), '--trusted-root', new_root]) == 1
    assert ev.main(['--consistency', str(path), '--trusted-root', new_root,
                    '--trusted-root', old_root]) == 0


# --- Operator ledger core ---------------------------------------------------------------

@pytest.fixture()
def rf(tmp_path, monkeypatch):
    import rf_core

    monkeypatch.setattr(rf_core, 'DATA_DIR', tmp_path)
    monkeypatch.setattr(rf_core, 'DB_PATH', tmp_path / 'ledger.db')
    monkeypatch.setattr(rf_core, 'PRIVATE_KEY_PATH', tmp_path / 'signing_key.pem')
    monkeypatch.setattr(rf_core, 'PUBLIC_KEY_PATH', tmp_path / 'signing_key.pub.pem')
    monkeypatch.setattr(rf_core, 'KEY_ID_PATH', tmp_path / 'signing_key.id')
    monkeypatch.setattr(rf_core, 'ANCHOR_PATH', tmp_path / 'anchors.jsonl')
    monkeypatch.setattr(rf_core, 'LOCK_PATH', tmp_path / 'anchors.lock')
    monkeypatch.delenv(rf_core.PINNED_KEY_ID_ENV, raising=False)
    return rf_core


def test_verification_never_creates_keys(rf):
    assert rf.verify_anchors() == (True, 'no anchors')
    assert not rf.PRIVATE_KEY_PATH.exists()
    assert not rf.PUBLIC_KEY_PATH.exists()


def test_anchor_verification_fails_when_public_key_removed(rf):
    rf.append_entry('test', {'n': 1})
    rf.create_anchor()
    assert rf.verify_anchors()[0] is True
    rf.PUBLIC_KEY_PATH.unlink()
    rf.PRIVATE_KEY_PATH.unlink()
    assert rf.verify_anchors() == (False, 'anchor verification initialization failed')
    assert not rf.PRIVATE_KEY_PATH.exists()


def test_key_substitution_detected_by_pinned_key_id(rf, monkeypatch):
    rf.append_entry('test', {'n': 1})
    anchor = rf.create_anchor()
    pinned = anchor['key_id']
    assert rf.verify_anchors(pinned_key_id=pinned)[0] is True

    # Attacker with data-directory write access regenerates the key and re-signs everything.
    for path in (rf.PRIVATE_KEY_PATH, rf.PUBLIC_KEY_PATH, rf.KEY_ID_PATH, rf.ANCHOR_PATH):
        path.unlink()
    rf.create_anchor()
    assert rf.verify_anchors()[0] is True
    assert rf.verify_anchors(pinned_key_id=pinned) == (
        False, 'anchor key does not match pinned key id')
    monkeypatch.setenv(rf.PINNED_KEY_ID_ENV, pinned)
    assert rf.verify_anchors()[0] is False


@pytest.mark.parametrize('entry_type', ['a|b', 'x\n', '\tx', 'ok\x00', 'x ', ' x', 'a\x85b'])
def test_ambiguous_entry_types_rejected(rf, entry_type):
    with pytest.raises(ValueError):
        rf.append_entry(entry_type, {})


def test_existing_entry_types_still_accepted(rf):
    for entry_type in ('test', 'system.bootstrap', 'audit.cli', 'auth.principal.created',
                       'audit.api', 'ids:alert/v2'):
        rf.append_entry(entry_type, {})
    assert rf.verify_chain()[0] is True


# --- Release manifest -------------------------------------------------------------------

def test_legacy_v1_manifest_still_verifies_and_v2_is_default(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from core import manifest as mf
    from core.merkle import compute_legacy_merkle_root

    private = Ed25519PrivateKey.generate()
    for name in ('a.txt', 'b.txt', 'c.txt'):
        (tmp_path / name).write_text(name, encoding='utf-8')
    files = [tmp_path / n for n in ('a.txt', 'b.txt', 'c.txt')]

    current = mf.sign_manifest(mf.build_manifest(files, tmp_path), private)
    assert current['schema'] == 'rightsframes.manifest.v2'
    assert mf.verify_manifest(current, private.public_key(), tmp_path)

    legacy = mf.build_manifest(files, tmp_path)
    legacy['schema'] = 'rightsframes.manifest.v1'
    legacy['merkle_root'] = compute_legacy_merkle_root(
        [bytes.fromhex(e['sha256']) for e in legacy['files']]).hex()
    legacy = mf.sign_manifest(legacy, private)
    assert mf.verify_manifest(legacy, private.public_key(), tmp_path)

    duplicated = mf.build_manifest(files, tmp_path)
    duplicated['files'] = duplicated['files'] + [duplicated['files'][-1]]
    assert not mf.verify_manifest(mf.sign_manifest(duplicated, private),
                                  private.public_key(), tmp_path)

