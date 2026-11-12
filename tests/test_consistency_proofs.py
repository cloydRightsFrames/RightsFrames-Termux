"""RFC 9162 consistency paths and rf.consistency.v1 append-only proofs between two anchors.

Attackers here hold everything except what each case says they lack. The proof checks
need ML-DSA-65 (v4 anchors are always hybrid); the pure Merkle tests do not.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import rf_consistency, rf_core, rf_merkle  # noqa: E402


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load('rf_verify_consistency_test', 'verifier/rf_verify.py')
tool = _load('rf_export_consistency_test', 'tools/rf_export_consistency.py')

needs_pq = pytest.mark.skipif(not rf_core.pq_available(),
                              reason='cryptography build lacks ML-DSA-65')
HASHES = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(70)]
OTHER = hashlib.sha256(b'other').hexdigest()


def _canon(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mth(leaves: list[str]) -> bytes:
    """Direct transcription of RFC 9162 section 2.1.1, used as the reference."""
    if not leaves:
        return hashlib.sha256(b'').digest()
    if len(leaves) == 1:
        return hashlib.sha256(b'\x00' + bytes.fromhex(leaves[0])).digest()
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b'\x01' + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def _subproof(m: int, leaves: list[str], whole: bool) -> list[bytes]:
    """Direct transcription of RFC 9162 section 2.1.4.1 SUBPROOF, used as the reference."""
    n = len(leaves)
    if m == n:
        return [] if whole else [_mth(leaves)]
    k = 1 << ((n - 1).bit_length() - 1)
    if m <= k:
        return _subproof(m, leaves[:k], whole) + [_mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_mth(leaves[:k])]


def _point(mp, base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    for name, value in (('DATA_DIR', base), ('DB_PATH', base / 'ledger.db'),
                        ('PRIVATE_KEY_PATH', base / 'signing_key.pem'),
                        ('PUBLIC_KEY_PATH', base / 'signing_key.pub.pem'),
                        ('KEY_ID_PATH', base / 'signing_key.id'),
                        ('ANCHOR_PATH', base / 'anchors.jsonl'),
                        ('LOCK_PATH', base / 'anchors.lock')):
        mp.setattr(rf_core, name, value)
    return base


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def _dump(path: Path, rows) -> None:
    path.write_text(''.join(_canon(r) + '\n' for r in rows), encoding='utf-8')


def _keys(base: Path):
    ed = serialization.load_pem_private_key((base / 'signing_key.pem').read_bytes(), None)
    pq = serialization.load_pem_private_key((base / rf_core.PQ_PRIVATE_KEY_NAME).read_bytes(), None)
    return ed, pq


def _resign(anchor: dict, ed, pq) -> dict:
    """Re-hash and re-sign a v4 anchor with BOTH operator keys (full key compromise)."""
    anchor = dict(anchor)
    anchor['anchor_hash'] = _sha(_canon({k: anchor[k] for k in rf_core.ANCHOR_CORE_V4}).encode())
    msg = anchor['anchor_hash'].encode()
    anchor['signature'] = base64.b64encode(ed.sign(msg)).decode()
    anchor['pq_signature'] = base64.b64encode(pq.sign(msg, b'rf.anchor.v4')).decode()
    return anchor


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    """Anchors at 0, 4, 4, 7 and 12 entries, then 2 unanchored entries."""
    monkeypatch.setenv('RF_PQ_SIGNING', 'auto')
    base = _point(monkeypatch, tmp_path / 'op')
    anchors = [rf_core.create_anchor()]
    for upto in (4, 4, 7, 12):
        for i in range(anchors[-1]['ledger_count'], upto):
            rf_core.append_entry('evt', {'n': i, 'text': 'naïve ✓'})
        anchors.append(rf_core.create_anchor())
    for i in range(12, 14):
        rf_core.append_entry('evt', {'n': i})
    assert [a['ledger_count'] for a in anchors] == [0, 4, 4, 7, 12]
    return {'base': base, 'tmp': tmp_path, 'anchors': anchors}


def _pin(anchor: dict) -> tuple[int, str]:
    return anchor['seq'], anchor['anchor_hash']


def _proof_file(ledger, first, second=None, name=None) -> tuple[Path, dict]:
    proof = rf_consistency.build_consistency_proof(ledger['base'], first, second)
    path = ledger['tmp'] / (name or f'c{first}-{second}.json')
    path.write_bytes(rf_consistency.canonical_proof(proof))
    return path, proof


def _write(ledger, proof, name) -> Path:
    path = ledger['tmp'] / name
    path.write_text(_canon(proof), encoding='utf-8')
    return path


# ---------------------------------------------------------------- RFC 9162 consistency paths


def test_consistency_paths_match_rfc9162_reference_and_verify_for_every_size_pair():
    for size in range(0, len(HASHES) + 1):
        leaves = HASHES[:size]
        second_root = _mth(leaves).hex()
        for first in range(0, size + 1):
            path = rf_merkle.consistency_path(leaves, first)
            first_root = _mth(leaves[:first]).hex()
            if 0 < first < size:
                assert path == [item.hex() for item in _subproof(first, leaves, True)]
                assert len(path) <= 2 * size.bit_length()
                assert rf_merkle.roots_from_consistency_path(
                    first, size, path, first_root) == (first_root, second_root)
                assert verifier._roots_from_consistency_path(
                    first, size, list(path), first_root) == (first_root, second_root)
            else:
                assert path == []
            assert rf_merkle.verify_consistency(first, size, path, first_root, second_root)


def test_every_mutation_of_a_consistency_path_fails_in_core_and_verifier():
    for first, size in ((1, 2), (1, 8), (3, 7), (4, 8), (6, 8), (5, 37), (32, 70), (33, 70), (69, 70)):
        leaves = HASHES[:size]
        path = rf_merkle.consistency_path(leaves, first)
        first_root, second_root = _mth(leaves[:first]).hex(), _mth(leaves).hex()
        mutations = [path[:-1], path[1:], path + [path[-1]], list(reversed(path))]
        mutations += [path[:i] + [OTHER] + path[i + 1:] for i in range(len(path))]
        for mutated in mutations:
            if mutated == path:
                continue
            assert not rf_merkle.verify_consistency(first, size, mutated, first_root, second_root)
            try:
                computed = verifier._roots_from_consistency_path(first, size, list(mutated), first_root)
            except verifier.VerificationError:
                continue
            assert computed != (first_root, second_root)
        # A history rewritten before `first` cannot be made consistent with the old root.
        rewritten = [OTHER] + leaves[1:]
        forged_path = rf_merkle.consistency_path(rewritten, first)
        assert not rf_merkle.verify_consistency(first, size, forged_path, first_root,
                                                _mth(rewritten).hex())
        assert not rf_merkle.verify_consistency(first, size, path, first_root, _mth(rewritten).hex())
        assert not rf_merkle.verify_consistency(first, size, path, OTHER, second_root)


def test_consistency_edge_sizes_and_input_validation():
    root5 = _mth(HASHES[:5]).hex()
    assert rf_merkle.verify_consistency(0, 5, [], rf_merkle.EMPTY_ROOT, root5)
    assert not rf_merkle.verify_consistency(0, 5, [], root5, root5)
    assert not rf_merkle.verify_consistency(0, 5, [OTHER], rf_merkle.EMPTY_ROOT, root5)
    assert rf_merkle.verify_consistency(5, 5, [], root5, root5)
    assert not rf_merkle.verify_consistency(5, 5, [], root5, OTHER)
    assert not rf_merkle.verify_consistency(5, 5, [OTHER], root5, root5)
    path = rf_merkle.consistency_path(HASHES[:5], 3)
    root3 = _mth(HASHES[:3]).hex()
    assert rf_merkle.verify_consistency(3, 5, tuple(path), root3, root5)
    for args in ((5, 3, path, root5, root3), (3, 5, [], root3, root5), (3, 5, 'x', root3, root5),
                 (3, 5, path, root3.upper(), root5), (3, 5, path, root3, None),
                 (True, 5, path, root3, root5), (3, 5.0, path, root3, root5),
                 (3, 5, [path[0].upper()] + path[1:], root3, root5),
                 (3, 5, [None] + path[1:], root3, root5), (3, 5, [OTHER] * 65, root3, root5),
                 (-1, 5, path, root3, root5)):
        assert not rf_merkle.verify_consistency(*args)
    for bad in (-1, 6, True, '2', None):
        with pytest.raises(ValueError):
            rf_merkle.consistency_path(HASHES[:5], bad)
    for args, match in (((0, 5, path, root3), 'first size'), ((3, 3, path, root3), 'first size'),
                        ((3, '5', path, root3), 'integers'), ((3, 5, path, 'zz'), 'first root'),
                        ((3, 5, [], root3), 'malformed'), ((3, 5, [1], root3), 'element'),
                        ((3, 5, path + [OTHER], root3), 'longer'),
                        ((3, 5, path[:-1], root3), 'shorter')):
        with pytest.raises(ValueError, match=match):
            rf_merkle.roots_from_consistency_path(*args)


# ---------------------------------------------------------------- rf.consistency.v1 proofs


@needs_pq
def test_proof_between_every_anchor_pair_verifies_and_discloses_no_entry(ledger):
    anchors = ledger['anchors']
    for first in anchors:
        for second in anchors[first['seq']:]:
            path, proof = _proof_file(ledger, first['seq'], second['seq'])
            assert set(proof) == verifier.CONSISTENCY_KEYS
            assert proof['first_anchor'] == first and proof['second_anchor'] == second
            blob = path.read_text(encoding='utf-8')
            assert 'naïve' not in blob and 'entry_type' not in blob and 'payload' not in blob
            report = verifier.verify_consistency(str(path), pin_anchors=[_pin(first)])
            assert report['status'] == 'VERIFIED' and report['type'] == 'rf.consistency.v1'
            assert report['trust_level'] == 'anchor_pinned'
            assert report['pinned_anchors'] == [first['seq']]
            assert report['appended_entries'] == second['ledger_count'] - first['ledger_count']
            assert report['next_pin'] == f"{second['seq']}:{second['anchor_hash']}"
            assert report['post_quantum'] == 'hybrid' and report['warnings'] == []


@needs_pq
def test_pins_can_be_walked_forward_from_the_first_anchor_to_the_newest(ledger):
    """An auditor holding only the oldest pin reaches the newest anchor proof by proof."""
    pin = _pin(ledger['anchors'][0])
    for nxt in ledger['anchors'][1:]:
        path, _ = _proof_file(ledger, pin[0], nxt['seq'], name=f'walk-{nxt["seq"]}.json')
        report = verifier.verify_consistency(str(path), pin_anchors=[pin])
        seq, digest = report['next_pin'].split(':')
        pin = (int(seq), digest)
    assert pin == _pin(ledger['anchors'][-1])
    # The pin reached this way authenticates a receipt against the newest anchor.
    from core import rf_receipt
    receipt_path = ledger['tmp'] / 'walk-receipt.json'
    receipt_path.write_bytes(rf_receipt.canonical_receipt(rf_receipt.build_receipt(ledger['base'], 9)))
    assert verifier.verify_receipt(str(receipt_path), pin_anchors=[pin])['trust_level'] == 'anchor_pinned'


@needs_pq
def test_default_second_anchor_is_newest_and_trust_levels(ledger):
    anchors = ledger['anchors']
    path, proof = _proof_file(ledger, 2, name='default.json')
    assert proof['second_anchor'] == anchors[-1]
    plain = verifier.verify_consistency(str(path))
    assert plain['trust_level'] == 'internal_only' and 'Pin the first anchor' in plain['warnings'][0]
    keyed = verifier.verify_consistency(str(path), pin_key_id=anchors[0]['key_id'],
                                        pin_pq_key_id=anchors[0]['pq_key_id'])
    assert keyed['trust_level'] == 'key_pinned'
    second_only = verifier.verify_consistency(str(path), pin_anchors=[_pin(anchors[-1])])
    assert second_only['trust_level'] == 'anchor_pinned' and second_only['pinned_anchors'] == [5]
    both = verifier.verify_consistency(str(path), pin_anchors=[_pin(anchors[1]), _pin(anchors[-1]),
                                                               (3, anchors[2]['anchor_hash'])])
    assert both['pinned_anchors'] == [2, 5] and '[3]' in both['warnings'][0]
    for kwargs, match in (
            ({'pin_anchors': [(2, OTHER)]}, 'pinned anchor 2 hash mismatch'),
            ({'pin_anchors': [_pin(anchors[1]), (5, OTHER)]}, 'pinned anchor 5 hash mismatch'),
            ({'pin_anchors': [_pin(anchors[1]), (2, OTHER)]}, 'pinned anchor 2 hash mismatch'),
            ({'pin_anchors': [(3, anchors[2]['anchor_hash'])]}, 'no --pin-anchor for anchor 2 or 5'),
            ({'pin_key_id': 'ed25519:' + OTHER}, 'does not match pinned key'),
            ({'pin_pq_key_id': 'mldsa65:' + OTHER}, 'post-quantum key')):
        with pytest.raises(verifier.VerificationError, match=match):
            verifier.verify_consistency(str(path), **kwargs)


@needs_pq
def test_selection_errors(ledger, tmp_path, monkeypatch):
    base = ledger['base']
    with pytest.raises(LookupError, match='anchor 9 does not exist'):
        rf_consistency.build_consistency_proof(base, 9)
    with pytest.raises(LookupError, match='anchor 9 does not exist'):
        rf_consistency.build_consistency_proof(base, 2, 9)
    for first, second in ((3, 3), (4, 2), (5, None)):
        with pytest.raises(rf_consistency.ConsistencyUnavailable, match='not later'):
            rf_consistency.build_consistency_proof(base, first, second)
    for first, second in ((0, 2), (True, 2), ('1', 2), (1, 0), (1, 2.0)):
        with pytest.raises(ValueError, match='positive integer'):
            rf_consistency.build_consistency_proof(base, first, second)
    with pytest.raises(FileNotFoundError):
        rf_consistency.build_consistency_proof(tmp_path / 'nowhere', 1)

    # A ledger whose early anchors predate Merkle commitments cannot prove from them.
    monkeypatch.setenv('RF_PQ_SIGNING', 'off')
    old = _point(monkeypatch, tmp_path / 'old')
    rf_core.append_entry('evt', {'n': 0})
    rf_core.create_anchor()
    monkeypatch.setenv('RF_PQ_SIGNING', 'auto')
    rf_core.create_anchor()
    rf_core.create_anchor()
    with pytest.raises(rf_consistency.ConsistencyUnavailable, match='carries no Merkle commitment'):
        rf_consistency.build_consistency_proof(old, 1)
    assert rf_consistency.build_consistency_proof(old, 2)['consistency_path'] == []


@needs_pq
def test_builder_refuses_a_ledger_that_no_longer_matches_its_anchors(ledger):
    base = ledger['base']
    conn = sqlite3.connect(base / 'ledger.db')
    original = conn.execute('SELECT entry_hash FROM ledger_entries WHERE id = 2').fetchone()[0]
    conn.execute('UPDATE ledger_entries SET entry_hash = ? WHERE id = 2', (OTHER,))
    conn.commit()
    with pytest.raises(ValueError, match='does not match the Merkle root of anchor 2'):
        rf_consistency.build_consistency_proof(base, 2, 5)
    conn.execute('UPDATE ledger_entries SET entry_hash = ? WHERE id = 2', (original,))
    conn.execute('DELETE FROM ledger_entries WHERE id > 10')
    conn.commit()
    conn.close()
    with pytest.raises(ValueError, match='ledger has 10 entries below anchor 5'):
        rf_consistency.build_consistency_proof(base, 2, 5)
    assert rf_consistency.build_consistency_proof(base, 2, 4)['second_anchor']['seq'] == 4


@needs_pq
def test_builder_checks_public_keys_and_anchor_form(ledger, monkeypatch):
    base = ledger['base']
    pq_pub = base / rf_core.PQ_PUBLIC_KEY_NAME
    saved = pq_pub.read_bytes()
    pq_pub.unlink()
    with pytest.raises(rf_consistency.ConsistencyUnavailable, match='both the Ed25519'):
        rf_consistency.build_consistency_proof(base, 2)
    from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
    pq_pub.write_bytes(mldsa.MLDSA65PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(ValueError, match='did not sign anchor 2'):
        rf_consistency.build_consistency_proof(base, 2)
    other_ed = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    pq_pub.write_bytes(other_ed)
    with pytest.raises(TypeError, match='not ML-DSA-65'):
        rf_consistency.build_consistency_proof(base, 2)
    pq_pub.write_bytes(saved)
    ed_pub = base / 'signing_key.pub.pem'
    ed_saved = ed_pub.read_bytes()
    ed_pub.write_bytes(saved)
    with pytest.raises(TypeError, match='not Ed25519'):
        rf_consistency.build_consistency_proof(base, 2)
    ed_pub.write_bytes(ed_saved)

    anchors_path = base / 'anchors.jsonl'
    rows = _jsonl(anchors_path)
    swapped = [dict(r) for r in rows]
    swapped[4]['ledger_count'] = 3
    _dump(anchors_path, swapped)
    with pytest.raises(ValueError, match='covers fewer entries'):
        rf_consistency.build_consistency_proof(base, 4, 5)
    swapped[4]['ledger_count'] = '12'
    _dump(anchors_path, swapped)
    with pytest.raises(ValueError, match='anchor 5 is malformed'):
        rf_consistency.build_consistency_proof(base, 4, 5)
    anchors_path.write_text(_canon(rows[0]) + '\n[1]\n', encoding='utf-8')
    with pytest.raises(ValueError, match='not an object'):
        rf_consistency.build_consistency_proof(base, 1)
    anchors_path.write_text(_canon(rows[0]) + '\n' + ' ' * 70000 + '{}\n', encoding='utf-8')
    with pytest.raises(ValueError, match='exceeds size limit'):
        rf_consistency.build_consistency_proof(base, 1)
    # A torn final line (interrupted append) is ignored, as for receipts.
    anchors_path.write_text(''.join(_canon(r) + '\n' for r in rows) + '{"seq": 6', encoding='utf-8')
    assert rf_consistency.build_consistency_proof(base, 1)['second_anchor']['seq'] == 5
    anchors_path.unlink()
    with pytest.raises(LookupError, match='0 anchors'):
        rf_consistency.build_consistency_proof(base, 1)


def _swap(proof, which, **changes):
    forged = json.loads(json.dumps(proof))
    forged[which].update(changes)
    return forged


@needs_pq
@pytest.mark.parametrize('case, match', [
    ('path_edit', 'does not reach the merkle_root signed by'),
    ('path_drop', 'shorter than the trees require|does not reach'),
    ('path_extra', 'longer than the trees require|does not reach'),
    ('path_empty', 'consistency path is empty'),
    ('path_not_list', 'consistency_path is not a list'),
    ('path_bad_element', 'element is malformed'),
    ('path_too_long', 'too long'),
    ('first_root_edit', 'anchor hash mismatch'),
    ('second_count_edit', 'anchor hash mismatch'),
    ('second_signature_edit', 'anchor signature invalid'),
    ('second_pq_signature_edit', 'post-quantum signature invalid'),
    ('first_v3', 'first_anchor is not a hybrid Merkle anchor'),
    ('second_not_object', 'second_anchor is not an object'),
    ('same_anchor', 'not later than first_anchor'),
    ('reversed', 'not later than first_anchor'),
    ('extra_field', 'unexpected fields'),
    ('wrong_schema', 'unsupported consistency proof schema'),
    ('foreign_key', 'key identity mismatch'),
    ('bad_pem', 'ML-DSA-65 key is malformed'),
])
def test_proof_tampering_is_rejected(ledger, case, match):
    _, proof = _proof_file(ledger, 2, 5)
    forged = json.loads(json.dumps(proof))
    path = forged['consistency_path']
    assert len(path) >= 2
    if case == 'path_edit':
        path[0] = OTHER
    elif case == 'path_drop':
        path.pop()
    elif case == 'path_extra':
        path.append(OTHER)
    elif case == 'path_empty':
        forged['consistency_path'] = []
    elif case == 'path_not_list':
        forged['consistency_path'] = {'0': path[0]}
    elif case == 'path_bad_element':
        path[1] = path[1].upper()
    elif case == 'path_too_long':
        forged['consistency_path'] = [OTHER] * 65
    elif case == 'first_root_edit':
        forged['first_anchor']['merkle_root'] = OTHER
    elif case == 'second_count_edit':
        forged['second_anchor']['ledger_count'] = 13
    elif case == 'second_signature_edit':
        forged['second_anchor']['signature'] = forged['first_anchor']['signature']
    elif case == 'second_pq_signature_edit':
        forged['second_anchor']['pq_signature'] = forged['first_anchor']['pq_signature']
    elif case == 'first_v3':
        forged['first_anchor']['schema'] = 'rf.anchor.v3'
    elif case == 'second_not_object':
        forged['second_anchor'] = [forged['second_anchor']]
    elif case == 'same_anchor':
        forged['second_anchor'] = forged['first_anchor']
    elif case == 'reversed':
        forged['first_anchor'], forged['second_anchor'] = forged['second_anchor'], forged['first_anchor']
    elif case == 'extra_field':
        forged['entries'] = []
    elif case == 'wrong_schema':
        forged['schema'] = 'rf.consistency.v2'
    elif case == 'foreign_key':
        from cryptography.hazmat.primitives.asymmetric import ed25519
        forged['signing_key_pem'] = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    elif case == 'bad_pem':
        forged['pq_signing_key_pem'] = 7
    with pytest.raises(verifier.VerificationError, match=match):
        verifier.verify_consistency(str(_write(ledger, forged, f'forged-{case}.json')),
                                    pin_anchors=[_pin(ledger['anchors'][1])])


@needs_pq
def test_key_holding_attacker_cannot_rewrite_history_behind_a_pinned_anchor(ledger):
    """Both signing keys stolen: entry 2 is rewritten and every later anchor re-signed.

    The attacker's newest anchor is validly signed, so it can only be caught by the pin
    the auditor already holds. Whatever the attacker pairs it with fails.
    """
    base, anchors = ledger['base'], ledger['anchors']
    ed, pq = _keys(base)
    _, honest = _proof_file(ledger, 2, 5)
    conn = sqlite3.connect(base / 'ledger.db')
    hashes = [row[0] for row in conn.execute(
        'SELECT entry_hash FROM ledger_entries WHERE id <= 12 ORDER BY id')]
    conn.close()
    rewritten = hashes[:1] + [OTHER] + hashes[2:]
    forged_second = _resign({**anchors[4], 'merkle_root': rf_merkle.merkle_root(rewritten)}, ed, pq)
    pin = [_pin(anchors[1])]

    # 1. Honest first anchor, forged second anchor, path from the rewritten ledger.
    attempt = {**honest, 'second_anchor': forged_second,
               'consistency_path': rf_merkle.consistency_path(rewritten, 4)}
    with pytest.raises(verifier.VerificationError, match='signed by second_anchor'):
        verifier.verify_consistency(str(_write(ledger, attempt, 'k1.json')), pin_anchors=pin)
    # 1b. From anchor 4 (7 entries, not a complete subtree) the rewritten path also
    #     fails to reproduce the root the pinned first anchor signed.
    _, honest7 = _proof_file(ledger, 4, 5)
    attempt = {**honest7, 'second_anchor': forged_second,
               'consistency_path': rf_merkle.consistency_path(rewritten, 7)}
    with pytest.raises(verifier.VerificationError, match='signed by first_anchor'):
        verifier.verify_consistency(str(_write(ledger, attempt, 'k1b.json')),
                                    pin_anchors=[_pin(anchors[3])])
    # 2. Same, keeping the honest path.
    attempt = {**honest, 'second_anchor': forged_second}
    with pytest.raises(verifier.VerificationError, match='signed by second_anchor'):
        verifier.verify_consistency(str(_write(ledger, attempt, 'k2.json')), pin_anchors=pin)
    # 3. First anchor re-signed over the rewritten prefix too: internally consistent,
    #    so it verifies WITHOUT a pin and is rejected by the pin held since the last review.
    forged_first = _resign({**anchors[1], 'merkle_root': rf_merkle.merkle_root(rewritten[:4])}, ed, pq)
    attempt = {**honest, 'first_anchor': forged_first, 'second_anchor': forged_second,
               'consistency_path': rf_merkle.consistency_path(rewritten, 4)}
    forged_path = _write(ledger, attempt, 'k3.json')
    assert verifier.verify_consistency(str(forged_path))['trust_level'] == 'internal_only'
    with pytest.raises(verifier.VerificationError, match='pinned anchor 2 hash mismatch'):
        verifier.verify_consistency(str(forged_path), pin_anchors=pin)
    # 4. Truncation: a re-signed "newest" anchor that covers fewer entries than the pin.
    shorter = _resign({**anchors[4], 'ledger_count': 3, 'ledger_head': hashes[2],
                       'merkle_root': rf_merkle.merkle_root(hashes[:3])}, ed, pq)
    attempt = {**honest, 'second_anchor': shorter, 'consistency_path': []}
    with pytest.raises(verifier.VerificationError, match='ledger count regressed'):
        verifier.verify_consistency(str(_write(ledger, attempt, 'k4.json')), pin_anchors=pin)


@needs_pq
def test_equal_size_empty_first_and_adjacent_anchor_rules(ledger):
    base, anchors = ledger['base'], ledger['anchors']
    ed, pq = _keys(base)
    # Anchors 2 and 3 cover the same four entries: empty path, equal roots.
    path, proof = _proof_file(ledger, 2, 3)
    assert proof['consistency_path'] == []
    assert verifier.verify_consistency(str(path), pin_anchors=[_pin(anchors[1])])['appended_entries'] == 0
    with pytest.raises(verifier.VerificationError, match='must be empty when both anchors'):
        verifier.verify_consistency(str(_write(ledger, {**proof, 'consistency_path': [OTHER]}, 'e1.json')))
    for change in ({'merkle_root': OTHER}, {'ledger_head': OTHER}):
        forged = {**proof, 'second_anchor': _resign({**anchors[2], **change}, ed, pq)}
        with pytest.raises(verifier.VerificationError, match='sign different ledgers'):
            verifier.verify_consistency(str(_write(ledger, forged, 'e2.json')))
    # Adjacent anchors must chain; non-adjacent ones are bound by the Merkle path alone.
    unchained = {**proof, 'second_anchor': _resign({**anchors[2], 'prev_anchor_hash': OTHER}, ed, pq)}
    with pytest.raises(verifier.VerificationError, match='does not chain to first_anchor'):
        verifier.verify_consistency(str(_write(ledger, unchained, 'e3.json')))
    # Anchor 1 covers no entries: the empty ledger is a prefix of every ledger.
    path, proof = _proof_file(ledger, 1, 5)
    assert proof['consistency_path'] == []
    assert verifier.verify_consistency(str(path), pin_anchors=[_pin(anchors[0])])['appended_entries'] == 12
    with pytest.raises(verifier.VerificationError, match='must be empty when the first anchor'):
        verifier.verify_consistency(str(_write(ledger, {**proof, 'consistency_path': [OTHER]}, 'e4.json')))
    for change in ({'merkle_root': OTHER}, {'ledger_head': OTHER}):
        forged = {**proof, 'first_anchor': _resign({**anchors[0], **change}, ed, pq)}
        with pytest.raises(verifier.VerificationError, match='does not sign the empty ledger'):
            verifier.verify_consistency(str(_write(ledger, forged, 'e5.json')))
    # An anchor dated before the one it claims to extend is rejected.
    _, proof = _proof_file(ledger, 2, 5)
    backdated = {**proof, 'second_anchor': _resign(
        {**anchors[4], 'created_at': '2000-01-01T00:00:00.000000Z'}, ed, pq)}
    with pytest.raises(verifier.VerificationError, match='anchor time regressed'):
        verifier.verify_consistency(str(_write(ledger, backdated, 'e6.json')))


@needs_pq
def test_proof_parsing_limits(ledger):
    path, proof = _proof_file(ledger, 2, 5)
    blob = path.read_text(encoding='utf-8')
    cases = {
        'dup.json': (blob.replace('"schema":', '"schema":"rf.consistency.v1","schema":', 1),
                     'duplicate'),
        'nan.json': (blob.replace('"consistency_path":[', '"consistency_path":[NaN,', 1), 'non-finite'),
        'list.json': ('[]', 'unexpected fields'),
        'big.json': (' ' * (verifier.MAX_RECEIPT_BYTES + 1), 'consistency proof exceeds size limit'),
    }
    for name, (text, match) in cases.items():
        target = ledger['tmp'] / name
        target.write_text(text, encoding='utf-8')
        with pytest.raises(verifier.VerificationError, match=match):
            verifier.verify_consistency(str(target))
    binary = ledger['tmp'] / 'bin.json'
    binary.write_bytes(b'\xff\xfe')
    with pytest.raises(verifier.VerificationError, match='not UTF-8'):
        verifier.verify_consistency(str(binary))
    with pytest.raises(verifier.VerificationError, match='cannot read consistency proof'):
        verifier.verify_consistency(str(ledger['tmp'] / 'missing.json'))
    non_ascii = {**proof, 'signing_key_pem': 'ключ'}
    with pytest.raises(verifier.VerificationError, match='not ASCII PEM'):
        verifier.verify_consistency(str(_write(ledger, non_ascii, 'pem.json')))


@needs_pq
def test_cli_and_exporter_tool(ledger, capsys, monkeypatch):
    base, anchors = ledger['base'], ledger['anchors']
    out = ledger['tmp'] / 'tool.json'
    assert tool.main(['--data-dir', str(base), '--from-seq', '2', '--out', str(out)]) == 0
    printed = capsys.readouterr().out
    assert 'from anchor 2 (4 entries) to anchor 5 (12 entries)' in printed
    assert f"verify with: --pin-anchor 2:{anchors[1]['anchor_hash']}" in printed
    assert f"next pin:    --pin-anchor 5:{anchors[4]['anchor_hash']}" in printed
    assert out.read_bytes() == rf_consistency.canonical_proof(
        rf_consistency.build_consistency_proof(base, 2))
    assert tool.main(['--data-dir', str(base), '--from-seq', '2', '--out', str(out)]) == 1
    assert 'refusing to overwrite' in capsys.readouterr().err
    missing = ledger['tmp'] / 'none.json'
    assert tool.main(['--data-dir', str(base), '--from-seq', '5', '--out', str(missing)]) == 1
    assert 'not later' in capsys.readouterr().err and not missing.exists()
    assert tool.main(['--data-dir', str(base), '--from-seq', '2', '--to-seq', '4',
                      '--out', str(ledger['tmp'] / 'two-four.json')]) == 0
    capsys.readouterr()
    monkeypatch.delenv('RF_DATA_DIR', raising=False)
    with pytest.raises(SystemExit):
        tool.main(['--from-seq', '1', '--out', str(missing)])
    capsys.readouterr()

    pin = f"2:{anchors[1]['anchor_hash']}"
    assert verifier.main([str(out), '--consistency', '--pin-anchor', pin, '--json']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['trust_level'] == 'anchor_pinned' and report['appended_entries'] == 8
    assert verifier.main([str(out), '--consistency']) == 10
    assert 'WARNING: No externally held anchor pin' in capsys.readouterr().out
    assert verifier.main([str(out), '--consistency', '--pin-anchor', f'2:{OTHER}', '--json']) == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'FAILED'
    for extra in (['--receipt'], ['--min-anchors', '1'], ['--require-full-pin']):
        assert verifier.main([str(out), '--consistency', '--json'] + extra) == 1
        assert json.loads(capsys.readouterr().out)['status'] == 'FAILED'
    # A consistency proof is not a receipt or a bundle, and a receipt is not a proof.
    assert verifier.main([str(out), '--receipt', '--json']) == 1
    assert verifier.main([str(out), '--json']) == 1
    capsys.readouterr()


@needs_pq
def test_exporter_removes_partial_output_on_write_failure(ledger, monkeypatch):
    out = ledger['tmp'] / 'partial.json'

    def boom(_fd):
        raise OSError('disk full')

    monkeypatch.setattr(tool.os, 'fsync', boom)
    with pytest.raises(OSError, match='disk full'):
        tool.export_consistency(ledger['base'], 2, out)
    assert not out.exists()
