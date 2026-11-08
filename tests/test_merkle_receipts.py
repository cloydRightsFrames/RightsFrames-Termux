"""RFC 9162 Merkle commitments (rf.anchor.v4) and single-entry inclusion receipts (rf.receipt.v1).

Attackers here hold everything except what each case says they lack. Merkle and receipt
checks need ML-DSA-65 (v4 anchors are always hybrid); the pure Merkle tests do not.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import rf_core, rf_merkle, rf_receipt  # noqa: E402
from core import merkle as legacy_merkle  # noqa: E402
from core.evidence import merkle as evidence_merkle  # noqa: E402


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load('rf_verify_receipt_test', 'verifier/rf_verify.py')
exporter = _load('rf_export_evidence_receipt_test', 'tools/rf_export_evidence.py')
receipt_tool = _load('rf_export_receipt_test', 'tools/rf_export_receipt.py')

needs_pq = pytest.mark.skipif(not rf_core.pq_available(),
                              reason='cryptography build lacks ML-DSA-65')
HASHES = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(80)]


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
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _dump(path: Path, rows) -> None:
    path.write_text(''.join(_canon(r) + '\n' for r in rows))


def _keys(base: Path):
    ed = serialization.load_pem_private_key((base / 'signing_key.pem').read_bytes(), None)
    pq = serialization.load_pem_private_key((base / rf_core.PQ_PRIVATE_KEY_NAME).read_bytes(), None)
    return ed, pq


def _resign(anchor: dict, ed, pq, context: bytes | None = None) -> dict:
    """Re-hash and re-sign an anchor with BOTH operator keys (full key compromise)."""
    fields = {'rf.anchor.v3': rf_core.ANCHOR_CORE_V3, 'rf.anchor.v4': rf_core.ANCHOR_CORE_V4}
    anchor = dict(anchor)
    anchor['anchor_hash'] = _sha(_canon({k: anchor[k] for k in fields[anchor['schema']]}).encode())
    msg = anchor['anchor_hash'].encode()
    anchor['signature'] = base64.b64encode(ed.sign(msg)).decode()
    anchor['pq_signature'] = base64.b64encode(
        pq.sign(msg, context or anchor['schema'].encode())).decode()
    return anchor


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    """7 entries, anchor 1 (covers 4), anchor 2 (covers 7), then 2 unanchored entries."""
    monkeypatch.setenv('RF_PQ_SIGNING', 'auto')
    base = _point(monkeypatch, tmp_path / 'op')
    for i in range(4):
        rf_core.append_entry('evt', {'n': i})
    a1 = rf_core.create_anchor()
    for i in range(4, 7):
        rf_core.append_entry('evt', {'n': i, 'text': 'naïve ✓'})
    a2 = rf_core.create_anchor()
    for i in range(7, 9):
        rf_core.append_entry('evt', {'n': i})
    return {'base': base, 'tmp': tmp_path, 'a1': a1, 'a2': a2}


def _receipt_file(ledger, entry_id, anchor_seq=None, name=None) -> tuple[Path, dict]:
    receipt = rf_receipt.build_receipt(ledger['base'], entry_id, anchor_seq)
    path = ledger['tmp'] / (name or f'r{entry_id}-{anchor_seq}.json')
    path.write_bytes(rf_receipt.canonical_receipt(receipt))
    return path, receipt


def _write_receipt(ledger, receipt, name) -> Path:
    path = ledger['tmp'] / name
    path.write_text(_canon(receipt))
    return path


# ---------------------------------------------------------------- RFC 9162 Merkle


def test_merkle_root_matches_rfc9162_reference_for_every_size():
    for size in range(0, len(HASHES) + 1):
        assert rf_merkle.merkle_root(HASHES[:size]) == _mth(HASHES[:size]).hex()
    assert rf_merkle.merkle_root([]) == rf_merkle.EMPTY_ROOT == _sha(b'')


def test_inclusion_paths_verify_and_every_mutation_fails():
    for size in range(1, 40):
        leaves, root = HASHES[:size], _mth(HASHES[:size]).hex()
        for index in range(size):
            path = rf_merkle.inclusion_path(leaves, index)
            assert len(path) <= max(1, (size - 1).bit_length())
            assert rf_merkle.verify_inclusion(leaves[index], index, size, path, root)
            assert verifier._root_from_path(leaves[index], index, size, path) == root
            if size == 1:
                continue
            assert not rf_merkle.verify_inclusion(HASHES[size], index, size, path, root)
            assert not rf_merkle.verify_inclusion(leaves[index], index, size, path + [HASHES[0]], root)
            assert not rf_merkle.verify_inclusion(leaves[index], index, size, path[:-1], root)
            other = (index + 1) % size
            assert not rf_merkle.verify_inclusion(leaves[index], other, size, path, root)
            flipped = list(path)
            flipped[0] = ('0' if flipped[0][0] != '0' else '1') + flipped[0][1:]
            assert not rf_merkle.verify_inclusion(leaves[index], index, size, flipped, root)


@pytest.mark.parametrize('args', [
    ('a' * 64, 0, 0, []), ('a' * 64, 3, 3, []), ('a' * 64, -1, 3, []),
    ('a' * 64, 0, 2, ['XYZ']), ('a' * 64, 0, 2, 'notalist'), ('a' * 64, True, 2, []),
    ('a' * 64, 0, 2, ['a' * 64] * 65),
])
def test_inclusion_rejects_malformed_proofs(args):
    with pytest.raises(ValueError):
        rf_merkle.root_from_inclusion_path(*args)
    assert rf_merkle.verify_inclusion(*args, root='a' * 64) is False


def test_merkle_input_validation_and_prefix_roots():
    with pytest.raises(ValueError):
        rf_merkle.leaf_hash('ABC')
    with pytest.raises(IndexError):
        rf_merkle.inclusion_path(HASHES[:3], 3)
    with pytest.raises(ValueError):
        rf_merkle.roots_at(HASHES[:3], [4])
    roots = rf_merkle.roots_at(HASHES, [0, 1, 17, 80])
    assert roots == {size: _mth(HASHES[:size]).hex() for size in (0, 1, 17, 80)}
    assert verifier._merkle_roots([''] + HASHES, {0, 1, 17, 80}) == roots


def test_duplicate_trailing_leaf_never_collides_cve_2012_2459():
    for size in range(1, 20):
        leaves = HASHES[:size]
        assert rf_merkle.merkle_root(leaves) != rf_merkle.merkle_root(leaves + [leaves[-1]])
        raw = [item.encode() for item in leaves]
        assert legacy_merkle.compute_merkle_root(raw) != \
            legacy_merkle.compute_merkle_root(raw + [raw[-1]])
        assert evidence_merkle.merkle_root(leaves) != \
            evidence_merkle.merkle_root(leaves + [leaves[-1]])


def test_legacy_evidence_merkle_proofs_are_exact():
    for size in range(1, 30):
        leaves = HASHES[:size]
        root = evidence_merkle.merkle_root(leaves)
        for index in range(size):
            proof = evidence_merkle.build_proof(leaves, index)
            assert evidence_merkle.verify_proof(proof, root)
            padded = evidence_merkle.MerkleProof(proof.leaf_index, proof.tree_size,
                                                 proof.leaf_hash, proof.siblings + ('0' * 64,))
            assert not evidence_merkle.verify_proof(padded, root)
            if proof.siblings:
                short = evidence_merkle.MerkleProof(proof.leaf_index, proof.tree_size,
                                                    proof.leaf_hash, proof.siblings[:-1])
                assert not evidence_merkle.verify_proof(short, root)


# ---------------------------------------------------------------- rf.anchor.v4 in core and verifier


@needs_pq
def test_v4_anchor_commits_to_rfc9162_root_and_verifies(ledger):
    hashes = [r['entry_hash'] for r in _jsonl_ledger(ledger)]
    assert ledger['a1']['schema'] == 'rf.anchor.v4'
    assert ledger['a1']['merkle_root'] == _mth(hashes[:4]).hex()
    assert ledger['a2']['merkle_root'] == _mth(hashes[:7]).hex()
    assert rf_core.verify_anchors() == (True, 'verified 2 anchors')
    bundle = ledger['tmp'] / 'b.zip'
    exporter.export_bundle(ledger['base'], bundle)
    report = verifier.verify_bundle(str(bundle), require_pq=True)
    assert report['merkle_anchors'] == 2 and report['merkle_committed_through_entry'] == 7


def _jsonl_ledger(ledger):
    conn = sqlite3.connect(ledger['base'] / 'ledger.db')
    try:
        rows = conn.execute('SELECT id, entry_hash FROM ledger_entries ORDER BY id').fetchall()
    finally:
        conn.close()
    return [{'id': r[0], 'entry_hash': r[1]} for r in rows]


@needs_pq
def test_wrong_merkle_root_signed_with_both_keys_is_rejected(ledger):
    """A full key compromise cannot make the signed root disagree with the ledger undetected."""
    ed, pq = _keys(ledger['base'])
    anchors = _jsonl(rf_core.ANCHOR_PATH)
    anchors[1]['merkle_root'] = HASHES[0]
    anchors[1] = _resign(anchors[1], ed, pq)
    _dump(rf_core.ANCHOR_PATH, anchors)
    assert rf_core.verify_anchors() == (False, 'merkle root mismatch at anchor 2')
    bundle = ledger['tmp'] / 'wrong-root.zip'
    exporter.export_bundle(ledger['base'], bundle)
    with pytest.raises(verifier.VerificationError, match='merkle root mismatch at anchor 2'):
        verifier.verify_bundle(str(bundle))


@needs_pq
def test_v4_to_v3_downgrade_is_rejected_by_core_and_verifier(ledger):
    ed, pq = _keys(ledger['base'])
    anchors = _jsonl(rf_core.ANCHOR_PATH)
    downgraded = {k: v for k, v in anchors[-1].items() if k != 'merkle_root'}
    downgraded.update(schema='rf.anchor.v3', seq=3, prev_anchor_hash=anchors[-1]['anchor_hash'])
    anchors.append(_resign(downgraded, ed, pq))
    _dump(rf_core.ANCHOR_PATH, anchors)
    assert rf_core.verify_anchors() == (False, 'merkle commitment downgrade at anchor 3')
    bundle = ledger['tmp'] / 'downgrade.zip'
    exporter.export_bundle(ledger['base'], bundle)
    with pytest.raises(verifier.VerificationError, match='merkle commitment downgrade at anchor 3'):
        verifier.verify_bundle(str(bundle))


@needs_pq
def test_v4_pq_signature_under_v3_context_is_rejected(ledger):
    """ML-DSA contexts are per schema: a v3-context signature cannot be replayed onto v4."""
    ed, pq = _keys(ledger['base'])
    anchors = _jsonl(rf_core.ANCHOR_PATH)
    anchors[0] = _resign(anchors[0], ed, pq, context=b'rf.anchor.v3')
    anchors[1]['prev_anchor_hash'] = anchors[0]['anchor_hash']
    anchors[1] = _resign(anchors[1], ed, pq)
    _dump(rf_core.ANCHOR_PATH, anchors)
    assert rf_core.verify_anchors() == (False, 'post-quantum signature invalid at anchor 1')


@needs_pq
def test_existing_v3_ledger_still_verifies_and_upgrades_to_v4(tmp_path, monkeypatch):
    """Ledgers anchored by v0.3.x (rf.anchor.v3) keep verifying; the next anchor is v4."""
    base = _point(monkeypatch, tmp_path / 'old')
    for i in range(3):
        rf_core.append_entry('evt', {'n': i})
    _, _, key_id = rf_core.load_or_create_keypair()
    _, pq_key_id = rf_core.load_or_create_pq_keypair()
    ed, pq = _keys(base)
    head = _jsonl_ledger({'base': base})[-1]['entry_hash']
    v3 = _resign({'schema': 'rf.anchor.v3', 'seq': 1, 'created_at': rf_core._utc_now(),
                  'ledger_count': 3, 'ledger_head': head, 'prev_anchor_hash': '0' * 64,
                  'key_id': key_id, 'pq_key_id': pq_key_id}, ed, pq)
    _dump(rf_core.ANCHOR_PATH, [v3])
    assert rf_core.verify_anchors() == (True, 'verified 1 anchors')
    rf_core.append_entry('evt', {'n': 3})
    assert rf_core.create_anchor()['schema'] == 'rf.anchor.v4'
    assert rf_core.verify_anchors() == (True, 'verified 2 anchors')
    bundle = tmp_path / 'mixed.zip'
    exporter.export_bundle(base, bundle)
    report = verifier.verify_bundle(str(bundle), require_pq=True)
    assert report['pq_anchors'] == 2 and report['merkle_anchors'] == 1


@needs_pq
def test_core_rejects_malformed_merkle_root(ledger):
    anchors = _jsonl(rf_core.ANCHOR_PATH)
    anchors[0]['merkle_root'] = 'Z' * 64
    _dump(rf_core.ANCHOR_PATH, anchors)
    assert rf_core.verify_anchors() == (False, 'anchor 1 malformed')


# ---------------------------------------------------------------- rf.receipt.v1


@needs_pq
def test_receipt_for_every_entry_verifies_and_discloses_nothing_else(ledger):
    a2 = ledger['a2']
    for entry_id in range(1, 8):
        path, receipt = _receipt_file(ledger, entry_id)
        assert receipt['anchor']['seq'] == 2 and receipt['tree_size'] == 7
        report = verifier.verify_receipt(str(path), pin_key_id=a2['key_id'],
                                         pin_anchors=[(2, a2['anchor_hash'])],
                                         pin_pq_key_id=a2['pq_key_id'])
        assert report['trust_level'] == 'anchor_pinned' and report['entry_id'] == entry_id
        text = path.read_text()
        rows = _jsonl_ledger(ledger)
        payloads = [json.dumps({'n': n}) for n in range(9) if n != entry_id - 1]
        assert not any(row['entry_hash'] in text for row in rows if row['id'] > 7)
        assert not any(_canon(json.loads(p)) in text for p in payloads)
        assert 'PRIVATE KEY' not in text


@needs_pq
def test_receipt_against_older_pinned_anchor(ledger):
    a1 = ledger['a1']
    path, receipt = _receipt_file(ledger, 3, anchor_seq=1)
    assert receipt['tree_size'] == 4
    report = verifier.verify_receipt(str(path), pin_anchors=[(1, a1['anchor_hash'])])
    assert report['trust_level'] == 'anchor_pinned'
    with pytest.raises(verifier.VerificationError, match='no --pin-anchor for receipt anchor 1'):
        verifier.verify_receipt(str(path), pin_anchors=[(2, ledger['a2']['anchor_hash'])])
    with pytest.raises(verifier.VerificationError, match='pinned anchor 1 hash mismatch'):
        verifier.verify_receipt(str(path), pin_anchors=[(1, '0' * 64)])
    mixed = verifier.verify_receipt(str(path), pin_anchors=[(1, a1['anchor_hash']),
                                                            (2, ledger['a2']['anchor_hash'])])
    assert any('do not apply' in w for w in mixed['warnings'])


@needs_pq
def test_receipt_selection_errors(ledger, tmp_path, monkeypatch):
    with pytest.raises(rf_receipt.ReceiptUnavailable, match='no rf.anchor.v4 anchor covers entry 8'):
        rf_receipt.build_receipt(ledger['base'], 8)
    with pytest.raises(rf_receipt.ReceiptUnavailable, match='not entry 5'):
        rf_receipt.build_receipt(ledger['base'], 5, anchor_seq=1)
    with pytest.raises(LookupError, match='anchor 9 does not exist'):
        rf_receipt.build_receipt(ledger['base'], 1, anchor_seq=9)
    with pytest.raises(ValueError, match='positive integer'):
        rf_receipt.build_receipt(ledger['base'], 0)
    monkeypatch.setenv('RF_PQ_SIGNING', 'off')
    plain = _point(monkeypatch, tmp_path / 'plain')
    rf_core.append_entry('evt', {'n': 1})
    rf_core.create_anchor()
    with pytest.raises(rf_receipt.ReceiptUnavailable):
        rf_receipt.build_receipt(plain, 1)


@needs_pq
def test_receipt_builder_refuses_inconsistent_ledger(ledger):
    conn = sqlite3.connect(ledger['base'] / 'ledger.db')
    try:
        conn.execute("UPDATE ledger_entries SET entry_hash = ? WHERE id = 2", ('f' * 64,))
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(ValueError, match='does not match the Merkle root'):
        rf_receipt.build_receipt(ledger['base'], 1)


@needs_pq
@pytest.mark.parametrize('case,match', [
    ('edit_payload_keep_hash', 'hash mismatch at 3'),
    ('edit_payload_rehash', 'does not reach the signed merkle_root'),
    ('wrong_leaf_index', 'leaf_index does not match'),
    ('wrong_tree_size', 'tree_size does not match'),
    ('truncated_path', 'shorter than the tree requires'),
    ('extended_path', 'longer than the tree requires'),
    ('malformed_path', 'path element is malformed'),
    ('path_not_list', 'inclusion_path is not a list'),
    ('extra_field', 'receipt has unexpected fields'),
    ('wrong_schema', 'unsupported receipt schema'),
    ('entry_extra_field', 'entry has unexpected fields'),
    ('noncanonical_payload', 'payload not canonical'),
    ('anchor_v3', 'not a hybrid Merkle anchor'),
    ('anchor_resigned_wrong_key', 'anchor signature invalid'),
    ('swapped_ed25519_key', 'key identity mismatch'),
    ('swapped_pq_key', 'post-quantum key identity mismatch'),
    ('bad_pem', 'public key unreadable'),
    ('entry_id_string', 'invalid id'),
])
def test_receipt_tampering_is_rejected(ledger, case, match):
    _, receipt = _receipt_file(ledger, 3)
    entry, anchor = receipt['entry'], receipt['anchor']
    if case == 'edit_payload_keep_hash':
        entry['payload'] = _canon({'n': 999})
    elif case == 'edit_payload_rehash':
        entry['payload'] = _canon({'n': 999})
        entry['entry_hash'] = _sha(
            f"3|{entry['prev_hash']}|{entry['ts']}|{entry['entry_type']}|{entry['payload']}".encode())
    elif case == 'wrong_leaf_index':
        receipt['leaf_index'] = 3
    elif case == 'wrong_tree_size':
        receipt['tree_size'] = 8
    elif case == 'truncated_path':
        receipt['inclusion_path'] = receipt['inclusion_path'][:-1]
    elif case == 'extended_path':
        receipt['inclusion_path'] = receipt['inclusion_path'] + ['0' * 64]
    elif case == 'malformed_path':
        receipt['inclusion_path'][0] = 'nothex'
    elif case == 'path_not_list':
        receipt['inclusion_path'] = 'abc'
    elif case == 'extra_field':
        receipt['note'] = 'x'
    elif case == 'wrong_schema':
        receipt['schema'] = 'rf.receipt.v0'
    elif case == 'entry_extra_field':
        entry['extra'] = 1
    elif case == 'noncanonical_payload':
        entry['payload'] = '{"n": 2}'
    elif case == 'anchor_v3':
        anchor['schema'] = 'rf.anchor.v3'
    elif case == 'anchor_resigned_wrong_key':
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        anchor['signature'] = base64.b64encode(
            Ed25519PrivateKey.generate().sign(anchor['anchor_hash'].encode())).decode()
    elif case == 'swapped_ed25519_key':
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        receipt['signing_key_pem'] = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    elif case == 'swapped_pq_key':
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
        receipt['pq_signing_key_pem'] = MLDSA65PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    elif case == 'bad_pem':
        receipt['signing_key_pem'] = 'garbage'
    elif case == 'entry_id_string':
        entry['id'] = '3'
    path = _write_receipt(ledger, receipt, f'{case}.json')
    with pytest.raises(verifier.VerificationError, match=match):
        verifier.verify_receipt(str(path))


@needs_pq
def test_receipt_parsing_limits(ledger):
    path, _ = _receipt_file(ledger, 1)
    text = path.read_text()
    dup = ledger['tmp'] / 'dup.json'
    dup.write_text('{"schema":"a",' + text[1:])
    with pytest.raises(verifier.VerificationError, match='duplicate JSON key'):
        verifier.verify_receipt(str(dup))
    big = ledger['tmp'] / 'big.json'
    big.write_bytes(b' ' * (verifier.MAX_RECEIPT_BYTES + 1))
    with pytest.raises(verifier.VerificationError, match='exceeds size limit'):
        verifier.verify_receipt(str(big))
    with pytest.raises(verifier.VerificationError, match='cannot read receipt'):
        verifier.verify_receipt(str(ledger['tmp'] / 'missing.json'))


@needs_pq
def test_key_holding_attacker_receipt_needs_anchor_pin(ledger):
    """Both keys stolen: a forged receipt verifies internally, and only the pin catches it."""
    ed, pq = _keys(ledger['base'])
    _, receipt = _receipt_file(ledger, 7)
    entry, anchor = receipt['entry'], receipt['anchor']
    entry['payload'] = _canon({'n': 6, 'text': 'forged'})
    entry['entry_hash'] = _sha(
        f"7|{entry['prev_hash']}|{entry['ts']}|{entry['entry_type']}|{entry['payload']}".encode())
    anchor['merkle_root'] = rf_merkle.root_from_inclusion_path(entry['entry_hash'], 6, 7,
                                                               receipt['inclusion_path'])
    anchor['ledger_head'] = entry['entry_hash']
    receipt['anchor'] = _resign(anchor, ed, pq)
    path = _write_receipt(ledger, receipt, 'stolen-keys.json')
    assert verifier.verify_receipt(str(path))['trust_level'] == 'internal_only'
    with pytest.raises(verifier.VerificationError, match='pinned anchor 2 hash mismatch'):
        verifier.verify_receipt(str(path), pin_anchors=[(2, ledger['a2']['anchor_hash'])])


@needs_pq
def test_last_entry_must_equal_ledger_head(ledger):
    ed, pq = _keys(ledger['base'])
    _, receipt = _receipt_file(ledger, 7)
    receipt['anchor']['ledger_head'] = 'e' * 64
    receipt['anchor'] = _resign(receipt['anchor'], ed, pq)
    path = _write_receipt(ledger, receipt, 'head.json')
    with pytest.raises(verifier.VerificationError, match='differs from ledger_head'):
        verifier.verify_receipt(str(path))


@needs_pq
def test_receipt_cli_and_exporter_tool(ledger, capsys):
    out = ledger['tmp'] / 'cli-receipt.json'
    assert receipt_tool.main(['--data-dir', str(ledger['base']), '--entry-id', '2',
                              '--out', str(out)]) == 0
    printed = capsys.readouterr().out
    pin = f"2:{ledger['a2']['anchor_hash']}"
    assert f'--pin-anchor {pin}' in printed
    assert receipt_tool.main(['--data-dir', str(ledger['base']), '--entry-id', '2',
                              '--out', str(out)]) == 1
    assert 'refusing to overwrite' in capsys.readouterr().err
    assert receipt_tool.main(['--data-dir', str(ledger['base']), '--entry-id', '99',
                              '--out', str(ledger['tmp'] / 'none.json')]) == 1
    assert not (ledger['tmp'] / 'none.json').exists()
    assert verifier.main([str(out), '--receipt', '--pin-anchor', pin, '--json']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['type'] == 'rf.receipt.v1' and report['trust_level'] == 'anchor_pinned'
    assert verifier.main([str(out), '--receipt']) == 10
    assert verifier.main([str(out), '--receipt', '--require-full-pin']) == 1
    bundle = ledger['tmp'] / 'b.zip'
    exporter.export_bundle(ledger['base'], bundle)
    assert verifier.main([str(bundle), '--receipt']) == 1


def test_receipt_tool_requires_data_dir(monkeypatch):
    monkeypatch.delenv('RF_DATA_DIR', raising=False)
    with pytest.raises(SystemExit):
        receipt_tool.main(['--entry-id', '1', '--out', os.devnull])


@needs_pq
def test_receipt_builder_checks_public_keys_against_anchor(ledger):
    pq_pub = ledger['base'] / rf_core.PQ_PUBLIC_KEY_NAME
    original = pq_pub.read_bytes()
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    pq_pub.write_bytes(MLDSA65PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(ValueError, match='did not sign anchor 2'):
        rf_receipt.build_receipt(ledger['base'], 1)
    pq_pub.unlink()
    with pytest.raises(rf_receipt.ReceiptUnavailable, match='need both'):
        rf_receipt.build_receipt(ledger['base'], 1)
    pq_pub.write_bytes(original)
    assert rf_receipt.build_receipt(ledger['base'], 1)['entry']['id'] == 1
