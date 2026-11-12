"""The signer never anchors state that contradicts its own newest anchor, the core's
anchor check agrees with the independent verifier, and format checks accept no
trailing newline.

Every refusal is also shown to be recoverable: once the ledger or the clock is put
right, anchoring resumes and the independent verifier accepts the result under a pin
taken before the incident.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'core'))

from core import rf_core, rf_merkle, rf_receipt  # noqa: E402

import rf_api_v1  # noqa: E402
import rf_auth  # noqa: E402


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load('rf_verify_consistency_test', 'verifier/rf_verify.py')
exporter = _load('rf_export_evidence_consistency_test', 'tools/rf_export_evidence.py')
pin_tool = _load('rf_pin_anchor_consistency_test', 'tools/rf_pin_anchor.py')

needs_pq = pytest.mark.skipif(not rf_core.pq_available(),
                              reason='cryptography build lacks ML-DSA-65')
HASH = 'a' * 64
STAMP = '2026-01-01T00:00:00.000000Z'


@pytest.fixture()
def ledger(tmp_path, monkeypatch):
    base = tmp_path / 'data'
    base.mkdir()
    for name, value in (('DATA_DIR', base), ('DB_PATH', base / 'ledger.db'),
                        ('PRIVATE_KEY_PATH', base / 'signing_key.pem'),
                        ('PUBLIC_KEY_PATH', base / 'signing_key.pub.pem'),
                        ('KEY_ID_PATH', base / 'signing_key.id'),
                        ('ANCHOR_PATH', base / 'anchors.jsonl'),
                        ('LOCK_PATH', base / 'anchors.lock')):
        monkeypatch.setattr(rf_core, name, value)
    monkeypatch.delenv('RF_PQ_SIGNING', raising=False)
    return base


def _anchor_lines() -> list[str]:
    return rf_core.ANCHOR_PATH.read_text(encoding='utf-8').splitlines()


def _snapshot() -> list[tuple]:
    with contextlib.closing(sqlite3.connect(rf_core.DB_PATH)) as conn:
        return conn.execute('SELECT id, ts, entry_type, payload, prev_hash, entry_hash '
                            'FROM ledger_entries ORDER BY id').fetchall()


def _replace_ledger(rows: list[tuple]) -> None:
    with contextlib.closing(sqlite3.connect(rf_core.DB_PATH)) as conn:
        conn.execute('DELETE FROM ledger_entries')
        conn.executemany('INSERT INTO ledger_entries (id, ts, entry_type, payload, prev_hash, '
                         'entry_hash) VALUES (?, ?, ?, ?, ?, ?)', rows)
        conn.commit()


def _rewritten(rows: list[tuple]) -> list[tuple]:
    """The same ledger with every payload changed and the hash chain recomputed."""
    forged, previous = [], '0' * 64
    for entry_id, ts, entry_type, payload, _, _ in rows:
        payload = payload.replace('"n"', '"forged"')
        digest = hashlib.sha256(
            f'{entry_id}|{previous}|{ts}|{entry_type}|{payload}'.encode('utf-8')).hexdigest()
        forged.append((entry_id, ts, entry_type, payload, previous, digest))
        previous = digest
    return forged


def _verify(base: Path, tmp_path: Path, name: str, **pins):
    out = tmp_path / f'{name}.zip'
    exporter.export_bundle(base, out)
    return verifier.verify_bundle(str(out), **pins)


def _seed(count: int = 3) -> dict:
    for n in range(count):
        rf_core.append_entry('evt', {'n': n})
    return rf_core.create_anchor()


# ------------------------------------------------------------- the signer


def test_rewritten_history_is_not_signed(ledger, tmp_path):
    first = _seed()
    pin = [(1, first['anchor_hash'])]
    genuine = _snapshot()
    _replace_ledger(_rewritten(genuine))
    assert rf_core.verify_chain() == (True, 'verified 3 entries')  # the hash chain alone cannot tell

    with pytest.raises(ValueError, match='refusing to anchor rewritten history'):
        rf_core.create_anchor()
    assert len(_anchor_lines()) == 1  # nothing was appended

    _replace_ledger(genuine)
    rf_core.append_entry('evt', {'n': 3})
    second = rf_core.create_anchor()
    assert second['seq'] == 2 and second['ledger_count'] == 4
    assert rf_core.verify_anchors() == (True, 'verified 2 anchors')
    assert _verify(ledger, tmp_path, 'recovered', pin_anchors=pin)['trust_level'] == 'anchor_pinned'


def test_rewriting_only_the_anchored_head_is_not_signed(ledger):
    _seed()
    rf_core.append_entry('evt', {'n': 3})
    rows = _snapshot()
    _replace_ledger(_rewritten(rows))  # entries 1..3 are anchored, entry 4 is not
    with pytest.raises(ValueError, match='ledger entry 3 differs from the head signed by anchor 1'):
        rf_core.create_anchor()


def test_truncated_ledger_is_not_signed(ledger, tmp_path):
    first = _seed()
    pin = [(1, first['anchor_hash'])]
    genuine = _snapshot()
    _replace_ledger(genuine[:2])
    assert rf_core.verify_chain()[0]

    with pytest.raises(ValueError, match='ledger has 2 entries but anchor 1 signed 3'):
        rf_core.create_anchor()
    assert len(_anchor_lines()) == 1

    # Restoring the missing entry makes the ledger anchorable and verifiable again.
    # Before this guard the signer appended an anchor with a lower ledger_count, and
    # the anchor log could never verify again.
    _replace_ledger(genuine)
    assert rf_core.create_anchor()['seq'] == 2
    assert rf_core.verify_anchors() == (True, 'verified 2 anchors')
    assert _verify(ledger, tmp_path, 'restored', pin_anchors=pin)['trust_level'] == 'anchor_pinned'


def test_emptied_ledger_is_not_signed(ledger):
    _seed()
    _replace_ledger([])
    with pytest.raises(ValueError, match='ledger has 0 entries but anchor 1 signed 3'):
        rf_core.create_anchor()


def test_clock_behind_the_newest_anchor_is_not_signed(ledger, tmp_path, monkeypatch):
    first = _seed()
    pin = [(1, first['anchor_hash'])]
    rf_core.append_entry('evt', {'n': 3})
    real_now = rf_core._utc_now

    monkeypatch.setattr(rf_core, '_utc_now', lambda: '2020-01-01T00:00:00.000000Z')
    with pytest.raises(ValueError, match='system clock .* is behind anchor 1'):
        rf_core.create_anchor()
    assert len(_anchor_lines()) == 1

    # The same instant as the newest anchor is not a regression.
    monkeypatch.setattr(rf_core, '_utc_now', lambda: first['created_at'])
    assert rf_core.create_anchor()['created_at'] == first['created_at']

    monkeypatch.setattr(rf_core, '_utc_now', real_now)
    assert rf_core.create_anchor()['seq'] == 3
    assert rf_core.verify_anchors() == (True, 'verified 3 anchors')
    assert _verify(ledger, tmp_path, 'clock', pin_anchors=pin)['trust_level'] == 'anchor_pinned'


@pytest.mark.parametrize('field, value', [
    ('ledger_count', '3'), ('ledger_count', True), ('ledger_count', -1), ('ledger_count', None),
    ('ledger_head', 7), ('ledger_head', None), ('created_at', 20260101), ('created_at', None),
    ('anchor_hash', 5), ('anchor_hash', None),
])
def test_malformed_newest_anchor_is_not_extended(ledger, field, value):
    _seed()
    anchor = json.loads(_anchor_lines()[0])
    if value is None:
        del anchor[field]
    else:
        anchor[field] = value
    rf_core.ANCHOR_PATH.write_text(json.dumps(anchor) + '\n', encoding='utf-8')
    with pytest.raises(ValueError, match='anchor 1 is malformed; refusing to anchor after it'):
        rf_core.create_anchor()
    assert len(_anchor_lines()) == 1


def test_ordinary_anchoring_is_unchanged(ledger, tmp_path):
    empty = rf_core.create_anchor()                    # an empty ledger can be anchored
    assert empty['ledger_count'] == 0
    again = rf_core.create_anchor()                    # and anchored again with nothing new
    assert again['seq'] == 2 and again['ledger_count'] == 0
    for n in range(4):
        rf_core.append_entry('evt', {'n': n})
    third = rf_core.create_anchor()
    assert third['ledger_count'] == 4
    rf_core.append_entry('evt', {'n': 4})
    assert rf_core.create_anchor()['ledger_count'] == 5
    assert rf_core.verify_anchors() == (True, 'verified 4 anchors')
    report = _verify(ledger, tmp_path, 'ordinary', pin_anchors=[(3, third['anchor_hash'])])
    assert report['trust_level'] == 'anchor_pinned' and report['pinned_through_entry'] == 4


def test_tampering_after_an_anchor_is_still_detected(ledger, tmp_path):
    _seed()
    with contextlib.closing(sqlite3.connect(rf_core.DB_PATH)) as conn:
        conn.execute("UPDATE ledger_entries SET payload='{\"n\":99}' WHERE id=2")
        conn.commit()
    assert rf_core.verify_chain() == (False, 'hash mismatch at 2')
    with pytest.raises(ValueError, match='ledger verification failed'):
        rf_core.create_anchor()
    with pytest.raises(verifier.VerificationError, match='hash mismatch at 2'):
        _verify(ledger, tmp_path, 'tampered')


# ------------------------------------------- core and verifier agree on time


def test_core_reports_an_anchor_dated_before_its_predecessor(ledger, tmp_path, monkeypatch):
    """A log written before the signer had the clock guard: the core must not call it healthy."""
    _seed()
    rf_core.append_entry('evt', {'n': 3})
    with monkeypatch.context() as patch:
        patch.setattr(rf_core, '_check_extends_newest_anchor', lambda *args: None)
        patch.setattr(rf_core, '_utc_now', lambda: '2020-01-01T00:00:00.000000Z')
        rf_core.create_anchor()

    assert rf_core.verify_anchors() == (False, 'anchor time regressed at 2')
    assert rf_core.health()['status'] == 'degraded'
    with pytest.raises(verifier.VerificationError, match='anchor time regressed at 2'):
        _verify(ledger, tmp_path, 'regressed')


def test_core_rejects_an_anchor_without_a_text_timestamp(ledger):
    _seed()
    anchor = json.loads(_anchor_lines()[0])
    anchor['created_at'] = 20260101
    rf_core.ANCHOR_PATH.write_text(json.dumps(anchor) + '\n', encoding='utf-8')
    assert rf_core.verify_anchors() == (False, 'anchor 1 malformed')


# ----------------------------------------------- no trailing newline anywhere


def test_format_patterns_reject_a_trailing_newline():
    assert verifier._HEX64.match(HASH) and not verifier._HEX64.match(HASH + '\n')
    assert verifier._TS.match(STAMP) and not verifier._TS.match(STAMP + '\n')
    assert rf_merkle._HEX64.match(HASH) and not rf_merkle._HEX64.match(HASH + '\n')
    assert pin_tool._HEX64.match(HASH) and not pin_tool._HEX64.match(HASH + '\n')
    assert rf_auth.valid_principal_id('admin') and not rf_auth.valid_principal_id('admin\n')
    assert rf_api_v1._KEY.match('key-12345') and not rf_api_v1._KEY.match('key-12345\n')
    with pytest.raises(ValueError, match='64 lowercase hex'):
        rf_merkle.leaf_hash(HASH + '\n')


def test_pin_arguments_and_pin_files_reject_a_trailing_newline(tmp_path):
    assert verifier._parse_pin(f'1:{HASH}') == (1, HASH)
    with pytest.raises(Exception, match='SEQ:SHA256HEX'):
        verifier._parse_pin(f'1:{HASH}\n')
    pins = tmp_path / 'pins.jsonl'
    pins.write_text(json.dumps({'seq': 1, 'anchor_hash': HASH}) + '\n', encoding='utf-8')
    assert pin_tool.read_pins(pins)[0]['anchor_hash'] == HASH
    pins.write_text(json.dumps({'seq': 1, 'anchor_hash': HASH + '\n'}) + '\n', encoding='utf-8')
    with pytest.raises(pin_tool.PinError, match='malformed'):
        pin_tool.read_pins(pins)


@needs_pq
def test_receipt_with_altered_path_elements_no_longer_verifies(ledger, tmp_path):
    """Anyone could append a newline to each path element and the receipt still verified."""
    for n in range(5):
        rf_core.append_entry('evt', {'n': n})
    anchor = rf_core.create_anchor()
    pin = [(anchor['seq'], anchor['anchor_hash'])]
    receipt = rf_receipt.build_receipt(ledger, 2, None)
    assert receipt['inclusion_path']
    path = tmp_path / 'receipt.json'

    path.write_bytes(rf_receipt.canonical_receipt(receipt))
    assert verifier.verify_receipt(str(path), pin_anchors=pin)['trust_level'] == 'anchor_pinned'

    altered = json.loads(json.dumps(receipt))
    altered['inclusion_path'] = [item + '\n' for item in altered['inclusion_path']]
    path.write_text(json.dumps(altered), encoding='utf-8')
    with pytest.raises(verifier.VerificationError, match='inclusion path element is malformed'):
        verifier.verify_receipt(str(path), pin_anchors=pin)
    with pytest.raises(ValueError, match='inclusion path element is malformed'):
        rf_merkle.root_from_inclusion_path(receipt['entry']['entry_hash'], receipt['leaf_index'],
                                           receipt['tree_size'], altered['inclusion_path'])


def test_bundle_timestamps_with_a_trailing_newline_are_rejected(ledger, tmp_path, monkeypatch):
    """Self-signed timestamps that only look well-formed: accepted before, rejected now."""
    with monkeypatch.context() as patch:
        patch.setattr(rf_core, '_utc_now', lambda: STAMP + '\n')
        rf_core.append_entry('evt', {'n': 0})
    rf_core.load_or_create_keypair()  # the exporter needs the public key
    with pytest.raises(verifier.VerificationError, match='bad timestamp at 1'):
        _verify(ledger, tmp_path, 'entry-ts')


def test_anchor_timestamp_with_a_trailing_newline_is_rejected(ledger, tmp_path, monkeypatch):
    rf_core.append_entry('evt', {'n': 0})
    with monkeypatch.context() as patch:
        patch.setattr(rf_core, '_utc_now', lambda: STAMP + '\n')
        rf_core.create_anchor()
    with pytest.raises(verifier.VerificationError, match='anchor 1 has malformed created_at'):
        _verify(ledger, tmp_path, 'anchor-ts')
