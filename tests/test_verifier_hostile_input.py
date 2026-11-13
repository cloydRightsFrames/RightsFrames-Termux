"""Malformed input is rejected with VerificationError, never with another exception type.

Every case below once escaped from verify_bundle / verify_receipt / verify_consistency as a
different exception (ValueError, UnicodeEncodeError, TypeError, lzma.LZMAError,
UnicodeDecodeError). The command line already failed closed on them; callers of the
functions did not get the documented error. Found by the fuzz targets in fuzz/.
"""
from __future__ import annotations

import importlib.util
import io
import json
import struct
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import rf_consistency, rf_core, rf_receipt  # noqa: E402


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load('rf_verify_hostile_test', 'verifier/rf_verify.py')
exporter = _load('rf_export_evidence_hostile_test', 'tools/rf_export_evidence.py')

needs_pq = pytest.mark.skipif(not rf_core.pq_available(),
                              reason='cryptography build lacks ML-DSA-65')
INTERNAL = 'internal verifier error'


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


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Nine entries (finite floats included), anchors after entries 5 and 9, and a bundle."""
    monkeypatch.setenv('RF_PQ_SIGNING', 'auto')
    base = _point(monkeypatch, tmp_path / 'op')
    for number in range(5):
        rf_core.append_entry('evt', {'n': number, 'ratio': 2.5, 'tiny': 1e-07, 'big': 1e+22})
    rf_core.create_anchor()
    for number in range(5, 9):
        rf_core.append_entry('evt', {'n': number, 'text': 'naïve ✓'})
    rf_core.create_anchor()
    bundle = tmp_path / 'bundle.zip'
    exporter.export_bundle(base, bundle)
    with zipfile.ZipFile(bundle) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    return {'base': base, 'tmp': tmp_path, 'bundle': bundle, 'members': members}


def _zip(members: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=compression) as archive:
        for name, blob in members.items():
            archive.writestr(name, blob)
    return buffer.getvalue()


def _with_manifest(members: dict[str, bytes], **changes) -> dict[str, bytes]:
    """Members with the manifest's file table matching them, then `changes` applied to it."""
    manifest = json.loads(members['manifest.json'])
    manifest['files'] = {name: {'sha256': verifier.sha256_hex(blob), 'bytes': len(blob)}
                         for name, blob in members.items() if name != 'manifest.json'}
    manifest.update(changes)
    return {**members, 'manifest.json': json.dumps(manifest).encode('utf-8')}


def _edit_first_entry(members: dict[str, bytes], **changes) -> dict[str, bytes]:
    lines = members['ledger.jsonl'].decode('utf-8').split('\n')
    entry = json.loads(lines[0])
    entry.update(changes)
    lines[0] = json.dumps(entry)
    return _with_manifest({**members, 'ledger.jsonl': '\n'.join(lines).encode('utf-8')})


def _rejects(world, name: str, blob: bytes, function, match: str, flag: str | None = None) -> None:
    path = world['tmp'] / name
    path.write_bytes(blob)
    with pytest.raises(verifier.VerificationError, match=match):
        function(str(path))
    # The command line reports the same failure, not an unexpected internal error.
    assert verifier.main([str(path), '--json'] + ([flag] if flag else [])) == 1


def test_finite_floats_in_payloads_still_verify(world, capsys):
    report = verifier.verify_bundle(str(world['bundle']))
    assert report['status'] == 'VERIFIED' and report['ledger_entries'] == 9
    assert '\\"ratio\\":2.5' in world['members']['ledger.jsonl'].decode('utf-8')
    if rf_core.pq_available():
        path = world['tmp'] / 'float-receipt.json'
        path.write_bytes(rf_receipt.canonical_receipt(rf_receipt.build_receipt(world['base'], 2)))
        assert verifier.verify_receipt(str(path))['entry_id'] == 2


@pytest.mark.parametrize('schema', [[], {}, ['rf.evidence.v2'], 5, None, True])
def test_bundle_manifest_schema_of_any_json_type_is_rejected(world, schema, capsys):
    blob = _zip(_with_manifest(world['members'], schema=schema))
    _rejects(world, 'schema.zip', blob, verifier.verify_bundle, 'unsupported bundle schema')
    assert INTERNAL not in capsys.readouterr().out


def test_bundle_with_corrupt_lzma_member_is_rejected(world, capsys):
    blob = bytearray(_zip(world['members'], zipfile.ZIP_LZMA))
    start = blob.find(b'manifest.json') + len('manifest.json') + 12
    blob[start:start + 40] = b'\xff' * 40
    _rejects(world, 'lzma.zip', bytes(blob), verifier.verify_bundle, 'cannot read bundle')
    assert INTERNAL not in capsys.readouterr().out


def test_bundle_with_undecodable_member_name_is_rejected(world, capsys):
    blob = bytearray(_zip(world['members']))
    directory = blob.find(b'PK\x01\x02')
    flags = struct.unpack_from('<H', blob, directory + 8)[0]
    struct.pack_into('<H', blob, directory + 8, flags | 0x800)  # "name is UTF-8"
    blob[directory + 46] = 0xFF                                  # ... and make it invalid UTF-8
    _rejects(world, 'name.zip', bytes(blob), verifier.verify_bundle, 'cannot read bundle')
    assert INTERNAL not in capsys.readouterr().out


@pytest.mark.parametrize('garbage', [b'', b'PK', b'PK\x05\x06' + b'\x00' * 18, b'\x00' * 4096,
                                     b'PK\x03\x04' + b'\xff' * 200])
def test_bundle_that_is_not_a_zip_is_rejected(world, garbage, capsys):
    # An empty but well-formed archive is readable; it is rejected for its (missing) members.
    _rejects(world, 'garbage.zip', garbage, verifier.verify_bundle,
             'cannot read bundle|unexpected archive members')
    assert INTERNAL not in capsys.readouterr().out


@pytest.mark.parametrize('changes, match', [
    ({'entry_type': '\ud800'}, 'bad entry_type at 1'),
    ({'entry_type': 'evt\udfff'}, 'bad entry_type at 1'),
    ({'payload': '{"a":1e999}'}, 'non-finite JSON number'),
    ({'payload': '{"a":-1e999}'}, 'non-finite JSON number'),
    ({'payload': '{"a":"\\ud800"}'}, 'payload not canonical at 1'),
])
def test_bundle_entry_with_unencodable_content_is_rejected(world, changes, match, capsys):
    blob = _zip(_edit_first_entry(world['members'], **changes))
    _rejects(world, 'entry.zip', blob, verifier.verify_bundle, match)
    assert INTERNAL not in capsys.readouterr().out


def test_bundle_anchor_with_unencodable_field_is_rejected(world, capsys):
    lines = world['members']['anchors.jsonl'].decode('utf-8').split('\n')
    anchor = json.loads(lines[0])
    name = 'pq_key_id' if 'pq_key_id' in anchor else 'schema'
    for value, match in (('\ud800', 'no canonical encoding|unsupported schema'),
                         ('@@INF@@', 'non-finite JSON number')):
        lines[0] = json.dumps({**anchor, name: value}).replace('"@@INF@@"', '1e999')
        members = _with_manifest({**world['members'], 'anchors.jsonl': '\n'.join(lines).encode('utf-8')})
        _rejects(world, 'anchor.zip', _zip(members), verifier.verify_bundle, match)
        assert INTERNAL not in capsys.readouterr().out


@needs_pq
@pytest.mark.parametrize('where, value, match', [
    (('entry', 'payload'), '{"a":1e999}', 'non-finite JSON number'),
    (('entry', 'entry_type'), '\ud800', 'bad entry_type'),
    (('entry', 'entry_type'), 'evt\udc00', 'bad entry_type'),
    (('entry', 'payload'), '{"a":"\\udfff"}', 'payload not canonical'),
    (('anchor', 'pq_key_id'), '\udfff', 'no canonical encoding'),
    (('anchor', 'pq_key_id'), '@@INF@@', 'non-finite JSON number'),
    (('anchor', 'pq_key_id'), '@@NEG@@', 'non-finite JSON number'),
    (('anchor', 'pq_key_id'), [], 'anchor hash mismatch'),
    (('anchor', 'pq_key_id'), {'a': None}, 'anchor hash mismatch'),
    (('anchor', 'ledger_count'), '@@INF@@', 'non-finite JSON number'),
    (('anchor', 'key_id'), '\ud800', 'key identity mismatch'),
])
def test_receipt_with_unencodable_content_is_rejected(world, where, value, match, capsys):
    receipt = rf_receipt.build_receipt(world['base'], 3)
    receipt[where[0]][where[1]] = value
    text = json.dumps(receipt).replace('"@@INF@@"', '1e999').replace('"@@NEG@@"', '-1e999')
    _rejects(world, 'receipt.json', text.encode('ascii'), verifier.verify_receipt, match, '--receipt')
    assert INTERNAL not in capsys.readouterr().out


@needs_pq
@pytest.mark.parametrize('anchor, field, value, match', [
    ('first_anchor', 'pq_key_id', '\ud800', 'no canonical encoding'),
    ('second_anchor', 'pq_key_id', '\udfff', 'no canonical encoding'),
    ('first_anchor', 'pq_key_id', '@@INF@@', 'non-finite JSON number'),
    ('second_anchor', 'ledger_count', '@@INF@@', 'non-finite JSON number'),
    ('second_anchor', 'seq', '@@INF@@', 'non-finite JSON number'),
    ('first_anchor', 'pq_key_id', [[]], 'anchor hash mismatch'),
])
def test_consistency_proof_with_unencodable_content_is_rejected(world, anchor, field, value, match, capsys):
    proof = rf_consistency.build_consistency_proof(world['base'], 1, 2)
    proof[anchor][field] = value
    text = json.dumps(proof).replace('"@@INF@@"', '1e999')
    _rejects(world, 'proof.json', text.encode('ascii'), verifier.verify_consistency, match, '--consistency')
    assert INTERNAL not in capsys.readouterr().out


@pytest.mark.parametrize('text', ['1e999', '-1e999', '[1e999]', '{"a":{"b":[0,1E400]}}', '1e309'])
def test_strict_loader_rejects_numbers_that_overflow_to_infinity(text):
    with pytest.raises(verifier.VerificationError, match='non-finite JSON number'):
        verifier._loads(text)


@pytest.mark.parametrize('text, expected', [('1e308', 1e308), ('-0.0', -0.0), ('2.5', 2.5),
                                            ('1e-400', 0.0), ('[1,2.0]', [1, 2.0])])
def test_strict_loader_keeps_finite_numbers(text, expected):
    assert verifier._loads(text) == expected
