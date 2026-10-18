import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
import rf_core  # noqa: E402


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


tool = _load('rf_pin_anchor_test', 'tools/rf_pin_anchor.py')


def _point(mp, base):
    base.mkdir(parents=True, exist_ok=True)
    for name, value in (('DATA_DIR', base), ('DB_PATH', base / 'ledger.db'),
                        ('PRIVATE_KEY_PATH', base / 'signing_key.pem'),
                        ('PUBLIC_KEY_PATH', base / 'signing_key.pub.pem'),
                        ('KEY_ID_PATH', base / 'signing_key.id'),
                        ('ANCHOR_PATH', base / 'anchors.jsonl'),
                        ('LOCK_PATH', base / 'anchors.lock')):
        mp.setattr(rf_core, name, value)


def test_pin_flow_and_check(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path / 'a')
    pins = tmp_path / 'pins' / 'anchor-pins.jsonl'
    first = tool.pin(rf_core.DATA_DIR, pins, create_anchor=True)
    assert first['status'] == 'pinned' and first['seq'] == 1
    assert tool.pin(rf_core.DATA_DIR, pins)['status'] == 'already_pinned'
    rf_core.append_entry('evt', {'n': 1})
    second = tool.pin(rf_core.DATA_DIR, pins, create_anchor=True)
    assert second['seq'] == 2
    assert len([line for line in pins.read_text().splitlines() if line.strip()]) == 2
    assert tool.check(rf_core.DATA_DIR, pins)['trust_level'] == 'anchor_pinned'


def test_pins_detect_regenerated_history(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path / 'a')
    pins = tmp_path / 'pins.jsonl'
    tool.pin(rf_core.DATA_DIR, pins, create_anchor=True)
    _point(monkeypatch, tmp_path / 'b')
    tool.pin(rf_core.DATA_DIR, tmp_path / 'other-pins.jsonl', create_anchor=True)
    with pytest.raises(tool.PinError):
        tool.check(rf_core.DATA_DIR, pins)


def test_pins_detect_rollback(tmp_path, monkeypatch):
    _point(monkeypatch, tmp_path / 'a')
    pins = tmp_path / 'pins.jsonl'
    tool.pin(rf_core.DATA_DIR, pins, create_anchor=True)
    rf_core.append_entry('evt', {'n': 1})
    tool.pin(rf_core.DATA_DIR, pins, create_anchor=True)
    anchors = rf_core.ANCHOR_PATH.read_text().splitlines(keepends=True)
    rf_core.ANCHOR_PATH.write_text(anchors[0])
    with pytest.raises(tool.PinError):
        tool.check(rf_core.DATA_DIR, pins)


def test_malformed_pins_rejected(tmp_path):
    bad = tmp_path / 'bad.jsonl'
    bad.write_text('{"seq":1,"anchor_hash":"nothex"}\n')
    with pytest.raises(tool.PinError):
        tool.read_pins(bad)