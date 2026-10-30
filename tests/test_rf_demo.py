"""The evaluator demo must pass end to end, and must fail if the verifier is weakened."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / 'tools' / 'rf_demo.py'


def _load_demo():
    spec = importlib.util.spec_from_file_location('rf_demo_under_test', DEMO)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_all_expectations_hold(capsys):
    demo = _load_demo()
    assert demo.main(['--entries', '4', '--json']) == 0
    report = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert report['passed'] is True
    checks = {item['check']: item for item in report['results']}
    hybrid = report['post_quantum'] != 'unavailable'
    assert len(checks) == (10 if hybrid else 8)
    pinned = checks['honest bundle, operator pins held externally']
    assert pinned['exit'] == 0 and 'anchor_pinned' in pinned['outcome']
    if hybrid:
        forger = checks['quantum forger: stolen Ed25519 key, re-sign anchors, key pins only']
        assert 'post-quantum signature invalid' in forger['outcome']
        downgrade = checks['downgrade: strip ML-DSA-65 signatures, re-sign Ed25519, key pins only']
        assert '--require-pq' in downgrade['outcome']
    for name, item in checks.items():
        if (name.startswith(('edit', 'delete', 'strip', 'quantum', 'downgrade'))
                or name.endswith('operator pins')):
            assert item['exit'] == 1, name
            assert item['outcome'].startswith('REJECTED'), name


def test_demo_rejects_too_few_entries():
    assert _load_demo().main(['--entries', '2']) == 1


def test_demo_detects_weakened_verifier(tmp_path, monkeypatch):
    """A verifier that accepts everything as anchor_pinned must make the demo fail."""
    fake = tmp_path / 'fake_verifier.py'
    fake.write_text(
        'import json\n'
        "print(json.dumps({'status': 'VERIFIED', 'trust_level': 'anchor_pinned'}))\n",
        encoding='utf-8',
    )
    demo = _load_demo()
    monkeypatch.setattr(demo, 'VERIFIER', fake)
    assert demo.main(['--entries', '3']) == 1


def test_demo_keep_refuses_existing_dir(tmp_path):
    existing = tmp_path / 'kept'
    existing.mkdir()
    assert _load_demo().main(['--keep', str(existing)]) == 1


def test_demo_keep_writes_bundles(tmp_path):
    kept = tmp_path / 'kept'
    assert _load_demo().main(['--entries', '3', '--keep', str(kept)]) == 0
    for name in ('evidence.zip', 'attack-1.zip', 'attack-forged-history.zip'):
        assert (kept / name).is_file(), name
