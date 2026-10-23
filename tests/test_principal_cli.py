"""The principal CLI must hand the one-time token to the operator, safely."""
from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
import rf_auth  # noqa: E402
import rf_core  # noqa: E402


def _cli():
    spec = importlib.util.spec_from_file_location('rf_principal_cli', ROOT / 'tools' / 'rf_principal.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def data(tmp_path, monkeypatch):
    base = tmp_path / 'data'
    base.mkdir()
    for name, value in (('DATA_DIR', base), ('DB_PATH', base / 'ledger.db'),
                        ('PRIVATE_KEY_PATH', base / 'signing_key.pem'),
                        ('PUBLIC_KEY_PATH', base / 'signing_key.pub.pem'),
                        ('KEY_ID_PATH', base / 'signing_key.id'),
                        ('ANCHOR_PATH', base / 'anchors.jsonl'),
                        ('LOCK_PATH', base / 'anchors.lock')):
        monkeypatch.setattr(rf_core, name, value)
    monkeypatch.setenv('RF_DATA_DIR', str(base))
    return base


def test_token_file_is_private_usable_and_never_overwritten(data, tmp_path):
    cli = _cli()
    token_file = tmp_path / 'secrets' / 'admin.token'
    assert cli.main(['create', '--id', 'admin-1', '--scopes', 'admin:principals',
                     '--token-file', str(token_file)]) == 0
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600 or os.name == 'nt'
    principal = rf_auth.authenticate(token_file.read_text(encoding='utf-8').strip())
    assert principal is not None and principal['id'] == 'admin-1'

    before = token_file.read_bytes()
    assert cli.main(['create', '--id', 'admin-2', '--scopes', 'ledger:read',
                     '--token-file', str(token_file)]) == 1
    assert token_file.read_bytes() == before
    assert rf_auth.get_principal('admin-2') is None


def test_print_token_outputs_working_token(data, capsys):
    cli = _cli()
    assert cli.main(['create', '--id', 'reader-1', '--scopes', 'ledger:read',
                     '--print-token']) == 0
    lines = dict(line.split('=', 1) for line in capsys.readouterr().out.splitlines())
    assert rf_auth.authenticate(lines['TOKEN'])['id'] == 'reader-1'


def test_create_requires_explicit_token_delivery(data):
    with pytest.raises(SystemExit) as exc:
        _cli().main(['create', '--id', 'reader-1', '--scopes', 'ledger:read'])
    assert exc.value.code == 2
