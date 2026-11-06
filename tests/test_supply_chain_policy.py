"""tools/verify_supply_chain_policy.py: the repository passes, and each control fails closed."""
from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('verify_supply_chain_policy',
                                               ROOT / 'tools' / 'verify_supply_chain_policy.py')
policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy)

SHA = 'a' * 40


def test_repository_passes(capsys):
    assert policy.main(['--root', str(ROOT)]) == 0
    out = capsys.readouterr().out
    for line in ('RIGHTSFRAMES_ZERO_TRUST_POLICY=PASS', 'ACTION_PINNING=PASS',
                 'HASH_LOCKED_INSTALLS=PASS', 'JOB_TIMEOUTS=PASS', 'RELEASE_SBOM_CONTROLS=PASS'):
        assert line in out


@pytest.fixture
def repo(tmp_path):
    shutil.copytree(ROOT / '.github' / 'workflows', tmp_path / '.github' / 'workflows')
    return tmp_path


def _add(repo, body):
    (repo / '.github' / 'workflows' / 'extra.yml').write_text(body, encoding='utf-8')


GOOD = (
    'name: extra\n'
    'on: push\n'
    'permissions:\n'
    '  contents: read\n'
    'jobs:\n'
    '  build:\n'
    '    runs-on: ubuntu-24.04\n'
    '    timeout-minutes: 5\n'
    '    steps:\n'
    f'      - uses: actions/checkout@{SHA} # v7\n'
    '      - run: python -m pip install --require-hashes -r core/requirements.txt\n'
    '  reuse:\n'
    '    uses: ./.github/workflows/slsa-build-l3.yml\n'
)


def test_good_extra_workflow_passes(repo):
    _add(repo, GOOD)
    assert policy.main(['--root', str(repo)]) == 0


@pytest.mark.parametrize('old, new, code', [
    (f'actions/checkout@{SHA}', 'actions/checkout@v7', 'NON_IMMUTABLE_ACTION_REF'),
    (f'actions/checkout@{SHA}', 'actions/checkout@main', 'MUTABLE_ACTION_REF'),
    (f'actions/checkout@{SHA}', 'docker://alpine:3', 'NON_IMMUTABLE_ACTION_REF'),
    ('--require-hashes ', '', 'UNHASHED_PIP_INSTALL'),
    ('    timeout-minutes: 5\n', '', 'MISSING_JOB_TIMEOUT'),
    ('permissions:\n  contents: read\n', '', 'MISSING_TOP_LEVEL_PERMISSIONS'),
    ('on: push\n', 'on:\n  pull_request_target:\n', 'DANGEROUS_TRIGGER'),
    ('ubuntu-24.04', 'self-hosted', 'UNTRUSTED_RUNNER_REFERENCE'),
])
def test_each_control_fails_closed(repo, capsys, old, new, code):
    assert old in GOOD
    _add(repo, GOOD.replace(old, new))
    assert policy.main(['--root', str(repo)]) == 1
    assert capsys.readouterr().out.startswith(code + '=')


def test_step_level_timeout_does_not_count_as_job_timeout(repo, capsys):
    _add(repo, GOOD.replace('    timeout-minutes: 5\n', '').replace(
        '      - run: python', '      - timeout-minutes: 5\n        run: python'))
    assert policy.main(['--root', str(repo)]) == 1
    assert capsys.readouterr().out.startswith('MISSING_JOB_TIMEOUT=extra.yml:build')


def test_unhashed_install_split_over_lines_is_caught(repo, capsys):
    _add(repo, GOOD.replace(
        '      - run: python -m pip install --require-hashes -r core/requirements.txt\n',
        '      - run: |\n          python -m pip install \\\n            semgrep==1.0\n'))
    assert policy.main(['--root', str(repo)]) == 1
    assert capsys.readouterr().out.startswith('UNHASHED_PIP_INSTALL=')


def test_removing_a_release_control_fails(repo, capsys):
    gate = repo / '.github' / 'workflows' / 'provenance-gate.yml'
    gate.write_text(gate.read_text(encoding='utf-8').replace(
        'predicate-type: https://cyclonedx.org/bom', 'predicate-type: x'), encoding='utf-8')
    assert policy.main(['--root', str(repo)]) == 1
    assert capsys.readouterr().out.startswith('MISSING_CONTROL=provenance-gate.yml:')
