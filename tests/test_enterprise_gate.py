"""Exercise the published gate against clean, disposable Git checkouts."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SUITE = 'tests/test_enterprise_control_plane.py'


@pytest.fixture
def checkout(tmp_path):
    repo = tmp_path / 'checkout with spaces'
    for directory in ('enterprise', '.github/workflows'):
        shutil.copytree(ROOT / directory, repo / directory,
                        ignore=shutil.ignore_patterns('__pycache__'))
    for name in (SUITE, '.gitignore', 'scripts/rf-enterprise-gate', 'tools/rf_release_sbom.py',
                 'tools/verify_supply_chain_policy.py', 'core/rf_filelock.py', 'core/__init__.py', 'core/requirements.txt',
                 'core/requirements-test.txt'):
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('GIT_', 'PYTHONPATH'))}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', PYTHON_BIN=sys.executable,
               GIT_AUTHOR_NAME='test', GIT_COMMITTER_NAME='test',
               GIT_AUTHOR_EMAIL='test@example.invalid', GIT_COMMITTER_EMAIL='test@example.invalid')

    def git(*args):
        return subprocess.check_output(['git', *args], cwd=repo, env=env, text=True).strip()

    git('init', '--quiet')
    git('add', '.')
    git('commit', '--quiet', '-m', 'test checkout')
    return repo, env, git


def evaluate(checkout):
    repo, env, _ = checkout
    run = subprocess.run([sys.executable, '-m', 'enterprise.control_plane.cli', 'evaluate'],
                         cwd=repo, env=env, capture_output=True, text=True, timeout=30)
    return run.returncode, json.loads(run.stdout)


def test_clean_gate_records_what_it_actually_tested(checkout):
    repo, env, git = checkout
    code, result = evaluate(checkout)
    assert code == 0 and result['allowed'], result
    evidence = result['evidence']
    assert evidence['tests_pass']['detail']['passed'] >= 5
    assert evidence['tests_pass']['detail']['suite'] == SUITE
    assert evidence['provenance_record']['detail'] == {'commit': git('rev-parse', 'HEAD'),
                                                      'tree': git('rev-parse', 'HEAD^{tree}')}
    assert all(lock['packages'] > 0 for lock in evidence['pinned_dependencies']['detail'].values())
    bash = shutil.which('bash')
    if bash and sys.platform in ('linux', 'android', 'darwin'):
        # Call the real Termux entry point from outside its checkout.
        proc = subprocess.run([bash, str(repo / 'scripts/rf-enterprise-gate')],
                              cwd=repo.parent, env=env, capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0 and 'RIGHTSFRAMES_ENTERPRISE_GATE=PASS' in proc.stdout, proc.stderr
    (repo / 'untracked').touch()
    code, result = evaluate(checkout)
    assert code == 1 and result['failures'] == ['clean_worktree']


@pytest.mark.parametrize(('path', 'contents', 'failed'), [
    (SUITE, '# no executable tests\n', 'tests_pass'),
    (SUITE, 'import unittest\nclass T(unittest.TestCase):\n def test_gate(self): self.fail()\n', 'tests_pass'),
    (SUITE, 'import unittest\nclass T(unittest.TestCase):\n @unittest.skip("pending")\n def test_gate(self): pass\n',
     'tests_pass'),
    ('core/requirements.txt', 'unhashed==1\n', 'pinned_dependencies'),
    ('core/requirements-test.txt', 'example==1.* --hash=sha256:' + '0' * 64, 'pinned_dependencies'),
    ('core/requirements-test.txt', 'example==1 # --hash=sha256:' + '0' * 64, 'pinned_dependencies'),
])
def test_presence_alone_never_passes(checkout, path, contents, failed):
    repo, _, git = checkout
    (repo / path).write_text(contents, encoding='utf-8')
    git('commit', '--quiet', '-am', 'exercise failed check')
    code, result = evaluate(checkout)
    assert code == 1 and result['failures'] == [failed], result
    assert result['evidence'][failed]['status'] == 'fail'


@pytest.mark.parametrize('required', [None, {}, {'tests_pass': False}, {'tests_pass': 'true'}])
def test_unusable_policy_is_rejected(checkout, required):
    repo, _, _ = checkout
    policy = {'schema': 'rf.policy.v1', 'mode': 'fail-closed'}
    if required is not None:
        policy['required'] = required
    (repo / 'enterprise/policy.json').write_text(json.dumps(policy), encoding='utf-8')
    code, result = evaluate(checkout)
    assert code == 1 and result['allowed'] is False and 'policy.required' in result['evaluation_error']
