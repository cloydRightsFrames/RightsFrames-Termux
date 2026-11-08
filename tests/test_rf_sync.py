"""termux/rf-sync.sh against real git repositories: a bare 'GitHub' remote and a node clone.

The clone's origin is the real GitHub URL, redirected to the local bare repository with
url.<path>.insteadOf, so the origin pin is exercised exactly as on the phone. Termux:API
and runit commands are stubbed on PATH. Global and system git config are ignored.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'termux' / 'rf-sync.sh'
GITHUB_URL = 'https://github.com/cloydRightsFrames/RightsFrames-Termux.git'

pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or shutil.which('bash') is None or shutil.which('git') is None,
    reason='rf-sync targets Termux (Linux bash and git)')


def _git_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(('GIT_', 'RF_'))}
    env.update(HOME=str(home), GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1',
               GIT_AUTHOR_NAME='node', GIT_AUTHOR_EMAIL='node@example.invalid',
               GIT_COMMITTER_NAME='node', GIT_COMMITTER_EMAIL='node@example.invalid',
               RF_PQ_SIGNING='off')
    return env


def _git(env, cwd: Path, *args: str) -> str:
    return subprocess.run(['git', *args], cwd=cwd, env=env, check=True, text=True,
                          capture_output=True).stdout.strip()


class World:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.home = tmp / 'home'
        self.home.mkdir()
        self.bin = tmp / 'stubs'
        self.bin.mkdir()
        self.env = _git_env(self.home)
        self.env['PATH'] = f'{self.bin}:{os.environ["PATH"]}'
        self.env['PREFIX'] = str(tmp / 'prefix')
        self.bare = tmp / 'github.git'
        self.upstream = tmp / 'upstream'
        self.node = tmp / 'node'
        _git(self.env, tmp, 'init', '--quiet', '--bare', '--initial-branch=main', str(self.bare))
        _git(self.env, tmp, 'init', '--quiet', '--initial-branch=main', str(self.upstream))
        ignore = shutil.ignore_patterns('__pycache__', '*.pyc')
        for part in ('core', 'verifier', 'tools'):
            shutil.copytree(ROOT / part, self.upstream / part, ignore=ignore)
        (self.upstream / 'termux').mkdir()
        (self.upstream / 'termux' / 'rf-pinnacle.sh').write_text('echo v1\n', encoding='utf-8')
        (self.upstream / 'notes.txt').write_text('line one\nline two\n', encoding='utf-8')
        self.commit_upstream('initial')
        _git(self.env, tmp, 'clone', '--quiet', str(self.bare), str(self.node))
        _git(self.env, self.node, 'remote', 'set-url', 'origin', GITHUB_URL)
        _git(self.env, self.node, 'config', f'url.{self.bare}.insteadOf', GITHUB_URL)

    def commit_upstream(self, message: str, files: dict[str, str] | None = None) -> str:
        for rel, text in (files or {}).items():
            path = self.upstream / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
        _git(self.env, self.upstream, 'add', '-A')
        _git(self.env, self.upstream, 'commit', '--quiet', '-m', message)
        _git(self.env, self.upstream, 'push', '--quiet', str(self.bare), 'HEAD:main')
        return _git(self.env, self.upstream, 'rev-parse', 'HEAD')

    def head(self) -> str:
        return _git(self.env, self.node, 'rev-parse', 'HEAD')

    def stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text('#!/usr/bin/env bash\n' + body, encoding='utf-8')
        path.chmod(0o755)

    def run(self, *args: str, **extra_env: str) -> subprocess.CompletedProcess:
        env = {**self.env, 'RF_REPO_DIR': str(self.node), **extra_env}
        return subprocess.run(['bash', str(SCRIPT), *args], env=env, text=True,
                              capture_output=True, timeout=180)


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def test_already_current(world):
    r = world.run()
    assert r.returncode == 0, r.stderr
    assert 'already at' in r.stdout
    assert 'Byte-compile' in r.stdout


def test_fast_forward_and_dry_run(world):
    before = world.head()
    target = world.commit_upstream('feature: new tool', {'tools/rf_new.py': 'print("new")\n'})
    dry = world.run('--dry-run')
    assert dry.returncode == 0, dry.stderr
    assert 'feature: new tool' in dry.stdout and 'nothing changed' in dry.stdout
    assert world.head() == before
    r = world.run()
    assert r.returncode == 0, r.stderr
    assert world.head() == target
    assert 'Update' in r.stdout and target[:10] in r.stdout


def test_local_edits_survive_a_non_conflicting_update(world):
    target = world.commit_upstream('upstream edit', {'tools/extra.txt': 'x\n'})
    notes = world.node / 'notes.txt'
    notes.write_text('line one\nline two\nlocal note\n', encoding='utf-8')
    r = world.run()
    assert r.returncode == 0, r.stderr
    assert world.head() == target
    assert notes.read_text(encoding='utf-8').endswith('local note\n')
    assert _git(world.env, world.node, 'stash', 'list') == ''


def test_conflicting_local_edits_roll_back_exactly(world):
    before = world.head()
    world.commit_upstream('upstream rewrites notes', {'notes.txt': 'upstream version\n'})
    notes = world.node / 'notes.txt'
    notes.write_text('my local version\n', encoding='utf-8')
    r = world.run()
    assert r.returncode == 2, r.stdout + r.stderr
    assert 'conflict' in r.stderr or 'conflict' in r.stdout
    assert world.head() == before
    assert notes.read_text(encoding='utf-8') == 'my local version\n'
    assert _git(world.env, world.node, 'stash', 'list') == ''


def test_untracked_file_in_the_way_changes_nothing(world):
    before = world.head()
    world.commit_upstream('adds file', {'newfile.txt': 'upstream\n'})
    (world.node / 'newfile.txt').write_text('mine\n', encoding='utf-8')
    notes = world.node / 'notes.txt'
    notes.write_text('edited\n', encoding='utf-8')
    r = world.run()
    assert r.returncode == 1
    assert world.head() == before
    assert (world.node / 'newfile.txt').read_text(encoding='utf-8') == 'mine\n'
    assert notes.read_text(encoding='utf-8') == 'edited\n'
    assert _git(world.env, world.node, 'stash', 'list') == ''


def test_diverged_history_is_refused(world):
    world.commit_upstream('upstream', {'a.txt': '1\n'})
    (world.node / 'local.txt').write_text('local\n', encoding='utf-8')
    _git(world.env, world.node, 'add', 'local.txt')
    _git(world.env, world.node, 'commit', '--quiet', '-m', 'local commit')
    before = world.head()
    r = world.run()
    assert r.returncode == 3
    assert 'not an ancestor' in r.stderr
    assert world.head() == before


def test_rewritten_upstream_history_is_refused(world):
    world.commit_upstream('one', {'a.txt': '1\n'})
    assert world.run().returncode == 0
    synced = world.head()
    _git(world.env, world.upstream, 'reset', '--quiet', '--hard', 'HEAD~1')
    (world.upstream / 'b.txt').write_text('rewritten\n', encoding='utf-8')
    _git(world.env, world.upstream, 'add', '-A')
    _git(world.env, world.upstream, 'commit', '--quiet', '-m', 'rewrite')
    _git(world.env, world.upstream, 'push', '--quiet', '--force', str(world.bare), 'HEAD:main')
    r = world.run()
    assert r.returncode == 3
    assert world.head() == synced


@pytest.mark.parametrize('setup,message', [
    (lambda w: _git(w.env, w.node, 'remote', 'set-url', 'origin',
                    'https://github.com/someone-else/RightsFrames-Termux.git'), 'expected https://github.com'),
    (lambda w: _git(w.env, w.node, 'switch', '--quiet', '-c', 'feature'), "switch to main"),
    (lambda w: _git(w.env, w.node, 'checkout', '--quiet', '--detach'), 'detached'),
])
def test_preflight_refusals(world, setup, message):
    setup(world)
    r = world.run()
    assert r.returncode == 1
    assert message in r.stderr


def test_origin_pin_accepts_ssh_and_case_variants(world):
    for url in ('git@github.com:cloydrightsframes/rightsframes-termux.git',
                'https://github.com/cloydRightsFrames/RightsFrames-Termux'):
        _git(world.env, world.node, 'remote', 'set-url', 'origin', url)
        _git(world.env, world.node, 'config', f'url.{world.bare}.insteadOf', url)
        r = world.run('status')
        assert r.returncode == 0, r.stderr
        assert 'up to date' in r.stdout


def test_missing_repo_and_bad_arguments(world):
    assert 'repository not found' in world.run(RF_REPO_DIR=str(world.tmp / 'nope')).stderr
    assert world.run('--bogus').returncode == 1
    assert world.run('--restart', 'bad name!').returncode == 1
    assert 'rf-sync 1.0.0' in world.run('--version').stdout
    assert 'Fast-forward only' in world.run('--help').stdout


def test_low_battery_is_refused_unless_forced_and_wake_lock_is_released(world):
    world.stub('termux-battery-status', 'echo \'{"percentage": 5, "plugged": "UNPLUGGED"}\'\n')
    marks = world.tmp / 'wake.log'
    world.stub('termux-wake-lock', f'echo lock >> {marks}\n')
    world.stub('termux-wake-unlock', f'echo unlock >> {marks}\n')
    r = world.run()
    assert r.returncode == 1 and 'battery at 5%' in r.stderr
    forced = world.run('--force')
    assert forced.returncode == 0, forced.stderr
    assert marks.read_text().split() == ['lock', 'unlock']


def test_fetch_retries_then_fails_cleanly(world):
    world.stub('sleep', 'exit 0\n')  # no real waiting in tests
    _git(world.env, world.node, 'config', f'url.{world.tmp / "missing.git"}.insteadOf', GITHUB_URL)
    _git(world.env, world.node, 'config', '--unset', f'url.{world.bare}.insteadOf')
    r = world.run(RF_SYNC_RETRIES='3')
    assert r.returncode == 1
    assert r.stdout.count('retrying') == 2 and 'after 3 attempts' in r.stderr


def test_concurrent_run_is_blocked_and_stale_lock_reclaimed(world):
    lock = world.home / '.rightsframes' / 'sync' / 'lock'
    lock.mkdir(parents=True)
    (lock / 'pid').write_text(f'{os.getpid()}\n')
    r = world.run()
    assert r.returncode == 1 and 'another rf-sync is running' in r.stderr
    assert (lock / 'pid').read_text().strip() == str(os.getpid())  # the holder's lock survives
    (lock / 'pid').write_text('999999999\n')
    r = world.run()
    assert r.returncode == 0, r.stderr
    assert 'reclaiming stale lock' in r.stdout
    assert not lock.exists()


def test_requirements_change_reinstalls_and_installer_change_is_flagged(world):
    calls = world.tmp / 'python-calls.log'
    world.stub('fake-python', f'echo "$*" >> {calls}\n'
                              f'if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then exit 0; fi\n'
                              f'exec {sys.executable} "$@"\n')
    world.commit_upstream('deps', {'core/requirements.txt': '# changed\n',
                                     'termux/rf-pinnacle.sh': 'echo v2\n'})
    r = world.run(PYTHON=str(world.bin / 'fake-python'))
    assert r.returncode == 0, r.stdout + r.stderr
    assert '-m pip install' in calls.read_text() and '--require-hashes' in calls.read_text()
    assert 'rf-pinnacle.sh changed' in r.stdout


def test_ledger_is_verified_and_torn_anchor_log_reported(world):
    data = world.tmp / 'ledger-data'
    build = ('import sys; sys.path.insert(0, sys.argv[1]); from core import rf_core; '
             "rf_core.append_entry('evt', {'n': 1}); rf_core.create_anchor()")
    subprocess.run([sys.executable, '-c', build, str(world.node)], check=True, timeout=120,
                   env={**world.env, 'RF_DATA_DIR': str(data)})
    r = world.run(RF_DATA_DIR=str(data))
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'verified 1 entries; verified 1 anchors' in r.stdout
    log = data / 'anchors.jsonl'
    log.write_bytes(log.read_bytes() + b'{"seq":')
    torn = world.run(RF_DATA_DIR=str(data))
    assert torn.returncode == 4
    assert 'torn write detected' in torn.stderr
    assert log.read_bytes().endswith(b'{"seq":')  # never repaired automatically


def test_restart_services_through_runit(world):
    calls = world.tmp / 'sv.log'
    world.stub('sv', f'echo "$*" >> {calls}\n'
                     'if [ "$1" = status ]; then echo "run: $2: (pid 1) 5s; run: log"; fi\n'
                     'if [ "$2" = broken ]; then exit 1; fi\n')
    ok = world.run('--restart', 'rf-api')
    assert ok.returncode == 0, ok.stderr
    assert 'restart rf-api' in calls.read_text()
    bad = world.run('--restart', 'broken')
    assert bad.returncode == 4 and 'sv restart failed' in bad.stderr


def test_status_and_install(world):
    world.commit_upstream('pending', {'z.txt': 'z\n'})
    (world.node / 'notes.txt').write_text('dirty\n', encoding='utf-8')
    r = world.run('status')
    assert r.returncode == 0, r.stderr
    assert '1 commit(s) behind GitHub' in r.stdout and '1 locally modified file' in r.stdout
    prefix_bin = world.tmp / 'prefix' / 'bin'
    prefix_bin.mkdir(parents=True)
    inst = world.run('--install')
    assert inst.returncode == 0, inst.stderr
    assert (prefix_bin / 'rf-sync').resolve() == SCRIPT.resolve()


def test_log_records_every_run(world):
    world.run()
    world.run('--dry-run')
    entries = (world.home / '.rightsframes' / 'sync' / 'rf-sync.log').read_text().splitlines()
    assert sum('START' in line for line in entries) == 2
    assert sum('END rc=0' in line for line in entries) == 2
    json.dumps(entries)  # plain text, no binary noise
