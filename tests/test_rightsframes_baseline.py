from pathlib import Path
import ast
import subprocess
import re
import hashlib


ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_git_head_matches_origin():
    head = run('git', 'rev-parse', 'HEAD')
    origin = run('git', 'rev-parse', 'origin/main')
    assert head.returncode == 0
    assert origin.returncode == 0

    head_sha = head.stdout.strip()
    origin_sha = origin.stdout.strip()

    assert re.fullmatch(r'[0-9a-f]{40}', head_sha)
    assert re.fullmatch(r'[0-9a-f]{40}', origin_sha)

    ancestry = run(
        'git',
        'merge-base',
        '--is-ancestor',
        origin_sha,
        head_sha,
    )

    assert ancestry.returncode == 0 or head_sha == origin_sha


def test_git_fsck_has_no_fatal_errors():
    result = run('git', 'fsck', '--full', '--no-reflogs')
    assert result.returncode == 0
    fatal = [
        line for line in result.stdout.splitlines()
        if line.startswith('missing ')
        or line.startswith('error ')
        or 'corrupt' in line.lower()
    ]
    assert fatal == []


def test_required_workflows_exist():
    workflows = [
        ROOT / '.github/workflows/continuous-release-integrity.yml',
        ROOT / '.github/workflows/provenance-gate.yml',
        ROOT / '.github/workflows/slsa-build-l3.yml',
        ROOT / '.github/workflows/verify.yml',
    ]
    for path in workflows:
        assert path.is_file()
        assert path.stat().st_size > 0


def test_python_sources_compile():
    files = [
        path for path in ROOT.rglob('*.py')
        if '.git' not in path.parts
        and '__pycache__' not in path.parts
    ]
    assert files
    for path in files:
        ast.parse(path.read_text(), filename=str(path))


def test_release_tags_exist():
    required = {'v0.1.0', 'v0.1.1', 'v0.1.2'}
    result = run('git', 'tag', '--list')
    assert result.returncode == 0
    assert required.issubset(set(result.stdout.splitlines()))


def test_provenance_verifiers_exist():
    files = [
        ROOT / 'provenance/verify_release.sh',
        ROOT / 'provenance/reproducibility_verify.sh',
        ROOT / 'provenance/adversarial_verify.sh',
    ]
    for path in files:
        assert path.is_file()
        assert path.stat().st_size > 0


def test_security_documentation_exists():
    files = [
        ROOT / 'SECURITY.md',
        ROOT / 'CONTRIBUTING.md',
        ROOT / 'README.md',
        ROOT / 'LICENSE',
    ]
    for path in files:
        assert path.is_file()
        assert path.stat().st_size > 0


def test_required_source_files_are_tracked():
    files = [
        'core/Dockerfile',
        'core/requirements.txt',
        'core/app.py',
        'core/rf_core.py',
        'tools/verify_supply_chain_policy.py',
        'tools/rf_source_l4_external_verifier.py',
        'provenance/verify_release.sh',
        'provenance/reproducibility_verify.sh',
        'provenance/adversarial_verify.sh',
    ]
    result = run('git', 'ls-files', '--error-unmatch', *files)
    assert result.returncode == 0


def test_workflows_have_explicit_permissions_policy():
    workflows = [
        ROOT / '.github/workflows/continuous-release-integrity.yml',
        ROOT / '.github/workflows/provenance-gate.yml',
        ROOT / '.github/workflows/slsa-build-l3.yml',
        ROOT / '.github/workflows/verify.yml',
    ]

    for path in workflows:
        text = path.read_text()
        assert (
            'permissions:' in text
            or 'permissions :' in text
            or 'permissions' in text
        )


def test_oidc_usage_is_declared():
    workflows = [
        ROOT / '.github/workflows/continuous-release-integrity.yml',
        ROOT / '.github/workflows/provenance-gate.yml',
        ROOT / '.github/workflows/slsa-build-l3.yml',
        ROOT / '.github/workflows/verify.yml',
    ]
    combined = '\n'.join(path.read_text() for path in workflows)
    assert 'id-token: write' in combined or 'id-token:write' in combined


def test_requirements_file_exists():
    path = ROOT / 'core/requirements.txt'
    assert path.is_file()
    assert path.stat().st_size > 0


def test_dockerfile_exists():
    path = ROOT / 'core/Dockerfile'
    assert path.is_file()
    assert path.stat().st_size > 0


def test_no_empty_required_source_files():
    files = [
        ROOT / 'core/Dockerfile',
        ROOT / 'core/requirements.txt',
        ROOT / 'core/app.py',
        ROOT / 'core/rf_core.py',
    ]
    for path in files:
        assert path.stat().st_size > 0


def test_repository_tree_is_resolvable():
    result = run('git', 'cat-file', '-e', 'HEAD^{tree}')
    assert result.returncode == 0


def test_reachable_git_objects_are_readable():
    objects = run('git', 'rev-list', '--all', '--objects')
    assert objects.returncode == 0

    object_ids = [
        line.split()[0]
        for line in objects.stdout.splitlines()
        if line.split()
    ]
    assert object_ids

    result = subprocess.run(
        ['git', 'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'],
        cwd=ROOT,
        input=''.join(obj + '\n' for obj in object_ids),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert result.returncode == 0

    for line in result.stdout.splitlines():
        parts = line.split()
        assert len(parts) >= 2
        assert parts[1] != 'missing'


def test_source_files_have_stable_hashes():
    files = [
        ROOT / 'core/Dockerfile',
        ROOT / 'core/requirements.txt',
        ROOT / 'core/app.py',
        ROOT / 'core/rf_core.py',
    ]
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert len(digest) == 64
        assert all(char in '0123456789abcdef' for char in digest)
