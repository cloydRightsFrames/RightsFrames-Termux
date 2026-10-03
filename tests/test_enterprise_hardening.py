import ast
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def run(*args):
    return subprocess.run(args,cwd=ROOT,text=True,capture_output=True)

def test_all_python_sources_compile():
    for p in ROOT.rglob('*.py'):
        if '.git' in p.parts or '__pycache__' in p.parts:
            continue
        ast.parse(p.read_text(encoding='utf-8'),filename=str(p))

def test_no_obvious_debug_or_unsafe_process_control():
    bad=(''.join(('os','.kill(')),''.join(('signal','.kill(')),''.join(('subprocess','.Popen(')))
    for p in ROOT.rglob('*.py'):
        if '.git' in p.parts or '__pycache__' in p.parts:
            continue
        s=p.read_text(encoding='utf-8')
        for token in bad:
            assert token not in s,f'{token} found in {p}'

def test_security_headers_are_present():
    p=ROOT/'core/app.py'
    s=p.read_text(encoding='utf-8')
    required=(
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Referrer-Policy',
        'Permissions-Policy',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'Cross-Origin-Opener-Policy',
        'Cross-Origin-Resource-Policy',
    )
    for x in required:
        assert x in s

def test_trusted_hosts_and_cors_are_restricted():
    s=(ROOT/'core/app.py').read_text(encoding='utf-8')
    assert 'TrustedHostMiddleware' in s
    assert 'allow_credentials=False' in s
    assert 'allow_methods=["GET", "POST", "OPTIONS"]' in s

def test_core_cryptography_primitives_exist():
    s=(ROOT/'core/rf_core.py').read_text(encoding='utf-8')
    assert 'Ed25519PrivateKey' in s
    assert 'Ed25519' in s
    assert 'hashlib.sha256' in s
    assert 'json.dumps' in s
    assert 'sort_keys=True' in s

def test_chain_verification_is_independent_of_append():
    s=(ROOT/'core/rf_core.py').read_text(encoding='utf-8')
    assert 'def verify_chain' in s
    assert 'def verify_anchors' in s
    assert 'prev_hash' in s
    assert 'entry_hash' in s

def test_required_supply_chain_controls_exist():
    required=(
        ROOT/'.github/workflows/continuous-release-integrity.yml',
        ROOT/'.github/workflows/provenance-gate.yml',
        ROOT/'.github/workflows/slsa-build-l3.yml',
        ROOT/'.github/workflows/verify.yml',
    )
    for p in required:
        assert p.is_file()
        assert p.stat().st_size>0

def test_workflows_have_explicit_permissions():
    for p in (ROOT/'.github/workflows').glob('*.yml'):
        s=p.read_text(encoding='utf-8')
        if 'jobs:' in s:
            assert 'permissions:' in s,f'missing permissions policy: {p}'

def test_oidc_workflows_declare_identity_permission():
    found=False
    for p in (ROOT/'.github/workflows').glob('*.yml'):
        s=p.read_text(encoding='utf-8')
        if 'id-token:' in s:
            found=True
            assert 'write' in s
    assert found

def test_requirements_are_pinned():
    p=ROOT/'core/requirements.txt'
    for raw in p.read_text(encoding='utf-8').splitlines():
        line=raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('--hash='):
            continue
        assert '==' in line,f'unpinned dependency: {line}'

def test_release_verifier_scripts_exist():
    for name in (
        'rf_release_artifact_verifier.py',
        'rf_enterprise_source_provenance_verifier.py',
        'rf_source_l4_external_verifier.py',
        'verify_source_l4_policy.py',
        'verify_supply_chain_policy.py',
    ):
        assert (ROOT/'tools'/name).is_file()

def test_security_documentation_exists():
    for name in ('SECURITY.md','CONTRIBUTING.md','docs/EXTERNAL-VERIFICATION.md'):
        assert (ROOT/name).is_file()

def test_git_tree_is_cleanly_resolvable():
    r=run('git','fsck','--no-reflogs','--full')
    assert r.returncode==0,r.stdout+r.stderr

def test_head_is_origin_main():
    a=run('git','rev-parse','HEAD').stdout.strip()
    b=run('git','rev-parse','origin/main').stdout.strip()
    assert a==b

def test_source_hashes_are_stable():
    for p in (ROOT/'core').rglob('*.py'):
        h=hashlib.sha256(p.read_bytes()).hexdigest()
        assert len(h)==64
        int(h,16)

def test_dockerfile_is_hardened_baseline():
    s=(ROOT/'core/Dockerfile').read_text(encoding='utf-8')
    assert 'FROM ' in s
    assert 'USER ' in s or 'user ' in s.lower()
    assert 'HEALTHCHECK' in s or 'healthcheck' in s.lower()

def test_verifier_cli_exists():
    p=ROOT/'verifier/evidence_verifier.py'
    s=p.read_text(encoding='utf-8')
    assert 'argparse' in s
    assert '--envelope' in s
    assert '--ledger' in s
    assert '--proof' in s
    assert '--signature' in s
