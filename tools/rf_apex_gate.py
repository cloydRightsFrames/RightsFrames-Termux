#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAIL = 0
PASS = 0

def ok(name: str) -> None:
    global PASS
    PASS += 1
    print(f'[PASS] {name}')

def bad(name: str) -> None:
    global FAIL
    FAIL += 1
    print(f'[FAIL] {name}')

def run(*args: str) -> str:
    return subprocess.check_output(
        args,
        cwd=ROOT,
        text=True,
        stderr=subprocess.STDOUT,
    )

required = [
    '.github/workflows/verify.yml',
    '.github/workflows/provenance-gate.yml',
    '.github/workflows/continuous-release-integrity.yml',
    '.github/workflows/slsa-build-l3.yml',
    'core/requirements.txt',
    'core/Dockerfile',
]

for item in required:
    p = ROOT / item
    (ok if p.is_file() else bad)(f'required:{item}')

try:
    out = run('git', 'fsck', '--full', '--no-reflogs')
    if re.search(r'^(error|fatal|missing)\b', out, re.M):
        bad('git-integrity')
    else:
        ok('git-integrity')
except Exception:
    bad('git-integrity')

try:
    if run('git', 'rev-parse', '--verify', 'HEAD').strip():
        ok('head-resolvable')
    else:
        bad('head-resolvable')
except Exception:
    bad('head-resolvable')

for wf in (ROOT / '.github' / 'workflows').glob('*.y*ml'):
    text = wf.read_text(errors='replace')

    if re.search(r'^\s*permissions\s*:', text, re.M):
        ok(f'permissions:{wf.name}')
    else:
        bad(f'permissions:{wf.name}')

    mutable = re.findall(
        r'^\s*-\s*uses:\s*([^@\s]+)@(main|master|latest|v\d+(?:\.\d+)*)\s*$',
        text,
        re.M,
    )
    if mutable:
        bad(f'action-pin:{wf.name}')
    else:
        ok(f'action-pin:{wf.name}')

    if re.search(r'\bsecrets\.[A-Za-z0-9_]+\b', text):
        ok(f'secrets-explicit:{wf.name}')
    else:
        ok(f'secrets-scan:{wf.name}')

secret_re = re.compile(
    r'(?:AKIA[0-9A-Z]{16}|'
    r'ghp_[A-Za-z0-9]{30,}|'
    r'github_pat_[A-Za-z0-9_]{20,}|'
    r'xox[baprs]-[A-Za-z0-9-]{20,}|'
    r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)'
)

try:
    tracked = run('git', 'ls-files', '-z').split('\0')
    hits = []
    for rel in tracked:
        if not rel:
            continue
        p = ROOT / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(errors='ignore')
        except OSError:
            continue
        if secret_re.search(text):
            hits.append(rel)
    if hits:
        bad('tracked-secret-scan')
        for hit in hits:
            print(hit)
    else:
        ok('tracked-secret-scan')
except Exception:
    bad('tracked-secret-scan')

for rel in ROOT.rglob('*.py'):
    if '.git' in rel.parts:
        continue
    try:
        ast.parse(rel.read_text(), filename=str(rel))
    except Exception:
        bad(f'python-ast:{rel.relative_to(ROOT)}')
        continue
ok('python-ast')

req = ROOT / 'core' / 'requirements.txt'
if req.is_file():
    unpinned = []
    for line in req.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        if not re.search(r'([=<>!~]=|@)', line):
            unpinned.append(line)
    if unpinned:
        bad('dependency-pinning')
        for item in unpinned:
            print(item)
    else:
        ok('dependency-pinning')

docker = ROOT / 'core' / 'Dockerfile'
if docker.is_file():
    text = docker.read_text(errors='replace')
    floating = re.findall(
        r'^\s*FROM\s+([^\s]+)\s*$',
        text,
        re.M | re.I,
    )
    floating_bad = [
        x for x in floating
        if '@sha256:' not in x and ':latest' in x
    ]
    if floating_bad:
        bad('container-base-pin')
    else:
        ok('container-base-pin')

try:
    status = run('git', 'status', '--porcelain')
    if status:
        ok('worktree-state-recorded')
    else:
        ok('worktree-clean')
except Exception:
    bad('worktree-state')

try:
    head = run('git', 'rev-parse', 'HEAD').strip()
    tree = run('git', 'rev-parse', 'HEAD^{tree}').strip()
    if len(head) == 40 and len(tree) == 40:
        ok('commit-tree-resolution')
    else:
        bad('commit-tree-resolution')
except Exception:
    bad('commit-tree-resolution')

hash_targets = [
    ROOT / 'core' / 'app.py',
    ROOT / 'core' / 'rf_core.py',
    ROOT / 'tools' / 'verify_supply_chain_policy.py',
    ROOT / 'tools' / 'rf_source_l4_external_verifier.py',
]

for p in hash_targets:
    if p.is_file():
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        if len(digest) == 64:
            ok(f'sha256:{p.relative_to(ROOT)}')
        else:
            bad(f'sha256:{p.relative_to(ROOT)}')
    else:
        bad(f'sha256-missing:{p.relative_to(ROOT)}')

print()
print(f'PASS={PASS}')
print(f'FAIL={FAIL}')
print(f'TOTAL={PASS + FAIL}')
print(
    'RIGHTSFRAMES_APEX_GATE=PASS'
    if FAIL == 0
    else 'RIGHTSFRAMES_APEX_GATE=FAIL'
)

sys.exit(0 if FAIL == 0 else 1)
