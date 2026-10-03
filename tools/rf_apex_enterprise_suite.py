#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / 'artifacts' / 'apex'
REPORT_DIR.mkdir(parents=True, exist_ok=True)

STAMP = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
REPORT = REPORT_DIR / f'apex_enterprise_{STAMP}.json'
MANIFEST = REPORT_DIR / f'apex_manifest_{STAMP}.json'

PASS = 0
FAIL = 0
WARN = 0
RESULTS = []

def result(level, control, detail=''):
    global PASS, FAIL, WARN
    if level == 'PASS':
        PASS += 1
    elif level == 'FAIL':
        FAIL += 1
    else:
        WARN += 1
    item = {
        'level': level,
        'control': control,
        'detail': detail,
    }
    RESULTS.append(item)
    print(f'[{level}] {control}' + (f' :: {detail}' if detail else ''))

def run(*args, timeout=30):
    try:
        p = subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout
    except Exception as e:
        return 255, str(e)

def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def tracked_files():
    rc, out = run('git', 'ls-files', '-z')
    if rc != 0:
        return []
    return [x for x in out.split('\0') if x]

def workflow_files():
    p = ROOT / '.github' / 'workflows'
    return sorted(p.glob('*.yml')) + sorted(p.glob('*.yaml'))

def scan_secrets():
    patterns = [
        r'AKIA[0-9A-Z]{16}',
        r'ASIA[0-9A-Z]{16}',
        r'ghp_[A-Za-z0-9]{30,}',
        r'github_pat_[A-Za-z0-9_]{20,}',
        r'xox[baprs]-[A-Za-z0-9-]{20,}',
        r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----',
        r'(?i)password\s*[:=]\s*[^\s]{12,}',
        r'(?i)secret\s*[:=]\s*[^\s]{12,}',
        r'(?i)api[_-]?key\s*[:=]\s*[^\s]{16,}',
    ]
    compiled = [re.compile(x) for x in patterns]
    hits = []
    for rel in tracked_files():
        p = ROOT / rel
        if not p.is_file() or '.git' in p.parts:
            continue
        try:
            text = p.read_text(errors='ignore')
        except Exception:
            continue
        for rx in compiled:
            if rx.search(text):
                hits.append(rel)
                break
    return sorted(set(hits))

print('=== RIGHTSFRAMES APEX ENTERPRISE PRODUCTION SUITE ===')
print(f'UTC={STAMP}')
print(f'ROOT={ROOT}')

required = [
    '.git',
    '.github/workflows/verify.yml',
    '.github/workflows/provenance-gate.yml',
    '.github/workflows/continuous-release-integrity.yml',
    '.github/workflows/slsa-build-l3.yml',
    'core/requirements.txt',
    'core/Dockerfile',
    'core/app.py',
    'core/rf_core.py',
    'tools/verify_supply_chain_policy.py',
    'tools/rf_source_l4_external_verifier.py',
    'provenance/verify_release.sh',
    'provenance/reproducibility_verify.sh',
    'provenance/adversarial_verify.sh',
]

for rel in required:
    if (ROOT / rel).exists():
        result('PASS', f'REQUIRED::{rel}')
    else:
        result('FAIL', f'REQUIRED::{rel}', 'missing')

rc, out = run('git', 'fsck', '--full', '--no-reflogs', timeout=120)
if rc == 0 and not re.search(r'^(error|fatal|missing)\b', out, re.M):
    result('PASS', 'GIT::FULL_FSCK')
else:
    result('FAIL', 'GIT::FULL_FSCK', out[-2000:])

rc, head = run('git', 'rev-parse', 'HEAD')
rc2, tree = run('git', 'rev-parse', 'HEAD^{tree}')
if rc == 0 and rc2 == 0 and len(head.strip()) == 40 and len(tree.strip()) == 40:
    result('PASS', 'GIT::HEAD_TREE_RESOLUTION')
else:
    result('FAIL', 'GIT::HEAD_TREE_RESOLUTION')

rc, status = run('git', 'status', '--porcelain=v1')
result(
    'PASS' if rc == 0 else 'FAIL',
    'GIT::WORKTREE_STATE',
    'clean' if not status.strip() else 'changes-present',
)

rc, branch = run('git', 'branch', '--show-current')
result(
    'PASS' if rc == 0 and branch.strip() == 'main' else 'WARN',
    'GIT::PRIMARY_BRANCH',
    branch.strip(),
)

rc, origin = run('git', 'rev-parse', 'origin/main')
if rc == 0:
    result(
        'PASS' if origin.strip() == head.strip() else 'WARN',
        'GIT::REMOTE_ALIGNMENT',
        'HEAD=origin/main' if origin.strip() == head.strip() else 'HEAD differs from origin/main',
    )
else:
    result('WARN', 'GIT::REMOTE_ALIGNMENT', 'origin/main unavailable')

rc, refs = run('git', 'show-ref')
result('PASS' if rc == 0 and refs.strip() else 'FAIL', 'GIT::REF_DATABASE')

for wf in workflow_files():
    text = wf.read_text(errors='replace')

    if re.search(r'^\s*permissions\s*:', text, re.M):
        result('PASS', f'CI::PERMISSIONS::{wf.name}')
    else:
        result('FAIL', f'CI::PERMISSIONS::{wf.name}')

    mutable = re.findall(
        r'^\s*-\s*uses:\s*([^@\s]+)@(main|master|latest|v\d+(?:\.\d+)*)\s*$',
        text,
        re.M,
    )
    if mutable:
        result('FAIL', f'CI::ACTION_PINNING::{wf.name}', ','.join(x[0] for x in mutable))
    else:
        result('PASS', f'CI::ACTION_PINNING::{wf.name}')

    if re.search(r'(?i)\bpull_request_target\b', text):
        result('WARN', f'CI::PR_TRUST_BOUNDARY::{wf.name}', 'pull_request_target requires review')
    else:
        result('PASS', f'CI::PR_TRUST_BOUNDARY::{wf.name}')

    if re.search(r'(?i)\bcontents:\s*write\b', text):
        result('WARN', f'CI::WRITE_SCOPE::{wf.name}', 'contents write permission present')
    else:
        result('PASS', f'CI::WRITE_SCOPE::{wf.name}')

    if re.search(r'(?i)\bsecrets\.', text):
        result('PASS', f'CI::SECRET_USAGE::{wf.name}')
    else:
        result('PASS', f'CI::SECRET_USAGE::{wf.name}', 'none detected')

requirements = ROOT / 'core' / 'requirements.txt'
if requirements.exists():
    unpinned = []
    for raw in requirements.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        if not re.search(r'(===|==|>=|<=|~=|!=|@)', line):
            unpinned.append(line)
    if unpinned:
        result('FAIL', 'SUPPLY_CHAIN::PYTHON_PINNING', ', '.join(unpinned))
    else:
        result('PASS', 'SUPPLY_CHAIN::PYTHON_PINNING')

    result(
        'PASS' if re.search(r'(?i)\b(fastapi|uvicorn|cryptography)\b', requirements.read_text())
        else 'WARN',
        'SUPPLY_CHAIN::CORE_RUNTIME_DECLARATIONS',
    )

docker = ROOT / 'core' / 'Dockerfile'
if docker.exists():
    dtext = docker.read_text(errors='replace')
    bases = re.findall(r'^\s*FROM\s+([^\s]+)', dtext, re.M | re.I)
    floating = [x for x in bases if '@sha256:' not in x]
    if floating:
        result('WARN', 'CONTAINER::BASE_DIGEST', ', '.join(floating))
    else:
        result('PASS', 'CONTAINER::BASE_DIGEST')

    if re.search(r'(?i)USER\s+\d+|USER\s+[A-Za-z_][A-Za-z0-9_-]*', dtext):
        result('PASS', 'CONTAINER::NONROOT_USER')
    else:
        result('WARN', 'CONTAINER::NONROOT_USER')

    if re.search(r'(?i)\bHEALTHCHECK\b', dtext):
        result('PASS', 'CONTAINER::HEALTHCHECK')
    else:
        result('WARN', 'CONTAINER::HEALTHCHECK')

secret_hits = scan_secrets()
if secret_hits:
    result('FAIL', 'SECRETS::TRACKED_SOURCE_SCAN', '; '.join(secret_hits))
else:
    result('PASS', 'SECRETS::TRACKED_SOURCE_SCAN')

python_failures = []
for rel in tracked_files():
    if not rel.endswith('.py'):
        continue
    p = ROOT / rel
    if not p.exists():
        continue
    try:
        ast.parse(p.read_text(errors='strict'), filename=rel)
    except Exception as e:
        python_failures.append(f'{rel}: {e}')

if python_failures:
    result('FAIL', 'CODE::PYTHON_AST', '; '.join(python_failures[:10]))
else:
    result('PASS', 'CODE::PYTHON_AST')

rc, out = run(
    sys.executable,
    '-m',
    'compileall',
    '-q',
    str(ROOT / 'core'),
    str(ROOT / 'tools'),
    str(ROOT / 'provenance'),
    timeout=120,
)
result('PASS' if rc == 0 else 'FAIL', 'CODE::PYTHON_COMPILE')

tests = ROOT / 'tests'
if tests.exists():
    rc, out = run(sys.executable, '-m', 'pytest', '-q', str(tests), timeout=180)
    result('PASS' if rc == 0 else 'FAIL', 'TEST::PYTEST', out[-2000:])
else:
    result('WARN', 'TEST::PYTEST', 'tests directory missing')

tracked = tracked_files()
manifest = {}

for rel in tracked:
    p = ROOT / rel
    if not p.is_file():
        continue
    try:
        st = p.stat()
        manifest[rel] = {
            'sha256': sha256(p),
            'bytes': st.st_size,
            'mode': oct(stat.S_IMODE(st.st_mode)),
        }
    except OSError:
        result('WARN', f'MANIFEST::{rel}', 'unreadable')

MANIFEST.write_text(
    json.dumps(
        {
            'schema': 'rightsframes.apex.manifest.v1',
            'generated_utc': STAMP,
            'commit': head.strip(),
            'tree': tree.strip(),
            'files': manifest,
        },
        indent=2,
        sort_keys=True,
    ) + '\n'
)

result('PASS', 'INTEGRITY::SOURCE_MANIFEST', str(MANIFEST))

for rel in [
    'tools/verify_supply_chain_policy.py',
    'tools/rf_source_l4_external_verifier.py',
    'provenance/verify_release.sh',
    'provenance/reproducibility_verify.sh',
    'provenance/adversarial_verify.sh',
]:
    p = ROOT / rel
    if not p.exists():
        continue
    mode = stat.S_IMODE(p.stat().st_mode)
    if rel.endswith('.sh') and not (mode & stat.S_IXUSR):
        result('WARN', f'FILEMODE::{rel}', 'script not executable')
    else:
        result('PASS', f'FILEMODE::{rel}')

for command in [
    'git',
    'python3',
    'pytest',
    'openssl',
    'curl',
]:
    result(
        'PASS' if shutil.which(command) else 'WARN',
        f'TOOLING::{command}',
        shutil.which(command) or 'not-installed',
    )

report = {
    'schema': 'rightsframes.apex.enterprise.v1',
    'generated_utc': STAMP,
    'repository': str(ROOT),
    'commit': head.strip(),
    'tree': tree.strip(),
    'pass': PASS,
    'fail': FAIL,
    'warn': WARN,
    'total': PASS + FAIL + WARN,
    'results': RESULTS,
    'manifest': str(MANIFEST),
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')

print()
print('=== RIGHTSFRAMES APEX ENTERPRISE RESULT ===')
print(f'PASS={PASS}')
print(f'FAIL={FAIL}')
print(f'WARN={WARN}')
print(f'TOTAL={PASS + FAIL + WARN}')
print(f'REPORT={REPORT}')
print(f'MANIFEST={MANIFEST}')
print(
    'RIGHTSFRAMES_APEX_ENTERPRISE_GATE=PASS'
    if FAIL == 0
    else 'RIGHTSFRAMES_APEX_ENTERPRISE_GATE=FAIL'
)

sys.exit(0 if FAIL == 0 else 1)
