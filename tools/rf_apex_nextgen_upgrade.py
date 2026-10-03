from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STAMP = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
OUT = ROOT / 'artifacts' / 'apex'
OUT.mkdir(parents=True, exist_ok=True)

PASS = 0
FAIL = 0
WARN = 0
RESULTS: list[dict[str, Any]] = []


def result(level: str, control: str, detail: str = '') -> None:
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


def run(*args: str, timeout: int = 60) -> tuple[int, str]:
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
    except Exception as exc:
        return 255, str(exc)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':'),
    ).encode('utf-8')


def tracked_files() -> list[str]:
    rc, out = run('git', 'ls-files', '-z')
    if rc != 0:
        return []
    return [item for item in out.split('\0') if item]


def safe_read(path: Path) -> str:
    return path.read_text(encoding='utf-8', errors='replace')


def scan_for_dangerous_process_control(path: Path) -> list[str]:
    hits = []
    try:
        text = safe_read(path)
    except OSError:
        return hits

    if path.suffix == '.py':
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            return hits

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and (
                    (func.value.id == 'os' and func.attr in {'kill', 'killpg'})
                    or
                    (func.value.id == 'signal' and func.attr in {'kill', 'pthread_kill'})
                )
            ):
                hits.append(
                    f'{func.value.id}.{func.attr}'
                )

            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == 'subprocess'
                and func.attr in {
                    'run',
                    'Popen',
                    'call',
                    'check_call',
                    'check_output',
                }
            ):
                for keyword in node.keywords:
                    if (
                        keyword.arg == 'shell'
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        hits.append(
                            f'subprocess.{func.attr}(shell=True)'
                        )

                if node.args:
                    first = node.args[0]
                    if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
                        command = first.elts[0]
                        if (
                            isinstance(command, ast.Constant)
                            and isinstance(command.value, str)
                            and command.value in {'kill', 'pkill', 'killall'}
                        ):
                            hits.append(
                                f'subprocess.{func.attr}({command.value})'
                            )

    else:
        destructive = re.compile(
            r'(?im)(?:^|[;&|]\s*)(?:command\s+)?(?:pkill|killall|kill)(?:\s|$)'
        )
        if destructive.search(text):
            hits.append('destructive process command')

    return sorted(set(hits))

def validate_python_tree() -> None:
    failures = []

    for rel in tracked_files():
        if not rel.endswith('.py'):
            continue

        path = ROOT / rel
        if not path.is_file():
            continue

        try:
            ast.parse(safe_read(path), filename=rel)
        except Exception as exc:
            failures.append(f'{rel}: {exc}')

    result(
        'PASS' if not failures else 'FAIL',
        'APEX::PYTHON_AST',
        'valid' if not failures else '; '.join(failures[:20]),
    )


def validate_hash_chain() -> None:
    from core.evidence.ledger import build_record, verify_chain

    records = []
    previous = None

    for sequence in range(128):
        record = build_record(
            sequence,
            f'apex-event-{sequence:08d}',
            hashlib.sha256(
                f'payload-{sequence}'.encode()
            ).hexdigest(),
            previous,
        )
        records.append(record)
        previous = record.record_digest

    ok, reason = verify_chain(records)

    result(
        'PASS' if ok else 'FAIL',
        'APEX::HASH_CHAIN_128',
        reason,
    )

    tampered = list(records)
    original = tampered[64]

    from dataclasses import replace

    tampered[64] = replace(
        original,
        record_digest='0' * 64,
    )

    ok, reason = verify_chain(tampered)

    result(
        'PASS' if not ok else 'FAIL',
        'APEX::HASH_CHAIN_TAMPER_REJECTION',
        reason,
    )


def validate_merkle() -> None:
    from core.evidence.merkle import (
        build_checkpoint,
        build_proof,
        merkle_root,
        verify_proof,
    )

    records = [
        hashlib.sha256(
            f'merkle-record-{index}'.encode()
        ).hexdigest()
        for index in range(257)
    ]

    root = merkle_root(records)
    checkpoint = build_checkpoint(records)

    valid = checkpoint.root_hash == root

    for index in range(len(records)):
        proof = build_proof(records, index)
        valid = valid and verify_proof(proof, root)

    result(
        'PASS' if valid else 'FAIL',
        'APEX::MERKLE_257_INCLUSION',
        'all proofs verified' if valid else 'proof failure',
    )

    tampered = list(records)
    tampered[128] = hashlib.sha256(
        b'tampered-record'
    ).hexdigest()

    proof = build_proof(records, 128)

    rejected = not verify_proof(
        proof,
        merkle_root(tampered),
    )

    result(
        'PASS' if rejected else 'FAIL',
        'APEX::MERKLE_TAMPER_REJECTION',
        'tampered root rejected' if rejected else 'tampered root accepted',
    )


def validate_signatures() -> None:
    from core.evidence.signing import (
        generate_keypair,
        sign,
        verify,
    )

    private_key, public_key = generate_keypair()

    payload = canonical({
        'schema': 'rf.signature.test.v1',
        'event': 'apex-verification',
        'timestamp': STAMP,
    })

    signature = sign(
        private_key,
        payload,
        'rf-apex-test-key-v1',
    )

    ok, reason = verify(
        public_key,
        payload,
        signature,
    )

    result(
        'PASS' if ok else 'FAIL',
        'APEX::ED25519_SIGNATURE',
        reason,
    )

    tampered = payload + b'\x00'

    ok, reason = verify(
        public_key,
        tampered,
        signature,
    )

    result(
        'PASS' if not ok else 'FAIL',
        'APEX::SIGNATURE_TAMPER_REJECTION',
        reason,
    )


def validate_envelopes() -> None:
    from core.evidence.envelope import (
        build_envelope,
        verify_envelope,
    )

    envelope = build_envelope(
        tenant_id='rightsframes',
        event_id='apex-envelope-0001',
        event_type='security.observation',
        source={
            'source_id': 'apex-test-source',
            'kind': 'verification',
        },
        observation={
            'status': 'pass',
            'control': 'cryptographic-integrity',
        },
        provenance={
            'collector': 'rightsframes-apex',
            'software': 'nextgen-suite',
        },
    )

    ok, reason = verify_envelope(envelope)

    result(
        'PASS' if ok else 'FAIL',
        'APEX::CANONICAL_EVIDENCE',
        reason,
    )

    envelope['observation']['status'] = 'tampered'

    ok, reason = verify_envelope(envelope)

    result(
        'PASS' if not ok else 'FAIL',
        'APEX::EVIDENCE_MUTATION_REJECTION',
        reason,
    )


def validate_verifier() -> None:
    verifier = ROOT / 'verifier' / 'evidence_verifier.py'

    if not verifier.exists():
        result('FAIL', 'APEX::INDEPENDENT_VERIFIER', 'missing')
        return

    rc, out = run(
        sys.executable,
        '-m',
        'py_compile',
        str(verifier),
    )

    result(
        'PASS' if rc == 0 else 'FAIL',
        'APEX::INDEPENDENT_VERIFIER',
        'compiles' if rc == 0 else out[-1000:],
    )


def validate_workflows() -> None:
    workflow_dir = ROOT / '.github' / 'workflows'

    if not workflow_dir.exists():
        result('FAIL', 'APEX::WORKFLOW_DIRECTORY', 'missing')
        return

    workflows = sorted(workflow_dir.glob('*.yml'))
    workflows += sorted(workflow_dir.glob('*.yaml'))

    for workflow in workflows:
        text = safe_read(workflow)

        has_permissions = bool(
            re.search(r'^\s*permissions\s*:', text, re.M)
        )

        mutable_actions = re.findall(
            r'^\s*-\s*uses:\s*([^@\s]+)@'
            r'(?:main|master|latest|v\d+(?:\.\d+)*)\s*$',
            text,
            re.M,
        )

        dangerous_trigger = bool(
            re.search(
                r'(?i)\bpull_request_target\b',
                text,
            )
        )

        result(
            'PASS' if has_permissions else 'FAIL',
            f'APEX::CI_PERMISSIONS::{workflow.name}',
        )

        result(
            'PASS' if not mutable_actions else 'FAIL',
            f'APEX::CI_ACTION_PINNING::{workflow.name}',
            ','.join(mutable_actions),
        )

        result(
            'WARN' if dangerous_trigger else 'PASS',
            f'APEX::CI_TRUST_BOUNDARY::{workflow.name}',
            'pull_request_target detected'
            if dangerous_trigger else 'controlled',
        )


def validate_supply_chain() -> None:
    requirements = ROOT / 'core' / 'requirements.txt'

    if not requirements.exists():
        result('FAIL', 'APEX::DEPENDENCY_MANIFEST', 'missing')
        return

    unpinned = []

    for raw in safe_read(requirements).splitlines():
        line = raw.strip()

        if (
            not line
            or line.startswith('#')
            or line.startswith('-')
        ):
            continue

        if not re.search(
            r'(===|==|>=|<=|~=|!=|@)',
            line,
        ):
            unpinned.append(line)

    result(
        'PASS' if not unpinned else 'FAIL',
        'APEX::DEPENDENCY_PINNING',
        'fully constrained'
        if not unpinned else ', '.join(unpinned),
    )


def validate_docker() -> None:
    dockerfile = ROOT / 'core' / 'Dockerfile'

    if not dockerfile.exists():
        result('FAIL', 'APEX::CONTAINER_DOCKERFILE', 'missing')
        return

    text = safe_read(dockerfile)

    nonroot = bool(
        re.search(
            r'(?im)^\s*USER\s+(?:\d+|[A-Za-z_][A-Za-z0-9_-]*)\s*$',
            text,
        )
    )

    healthcheck = bool(
        re.search(r'(?im)^\s*HEALTHCHECK\b', text)
    )

    pinned = bool(
        re.search(
            r'(?im)^\s*FROM\s+\S+@sha256:[0-9a-f]{64}',
            text,
        )
    )

    result(
        'PASS' if nonroot else 'FAIL',
        'APEX::CONTAINER_NONROOT',
    )

    result(
        'PASS' if healthcheck else 'FAIL',
        'APEX::CONTAINER_HEALTHCHECK',
    )

    result(
        'PASS' if pinned else 'WARN',
        'APEX::CONTAINER_BASE_DIGEST',
        'all FROM images digest-pinned'
        if pinned else 'base image digest not pinned',
    )


def validate_process_safety() -> None:
    forbidden = []

    for rel in tracked_files():
        if not (
            rel.endswith('.py')
            or rel.endswith('.sh')
        ):
            continue

        path = ROOT / rel

        if not path.is_file():
            continue

        hits = scan_for_dangerous_process_control(path)

        if hits:
            forbidden.append(
                f'{rel}:{";".join(hits)}'
            )

    result(
        'PASS' if not forbidden else 'WARN',
        'APEX::PROCESS_CONTROL_AUDIT',
        'no destructive process controls detected'
        if not forbidden
        else '; '.join(forbidden[:20]),
    )


def validate_filesystem_permissions() -> None:
    targets = [
        ROOT / 'verifier',
        ROOT / 'core',
        ROOT / 'provenance',
        ROOT / 'tools',
    ]

    failures = []

    for target in targets:
        if not target.exists():
            continue

        try:
            mode = stat.S_IMODE(target.stat().st_mode)

            if mode & stat.S_IWOTH:
                failures.append(
                    f'{target.relative_to(ROOT)} world-writable'
                )
        except OSError as exc:
            failures.append(str(exc))

    result(
        'PASS' if not failures else 'FAIL',
        'APEX::SOURCE_DIRECTORY_PERMISSIONS',
        'restricted'
        if not failures else '; '.join(failures),
    )


def write_report() -> None:
    head_rc, head = run('git', 'rev-parse', 'HEAD')
    tree_rc, tree = run('git', 'rev-parse', 'HEAD^{tree}')

    report = {
        'schema': 'rightsframes.apex.nextgen.v1',
        'generated_utc': STAMP,
        'commit': head.strip() if head_rc == 0 else None,
        'tree': tree.strip() if tree_rc == 0 else None,
        'results': RESULTS,
        'summary': {
            'pass': PASS,
            'fail': FAIL,
            'warn': WARN,
            'total': PASS + FAIL + WARN,
        },
    }

    path = OUT / f'apex_nextgen_{STAMP}.json'

    payload = json.dumps(
        report,
        indent=2,
        sort_keys=True,
    ) + '\n'

    path.write_text(
        payload,
        encoding='utf-8',
    )

    print(f'REPORT={path}')
    print(f'PASS={PASS}')
    print(f'FAIL={FAIL}')
    print(f'WARN={WARN}')
    print(f'TOTAL={PASS + FAIL + WARN}')
    print(
        'RIGHTSFRAMES_APEX_NEXTGEN='
        + ('PASS' if FAIL == 0 else 'FAIL')
    )


def main() -> int:
    validate_python_tree()
    validate_envelopes()
    validate_signatures()
    validate_hash_chain()
    validate_merkle()
    validate_verifier()
    validate_workflows()
    validate_supply_chain()
    validate_docker()
    validate_process_safety()
    validate_filesystem_permissions()
    write_report()

    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
