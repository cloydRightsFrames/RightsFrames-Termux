#!/usr/bin/env python3
"""Fail-closed supply-chain policy for this repository's GitHub workflows.

Run from anywhere: ``python3 tools/verify_supply_chain_policy.py [--root DIR]``.
Exits non-zero with ``<VIOLATION>=<file>:<detail>`` on the first violation.
Standard library only, so it runs before any dependency is installed.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

REQUIRED = {
    'provenance-gate.yml': [
        'slsa3-build:',
        'attestations: write',
        'artifact-metadata: write',
        'gh attestation verify',
        '--deny-self-hosted-runners',
        'reproducibility:',
        'release-policy:',
        'sbom:',
        'predicate-type: https://cyclonedx.org/bom',
        '--predicate-type https://cyclonedx.org/bom',
    ],
    'slsa-build-l3.yml': [
        'workflow_call:',
        'id-token: write',
        'attestations: write',
        'artifact-metadata: write',
        'git archive',
        'gzip -n',
    ],
    'continuous-release-integrity.yml': [
        'gh attestation download',
        'gh attestation verify',
        '--bundle',
        '--custom-trusted-root',
        '--signer-workflow "${REPO}/.github/workflows/provenance-gate.yml"',
        '--deny-self-hosted-runners',
    ],
}

_SHA = re.compile(r'[0-9a-fA-F]{40}')
_DIGEST = re.compile(r'sha256:[0-9a-fA-F]{64}')
_USES = re.compile(r'^\s*(?:-\s+)?uses:\s*(\S+)', re.MULTILINE)


class Violation(Exception):
    pass


def _fail(code: str, where: str) -> None:
    raise Violation(f'{code}={where}')


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(' '))


def _immutable(ref: str) -> bool:
    ref = ref.strip('\'"')
    if ref.startswith('./'):
        return '@' not in ref
    if ref.startswith('docker://'):
        _, sep, digest = ref.rpartition('@')
        return bool(sep) and bool(_DIGEST.fullmatch(digest))
    action, sep, version = ref.partition('@')
    return bool(action) and bool(sep) and bool(_SHA.fullmatch(version))


def _jobs(text: str) -> list[tuple[str, list[str]]]:
    """Return (job id, body lines) for every job under the top-level `jobs:` key."""
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if re.fullmatch(r'jobs:\s*', line))
    except StopIteration:
        return []
    jobs: list[tuple[str, list[str]]] = []
    job_indent = None
    current: tuple[str, list[str]] | None = None
    for line in lines[start + 1:]:
        if not line.strip() or line.lstrip().startswith('#'):
            if current:
                current[1].append(line)
            continue
        indent = _indent(line)
        if indent == 0:
            break
        if job_indent is None:
            job_indent = indent
        if indent == job_indent:
            match = re.fullmatch(r'\s*([A-Za-z0-9_-]+):\s*(#.*)?', line)
            if not match:
                _fail('UNPARSEABLE_JOB', line.strip())
            current = (match.group(1), [])
            jobs.append(current)
        elif current is not None:
            current[1].append(line)
    return jobs


def _job_has(body: list[str], key: str) -> bool:
    lines = [line for line in body if line.strip() and not line.lstrip().startswith('#')]
    if not lines:
        return False
    child = _indent(lines[0])
    return any(_indent(line) == child and line.lstrip().startswith(key + ':') for line in lines)


def _logical_lines(text: str) -> list[str]:
    out: list[str] = []
    buf = ''
    for line in text.splitlines():
        if line.rstrip().endswith('\\'):
            buf += line.rstrip()[:-1] + ' '
            continue
        out.append(buf + line)
        buf = ''
    if buf:
        out.append(buf)
    return out


def check(root: Path) -> list[str]:
    wf_dir = root / '.github' / 'workflows'
    for name, needles in REQUIRED.items():
        p = wf_dir / name
        if not p.is_file():
            _fail('MISSING_WORKFLOW', name)
        s = p.read_text(encoding='utf-8')
        for needle in needles:
            if needle not in s:
                _fail('MISSING_CONTROL', f'{name}:{needle}')

    files = sorted(list(wf_dir.glob('*.yml')) + list(wf_dir.glob('*.yaml')))
    if not files:
        _fail('MISSING_WORKFLOW', '.github/workflows')
    for p in files:
        s = p.read_text(encoding='utf-8')
        if 'pull_request_target:' in s:
            _fail('DANGEROUS_TRIGGER', f'{p.name}:pull_request_target')
        if 'self-hosted' in s.lower() and '--deny-self-hosted-runners' not in s:
            _fail('UNTRUSTED_RUNNER_REFERENCE', p.name)
        if re.search(r'uses:\s*[^\s@]+@main(?:\s|$)', s):
            _fail('MUTABLE_ACTION_REF', f'{p.name}:main')
        for ref in _USES.findall(s):
            if not _immutable(ref):
                code = 'NON_IMMUTABLE_ATTEST_REF' if ref.startswith('actions/attest@') else 'NON_IMMUTABLE_ACTION_REF'
                _fail(code, f'{p.name}:{ref}')
        if not re.search(r'^permissions:', s, re.MULTILINE):
            _fail('MISSING_TOP_LEVEL_PERMISSIONS', p.name)
        for job, body in _jobs(s):
            if _job_has(body, 'runs-on') and not _job_has(body, 'timeout-minutes'):
                _fail('MISSING_JOB_TIMEOUT', f'{p.name}:{job}')
        for line in _logical_lines(s):
            if re.search(r'\bpip3?\s+install\b', line) and '--require-hashes' not in line:
                _fail('UNHASHED_PIP_INSTALL', f'{p.name}:{line.strip()}')

    return [
        'RIGHTSFRAMES_ZERO_TRUST_POLICY=PASS',
        'SLSA_BUILD_L3_CONTROLS=PASS',
        'EXTERNAL_ATTESTATION_VERIFICATION=PASS',
        'REPRODUCIBILITY_CONTROLS=PASS',
        'FAIL_CLOSED_RELEASE_POLICY=PASS',
        'DANGEROUS_TRIGGER_SCAN=PASS',
        'ACTION_PINNING=PASS',
        'HASH_LOCKED_INSTALLS=PASS',
        'LEAST_PRIVILEGE_DEFAULTS=PASS',
        'JOB_TIMEOUTS=PASS',
        'RELEASE_SBOM_CONTROLS=PASS',
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args(argv)
    try:
        lines = check(args.root.resolve())
    except Violation as exc:
        print(str(exc))
        return 1
    print('\n'.join(lines))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
