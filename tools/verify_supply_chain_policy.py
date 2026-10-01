#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / '.github' / 'workflows'
required = {
    'provenance-gate.yml': [
        'slsa3-build:',
        'attestations: write',
        'artifact-metadata: write',
        'gh attestation verify',
        '--deny-self-hosted-runners',
        'reproducibility:',
        'release-policy:',
    ],
    'slsa-build-l3.yml': [
        'workflow_call:',
        'id-token: write',
        'attestations: write',
        'artifact-metadata: write',
        'actions/attest@v4',
        'git archive',
        'gzip -n',
    ],
    'continuous-release-integrity.yml': [
        'gh attestation verify',
        '--deny-self-hosted-runners',
        'slsa-build-l3.yml',
    ],
}

for name, needles in required.items():
    p = WF / name
    if not p.is_file():
        raise SystemExit(f'MISSING_WORKFLOW={name}')
    s = p.read_text(encoding='utf-8')
    for needle in needles:
        if needle not in s:
            raise SystemExit(f'MISSING_CONTROL={name}:{needle}')

for p in sorted(WF.glob('*.yml')):
    s = p.read_text(encoding='utf-8')
    if 'pull_request_target:' in s:
        raise SystemExit(f'DANGEROUS_TRIGGER={p.name}:pull_request_target')
    if 'self-hosted' in s.lower() and '--deny-self-hosted-runners' not in s:
        raise SystemExit(f'UNTRUSTED_RUNNER_REFERENCE={p.name}')
    if re.search(r'uses:\s*[^\s@]+@main(?:\s|$)', s):
        raise SystemExit(f'MUTABLE_ACTION_REF={p.name}:main')

print('RIGHTSFRAMES_ZERO_TRUST_POLICY=PASS')
print('SLSA_BUILD_L3_CONTROLS=PASS')
print('EXTERNAL_ATTESTATION_VERIFICATION=PASS')
print('REPRODUCIBILITY_CONTROLS=PASS')
print('FAIL_CLOSED_RELEASE_POLICY=PASS')
print('DANGEROUS_TRIGGER_SCAN=PASS')
