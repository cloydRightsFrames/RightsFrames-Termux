#!/usr/bin/env python3
"""CycloneDX SBOM for a RightsFrames release.

generate  Build the SBOM of the hash-locked runtime dependencies
          (core/requirements.txt) with cyclonedx-py, make it reproducible
          (fixed timestamp from SOURCE_DATE_EPOCH, a serial number derived
          from repository + commit + version), validate it against the
          CycloneDX 1.6 JSON schema and check it is complete.
          Needs the pinned tool set in .github/scripts/requirements-sbom.txt.

verify    Check an SBOM against the lock file with the standard library
          only: every locked package appears exactly once, with the same
          version and exactly the same SHA-256 distribution hashes, and
          nothing else is listed. Anyone can run this on a downloaded
          release SBOM.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

PRODUCT = 'RightsFrames-Termux'
SPEC_VERSION = '1.6'
_REQ = re.compile(r'^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)')
_HASH = re.compile(r'--hash=sha256:([0-9a-f]{64})')
_SERIAL = re.compile(r'urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')


class SBOMError(Exception):
    pass


def normalize(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def parse_lock(text: str) -> dict[str, tuple[str, frozenset[str]]]:
    """Map normalized package name -> (version, SHA-256 hashes) from a uv/pip-compile lock."""
    logical: list[str] = []
    buf = ''
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].rstrip() if raw.lstrip().startswith('#') else raw.rstrip()
        if line.endswith('\\'):
            buf += line[:-1] + ' '
            continue
        logical.append(buf + line)
        buf = ''
    if buf:
        logical.append(buf)
    packages: dict[str, tuple[str, frozenset[str]]] = {}
    for line in logical:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        match = _REQ.match(stripped)
        if not match:
            raise SBOMError(f'unpinned or unsupported requirement: {stripped[:80]}')
        name = normalize(match.group(1))
        hashes = frozenset(_HASH.findall(stripped))
        if not hashes:
            raise SBOMError(f'requirement without hashes: {name}')
        if name in packages:
            raise SBOMError(f'duplicate requirement: {name}')
        packages[name] = (match.group(2), hashes)
    if not packages:
        raise SBOMError('lock file lists no packages')
    return packages


def _component_hashes(component: dict) -> frozenset[str]:
    found: set[str] = set()
    for item in component.get('hashes', []) or []:
        if item.get('alg') == 'SHA-256':
            found.add(str(item.get('content', '')).lower())
    for ref in component.get('externalReferences', []) or []:
        for item in ref.get('hashes', []) or []:
            if item.get('alg') == 'SHA-256':
                found.add(str(item.get('content', '')).lower())
    return frozenset(found)


def verify_sbom(bom: dict, lock: dict[str, tuple[str, frozenset[str]]],
                version: str | None = None) -> int:
    """Raise SBOMError unless `bom` describes exactly the packages in `lock`; return the count."""
    if bom.get('bomFormat') != 'CycloneDX':
        raise SBOMError('not a CycloneDX document')
    if bom.get('specVersion') != SPEC_VERSION:
        raise SBOMError(f'specVersion is {bom.get("specVersion")!r}, expected {SPEC_VERSION}')
    if not _SERIAL.fullmatch(str(bom.get('serialNumber', ''))):
        raise SBOMError('serialNumber missing or not an urn:uuid')
    root = (bom.get('metadata') or {}).get('component') or {}
    if root.get('name') != PRODUCT:
        raise SBOMError(f'root component is {root.get("name")!r}, expected {PRODUCT}')
    if version is not None and root.get('version') != version:
        raise SBOMError(f'root version is {root.get("version")!r}, expected {version!r}')
    seen: dict[str, tuple[str, frozenset[str]]] = {}
    for component in bom.get('components', []) or []:
        name = normalize(str(component.get('name', '')))
        if not name:
            raise SBOMError('component without a name')
        if name in seen:
            raise SBOMError(f'component listed twice: {name}')
        comp_version = str(component.get('version', ''))
        purl = str(component.get('purl', ''))
        if not purl.startswith(f'pkg:pypi/{name}@{comp_version}'):
            raise SBOMError(f'purl for {name} is {purl!r}')
        seen[name] = (comp_version, _component_hashes(component))
    missing = sorted(set(lock) - set(seen))
    extra = sorted(set(seen) - set(lock))
    if missing:
        raise SBOMError('missing from SBOM: ' + ', '.join(missing))
    if extra:
        raise SBOMError('not in the lock file: ' + ', '.join(extra))
    for name, (lock_version, lock_hashes) in sorted(lock.items()):
        sbom_version, sbom_hashes = seen[name]
        if sbom_version != lock_version:
            raise SBOMError(f'{name}: SBOM version {sbom_version}, lock version {lock_version}')
        if sbom_hashes != lock_hashes:
            raise SBOMError(f'{name}: SBOM hashes differ from the lock file')
    return len(seen)


def generate(requirements: Path, version: str, repository: str, commit: str,
             ref_name: str, epoch: int) -> str:
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise SBOMError('commit must be a full lowercase SHA-1')
    if not re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9._-]+', repository):
        raise SBOMError('repository must be owner/name')
    lock = parse_lock(requirements.read_text(encoding='utf-8'))
    with tempfile.TemporaryDirectory() as tmp:
        pyproject = Path(tmp) / 'pyproject.toml'
        pyproject.write_text(
            '[project]\n'
            f'name = {json.dumps(PRODUCT)}\n'
            f'version = {json.dumps(version)}\n'
            'description = "Tamper-evident governance ledger: runtime dependencies of the API service"\n',
            encoding='utf-8',
        )
        raw = Path(tmp) / 'raw.cdx.json'
        env = dict(os.environ, SOURCE_DATE_EPOCH=str(int(epoch)))
        subprocess.run(
            [sys.executable, '-m', 'cyclonedx_py', 'requirements',
             '--pyproject', str(pyproject), '--mc-type', 'application',
             '--sv', SPEC_VERSION, '--output-reproducible', '--validate',
             '-o', str(raw), str(requirements)],
            check=True, env=env,
        )
        bom = json.loads(raw.read_text(encoding='utf-8'))
    bom['serialNumber'] = 'urn:uuid:' + str(uuid.uuid5(
        uuid.NAMESPACE_URL, f'https://github.com/{repository}/commit/{commit}#sbom/{version}'))
    root = bom['metadata']['component']
    root['purl'] = f'pkg:github/{repository.lower()}@{ref_name}'
    root['externalReferences'] = [{'type': 'vcs', 'url': f'https://github.com/{repository}'}]
    text = json.dumps(bom, indent=2, ensure_ascii=False) + '\n'
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(text)
    if error is not None:
        raise SBOMError(f'CycloneDX schema validation failed: {error}')
    verify_sbom(json.loads(text), lock, version)
    return text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description='CycloneDX SBOM for a RightsFrames release.')
    sub = ap.add_subparsers(dest='command', required=True)
    g = sub.add_parser('generate')
    g.add_argument('--requirements', type=Path, default=Path('core/requirements.txt'))
    g.add_argument('--version', required=True)
    g.add_argument('--repository', required=True)
    g.add_argument('--commit', required=True)
    g.add_argument('--ref-name', required=True)
    g.add_argument('--epoch', type=int, required=True)
    g.add_argument('--out', type=Path, required=True)
    v = sub.add_parser('verify')
    v.add_argument('--sbom', type=Path, required=True)
    v.add_argument('--requirements', type=Path, default=Path('core/requirements.txt'))
    v.add_argument('--version')
    args = ap.parse_args(argv)
    try:
        if args.command == 'generate':
            text = generate(args.requirements, args.version, args.repository,
                            args.commit, args.ref_name, args.epoch)
            args.out.write_text(text, encoding='utf-8')
            count = len(json.loads(text)['components'])
            print(f'SBOM_GENERATED={args.out} components={count}')
            return 0
        bom = json.loads(args.sbom.read_text(encoding='utf-8'))
        count = verify_sbom(bom, parse_lock(args.requirements.read_text(encoding='utf-8')), args.version)
        print(f'SBOM_VERIFICATION=PASS components={count}')
        return 0
    except (SBOMError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f'SBOM_VERIFICATION=FAIL {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
