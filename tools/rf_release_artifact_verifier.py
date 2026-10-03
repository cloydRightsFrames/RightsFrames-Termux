#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_RE = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
TAG_RE = re.compile(r'^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$')
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')


class VerificationFailure(Exception):
    pass


def fail(code: str, detail: str) -> None:
    print(f'RELEASE_ARTIFACT_VERIFICATION=FAIL')
    print(f'FAILURE_CODE={code}')
    print(f'FAILURE_DETAIL={detail}')
    raise SystemExit(1)


def run(*args: str) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            args,
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 125, '', str(exc)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open('rb') as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b''):
                digest.update(block)
    except OSError as exc:
        fail('ARTIFACT_READ_FAILED', str(exc))
    return digest.hexdigest()


def gh_json(endpoint: str) -> Any:
    rc, out, err = run('gh', 'api', endpoint)
    if rc != 0:
        fail('GITHUB_API_FAILED', err or endpoint)
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        fail('GITHUB_API_INVALID_JSON', str(exc))
    raise AssertionError


def require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        fail(code, detail)


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Fail-closed GitHub release artifact verifier'
    )
    parser.add_argument('owner')
    parser.add_argument('repo')
    parser.add_argument('tag')
    parser.add_argument('artifact')
    args = parser.parse_args()

    owner = args.owner
    repo = args.repo
    tag = args.tag
    artifact = Path(args.artifact).resolve()

    require(
        REPO_RE.fullmatch(f'{owner}/{repo}') is not None,
        'INVALID_REPOSITORY',
        f'{owner}/{repo}',
    )
    require(
        TAG_RE.fullmatch(tag) is not None,
        'INVALID_TAG',
        tag,
    )
    require(
        artifact.is_file(),
        'ARTIFACT_MISSING',
        str(artifact),
    )
    require(
        artifact.stat().st_size > 0,
        'ARTIFACT_EMPTY',
        str(artifact),
    )
    require(
        stat.S_ISREG(artifact.stat().st_mode),
        'ARTIFACT_NOT_REGULAR_FILE',
        str(artifact),
    )

    rc, _, err = run('gh', 'auth', 'status')
    require(
        rc == 0,
        'GITHUB_AUTH_REQUIRED',
        err or 'GitHub CLI authentication required',
    )

    expected_repo = f'{owner}/{repo}'
    release_endpoint = f'repos/{expected_repo}/releases/tags/{tag}'
    release = gh_json(release_endpoint)

    require(
        isinstance(release, dict),
        'RELEASE_RESPONSE_INVALID',
        'release response is not an object',
    )

    require(
        release.get('draft') is False,
        'RELEASE_DRAFT',
        'draft release is not an acceptable trust anchor',
    )

    assets = release.get('assets')
    require(
        isinstance(assets, list),
        'RELEASE_ASSETS_INVALID',
        'release assets missing or malformed',
    )

    artifact_name = artifact.name
    matches = [
        asset for asset in assets
        if isinstance(asset, dict)
        and asset.get('name') == artifact_name
    ]

    require(
        len(matches) == 1,
        'ASSET_BINDING_INVALID',
        f'expected exactly one asset named {artifact_name!r}; found {len(matches)}',
    )

    asset = matches[0]

    remote_digest = asset.get('digest')
    require(
        isinstance(remote_digest, str),
        'REMOTE_DIGEST_MISSING',
        f'GitHub release asset {artifact_name!r} has no published digest',
    )

    require(
        remote_digest.startswith('sha256:'),
        'REMOTE_DIGEST_ALGORITHM_INVALID',
        remote_digest,
    )

    expected_digest = remote_digest.removeprefix('sha256:')

    require(
        SHA256_RE.fullmatch(expected_digest) is not None,
        'REMOTE_DIGEST_INVALID',
        remote_digest,
    )

    local_digest = sha256_file(artifact)

    require(
        SHA256_RE.fullmatch(local_digest) is not None,
        'LOCAL_DIGEST_INVALID',
        local_digest,
    )

    require(
        local_digest == expected_digest,
        'ARTIFACT_DIGEST_MISMATCH',
        f'local={local_digest} remote={expected_digest}',
    )

    release_tag = release.get('tag_name')
    require(
        release_tag == tag,
        'TAG_BINDING_MISMATCH',
        f'expected={tag} actual={release_tag}',
    )

    repo_url = release.get('html_url', '')
    normalized_release_url = (
        repo_url.strip().rstrip('/').lower()
        if isinstance(repo_url, str)
        else ''
    )
    normalized_expected_release_prefix = (
        f'https://github.com/{expected_repo}/releases/'.lower()
    )
    require(
        normalized_release_url.startswith(
            normalized_expected_release_prefix
        ),
        'RELEASE_REPOSITORY_BINDING_FAILED',
        str(repo_url),
    )

    asset_id = asset.get('id')
    require(
        isinstance(asset_id, int) and asset_id > 0,
        'ASSET_ID_INVALID',
        str(asset_id),
    )

    asset_state = asset.get('state')
    require(
        asset_state == 'uploaded',
        'ASSET_STATE_INVALID',
        str(asset_state),
    )

    content_type = asset.get('content_type')
    require(
        isinstance(content_type, str) and content_type,
        'ASSET_CONTENT_TYPE_MISSING',
        artifact_name,
    )

    size = asset.get('size')
    require(
        isinstance(size, int) and size > 0,
        'REMOTE_ASSET_SIZE_INVALID',
        str(size),
    )

    local_size = artifact.stat().st_size
    require(
        local_size == size,
        'ARTIFACT_SIZE_MISMATCH',
        f'local={local_size} remote={size}',
    )

    output = {
        'schema': 'rightsframes.release-artifact-verification.v1',
        'repository': expected_repo,
        'tag': tag,
        'artifact': artifact_name,
        'asset_id': asset_id,
        'asset_state': asset_state,
        'content_type': content_type,
        'size': local_size,
        'algorithm': 'sha256',
        'digest': local_digest,
        'remote_digest': f'sha256:{expected_digest}',
        'release_url': repo_url,
    }

    print(json.dumps(output, sort_keys=True))
    print('ARTIFACT_REPOSITORY_BINDING=PASS')
    print('ARTIFACT_TAG_BINDING=PASS')
    print('ARTIFACT_ASSET_BINDING=PASS')
    print('ARTIFACT_SIZE_BINDING=PASS')
    print('ARTIFACT_SHA256_BINDING=PASS')
    print('RELEASE_ARTIFACT_VERIFICATION=PASS')
    return 0


if __name__ == '__main__':
    main()
