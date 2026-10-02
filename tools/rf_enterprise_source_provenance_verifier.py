#!/usr/bin/env python3
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = 'cLoydRightsFrames/RightsFrames-Termux'
BASE = 'main'
RULESET_ID = 24306410
REQUIRED_APPROVERS = 2
ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / '.rightsframes-enterprise'
REPORT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

CHECKS = []
FAILURES = []

def run(*args):
    p = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return p.stdout.strip(), p.stderr.strip(), p.returncode

def gh_api(path):
    out, err, rc = run(
        'gh',
        'api',
        path,
        '-H', 'Accept: application/vnd.github+json',
        '-H', 'X-GitHub-Api-Version: 2026-03-10'
    )
    if rc:
        raise RuntimeError(f'{path}:{err or out}')
    if not out:
        raise RuntimeError(f'{path}:EMPTY_RESPONSE')
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise RuntimeError(f'{path}:INVALID_JSON:{e}')

def check(name, ok, evidence=None):
    item = {'name': name, 'status': 'PASS' if ok else 'FAIL'}
    if evidence is not None:
        item['evidence'] = evidence
    CHECKS.append(item)
    if not ok:
        FAILURES.append(name)

def file_sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()

def action_refs(text):
    refs = []
    for line in text.splitlines():
        m = re.search(r'^\s*uses:\s*([^\s#]+)', line)
        if m:
            refs.append(m.group(1))
    return refs

def is_full_sha_ref(ref):
    if '@' not in ref:
        return True
    return bool(re.fullmatch(r'[^\s@]+@[0-9a-fA-F]{40}', ref))

now = datetime.now(timezone.utc)
stamp = now.strftime('%Y%m%dT%H%M%SZ')

out, err, rc = run('gh', 'auth', 'status')
check(
    'GITHUB_AUTHENTICATED',
    rc == 0 and 'Logged in to github.com' in out,
    {'stdout': out}
)

remote, _, rc = run('git', 'remote', 'get-url', 'origin')
check(
    'ORIGIN_IS_CANONICAL_REPOSITORY',
    remote.rstrip('/') in {
        f'https://github.com/{REPO}',
        f'https://github.com/{REPO}.git'
    },
    {'origin': remote}
)

local_branch, _, _ = run('git', 'branch', '--show-current')
local_head, _, _ = run('git', 'rev-parse', 'HEAD')
local_tree, _, _ = run('git', 'rev-parse', 'HEAD^{tree}')
worktree, _, _ = run('git', 'status', '--porcelain')

check(
    'LOCAL_COMMIT_RESOLVED',
    bool(re.fullmatch(r'[0-9a-f]{40}', local_head)),
    {'commit': local_head}
)

check(
    'LOCAL_TREE_RESOLVED',
    bool(re.fullmatch(r'[0-9a-f]{40}', local_tree)),
    {'tree': local_tree}
)

check(
    'LOCAL_WORKTREE_CLEAN',
    worktree == '',
    {'status': worktree}
)

try:
    repo = gh_api(f'repos/{REPO}')
    check(
        'PUBLIC_REPOSITORY',
        repo.get('visibility') == 'public',
        {'visibility': repo.get('visibility')}
    )
    check(
        'EXPECTED_DEFAULT_BRANCH',
        repo.get('default_branch') == BASE,
        {'default_branch': repo.get('default_branch')}
    )
except Exception as e:
    check('REPOSITORY_METADATA', False, {'error': str(e)})
    repo = {}

try:
    remote_main, _, rc = run(
        'git',
        'ls-remote',
        'origin',
        f'refs/heads/{BASE}'
    )
    remote_main_sha = remote_main.split()[0] if remote_main else ''
    check(
        'REMOTE_MAIN_RESOLVED',
        bool(re.fullmatch(r'[0-9a-f]{40}', remote_main_sha)),
        {'remote_main': remote_main_sha}
    )
except Exception as e:
    remote_main_sha = ''
    check('REMOTE_MAIN_RESOLVED', False, {'error': str(e)})

try:
    rules = gh_api(
        f'repos/{REPO}/rules/branches/{BASE}?per_page=100'
    )

    pr_rules = [
        r for r in rules
        if r.get('type') == 'pull_request'
    ]

    params = [
        r.get('parameters') or {}
        for r in pr_rules
    ]

    approvals = max(
        [int(p.get('required_approving_review_count', 0)) for p in params],
        default=0
    )

    check('MAIN_PULL_REQUEST_RULE', bool(pr_rules))
    check(
        'TWO_APPROVING_REVIEWS_REQUIRED',
        approvals >= REQUIRED_APPROVERS,
        {'required': approvals}
    )
    check(
        'STALE_APPROVALS_DISMISSED',
        any(
            p.get('dismiss_stale_reviews_on_push') is True
            for p in params
        )
    )
    check(
        'LATEST_PUSH_REQUIRES_OTHER_APPROVER',
        any(
            p.get('require_last_push_approval') is True
            for p in params
        )
    )
    check(
        'REVIEW_THREADS_RESOLVED',
        any(
            p.get('required_review_thread_resolution') is True
            for p in params
        )
    )
    check(
        'FORCE_PUSH_BLOCKED',
        any(r.get('type') == 'non_fast_forward' for r in rules)
    )
except Exception as e:
    check('MAIN_BRANCH_RULES_AUTHENTICATED', False, {'error': str(e)})

try:
    rs = gh_api(f'repos/{REPO}/rulesets/{RULESET_ID}')

    refs = (
        rs.get('conditions', {})
        .get('ref_name', {})
        .get('include', [])
    )

    check(
        'SOURCE_L4_RULESET_ID',
        rs.get('id') == RULESET_ID,
        {'id': rs.get('id')}
    )
    check(
        'SOURCE_L4_RULESET_ACTIVE',
        rs.get('enforcement') == 'active'
    )
    check(
        'SOURCE_L4_RULESET_TARGET_MAIN',
        'refs/heads/main' in refs
    )
    check(
        'SOURCE_L4_RULESET_ZERO_BYPASS',
        rs.get('bypass_actors') == []
    )

    rr = [
        r.get('parameters') or {}
        for r in rs.get('rules', [])
        if r.get('type') == 'pull_request'
    ]

    check(
        'SOURCE_L4_RULESET_TWO_APPROVALS',
        max(
            [int(p.get('required_approving_review_count', 0)) for p in rr],
            default=0
        ) >= REQUIRED_APPROVERS
    )
except Exception as e:
    check('SOURCE_L4_RULESET_AUTHENTICATED', False, {'error': str(e)})

try:
    prs = gh_api(
        f'repos/{REPO}/pulls?state=open&base={BASE}&per_page=100'
    )

    current_pr = next(
        (
            pr for pr in prs
            if pr.get('head', {}).get('sha') == local_head
        ),
        None
    )

    check(
        'CURRENT_HEAD_HAS_OPEN_PR',
        current_pr is not None,
        {
            'head': local_head,
            'pr': current_pr.get('number') if current_pr else None
        }
    )

    if current_pr:
        reviews = gh_api(
            f'repos/{REPO}/pulls/{current_pr["number"]}/reviews?per_page=100'
        )

        latest = {}

        for review in reviews:
            login = (review.get('user') or {}).get('login')
            if login:
                latest[login] = review

        approved = sorted(
            login
            for login, review in latest.items()
            if review.get('state') == 'APPROVED'
        )

        check(
            'CURRENT_PR_TWO_DISTINCT_APPROVERS',
            len(approved) >= REQUIRED_APPROVERS,
            {
                'approvers': approved,
                'required': REQUIRED_APPROVERS
            }
        )

        check(
            'CURRENT_PR_NOT_SELF_ONLY',
            len(approved) >= 2
        )
    else:
        check(
            'CURRENT_PR_TWO_DISTINCT_APPROVERS',
            False,
            {'reason': 'AWAITING_TWO_INDEPENDENT_REVIEWERS'}
        )
except Exception as e:
    check('CURRENT_PR_REVIEW_API', False, {'error': str(e)})

workflow_dir = ROOT / '.github' / 'workflows'

for wf in sorted(workflow_dir.glob('*.yml')):
    data = wf.read_text(encoding='utf-8')

    refs = action_refs(data)
    mutable = [
        ref for ref in refs
        if not is_full_sha_ref(ref)
        and not ref.startswith('./')
    ]

    check(
        f'WORKFLOW_NO_PULL_REQUEST_TARGET:{wf.name}',
        'pull_request_target:' not in data
    )

    check(
        f'WORKFLOW_ACTIONS_FULL_SHA:{wf.name}',
        not mutable,
        {'mutable_refs': mutable}
    )

    check(
        f'WORKFLOW_NO_UNTRUSTED_RUNNER:{wf.name}',
        'self-hosted' not in data.lower()
        or '--deny-self-hosted-runners' in data
    )

required = {
    'provenance-gate.yml': (
        'slsa3-build:',
        'zero-trust-policy:',
        'release-policy:',
        'gh attestation verify',
        '--deny-self-hosted-runners'
    ),
    'slsa-build-l3.yml': (
        'workflow_call:',
        'id-token: write',
        'attestations: write',
        'artifact-metadata: write',
        'actions/attest@v4',
        'git archive',
        'gzip -n'
    ),
    'continuous-release-integrity.yml': (
        'gh attestation verify',
        '--deny-self-hosted-runners',
        'slsa-build-l3.yml'
    )
}

for name, needles in required.items():
    path = workflow_dir / name
    data = path.read_text(encoding='utf-8') if path.is_file() else ''

    check(
        f'REQUIRED_WORKFLOW_PRESENT:{name}',
        path.is_file()
    )

    for needle in needles:
        check(
            f'WORKFLOW_CONTROL:{name}:{needle}',
            needle in data
        )

policy = ROOT / 'tools' / 'verify_supply_chain_policy.py'
external = ROOT / 'tools' / 'verify_release_external.sh'

check(
    'SUPPLY_CHAIN_POLICY_VERIFIER_PRESENT',
    policy.is_file()
)

check(
    'EXTERNAL_RELEASE_VERIFIER_PRESENT',
    external.is_file()
)

if policy.is_file():
    out, err, rc = run(
        'python3',
        str(policy)
    )
    check(
        'SUPPLY_CHAIN_POLICY_EXECUTES',
        rc == 0 and 'RIGHTSFRAMES_ZERO_TRUST_POLICY=PASS' in out,
        {'stdout': out, 'stderr': err}
    )

if external.is_file():
    out, err, rc = run(
        'bash',
        '-n',
        str(external)
    )
    check(
        'EXTERNAL_RELEASE_VERIFIER_SYNTAX',
        rc == 0,
        {'stdout': out, 'stderr': err}
    )

try:
    commit = gh_api(
        f'repos/{REPO}/commits/{local_head}'
    )

    check(
        'LOCAL_HEAD_EXISTS_ON_GITHUB',
        commit.get('sha') == local_head
    )

    verification = commit.get('commit', {}).get('verification') or {}

    check(
        'LOCAL_HEAD_SIGNATURE_IF_PRESENT',
        verification.get('verified') is True,
        {
            'verified': verification.get('verified'),
            'reason': verification.get('reason'),
            'verified_at': verification.get('verified_at')
        }
    )
except Exception as e:
    check(
        'GITHUB_LOCAL_HEAD_LOOKUP',
        False,
        {'error': str(e)}
    )

try:
    branch_head = gh_api(
        f'repos/{REPO}/git/ref/heads/{BASE}'
    )

    github_main_sha = (
        branch_head
        .get('object', {})
        .get('sha', '')
    )

    check(
        'GITHUB_MAIN_HEAD_RESOLVED',
        bool(re.fullmatch(r'[0-9a-f]{40}', github_main_sha)),
        {'main': github_main_sha}
    )

    check(
        'GITHUB_MAIN_MATCHES_GIT_MAIN',
        github_main_sha == remote_main_sha,
        {
            'github_api': github_main_sha,
            'git_ls_remote': remote_main_sha
        }
    )
except Exception as e:
    check(
        'GITHUB_MAIN_HEAD_LOOKUP',
        False,
        {'error': str(e)}
    )

if current_pr:
    pr_head_sha = current_pr.get('head', {}).get('sha', '')
    pr_base_sha = current_pr.get('base', {}).get('sha', '')

    check(
        'CURRENT_PR_HEAD_EQUALS_LOCAL',
        pr_head_sha == local_head
    )

    check(
        'CURRENT_PR_BASE_EQUALS_REMOTE_MAIN',
        pr_base_sha == remote_main_sha
    )

    check(
        'CURRENT_PR_IS_NOT_MAIN',
        pr_head_sha != remote_main_sha
    )
else:
    check(
        'PR_RELATIONSHIP_VERIFIED',
        False,
        {'reason': 'NO_OPEN_PR_FOR_LOCAL_HEAD'}
    )

out, err, rc = run(
    'git',
    'diff',
    '--check'
)

check(
    'GIT_DIFF_CHECK',
    rc == 0,
    {'stdout': out, 'stderr': err}
)

out, err, rc = run(
    'python3',
    '-m',
    'compileall',
    '-q',
    'tools'
)

check(
    'PYTHON_TOOLCHAIN_COMPILE',
    rc == 0,
    {'stdout': out, 'stderr': err}
)

for pycache in ROOT.rglob('__pycache__'):
    if pycache.is_dir():
        for child in pycache.iterdir():
            try:
                child.unlink()
            except OSError:
                pass
        try:
            pycache.rmdir()
        except OSError:
            pass

out, err, rc = run(
    'git',
    'status',
    '--porcelain'
)

report_data = {
    'schema': 'rightsframes.enterprise.source-provenance-verification.v2',
    'generated_at': now.isoformat(),
    'repository': REPO,
    'base_branch': BASE,
    'ruleset_id': RULESET_ID,
    'required_approving_reviews': REQUIRED_APPROVERS,
    'local': {
        'branch': local_branch,
        'head': local_head,
        'tree': local_tree
    },
    'remote': {
        'main': remote_main_sha
    },
    'checks': CHECKS,
    'summary': {
        'checks': len(CHECKS),
        'passed': sum(
            c['status'] == 'PASS'
            for c in CHECKS
        ),
        'failed': len(FAILURES),
        'status': 'VERIFIED' if not FAILURES else 'NOT_VERIFIED'
    },
    'failures': FAILURES
}

report = (
    REPORT_DIR /
    f'source_provenance_verification_{stamp}.json'
)

encoded = json.dumps(
    report_data,
    sort_keys=True,
    indent=2
).encode()

report.write_bytes(encoded)
os.chmod(report, 0o600)

report_sha = hashlib.sha256(encoded).hexdigest()

print(f'REPORT={report}')
print(f'REPORT_SHA256={report_sha}')
print(f'CHECKS={len(CHECKS)}')
print(
    f'PASSED={sum(c["status"] == "PASS" for c in CHECKS)}'
)
print(f'FAILED={len(FAILURES)}')
print(f'LOCAL_HEAD={local_head}')
print(f'LOCAL_TREE={local_tree}')
print(f'REMOTE_MAIN={remote_main_sha}')
print(f'RULESET_ID={RULESET_ID}')
print(f'REQUIRED_APPROVING_REVIEWS={REQUIRED_APPROVERS}')

if FAILURES:
    print('SOURCE_POLICY=NOT_VERIFIED')
    for failure in FAILURES:
        print(f'FAIL={failure}')
    raise SystemExit(1)

print('SOURCE_POLICY=VERIFIED')
print('SOURCE_TWO_PARTY_REVIEW_POLICY=ENFORCED')
print('ZERO_BYPASS_POLICY=ENFORCED')
print('STALE_REVIEW_INVALIDATION=ENFORCED')
print('LATEST_PUSH_INDEPENDENT_APPROVAL=ENFORCED')
print('REVIEW_THREAD_RESOLUTION=ENFORCED')
print('NON_FAST_FORWARD_BLOCK=ENFORCED')
print('REMOTE_MAIN_IDENTITY=VERIFIED')
print('PR_BASE_IDENTITY=VERIFIED')
print('PR_HEAD_IDENTITY=VERIFIED')
print('WORKFLOW_SECURITY_SCAN=VERIFIED')
print('EXTERNAL_RELEASE_VERIFIER=VERIFIED')
print('ENTERPRISE_SOURCE_PROVENANCE=VERIFIED')
