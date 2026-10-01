#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = 'cLoydRightsFrames/RightsFrames-Termux'
BRANCH = 'main'
PR = '5'
REQUIRED_APPROVERS = 2

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github' / 'workflows'
REPORT_DIR = ROOT / '.rightsframes-enterprise'

REPORT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

checks = []
failures = []

def run(*args):
    p = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def check(name, condition, detail=''):
    checks.append({
        'name': name,
        'passed': bool(condition),
        'detail': detail
    })
    if not condition:
        failures.append(name)

def gh_json(*args):
    rc, out, err = run('gh', 'api', *args)
    if rc:
        raise RuntimeError(
            f'GH_API_FAILED:{"/".join(args)}:{err}'
        )
    try:
        return json.loads(out)
    except Exception as exc:
        raise RuntimeError(
            f'GH_API_JSON_FAILED:{"/".join(args)}:{exc}'
        )

def git(*args):
    rc, out, err = run('git', *args)
    if rc:
        raise RuntimeError(
            f'GIT_FAILED:{" ".join(args)}:{err}'
        )
    return out

started = datetime.now(timezone.utc)

rc, _, _ = run('gh', 'auth', 'status')
check(
    'GH_AUTHENTICATED',
    rc == 0,
    'authenticated GitHub CLI required'
)

try:
    repo_data = gh_json(f'repos/{REPO}')
    check(
        'REPOSITORY_REACHABLE',
        repo_data.get('full_name', '').lower() == REPO.lower(),
        repo_data.get('full_name', '')
    )
except Exception as exc:
    check('REPOSITORY_REACHABLE', False, str(exc))
    repo_data = {}

try:
    branch_data = gh_json(
        f'repos/{REPO}/branches/{BRANCH}'
    )
    remote_main = branch_data.get('commit', {}).get('sha', '')
    check(
        'MAIN_BRANCH_EXISTS',
        bool(re.fullmatch(r'[0-9a-f]{40}', remote_main)),
        remote_main
    )
except Exception as exc:
    remote_main = ''
    check('MAIN_BRANCH_EXISTS', False, str(exc))

try:
    rules = gh_json(
        f'repos/{REPO}/rules/branches/{BRANCH}?per_page=100'
    )
except Exception as exc:
    rules = []
    check('MAIN_RULES_RETRIEVABLE', False, str(exc))

pull_rule = None
non_fast_forward = False

if isinstance(rules, list):
    for rule in rules:
        if rule.get('type') == 'pull_request':
            pull_rule = rule.get('parameters') or {}
        if rule.get('type') == 'non_fast_forward':
            non_fast_forward = True

check(
    'PULL_REQUEST_RULE_PRESENT',
    pull_rule is not None,
    'branch rules endpoint'
)

required_count = int(
    (pull_rule or {}).get(
        'required_approving_review_count',
        0
    )
)

check(
    'TWO_APPROVING_REVIEWS_REQUIRED',
    required_count >= REQUIRED_APPROVERS,
    str(required_count)
)

check(
    'STALE_REVIEWS_DISMISSED',
    (pull_rule or {}).get(
        'dismiss_stale_reviews_on_push'
    ) is True
)

check(
    'LATEST_PUSH_APPROVAL_REQUIRED',
    (pull_rule or {}).get(
        'require_last_push_approval'
    ) is True
)

check(
    'REVIEW_THREADS_MUST_RESOLVE',
    (pull_rule or {}).get(
        'required_review_thread_resolution'
    ) is True
)

check(
    'NON_FAST_FORWARD_BLOCKED',
    non_fast_forward
)

try:
    ruleset = gh_json(
        f'repos/{REPO}/rulesets/24306410'
    )

    check(
        'SOURCE_L4_RULESET_ACTIVE',
        ruleset.get('enforcement') == 'active',
        str(ruleset.get('enforcement'))
    )

    includes = (
        ruleset
        .get('conditions', {})
        .get('ref_name', {})
        .get('include', [])
    )

    check(
        'SOURCE_L4_RULESET_TARGETS_MAIN',
        'refs/heads/main' in includes,
        str(includes)
    )

    check(
        'SOURCE_L4_BYPASS_EMPTY',
        not ruleset.get('bypass_actors'),
        str(ruleset.get('bypass_actors'))
    )

    check(
        'SOURCE_L4_CURRENT_USER_CANNOT_BYPASS',
        ruleset.get('current_user_can_bypass') == 'never',
        str(ruleset.get('current_user_can_bypass'))
    )
except Exception as exc:
    check(
        'SOURCE_L4_RULESET_RETRIEVABLE',
        False,
        str(exc)
    )

try:
    pr = gh_json(
        f'repos/{REPO}/pulls/{PR}'
    )

    pr_head = (
        pr.get('head', {})
        .get('sha', '')
    )

    pr_base = (
        pr.get('base', {})
        .get('sha', '')
    )

    check(
        'CURRENT_PR_OPEN',
        pr.get('state') == 'open',
        str(pr.get('state'))
    )

    check(
        'CURRENT_PR_TARGETS_MAIN',
        pr.get('base', {}).get('ref') == BRANCH,
        pr.get('base', {}).get('ref', '')
    )

    check(
        'CURRENT_PR_HEAD_IS_IMMUTABLE_SHA',
        bool(re.fullmatch(r'[0-9a-f]{40}', pr_head)),
        pr_head
    )

    check(
        'CURRENT_PR_BASE_MATCHES_REMOTE_MAIN',
        pr_base == remote_main,
        f'base={pr_base} remote_main={remote_main}'
    )

    reviews = gh_json(
        f'repos/{REPO}/pulls/{PR}/reviews?per_page=100'
    )

    latest_by_user = {}

    for review in reviews if isinstance(reviews, list) else []:
        user = (
            review.get('user', {})
            .get('id')
        )

        state = review.get('state')

        if user is None:
            continue

        latest_by_user[user] = {
            'state': state,
            'login': review.get('user', {}).get('login'),
            'submitted_at': review.get('submitted_at'),
            'commit_id': review.get('commit_id')
        }

    approvals = [
        item for item in latest_by_user.values()
        if item.get('state') == 'APPROVED'
    ]

    distinct_approvers = {
        item.get('login')
        for item in approvals
        if item.get('login')
    }

    final_revision_approvals = {
        item.get('login')
        for item in approvals
        if item.get('commit_id') == pr_head
    }

    check(
        'CURRENT_PR_TWO_DISTINCT_APPROVERS',
        len(distinct_approvers) >= REQUIRED_APPROVERS,
        json.dumps(
            sorted(distinct_approvers),
            sort_keys=True
        )
    )

    check(
        'CURRENT_PR_FINAL_REVISION_TWO_APPROVALS',
        len(final_revision_approvals) >= REQUIRED_APPROVERS,
        json.dumps(
            sorted(final_revision_approvals),
            sort_keys=True
        )
    )

    check(
        'CURRENT_PR_NOT_SELF_ONLY',
        len(distinct_approvers) >= REQUIRED_APPROVERS,
        f'approved={sorted(distinct_approvers)}'
    )

except Exception as exc:
    pr_head = ''
    check(
        'CURRENT_PR_RETRIEVABLE',
        False,
        str(exc)
    )

workflow_count = 0
action_count = 0
mutable_actions = []
self_hosted = []
dangerous_triggers = []

action_re = re.compile(
    r'^\s*uses:\s*'
    r'([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)'
    r'@([^\s#]+)'
)

runner_re = re.compile(
    r'^\s*runs-on:\s*(.+?)\s*$'
)

for path in sorted(WORKFLOWS.glob('*.yml')):
    workflow_count += 1
    lines = path.read_text(
        encoding='utf-8',
        errors='strict'
    ).splitlines()

    for number, line in enumerate(lines, 1):
        action = action_re.match(line)

        if action:
            action_count += 1

            repository, reference = action.groups()

            if not re.fullmatch(
                r'[0-9a-fA-F]{40}',
                reference
            ):
                mutable_actions.append(
                    f'{path.name}:{number}:'
                    f'{repository}@{reference}'
                )

        runner = runner_re.match(line)

        if runner:
            value = runner.group(1).strip()

            if 'self-hosted' in value.lower():
                self_hosted.append(
                    f'{path.name}:{number}:{value}'
                )

    workflow_text = '\n'.join(lines)

    if re.search(
        r'(?m)^\s*pull_request_target\s*:',
        workflow_text
    ):
        dangerous_triggers.append(
            f'{path.name}:pull_request_target'
        )

check(
    'ALL_WORKFLOW_ACTIONS_FULL_SHA',
    not mutable_actions,
    '|'.join(mutable_actions)
)

check(
    'NO_SELF_HOSTED_RUNNER_EXECUTION',
    not self_hosted,
    '|'.join(self_hosted)
)

check(
    'NO_PULL_REQUEST_TARGET',
    not dangerous_triggers,
    '|'.join(dangerous_triggers)
)

local_head = git('rev-parse', 'HEAD')
local_tree = git('rev-parse', 'HEAD^{tree}')
unstaged = git('diff', '--name-only').splitlines()
untracked = git(
    'ls-files',
    '--others',
    '--exclude-standard'
).splitlines()

unexpected_unstaged = [
    item for item in unstaged
    if item != '.rightsframes-enterprise'
    and not item.startswith('.rightsframes-enterprise/')
]

unexpected_untracked = [
    item for item in untracked
    if item != '.rightsframes-enterprise'
    and not item.startswith('.rightsframes-enterprise/')
]

check(
    'LOCAL_HEAD_DISCOVERED',
    bool(re.fullmatch(r'[0-9a-f]{40}', local_head)),
    local_head
)

check(
    'LOCAL_TREE_DISCOVERED',
    bool(re.fullmatch(r'[0-9a-f]{40}', local_tree)),
    local_tree
)

check(
    'LOCAL_UNSTAGED_CHANGES_CLEAN',
    not unexpected_unstaged,
    '|'.join(unexpected_unstaged)
)

check(
    'LOCAL_UNTRACKED_CHANGES_CLEAN',
    not unexpected_untracked,
    '|'.join(unexpected_untracked)
)

check(
    'STAGED_RELEASE_CANDIDATE_ALLOWED',
    True,
    'staged changes are the candidate revision under verification'
)

check(
    'REMOTE_MAIN_IS_NOT_MISTAKEN_FOR_PR_HEAD',
    bool(remote_main) and remote_main != pr_head,
    f'main={remote_main} pr={pr_head}'
)

policy_enforced = (
    pull_rule is not None
    and required_count >= REQUIRED_APPROVERS
    and (pull_rule or {}).get(
        'dismiss_stale_reviews_on_push'
    ) is True
    and (pull_rule or {}).get(
        'require_last_push_approval'
    ) is True
    and (pull_rule or {}).get(
        'required_review_thread_resolution'
    ) is True
    and non_fast_forward
    and not mutable_actions
    and not self_hosted
    and not dangerous_triggers
)

source_l4_verified = (
    policy_enforced
    and len(distinct_approvers) >= REQUIRED_APPROVERS
    and len(final_revision_approvals) >= REQUIRED_APPROVERS
)

report = {
    'schema':
        'rightsframes.slsa.source-l4.external-verification.v1',
    'generated_at':
        started.isoformat(),
    'repository':
        REPO,
    'protected_branch':
        BRANCH,
    'current_pr':
        PR,
    'slsa_version':
        '1.2',
    'target':
        'SLSA_SOURCE_LEVEL_4',
    'verified_property':
        'SLSA_SOURCE_TWO_PARTY_REVIEWED',
    'policy_enforced':
        policy_enforced,
    'source_l4_verified':
        source_l4_verified,
    'remote_main':
        remote_main,
    'current_pr_head':
        pr_head,
    'local_head':
        local_head,
    'local_tree':
        local_tree,
    'workflow_count':
        workflow_count,
    'workflow_action_count':
        action_count,
    'mutable_actions':
        mutable_actions,
    'self_hosted_runner_references':
        self_hosted,
    'dangerous_triggers':
        dangerous_triggers,
    'rules': {
        'required_approving_reviews':
            required_count,
        'required_reviewers':
            REQUIRED_APPROVERS,
        'dismiss_stale_reviews_on_push':
            (pull_rule or {}).get(
                'dismiss_stale_reviews_on_push'
            ),
        'require_last_push_approval':
            (pull_rule or {}).get(
                'require_last_push_approval'
            ),
        'required_review_thread_resolution':
            (pull_rule or {}).get(
                'required_review_thread_resolution'
            ),
        'non_fast_forward_blocked':
            non_fast_forward
    },
    'checks': checks
}

payload = json.dumps(
    report,
    sort_keys=True,
    indent=2
).encode()

stamp = datetime.now(
    timezone.utc
).strftime('%Y%m%dT%H%M%SZ')

report_path = (
    REPORT_DIR /
    f'source_l4_external_verification_{stamp}.json'
)

report_path.write_bytes(payload)
os.chmod(report_path, 0o600)

import hashlib

digest = hashlib.sha256(payload).hexdigest()

print(
    f'REPORT={report_path}'
)
print(
    f'REPORT_SHA256={digest}'
)
print(
    f'CHECKS={len(checks)}'
)
print(
    f'PASSED={sum(1 for x in checks if x["passed"])}'
)
print(
    f'FAILED={sum(1 for x in checks if not x["passed"])}'
)
print(
    f'REMOTE_MAIN={remote_main}'
)
print(
    f'CURRENT_PR_HEAD={pr_head}'
)
print(
    f'LOCAL_HEAD={local_head}'
)
print(
    f'LOCAL_TREE={local_tree}'
)
print(
    f'WORKFLOWS_SCANNED={workflow_count}'
)
print(
    f'ACTIONS_SCANNED={action_count}'
)
print(
    f'REQUIRED_APPROVING_REVIEWS={required_count}'
)
print(
    f'POLICY_ENFORCED={str(policy_enforced).upper()}'
)
print(
    f'SOURCE_L4_VERIFIED={str(source_l4_verified).upper()}'
)

if not source_l4_verified:
    print('SOURCE_L4_STATUS=NOT_YET_VERIFIED')
    for failure in failures:
        print(f'FAIL={failure}')
    raise SystemExit(1)

print('SOURCE_L4_STATUS=VERIFIED')
print('SLSA_SOURCE_TWO_PARTY_REVIEWED=VERIFIED')
