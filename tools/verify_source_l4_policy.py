#!/usr/bin/env python3
import json
import subprocess
import sys

REPO = 'cloydRightsFrames/RightsFrames-Termux'
RULESET_ID = 24306410
RULESET_NAME = 'RightsFrames Source L4 Two-Party Review'
BRANCH_REF = 'refs/heads/main'
REQUIRED_APPROVERS = 2

def fail(msg):
    print('SOURCE_L4_POLICY=FAIL')
    print(f'REASON={msg}')
    raise SystemExit(1)

def gh_json(*args):
    result = subprocess.run(
        ('gh', 'api', *args),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(detail or f'gh api exited {result.returncode}')
    if not result.stdout.strip():
        raise RuntimeError('empty response')
    return json.loads(result.stdout)

try:
    ruleset = gh_json(f'repos/{REPO}/rulesets/{RULESET_ID}')
except Exception as exc:
    fail(f'GITHUB_RULESET_UNAVAILABLE:{exc}')

if ruleset.get('id') != RULESET_ID:
    fail('RULESET_ID_MISMATCH')

if ruleset.get('name') != RULESET_NAME:
    fail('RULESET_NAME_MISMATCH')

if ruleset.get('target') != 'branch':
    fail('RULESET_TARGET_MISMATCH')

if ruleset.get('enforcement') != 'active':
    fail('RULESET_NOT_ACTIVE')

includes = (
    ruleset
    .get('conditions', {})
    .get('ref_name', {})
    .get('include', [])
)

if BRANCH_REF not in includes:
    fail('MAIN_BRANCH_NOT_PROTECTED')

pull_rules = [
    rule.get('parameters') or {}
    for rule in ruleset.get('rules', [])
    if rule.get('type') == 'pull_request'
]

if not pull_rules:
    fail('PULL_REQUEST_RULE=NOT_FOUND')

if max(
    int(rule.get('required_approving_review_count', 0))
    for rule in pull_rules
) < REQUIRED_APPROVERS:
    fail('REQUIRED_APPROVING_REVIEWERS<2')

if not any(
    rule.get('require_last_push_approval') is True
    for rule in pull_rules
):
    fail('LAST_PUSH_APPROVAL=NOT_REQUIRED')

if not any(
    rule.get('dismiss_stale_reviews_on_push') is True
    for rule in pull_rules
):
    fail('STALE_REVIEWS=NOT_DISMISSED')

if not any(
    rule.get('required_review_thread_resolution') is True
    for rule in pull_rules
):
    fail('REVIEW_THREAD_RESOLUTION=NOT_REQUIRED')

if not any(
    rule.get('allowed_merge_methods') == ['squash']
    for rule in pull_rules
):
    fail('SQUASH_MERGE_ONLY=NOT_ENFORCED')

print('SOURCE_L4_POLICY=PASS')
print('PROTECTED_BRANCH=main')
print(f'RULESET_ID={RULESET_ID}')
print('RULESET_ENFORCEMENT=active')
print(f'REQUIRED_APPROVING_REVIEWERS={REQUIRED_APPROVERS}')
print('LAST_PUSH_APPROVAL=REQUIRED')
print('STALE_REVIEWS=DISMISSED')
print('REVIEW_THREAD_RESOLUTION=REQUIRED')
print('SQUASH_MERGE_ONLY=REQUIRED')
print('SLSA_SOURCE_TWO_PARTY_REVIEWED=POLICY_ENFORCED')
