#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

REPO = 'cLoydRightsFrames/RightsFrames-Termux'
BRANCH = 'main'
REQUIRED_APPROVERS = 2

def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()

def fail(msg):
    print(f'SOURCE_L4_POLICY=FAIL')
    print(f'REASON={msg}')
    raise SystemExit(1)

try:
    rulesets = json.loads(run(
        'gh', 'api',
        f'repos/{REPO}/rulesets?includes_parents=true&per_page=100'
    ))
except Exception as e:
    fail(f'GITHUB_RULESETS_UNAVAILABLE:{e}')

matching = []
for ruleset in rulesets:
    if ruleset.get('enforcement') != 'active':
        continue
    refs = ruleset.get('conditions', {}).get('ref_name', {}).get('include', [])
    if 'refs/heads/main' not in refs:
        continue
    matching.append(ruleset)

if not matching:
    fail('ACTIVE_MAIN_BRANCH_RULESET=NOT_FOUND')

pull_rules = []
for ruleset in matching:
    for rule in ruleset.get('rules', []):
        if rule.get('type') == 'pull_request':
            pull_rules.append(rule.get('parameters') or {})

if not pull_rules:
    fail('PULL_REQUEST_RULE=NOT_FOUND')

if max(
    (int(r.get('required_approving_review_count', 0)) for r in pull_rules),
    default=0
) < REQUIRED_APPROVERS:
    fail('REQUIRED_APPROVING_REVIEWERS<2')

if not any(r.get('require_last_push_approval') is True for r in pull_rules):
    fail('LAST_PUSH_APPROVAL=NOT_REQUIRED')

if not any(r.get('dismiss_stale_reviews_on_push') is True for r in pull_rules):
    fail('STALE_REVIEWS=NOT_DISMISSED')

if not any(r.get('required_review_thread_resolution') is True for r in pull_rules):
    fail('REVIEW_THREAD_RESOLUTION=NOT_REQUIRED')

print('SOURCE_L4_POLICY=PASS')
print('PROTECTED_BRANCH=main')
print('REQUIRED_APPROVING_REVIEWERS=2')
print('LAST_PUSH_APPROVAL=REQUIRED')
print('STALE_REVIEWS=DISMISSED')
print('REVIEW_THREAD_RESOLUTION=REQUIRED')
print('SLSA_SOURCE_TWO_PARTY_REVIEWED=POLICY_ENFORCED')
print('SOURCE_L4_POLICY=PASS')
print('PROTECTED_BRANCH=main')
print('REQUIRED_APPROVING_REVIEWERS=2')
print('SLSA_SOURCE_TWO_PARTY_REVIEWED=POLICY_ENFORCED')
