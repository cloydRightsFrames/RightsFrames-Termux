from pathlib import Path
import re
import sys

p = Path(sys.argv[1])
s = p.read_text(encoding='utf-8')

s = re.sub(
    r'(?m)^  enance/verify_release\.sh &&\n',
    '',
    s,
)

s = re.sub(
    r"(?m)^  printf '%s\\n' '=== STATUS ===' &&\n",
    '',
    s,
)

s = re.sub(
    r'(?m)^  git status --short --branch\n',
    '',
    s,
)

s = re.sub(
    r'(?ms)^\s*mv \\\n\s*"dist/RightsFrames-Termux-\$\{GITHUB_REF_NAME\}\.tar\.gz" \\\n\s*"dist/RightsFrames-Termux-\$\{GITHUB_REF_NAME\}\.tar\.gz"\n',
    '',
    s,
)

s = s.replace(
    'test "$(git rev-list -n1 "refs/tags/${TAG}")" = "${GITHUB_SHA}"',
    'TAG_TARGET="$(git rev-parse "refs/tags/${TAG}^{commit}")"\n'
    '            test "$TAG_TARGET" = "${GITHUB_SHA}"',
)

p.write_text(s, encoding='utf-8')
print('REPAIR=PASS')
