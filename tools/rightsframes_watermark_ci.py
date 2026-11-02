#!/usr/bin/env python3
"""Read-only RightsFrames CI watermark-comment policy. Never edits source or evidence."""
import io
import re
import subprocess
import sys
import tokenize
from pathlib import PurePosixPath

SUFFIXES = {'.py', '.pyi', '.sh', '.bash', '.zsh', '.fish', '.js', '.jsx', '.ts', '.tsx',
            '.mjs', '.cjs', '.go', '.rs', '.java', '.kt', '.kts', '.c', '.cc', '.cpp',
            '.h', '.hpp', '.cs', '.rb', '.php', '.lua', '.pl', '.r', '.sql', '.ps1',
            '.psm1', '.psd1', '.bat', '.cmd', '.gradle', '.groovy', '.swift', '.dart',
            '.toml', '.ini', '.yml', '.yaml', '.json', '.xml', '.html', '.htm', '.css',
            '.scss', '.sass'}
NAMES = {'makefile', 'dockerfile', '.gitignore', '.gitattributes', '.editorconfig',
         '.env.example', 'justfile'}
SKIP_DIRS = {'.git', '.cache', '.npm', '.cargo', '.rustup', '.gradle', '.venv', 'venv',
             'node_modules', 'site-packages', '__pycache__', '.tox', '.mypy_cache',
             '.pytest_cache', '.next', '.expo', '.termux', 'storage', 'usr', 'lib',
             'opt', 'dist', 'build', 'target', 'coverage', 'vendor', 'third_party',
             'third-party', '.local', '.config', 'backups'}
SENSITIVE = {'license', 'license.md', 'license.txt', 'copying', 'notice', 'authors',
             'contributors', 'code_of_conduct.md', 'security.md', 'package-lock.json',
             'yarn.lock', 'poetry.lock', 'cargo.lock', 'go.sum'}
SENSITIVE_SUFFIXES = {'.sig', '.asc', '.pem', '.pub', '.key', '.p12', '.pfx',
                      '.db', '.sqlite', '.sqlite3', '.lock', '.manifest.json'}
COMMENT = re.compile(r'^\s*(?:#|//|;|--|/\*+|\*|<!--|%)\s*(.*?)\s*(?:\*/|-->)?\s*$')
BAD = re.compile(r'''(?ix)^(?:
  @?(?:rf[_\s-]?)?(?:ai[_\s-]?)?watermark(?:[_\s-]?(?:id|tag|marker|stamp))?\s*(?::|=|$|\s+-\s+)\s*.*
  | (?:ai|synthetic|hidden|generated)[_\s-]+watermark\s*(?::|=|$|\s+-\s+)\s*.*
  | (?:generated|created|authored|written)[_\s-]+by\s+(?:chatgpt|openai|claude|anthropic|gemini|google\s+gemini|github\s+copilot|copilot|gpt[-\s]?[3456])\b.*
  | (?:made\s+with|produced\s+by)\s+(?:chatgpt|claude|gemini|github\s+copilot)\b.*
)$''')
PROTECTED = re.compile(r'(?i)\b(?:copyright|license|licensed|spdx|all\s+rights\s+reserved|provenance|attestation|merkle|sbom|audit|evidence|manifest|signature|signed|sha(?:256|384|512)|commit\s+id|sourceMappingURL)\b')
JS_LIKE = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.go', '.rs', '.java',
           '.kt', '.kts', '.c', '.cc', '.cpp', '.h', '.hpp', '.cs', '.gradle',
           '.groovy', '.swift', '.dart', '.css', '.scss', '.sass'}
MAX_FILE = 8 * 1024 * 1024

def git(*args):
    p = subprocess.run(['git', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode:
        raise RuntimeError(f'git {args[0]} failed: {p.stderr.decode("utf-8", "replace")[:200]}')
    return p.stdout

def is_source(path):
    parts = PurePosixPath(path).parts
    name = parts[-1].lower()
    if any(item in SKIP_DIRS for item in parts[:-1]):
        return False
    if name in SENSITIVE or any(name.endswith(s) for s in SENSITIVE_SUFFIXES):
        return False
    if any(x in {'evidence', 'immutable', 'signed-records'} for x in parts[:-1]):
        return False
    return PurePosixPath(name).suffix in SUFFIXES or name in NAMES

def is_bad_comment(line, path):
    stripped = line.lstrip()
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in JS_LIKE and not stripped.startswith(('//', '/*', '*')):
        return False
    if suffix in {'.html', '.htm', '.xml'} and not stripped.startswith('<!--'):
        return False
    if suffix == '.sql' and not stripped.startswith(('--', '/*', '*')):
        return False
    if suffix in {'.ini', '.toml'} and not stripped.startswith(('#', ';')):
        return False
    if suffix not in JS_LIKE | {'.html', '.htm', '.xml', '.sql', '.ini', '.toml'} and not stripped.startswith('#'):
        return False
    m = COMMENT.fullmatch(line.rstrip('\r\n'))
    return bool(m and BAD.fullmatch(m.group(1).strip()) and not PROTECTED.search(m.group(1)))

def inspect(data, path):
    if len(data) > MAX_FILE or b'\0' in data:
        raise ValueError('oversize or binary source')
    txt = data.decode('utf-8-sig' if data.startswith(b'\xef\xbb\xbf') else 'utf-8')
    lines = txt.splitlines(keepends=True)
    if PurePosixPath(path).suffix.lower() in {'.py', '.pyi'}:
        try:
            tokens = tokenize.generate_tokens(io.StringIO(txt).readline)
            return [n for t in tokens if t.type == tokenize.COMMENT
                    for n, col in [t.start]
                    if not lines[n-1][:col].strip() and is_bad_comment(lines[n-1], path)]
        except (tokenize.TokenError, IndentationError) as exc:
            raise ValueError(f'cannot tokenize source: {exc}') from exc
    return [n for n, line in enumerate(lines, 1) if is_bad_comment(line, path)]

def selftest():
    assert inspect(b'# Watermark: test-only\nprint("safe")\n', 'test.py') == [1]
    assert inspect(b'// Generated by ChatGPT\nconst x = 1;\n', 'test.js') == [1]
    assert inspect(b'# SPDX-License-Identifier: MIT\n', 'test.py') == []
    assert inspect(b'print("# Watermark: not a comment")\n', 'test.py') == []
    assert inspect(b'# Audit signature watermark: do not edit\n', 'test.py') == []
    print('WATERMARK_POLICY_SELFTEST=PASS')

def scan():
    records = git('ls-tree', '-r', '-z', 'HEAD')
    inspected = blocked = unscanned = 0
    for rec in records.split(b'\0'):
        if not rec:
            continue
        meta, rawpath = rec.split(b'\t', 1)
        mode, objtype, sha = meta.split()
        path = rawpath.decode('utf-8', 'surrogateescape')
        if mode not in (b'100644', b'100755'):
            continue  # Do not dereference links or inspect submodule trees.
        if not is_source(path):
            continue
        try:
            data = git('cat-file', 'blob', sha.decode('ascii'))
            hits = inspect(data, path)
            inspected += 1
            for line in hits:
                print(f'BLOCKED_MARKER mode=ci path={path} line={line}')
            blocked += len(hits)
        except (UnicodeError, ValueError, RuntimeError) as exc:
            print(f'UNSCANNABLE_SOURCE path={path} reason={str(exc)[:140]}')
            unscanned += 1
    print(f'WATERMARK_POLICY_RESULT inspected={inspected} blocked={blocked} unscanned={unscanned}')
    return 1 if blocked else (2 if unscanned else 0)

if __name__ == '__main__':
    try:
        if len(sys.argv) == 2 and sys.argv[1] == '--selftest':
            selftest()
        elif len(sys.argv) == 2 and sys.argv[1] == '--scan-head':
            selftest()
            sys.exit(scan())
        else:
            sys.exit('usage: rightsframes_watermark_ci.py --selftest|--scan-head')
    except (AssertionError, RuntimeError) as exc:
        sys.exit(f'WATERMARK_POLICY_ERROR={exc}')
