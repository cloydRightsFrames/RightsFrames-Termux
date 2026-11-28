#!/data/data/com.termux/files/usr/bin/bash
# RightsFrames RC3 product validator: true process-wide isolated Python runtime.
set -Eeuo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"
VENV="${RF_PRODUCT_VENV:-$ROOT/.rf-private-venv}"
REQ="$(mktemp "${TMPDIR:-/tmp}/rf-pydantic.XXXXXXXX")"
trap 'rm -f -- "$REQ"' EXIT
printf '\n=== RIGHTSFRAMES ISOLATED RUNTIME ===\n'
python - <<'PYCODE'
import sys, importlib.metadata as m
print('PYTHON='+sys.version.split()[0])
for name in ('pydantic','pydantic-core','fastapi','uvicorn','starlette','cryptography'):
    try: print(name.upper().replace('-','_')+'='+m.version(name))
    except m.PackageNotFoundError: raise SystemExit('MISSING_DEPENDENCY='+name)
if m.version('pydantic-core')!='2.50.5':
    raise SystemExit('STOP: expected compiled pydantic-core 2.50.5; never mutate global Termux')
PYCODE
grep -q '^pydantic==2.14.4 ' "$ROOT/core/requirements.txt" || { echo 'REQUIREMENTS_LOCK_UNEXPECTED'; exit 1; }
[ ! -e "$VENV" ] || { echo 'STOP: private runtime already exists; refuse overwrite'; exit 1; }
python -m venv --without-pip --system-site-packages "$VENV"
[ -x "$VENV/bin/python" ] || { echo 'PRIVATE_PYTHON_MISSING'; exit 1; }
export PATH="$VENV/bin:$PATH" PYTHONNOUSERSITE=1
unset PYTHONPATH
SITE="$(python -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"
case "$SITE" in "$VENV"/*) ;; *) echo 'STOP: venv Python installation path escapes private runtime'; exit 1;; esac
mkdir -p "$SITE"
cat > "$REQ" <<'REQUIREMENTS'
pydantic==2.14.4 \
  --hash=sha256:653a2ad9f6d8858529c77c72717d0ea991d6c6837fe683246b2f4b2bbfc3fadc \
  --hash=sha256:7c19f1d46f8accf55a4617a6116e1ade64840870f397b846a2c53fb9019414ba
REQUIREMENTS
PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 PIP_REQUIRE_VIRTUALENV=false \
  python -m pip install --no-deps --only-binary=:all: --require-hashes --disable-pip-version-check \
    --no-cache-dir --target "$SITE" -r "$REQ"
export PYTHONPATH="$ROOT"
python - <<'PYCODE'
import os,sys,subprocess,pydantic,pydantic_core,fastapi
assert pydantic.__version__=='2.14.4' and pydantic_core.__version__=='2.50.5'
assert os.path.realpath(sys.executable).endswith('/bin/python3.14') or sys.prefix!=sys.base_prefix
assert sys.prefix!=sys.base_prefix, 'must be inside an isolated virtual environment'
probe='import pydantic,pydantic_core,sys; assert pydantic.__version__=="2.14.4" and pydantic_core.__version__=="2.50.5" and sys.prefix!=sys.base_prefix'
env=dict(os.environ); env.pop('PYTHONPATH',None)
subprocess.run([sys.executable,'-c',probe],env=env,check=True,timeout=20)
print('PYDANTIC='+pydantic.__version__+' CORE='+pydantic_core.__version__)
print('ISOLATED_FRESH_SUBPROCESS=PASS')
PYCODE
printf '\n=== RIGHTSFRAMES REAL LEDGER AND SIGNATURE TESTS ===\n'
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p test_rf_agent_gate.py -v
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p test_rf_agent_sdk.py -v
printf '\n=== RIGHTSFRAMES REAL LOOPBACK HTTP ACCEPTANCE ===\n'
PYTHONDONTWRITEBYTECODE=1 python tools/rf_agent_acceptance.py
