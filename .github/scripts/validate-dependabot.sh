#!/bin/bash
set -euo pipefail
echo "Validating Dependabot configuration..."
if ! command -v yamllint &> /dev/null; then
    python3 -m pip install --require-hashes -r .github/scripts/requirements-yamllint.txt
fi
yamllint -d relaxed .github/dependabot.yml || exit 1
echo "✅ All configurations validated"
