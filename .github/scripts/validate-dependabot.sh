#!/bin/bash
set -euo pipefail
echo "Validating Dependabot configuration..."
if ! command -v yamllint &> /dev/null; then
    pip install --require-hashes -r .github/scripts/requirements-yamllint.txt > /dev/null 2>&1
fi
yamllint -d relaxed .github/dependabot.yml || exit 1
echo "✅ All configurations validated"
