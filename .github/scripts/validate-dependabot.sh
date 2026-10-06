#!/bin/bash
set -euo pipefail
echo "Validating Dependabot configuration..."
if ! command -v yamllint &> /dev/null; then
    pip install yamllint > /dev/null 2>&1
fi
yamllint -d relaxed .github/dependabot.yml || exit 1
echo "✅ All configurations validated"
