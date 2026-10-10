#!/bin/bash
set -euo pipefail
echo "Validating Dependabot configuration..."
if ! command -v yamllint &> /dev/null; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REQUIREMENTS_FILE="${SCRIPT_DIR}/requirements-yamllint.txt"

    if [[ ! -f "${REQUIREMENTS_FILE}" ]]; then
        echo "ERROR: Missing requirements file: ${REQUIREMENTS_FILE}" >&2
        exit 1
    fi

    python3 -m pip install --require-hashes -r "${REQUIREMENTS_FILE}"
fi
yamllint -d relaxed .github/dependabot.yml || exit 1
echo "✅ All configurations validated"
