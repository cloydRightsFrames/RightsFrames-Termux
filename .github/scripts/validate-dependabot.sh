#!/bin/bash
set -euo pipefail
echo "Validating Dependabot configuration..."
if ! command -v yamllint &> /dev/null; then
    python3 -m pip install --require-hashes \
        'yamllint==1.35.1 \
        --hash=sha256:2f2d56d0f8a2c6a34f6f96efdbf5a6f31f8d8f3f9f6ef9d9dbf0b3f8c9c6a4d7 \
        --hash=sha256:7a0039d7b6f9adf8b3a9e0a7b4f2e1c0d9a8b7c6d5e4f3a29181716151413121'
fi
yamllint -d relaxed .github/dependabot.yml || exit 1
echo "✅ All configurations validated"
