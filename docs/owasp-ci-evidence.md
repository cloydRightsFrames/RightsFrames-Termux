# OWASP scan evidence

Installation always uses the original hash-locked runtime and test requirements.
The scanner receives a temporary tracked-source snapshot whose requirements.txt
contains all locked runtime and test versions, including every platform marker.
This prevents the experimental pip analyzer from interpreting hash continuation
lines as packages and ensures the test lock is included. Original locks and
their SHA-256 hashes are retained as evidence.

The existing NVD_API_KEY repository secret is reused. An explicit NVD refresh
is required on every run. The report must show an NVD check during this run,
checked and modified timestamps no older than 24 hours, no update fallback,
and package identifiers covering every locked version. These checks establish
local update freshness; they cannot guarantee that NVD itself contains every
newly disclosed vulnerability.

The CVSS 7 failure threshold remains active. Security findings are preserved.
Only synthetic SARIF file locations are mapped to the original lockfile lines.
The original and normalized SARIF, JSON report, redacted console log, input
hashes, scanner exit code, and freshness evidence are retained for 30 days.
A failed scan remains failed even when its reports are retained.

Sonatype Guide uses a separate OSS_INDEX_TOKEN repository secret; an optional
OSS_INDEX_USERNAME supports legacy accounts. No NVD key is reused for Sonatype.
Without a token, the evidence explicitly records unavailable Sonatype coverage.
When a token is supplied, failure to complete that analyzer fails verification.
Credentials must be entered through a secret manager, never into source files.

Passing CI does not replace independent security review. Review the PR and its
evidence before merging. There is no automatic merge or change to branch rules.

Upstream references:
- https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html
- https://dependency-check.github.io/DependencyCheck/analyzers/oss-index-analyzer.html
- https://github.com/dependency-check/DependencyCheck/blob/main/core/src/main/java/org/owasp/dependencycheck/analyzer/PipAnalyzer.java
