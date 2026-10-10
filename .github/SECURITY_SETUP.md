# Enterprise Security Configuration

## Production-Grade Scanners
- CodeQL: JS/TS, Python, Go, C++, Java
- Dependabot: NPM, Python, Docker, Go, Terraform
- Trivy: Container & IaC
- Semgrep: Code patterns
- TruffleHog + GitGuardian: Secrets

## Secrets Required (GitHub UI)
Settings → Secrets and variables → Actions:
1. GITGUARDIAN_API_KEY
2. SLACK_WEBHOOK_URL (optional)

## Branch Protection (main, develop, release/**)
- Status checks: All 5 CodeQL + 4 scanners
- 2 required reviews
- Code owner approval
- Signed commits
- Admin pushes only

## Schedules
- Daily 03:00 UTC: NPM, Python, Go
- Weekly Monday 04:00 UTC: GitHub Actions, Terraform
- Sunday 02:00 UTC: CodeQL full scan
- Every push/PR: Instant triggers

## Monitor
Security → Code scanning alerts
Security → Dependabot alerts
Insights → Security dashboard
