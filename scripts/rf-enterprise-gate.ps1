[CmdletBinding()]
param([string]$Python = "python")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Push-Location -LiteralPath (Join-Path $PSScriptRoot "..")
try {
    & $Python -m enterprise.control_plane.cli readiness
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $Python -m enterprise.control_plane.cli evaluate
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $Python tools/verify_supply_chain_policy.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Output "RIGHTSFRAMES_ENTERPRISE_GATE=PASS"
}
finally {
    Pop-Location
}
