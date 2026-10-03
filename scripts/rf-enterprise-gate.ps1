[CmdletBinding()]
param([string]$Python = "python")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
& $Python -m py_compile enterprise/control_plane/audit.py enterprise/control_plane/policy.py enterprise/control_plane/health.py enterprise/control_plane/provenance.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python -m unittest discover -s tests -p test_enterprise_control_plane.py -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python -m enterprise.control_plane.cli readiness
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "RIGHTSFRAMES_ENTERPRISE_GATE=PASS"
