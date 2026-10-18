[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "NOT_A_DIRECTORY: $Path" }
$full = (Resolve-Path -LiteralPath $Path).ProviderPath
if ($full -match '^[A-Za-z]:\\?$' -or $full -ieq $env:SystemRoot -or $full -ieq $env:USERPROFILE) { throw "REFUSING_BROAD_PATH: $full" }
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$grants = @("${me}:(OI)(CI)F", '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
Write-Output "TARGET: $full"
Write-Output 'CURRENT ACL:'
& icacls $full
Write-Output ('PLAN: icacls "{0}" /inheritance:r /grant:r {1}' -f $full, ($grants -join ' '))
if (-not $Apply) { Write-Output 'DRY_RUN (pass -Apply to enforce)'; return }
& icacls $full /inheritance:r /grant:r @grants
if ($LASTEXITCODE -ne 0) { throw 'ICACLS_FAILED' }
$allowed = @($me, 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
$extra = (Get-Acl -LiteralPath $full).Access | Where-Object { $allowed -notcontains $_.IdentityReference.Value }
if ($extra) { throw ('UNEXPECTED_ACES: ' + (($extra | ForEach-Object { $_.IdentityReference.Value }) -join ', ')) }
Write-Output 'ACL_ENFORCED'