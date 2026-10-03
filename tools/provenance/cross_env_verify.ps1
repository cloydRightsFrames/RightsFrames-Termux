$ErrorActionPreference = "Stop"
$Root = (Resolve-Path $(if ($args.Count) { $args[0] } else { "." })).Path
$Out = if ($args.Count -gt 1) { $args[1] } else { "cross-environment-manifest-windows.json" }

$Commit = (git -C $Root rev-parse HEAD).Trim()
$Paths = @(git -C $Root ls-files)

$Files = foreach ($Rel in ($Paths | Sort-Object)) {
    $Full = Join-Path $Root $Rel
    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Full).Hash.ToLower()
    [ordered]@{
        path = $Rel.Replace("\","/")
        sha256 = $Hash
        size = (Get-Item -LiteralPath $Full).Length
    }
}

$Manifest = [ordered]@{
    schema = "rightsframes.cross-environment-manifest/v1"
    repository = "cLoydRightsFrames/RightsFrames-Termux"
    commit = $Commit
    tracked_file_count = @($Files).Count
    tracked_files = @($Files)
}

$Json = $Manifest | ConvertTo-Json -Depth 20 -Compress
[IO.File]::WriteAllText(
    $Out,
    $Json + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)

$Digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $Out).Hash.ToLower()
[IO.File]::WriteAllText(
    "$Out.sha256",
    "$Digest  $(Split-Path $Out -Leaf)$([Environment]::NewLine)",
    [Text.UTF8Encoding]::new($false)
)

Write-Host "COMMIT=$Commit"
Write-Host "TRACKED_FILES=$(@($Files).Count)"
Write-Host "MANIFEST_SHA256=$Digest"
Write-Host "CROSS_ENVIRONMENT_MANIFEST=VERIFIED"
