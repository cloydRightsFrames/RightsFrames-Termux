$ErrorActionPreference = "Stop"

$Root = (Resolve-Path $(if ($args.Count) { $args[0] } else { "." })).Path
$Out = if ($args.Count -gt 1) { $args[1] } else { "cross-environment-manifest.json" }

$Commit = (git -C $Root rev-parse HEAD).Trim()
$Lines = @(git -C $Root ls-tree -r --long HEAD)

$Files = foreach ($Line in $Lines) {
    if ([string]::IsNullOrWhiteSpace($Line)) { continue }

    $Parts = $Line -split "`t", 2
    if ($Parts.Count -ne 2) { throw "INVALID_GIT_TREE_RECORD" }

    $Meta = $Parts[0] -split " ", 4
    if ($Meta.Count -ne 4) { throw "INVALID_GIT_TREE_META" }

    $Mode = $Meta[0]
    $Type = $Meta[1]
    $Blob = $Meta[2]
    $Size = [int64]$Meta[3]
    $Path = $Parts[1].Replace("\","/")

    if ($Type -ne "blob") { continue }

    [ordered]@{
        path = $Path
        git_blob = $Blob
        size = $Size
    }
}

$Files = @($Files | Sort-Object -Property path)

$Manifest = [ordered]@{
    schema = "rightsframes.cross-environment-manifest/v2"
    repository = "cLoydRightsFrames/RightsFrames-Termux"
    commit = $Commit
    tracked_file_count = $Files.Count
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

Write-Output "COMMIT=$Commit"
Write-Output "TRACKED_FILES=$($Files.Count)"
Write-Output "MANIFEST_SHA256=$Digest"
