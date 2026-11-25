param(
    [int]$CoreCrateBudget = 450
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

# 1. Strict UTF-8 & mojibake guard across all source/test/doc files
$utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
$mojibakeRx = 'ðŸ|â†|â€|âœ|âš|Ã—|Â§|â Œ'
$badFiles = @()
Get-ChildItem -Path "src","tests","docs","README.md","Cargo.toml" -Recurse -File | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    try {
        $text = $utf8Strict.GetString($bytes)
    } catch {
        $badFiles += "$($_.FullName) (invalid UTF-8)"
        return
    }
    if ($text.Contains([char]0xFFFD)) {
        $badFiles += "$($_.FullName) (contains U+FFFD replacement char)"
    } elseif ($text -match $mojibakeRx) {
        $badFiles += "$($_.FullName) (contains UTF-8/CP1252 mojibake)"
    }
}
if ($badFiles.Count -gt 0) {
    Write-Error ("Encoding guard failed:`n" + ($badFiles -join "`n"))
    exit 1
}

# 2. Crate-count footprint verification
$coreCrates = (cargo tree --no-default-features --features core --prefix none 2>$null | Sort-Object -Unique | Measure-Object).Count
$fullCrates = (cargo tree --no-default-features --features full --prefix none 2>$null | Sort-Object -Unique | Measure-Object).Count

Write-Host "=== Nexus-IO Profile Dependency Footprint ==="
Write-Host "  encoding : OK (strict UTF-8, 0 mojibake)"
Write-Host "  core     : $coreCrates unique crates (budget <= $CoreCrateBudget)"
Write-Host "  full     : $fullCrates unique crates"

if ($coreCrates -gt $CoreCrateBudget) {
    Write-Error "Footprint regression: core has $coreCrates crates (exceeds budget of $CoreCrateBudget)"
    exit 1
}
Write-Host "OK: core is within footprint budget."
