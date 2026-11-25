param(
    [int]$CoreCrateBudget = 450
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$coreCrates = (cargo tree --no-default-features --features profile-core --prefix none 2>$null | Sort-Object -Unique | Measure-Object).Count
$appCrates  = (cargo tree --no-default-features --features profile-app  --prefix none 2>$null | Sort-Object -Unique | Measure-Object).Count
$fullCrates = (cargo tree --no-default-features --features profile-full --prefix none 2>$null | Sort-Object -Unique | Measure-Object).Count

Write-Host "=== Nexus-IO Profile Dependency Footprint ==="
Write-Host "  profile-core : $coreCrates unique crates (budget <= $CoreCrateBudget)"
Write-Host "  profile-app  : $appCrates unique crates"
Write-Host "  profile-full : $fullCrates unique crates"

if ($coreCrates -gt $CoreCrateBudget) {
    Write-Error "Footprint regression: profile-core has $coreCrates crates (exceeds budget of $CoreCrateBudget)"
    exit 1
}
Write-Host "OK: profile-core is within footprint budget."
