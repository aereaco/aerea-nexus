param(
    [int]$CoreCrateBudget = 450
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$coreCrates = (cargo tree --no-default-features --features core --prefix none 2>$null | Sort-Object -Unique | Measure-Object).Count
$fullCrates = (cargo tree --no-default-features --features full --prefix none 2>$null | Sort-Object -Unique | Measure-Object).Count

Write-Host "=== Nexus-IO Profile Dependency Footprint ==="
Write-Host "  core : $coreCrates unique crates (budget <= $CoreCrateBudget)"
Write-Host "  full : $fullCrates unique crates"

if ($coreCrates -gt $CoreCrateBudget) {
    Write-Error "Footprint regression: core has $coreCrates crates (exceeds budget of $CoreCrateBudget)"
    exit 1
}
Write-Host "OK: core is within footprint budget."
