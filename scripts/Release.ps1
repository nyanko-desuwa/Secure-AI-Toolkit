# Maintainer release helper. Does not publish unless explicit flags are passed.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [switch]$Tag,

    [switch]$Push,

    [switch]$CreateRelease,

    [switch]$SkipScan
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version must be semver X.Y.Z without leading v"
}
$TagName = "v$Version"

$status = git status --porcelain
if ($status) {
    Write-Error "Working tree is not clean:`n$status"
    exit 1
}

$branch = git rev-parse --abbrev-ref HEAD
if ($branch -ne "main") {
    throw "Refusing to release from branch '$branch' (expected main)"
}

Write-Host "==> validate repository"
python (Join-Path $Root "scripts\validate_repository.py")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> extract changelog for $Version"
$notes = python (Join-Path $Root "scripts\validate_repository.py") --extract-changelog $Version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$notes.Split("`n") | Select-Object -First 5 | ForEach-Object { Write-Host $_ }
Write-Host "..."

if (-not $SkipScan) {
    $gitleaks = Get-Command gitleaks -ErrorAction SilentlyContinue
    if (-not $gitleaks) {
        throw "gitleaks not installed; install it or pass -SkipScan for a dry local check"
    }
    Write-Host "==> gitleaks"
    & gitleaks detect --source $Root --config (Join-Path $Root ".gitleaks.toml") --verbose
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Host "==> secret scan skipped (-SkipScan)"
}

if ($Tag) {
    git rev-parse $TagName 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        throw "Tag already exists: $TagName"
    }
    Write-Host "==> git tag -a $TagName"
    git tag -a $TagName -m $Version
}

if ($Push) {
    if (-not $Tag) { throw "-Push requires -Tag" }
    Write-Host "==> push main and $TagName (CI release workflow creates the GitHub Release)"
    git push origin main
    git push origin $TagName
}

if ($CreateRelease) {
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) { throw "gh not installed" }
    $tmp = [System.IO.Path]::GetTempFileName()
    Set-Content -Path $tmp -Value $notes -NoNewline
    Write-Host "==> gh release create $TagName"
    gh release create $TagName --title $TagName --notes-file $tmp
    Remove-Item $tmp -Force
}

Write-Host "Release helper finished for $TagName"
