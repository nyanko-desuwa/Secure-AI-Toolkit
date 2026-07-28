# Install production skills from this checkout into Claude Code skill dirs.
[CmdletBinding()]
param(
    [ValidateSet("user", "project")]
    [string]$Scope = "user",

    [string[]]$Skills = @(),

    [switch]$All,

    [ValidateSet("copy", "symlink")]
    [string]$Mode = "copy",

    [string]$Dest = "",

    [switch]$DryRun,

    [switch]$Force,

    [switch]$Verify
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$CatalogPath = Join-Path $Root "catalog\skills.json"

if (-not (Test-Path $CatalogPath)) {
    throw "Missing catalog: $CatalogPath"
}

$catalog = Get-Content -Raw -Path $CatalogPath | ConvertFrom-Json
$byName = @{}
foreach ($s in $catalog.skills) {
    $byName[$s.name] = $s
}

if (-not $Dest) {
    if ($Scope -eq "user") {
        $Dest = Join-Path $HOME ".claude\skills"
    } else {
        $Dest = Join-Path (Get-Location) ".claude\skills"
    }
}

$selected = @()
if ($All) {
    $selected = @($catalog.skills | ForEach-Object { $_.name })
} elseif ($Skills.Count -gt 0) {
    # PowerShell receives `-Skills a,b` as one CSV string in some hosts.
    $selected = @($Skills | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
} else {
    throw "Specify -All or -Skills name1,name2"
}

foreach ($name in $selected) {
    if (-not $byName.ContainsKey($name)) {
        throw "Unknown or non-production skill: $name"
    }
}

Write-Host "Destination: $Dest"
Write-Host "Mode: $Mode"
Write-Host ("Skills ({0}): {1}" -f $selected.Count, ($selected -join ", "))

if (-not $DryRun) {
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
}

foreach ($name in $selected) {
    $src = Join-Path $Root $byName[$name].path
    $dst = Join-Path $Dest $name
    if (-not (Test-Path $src)) {
        throw "Source missing: $src"
    }
    if (Test-Path $dst) {
        if ($Force) {
            Write-Host "Replace: $dst"
            if (-not $DryRun) {
                Remove-Item -Recurse -Force $dst
            }
        } else {
            throw "Collision (use -Force to replace): $dst"
        }
    }
    Write-Host "$Mode $src -> $dst"
    if ($DryRun) { continue }
    if ($Mode -eq "copy") {
        Copy-Item -Recurse -Path $src -Destination $dst
    } else {
        try {
            New-Item -ItemType SymbolicLink -Path $dst -Target $src | Out-Null
        } catch {
            throw @"
Failed to create symlink at $dst.
On Windows, symlink creation may require Developer Mode or an elevated shell.
Fall back to -Mode copy, or enable Developer Mode and retry.
Underlying error: $_
"@
        }
    }
}

if ($Verify -and -not $DryRun) {
    foreach ($name in $selected) {
        $skillMd = Join-Path (Join-Path $Dest $name) "SKILL.md"
        if (-not (Test-Path $skillMd)) {
            throw "Verify failed: $skillMd missing"
        }
    }
    Write-Host "Verify OK"
}

Write-Host "Done."
