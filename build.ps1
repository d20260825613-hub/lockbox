<#
.SYNOPSIS
  Build, test and hand over one of the projects in this workspace.

.DESCRIPTION
  One script for every project rather than six near-identical ones. Run it from
  the project directory, or pass -Project.

  It does the things a "how do I ship this" checklist needs and that are easy to
  do out of order or forget:
    check   syntax-check every source file and run the test suite
    pack    produce the npm tarball in dist/ and print its contents
    link    npm link, so the command is on PATH locally
    publish npm publish (dry-run unless -Publish is given)
    all     check, then pack, then link

  Nothing here writes outside the project's own dist/ directory, and nothing
  publishes to the registry unless you ask for it explicitly.

.EXAMPLE
  .\build.ps1
  .\build.ps1 -Task pack
  .\build.ps1 -Task all -Publish

.NOTES
  PowerShell 5.1 compatible. No administrator rights needed.
#>

[CmdletBinding()]
param(
    [ValidateSet('check', 'pack', 'link', 'publish', 'all')]
    [string]$Task = 'check',

    # Where the tarball goes, relative to the project root.
    [string]$OutDir = 'dist',

    # Actually publish. Without this, -Task publish only does a dry run.
    [switch]$Publish,

    # Skip the test suite. Only useful when you have just run it.
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'

# Resolve the project root as the directory holding this script.
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path (Join-Path $ProjectRoot 'package.json'))) {
    Write-Error "no package.json next to build.ps1; run this from a project directory"
    exit 1
}

$Manifest = Get-Content (Join-Path $ProjectRoot 'package.json') -Raw | ConvertFrom-Json
$ProjectName = $Manifest.name
$ProjectVersion = $Manifest.version

function Write-Step {
    param([string]$Text)
    Write-Host ''
    Write-Host "== $Text" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Text)
    Write-Host "   $Text" -ForegroundColor Green
}

function Write-Note {
    param([string]$Text)
    Write-Host "   $Text" -ForegroundColor DarkGray
}

# npm on Windows is a .cmd shim. Invoking the .ps1 wrapper is blocked by the
# default execution policy on many machines, so the .cmd path is used directly.
function Get-NpmPath {
    $command = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $command = Get-Command npm -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'npm was not found on PATH'
}

function Invoke-Npm {
    param([string[]]$Arguments, [switch]$AllowFailure)
    $npm = Get-NpmPath
    Write-Note "npm $($Arguments -join ' ')"
    & $npm @Arguments
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) {
        throw "npm $($Arguments[0]) failed with exit code $LASTEXITCODE"
    }
    return $LASTEXITCODE
}

# ---------------------------------------------------------------- check -----
function Invoke-Check {
    Write-Step "check $ProjectName@$ProjectVersion"

    $sources = Get-ChildItem -Path (Join-Path $ProjectRoot 'src'), (Join-Path $ProjectRoot 'bin') -Recurse -File -Filter '*.js' -ErrorAction SilentlyContinue
    if (-not $sources) { throw 'no source files found under src/ or bin/' }

    $failed = 0
    foreach ($file in $sources) {
        $relative = $file.FullName.Substring($ProjectRoot.Length + 1)
        & node --check $file.FullName 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "   FAIL $relative" -ForegroundColor Red
            & node --check $file.FullName
            $failed++
        }
    }
    if ($failed -gt 0) { throw "$failed file(s) failed the syntax check" }
    Write-Ok "$($sources.Count) source file(s) parse"

    if ($SkipTests) {
        Write-Note 'tests skipped (-SkipTests)'
        return
    }

    # node --test with a bare directory is rejected by Node 21+, and a glob is
    # rejected by Node 18-20. Naming the files works on every version.
    $testFiles = Get-ChildItem -Path (Join-Path $ProjectRoot 'test') -File -Filter '*.test.js' -ErrorAction SilentlyContinue |
        Sort-Object Name | ForEach-Object { "test/$($_.Name)" }
    if (-not $testFiles) {
        Write-Note 'no test files found'
        return
    }

    $exit = Invoke-Npm -Arguments (@('--silent', 'exec', '--', 'node', '--test') + $testFiles) -AllowFailure
    if ($exit -ne 0) { throw "the test suite failed with exit code $exit" }
    Write-Ok "$($testFiles.Count) test file(s) passed"
}

# ----------------------------------------------------------------- pack -----
function Invoke-Pack {
    Write-Step 'pack'

    $target = Join-Path $ProjectRoot $OutDir
    if (Test-Path $target) { Remove-Item $target -Recurse -Force }
    New-Item -ItemType Directory -Path $target -Force | Out-Null

    $npm = Get-NpmPath
    $json = & $npm pack --pack-destination $target --json 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "npm pack failed: $json" }

    $report = $json | ConvertFrom-Json
    $entry = $report[0]
    $tarball = Join-Path $target $entry.filename

    Write-Ok "$($entry.filename)  ($([math]::Round($entry.size / 1KB, 1)) KB packed, $([math]::Round($entry.unpackedSize / 1KB, 1)) KB unpacked)"

    # A tarball that ships the tests or the maintainer scripts is a mistake, and
    # it is invisible unless someone looks.
    $paths = $entry.files | ForEach-Object { $_.path }
    $unwanted = $paths | Where-Object { $_ -match '^(test|scripts|\.github)/' }
    if ($unwanted) {
        Write-Host "   WARNING: the tarball contains $($unwanted.Count) file(s) it probably should not:" -ForegroundColor Yellow
        $unwanted | Select-Object -First 5 | ForEach-Object { Write-Note $_ }
    }

    foreach ($required in 'package.json', 'README.md') {
        if ($paths -notcontains $required) {
            Write-Host "   WARNING: $required is not in the tarball" -ForegroundColor Yellow
        }
    }

    Write-Note "$($paths.Count) file(s) in the package"
    Write-Host "   tarball: $tarball" -ForegroundColor DarkGray
    return $tarball
}

# ----------------------------------------------------------------- link -----
function Invoke-Link {
    Write-Step 'link'
    $exit = Invoke-Npm -Arguments @('link') -AllowFailure
    if ($exit -ne 0) { throw 'npm link failed' }
    $binName = ($Manifest.bin.PSObject.Properties | Select-Object -First 1).Name
    Write-Ok "the '$binName' command now points at this checkout"
    Write-Note "undo with: npm unlink -g $ProjectName"
}

# -------------------------------------------------------------- publish -----
function Invoke-Publish {
    Write-Step 'publish'

    if (-not (Test-Path (Join-Path $ProjectRoot 'LICENSE'))) {
        throw 'no LICENSE file; publishing without one is a bad idea'
    }
    $gitStatus = & git status --porcelain 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitStatus) {
        throw 'the working tree has uncommitted changes; commit or stash them first'
    }

    if ($Publish) {
        $exit = Invoke-Npm -Arguments @('publish', '--access', 'public') -AllowFailure
        if ($exit -ne 0) { throw 'npm publish failed' }
        Write-Ok "published $ProjectName@$ProjectVersion"
    }
    else {
        $exit = Invoke-Npm -Arguments @('publish', '--dry-run', '--access', 'public') -AllowFailure
        if ($exit -ne 0) { throw 'npm publish --dry-run failed' }
        Write-Ok 'dry run only; re-run with -Publish to actually publish'
    }
}

switch ($Task) {
    'check' { Invoke-Check }
    'pack' { Invoke-Pack | Out-Null }
    'link' { Invoke-Link }
    'publish' { Invoke-Publish }
    'all' {
        Invoke-Check
        Invoke-Pack | Out-Null
        Invoke-Link
    }
}

Write-Host ''
# ${} around the variable name: `"$ProjectVersion: ..."` parses as a scope
# reference and fails, which is a genuinely confusing error message.
Write-Host "${ProjectName}@${ProjectVersion}: $Task complete" -ForegroundColor Green
