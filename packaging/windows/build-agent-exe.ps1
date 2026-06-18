#Requires -Version 5.1
<#
.SYNOPSIS
    Build the frozen Fathomline Windows agent executable (fathomline-agent.exe) via PyInstaller.

.DESCRIPTION
    Offline-authored scaffolding for ADR-027 phase W1's "frozen exe" item. This script MUST run on
    a Windows build host (or a CI `windows-latest` runner) with Python 3.12+ available — PyInstaller
    produces a native executable for the OS it runs on, so a Linux box cannot produce a Windows exe.

    Steps (all idempotent — safe to re-run):
      1. Create (or reuse) a build venv under packaging/windows/.build-venv.
      2. Install the project (the `fathom` package + its runtime deps) and PyInstaller into it.
      3. Run PyInstaller against fathomline-agent.spec.
      4. Emit dist/fathomline-agent.exe and print its SHA256 (for the enrolment bundle / release notes).

    The resulting exe is what fathom/core/deploy/winbundle.py's run-scan.ps1 prefers over
    `py -3 -m fathom.agent` — drop it next to agent.config.yaml in the deployed bundle.

.NOTES
    This is scaffolding to be exercised in CI later; it has NOT been run (no Windows host available
    at authoring time). Treat the first real CI run as the validation step.
#>
[CmdletBinding()]
param(
    # Python launcher / interpreter to bootstrap the venv from. `py -3` is the Windows launcher;
    # override to a full path if multiple versions are installed.
    [string]$Python = "py",
    # Pass -Clean to force a fresh venv + wipe build/dist (use when deps or the spec changed).
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Resolve paths relative to this script so the build works from any cwd (CI invokes it by path).
$ScriptDir = $PSScriptRoot
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Spec      = Join-Path $ScriptDir "fathomline-agent.spec"
$VenvDir   = Join-Path $ScriptDir ".build-venv"
$BuildDir  = Join-Path $ScriptDir "build"     # PyInstaller's intermediate work dir.
$DistDir   = Join-Path $ScriptDir "dist"      # PyInstaller's output dir → fathomline-agent.exe.
$ExePath   = Join-Path $DistDir  "fathomline-agent.exe"

Write-Host "== Fathomline Windows agent build ==" -ForegroundColor Cyan
Write-Host "repo root : $RepoRoot"
Write-Host "spec      : $Spec"

if (-not (Test-Path $Spec)) {
    throw "Spec not found: $Spec (run this from the repo, not a copy of the script)."
}

# --- 1. venv -----------------------------------------------------------------------------------
# Idempotent: reuse an existing venv unless -Clean was passed. A fresh checkout has none.
if ($Clean -and (Test-Path $VenvDir)) {
    Write-Host "-Clean: removing existing venv, build/ and dist/" -ForegroundColor Yellow
    Remove-Item -Recurse -Force $VenvDir
    if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
    if (Test-Path $DistDir)  { Remove-Item -Recurse -Force $DistDir }
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "Creating build venv at $VenvDir ..." -ForegroundColor Green
    # `py -3 -m venv` on the Windows launcher; if -Python is a full interpreter path this still works.
    & $Python -3 -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        # Fall back to invoking $Python without the -3 launcher arg (e.g. when $Python is python.exe).
        & $Python -m venv $VenvDir
    }
} else {
    Write-Host "Reusing existing build venv." -ForegroundColor Green
}

if (-not (Test-Path $VenvPython)) {
    throw "venv python not found after creation: $VenvPython"
}

# --- 2. install project + pyinstaller ----------------------------------------------------------
# Always upgrade pip first (quiet) so wheel resolution is current; then install the project from the
# repo root (pulls pydantic, blake3, sqlalchemy, pyyaml, httpx, cryptography, ... per pyproject.toml)
# plus PyInstaller. Re-running just no-ops on already-satisfied requirements — that is the idempotency.
Write-Host "Upgrading pip and installing the project + PyInstaller ..." -ForegroundColor Green
& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }

# Install the project itself (non-editable: we want a clean, importable `fathom` in site-packages so
# the freeze matches a real install). `aiosqlite` lives in the [dev] extra but the frozen agent needs
# it at runtime (sqlite+aiosqlite staging driver), so install it explicitly alongside PyInstaller.
& $VenvPython -m pip install "$RepoRoot"
if ($LASTEXITCODE -ne 0) { throw "project install failed" }
& $VenvPython -m pip install pyinstaller aiosqlite
if ($LASTEXITCODE -ne 0) { throw "pyinstaller/aiosqlite install failed" }

# --- 3. run pyinstaller ------------------------------------------------------------------------
# --noconfirm so a re-run overwrites dist/ without prompting (idempotent). --clean clears the stale
# PyInstaller cache only when -Clean was requested (a normal re-run reuses it for speed).
Write-Host "Running PyInstaller ..." -ForegroundColor Green
$piArgs = @("-m", "PyInstaller", "--noconfirm",
            "--distpath", $DistDir, "--workpath", $BuildDir, $Spec)
if ($Clean) { $piArgs += "--clean" }
& $VenvPython @piArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

# --- 4. verify + checksum ----------------------------------------------------------------------
if (-not (Test-Path $ExePath)) {
    throw "Expected output not found: $ExePath (PyInstaller ran but produced no exe)."
}

$hash = (Get-FileHash -Algorithm SHA256 -Path $ExePath).Hash.ToLower()
$size = (Get-Item $ExePath).Length

Write-Host ""
Write-Host "== Build complete ==" -ForegroundColor Cyan
Write-Host "exe    : $ExePath"
Write-Host "size   : $size bytes"
Write-Host "sha256 : $hash"
Write-Host ""
Write-Host "Sanity check (prints the config-required error, exit code 2, when run with no config):"
Write-Host "  `$env:FATHOM_AGENT_CONFIG = `$null; & '$ExePath' scan"
Write-Host "Drop fathomline-agent.exe next to agent.config.yaml in the winbundle to use it."
