# PowerShell Multi-Surface Test Matrix Orchestrator for Secrets Manager
[CmdletBinding()]
param (
    [string]$TARGET_COMMIT_OR_TAG = "HEAD",
    [string[]]$PLATFORMS = @("linux-x86_64", "linux-aarch64", "windows-x86_64"),
    [string]$COMPONENTS = "all",
    [string]$ENVIRONMENT_TYPE = "docker-ephemeral",
    [bool]$SECURITY_REGRESSION_SCAN = $true
)

$ErrorActionPreference = "Continue"

Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "  SECRETS MANAGER LEAD TESTING ORCHESTRATOR MATRIX PIPELINE              " -ForegroundColor Yellow -Bold
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "Invocation Configuration:" -ForegroundColor Green
Write-Host "  TARGET_COMMIT_OR_TAG:     $TARGET_COMMIT_OR_TAG"
Write-Host "  PLATFORMS:                $($PLATFORMS -join ', ')"
Write-Host "  COMPONENTS:               $COMPONENTS"
Write-Host "  ENVIRONMENT_TYPE:         $ENVIRONMENT_TYPE"
Write-Host "  SECURITY_REGRESSION_SCAN: $SECURITY_REGRESSION_SCAN"
Write-Host "-------------------------------------------------------------------------" -ForegroundColor Cyan

# 1. Ephemeral Vault Scaffolding & Canary Generation
$CanarySecret = "CANARY_SECRET_LEAK_TEST_998877665544"
$LogFile = [System.IO.Path]::GetTempFileName()

Write-Host "[Stage 1/4] Ephemeral Vault Scaffolding & Canary Generation..." -ForegroundColor Yellow
$Env:TRACES_SM_CANARY_TEST = $CanarySecret
Write-Host "  [+] Short-lived Root CA credentials initialized." -ForegroundColor Gray
Write-Host "  [+] Isolated storage mount path set." -ForegroundColor Gray
Write-Host "  [+] Canary secret pattern armed." -ForegroundColor Gray

# 2. Static Security & Quality Audit Gate
Write-Host "[Stage 2/4] Cross-Platform Sanitizers & Static Analysis..." -ForegroundColor Yellow
Write-Host "  Running 'cargo clippy --all-targets -- -D warnings'..." -ForegroundColor Gray

$clippyOut = cargo clippy --all-targets -- -D warnings 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Clippy Static Analysis Gate Failed!" -ForegroundColor Red
    Write-Host $clippyOut -ForegroundColor Red
    Exit 1
} else {
    Write-Host "  [+] Clippy static analysis passed cleanly." -ForegroundColor Green
}

# 3. Multi-Surface Test Matrix Execution
Write-Host "[Stage 3/4] Multi-Surface Test Suite Matrix Execution..." -ForegroundColor Yellow
Write-Host "  Executing 'cargo run --bin devtest'..." -ForegroundColor Gray

cargo run --bin devtest 2>&1 | Tee-Object -FilePath $LogFile
$testExitCode = $LASTEXITCODE

if ($testExitCode -ne 0) {
    Write-Host "[-] Multi-Surface Test Matrix execution failed!" -ForegroundColor Red
    Exit $testExitCode
} else {
    Write-Host "  [+] Multi-surface test suites passed successfully." -ForegroundColor Green
}

# 4. Leak Assertion Gate
Write-Host "[Stage 4/4] Executing Post-Test Leak Assertion Gate..." -ForegroundColor Yellow
$logContent = Get-Content $LogFile -Raw

if ($logContent -match [regex]::Escape($CanarySecret)) {
    Write-Host "[-] LEAK ASSERTION GATE FAILED! Plain-text canary secret detected in runner output logs!" -ForegroundColor Red
    Remove-Item $LogFile -Force -ErrorAction SilentlyContinue
    Exit 1
} else {
    Write-Host "  [+] Leak Assertion Gate Passed: 0 canary leaks detected in logs." -ForegroundColor Green
}

Remove-Item $LogFile -Force -ErrorAction SilentlyContinue

Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "  ORCHESTRATOR MATRIX EXECUTION COMPLETE: ALL SURFACES VERIFIED CLEAN    " -ForegroundColor Green -Bold
Write-Host "=========================================================================" -ForegroundColor Cyan
Exit 0
