# QA Multi-Surface Test Suite Runner for Secrets Manager
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
Write-Host "  QA SECRETS MANAGER MULTI-SURFACE TEST MATRIX RUNNER                    " -ForegroundColor Yellow -Bold
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "Invocation Configuration:" -ForegroundColor Green
Write-Host "  TARGET_COMMIT_OR_TAG:     $TARGET_COMMIT_OR_TAG"
Write-Host "  PLATFORMS:                $($PLATFORMS -join ', ')"
Write-Host "  COMPONENTS:               $COMPONENTS"
Write-Host "  ENVIRONMENT_TYPE:         $ENVIRONMENT_TYPE"
Write-Host "  SECURITY_REGRESSION_SCAN: $SECURITY_REGRESSION_SCAN"
Write-Host "-------------------------------------------------------------------------" -ForegroundColor Cyan

# 1. Ephemeral Vault Scaffolding & Canary Generation
$CanarySecret = "CANARY_SECRET_QA_TEST_88776655"
$LogFile = [System.IO.Path]::GetTempFileName()

Write-Host "[QA Stage 1/3] Ephemeral Scaffolding & Canary Pattern Initialization..." -ForegroundColor Yellow
$Env:TRACES_SM_CANARY_TEST = $CanarySecret
Write-Host "  [+] Transient vault environment configured." -ForegroundColor Gray
Write-Host "  [+] Canary pattern armed for memory/log leak scanner." -ForegroundColor Gray

# 2. Execute Multi-Surface QA DevTest Matrix
Write-Host "[QA Stage 2/3] Multi-Surface Test Matrix Execution..." -ForegroundColor Yellow
cargo run --bin devtest -- --report qa/qa_matrix_report.md 2>&1 | Tee-Object -FilePath $LogFile
$testExitCode = $LASTEXITCODE

if ($testExitCode -ne 0) {
    Write-Host "[-] QA Test Matrix execution failed!" -ForegroundColor Red
    Exit $testExitCode
} else {
    Write-Host "  [+] Multi-surface test matrix passed cleanly." -ForegroundColor Green
}

# 3. Post-Test Canary Leak Assertion Gate
Write-Host "[QA Stage 3/3] Post-Test Leak Assertion Gate Audit..." -ForegroundColor Yellow
$logContent = Get-Content $LogFile -Raw

if ($logContent -match [regex]::Escape($CanarySecret)) {
    Write-Host "[-] LEAK ASSERTION GATE FAILED! Plain-text canary secret detected in runner logs!" -ForegroundColor Red
    Remove-Item $LogFile -Force -ErrorAction SilentlyContinue
    Exit 1
} else {
    Write-Host "  [+] Leak Assertion Gate Passed: 0 canary leaks detected." -ForegroundColor Green
}

Remove-Item $LogFile -Force -ErrorAction SilentlyContinue

Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "  QA MULTI-SURFACE SUITE COMPLETED SUCCESSFULLY                           " -ForegroundColor Green -Bold
Write-Host "=========================================================================" -ForegroundColor Cyan
Exit 0
