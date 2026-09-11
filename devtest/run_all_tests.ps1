# PowerShell automated execution script for traces-sm devtest

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [TRACES-SM] Starting DevTest Automated Verification Suite" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Split-Path -Parent $scriptDir
Set-Location $rootDir

# Ensure MinGW GCC & RUSTFLAGS for Windows GNU toolchain
if (Test-Path "C:\Users\admin\w64devkit\bin") {
    $env:PATH = "C:\Users\admin\w64devkit\bin;" + $env:PATH
}
$env:RUSTFLAGS = "-C linker=rust-lld -C link-self-contained=yes"

Write-Host "`n[1/3] Checking workspace compilation..." -ForegroundColor Yellow
cargo check --workspace
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Workspace compilation failed!" -ForegroundColor Red
    exit 1
}

Write-Host "`n[2/3] Running Cargo Integration Tests..." -ForegroundColor Yellow
cargo test -p traces-sm-devtest -- --nocapture
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Integration tests failed!" -ForegroundColor Red
    exit 1
}

Write-Host "`n[3/3] Executing DevTest Diagnostic Runner..." -ForegroundColor Yellow
$reportPath = Join-Path $scriptDir "test_report.md"
cargo run -p traces-sm-devtest -- --all --report "$reportPath"

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host " [SUCCESS] ALL DEVTEST SUITES PASSED CLEANLY ON WINDOWS / NON-SGX!" -ForegroundColor Green
    Write-Host " [REPORT] Audit report generated at: $reportPath" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
} else {
    Write-Host "`n[FAIL] DevTest execution encountered failures!" -ForegroundColor Red
    exit 1
}
