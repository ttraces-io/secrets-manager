# Script to synchronize wiki/ folder to GitHub Wiki repo (ttraces-io/secrets-manager.wiki.git)
param (
    [string]$WikiRepoUrl = "https://github.com/ttraces-io/secrets-manager.wiki.git"
)

$wikiDir = "$env:TEMP\traces-sm-wiki"
if (Test-Path $wikiDir) { Remove-Item -Path $wikiDir -Recurse -Force }

Write-Host "Cloning GitHub Wiki repository..." -ForegroundColor Cyan
git clone $WikiRepoUrl $wikiDir

Write-Host "Copying all wiki pages and sidebar/footer to Wiki repo..." -ForegroundColor Yellow
Copy-Item -Path "wiki\*" -Destination $wikiDir -Recurse -Force

Set-Location -Path $wikiDir
git add .
git commit -m "Sync documentation from main repo wiki/ folder"
git push origin master

Write-Host "GitHub Wiki synchronized successfully!" -ForegroundColor Green
