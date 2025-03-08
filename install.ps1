#requires -version 4
Write-Host "Military Crypto Installer" -ForegroundColor Cyan

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Go not installed!" -ForegroundColor Red
    Write-Host "Download from: https://golang.org/dl/" -ForegroundColor Yellow
    exit
}

Write-Host "Installing dependencies..." -ForegroundColor Green
go get github.com/urfave/cli/v2
go get golang.org/x/crypto/chacha20poly1305
go get golang.org/x/crypto/curve25519
go get golang.org/x/term

Write-Host "Building executable..." -ForegroundColor Yellow
go build -o military-crypto.exe

Write-Host "`nInstallation completed!" -ForegroundColor Green
Write-Host "Run using: .\military-crypto.exe"