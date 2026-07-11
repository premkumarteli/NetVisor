
# NetVisor Local Capture Smoke Test
# Run this script as Administrator

Write-Host "=== NetVisor Local Capture Smoke Test ===" -ForegroundColor Cyan
Write-Host "confdir : C:\Users\prem\Network\runtime\agent\mitm" -ForegroundColor Yellow
Write-Host "mode    : local:chrome.exe" -ForegroundColor Yellow
Write-Host "addon   : C:\Users\prem\Network\agent\dpi\mitm_addon.py" -ForegroundColor Yellow
Write-Host ""
Write-Host "Steps:" -ForegroundColor Green
Write-Host "  1. Kill all Chrome processes first (close Chrome manually)"
Write-Host "  2. Watch for: 'Proxy server listening' or driver init messages"
Write-Host "  3. Open Chrome normally from taskbar after proxy starts"
Write-Host "  4. Visit https://example.com and https://www.google.com"
Write-Host "  5. Watch for __NETVISOR_WEB_EVENT__ lines below"
Write-Host "  6. Press Ctrl+C to stop"
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as Administrator, then run this script." -ForegroundColor Red
    pause
    exit 1
}

Write-Host "Admin check: PASSED" -ForegroundColor Green
Write-Host "Starting mitmdump in Local Capture mode..." -ForegroundColor Cyan
Write-Host "-------------------------------------------"

& "C:\Users\prem\Network\.venv\Scripts\mitmdump.exe" `
    --set confdir="C:\Users\prem\Network\runtime\agent\mitm" `
    --mode "local:chrome.exe" `
    -s "C:\Users\prem\Network\agent\dpi\mitm_addon.py" `
    -v
