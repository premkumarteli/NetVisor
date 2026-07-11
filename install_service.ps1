# install_service.ps1
# Requires administrative privileges

$ErrorActionPreference = "Stop"

$ProjectRoot = "C:\Users\prem\Network"
$PythonExe = "$ProjectRoot\.venv\Scripts\python.exe"
$ServiceScript = "$ProjectRoot\netvisor_service.py"

Write-Host "[*] Registering NetVisorAgent service..." -ForegroundColor Cyan
# Run the installation command
& $PythonExe $ServiceScript --startup manual install

Write-Host "[*] Configuring failure recovery actions..." -ForegroundColor Cyan
# Configure service restart on failure:
# restart after 60s for 1st, 2nd, and all subsequent failures. Reset counter after 1 day.
& sc.exe failure NetVisorAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000

Write-Host "[*] Configuring startup type to manual..." -ForegroundColor Cyan
& sc.exe config NetVisorAgent start= demand

Write-Host "[*] Starting NetVisorAgent service..." -ForegroundColor Cyan
& sc.exe start NetVisorAgent

Write-Host "[+] NetVisorAgent service successfully installed and started!" -ForegroundColor Green
