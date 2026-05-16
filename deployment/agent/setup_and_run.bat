@echo off
setlocal

echo =========================================
echo NetVisor Agent Setup ^(Windows^)
echo =========================================
echo.

set "DEFAULT_SERVER_URL=http://10.159.79.96:8000"
set /p SERVER_URL="Enter NetVisor server URL [%DEFAULT_SERVER_URL%]: "
if "%SERVER_URL%"=="" set "SERVER_URL=%DEFAULT_SERVER_URL%"

echo.
echo [1/4] Updating config\agent.json ...
python -c "import json, os; from pathlib import Path; root=Path.cwd(); cfg=root/'config'/'agent.json'; data=json.loads(cfg.read_text(encoding='utf-8')); base=os.environ['SERVER_URL'].rstrip('/'); collect=base if '/api/v1/collect' in base else base + '/api/v1/collect/packet'; root_url=collect.split('/api/v1/collect', 1)[0]; data['server_url']=collect; data['heartbeat_url']=root_url + '/api/v1/collect/heartbeat'; cfg.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8'); print('server_url=' + data['server_url'])"
if errorlevel 1 goto fail

echo.
echo [2/4] Installing Python dependencies ...
python -m pip install -r requirements.txt
if errorlevel 1 goto fail

echo.
echo [3/4] Checking server connectivity ...
python scripts\check_agent_connectivity.py
if errorlevel 1 (
    echo.
    echo [!] Connectivity failed. Start the NetVisor server and allow TCP 8000 in Windows Firewall.
    pause
    exit /b 1
)

echo.
echo [4/4] Starting NetVisor Agent ...
echo Run this window as Administrator for packet capture.
python run_agent.py
pause
exit /b 0

:fail
echo.
echo [!] Setup failed.
pause
exit /b 1
