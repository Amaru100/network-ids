@echo off
echo ============================================================
echo   NIDS Agent — Starting...
echo ============================================================
echo.
echo NOTE: This must be run as Administrator!
echo Right-click CMD and select "Run as Administrator"
echo.

:: Get computer name as default agent name
set AGENT_NAME=%COMPUTERNAME%

python nids_agent.py --agent-name %AGENT_NAME%
pause
