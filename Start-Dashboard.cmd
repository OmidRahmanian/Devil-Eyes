@echo off
title Devils Eyes Dashboard
wsl.exe -d Ubuntu-24.04 -u root -- service postgresql start
if errorlevel 1 goto failed
echo Dashboard: http://localhost:8080
echo Use Copy-Dashboard-Token.cmd to copy your login token.
echo Keep this window open. Press Ctrl+C to stop the dashboard.
wsl.exe -d Ubuntu-24.04 -- bash /home/omid/.local/share/watchtower/start.sh dashboard
if errorlevel 1 goto failed
exit /b 0
:failed
echo Dashboard could not start. Review the message above.
pause
exit /b 1
